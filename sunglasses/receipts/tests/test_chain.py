"""The writer core (spec §3-4), independent of the A/B sealing policy: every
test's oracle is the standalone verifier or the bytes on disk, never the
writer's own report of what it did."""
import os
import pathlib
import stat
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import chain                                               # noqa: E402
import keys                                                # noqa: E402
import verify                                              # noqa: E402
import wire                                                # noqa: E402


@pytest.fixture
def home(tmp_path):
    keys.init(tmp_path)
    return tmp_path


def _writer(home, **kw):
    kw.setdefault("producer", "hook")
    return chain.Chain(home / "receipts" / "chain", keys.load(home), **kw)


def _segments(home):
    return sorted((home / "receipts" / "chain").glob("segment-*.chain"))


def _report(home, path):
    fp = keys.load(home).fingerprint
    return verify.verify(path.read_bytes(), keys.public_path(home, fp).read_bytes())


def _records(path):
    return [wire.decode_strict(line) for line in path.read_bytes().splitlines(True)]


def _call(eval_id):
    return [{"event": "in_flight", "body": {"eval_id": eval_id}},
            {"event": "decision", "body": {"eval_id": eval_id}}]


def test_a_new_chain_opens_with_genesis_and_its_checkpoint(home):
    _writer(home).write(_call("a"), seal="close")
    [segment] = _segments(home)
    records = _records(segment)
    assert [r["event"] for r in records[:2]] == ["genesis", "checkpoint"]
    assert records[1]["purpose"] == "genesis"
    report = _report(home, segment)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["unsigned_tail"] == "NO_VISIBLE_TAIL"
    assert report.results["lifecycle"] == "LIFECYCLE_COMPLETE"


def test_every_record_carries_the_envelope(home):
    _writer(home).write(_call("a"), seal="close")
    [segment] = _segments(home)
    data = [r for r in _records(segment) if r["event"] not in ("genesis", "checkpoint")]
    for record in data:
        assert record["producer"] == "hook"
        assert isinstance(record["t_wall_ns"], int)
        assert record["key_id"] == keys.load(home).fingerprint


def test_the_interval_is_sealed_before_the_next_record_is_admitted(home):
    writer = _writer(home, interval=3)
    for n in range(4):
        writer.write(_call(str(n)))
    [segment] = _segments(home)
    records = _records(segment)
    unsigned = 0
    for record in records[2:]:
        unsigned = 0 if record["event"] == "checkpoint" else unsigned + 1
        assert unsigned <= 3
    report = _report(home, segment)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.tail["count"] == unsigned


def test_a_sealed_end_is_continued_by_the_next_writer(home):
    _writer(home).write(_call("a"), seal="release")
    _writer(home).write(_call("b"), seal="release")
    [segment] = _segments(home)
    records = _records(segment)
    assert [r["seq"] for r in records] == list(range(len(records)))
    assert sum(r["event"] == "genesis" for r in records) == 1
    assert _report(home, segment).results["chain_integrity"] == "CHAIN_OK"


def _replace_last_line(path, record):
    lines = path.read_bytes().splitlines(True)
    path.write_bytes(b"".join(lines[:-1]) + wire.encode(record))


def _forged_signature(record):
    signature = record["signature"]
    flipped = "0" if signature[0] != "0" else "1"
    return dict(record, signature=flipped + signature[1:])


def _signed_by_another_key(record):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    other = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = other.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    unsigned["key_id"] = wire.key_fingerprint(public)
    return dict(unsigned, signature=other.sign(
        wire.checkpoint_signing_bytes(unsigned)).hex())


@pytest.mark.parametrize("tamper", [_forged_signature, _signed_by_another_key])
def test_a_sealed_end_whose_seal_does_not_verify_is_not_continued(home, tamper):
    """R15b: a sealed tail is continued only when its closing checkpoint's
    signature verifies under this writer's key. Otherwise the checkpoint is
    just bytes: the segment is closed untouched and a new genesis names the
    last checkpoint that does verify. The control is the test above."""
    _writer(home).write(_call("a"), seal="close")
    [old] = _segments(home)
    records = _records(old)
    _replace_last_line(old, tamper(records[-1]))
    before = old.read_bytes()
    genesis_checkpoint = records[1]
    assert genesis_checkpoint["purpose"] == "genesis"

    _writer(home).write(_call("b"), seal="close")

    assert old.read_bytes() == before
    assert len(_segments(home)) == 2
    new = _segments(home)[1]
    genesis = _records(new)[0]
    assert genesis["body"]["previous"] == {
        "chain_id": records[0]["chain_id"], "seq": genesis_checkpoint["seq"],
        "hash": wire.record_hash(before.splitlines(True)[1])}
    assert genesis["body"]["observed_unsigned"] == 3     # a's two rows + the seal
    assert _report(home, new).results["chain_integrity"] == "CHAIN_OK"


def test_a_restart_never_signs_an_unsigned_suffix(home):
    _writer(home).write(_call("a"))                        # crashed: never sealed
    [old] = _segments(home)
    before = old.read_bytes()
    last_checkpoint = [(r["seq"], wire.record_hash(line))
                       for r, line in zip(_records(old), before.splitlines(True))
                       if r["event"] == "checkpoint"][-1]

    _writer(home).write(_call("b"), seal="close")

    assert old.read_bytes() == before                      # closed untouched
    old_report = _report(home, old)
    assert old_report.results["unsigned_tail"] == "UNVERIFIED_TAIL"
    assert old_report.tail["count"] == 2
    new = _segments(home)[1]
    genesis = _records(new)[0]
    assert genesis["body"]["previous"] == {
        "chain_id": _records(old)[0]["chain_id"],
        "seq": last_checkpoint[0], "hash": last_checkpoint[1]}
    assert genesis["body"]["observed_unsigned"] == 2
    assert _report(home, new).results["chain_integrity"] == "CHAIN_OK"


def test_another_writers_unsigned_suffix_is_never_signed(home):
    first = _writer(home)
    first.write(_call("a"))                                # first's, unsealed
    _writer(home).write(_call("b"), seal="release")        # must not seal it
    first.write(_call("c"), seal="release")                # nor may first, now
    old, *_ = _segments(home)
    assert _report(home, old).tail["count"] == 2
    for segment in _segments(home):
        assert _report(home, segment).results["chain_integrity"] == "CHAIN_OK"


def test_a_writer_keeps_its_own_suffix_across_writes(home):
    """The long-lived proxy: unsealed rows between lock holds are its own."""
    writer = _writer(home)
    writer.write(_call("a"))
    writer.write(_call("b"), seal="close")
    [segment] = _segments(home)
    assert _report(home, segment).results["unsigned_tail"] == "NO_VISIBLE_TAIL"


def test_a_torn_tail_is_left_torn_and_a_new_segment_opens(home):
    _writer(home).write(_call("a"), seal="release")
    [old] = _segments(home)
    with open(old, "ab") as handle:
        handle.write(b'{"torn')
    before = old.read_bytes()
    _writer(home).write(_call("b"), seal="close")
    assert old.read_bytes() == before
    assert _report(home, old).results["chain_integrity"] == "TRUNCATED_RECORD"
    genesis = _records(_segments(home)[1])[0]
    assert genesis["body"]["observed_torn_bytes"] == len(b'{"torn')


def test_a_float_is_refused_and_nothing_is_written(home):
    writer = _writer(home)
    writer.write(_call("a"), seal="release")
    [segment] = _segments(home)
    before = segment.read_bytes()
    with pytest.raises(wire.NotEncodable):
        writer.write([{"event": "decision", "body": {"eval_id": "b", "ms": 1.5}}])
    assert segment.read_bytes() == before


def test_an_envelope_field_cannot_be_supplied_by_the_producer(home):
    with pytest.raises(ValueError):
        _writer(home).write([{"event": "decision", "body": {}, "seq": 7}])


def test_a_full_segment_closes_and_the_next_names_it(home):
    writer = _writer(home, max_records=8)
    for n in range(4):
        writer.write(_call(str(n)))
    first, second, *_ = _segments(home)
    records = _records(first)
    assert records[-1]["event"] == "checkpoint" and records[-1]["purpose"] == "close"
    assert _report(home, first).results["unsigned_tail"] == "NO_VISIBLE_TAIL"
    assert _records(second)[0]["body"]["previous"]["seq"] == records[-1]["seq"]
    assert _records(second)[0]["body"]["observed_unsigned"] == 0


def test_segments_are_owner_only(home):
    _writer(home).write(_call("a"), seal="release")
    [segment] = _segments(home)
    assert stat.S_IMODE(os.stat(segment).st_mode) == 0o600


_FSYNC_SPY = """
import os, stat, sys; sys.path.insert(0, sys.argv[1])
import chain, keys, pathlib
home = pathlib.Path(sys.argv[2])
writer = chain.Chain(home / "receipts" / "chain", keys.load(home), producer="hook")
writer.write([{"event": "in_flight", "body": {"eval_id": "a"}},
              {"event": "decision", "body": {"eval_id": "a"}}])
synced, real = [], os.fsync
os.fsync = lambda fd: synced.append(stat.S_ISDIR(os.fstat(fd).st_mode)) or real(fd)
writer.seal("release")
print(" ".join(sorted({"dir" if d else "file" for d in synced})))
"""


def test_a_checkpoint_is_fsynced_with_its_directory(home):
    # The spy runs in a child process: the package's environment guard
    # (tests/test_repair_v056.py) refuses any handle on the os module in
    # package code, a monkeypatch of it included (T9 ruling 50).
    import subprocess
    proc = subprocess.run([sys.executable, "-c", _FSYNC_SPY, str(HERE.parent), str(home)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["dir", "file"], proc.stdout


def test_no_signer_is_refused(home, tmp_path):
    with pytest.raises(ValueError):
        chain.Chain(tmp_path / "x", None, producer="hook")


@pytest.mark.parametrize("chunk", [37, 1 << 16])
def test_the_tail_is_read_back_across_chunk_boundaries(home, monkeypatch, chunk):
    monkeypatch.setattr(chain, "_CHUNK", chunk)
    _writer(home).write(_call("a"), seal="release")
    _writer(home).write(_call("b") + _call("c"))           # crashed, 4 unsigned
    [old] = _segments(home)
    checkpoint = [r for r in _records(old) if r["event"] == "checkpoint"][-1]
    _writer(home).write(_call("d"), seal="close")
    genesis = _records(_segments(home)[1])[0]
    assert genesis["body"]["observed_unsigned"] == 4
    assert genesis["body"]["previous"]["seq"] == checkpoint["seq"]


_WORKER = """
import sys; sys.path.insert(0, sys.argv[1])
import chain, keys, pathlib
home = pathlib.Path(sys.argv[2])
writer = chain.Chain(home / "receipts" / "chain", keys.load(home), producer="hook")
for n in range(40):
    eval_id = sys.argv[3] + str(n)
    writer.write([{"event": "in_flight", "body": {"eval_id": eval_id}}], seal="release")
    writer.write([{"event": "decision", "body": {"eval_id": eval_id}}], seal="release")
"""


def test_concurrent_writers_that_seal_every_hold_share_one_segment(home):
    """flock is the only thing between two hook processes: if a hold could
    interleave, a writer would meet a foreign suffix and fork a segment."""
    import subprocess
    procs = [subprocess.Popen([sys.executable, "-c", _WORKER, str(HERE.parent),
                               str(home), tag]) for tag in ("p", "q", "r")]
    assert [p.wait(timeout=60) for p in procs] == [0, 0, 0]
    [segment] = _segments(home)
    report = _report(home, segment)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["lifecycle"] == "LIFECYCLE_COMPLETE"
    assert sum(r["event"] == "in_flight" for r in _records(segment)) == 120


_UNSEALED = """
import sys; sys.path.insert(0, sys.argv[1])
import chain, keys, pathlib
home = pathlib.Path(sys.argv[2])
writer = chain.Chain(home / "receipts" / "chain", keys.load(home), producer="proxy")
writer.write([{"event": "in_flight", "body": {"eval_id": sys.argv[3]}}],
             seal=None if sys.argv[4] == "open" else "release")
"""


def _process(home, eval_id, mode):
    import subprocess
    subprocess.run([sys.executable, "-c", _UNSEALED, str(HERE.parent), str(home),
                    eval_id, mode], check=True, timeout=60)


def test_a_writers_own_suffix_lives_in_its_memory_only(home):
    """T9 R15d. The in-process exception (a long-lived writer keeps its own
    unsigned rows across holds) must die with the process: nothing on disk
    remembers it, and the next PROCESS opens a new genesis, leaving the rows
    it did not write as an unverified tail it never repairs."""
    _process(home, "a", "open")                  # exits with one unsigned row
    directory = home / "receipts" / "chain"
    assert sorted(p.name for p in directory.iterdir()) == [
        "LOCK", "segment-000001.chain"]
    assert (directory / "LOCK").stat().st_size == 0
    [old] = _segments(home)
    before = old.read_bytes()

    _process(home, "b", "sealed")

    assert old.read_bytes() == before
    old_report = _report(home, old)
    assert old_report.results["unsigned_tail"] == "UNVERIFIED_TAIL"
    assert old_report.tail["count"] == 1
    new = _segments(home)[1]
    assert _records(new)[0]["body"]["observed_unsigned"] == 1
    assert _report(home, new).results["chain_integrity"] == "CHAIN_OK"


def test_the_control_one_process_continues_its_own_suffix(home):
    """The paired control: the same two writes in ONE process stay one
    segment, so the test above is measuring the process boundary."""
    writer = _writer(home, producer="proxy")
    writer.write([{"event": "in_flight", "body": {"eval_id": "a"}}])
    writer.write([{"event": "in_flight", "body": {"eval_id": "b"}}], seal="release")
    [segment] = _segments(home)
    assert _report(home, segment).results["unsigned_tail"] == "NO_VISIBLE_TAIL"


# --- hard limits: the interval and the line (spec freeze prep) --------------

LINE_LIMIT = 16 * 1024            # bytes of one line, its LF included


@pytest.mark.parametrize("interval", [0, -1, True, 1.5, "100", None])
def test_an_interval_that_is_not_a_positive_integer_is_refused(home, interval):
    """The interval is bound in every signed checkpoint. Zero or less would
    checkpoint after every record while the header claims a cadence of none;
    a float is refused by the wire only when the first checkpoint is signed,
    long after the writer was built. Refused at construction instead."""
    with pytest.raises(ValueError):
        _writer(home, interval=interval)
    assert not (home / "receipts" / "chain").exists()


def test_the_control_an_interval_of_one_seals_every_record(home):
    _writer(home, interval=1).write(_call("a"))
    [segment] = _segments(home)
    events = [(r["event"], r.get("purpose")) for r in _records(segment)]
    assert events == [("genesis", None), ("checkpoint", "genesis"),
                      ("in_flight", None), ("checkpoint", "interval"),
                      ("decision", None), ("checkpoint", "interval")]
    assert _report(home, segment).results["chain_integrity"] == "CHAIN_OK"


def _one_line(home, name, sizes):
    """The data line a fresh writer writes for a body of `sizes` x-strings,
    on a fixed clock, so two writers differ only in the filler."""
    directory = home / "receipts" / name
    writer = chain.Chain(directory, keys.load(home), producer="hook",
                         clock=lambda: 1)
    body = {f"f{i}": "x" * n for i, n in enumerate(sizes)}
    writer.write([{"event": "decision", "body": body}], seal="close")
    [segment] = sorted(directory.glob("segment-*.chain"))
    return segment.read_bytes().splitlines(True)[2]


def _filler(total, parts=5):
    """`total` bytes of filler over `parts` strings, none over the wire's 4096."""
    sizes = [min(4096, max(0, total - 4096 * i)) for i in range(parts)]
    assert sum(sizes) == total
    return sizes


def test_a_line_of_exactly_16_kib_is_written(home):
    """The control for the refusal below: the limit is inclusive."""
    probe = _one_line(home, "probe", [0] * 5)
    line = _one_line(home, "at", _filler(LINE_LIMIT - len(probe)))
    assert len(line) == LINE_LIMIT
    assert wire.decode_strict(line)["event"] == "decision"


def test_a_line_over_16_kib_is_refused_and_nothing_is_written(home):
    """Every value inside the wire's own bounds, and the line one byte over:
    the writer refuses the whole batch before a byte reaches the file, as it
    does a float."""
    probe = _one_line(home, "probe", [0] * 5)
    sizes = _filler(LINE_LIMIT - len(probe) + 1)
    writer = _writer(home, clock=lambda: 1)       # the probe's clock
    writer.write(_call("a"), seal="release")
    [segment] = _segments(home)
    before = segment.read_bytes()
    with pytest.raises(wire.NotEncodable):
        writer.write([{"event": "decision",
                       "body": {f"f{i}": "x" * n for i, n in enumerate(sizes)}}])
    assert segment.read_bytes() == before


# --- WIRE_SPEC "Record fields" is the writer's, measured ---------------------

def _spec_tables():
    """{table: {field: [cited chain.py line numbers]}} from WIRE_SPEC's three
    record tables."""
    import re
    text = (HERE.parent / "WIRE_SPEC.md").read_text(encoding="utf-8")
    section = text.split("## Record fields", 1)[1].split("\n## ", 1)[0]
    tables = {}
    for name in ("genesis", "event", "checkpoint"):
        body = section.split(f"### {name}\n", 1)[1].split("\n### ", 1)[0]
        rows = {}
        for line in body.splitlines():
            match = re.match(r"\| `(\w+)` \|.*\| (chain\.py:[\d:, -]+) \|$", line)
            if not match:
                continue
            cited = []
            for ref in re.findall(r"(\d+)(?:-(\d+))?", match.group(2).split(":", 1)[1]):
                start = int(ref[0])
                cited.extend(range(start, int(ref[1] or start) + 1))
            rows[match.group(1)] = cited
        tables[name] = rows
    return tables


def test_the_spec_names_every_field_the_writer_writes(home, tables=None):
    writer = _writer(home, max_records=8)
    writer.write(_call("a"), seal="close")
    writer.write([{"event": "in_flight", "body": {"eval_id": "b"}, "t_mono_ns": 7},
                  {"event": "decision", "body": {"eval_id": "b"}}], seal="close")
    writer.write(_call("c"), seal="close")
    assert len(_segments(home)) > 1                   # a successor genesis too
    seen = {"genesis": set(), "event": set(), "checkpoint": set()}
    for path in _segments(home):
        for record in _records(path):
            kind = record["event"] if record["event"] in seen else "event"
            seen[kind] |= set(record)
    tables = _spec_tables() if tables is None else tables
    assert {name: set(rows) for name, rows in tables.items()} == seen
    source = (HERE.parent / "chain.py").read_text(encoding="utf-8").splitlines()
    for name, rows in tables.items():
        for field, cited in rows.items():
            text = "\n".join(source[n - 1] for n in cited)
            assert f'"{field}"' in text or f"{field}=" in text, (
                f"WIRE_SPEC {name}.{field} cites chain.py:{cited}, which does "
                "not write it")


def test_the_control_a_field_the_spec_does_not_name_is_caught(home):
    tables = _spec_tables()
    del tables["event"]["t_mono_ns"]
    with pytest.raises(AssertionError):
        test_the_spec_names_every_field_the_writer_writes(home, tables)
