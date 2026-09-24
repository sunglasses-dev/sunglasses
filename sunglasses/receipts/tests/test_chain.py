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


def test_a_checkpoint_is_fsynced_with_its_directory(home, monkeypatch):
    writer = _writer(home)
    writer.write(_call("a"))
    synced = []
    real = os.fsync
    monkeypatch.setattr(chain.os, "fsync", lambda fd: synced.append(
        stat.S_ISDIR(os.fstat(fd).st_mode)) or real(fd))
    writer.seal("release")
    assert set(synced) == {True, False}


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
