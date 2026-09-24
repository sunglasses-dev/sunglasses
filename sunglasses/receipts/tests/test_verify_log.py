"""The verifier over one LOG: a directory of segments (T9 ruling 15).

One chain per log. A log rotates into segments, and each segment after the
first opens with a genesis naming the last checkpoint of the one before it. The
verifier reports each segment's five results AND five for the log, computed
from the segments plus the links between them. Nothing here reads a second
log: a hook call and a proxy item that belong together live in different logs,
and pairing them is lifecycle, never integrity.

Segments are built from the wire (test_verify's `_Chain`), not by the writer,
except the one round trip at the end.
"""
import pathlib
import shutil
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import codes                                               # noqa: E402
import verify                                              # noqa: E402
import wire                                                # noqa: E402
from test_verify import FP, OTHER_SEED, PUBLIC, _Chain     # noqa: E402


def _segment(chain_id, previous=None, observed_unsigned=0, **kw):
    """A segment's opening, as the writer frames it: genesis (naming its
    predecessor, if any) and the genesis checkpoint."""
    c = _Chain(chain_id=chain_id, **kw)
    c.lines = []
    body = {}
    if previous is not None:
        body = {"previous": previous, "observed_unsigned": observed_unsigned}
    c._add({"event": "genesis", "prev_hash": None, "body": body})
    c.seal("genesis")
    return c


def _names(c):
    """What a successor's genesis names: this segment's last checkpoint."""
    index = max(i for i, line in enumerate(c.lines)
                if wire.decode_strict(line)["event"] == "checkpoint")
    return {"chain_id": c.chain_id, "seq": index,
            "hash": wire.record_hash(c.lines[index])}


def _write(log, *segments, numbers=None):
    log.mkdir(parents=True, exist_ok=True)
    for number, c in zip(numbers or range(1, len(segments) + 1), segments):
        (log / f"segment-{number:06d}.chain").write_bytes(c.data())
    return log


def _three(first_extra=None):
    a = _segment("seg-a")
    a.call("e1")
    if first_extra:
        first_extra(a)
    a.seal("close")
    b = _segment("seg-b", previous=_names(a))
    b.call("e2")
    b.seal("close")
    c = _segment("seg-c", previous=_names(b))
    c.call("e3")
    c.seal("close")
    return a, b, c


def _results(report):
    return {k: report.results[k] for k in codes.RESULT_KINDS}


LOG_OK = {"key_trust": "KEY_TRUSTED", "chain_integrity": "CHAIN_OK",
          "unsigned_tail": "NO_VISIBLE_TAIL",
          "expected_endpoint": "HISTORY_EXTENT_UNKNOWN",
          "lifecycle": "LIFECYCLE_COMPLETE"}


def test_linked_segments_are_one_log(tmp_path):
    log = _write(tmp_path / "hook", *_three())
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert _results(report) == LOG_OK
    assert [name for name, _ in report.segments] == [
        "segment-000001.chain", "segment-000002.chain", "segment-000003.chain"]
    for _, segment in report.segments:
        assert segment.results["chain_integrity"] == "CHAIN_OK"
    assert codes.strict_exit_code(report.results) == 1   # extent is unknown


@pytest.mark.parametrize("gone", [0, 1])
def test_a_deleted_segment_is_named_by_its_successor(tmp_path, gone):
    segments = list(_three())
    numbers = [1, 2, 3]
    del segments[gone], numbers[gone]
    log = _write(tmp_path / "hook", *segments, numbers=numbers)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "SEGMENT_MISSING"
    assert report.first_failure_segment == f"segment-{numbers[gone]:06d}.chain"
    for _, segment in report.segments:                   # each stands alone
        assert segment.results["chain_integrity"] == "CHAIN_OK"


def test_the_last_segment_deleted_is_not_detectable_here(tmp_path):
    """LC02 at log scale: nothing names the newest segment, so removing it
    leaves a log that verifies. Only a retained endpoint can tell."""
    a, b, c = _three()
    log = _write(tmp_path / "hook", a, b)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["expected_endpoint"] == "HISTORY_EXTENT_UNKNOWN"
    retained = dict(_names(c))
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP,
                               expected_endpoint=retained)
    assert report.results["expected_endpoint"] == "EXPECTED_CHECKPOINT_MISSING"


def test_a_successor_naming_the_wrong_checkpoint_breaks_the_link(tmp_path):
    a, _, _ = _three()
    wrong = dict(_names(a), hash="0" * 64)
    b = _segment("seg-b", previous=wrong)
    b.seal("close")
    log = _write(tmp_path / "hook", a, b)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "HASH_LINK_MISMATCH"
    assert report.first_failure_segment == "segment-000002.chain"


def test_a_later_segment_that_names_no_predecessor_does_not_fit(tmp_path):
    a, _, _ = _three()
    b = _segment("seg-b")                                # a fresh start
    b.seal("close")
    log = _write(tmp_path / "hook", a, b)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "CONTEXT_MISMATCH"
    assert report.first_failure_segment == "segment-000002.chain"


def test_a_segment_that_fails_is_the_logs_failure(tmp_path):
    a, b, c = _three()
    line = bytearray(b.lines[2])
    line[line.index(b"e2")] = ord("E")                   # edit b's in_flight
    b.lines[2] = bytes(line)
    log = _write(tmp_path / "hook", a, b, c)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "HASH_LINK_MISMATCH"
    assert report.first_failure_segment == "segment-000002.chain"
    assert dict(report.segments)["segment-000001.chain"].results[
        "chain_integrity"] == "CHAIN_OK"


def test_a_call_that_died_leaves_its_segment_unverified_and_only_that_one(tmp_path):
    """Spec vector 18: rows with no close checkpoint, then the next call opens a
    new segment naming the last checkpoint that verifies."""
    a = _segment("seg-a")
    a.call("e1")
    a.seal("close")
    named = _names(a)
    a.call("e2")                                         # died: never sealed
    b = _segment("seg-b", previous=named, observed_unsigned=2)
    b.call("e3")
    b.seal("close")
    log = _write(tmp_path / "hook", a, b)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["unsigned_tail"] == "UNVERIFIED_TAIL"
    tails = {name: s.results["unsigned_tail"] for name, s in report.segments}
    assert tails == {"segment-000001.chain": "UNVERIFIED_TAIL",
                     "segment-000002.chain": "NO_VISIBLE_TAIL"}


def test_an_item_that_spans_a_rotation_is_complete(tmp_path):
    """Lifecycle is judged over the log's verified prefixes in order, so a
    proxy item opened before a size rotation and settled after it pairs."""
    a = _segment("seg-a")
    a.event("in_flight", eval_id="x")
    a.seal("close")
    b = _segment("seg-b", previous=_names(a))
    b.event("decision", eval_id="x")
    b.seal("close")
    log = _write(tmp_path / "proxy", a, b)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["lifecycle"] == "LIFECYCLE_COMPLETE"
    assert dict(report.segments)["segment-000001.chain"].results[
        "lifecycle"] == "LIFECYCLE_ORPHAN"


def test_an_item_never_settled_is_an_orphan_of_the_log(tmp_path):
    a = _segment("seg-a")
    a.event("in_flight", eval_id="x")
    a.seal("close")
    b = _segment("seg-b", previous=_names(a))
    b.seal("close")
    log = _write(tmp_path / "proxy", a, b)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["lifecycle"] == "LIFECYCLE_ORPHAN"


def test_a_retained_endpoint_is_found_in_its_own_segment(tmp_path):
    a, b, c = _three()
    log = _write(tmp_path / "hook", a, b, c)
    endpoint = _names(b)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP,
                               expected_endpoint=endpoint)
    assert report.results["expected_endpoint"] == "ENDPOINT_CONFIRMED"
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP,
                               expected_endpoint=dict(endpoint, hash="0" * 64))
    assert report.results["expected_endpoint"] == "CHECKPOINT_MISMATCH"


def test_an_empty_log_has_no_genesis(tmp_path):
    (tmp_path / "hook").mkdir()
    report = verify.verify_log(tmp_path / "hook", PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "MISSING_GENESIS"
    assert report.segments == []


def test_each_log_is_verified_alone(tmp_path):
    """Spec vector 17: two logs, five results each; deleting one does not move
    the other's integrity."""
    hook = _write(tmp_path / "hook", *_three())
    a = _segment("proxy-a")
    a.call("p1")
    a.seal("close")
    proxy = _write(tmp_path / "proxy-srv", a)
    before = _results(verify.verify_log(hook, PUBLIC, expected_fingerprint=FP))
    assert _results(verify.verify_log(proxy, PUBLIC, expected_fingerprint=FP)) == LOG_OK
    shutil.rmtree(proxy)
    assert _results(verify.verify_log(hook, PUBLIC, expected_fingerprint=FP)) == before


def test_the_render_prints_the_log_then_each_segment_and_no_summary(tmp_path):
    log = _write(tmp_path / "hook", *_three())
    text = verify.render_log(verify.verify_log(log, PUBLIC, expected_fingerprint=FP))
    for kind in codes.RESULT_KINDS:
        assert text.count(f"{kind}: ") == 4              # the log + 3 segments
    assert "segment-000002.chain" in text
    for word in ("PASS", "VALID", "clean", "verified OK"):
        assert word not in text


def test_the_writers_own_rotation_verifies_as_one_log(tmp_path):
    import chain
    import keys
    keys.init(tmp_path)
    signer = keys.load(tmp_path)
    log = tmp_path / "receipts" / "chain"
    writer = chain.Chain(log, signer, producer="hook", max_records=12)
    for n in range(10):
        writer.write([{"event": "in_flight", "body": {"eval_id": str(n)}},
                      {"event": "decision", "body": {"eval_id": str(n)}}],
                     seal="close")
    assert len(list(log.glob("segment-*.chain"))) > 2
    public = keys.public_path(tmp_path, signer.fingerprint).read_bytes()
    report = verify.verify_log(log, public, expected_fingerprint=signer.fingerprint)
    assert _results(report) == LOG_OK


# --- 12 · rotation: specified, not built (T9 ruling 40) -----------------------

def _rotated():
    """A log whose second segment names the first's last checkpoint, as a
    rotation would, and is signed by a different key."""
    a = _segment("seg-a")
    a.call("e1")
    a.seal("close")
    b = _segment("seg-b", previous=_names(a), seed=OTHER_SEED)
    b.call("e2")
    b.seal("close")
    return a, b


def test_a_segment_under_another_key_names_the_rotation_limit(tmp_path):
    log = _write(tmp_path / "hook", *_rotated())
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "ROTATION_UNSUPPORTED"
    assert report.first_failure_segment == "segment-000002.chain"
    assert codes.strict_exit_code(report.results) == 1
    # The first segment, under the supplied key, is still judged on its own.
    assert dict(report.segments)["segment-000001.chain"].results[
        "chain_integrity"] == "CHAIN_OK"


def test_the_control_the_same_log_under_one_key_is_one_log(tmp_path):
    a, _ = _rotated()
    b = _segment("seg-b", previous=_names(a))
    b.call("e2")
    b.seal("close")
    log = _write(tmp_path / "hook", a, b)
    assert _results(verify.verify_log(log, PUBLIC, expected_fingerprint=FP)) == LOG_OK


def test_a_first_segment_under_another_key_is_still_a_context_mismatch(tmp_path):
    """No predecessor named, so nothing claims a transition: not rotation."""
    c = _segment("seg-a", seed=OTHER_SEED)
    c.call("e1")
    c.seal("close")
    log = _write(tmp_path / "hook", c)
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "CONTEXT_MISMATCH"


@pytest.mark.xfail(strict=True, reason=(
    "Spec vector 12. Rotation is specified, not built and not claimed (T9 "
    "ruling 40): the verifier prints ROTATION_UNSUPPORTED. This row is the "
    "target, and it turns strict-xpass the day rotation is built."))
def test_12_rotation_with_the_old_key_absent_is_successor_asserted(tmp_path):
    log = _write(tmp_path / "hook", *_rotated())
    report = verify.verify_log(log, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "SUCCESSOR_ASSERTED"


# --- the exported log vectors (VECTORS.json "verifier_logs"), replayed -------

def _log_vectors():
    import json
    return json.loads((HERE.parent / "VECTORS.json").read_text())["verifier_logs"]


@pytest.mark.parametrize("vector", _log_vectors(), ids=lambda v: v["id"])
def test_every_exported_log_vector_replays(tmp_path, vector):
    public = bytes.fromhex(vector["public_hex"])
    for name, segments in vector["logs"].items():
        log = tmp_path / name
        log.mkdir()
        for seg in segments:
            (log / seg["name"]).write_bytes(bytes.fromhex(seg["data_hex"]))
    for name, want in vector["expect"].items():
        report = verify.verify_log(tmp_path / name, public,
                                   expected_fingerprint=vector["expected_fingerprint"])
        assert _results(report) == want["results"]
        assert report.first_failure_segment == want["first_failure_segment"]
        if "segments" in want:
            assert {n: _results(s) for n, s in report.segments} == want["segments"]
