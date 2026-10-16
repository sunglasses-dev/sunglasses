"""The driver's own controls: every outcome branch, the mutants that must not survive, the lock,
the atomic write, the refusal and the rule that it cannot spend.

The classifier is the one place a wrong `passed` can be minted, so each branch has a test and
each guard in it has a MUTANT: the source is rewritten in memory with one guard removed and the
test that guards it must go red against the rewrite. A test that stays green against its own
mutant was not testing the guard (the Sep-13 law, and the reason `guard_sweep.py` exists).
"""
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import types

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "boundary"))

import drive                                               # noqa: E402
import produce                                             # noqa: E402
import schema                                              # noqa: E402

SOURCE = pathlib.Path(drive.__file__).read_text()


def R(assertions=()):
    return types.SimpleNamespace(assertions=list(assertions))


def mutant(old: str, new: str):
    """drive.py with ONE guard rewritten. Aborts if the rewrite did not apply, because a mutant
    that changed nothing would pass every test for the most boring reason."""
    assert SOURCE.count(old) == 1, f"the mutation does not apply exactly once: {old!r}"
    module = types.ModuleType("drive_mutant")
    module.__file__ = drive.__file__
    exec(compile(SOURCE.replace(old, new), "drive_mutant", "exec"), module.__dict__)
    return module


# --- one check per guard, each run against the real module and against its mutant -------------

def check_passed_needs_a_subject_and_a_proven_stimulus(d):
    assert d.classify_run(R(), True, True, False)[0] == "passed"
    assert d.classify_run(R([{"op": "x", "held": True}]), True, None, None)[0] == "passed"


def check_unproven_stimulus_is_never_a_pass(d):
    assert d.classify_run(R([{"op": "x", "held": True}]), None, True, False)[:2] == (
        "refused", "EXEC_OBSERVER_ABSENT")
    assert d.classify_run(R([{"op": "x", "held": True}]), False, True, False)[0] == "refused"


def check_payload_reaching_the_client_is_failed_not_passed(d):
    assert d.classify_run(R(), True, True, True)[:2] == ("failed", "EXEC_CONTRADICTED")


def check_zero_subject_is_refused_not_passed(d):
    assert d.classify_run(R(), True, None, None)[0] == "refused"
    assert d.classify_run(R([{"op": "x", "held": None}]), True, None, None)[0] == "refused"


def check_a_harness_stall_is_refused_even_with_held_true(d):
    assert d.classify_run(R([{"op": "x", "held": True}, {"op": "harness_stall", "held": None}]),
                          True, True, False)[0] == "refused"


def check_payload_in_finds_raw_and_json_escaped_and_none_without_payload(d):
    payload = b"A\nB"
    assert d.payload_in(b'{"m":"A\\nB"}', payload) is True
    assert d.payload_in(b"A\nB", payload) is True
    assert d.payload_in(b'{"m":"other"}', payload) is False
    assert d.payload_in(b"x", b"") is None


@pytest.mark.parametrize("check", [
    check_passed_needs_a_subject_and_a_proven_stimulus,
    check_unproven_stimulus_is_never_a_pass,
    check_payload_reaching_the_client_is_failed_not_passed,
    check_zero_subject_is_refused_not_passed,
    check_a_harness_stall_is_refused_even_with_held_true,
    check_payload_in_finds_raw_and_json_escaped_and_none_without_payload,
], ids=lambda f: f.__name__)
def test_the_real_driver_passes_every_branch(check):
    check(drive)


# Each mutant removes ONE guard. The named check must fail against it.
MUTANTS = [
    ("control gate removed", "    if control_delivered is not True:\n        return \"refused\"",
     "    if False:\n        return \"refused\"", check_unproven_stimulus_is_never_a_pass),
    ("payload needle removed", "    return any(n and n in wire for n in needles)", "    return False",
     check_payload_in_finds_raw_and_json_escaped_and_none_without_payload),
    ("seed expectation ignored", "(expect_absent is True and payload_in_strict is True)",
     "(False and payload_in_strict is True)", check_payload_reaching_the_client_is_failed_not_passed),
    ("harness stall ignored", "    stalled = any(a.get(\"op\") == \"harness_stall\" for a in run.assertions)",
     "    stalled = False", check_a_harness_stall_is_refused_even_with_held_true),
    ("zero subject counted as held", "    if not held_true:\n        return \"refused\", \"EXEC_OBSERVER_ABSENT\", evidence\n    return \"passed\"",
     "    if False:\n        return \"refused\", \"EXEC_OBSERVER_ABSENT\", evidence\n    return \"passed\"",
     check_zero_subject_is_refused_not_passed),
]


@pytest.mark.parametrize("name,old,new,check", MUTANTS, ids=[m[0] for m in MUTANTS])
def test_each_mutant_is_caught(name, old, new, check):
    broken = mutant(old, new)
    with pytest.raises(AssertionError):
        check(broken)


# --- the rest of the classifier ---------------------------------------------------------------

def test_a_false_assertion_is_failed():
    assert drive.classify_run(R([{"op": "x", "held": False}]), True, None, None)[0] == "failed"


def test_original_expected_but_not_delivered_is_failed_and_delivered_is_passed():
    assert drive.classify_run(R(), True, False, None, True, False)[:2] == ("failed", "EXEC_CONTRADICTED")
    assert drive.classify_run(R(), True, False, None, True, True)[0] == "passed"
    assert drive.classify_run(R(), True, False, None, True, None)[0] == "refused"


def test_client_origin_absence_is_graded_at_the_upstream_destination():
    assert drive.classify_run(R(), True, True, True, None, None, "client")[0] == "failed"
    out = drive.classify_run(R(), True, True, False, None, None, "client")
    assert out[0] == "passed" and "payload_absent_at_destination(client)" in out[2]["held"]


def test_absence_is_graded_only_when_the_control_saw_the_payload():
    assert drive.classify_run(R(), False, True, False, None, None, "upstream")[0] == "refused"


# --- determinism keys -------------------------------------------------------------------------

def test_normalise_drops_clocks_ids_and_nested_json_clocks_but_keeps_facts():
    a = {"kind": "RPC_EGRESS", "at": 1, "mono": 5, "pid": 9,
         "raw": '{"id":1,"error":{"elapsed_ms":1.5,"code":-32070}}'}
    b = {"kind": "RPC_EGRESS", "at": 2, "mono": 8, "pid": 7,
         "raw": '{"id":1,"error":{"elapsed_ms":1584.7,"code":-32070}}'}
    c = {"kind": "RPC_EGRESS", "at": 2, "mono": 8, "pid": 7,
         "raw": '{"id":1,"error":{"elapsed_ms":1.5,"code":-32001}}'}
    assert drive.normalise(a) == drive.normalise(b)
    assert drive.normalise(a) != drive.normalise(c)          # a changed code is a changed fact


def test_stable_record_digest_ignores_time_and_volatile_but_not_the_outcome():
    r = {"variant_id": "x", "outcome": "passed", "started_at": "1", "finished_at": "2",
         "volatile": {"b": 1}}
    assert drive.stable_record_digest(r) == drive.stable_record_digest(
        dict(r, started_at="9", volatile={"b": 2}))
    assert drive.stable_record_digest(r) != drive.stable_record_digest(dict(r, outcome="failed"))


def test_run_root_inside_a_request_is_normalised_so_two_runs_hash_equal():
    a = b'{"path":"/private/tmp/drv-aaa-proxy_strict/drop/effect.bin","id":1}\n'
    b = b'{"path":"/private/tmp/drv-bbb-proxy_strict/drop/effect.bin","id":1}\n'
    assert drive.stable_digest_of(a, True, pathlib.Path("/private/tmp/drv-aaa-proxy_strict")) == \
        drive.stable_digest_of(b, True, pathlib.Path("/private/tmp/drv-bbb-proxy_strict"))
    assert drive.stable_digest_of(a, True) != drive.stable_digest_of(b, True)


# --- the lock, never forced -------------------------------------------------------------------

def test_lock_is_taken_with_an_owner_file_and_removed_on_exit(tmp_path):
    path = tmp_path / ".heavy-run.lock"
    with drive.Lock(path, owner="a test"):
        assert path.is_dir() and "a test" in (path / "owner").read_text()
    assert not path.exists()


def test_lock_removed_even_when_the_loop_raises(tmp_path):
    path = tmp_path / ".heavy-run.lock"
    with pytest.raises(RuntimeError):
        with drive.Lock(path):
            raise RuntimeError("the loop died")
    assert not path.exists()


def test_a_lock_held_by_someone_else_is_polled_then_refused_and_never_forced(tmp_path):
    path = tmp_path / ".heavy-run.lock"
    path.mkdir()
    (path / "owner").write_text("someone else\n")
    with pytest.raises(drive.Refusal):
        with drive.Lock(path, wait_seconds=0, poll_seconds=0):
            pytest.fail("entered a lock that someone else holds")
    assert (path / "owner").read_text() == "someone else\n", "the other holder's lock was touched"


def test_no_lock_configured_means_no_lock(tmp_path):
    with drive.Lock(None) as lock:
        assert lock.held is False


# --- the atomic write, the refusal, the exit codes --------------------------------------------

def test_write_is_atomic_a_crash_leaves_no_file_and_no_temp(tmp_path, monkeypatch):
    target = tmp_path / "execution_run.json"

    def boom(*_):
        raise OSError("disk went away")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        drive.write_atomic(target, {"a": 1})
    assert not target.exists() and list(tmp_path.iterdir()) == []


def test_write_replaces_a_previous_document_whole(tmp_path):
    target = tmp_path / "execution_run.json"
    drive.write_atomic(target, {"a": 1})
    drive.write_atomic(target, {"b": 2})
    assert json.loads(target.read_text()) == {"b": 2}


def test_an_unreadable_corpus_is_exit_3_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(produce, "MATERIALISED", tmp_path / "absent")
    out = tmp_path / "execution_run.json"
    assert drive.main(["--out", str(out)]) == 3
    assert not out.exists()


def test_a_held_lock_is_exit_3_and_writes_nothing(tmp_path, monkeypatch):
    lock = tmp_path / ".heavy-run.lock"
    lock.mkdir()
    monkeypatch.setenv(drive.LOCK_ENV, str(lock))
    monkeypatch.setattr(drive, "LOCK_WAIT_SECONDS", 0)
    monkeypatch.setattr(produce, "plan_corpus", lambda: {"drivable": ["G2-00.x"], "blocked": {}, "invalid": {}})
    monkeypatch.setattr(produce, "_digest_tree", lambda root: "0" * 64)
    out = tmp_path / "execution_run.json"
    assert drive.main(["--out", str(out)]) == 3
    assert not out.exists() and lock.is_dir()


# --- the run document -------------------------------------------------------------------------

def _record(variant_id, outcome="passed"):
    return {"record_schema": 1, "variant_id": variant_id, "outcome": outcome}


def test_run_document_binds_records_counts_and_ledger_header():
    records = [_record("b.x", "failed"), _record("a.x", "passed"), _record("c.x", "refused")]
    doc = drive.build_run_doc(records, started_at="2026-10-05T00:00:00+00:00", corpus_digest="d" * 64,
                              run_id="t")
    header = doc["header"]
    assert [r["variant_id"] for r in doc["records"]] == ["a.x", "b.x", "c.x"]
    assert header["counts"] == {"passed": 1, "failed": 1, "refused": 1, "errored": 0}
    assert header["records_digest"] == schema.records_digest(records)
    assert header["ledger"] == {"scope": "no_live_calls_standin_run", "unit": schema.LEDGER_UNIT,
                                "charges": 0}
    assert (header["route"], header["implementation_kind"]) == ("proxy_strict", "harness_stand_in")


def test_records_digest_does_not_depend_on_input_order():
    one, two = _record("a.x"), _record("b.x", "failed")
    assert schema.records_digest([one, two]) == schema.records_digest([two, one])
    assert schema.records_digest([one, two]) != schema.records_digest([one, _record("b.x", "passed")])


# --- it cannot spend --------------------------------------------------------------------------

def test_the_driver_has_no_way_to_make_a_live_call():
    """The nightly ledger line says no live calls, and it is zero by construction. Keep it so: no
    network client, no model client, no ledger. The git head lookup is the only subprocess."""
    imports = set(re.findall(r"^\s*(?:import|from)\s+([\w.]+)", SOURCE, re.M))
    forbidden = {"urllib", "urllib.request", "http", "http.client", "requests", "socket", "ssl",
                 "anthropic", "openai", "runner_ledger"}
    assert not (imports & forbidden), imports & forbidden
    assert re.search(r"\bLedger\b", SOURCE) is None
    assert drive.LIVE_CALLS == 0


# --- one real variant, end to end -------------------------------------------------------------

def _corpus_readable():
    try:
        return produce.MATERIALISED.is_dir() and any(produce.MATERIALISED.iterdir())
    except OSError:
        return False


@pytest.mark.skipif(not _corpus_readable(), reason="the pinned corpus is not readable from this account")
def test_one_real_variant_is_driven_twice_and_the_record_is_deterministic():
    # The adapter refuses a run root anywhere but /private/tmp, so the pytest tmp_path will not do.
    parent = pathlib.Path(tempfile.mkdtemp(dir="/private/tmp", prefix="drvtest-"))
    try:
        _one_variant_twice(parent)
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def _one_variant_twice(tmp_path):
    planned = produce.plan_corpus()
    assert planned["drivable"], "the planner found nothing drivable"
    variant_id = sorted(planned["drivable"])[0]
    first = drive.drive_one(variant_id, drive.REPO, tmp_path)
    second = drive.drive_one(variant_id, drive.REPO, tmp_path)
    for record in (first, second):
        assert record["outcome"] in schema.EXEC_STATES and record["outcome"] != "not_run"
        assert record["route"] == "proxy_strict" and record["implementation_kind"] == "harness_stand_in"
        assert re.fullmatch(r"[0-9a-f]{40}", record["harness_head"])
        assert "control" in record and record["delivered_digest"]
        if record["outcome"] != "passed":
            assert record["reason_code"] in schema.REASON_CODES
    assert first["stable_record_digest"] == second["stable_record_digest"]
    assert list(tmp_path.iterdir()) == [], "a run directory was left behind"
