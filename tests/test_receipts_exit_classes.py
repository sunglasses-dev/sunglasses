"""
test_receipts_exit_classes.py — every reason code is ok, fail or limit, and the
exit code is derived from that tag (T9 rulings 46 and 48).

0 means every result is ok. 1 means at least one result is a failure. 3 means
no failure and at least one limit: the verifier could not conclude because the
caller did not supply something, or the feature is specified and not built. 2
stays the CLI's usage exit. `--strict` turns a limit into 1.

A code with no tag is a code whose exit nobody decided, so the enumeration test
goes red the moment one is added to CODES without a class, and a result that is
not a known code at all exits 1. The eight limits are named here one by one,
so moving a code between classes is a red too. NO_LOG, the seventh, is a
`--verify` that found nothing on disk to verify (T9 ruling 53). LOG_UNCHAINED,
the eighth, is a log the home walk found with no chain and nothing to say it
should have one (T9 ruling 60).
"""
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

from sunglasses.receipts import codes

TREE = pathlib.Path(__file__).resolve().parents[1]

LIMITS = {"PAIRING_UNKEYED", "EMPTY_CHAIN", "NO_SESSION", "ROTATION_UNSUPPORTED",
          "KEY_UNTRUSTED", "HISTORY_EXTENT_UNKNOWN", "NO_LOG", "LOG_UNCHAINED"}
OKS = {"KEY_TRUSTED", "CHAIN_OK", "NO_VISIBLE_TAIL", "ENDPOINT_CONFIRMED",
       "LIFECYCLE_COMPLETE"}

PASSING = {"key_trust": "KEY_TRUSTED", "chain_integrity": "CHAIN_OK",
           "unsigned_tail": "NO_VISIBLE_TAIL",
           "expected_endpoint": "ENDPOINT_CONFIRMED",
           "lifecycle": "LIFECYCLE_COMPLETE"}


# ── (a) the enumeration ──────────────────────────────────────────────────────

def test_every_code_carries_exactly_one_tag():
    assert codes.untagged() == []
    assert set(codes.CLASS) == set(codes.CODES)
    assert set(codes.CLASS.values()) <= {codes.OK, codes.FAIL, codes.LIMIT}


def test_the_control_a_code_added_to_the_source_alone_is_found():
    # On the real module, the way a code is actually added: one more entry in
    # the CODES literal and in no class set, then the module runs again. A
    # table built from CODES with a default would tag it and report nothing;
    # patching CODES after import would not rebuild the table at all.
    source = pathlib.Path(codes.__file__).read_text()
    edited = source.replace("CODES = {\n",
                            'CODES = {\n    "NEW_CODE": "a code nobody tagged",\n', 1)
    assert edited != source
    module = {"__name__": "codes_with_one_more_code"}
    exec(compile(edited, codes.__file__, "exec"), module)
    assert "NEW_CODE" in module["CODES"]
    assert module["untagged"]() == ["NEW_CODE"]


def test_the_control_a_code_in_two_sets_is_found():
    table = codes._tag(ok={"CHAIN_OK"}, fail={"CHAIN_OK"})
    assert codes.untagged({"CHAIN_OK": ""}, table) == ["CHAIN_OK"]


def test_the_control_a_new_untagged_code_is_found():
    assert codes.untagged(dict(codes.CODES, NEW_CODE="a code nobody tagged")) == [
        "NEW_CODE"]


def test_the_control_a_tag_outside_the_three_is_found():
    assert codes.untagged(codes.CODES, dict(codes.CLASS, CHAIN_OK="maybe")) == [
        "CHAIN_OK"]


def test_the_control_a_tag_for_a_code_that_does_not_exist_is_found():
    assert codes.untagged(codes.CODES, dict(codes.CLASS, GONE_CODE=codes.FAIL)) == [
        "GONE_CODE"]


@pytest.mark.parametrize("code", sorted(LIMITS))
def test_each_of_the_eight_limits_is_a_limit(code):
    assert codes.CLASS[code] == codes.LIMIT


def test_the_limit_class_is_exactly_the_eight():
    assert {c for c, t in codes.CLASS.items() if t == codes.LIMIT} == LIMITS


def test_the_ok_class_is_the_five_passing_results():
    assert {c for c, t in codes.CLASS.items() if t == codes.OK} == OKS


@pytest.mark.parametrize("code", [
    "UNKNOWN_FIELD", "SEQUENCE_GAP", "LIFECYCLE_ORPHAN", "KEY_UNUSABLE",
    "LEGACY_UNSIGNED", "PREDECESSOR_UNAVAILABLE", "SUCCESSOR_ASSERTED",
    "SUCCESSOR_ENDORSED", "PATH_UNREADABLE", "LOG_MISSING"])
def test_these_are_failures(code):
    assert codes.CLASS[code] == codes.FAIL


def test_the_exits_are_distinct_and_the_limit_is_not_the_usage_exit():
    assert (codes.EXIT_OK, codes.EXIT_FAIL, codes.EXIT_USAGE, codes.EXIT_LIMIT) == (
        0, 1, 2, 3)


# ── (b) the exit table, one code per class, default and strict ───────────────

KIND = {"KEY_UNTRUSTED": "key_trust", "HISTORY_EXTENT_UNKNOWN": "expected_endpoint",
        "ROTATION_UNSUPPORTED": "chain_integrity", "SEQUENCE_GAP": "chain_integrity"}


@pytest.mark.parametrize("code,default,strict", [
    (None, 0, 0),
    ("SEQUENCE_GAP", 1, 1),
    ("UNKNOWN_FIELD", 1, 1),
] + [(code, "limit", 1) for code in sorted(LIMITS)])
def test_the_exit_table(code, default, strict):
    # The limit exit is one constant (T11): a ruling that moves it moves here.
    default = codes.EXIT_LIMIT if default == "limit" else default
    results = dict(PASSING) if code is None else dict(
        PASSING, **{KIND.get(code, "lifecycle"): code})
    assert codes.exit_code(results) == default
    assert codes.exit_code(results, strict=True) == strict
    assert codes.strict_exit_code(results) == strict


@pytest.mark.parametrize("code", sorted(codes.CODES))
def test_strict_never_returns_the_usage_or_limit_exit(code):
    for kind in codes.RESULT_KINDS:
        assert codes.strict_exit_code(dict(PASSING, **{kind: code})) in (0, 1)


def test_a_failure_beside_a_limit_is_a_failure():
    results = dict(PASSING, chain_integrity="SIGNATURE_INVALID",
                   lifecycle="PAIRING_UNKEYED")
    assert codes.exit_code(results) == 1
    assert codes.exit_code(results, strict=True) == 1


def test_a_result_that_is_no_known_code_fails_closed():
    assert codes.exit_code(dict(PASSING, lifecycle="NOT_A_CODE")) == 1


@pytest.mark.parametrize("exits,combined", [
    ([], 0), ([0, 0], 0), ([0, "L"], "L"), (["L", 1], 1), ([1, "L"], 1),
    ([0, "L", 0], "L")])
def test_exits_across_logs_combine_failure_over_limit(exits, combined):
    # max() would make a limit (3) outrank a failure (1).
    limit = codes.EXIT_LIMIT
    exits = [limit if e == "L" else e for e in exits]
    assert codes.combine_exits(*exits) == (limit if combined == "L" else combined)


# ── (c) the spec states the exits, the strict rule and the class test ───────

def test_the_spec_states_the_exits_and_the_strict_rule():
    spec = (TREE / "sunglasses" / "receipts" / "WIRE_SPEC.md").read_text()
    section = spec.split("## Exit codes (T9 rulings 46 and 48)", 1)[1].split(
        "\n## ", 1)[0]
    for row in ("| 0 | every result is ok |",
                "| 1 | at least one result is a failure |",
                "| 2 | a usage error: the command line itself was wrong |",
                "| 3 | no failure, and at least one limit |"):
        assert row in section
    assert "`--strict` counts a limit as a failure" in section
    assert ("LIMIT = verifier could not conclude because the CALLER did not "
            "supply something (fingerprint, endpoint, key, session, log) or the "
            "feature is specified-not-built (R40), log bytes consistent with "
            "clean. FAIL = the log's bytes contradict or lack what they must "
            "carry. Every limit exits non-zero.") in section
    for code in LIMITS:
        assert f"`{code}`" in section
    assert ("`--verify` with nothing on disk to verify prints `NO_LOG` and "
            "exits 3") in section
    assert "(strict exit\n  0)" not in spec


# ── the CLI carries the table ────────────────────────────────────────────────

def _cli(home, *argv):
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", *argv],
                          cwd=TREE, capture_output=True, text=True, env=env)
    return proc.returncode, re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout + proc.stderr)


def test_the_cli_exits_3_on_a_limit_and_1_under_strict(tmp_path):
    """A proxy chain sealed with no HEADER: every result ok except
    lifecycle NO_SESSION, a limit."""
    pytest.importorskip("cryptography")
    from sunglasses.receipts import chain, keys, wire
    home = tmp_path / "home"
    keys.init(home)
    signer = keys.load(home)
    log = home / "receipts" / "proxy-srv"
    chain.Chain(log, signer, producer="proxy").write([], seal="close")
    lines = sorted(log.glob("segment-*.chain"))[-1].read_bytes().splitlines(
        keepends=True)
    last = max(i for i, line in enumerate(lines)
               if wire.decode_strict(line)["event"] == "checkpoint")
    endpoint = json.dumps({"chain_id": wire.decode_strict(lines[0])["chain_id"],
                           "seq": last, "hash": wire.record_hash(lines[last])})
    argv = ("--verify", "--fingerprint", signer.fingerprint, "--endpoint", endpoint)
    code, out = _cli(home, *argv)
    assert "expected_endpoint: ENDPOINT_CONFIRMED" in out, out
    assert "lifecycle: NO_SESSION" in out, out
    assert code == codes.EXIT_LIMIT == 3, out
    code, out = _cli(home, *argv, "--strict")
    assert code == 1, out
    # Without the caller's fingerprint and endpoint: still limits, still 3.
    code, out = _cli(home, "--verify")
    assert "key_trust: KEY_UNTRUSTED" in out, out
    assert code == 3, out
    # A malformed argument stays the usage exit, never a limit.
    code, out = _cli(home, "--verify", "--endpoint", "[1]")
    assert code == 2, out


# ── T9 ruling 53: nothing on disk is a limit, a listing is not a verdict ─────

@pytest.mark.parametrize("code,default,strict", [
    ("KEY_TRUSTED", 0, 0), ("NO_LOG", 3, 1), ("SEQUENCE_GAP", 1, 1),
    ("NOT_A_CODE", 1, 1)])
def test_one_code_standing_alone_exits_by_its_class(code, default, strict):
    assert codes.exit_for(code) == default
    assert codes.exit_for(code, strict=True) == strict


def test_verify_with_nothing_on_disk_is_no_log_a_limit(tmp_path):
    home = tmp_path / "empty-home"
    code, out = _cli(home, "--verify")
    assert "NO_LOG" in out, out
    assert "sunglasses init" in out, out
    assert code == codes.EXIT_LIMIT == 3, out
    code, out = _cli(home, "--verify", "--strict")
    assert "NO_LOG" in out, out
    assert code == 1, out
    assert not home.exists()


def test_the_control_a_listing_with_nothing_on_disk_stays_0(tmp_path):
    # Without --verify no verdict was asked for, so there is none to give.
    code, out = _cli(tmp_path / "empty-home")
    assert "No receipts" in out, out
    assert "NO_LOG" not in out, out
    assert code == 0, out


def _vector_log(tmp_path, vector="17", name="hook"):
    """A multi-segment log from the shipped vectors, its key beside it, and the
    endpoint its last checkpoint commits to, read from the record itself."""
    from sunglasses.receipts import wire
    data = json.loads((TREE / "sunglasses" / "receipts" / "VECTORS.json").read_text())
    v = next(x for x in data["verifier_logs"] if x["id"] == vector)
    log = tmp_path / name
    log.mkdir()
    for seg in v["logs"][name]:
        (log / seg["name"]).write_bytes(bytes.fromhex(seg["data_hex"]))
    (log / f"{v['expected_fingerprint']}.pub").write_bytes(bytes.fromhex(v["public_hex"]))
    lines = b"".join(bytes.fromhex(seg["data_hex"])
                     for seg in v["logs"][name]).splitlines(keepends=True)
    last = [line for line in lines if wire.decode_strict(line)["event"] == "checkpoint"][-1]
    rec = wire.decode_strict(last)
    endpoint = {"chain_id": rec["chain_id"], "seq": rec["seq"],
                "hash": wire.record_hash(last)}
    return log, v["expected_fingerprint"], json.dumps(endpoint), len(v["logs"][name])


def test_a_segment_checked_alone_under_a_confirmed_log_says_so(tmp_path):
    """T9 ruling 53 (O1), display only. Each segment is checked alone, with no
    endpoint; under a log whose endpoint is confirmed that is not an unknown
    extent, and printing HISTORY_EXTENT_UNKNOWN there reads as a contradiction.
    The exit and the segment's own result are unchanged."""
    pytest.importorskip("cryptography")
    log, fp, endpoint, n = _vector_log(tmp_path)
    assert n == 3
    argv = ("--verify", "--log", str(log), "--fingerprint", fp)
    code, out = _cli(tmp_path / "home", *argv, "--endpoint", endpoint, "--strict")
    assert out.count("expected_endpoint: ENDPOINT_CONFIRMED") == 1, out
    assert out.count("expected_endpoint: segment checked alone (no endpoint)") == n, out
    assert "HISTORY_EXTENT_UNKNOWN" not in out, out
    assert code == 0, out
    # The control: with no endpoint the log's extent IS unknown, a limit, and
    # every segment still says HISTORY_EXTENT_UNKNOWN.
    code, out = _cli(tmp_path / "home", *argv)
    assert out.count("expected_endpoint: HISTORY_EXTENT_UNKNOWN") == n + 1, out
    assert "segment checked alone" not in out, out
    assert code == 3, out
