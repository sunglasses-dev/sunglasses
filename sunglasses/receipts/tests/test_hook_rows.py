"""Hook rows into chained bodies (spec §1 + §5, T9 RULING 11 Q3): an allowlist,
value-checked, integers only, and the error's CLASS NAME only -- its message
never reaches a signed byte."""
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import hook_rows                                           # noqa: E402
import wire                                                # noqa: E402

EVAL = "0123456789abcdef"
DIGEST = "a" * 64


def _decision(**extra):
    row = {"ts": "2026-09-24T00:00:00", "kind": "decision", "eval_id": EVAL,
           "tool_name": "Bash", "session_id": "s-1", "decision": "deny",
           "lane": "deterministic", "rule_id": "GLS-FW-SEC-AWS",
           "input_sha256": DIGEST, "elapsed_ms": 1.25}
    row.update(extra)
    return row


def test_an_in_flight_row_keeps_its_pairing_fields():
    body = hook_rows.in_flight({"ts": "x", "kind": "in_flight", "eval_id": EVAL,
                                "tool_name": "Bash", "session_id": "s-1",
                                "input_sha256": DIGEST})
    assert body == {"eval_id": EVAL, "tool_name": "Bash", "session_id": "s-1",
                    "input_sha256": DIGEST}


def test_a_decision_row_is_integers_only():
    body = hook_rows.decision(_decision(pin_state_age_s=12.7))
    assert body["elapsed_us"] == 1250 and "elapsed_ms" not in body
    assert body["pin_state_age_s"] == 12
    wire.encode({"body": body})                            # no float survives


def test_the_error_message_never_reaches_the_body():
    """Q3: an exception message may quote the value that caused it."""
    secret = "AKIAIOSFODNN7EXAMPLE"
    body = hook_rows.decision(_decision(error=f"ValueError: bad {secret!r}",
                                        degraded=True),
                              error_types=["ValueError"])
    assert body["error_types"] == ["ValueError"]
    assert body["degraded"] is True
    assert secret not in repr(body) and "error" not in body
    assert "withheld" not in body              # dropped by rule, not by failure


def test_an_error_type_must_be_a_class_name():
    body = hook_rows.decision(_decision(), error_types=["ValueError: leaked"])
    assert "error_types" not in body
    assert body["withheld"] == ["error_types"]


@pytest.mark.parametrize("field,value", [
    ("eval_id", "not-hex"),
    ("decision", "maybe"),
    ("lane", "sideways"),
    ("rule_id", "GLS-FW-X; rm -rf"),
    ("input_sha256", "zz"),
    ("tool_name", "Bash\x1b[2J"),
    ("policy_state", "Broken State!"),
    ("pin_checked_at", "yesterday <script>"),
])
def test_a_value_that_fails_its_grammar_is_withheld_and_named(field, value):
    body = hook_rows.decision(_decision(**{field: value}))
    assert field not in body
    assert body["withheld"] == [field]


def test_an_unknown_field_is_withheld_and_named():
    body = hook_rows.decision(_decision(payload_excerpt="the secret itself"))
    assert "payload_excerpt" not in body
    assert body["withheld"] == ["payload_excerpt"]
    assert "the secret itself" not in repr(body)


@pytest.mark.parametrize("name", ["AKIA\x1bname", "name\x1b[2J", "name with space"])
def test_an_unknown_field_with_a_hostile_name_is_counted_not_named(name):
    body = hook_rows.decision(_decision(**{name: 1}))
    assert body["withheld_unnamed"] == 1
    assert "withheld" not in body


def test_a_flag_is_carried_only_when_true():
    body = hook_rows.decision(_decision(degraded=False, fuzzy_lane=1))
    assert "degraded" not in body and "fuzzy_lane" not in body
    assert body["withheld"] == ["degraded", "fuzzy_lane"]


@pytest.mark.parametrize("ms", ["1.25", True, -1, float("nan")])
def test_an_elapsed_that_is_not_a_duration_is_withheld(ms):
    body = hook_rows.decision(_decision(elapsed_ms=ms))
    assert "elapsed_us" not in body
    assert body["withheld"] == ["elapsed_ms"]


def test_a_cleared_canary_keeps_its_rule_and_fingerprint_only():
    cleared = [{"rule_id": "GLS-FW-SEC-AWS", "fingerprint": "sha256:" + "f" * 16, "name": "AWS key",
                "reason": "cleared by KNOWN_PUBLIC_CANARIES: ..."}]
    body = hook_rows.decision(_decision(cleared_canaries=cleared))
    assert body["cleared_canaries"] == [{"rule_id": "GLS-FW-SEC-AWS",
                                         "fingerprint": "sha256:" + "f" * 16}]


def test_an_unencodable_input_is_null_with_its_reason():
    body = hook_rows.decision(_decision(input_sha256=None,
                                        input_sha256_reason="unencodable"))
    assert body["input_sha256"] is None
    assert body["input_digest"] == "UNENCODABLE"


def test_every_body_encodes():
    rows = [_decision(), _decision(degraded=True, fuzzy_lane=True,
                                   pin_source="pin_state", pin_reach="pinned",
                                   pin_state_stale=True,
                                   pin_checked_at="2026-09-24T00:00:00+00:00")]
    for row in rows:
        wire.encode({"body": hook_rows.decision(row)})
