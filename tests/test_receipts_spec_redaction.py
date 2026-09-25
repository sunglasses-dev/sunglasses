"""WIRE_SPEC "Redaction: what is never signed" names what the code does.

The section is prose, so it drifts the day a field is added to an allowlist or
the never list. These rows hold its named lists equal to the code's: every
forbidden proxy field and every hook allowlist field appears in the section,
and the section names no hook field the code does not carry.
"""
import pathlib
import re

from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.receipts import hook_rows

SPEC = pathlib.Path(proxy_receipts.__file__).resolve().parents[1] / "receipts" / "WIRE_SPEC.md"


def _section():
    text = SPEC.read_text(encoding="utf-8")
    return text.split("## Redaction: what is never signed", 1)[1].split("\n## ", 1)[0]


def _named(part):
    return set(re.findall(r"`([a-z_0-9]+)`", part))


def test_the_spec_names_every_field_the_proxy_never_signs():
    never = _section().split("The never list", 1)[1].split("\n- ", 1)[0]
    assert _named(never) == set(proxy_receipts.FORBIDDEN_FIELDS)


def test_the_spec_names_exactly_the_hook_allowlist():
    hook = _section().split("**The hook**", 1)[1].split("**The proxy**", 1)[0]
    allowlist = hook.split("An allowlist", 1)[1].split("\n- ", 1)[0]
    # `decision` is both the terminal event and a field of it.
    assert _named(allowlist) - {"in_flight"} == set(hook_rows._DECISION)


def test_the_spec_names_what_the_hook_adds_after_the_allowlist():
    hook = _section().split("**The hook**", 1)[1].split("**The proxy**", 1)[0]
    body = hook_rows.decision(
        {"elapsed_ms": 1.5, "pin_state_age_s": 2.5, "unknown_field": 1,
         "Bad Name": 1, "input_sha256": None, "input_sha256_reason": "unencodable",
         "cleared_canaries": [{"rule_id": "GLS-X-1", "fingerprint": "sha256:" + "0" * 8}]},
        error_types=["ValueError"])
    assert set(body) - set(hook_rows._DECISION) <= _named(hook)
    assert {"elapsed_us", "error_types", "withheld", "withheld_unnamed",
            "input_digest"} <= set(body)
