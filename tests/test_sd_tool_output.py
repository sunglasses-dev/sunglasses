"""The credential rules on `tool_output`: what a tool prints, scanned as a tool result.

The eight `-API` rules and the JWT rule are declared on `tool_output` as well as
`api_response`. The 104-document clean corpora measured four hits, all on the secret-scanner
documents that already hit on `api_response`, and no decision changed. NO CORPUS OF REAL TOOL
OUTPUT EXISTS in this repository, so the false-positive exposure on real tool results is
unmeasured; the near misses below are the common high-entropy shapes a tool prints that are not
keys, not a measurement of the field.

Three properties:

  1. the same bytes get the same answer on `tool_output` as on `api_response`
  2. the shapes a tool prints that are NOT keys stay clean
  3. the parents are untouched: no other credential rule reaches `tool_output`

NOT ONE CREDENTIAL-SHAPED LITERAL IS STORED HERE. Values are assembled at import time from the
fragments in `sd_api_sibling_rows`, for the reason that file gives.
"""
import pathlib
import string
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.engine import SunglassesEngine          # noqa: E402
from sunglasses.patterns import PATTERNS                 # noqa: E402
import sd_api_sibling_rows as rows                       # noqa: E402

_JWT = ("ey" + "J" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJ1c2VyIn0" + "."
        + rows._fill(rows._LOWER, 24))


def cat_env(token):
    return "$ cat .env\nDATABASE_URL=postgres://db.internal/app\nSERVICE_KEY=" + token + "\nDEBUG=false\n"


def configure_list(token):
    return ("      Name                    Value             Type    Location\n"
            "      ----                    -----             ----    --------\n"
            "access_key     ****************" + token[-4:] + " shared-credentials-file\n"
            "   raw_value=" + token + "\n")


def git_diff(token):
    return ("diff --git a/config.py b/config.py\n--- a/config.py\n+++ b/config.py\n"
            "@@ -1,2 +1,3 @@\n import os\n+API_TOKEN = \"" + token + "\"\n")


TOOL_CARRIERS = {"cat_env": cat_env, "configure_list": configure_list, "git_diff": git_diff}

TOKENS = dict(rows.TOKENS)
TOKENS["GLS-SD-005"] = _JWT


def _decision_ids(engine, text, channel):
    result = engine.scan(text, channel=channel)
    return result.decision, sorted(f["id"] for f in result.findings if f["id"].startswith("GLS-SD-"))


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


@pytest.mark.parametrize("rule_id", sorted(TOKENS))
@pytest.mark.parametrize("carrier", sorted(TOOL_CARRIERS))
def test_a_credential_in_tool_output_blocks_like_api_response(engine, rule_id, carrier):
    text = TOOL_CARRIERS[carrier](TOKENS[rule_id])
    out_decision, out_ids = _decision_ids(engine, text, "tool_output")
    api_decision, api_ids = _decision_ids(engine, text, "api_response")
    assert out_ids, f"{carrier}/{rule_id}: no credential rule fired on tool_output"
    assert (out_decision, out_ids) == (api_decision, api_ids), (
        "the same bytes must get the same answer on tool_output and api_response")
    assert out_decision == "block"


_HEX40 = "9fceb02d0ae598e95dc970b74767f19372d61af8"
_HEX64 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_B64 = ("TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz"
        "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLg==")
NEAR_MISSES = [
    "commit " + _HEX40 + "\nAuthor: dev <dev@example.org>\n",
    "request_id: 3f2b8c1e-5d4a-4e7b-9c1d-2a6f8e0b7d34",
    "sha256:" + _HEX64,
    "integrity sha512-" + _B64 + " (lodash 4.17.21)",
    "requests==2.31.0 \\\n    --hash=sha256:" + _HEX64,
    "payload (base64): " + _B64,
    "arn:aws:iam::123456789012:role/deploy-role",
    "Account: 123456789012  Region: us-east-1  User: deploy-bot",
    "ERROR 500 at 2026-11-06T21:50:11Z trace=" + _HEX40[:32],
    "Rotate your credential every 90 days as a matter of policy.",
]


@pytest.mark.parametrize("text", NEAR_MISSES)
def test_what_a_tool_prints_that_is_not_a_key_stays_clean(engine, text):
    decision, ids = _decision_ids(engine, text, "tool_output")
    assert not ids, f"{ids} fired on a non-key shape on tool_output: {text[:60]!r}"


_TOOL_RESULT_RULES = sorted([p["id"] for p in PATTERNS
                             if p["id"].startswith("GLS-SD-") and p["id"].endswith("-API")]
                            + ["GLS-SD-005"])


def test_exactly_the_tool_result_rules_reach_tool_output():
    declared = sorted(p["id"] for p in PATTERNS
                      if p["id"].startswith("GLS-SD-") and "tool_output" in p["channel"])
    assert declared == _TOOL_RESULT_RULES
    assert len(declared) == 10


@pytest.mark.parametrize("parent", ["GLS-SD-001", "GLS-SD-002", "GLS-SD-003", "GLS-SD-004",
                                    "GLS-SD-006", "GLS-SD-007", "GLS-SD-008", "GLS-SD-009",
                                    "GLS-SD-010", "GLS-SD-011"])
def test_the_parents_do_not_reach_tool_output(parent):
    by_id = {p["id"]: p for p in PATTERNS}
    assert "tool_output" not in by_id[parent]["channel"], parent


def test_removing_the_ten_reopens_tool_output():
    """With the ten gone, a key printed by a tool is allowed again: this change is what closes it."""
    engine = SunglassesEngine(patterns=[p for p in PATTERNS if p["id"] not in _TOOL_RESULT_RULES])
    for rule_id in sorted(rows.TOKENS):
        text = cat_env(rows.TOKENS[rule_id])
        decision, ids = _decision_ids(engine, text, "tool_output")
        assert not ids and decision != "block", rule_id
