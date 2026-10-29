"""The words "a tool result is the api_response channel" match what the code does.

`scan --channel tool_output` is a documented channel, and a reader could take it for the
channel a tool's output is scanned under. It is not: no credential rule is declared on it. The
MCP proxy reads a tool result as `api_response`, and the `-API` credential rules are declared
there. The help text and the README say so, and this test compares those words with the rules
and the proxy, so either side moving makes the test fail until the other is updated.
"""
import subprocess
import sys

from sunglasses.engine import SunglassesEngine
from sunglasses.proxy import selector

_SENTENCE = "A tool result is the api_response channel"


def _credential_rules():
    engine = SunglassesEngine()
    return [p for p in engine._patterns if p["id"].startswith("GLS-SD-")]


def test_help_text_carries_the_sentence():
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses", "scan", "--help"],
        capture_output=True, text=True, timeout=120,
    )
    assert _SENTENCE in " ".join(proc.stdout.split())


def test_readme_carries_the_sentence():
    import pathlib

    readme = (pathlib.Path(__file__).resolve().parent.parent / "README.md").read_text()
    assert "A tool result is the `api_response` channel" in " ".join(readme.split())


def test_the_proxy_reads_a_tool_result_as_api_response():
    assert selector._RESULT_CHANNEL["tools/call"] == selector.API_RESPONSE == "api_response"


def test_the_api_credential_rules_are_declared_on_api_response():
    api_rules = [p for p in _credential_rules() if p["id"].endswith("-API")]
    assert api_rules, "no -API credential rules found"
    for p in api_rules:
        assert "api_response" in p["channel"], p["id"]


def test_no_credential_rule_is_declared_on_tool_output():
    declared = [p["id"] for p in _credential_rules() if "tool_output" in p["channel"]]
    assert declared == [], (
        f"credential rules now declared on tool_output: {declared}. The help text and the "
        "README say none are; update them (and the CHANGELOG line) with the rule change."
    )
