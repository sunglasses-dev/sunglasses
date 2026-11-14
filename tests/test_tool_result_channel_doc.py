"""The words "a tool result is the api_response channel" match what the code does.

`scan --channel tool_output` is a documented channel, and a reader could take it for the
channel a tool's output is scanned under. The credential rules for a tool result are declared
on it as well as on `api_response`: the nine `-API` rules and the JWT rule. The MCP proxy reads
a tool result as `api_response`. The help text and the README say so, and this test compares
those words with the rules and the proxy. It pins four facts: the proxy reads a tool result as
`api_response`, every `-API` credential rule is declared on `api_response`, exactly those rules
plus `GLS-SD-005` are the credential rules declared on `tool_output`, and none of the other
parents is. It also pins the full wording of those clauses in the help text, the README and
the docstring of the CrewAI integration (`_scan_text`, read with `inspect.getdoc`).
It does not pin the complete channel list of any rule.
"""
import subprocess
import sys

from sunglasses.engine import SunglassesEngine
from sunglasses.proxy import selector

_HELP_CLAUSES = (
    "A tool result is the api_response channel",
    "the credential rules for tool results are declared there and on tool_output",
    "releases up to 0.6.19 declared none on tool_output",
)
_README_CLAUSES = (
    "A tool result is the `api_response` channel",
    "`sunglasses scan --channel api_response` runs those rules",
    "`--channel tool_output` runs them too",
    "Releases up to 0.6.19 declared none of the credential rules on `tool_output`",
)

_CREWAI_CLAUSES = (
    "A tool result is the api_response channel",
    "the credential rules for tool results are declared there and on tool_output",
    "releases up to 0.6.19 declared none on tool_output",
)


def _credential_rules():
    engine = SunglassesEngine()
    return [p for p in engine._patterns if p["id"].startswith("GLS-SD-")]


def test_help_text_carries_the_clauses():
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses", "scan", "--help"],
        capture_output=True, text=True, timeout=120,
    )
    text = " ".join(proc.stdout.split())
    for clause in _HELP_CLAUSES:
        assert clause in text, clause


def test_readme_carries_the_clauses():
    import pathlib

    readme = (pathlib.Path(__file__).resolve().parent.parent / "README.md").read_text()
    text = " ".join(readme.split())
    for clause in _README_CLAUSES:
        assert clause in text, clause


def test_crewai_docstring_carries_the_clauses():
    import inspect

    from sunglasses.integrations import crewai

    text = " ".join(inspect.getdoc(crewai._scan_text).split())
    for clause in _CREWAI_CLAUSES:
        assert clause in text, clause
    assert "tool_output does not" not in text


def test_the_proxy_reads_a_tool_result_as_api_response():
    assert selector._RESULT_CHANNEL["tools/call"] == selector.API_RESPONSE == "api_response"


def test_the_api_credential_rules_are_declared_on_api_response():
    api_rules = [p for p in _credential_rules() if p["id"].endswith("-API")]
    assert api_rules, "no -API credential rules found"
    for p in api_rules:
        assert "api_response" in p["channel"], p["id"]


def test_exactly_the_tool_result_credential_rules_are_declared_on_tool_output():
    declared = sorted(p["id"] for p in _credential_rules() if "tool_output" in p["channel"])
    expected = sorted(
        [p["id"] for p in _credential_rules() if p["id"].endswith("-API")] + ["GLS-SD-005"]
    )
    assert len(expected) == 10
    assert declared == expected, (
        f"credential rules declared on tool_output: {declared}; the reviewed set is {expected}. "
        "The help text and the README name this set; update them (and the CHANGELOG line) "
        "with the rule change."
    )
