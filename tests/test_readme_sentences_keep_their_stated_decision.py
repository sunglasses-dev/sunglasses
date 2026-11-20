"""The public README's examples of three shapes keep the outcome the README states.

The examples are read from README.md itself, so a new example written in one of these shapes joins
the gate without an edit here. Shapes read (counted at the time of writing):

  1. "`<sentence>` is flagged as review." / "`<sentence>` is blocked as critical."   2 sentences,
     scanned on the message and file channels (the README names no channel).
  2. The Python integration block: engine.scan("<text>") followed by print(result.decision)  # "x",
     print(result.severity)  # "x" and print(result.is_clean)  # True/False.        1 call, 3 outcomes.
  3. The MCP paragraph: scan_text with {"text": "<text>"} and the sentence that reads its result
     ("decision": "x", "inspection_complete": true/false, "is_clean": true/false).   1 call, 3 outcomes.

The command line demo (notes.md, vendor-brief.md, attachments.zip) names files whose text the README
does not show, so no input exists to scan and it is left out.

Every stated outcome of these three shapes is asserted as written."""
import re
from pathlib import Path

import pytest

from sunglasses.engine import SunglassesEngine

README = Path(__file__).resolve().parents[1] / "README.md"
TEXT = README.read_text(encoding="utf-8")
ENGINE = SunglassesEngine()
CHANNELS = ("message", "file")

SENTENCE = re.compile(r"`([^`\n]+)`\s+(?:is|are)\s+(?:flagged as (review)|blocked as (critical|high))")
CALL = re.compile(r'engine\.scan\("([^"\n]+)"\)')
PRINT = re.compile(r'print\(result\.(decision|severity|is_clean)\)\s+#\s+("?)([A-Za-z_]+)\2')
MCP = re.compile(r'`scan_text` with `\{"text": "([^"\n]+)"\}`\.[^\n]*?`"decision": "(\w+)"`[^\n]*?`"inspection_complete": (true|false)`[^\n]*?`"is_clean": (true|false)`')


def _sentences():
    seen = {}
    for m in SENTENCE.finditer(TEXT):
        seen[(m.group(1), "review" if m.group(2) else m.group(3))] = None
    return sorted(seen)


def _python_block():
    out = []
    for m in CALL.finditer(TEXT):
        block = TEXT[m.end(): TEXT.find("```", m.end())]
        for p in PRINT.finditer(block):
            out.append((m.group(1), p.group(1), p.group(3)))
    return out


def _mcp():
    out = []
    for m in MCP.finditer(TEXT):
        out += [(m.group(1), "decision", m.group(2)), (m.group(1), "inspection_complete", m.group(3)),
                (m.group(1), "is_clean", m.group(4))]
    return out


SENTENCES = _sentences()
PYTHON = _python_block()
MCP_ROWS = _mcp()


def test_the_readme_still_shows_its_examples():
    assert {d for _, d in SENTENCES} >= {"review", "critical"}, SENTENCES
    assert {f for _, f, _ in PYTHON} >= {"decision", "severity", "is_clean"}, PYTHON
    assert {f for _, f, _ in MCP_ROWS} == {"decision", "inspection_complete", "is_clean"}, MCP_ROWS


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("sentence,decision", SENTENCES)
def test_a_documented_sentence_keeps_the_decision_the_readme_states(sentence, decision, channel):
    result = ENGINE.scan(sentence, channel=channel)
    severities = {f["severity"] for f in result.findings}
    if decision == "review":
        assert result.decision != "block", (sentence, channel, result.decision)
        assert "review" in severities and not severities & {"high", "critical"}, (sentence, channel, severities)
    else:
        assert result.decision == "block", (sentence, channel, result.decision)
        assert decision in severities, (sentence, channel, severities)


def _read(result, field):
    value = getattr(result, field)
    return str(value).lower() if isinstance(value, bool) else str(value)


def _rows(kind, rows):
    return [pytest.param(text, field, stated, id=f"{kind}-{field}") for text, field, stated in rows]


@pytest.mark.parametrize("text,field,stated", _rows("python", PYTHON))
def test_the_python_example_prints_what_the_readme_says(text, field, stated):
    assert _read(ENGINE.scan(text), field) == stated.lower(), (text, field, stated)


@pytest.mark.parametrize("text,field,stated", _rows("mcp", MCP_ROWS))
def test_the_mcp_example_reads_what_the_readme_says(text, field, stated):
    assert _read(ENGINE.scan(text, channel="message"), field) == stated.lower(), (text, field, stated)
