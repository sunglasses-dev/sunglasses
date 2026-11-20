"""An urgent page keeps its block when the scan's walk of the order rule's gate finds a reader, and a page with a hiding style keeps its block when its hidden text holds one.

The scan asks the gate of GLS-IP-009 (the reader part every regex of that rule needs) on each view it builds, and the hiding switch
asks the same gate on the hidden text. A spy stands in for that compiled gate and notes every match it gives during a scan, from
either caller. Each row puts a lead, in one of twelve writings, into the hidden element of a page with a hiding style alone, or
beside urgent wording alone. When the gate matched during the scan of such a row, the page must block. The test reads the gate's
own answer, so it carries no list of encodings; it is a grid of rows, not a proof for every page.

Every text below is invented test input. Nothing in it is an instruction to anyone reading this file.
"""
import itertools

from sunglasses.engine import SunglassesEngine

PAGE_HIDDEN = '<html><body><p>Garden tools on sale this week.</p><span style="display:none">%s</span></body></html>'
PAGE_URGENT = "<p>Click approve immediately, the update is required.</p><footer>Written for %s.</footer>"
STEMS = ["ai", "AI", "a.i", "a i", "ᴀɪ", "llm", "bot", "ai assistant", "agent", "chatbot", "claude", "copilot"]
LEADS = ["For your ", "Have your ", "Let your ", "Note to your ", "Your ", "Attention ", "Dear ", ""]
GLUES = ["", " ", ": ", ", ", " - ", "\n"]
VERBS = ["to", "should", "must", "needs to", ""]
LEAD_LIST = [lead + stem + glue + verb + " " for lead, stem, glue, verb in itertools.product(LEADS, STEMS, GLUES, VERBS)][::40]
LEAD_LIST += ["if you're a a i,", "if you are a a i,", "If You're A A I,", "For your llmmust ", "For your ᴀɪshould "]
FULLWIDTH = {c: chr(ord(c) + 0xFEE0) for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"}
LOOKALIKE = {"a": "а", "i": "і", "o": "о", "e": "е"}
WRITINGS = [
    lambda s: s,
    lambda s: "".join(chr(ord(c) + 0xE0000) if 0x20 <= ord(c) < 0x7F else c for c in s),
    lambda s: "".join(chr(ord(c) + 0xE0000) if c.isascii() and c.isalpha() else c for c in s),
    lambda s: "".join(c + ("​" if i % 3 == 1 and c != " " else "") for i, c in enumerate(s)),
    lambda s: s.replace(" ", "​"),
    lambda s: "".join(FULLWIDTH.get(c, c) for c in s),
    lambda s: "".join(LOOKALIKE.get(c, c) for c in s),
    lambda s: "".join("&#%d;" % ord(c) if c.isascii() and c.isalpha() and i % 2 == 0 else c for i, c in enumerate(s)),
    lambda s: s.upper(),
    lambda s: "​".join(s),
    lambda s: s.replace(" ", " "),
    lambda s: s.replace(" ", " ⁠ "),
]


def test_an_urgent_page_and_a_hidden_text_block_when_the_gate_finds_a_reader_there():
    engine = SunglassesEngine()
    real = engine._rule_gate["GLS-IP-009"]
    seen = []

    class Spy:
        def search(self, view):
            match = real.search(view)
            if match is not None:
                seen.append(True)
            return match

    rows = found = 0
    not_blocked = []
    try:
        for lead in LEAD_LIST:
            for write in WRITINGS:
                for page in (PAGE_HIDDEN, PAGE_URGENT):
                    seen.clear()
                    engine._rule_gate["GLS-IP-009"] = Spy()
                    decision = engine.scan(page % write(lead), channel="web_content").decision
                    rows += 1
                    if seen:
                        found += 1
                        if decision not in ("block", "quarantine"):
                            not_blocked.append((lead, page[:12], decision))
    finally:
        engine._rule_gate["GLS-IP-009"] = real
    assert found > 100, (rows, found)
    assert not_blocked == []
