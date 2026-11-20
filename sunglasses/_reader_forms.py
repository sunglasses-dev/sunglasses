"""The reader names the hidden-text switch and the urgency switch read, in one place.

GLS-IP-009 addresses an AI reader in a number of forms. The urgency rule keeps the release's block on a page that names such a reader,
and the hiding rule keeps it on hidden text that names one. They ask two things: the list below, and the compiled gate of GLS-IP-009. Each of the two accepts forms the
other does not, and a yes from either keeps the block. The urgency switch takes the gate's answer from the scan's own walk of the
rule, on every subject the rule reads (reader_gate_seen in engine.py), and asks this list on those subjects. The hiding switch reads
the hidden text alone and asks this list and the gate there. tests/test_reader_forms_match_the_order_rule.py writes out sample forms
of the rule's gate by code, one alternative at a time, and asks this list about each sample.
"""
import re

# Each entry is one form, as a regex fragment. The edge around the whole list is a letter or digit of ASCII only, so a letter of a script
# written without spaces never blocks a match.
READER_FORMS = (
    r"ai", r"a\.i\.", r"a(?:\.[ \t]?|[ \t])i\b\.?", r"ᴀ[ \t]?ɪ", r"artificial[ \t]+intelligence",
    r"bots?", r"chat[\s-]?bots?", r"llms?", r"gpts?", r"gpt-?[0-9][a-z0-9.]*", r"chat[\s-]?gpt",
    r"agents?", r"assistants?", r"models?", r"(?:automated|autonomous)[ \t]+(?:shopping[ \t]+)?(?:buyers?|shoppers?)",
    r"co[\s-]?pilots?", r"claude", r"gemini", r"grok", r"siri", r"alexa", r"cortana", r"bard", r"perplexity", r"llama",
    r"mistral", r"deepseek", r"qwen", r"kimi", r"codex", r"bixby", r"bing[ \t]+chat",
    r"ai(?:to|should|must)",  # the order rule lets "your ai" stand glued to the verb behind it, so the list reads it so too
)

READER = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(READER_FORMS) + r")(?![A-Za-z0-9])", re.I)
