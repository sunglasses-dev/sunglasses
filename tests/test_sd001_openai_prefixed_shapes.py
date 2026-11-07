"""GLS-SD-001 and its -API sibling: OpenAI project, service-account and admin key shapes.

OpenAI's own client code treats four prefixes as OpenAI keys: `sk-proj-`, `sk-svcacct-`, `sk-admin-`
and plain `sk-`. Only the prefixes are vendor-confirmed; the length and the body alphabet are not
documented anywhere this repository can read. So the rule asks for the three prefixes and a tail that
looks like a key and not like words: twenty or more of letters, digits, underscores and hyphens, where
one of the first nine hyphen-separated parts is twelve or more of letters, digits and underscores and
holds both a letter and a digit. The twenty and the twelve are floors chosen by us, not key lengths.

The left boundary from `test_sd001_left_boundary.py` applies here for the same reason, and it is not
optional: without it `risk-proj-...`, `disk-admin-...` and `task-svcacct-...` are ordinary words. The
tail rule is not optional either: a documentation file named after the prefix
(`docs/sk-proj-credential-format-reference.md`) has a tail of hyphenated words and no digit.

THE COST, PINNED RATHER THAN HIDDEN. A key written directly after a letter or digit is not reported
by this alternative; a tail with no digit in a twelve-character part, or only digits, is not reported;
and a token that begins with a prefix and then carries a twelve-character part with both a letter and
a digit (a version stamp glued to a word) is reported.

NOT ONE CREDENTIAL-SHAPED LITERAL IS STORED HERE; values are assembled from fragments.
"""
import hashlib
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.engine import SunglassesEngine          # noqa: E402
from sunglasses.patterns import PATTERNS                 # noqa: E402
import sd_api_sibling_rows as rows                       # noqa: E402

_BY_ID = {p["id"]: p for p in PATTERNS}
_PREFIXES = ["sk" + "-proj-", "sk" + "-svcacct-", "sk" + "-admin-"]
_PLAIN = rows._fill(rows._LOWER, 40)
_MIXED = "q7" + rows._fill(rows._LOWER, 16) + "_" + rows._fill(rows._LOWER, 14) + "-" + rows._fill(rows._LOWER, 20)
_RULE_CHANNEL = {"GLS-SD-001": "file", "GLS-SD-001-API": "api_response"}
_CHANNELS = ["message", "file", "api_response", "web_content", "log_memory", "tool_output",
             "agent_input", "code", "prompt"]


def _alone(rule_id):
    return SunglassesEngine(patterns=[_BY_ID[rule_id]], mechanisms=False)


def _hits(rule_id, text):
    return [f["id"] for f in _alone(rule_id).scan(text, _RULE_CHANNEL[rule_id]).findings]


def _declared(rule_id):
    return sorted(_BY_ID[rule_id]["channel"])


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("prefix", _PREFIXES)
@pytest.mark.parametrize("body", [_PLAIN, _MIXED], ids=["alnum", "underscore-and-hyphen"])
@pytest.mark.parametrize("before", ["", "=", ":", " ", '"', "'", "(", "[", "\n", "`", "KEY=", "Bearer ",
                                    '"api_key": "', "export K=", "KEY_"])
def test_a_prefixed_key_at_a_word_edge_fires(rule_id, prefix, body, before):
    assert rule_id in _hits(rule_id, before + prefix + body + " end")


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("word,prefix", [("risk", "proj-"), ("disk", "admin-"), ("task", "svcacct-"),
                                         ("desk", "proj-"), ("mask", "admin-"), ("TASK", "svcacct-")])
def test_a_word_ending_in_sk_is_not_a_key(rule_id, word, prefix):
    assert _hits(rule_id, f"see {word}-{prefix}{_PLAIN} ok") == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("text", [
    "sk" + "-admin-1234abcd",                       # a documentation placeholder, shorter than the floor
    "sk" + "-admin-panel",
    "sk" + "-proj-",
    "sk" + "-svcacct-short",
    "sk" + "-abcdefghijklmnop123",                  # a documentation placeholder, 19 characters
], ids=["admin-placeholder", "admin-panel", "bare-prefix", "svcacct-short", "plain-placeholder"])
def test_placeholders_and_short_strings_stay_clean(rule_id, text):
    assert _hits(rule_id, f"example: {text} end") == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("prefix", _PREFIXES)
def test_a_key_glued_to_a_letter_is_the_disclosed_cost(rule_id, prefix):
    """Pinned in the direction that is NOT a feature, so the cost cannot drift unnoticed."""
    assert _hits(rule_id, "x" + prefix + _PLAIN) == []
    assert _hits(rule_id, "7" + prefix + _PLAIN) == []


# Three documentation filenames from the review packet (ids and sha256 only), pinned clean on purpose.
_DOC_FILENAMES = {
    "DOC01": ("docs/sk" + "-proj-credential-format-reference.md\n", "abb2ddc727baef55"),
    "DOC02": ("docs/sk" + "-svcacct-credential-format-reference.md\n", "81858d5cae985165"),
    "DOC03": ("docs/sk" + "-admin-credential-format-reference.md\n", "25f301be3bf0525f"),
}


@pytest.mark.parametrize("doc_id", sorted(_DOC_FILENAMES))
def test_the_packet_fixture_bytes_are_the_reviewed_bytes(doc_id):
    text, sha16 = _DOC_FILENAMES[doc_id]
    assert hashlib.sha256(text.encode()).hexdigest()[:16] == sha16


@pytest.mark.parametrize("channel", ["message", "file", "api_response", "tool_output"])
@pytest.mark.parametrize("doc_id", sorted(_DOC_FILENAMES))
def test_a_documentation_filename_named_after_a_prefix_stays_clean(doc_id, channel):
    result = SunglassesEngine().scan(_DOC_FILENAMES[doc_id][0], channel)
    assert not [f["id"] for f in result.findings if f["id"].startswith("GLS-SD-")]
    assert result.decision == "allow"


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("tail", [
    "configuration-and-management-guide",            # words, no digit
    "administration-and-configuration-guide",        # words of 13 and 14 letters, still no digit
    "v2-configuration-management-guide",             # a digit, but not inside the long word
    "20241107123456-export",                         # a timestamp: digits only, no letter in the part
    "format-reference-2024-edition-notes",           # digits, every part shorter than twelve
    "a1-b2-c3-d4-e5-f6-g7-h8-i9-j0-k1-l2",           # short parts only
], ids=["words", "long-words", "version-prefix", "timestamp", "short-parts", "many-short-parts"])
@pytest.mark.parametrize("prefix", _PREFIXES)
def test_a_tail_that_reads_as_words_or_a_stamp_stays_clean(rule_id, prefix, tail):
    assert _hits(rule_id, f"see {prefix}{tail} ok") == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("prefix", _PREFIXES)
def test_the_floor_is_twenty_and_a_nineteen_character_tail_stays_clean(rule_id, prefix):
    twenty = "gK27S83WE4CjvXZ21D4w"
    assert len(twenty) == 20
    assert rule_id in _hits(rule_id, 'VALUE="' + prefix + twenty + '"')
    assert _hits(rule_id, 'VALUE="' + prefix + twenty[:19] + '"') == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
@pytest.mark.parametrize("prefix", _PREFIXES)
def test_the_disclosed_cost_a_tail_without_a_digit_is_not_reported(rule_id, prefix):
    """Pinned in the direction that is NOT a feature. A random key tail of 40 characters holds no
    digit about one time in a thousand; a lowercase-only synthetic tail never does."""
    assert _hits(rule_id, "k=" + prefix + "abcdefghijklmnopqrstuvwxyzabcdefghijklmn") == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
def test_the_known_hazard_is_a_glued_version_stamp(rule_id):
    """Documented, not hidden: a part of twelve or more with a letter and a digit reads as a key."""
    prose = "sk" + "-admin-release2024november-notes"
    assert rule_id in _hits(rule_id, f"read {prose} first")


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
def test_a_long_run_of_hyphen_separated_parts_costs_a_bounded_scan(rule_id):
    """The lookaheads stop after nine parts, so a hostile tail cannot make the scan grow with the
    number of parts. Correctness here; the time bound is the repository's pattern-perf gate."""
    text = "k=sk" + "-proj-" + "-".join(["ab"] * 5000) + " end"
    assert _hits(rule_id, text) == []


@pytest.mark.parametrize("rule_id", sorted(_RULE_CHANNEL))
def test_the_plain_and_anthropic_shapes_are_unchanged(rule_id):
    assert rule_id in _hits(rule_id, "k=" + "sk" + "-" + _PLAIN)
    assert rule_id in _hits(rule_id, "k=" + "sk" + "-ant-" + rows._fill(rows._LOWER, 24))


def test_the_sibling_carries_the_same_alternatives_as_the_parent():
    assert _BY_ID["GLS-SD-001"]["regex"] == _BY_ID["GLS-SD-001-API"]["regex"]


@pytest.mark.parametrize("prefix", _PREFIXES)
@pytest.mark.parametrize("channel", _CHANNELS)
def test_the_full_ruleset_decides_a_prefixed_key_like_a_plain_one(prefix, channel):
    """On every channel, including the aliases and the ones neither rule declares, the three new
    shapes get the decision and the SD findings the plain shape already gets. Nothing gains a
    channel, nothing loses one."""
    engine = SunglassesEngine()

    def verdict(secret):
        r = engine.scan("k=" + secret, channel)
        return r.decision, sorted(f["id"] for f in r.findings if f["id"].startswith("GLS-SD-001"))

    assert verdict(prefix + _PLAIN) == verdict("sk" + "-" + _PLAIN)


def test_the_new_shapes_block_where_the_rules_are_declared():
    for channel in ("message", "file", "api_response", "log_memory", "agent_input", "tool_output"):
        for prefix in _PREFIXES:
            assert SunglassesEngine().scan("k=" + prefix + _PLAIN, channel).decision == "block", (prefix, channel)


@pytest.mark.parametrize("channel", _CHANNELS)
def test_the_full_ruleset_stays_clean_on_a_word_internal_id(channel):
    result = SunglassesEngine().scan("created task-proj-" + _PLAIN + " ok", channel)
    assert not [f["id"] for f in result.findings if f["id"].startswith("GLS-SD-")]
