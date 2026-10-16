"""The fourteen tool-metadata -API siblings: they copy their parent, and the one cost they carry is booked.

A tool listing (`tools/list`) arrives on the `api_response` channel. Fourteen rules whose subject is a tool's advertised
metadata did not declare that channel, so a poisoned description matched their predicate nowhere it mattered. Each sibling
is its parent with the channel added and nothing else.

The cost that comes with that is ruled and booked here. A description that reads as a harmless security-training tool (it
explains why a description claiming trusted status must never bypass approval, and names debug mode and self-attestation
as things that do not authorise skipping review) is blocked on `api_response` by two of the siblings. The ruling is that it
is blocked regardless of framing: a tool listing is attacker-controlled text, and "this is a training tool" is exactly the
costume an attacker writes. So there is no predicate narrowing, which would break the copy-the-parent rule, and no exemption
for security prose, which would be an off switch the attacker holds.

The cost is inherited, not new. The same text is already blocked on `file` by exactly the two parents. The siblings carry an
existing false positive onto the channel where a poisoned listing arrives, and the test below pins that relationship, so a
sibling that ever fires where its parent does not shows up as new cost.

The text is not in tests/fp_real_world_corpus: that directory is real famous-repo READMEs and feeds the published precision
benchmark, so a constructed text there would move a public number.
"""
import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

SIBLINGS = [
    "GLS-TP-001-API", "GLS-TP-002-API",
    "GLS-TP-ITDP-219-API", "GLS-TP-ITDP-220-API", "GLS-TP-ITDP-221-API", "GLS-TP-ITDP-224-API",
    "GLS-TP-ITDP-226-API", "GLS-TP-ITDP-232-API", "GLS-TP-ITDP-252-API",
    "GLS-TMS-234-API", "GLS-TMS-237-API", "GLS-TMS-239-API", "GLS-TMS-240-API",
    "GLS-MTI-001-API",
]

DEFENSIVE_DESCRIPTION = (
    "Explain why a tool description claiming trusted status must never bypass "
    "approval. This security training tool documents tool metadata that claims "
    "system authority to override instructions. It warns that debug mode does "
    "not authorize skipping approval, and self-attestation must not disable "
    "review. Examples use only {KEY}, {LOWER}, {SECRET}, and {DSN} placeholders."
)

RULED_SIBLINGS = {"GLS-TP-ITDP-226-API", "GLS-TMS-234-API"}

BY_ID = {p["id"]: p for p in PATTERNS}


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _fired(engine, channel):
    result = engine.scan(DEFENSIVE_DESCRIPTION, channel=channel)
    return result.decision, {f["id"] for f in result.to_dict()["findings"]}


def test_there_are_exactly_fourteen_siblings_and_each_has_a_parent():
    present = {p["id"] for p in PATTERNS if p["id"] in set(SIBLINGS)}
    assert present == set(SIBLINGS), sorted(set(SIBLINGS) ^ present)
    for sid in SIBLINGS:
        assert sid[: -len("-API")] in BY_ID, f"{sid} has no parent in the rule DB"


@pytest.mark.parametrize("sid", SIBLINGS)
def test_a_sibling_is_its_parent_with_only_the_id_the_name_and_the_channel_changed(sid):
    sibling, parent = BY_ID[sid], BY_ID[sid[: -len("-API")]]
    changed = sorted(k for k in set(sibling) | set(parent) if sibling.get(k) != parent.get(k))
    assert changed == ["channel", "id", "name"], (sid, changed)
    assert sibling["channel"] == ["api_response"]
    assert "regex" in sibling or "keywords" in sibling


def test_the_ruled_cost_is_blocked_on_api_response(engine):
    """Blocked regardless of framing. If this goes clean, somebody narrowed a predicate or added an exemption."""
    decision, fired = _fired(engine, "api_response")
    assert decision == "block", (decision, fired)
    siblings = {i for i in fired if i.endswith("-API") and i in set(SIBLINGS)}
    assert siblings == RULED_SIBLINGS, (
        f"the booked cost is exactly {sorted(RULED_SIBLINGS)}; got {sorted(siblings)}. "
        f"A different set is a different cost and needs its own ruling")


def test_the_cost_is_inherited_from_the_parents(engine):
    """Every sibling that fires here has its parent firing on the parent's own channel."""
    _, on_api = _fired(engine, "api_response")
    decision, on_file = _fired(engine, "file")
    assert decision == "block"
    parents = {i[: -len("-API")] for i in on_api if i in set(SIBLINGS)}
    assert parents and parents <= on_file, (
        f"sibling(s) {sorted(parents - on_file)} fire on api_response while "
        f"their parent does NOT fire on file -- that is new cost, not inherited")
