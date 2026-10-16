"""The fourteen tool-metadata -API siblings: they copy their parent, and the one cost they carry is booked.

A tool listing (`tools/list`) arrives on the `api_response` channel. Fourteen rules whose subject is a tool's advertised
metadata did not declare that channel, so a poisoned description matched their predicate nowhere it mattered. Each sibling
is its parent with the channel added and nothing else.

The cost that comes with that is inherited, not new. The same text is already blocked by exactly the two parents on `file`,
because both of those parents declare `file`. The siblings carry an existing false positive onto the channel where a poisoned
listing arrives, and the tests below pin that relationship against complete findings, so a sibling that ever fires where its
parent does not shows up as new cost.

The baseline is the parent's own declared channels, not `file`. Four of the fourteen parents (`GLS-TMS-237`, `GLS-TMS-239`,
`GLS-TMS-240`, `GLS-TP-ITDP-252`) do not read `file`, so a `file` comparison says nothing about them. Measured over the 1,583
exported attack-db documents used as scan input, the siblings that fire on `api_response` and have no parent finding on `file`
are 180 pairs (`GLS-TMS-237-API` 175, `GLS-TMS-239-API` 3, `GLS-TP-ITDP-252-API` 2); every one of them has its parent firing on
a channel the parent declares, so against the declared channels the new cost is 0 pairs. These are catalog documents that
describe the attacks the rules exist for, not benign prose.

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
RULED_PARENTS = {sid[: -len("-API")] for sid in RULED_SIBLINGS}
FAMILY_PREFIXES = ("GLS-TP-", "GLS-TMS-", "GLS-MTI-")

BY_ID = {p["id"]: p for p in PATTERNS}


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _fired(engine, channel, text=DEFENSIVE_DESCRIPTION):
    """Decision and the COMPLETE set of finding ids. `to_dict()` reports a reduced view that can hide a finding."""
    result = engine.scan(text, channel=channel)
    return result.decision, {f["id"] for f in result.findings}


def test_there_are_exactly_fourteen_siblings_and_each_has_a_parent():
    """The population is read off the catalog by family, not filtered through the expected list."""
    actual = {pid for pid in BY_ID if pid.endswith("-API") and pid.startswith(FAMILY_PREFIXES)}
    assert actual == set(SIBLINGS), (sorted(actual - set(SIBLINGS)), sorted(set(SIBLINGS) - actual))
    for sid in actual:
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
    siblings = fired & set(SIBLINGS)
    assert siblings == RULED_SIBLINGS, (
        f"the booked cost is exactly {sorted(RULED_SIBLINGS)}; got {sorted(siblings)}. "
        f"A different set is a different cost and needs its own ruling")


def test_the_text_is_blocked_on_file_by_exactly_the_two_parents(engine):
    decision, fired = _fired(engine, "file")
    assert decision == "block"
    family = {i for i in fired if i.startswith(FAMILY_PREFIXES)}
    assert family == RULED_PARENTS, (
        f"the same text on file is blocked by exactly {sorted(RULED_PARENTS)}; got {sorted(family)}")


def test_the_cost_is_inherited_from_the_parents_on_a_channel_they_declare(engine):
    """Every sibling that fires has its parent firing on a channel the parent itself declares.

    The control is the parent's own declared channels: four parents do not read `file`, so a comparison against `file` alone
    would call their siblings new cost whatever they matched.
    """
    _, on_api = _fired(engine, "api_response")
    firing = on_api & set(SIBLINGS)
    assert firing, "no sibling fires on the booked text; the ruling it pins is gone"
    for sid in sorted(firing):
        parent = sid[: -len("-API")]
        declared = BY_ID[parent]["channel"]
        assert any(parent in _fired(engine, ch)[1] for ch in declared), (
            f"{sid} fires on api_response but its parent {parent} fires on none of {declared} -- new cost, not inherited")
