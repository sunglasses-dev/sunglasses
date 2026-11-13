"""No two rules are exact copies of each other on the same channels.

Twenty rules carried a regex list and a channel list identical to a lower numbered
rule. A copy adds nothing to detection (the lowest id already reports the same text
on the same channel) and costs a second report line, a second card and a second
count. They were removed and the lowest id of each group was kept.

This test fails when a new rule repeats the regex list of an older one on the same
channels, and when one of the removed ids comes back.
"""
from collections import defaultdict

from sunglasses.patterns import PATTERNS

REMOVED = (
    "GLS-CAI-528", "GLS-CAI-622", "GLS-CAI-624", "GLS-CAI-625", "GLS-CAI-629",
    "GLS-CAI-632", "GLS-CAI-690", "GLS-CAI-691", "GLS-CAI-692", "GLS-CAI-693",
    "GLS-CAI-694", "GLS-CAI-695", "GLS-CAI-697", "GLS-CAI-698", "GLS-CAI-699",
    "GLS-CAI-701", "GLS-CAI-702", "GLS-CAI-703", "GLS-CAI-704", "GLS-V03-0492",
)
KEPT = (
    "GLS-CAI-249", "GLS-CAI-250", "GLS-CAI-264", "GLS-CAI-277", "GLS-CAI-278",
    "GLS-CAI-279", "GLS-CAI-281", "GLS-CAI-282", "GLS-CAI-284", "GLS-CAI-308",
    "GLS-CAI-310", "GLS-CAI-316", "GLS-CAI-328", "GLS-CAI-335", "GLS-CAI-339",
    "GLS-CAI-506", "GLS-CAI-527", "GLS-CAI-584", "GLS-MRC-492",
)


def test_the_removed_ids_are_gone_and_the_kept_ids_are_still_listed():
    ids = {p["id"] for p in PATTERNS}
    assert not ids & set(REMOVED), sorted(ids & set(REMOVED))
    assert set(KEPT) <= ids, sorted(set(KEPT) - ids)


# One pair is left on purpose: it sits in a three rule group whose third rule reads other
# channels, and that group was ruled to stay as it is. Remove the pair here when it goes.
LEFT_FOR_NOW = [["GLS-TOP-484", "GLS-V03-0484"]]


def test_no_two_rules_share_a_regex_list_and_a_channel_list():
    seen = defaultdict(list)
    for p in PATTERNS:
        rx = p.get("regex")
        if not rx:
            continue
        key = (tuple(rx) if isinstance(rx, (list, tuple)) else (rx,),
               tuple(sorted(p.get("channel") or ())))
        seen[key].append(p["id"])
    copies = sorted(sorted(v) for v in seen.values() if len(v) > 1)
    assert copies == LEFT_FOR_NOW, copies
