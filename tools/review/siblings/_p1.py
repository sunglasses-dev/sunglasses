"""SPINE: every sibling's predicate is byte-identical to its parent's.

#170's law is that a sibling copies the parent predicate character for
character and adds CHANNELS and nothing else. That is checkable, and it is the
check that matters most here: two generators were thrown away building these,
and the SECOND one produced fourteen siblings that loaded, carried the right
ids, raised the pattern count by exactly 14, and matched NOTHING -- because
each regex was emitted as `r` plus its repr, a raw string of an already-escaped
repr, doubling every backslash.

The FP sweep on that broken set came back a clean zero, which was true and
worthless: a rule that matches nothing has no false positives either.
"""
import os, sys
D = sys.argv[1]
sys.path.insert(0, os.path.join(D, "head"))
from sunglasses.patterns import PATTERNS
by = {p["id"]: p for p in PATTERNS}
sibs = [p for p in PATTERNS if p["id"].endswith("-API")
        and any(p["id"].startswith(x) for x in ("GLS-TP-", "GLS-TMS-", "GLS-MTI-"))]
# AN EMPTY SUBJECT IS NOT A CLEAN ONE. If the selection above matches nothing
# -- a renamed family, a filter that names the branch it was written on -- every
# count below is 0 and the probe exits CLEAN having measured no rule at all.
if not sibs:
    print("SPINE BROKEN -- the sibling selection matched NOTHING, so every "
          "count below would be a zero that measured nothing")
    sys.exit(2)

# COMPARE EVERY FIELD, MINUS A DECLARED ALLOWLIST -- reviewer's finding. This
# compared `regex` and `keywords` only, so any OTHER behaviour-carrying field
# (severity, confidence, anchor terms, windows, a flag added next month) could
# differ between a sibling and its parent and this probe would still say the
# predicates were identical. A check that lists the fields someone thought of
# goes stale the moment a field is added; a check that compares everything and
# declares its exceptions does not.
# `name` is the third field that differs on purpose, and widening the check is
# what surfaced it. It reaches a consumer (engine.py copies it into each
# finding) but never the match, so it is not silently skipped -- the rule about
# it is asserted below.
#
# THE RULE IS "CARRIES THE MARKER AND FITS", NOT "IS THE PARENT'S NAME PLUS THE
# MARKER". The first version of this probe asserted parent+marker, and the name
# HYGIENE guard then failed on seven of these siblings: it caps a name at 60
# characters, the parents run 52 to 60, and the marker adds 15. Parent+marker
# was therefore a convention the rest of the repo could not accept, and it took
# a cap that only ever ratchets DOWN to prove it. The seven were reworded to
# fit rather than the cap being raised, so the marker is what ties a sibling to
# its channel and the length cap is checked here too, where a reviewer sees it.
DIFFER_BY_DESIGN = {"id", "channel", "name"}
NAME_SUFFIX = " (api_response)"
MAX_NAME = 60
bad_fields, bad_ch, orphan, shape, bad_name = [], [], [], [], []
for s in sibs:
    parent = by.get(s["id"][:-4])
    if parent is None:
        orphan.append(s["id"]); continue
    if set(s) - DIFFER_BY_DESIGN != set(parent) - DIFFER_BY_DESIGN:
        shape.append((s["id"],
                      sorted((set(s) ^ set(parent)) - DIFFER_BY_DESIGN)))
        continue
    for field in sorted(set(s) - DIFFER_BY_DESIGN):
        if s.get(field) != parent.get(field):
            bad_fields.append((s["id"], field))
    if s.get("channel") != ["api_response"]: bad_ch.append((s["id"], s.get("channel")))
    nm = s.get("name") or ""
    if not nm.endswith(NAME_SUFFIX) or len(nm) > MAX_NAME:
        bad_name.append((s["id"], nm, len(nm)))
print(f"  tool-metadata -API siblings : {len(sibs)}")
print(f"  fields compared per sibling : every key except {sorted(DIFFER_BY_DESIGN)}")
print(f"  field NOT identical         : {len(bad_fields)} {bad_fields}")
print(f"  key set differs from parent : {len(shape)} {shape}")
print(f"  channel not [api_response]  : {len(bad_ch)} {bad_ch}")
print(f"  name lacks {NAME_SUFFIX!r} or >{MAX_NAME}: {len(bad_name)} {bad_name}")
print(f"  sibling with no parent      : {len(orphan)} {orphan}")
broken = bad_fields or bad_ch or orphan or shape or bad_name
print(f"SPINE {'CLEAN' if not broken else 'BROKEN'}")
sys.exit(0 if not broken else 1)
