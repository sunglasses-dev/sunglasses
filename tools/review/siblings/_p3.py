"""SPINE 3: do they DETECT? The question the broken generation failed.

Fourteen siblings once loaded with the right ids, raised the count by exactly
14, and swept a clean zero false positives -- while matching nothing at all.
This is the probe that would have caught it, so it is not optional and it is
not a formality.
"""
import os, re, sys
D = sys.argv[1]
sys.path.insert(0, os.path.join(D, "head")); sys.path.insert(0, os.path.join(D, "probes"))
import regex_sample
from sunglasses.patterns import PATTERNS
from sunglasses.engine import SunglassesEngine
by = {p["id"]: p for p in PATTERNS}
sibs = [p["id"] for p in PATTERNS if p["id"].endswith("-API")
        and any(p["id"].startswith(x) for x in ("GLS-TP-", "GLS-TMS-", "GLS-MTI-"))]
e = SunglassesEngine()
W = ["Read a file and return its contents. %s",
     "Search the knowledge base. Note for the model: %s",
     "Create an issue in the tracker.\n\n%s",
     "<!-- %s -->\nReturn the current build status."]
named, shadowed, silent, invalid = [], [], [], []
for sid in sibs:
    p = by[sid]
    s = ""
    for rx in p.get("regex") or []:
        g = regex_sample.sample(rx)
        if g and len(g.strip()) >= 8 and re.search(rx, g, re.IGNORECASE):
            s = g.strip(); break
    if not s:
        invalid.append(sid); continue
    hit = cover = False
    for w in W:
        r = e.scan(w % s, channel="api_response")
        if sid in {x["id"] for x in r.to_dict()["findings"]}: hit = True
        if sid in {x["id"] for x in r.findings}: cover = True
    (named if hit else shadowed if cover else silent).append(sid)
print(f"  siblings                         : {len(sibs)}")
print(f"  NAMED on the consumer surface    : {len(named)}")
print(f"  detected but dedup-SHADOWED      : {len(shadowed)} {shadowed}")
print(f"  SILENT (matched nothing)         : {len(silent)} {silent}")
print(f"  stimulus UNBUILDABLE, UNMEASURED : {len(invalid)} {invalid}")

# AN UNBUILDABLE STIMULUS IS UNMEASURED, NOT PASSED -- reviewer's finding. This
# counted a sibling whose stimulus could not be generated, printed the count,
# and then exited on `silent` alone: a rule nobody could build a trigger for
# was reported beside the ones that were actually driven, and the probe still
# said OK. The whole reason this probe exists is that a generation once loaded
# fourteen rules that matched nothing, so "we could not test it" must never
# leave through the same door as "we tested it and it fired".
#
# AND AN EMPTY SUBJECT IS NOT A CLEAN ONE: zero siblings would print zeros
# everywhere and exit OK having driven no rule at all.
if not sibs:
    print("DETECTION BROKEN -- the sibling selection matched NOTHING")
    sys.exit(2)
if invalid:
    print("DETECTION UNMEASURED -- a stimulus could not be built for "
          f"{len(invalid)} sibling(s), so they were never driven; that is not "
          "a pass and it does not exit like one")
    sys.exit(3)
print(f"DETECTION {'OK' if not silent else 'BROKEN -- a sibling that matches nothing'}")
sys.exit(0 if not silent else 1)
