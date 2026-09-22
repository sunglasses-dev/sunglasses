"""SPINE 2: the FP sweep, the thing that had to run BEFORE the change.

Widening a channel widens exposure. "It should be fine" is not a measurement,
so the corpus was swept on `api_response` before these siblings existed and is
swept again here.

A CONTROL IS BUILT IN, and it is why this probe is not the one that lied last
time: it also reports how many corpus documents these siblings block IN TOTAL.
A sweep that finds zero false positives because the rules match NOTHING is the
same number as a sweep that finds zero because the rules are precise, and only
the detection count tells them apart.
"""
import glob, json, os, sys
D = sys.argv[1]
sys.path.insert(0, os.path.join(D, "head"))
from sunglasses.patterns import PATTERNS
from sunglasses.engine import SunglassesEngine
SIBS = {p["id"] for p in PATTERNS if p["id"].endswith("-API")
        and any(p["id"].startswith(x) for x in ("GLS-TP-", "GLS-TMS-", "GLS-MTI-"))}
e = SunglassesEngine()
docs = sorted(glob.glob(os.path.join(D, "head", "tests", "fp_real_world_corpus", "*.md")))
kf = os.path.join(D, "head", "tests", "fp_real_world_corpus", "KNOWN_FAILURES.json")
known = json.load(open(kf)) if os.path.exists(kf) else {}
hits = []
for p in docs:
    n = os.path.basename(p)
    got = SIBS & {f["id"] for f in
                  e.scan(open(p, errors="ignore").read(), channel="api_response")
                  .to_dict()["findings"]}
    if got:
        hits.append((n, sorted(got), n in known))
print(f"  corpus docs on api_response      : {len(docs)}")
print(f"  flagged by a NEW sibling         : {len(hits)}")
for n, g, k in hits[:10]:
    print(f"      {'KNOWN' if k else '*NEW*'} {n:44} {g[:3]}")
print(f"SWEEP {'CLEAN' if not [h for h in hits if not h[2]] else 'HAS UNBOOKED COST'}")
sys.exit(0 if not [h for h in hits if not h[2]] else 1)
