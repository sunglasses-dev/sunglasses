import sys, os, glob, json
D = sys.argv[1]; sys.path.insert(0, os.path.join(D, "probes"))
from _common import head_engine, without
RULE="GLS-SD-010-EMB"
ship=head_engine(D); base=without(D, RULE)
docs=sorted(glob.glob(os.path.join(D,"head","tests","fp_real_world_corpus","*.md")))
# A SWEEP OVER NOTHING IS NOT A CLEAN SWEEP. This subject comes from a GLOB, so
# a moved corpus, a renamed directory or an extension change empties it in
# silence -- and every count below is then 0, `unbooked` is empty, and the probe
# exits 0 reporting no false positives over no documents. This exact reassuring
# zero has already been banked once: an FP sweep came back clean over a rule set
# that matched nothing at all, which was true and worthless.
if not docs:
    print(f"  *** NO CORPUS DOCUMENTS under {os.path.join(D,'head','tests','fp_real_world_corpus')}. "
          f"A zero here would measure nothing. Harness defect, not a product finding. ***")
    sys.exit(2)
print(f"  corpus documents swept        : {len(docs)}")
hits=[];flips=[]
for p in docs:
    t=open(p,errors="ignore").read(); n=os.path.basename(p)
    a=base.scan(t,channel="file"); b=ship.scan(t,channel="file")
    # to_dict(), like p1 and p2. r1 caught this one still reading the raw
    # list while MANIFEST §5 claimed every probe read the deduped surface.
    # Raw counting happens to be conservative for false positives, but the
    # claim was wrong and the claim is what gets fixed.
    if RULE in {f["id"] for f in b.to_dict()["findings"]}: hits.append(n)
    if a.decision!=b.decision: flips.append(n)
# A hit that is BOOKED on the ratchet with a reason is an accepted cost, not a
# regression. An unbooked hit is a cost nobody decided on. The difference is
# the whole point of the ratchet, so the probe has to know it -- this exited 1
# on the accepted row until it did.
kf_path = os.path.join(D, "head", "tests", "fp_real_world_corpus", "KNOWN_FAILURES.json")
known = json.load(open(kf_path)) if os.path.exists(kf_path) else {}
def booked(n):
    e = known.get(n) or {}
    return RULE in (e.get("patterns") or []) and bool(e.get("reason"))
accepted = [n for n in hits if booked(n)]
unbooked = [n for n in hits if not booked(n)]
flips_unbooked = [n for n in flips if not booked(n)]
print(f"  docs {len(docs)} | rule fires on {len(hits)} | ACCEPTED on the ratchet "
      f"{len(accepted)} {accepted} | UNBOOKED {len(unbooked)} {unbooked}")
print(f"  decision flips {len(flips)} | unbooked flips {len(flips_unbooked)} {flips_unbooked}")
for n in accepted:
    print(f"      {n}: reason recorded, ruled_by {known[n].get('ruled_by','(none)')}")
print(f"SWEEP {'CLEAN (only accepted rows)' if not unbooked and not flips_unbooked else 'HAS UNBOOKED COST'}")
sys.exit(0 if not unbooked and not flips_unbooked else 1)

