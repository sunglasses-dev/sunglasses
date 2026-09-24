import sys, os
D = sys.argv[1]; sys.path.insert(0, os.path.join(D, "probes"))
from _common import head_engine
sys.path.insert(0, os.path.join(D, "head", "tests"))
import sd010_embedded_rows as rows
RULE = "GLS-SD-010-EMB"; PARENT = "GLS-SD-010"
e = head_engine(D)
# The rule's OWN declared channels, read from the head tree, not a list typed
# here: round 8 widened the rule to eight and a typed list would have kept
# measuring six while reading as complete.
from sunglasses.patterns import PATTERNS as _P
CH = [r for r in _P if r["id"] == RULE][0]["channel"]
N = len(CH)
def ids(t,c): 
    # to_dict(): the deduped surface a consumer sees, not the raw list.
    r=e.scan(t,channel=c); d=r.to_dict()
    return d["decision"], {f["id"] for f in d["findings"]}
bad=0
for k in sorted(rows.MUST_FIRE):
    blocked=sum(ids(rows.MUST_FIRE[k],c)[0]=="block" for c in CH)
    named=sum(RULE in ids(rows.MUST_FIRE[k],c)[1] for c in CH)
    shadow = k in rows.PARENT_ALSO_COVERS
    ok = blocked==N and (named==N or shadow)
    bad += not ok
    print(f"  MUST-FIRE  {k:38} block {blocked}/{N}  named {named}/{N} {'(parent shadows it on message/file/code, the consumer surface)' if shadow else ''} {'OK' if ok else '*FAIL*'}")
for k in sorted(rows.BENIGN):
    fires=sum(RULE in ids(rows.BENIGN[k],c)[1] for c in CH); bad += fires>0
    print(f"  BENIGN     {k:38} rule fires {fires}/{N} {'OK' if not fires else '*FAIL*'}")
for k in sorted(rows.DISCLOSED_MISSES):
    fires=sum(RULE in ids(rows.DISCLOSED_MISSES[k],c)[1] for c in CH)
    # A CHANGED disclosed row counts. r1: the driver printed *CHANGED* and
    # still exited 0, so the row was decoration rather than a check.
    bad += fires>0
    print(f"  DISCLOSED  {k:38} rule fires {fires}/{N} {'as disclosed' if not fires else '*CHANGED*'}")
print(f"MATRIX {'CLEAN' if not bad else str(bad)+' ROWS FAILED'}")
# The exit code is the verdict. r1: this exited 0 no matter what it printed.
sys.exit(0 if not bad else 1)
