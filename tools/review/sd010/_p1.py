import sys, os
D = sys.argv[1]
sys.path.insert(0, os.path.join(D, "head", "tests"))
import sd010_embedded_rows as rows
RULE = "GLS-SD-010-EMB"
# The embedded rows only. The two line-start rows are covered by the PARENT on
# base as well, so counting them would understate the gap.
EMB = [k for k in rows.MUST_FIRE if k not in rows.PARENT_ALSO_COVERS]

def engine(tree):
    for m in [m for m in list(sys.modules) if m.startswith("sunglasses")]:
        del sys.modules[m]
    p = os.path.join(D, tree)
    sys.path.insert(0, p)
    from sunglasses.engine import SunglassesEngine
    e = SunglassesEngine()
    sys.path.remove(p)
    return e

for tree in ("base", "head"):
    e = engine(tree)
    # to_dict() is the DEDUPED, consumer-visible surface (CLI, API, SARIF).
    # The raw .findings list reports ids a user is never shown, so counting it
    # would overstate what this rule delivers.
    def ids(t):
        return {f["id"] for f in e.scan(t, channel="file").to_dict()["findings"]}
    uncaught = [k for k in EMB if not [i for i in ids(rows.MUST_FIRE[k])
                                       if i.startswith("GLS-SD-")]]
    named = [k for k in EMB if RULE in ids(rows.MUST_FIRE[k])]
    fp = [k for k in rows.BENIGN if RULE in ids(rows.BENIGN[k])]
    print(f"{tree:5} embedded rows {len(EMB)} | uncaught by ANY GLS-SD rule {len(uncaught)} "
          f"| named by {RULE} {len(named)} | benign twins firing {len(fp)}")
    if tree == "base" and len(uncaught) != len(EMB):
        print(f"  *** BASE DOES NOT REPRODUCE THE GAP on: {uncaught and sorted(set(EMB)-set(uncaught))} "
              f"-- nothing this round says about HEAD is meaningful ***")
        sys.exit(2)
    if tree == "head":
        # The exit code IS the verdict. r1 and r2 both had to read the numbers
        # because this returned 0 no matter what it printed.
        bad = len(uncaught) or len(named) != len(EMB) or len(fp)
        sys.exit(1 if bad else 0)
