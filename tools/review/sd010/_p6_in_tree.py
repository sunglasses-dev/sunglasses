"""Runs INSIDE a tree. Prints `row<TAB>decision` for the six evasion rows."""
import sys
sys.path.insert(0, "."); sys.path.insert(0, "tests")
from sunglasses.engine import SunglassesEngine
import sd010_embedded_rows as rows
e = SunglassesEngine()
for r in sorted(k for k in rows.MUST_FIRE if k.startswith("evasion_")):
    d = e.scan(rows.MUST_FIRE[r], channel="file").to_dict()
    ids = {f["id"] for f in d["findings"]}
    print(f"{r}\t{'block' if 'GLS-SD-010-EMB' in ids else 'allow'}")
