import sys, os, copy
def head_engine(D, patterns=None):
    p = os.path.join(D, "head")
    if p not in sys.path: sys.path.insert(0, p)
    if os.path.join(p, "tests") not in sys.path: sys.path.insert(0, os.path.join(p, "tests"))
    from sunglasses.engine import SunglassesEngine
    return SunglassesEngine(patterns=patterns) if patterns is not None else SunglassesEngine()
def head_patterns(D):
    p = os.path.join(D, "head")
    if p not in sys.path: sys.path.insert(0, p)
    from sunglasses.patterns import PATTERNS
    return PATTERNS
def rule_regex(D, rid="GLS-SD-010-EMB"):
    return [x for x in head_patterns(D) if x["id"] == rid][0]["regex"][0]
def with_regex(D, rx, rid="GLS-SD-010-EMB"):
    pats = copy.deepcopy(head_patterns(D))
    for x in pats:
        if x["id"] == rid: x["regex"] = [rx]
    return head_engine(D, pats)
def without(D, rid):
    return head_engine(D, [x for x in copy.deepcopy(head_patterns(D)) if x["id"] != rid])
