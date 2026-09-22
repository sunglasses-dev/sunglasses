"""The case-CONSTRUCTING runner. r1 and r2 both hit the same ceiling:

    "0 findings (UNMEASURED)"

not because the rule was clean, but because every probe I supplied ran FIXED
fixtures. A review that can only run my fixtures can only confirm my beliefs.
Both rounds asked for a permitted runner and I had not written one.

This builds its cases INTERNALLY from orthogonal axes and prints counts and
ids only -- no fixture bodies, no product source, no writes anywhere. The
reviewer chooses an axis with a selector argument and can therefore probe
shapes the author never enumerated.

THE AXIS THAT HAS BEATEN EVERY PREDICATE SO FAR IS THE QUOTING CONTEXT, not
the value. The interior-quote evasion (`API_KEY=${VAR}'<secret>`) survived a
token list, a structural exclusion, a terminator fix AND a positive
secret-shaped test, because in each one the value region ended at the first
quote of either kind. Fixed fixtures were never going to find it.

Usage:  python3 _p7.py <dir> [axis ...]      axes: quoting value boundary key all
"""
import itertools, os, sys

D = sys.argv[1]
ARGS = sys.argv[2:]
# A directory of REVIEWER-AUTHORED candidates. Round 3 refused item 9 because
# it could not search beyond the axes I wrote, and it was right: a review that
# can only run the author's cases can only confirm the author's beliefs.
# Authoring a JSON object is not authoring a probe, so this is inside the
# no-new-code restriction -- the same mechanism the worker lane uses.
#
#   {"name": "...", "expect": "block" | "allow", "why": "...",
#    "text": "<the input>", "channel": "file"}
#
# Every step record prints the CHANNEL it used, so a result cannot be read
# without knowing what it was measured on.
CASES = None
if "--cases" in ARGS:
    i = ARGS.index("--cases")
    CASES = ARGS[i + 1]
    ARGS = ARGS[:i] + ARGS[i + 2:]
AXES = ARGS or ["all"]
sys.path.insert(0, os.path.join(D, "head"))
from sunglasses.engine import SunglassesEngine

RULE = "GLS-SD-010-EMB"
SEC = "hunter" + "2" + "x9q"          # assembled; matches no real account
BENIGN_V = "${API_KEY}"                # a reference: nothing to leak

# ── the axes, each a mapping label -> a function wrapping (key, value) ───────
QUOTING = {
    "json_double":        lambda k, v: '{"cfg":"' + k + '=' + v + '"}',
    "single_in_double":   lambda k, v: '{"cfg":"' + k + '=' + v + "'tail\"}",
    "double_in_single":   lambda k, v: "{'cfg':'" + k + '=' + v + '"tail\'}',
    "escaped_double":     lambda k, v: '{"cfg":"' + k + '=' + v + '\\"tail"}',
    "nested_json_string": lambda k, v: '{"outer":"{\\"cfg\\":\\"' + k + '=' + v + '\\"}"}',
    "python_repr":        lambda k, v: "{'cfg':'" + k + '=' + v + "'}",
    "yaml_quoted":        lambda k, v: 'env:\n  - "' + k + '=' + v + '"\n',
    "yaml_bare_indented": lambda k, v: 'env:\n  ' + k + '=' + v + '\n',
    # BARE CR is a default axis now, not an afterthought: it is the one cell
    # this runner found on its first execution, after two review rounds and two
    # hundred hand-written fixtures had never tried it.
    "cr_only_line":       lambda k, v: 'x\r  ' + k + '=' + v + '\r',
    "crlf_line":          lambda k, v: 'x\r\n  ' + k + '=' + v + '\r\n',
    "cr_inside_json":     lambda k, v: '{"d":"x\r' + k + '=' + v + '"}',
    "escaped_newline":    lambda k, v: '{"d":"HOME=/root\\n' + k + '=' + v + '"}',
    "bare_line":          lambda k, v: k + '=' + v + '\n',
}
VALUES = {
    "plain_secret":      SEC,
    "angle_wrapped":     "<" + SEC + ">",
    "ref_shaped":        "${" + SEC + "}",
    "ref_then_comma":    "${VAR}," + SEC,
    "prefixed_example":  "example" + SEC,
    "prefixed_xxx":      "xxx" + SEC,
    "all_lower_nodigit": "abcdefghijkl",
    "all_upper":         "ABCDEFGHIJKL",
    "short":             "ab1",
}
KEYS = {"API_KEY": "API_KEY", "PASSWORD": "PASSWORD", "lower_kwarg": "api_key"}

e = SunglassesEngine()

def fires(text):
    """Reported by THIS rule anywhere a consumer would see it.

    Not `file` alone. GLS-SD-010 declares message/file/code and dedup reports
    the PARENT there, suppressing this id -- so a shape at a bare line start
    looks "missed" on `file` while being reported on api_response. The first
    draft of this runner checked `file` only and produced six such phantom
    rows. A fail row is a harness defect until the stimulus is proven.
    """
    for ch in ("file", "api_response", "log_memory", "agent_input"):
        d = e.scan(text, channel=ch).to_dict()
        if RULE in {f["id"] for f in d["findings"]}:
            return True
    return False

def covered(text):
    """Blocked by ANY GLS-SD rule -- the honest question for a leak."""
    d = e.scan(text, channel="file").to_dict()
    return any(f["id"].startswith("GLS-SD-") for f in d["findings"])

def run(axis):
    print(f"\n[{axis}]")
    rows, missed = 0, []
    if axis in ("quoting", "all"):
        for qn, q in QUOTING.items():
            for vn, v in VALUES.items():
                rows += 1
                # A REAL SECRET in any quoting context must be reported. The
                # three non-secret values are controls, not expectations.
                expect = vn not in ("all_lower_nodigit", "all_upper", "short")
                got = fires(q("API_KEY", v))
                if expect and not got:
                    missed.append(f"{qn}/{vn}")
    if axis in ("key", "all"):
        for kn, k in KEYS.items():
            for qn, q in QUOTING.items():
                rows += 1
                got = fires(q(k, SEC))
                # a lower-case kwarg must NOT fire; an upper-case key must
                if kn == "lower_kwarg" and got:
                    missed.append(f"KEYCASE {qn}/{kn} fired")
                if kn != "lower_kwarg" and not got:
                    missed.append(f"{qn}/{kn}")
    if axis in ("value", "all"):
        for vn, v in VALUES.items():
            rows += 1
            if vn in ("all_lower_nodigit", "all_upper", "short"):
                continue
            if not fires('{"cfg":"API_KEY=' + v + '"}'):
                missed.append(f"VALUE {vn}")
    if axis in ("boundary", "all"):
        for b in ("", " ", "\t", "`", "|", ">", ",", "[", "{", '"', "'"):
            rows += 1
            got = fires('x' + b + 'API_KEY=' + SEC + '\n')
            # a BARE SPACE and a BACKTICK must never be boundaries
            if b in (" ", "`") and got:
                missed.append(f"BOUNDARY {b!r} admitted")
    print(f"  cases {rows} · unreported/unexpected {len(missed)}")
    for m in missed:
        print(f"      {m}")
    return missed

def run_cases(path):
    """Reviewer-authored JSON candidates. The finding is a mismatch."""
    import json, glob
    files = sorted(glob.glob(os.path.join(path, "*.json")))
    print(f"\n[cases {path}]  {len(files)} authored candidate(s)")
    miss = []
    for f in files:
        try:
            c = json.load(open(f))
        except Exception as exc:
            print(f"      {os.path.basename(f)}: UNREADABLE ({exc}) -- not scored")
            miss.append(os.path.basename(f))
            continue
        need = c.get("expect")
        ch = c.get("channel", "file")
        if need not in ("block", "allow") or not isinstance(c.get("text"), str):
            print(f"      {c.get('name', f)}: needs \"expect\" block|allow and a "
                  f"string \"text\" -- not scored")
            miss.append(c.get("name", f))
            continue
        d = e.scan(c["text"], channel=ch).to_dict()
        ids = {x["id"] for x in d["findings"]}
        got = "block" if RULE in ids else "allow"
        ok = got == need
        if not ok:
            miss.append(c.get("name", f))
        print(f"      {c.get('name','?'):40} channel={ch:12} expect {need:5} "
              f"got {got:5} {'OK' if ok else '*MISMATCH*'}")
    print(f"  cases {len(files)} · mismatches {len(miss)}")
    return miss

bad = []
for a in AXES:
    bad += run(a)
if CASES:
    bad += run_cases(CASES)
print(f"\nCONSTRUCTED {'CLEAN' if not bad else str(len(bad))+' ROWS TO EXPLAIN'}")
sys.exit(0 if not bad else 1)
