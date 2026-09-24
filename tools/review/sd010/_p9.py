"""The DECODER probe, shipped as a file because round 10 could not run one.

Round 10 wanted to check, independently of the grammar module, what Python,
JSON and YAML make of a spelling, and was REFUSED: the contract forbids an
inline script and no supplied probe decoded anything. T9 RULING 32 named that
a harness gap, so this is it.

For every spelling it prints what each decoder does, by CODEPOINT only (the
reviewer channel filters on text), and where the matrix stands on it:

    TABLE        an escape the table lists, with the grammars it claims
    NOT_ESCAPE   bytes the table says no grammar reads as an escape
    DERIVED      a spelling enumerated from the decoders' own rules (RULING 32)
    absent       the matrix has no row for it

The decoding here is written again, not imported, so a wrong decoder in the
grammar module cannot agree with itself. The probe FAILS (exit 1) when the
matrix says one thing about a spelling and the decoders say another, or when
the regex engine's own fold set differs from the one the matrix enumerated.
An ABSENT spelling is reported, never failed: whether it matters is the
reviewer's call, and p7 is where to test it against the rule.

Spellings: the sixteen round 10 probed, then every fenced ```decode block in
VERDICT.md, each {"name": "...", "spelling": "..."} (JSON string escapes, so
a backslash is written twice and a non-ASCII letter as \\uXXXX).
"""
import ast, json, os, re, string, sys, warnings

D = sys.argv[1]
sys.path.insert(0, os.path.join(D, "head"))
sys.path.insert(0, os.path.join(D, "head", "tests"))
import yaml                                                   # noqa: E402
import sd010_escape_grammar as grammar                        # noqa: E402
import test_sd010_escape_grammar as matrix_tests              # noqa: E402


def read(which, spelling):
    quoted = '"' + spelling + '"'
    try:
        if which == "json":
            got = json.loads(quoted)
        elif which == "python":
            with warnings.catch_warnings():   # an unknown escape warns and stays
                warnings.simplefilter("ignore")
                got = ast.literal_eval(quoted)
        else:
            got = yaml.safe_load(quoted)
    except Exception as exc:                  # noqa: BLE001 -- a refusal is the answer
        return None, type(exc).__name__
    return (got, None) if isinstance(got, str) else (None, "not a string")


def cps(s, cap=14):
    out = " ".join("U+%04X" % ord(c) for c in s[:cap])
    return out + (" +%d more" % (len(s) - cap) if len(s) > cap else "")


bad = 0

# 1. the fold set, enumerated again from the engine. An ALTERNATION of the 52
# letters, not the matrix's character class, so the two are built differently.
_any_letter = re.compile("|".join(string.ascii_letters), re.IGNORECASE)
folds = [c for c in range(0x80, 0x110000) if _any_letter.fullmatch(chr(c))]
mine = {chr(c) for c in folds}
theirs = set(grammar.FOLD_EQUIVALENTS)
print(f"FOLD SET  engine says {len(mine)}: {cps(''.join(sorted(mine)))}")
print(f"          matrix enumerated {len(theirs)}: "
      f"{'SAME' if mine == theirs else '*** DIFFERS ***'}")
bad += mine != theirs

# 2. where the matrix stands on a spelling
table = {}
for e in grammar.TABLE:
    table.setdefault(e.spelling, []).append(e)
derived = {d.spelling: d for d in grammar.DERIVED}
not_escapes = set(grammar.NOT_ESCAPES)


def check(name, spelling):
    got = {g: read(g, spelling) for g in ("json", "python", "yaml")}
    readings = []
    for g in ("json", "python", "yaml"):
        s, _ = got[g]
        if s is not None and s not in readings:
            readings.append(s)
    if spelling in table:
        where, ok = "TABLE", all(got[g][0] == e.decoded
                                 for e in table[spelling] for g in e.grammars)
    elif spelling in derived:
        where, ok = "DERIVED " + derived[spelling].family, \
            tuple(readings) == tuple(derived[spelling].readings)
    elif spelling in not_escapes:
        # the claim is that the decoded reading IS the raw reading
        where, ok = "NOT_ESCAPE", all(s is None or s == spelling for s, _ in got.values())
    else:
        where, ok = "absent", True
    print(f"  {name}")
    print(f"    spelling {cps(spelling)}")
    for g in ("json", "python", "yaml"):
        s, why = got[g]
        print(f"    {g:7} " + (f"REFUSED {why}" if s is None else f"reads {cps(s)}"))
    print(f"    matrix  {where}  {'agrees' if ok else '*** DISAGREES ***'}")
    return not ok


print("ROUND 10 PROBES")
for name, spelling in matrix_tests.R10_PROBES.items():
    bad += check(name, spelling)

vpath = os.path.join(D, "VERDICT.md")
blocks = re.findall(r"```decode\s*\n(.*?)```", open(vpath, encoding="utf-8").read(), re.S) \
    if os.path.exists(vpath) else []
print(f"YOUR SPELLINGS: {len(blocks)} fenced decode block(s) in VERDICT.md")
unparsed = 0
for i, b in enumerate(blocks, 1):
    try:
        row = json.loads(b)
        name, spelling = str(row["name"]), row["spelling"]
        assert isinstance(spelling, str) and spelling
    except Exception as exc:                  # noqa: BLE001
        print(f"  block {i}: NOT PARSED ({type(exc).__name__}), not scored")
        unparsed += 1
        continue
    bad += check(name, spelling)

print(f"DECODE  {bad} disagreement(s), {unparsed} unparsed block(s)")
sys.exit(1 if bad else 0)
