"""Write one complete tree per mutation, each carrying exactly one defect.

A mutation that was never injected is worse than one that survived: it reads as
a skip. So this fails loudly if a target string is absent, and it verifies after
writing that the mutant's patterns.py actually DIFFERS from head's.
"""
import io, os, shutil, sys, json

D = sys.argv[1]
SRC = os.path.join(D, "head")
OUT = os.path.join(D, "v")
REL = os.path.join("sunglasses", "patterns.py")
orig = io.open(os.path.join(SRC, REL), encoding="utf-8").read()

# ROUND 11 moved the name scopes from `(?i:` to `(?ai:` (RULING 32), and the
# two targets that spell a scope moved with them; the builder refused until
# they did.
#
# ROUND 10 REWROTE THE RULE FROM A TABLE (T9 RULING 13), and every target
# below moved with it; the builder refused until they were retargeted, which is
# the feature. The indentation and separator groups now span several source
# lines, so those targets are CUT from the file between two anchors that must
# each occur once, rather than typed out and left to drift.
def _between(start, end):
    assert orig.count(start) == 1 and orig.count(end) == 1, (start, end)
    i = orig.index(start)
    return orig[i:orig.index(end, i)]

CLASS = r"""\x85\u2028\u2029\"'{\[,]"""
INDENT = _between(r'r"(?:[ \t]|(?-i:', r'r"(?-i:(?:API_KEY')
SEP = _between(r'r"(?:\s|(?-i:', r'r"(?:=|(?-i:')
LEAD = "\n" + " " * 12            # the indentation of a regex source line
EQUALS_END = r'r"|\\N\{(?ai:EQUALS SIGN)\}))",'
EXCLUSION = r"""r"(?![ \t]*[\"']?[ \t]*(?:<|\$\{|your[_-]|x{3,}|example|changeme|redacted))","""

MUTS = [
 ("V1-case-scope-dropped",       "(?-i:(?:API_KEY", "(?:(?:API_KEY"),
 ("V2-indentation-dropped",      INDENT, ""),
 ("V4-bare-space-a-boundary",    CLASS, r"""\x85\u2028\u2029\"'{\[, ]"""),
 ("V5-line-start-dropped",       r'r"(?:\A|', 'r"(?:'),
 ("V7-apostrophe-removed",       CLASS, r"""\x85\u2028\u2029\"{\[,]"""),
 ("V10-literal-CR-removed",      r"[\n\r\v\f", r"[\n\v\f"),
 ("V12-escaped-tab-not-indent",  r"\\[ \tt]|", r"\\[ \t]|"),
 ("V13-unicode-separators-gone", CLASS, r"""\x85\"'{\[,]"""),
 ("V14-separator-literal-only",  SEP, r'r"\s*"' + LEAD),
 # NEW in round 10: one row per escape family the table added. The matrix
 # (tests/test_sd010_escape_grammar.py) is what sees these.
 ("V15-boundary-hex-escapes-gone",
  r'r"|\\x(?:0[a-dA-D]|1[c-eC-E]|85|2[27cC]|5[bB]|7[bB])"', 'r""'),
 ("V16-boundary-octal-escapes-gone",
  r'r"|\\(?:0?(?:1[2-5]|3[4-6]|4[27]|54)|205|133|173)"', 'r""'),
 ("V17-line-feed-names-gone",
  r"(?ai:LINE FEED|NEW LINE|END OF LINE|LF|NL|EOL|CARRIAGE", r"(?ai:CARRIAGE"),
 ("V18-indentation-numeric-gone",
  r"|\\x(?:09|20)|\\u00(?:09|20)|\\U000000(?:09|20)", ""),
 ("V19-escaped-equals-gone",
  r"\\x3[dD]|\\u003[dD]|\\U0000003[dD]|\\0?75", r"\\x3[dD]"),
 # the OVER-FIRE direction: IGNORECASE reading \R \T \V as escapes, and a
 # backslash before any whitespace read as an escape (r9's class)
 ("V20-escapes-case-folded",     r"(?-i:\\", r"(?:\\", 0),   # every occurrence
 ("V21-backslash-any-space",
  r"\\[ \t\n\r\x85\u2028\u2029tnrfvNLP_]", r"\\[\stnrfvNLP_]"),
 # ROUND 11 (T9 RULING 32): the four character-name scopes fold ASCII case
 # only. Put Unicode folding back and a name spelled with a dotted or dotless
 # I, a long s or the Kelvin sign reads as its ASCII twin again, which is the
 # over-fire round 10 found. Every occurrence, because each scope is a door.
 ("V22-names-fold-beyond-ASCII", "(?ai:", "(?i:", 0),
 # The CLASS control: put a value exclusion back and the evasion rows must go
 # quiet. This guards the decision the rule now rests on.
 ("V11-value-exclusion-readded", EQUALS_END, EQUALS_END[:-2] + '"' + LEAD + EXCLUSION),
]

# A mutation may need EVERY occurrence replaced, not the first. The
# indentation group appears seven times in the boundary class, so replacing
# one left the other six and the rows still fired -- a SURVIVOR that meant
# "my mutation was too weak", not "no guard here". A survivor that is really
# an ineffective mutation is the same lie as a kill that never injected.
MUTS = [(m + (1,)) if len(m) == 3 else m for m in MUTS]
missing = [n for n, old, _new, _c in MUTS if old not in orig]
# ONE occurrence means one. A target that also matched a comment or a sibling
# rule would mutate the wrong bytes and read as a kill of this rule.
ambiguous = [(n, orig.count(old)) for n, old, _new, c in MUTS
             if c == 1 and orig.count(old) > 1]
if ambiguous:
    sys.exit(f"MUTATION TARGETS AMBIGUOUS, refusing: {ambiguous}")
if missing:
    sys.exit(f"MUTATION TARGETS ABSENT, refusing to build a battery that would "
             f"silently skip: {missing}")

ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache")
index = []
for name, old, new, count in MUTS:
    dst = os.path.join(OUT, name)
    shutil.copytree(SRC, dst, ignore=ignore)
    mutated = orig.replace(old, new) if count == 0 else orig.replace(old, new, count)
    assert mutated != orig, name
    io.open(os.path.join(dst, REL), "w", encoding="utf-8").write(mutated)
    # verified on disk, not assumed from the write returning
    back = io.open(os.path.join(dst, REL), encoding="utf-8").read()
    assert back == mutated and back != orig, f"{name} did not land on disk"
    index.append(name)

# A CONTROL TREE: a verbatim copy with no defect. If the battery reports this
# one red, the harness is broken and no other row means anything.
dst = os.path.join(OUT, "V0-control-unchanged")
shutil.copytree(SRC, dst, ignore=ignore)
assert io.open(os.path.join(dst, REL), encoding="utf-8").read() == orig
index.insert(0, "V0-control-unchanged")

io.open(os.path.join(OUT, "INDEX.json"), "w").write(json.dumps(index, indent=2))
print(f"built {len(index)} trees (1 control + {len(MUTS)} variants) under v/")
for n in index:
    print(f"  {n}")
