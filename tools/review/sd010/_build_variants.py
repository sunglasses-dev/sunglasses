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

# THE BOUNDARY CLASS MOVED AGAIN with the indentation fix, and the builder
# REFUSED to build until these were retargeted -- five targets had gone stale.
# That refusal is the feature: a mutation never injected reads as a kill you
# did not earn. Two new rows cover what the fix added.
IND  = r"(?:[ \t]|\\t)*"
CLASS = r"""[\"'{\[,]"""
# Round 7 moved the SEPARATOR: `\s*=` became this, and V11's target went stale
# with it -- the builder refused until it was retargeted, as it should.
SEP = r"(?:\s|\\[tnrf])*="

MUTS = [
 ("V1-case-scope-dropped",       "(?-i:(?:API_KEY", "(?:(?:API_KEY"),
 # every indentation allowance, everywhere
 ("V2-indentation-dropped",      IND, "", 0),      # every occurrence
 ("V4-bare-space-a-boundary",    CLASS, r"""[\"'{\[, ]"""),
 ("V5-line-start-dropped",       r"(?:\A" + IND + "|", "(?:"),
 ("V7-apostrophe-removed",       CLASS, r"""[\"{\[,]"""),
 ("V10-literal-CR-removed",      r"|\r" + IND, ""),
 # NEW, from round 4b's findings
 ("V12-escaped-tab-not-indent",  IND, r"[ \t]*", 0),   # every occurrence
 ("V13-unicode-separators-gone", r"|[\u2028\u2029]" + IND, ""),
 # NEW, from round 7's finding: the separator back to literal whitespace only
 ("V14-separator-literal-only",  SEP, r"\s*="),
 # The CLASS control: put a value exclusion back and the evasion rows must go
 # quiet. This guards the decision the rule now rests on.
 ("V11-value-exclusion-readded",
  r"""|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY))""" + SEP + '",',
  r"""|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY))""" + SEP
  + r"""(?![ \t]*[\"']?[ \t]*(?:<|\$\{|your[_-]|x{3,}|example|changeme|redacted))","""),
]

# A mutation may need EVERY occurrence replaced, not the first. The
# indentation group appears seven times in the boundary class, so replacing
# one left the other six and the rows still fired -- a SURVIVOR that meant
# "my mutation was too weak", not "no guard here". A survivor that is really
# an ineffective mutation is the same lie as a kill that never injected.
MUTS = [(m + (1,)) if len(m) == 3 else m for m in MUTS]
missing = [n for n, old, _new, _c in MUTS if old not in orig]
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
