"""Write one complete tree per mutation, each carrying exactly one defect.

A mutation that was never injected is worse than one that survived: it reads as
a skip. So this fails loudly if a target string is absent, and it verifies after
writing that the mutant's patterns.py actually DIFFERS from head's.
"""
import io, os, shutil, sys, json

D = sys.argv[1]
SRC = os.path.join(D, "head")
OUT = os.path.join(D, "mutants")
REL = os.path.join("sunglasses", "patterns.py")
orig = io.open(os.path.join(SRC, REL), encoding="utf-8").read()

# The predicate has NO exclusion any more -- value-driven exclusions were
# closed as a class on 9-21 after three of them were defeated by
# attacker-chosen bytes. So M3/M8/M9 (which mutated that exclusion) are gone
# and M11 replaces them: it ADDS one back and must silence the evasion rows.
# The builder refused to build until these were retargeted, which is the point
# of a target-absent guard -- a mutation that was never injected reads as a
# skip, and a skip reads as coverage.
BOUNDARY = r"(?:\A[ \t]*|\n[ \t]*|\r[ \t]*"
CLASS    = r"""[\"'{\[,])"""
TAIL     = r"""|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY))\s*=","""

MUTS = [
 ("M1-case-scope-dropped",      "(?-i:(?:API_KEY", "(?:(?:API_KEY"),
 ("M2-indentation-dropped",     BOUNDARY, r"(?:\A|\n|\r"),
 ("M4-bare-space-a-boundary",   CLASS, r"""[\"'{\[, ])"""),
 ("M5-line-start-dropped",      r"(?:\A[ \t]*|\n[ \t]*", r"(?:\n[ \t]*"),
 ("M7-apostrophe-removed",      CLASS, r"""[\"{\[,])"""),
 ("M10-literal-CR-removed",     r"|\r[ \t]*", ""),
 # The CLASS control: put a value exclusion back and the evasion rows must go
 # quiet. This is the one that guards the decision the rule now rests on.
 ("M11-value-exclusion-readded", TAIL,
  r"""|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY))\s*="""
  r"""(?![ \t]*[\"']?[ \t]*(?:<|\$\{|your[_-]|x{3,}|example|changeme|redacted))","""),
]

missing = [n for n, old, _ in MUTS if old not in orig]
if missing:
    sys.exit(f"MUTATION TARGETS ABSENT, refusing to build a battery that would "
             f"silently skip: {missing}")

ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache")
index = []
for name, old, new in MUTS:
    dst = os.path.join(OUT, name)
    shutil.copytree(SRC, dst, ignore=ignore)
    mutated = orig.replace(old, new, 1)
    assert mutated != orig, name
    io.open(os.path.join(dst, REL), "w", encoding="utf-8").write(mutated)
    # verified on disk, not assumed from the write returning
    back = io.open(os.path.join(dst, REL), encoding="utf-8").read()
    assert back == mutated and back != orig, f"{name} did not land on disk"
    index.append(name)

# A CONTROL TREE: a verbatim copy with no defect. If the battery reports this
# one red, the harness is broken and no other row means anything.
dst = os.path.join(OUT, "M0-control-unmutated")
shutil.copytree(SRC, dst, ignore=ignore)
assert io.open(os.path.join(dst, REL), encoding="utf-8").read() == orig
index.insert(0, "M0-control-unmutated")

io.open(os.path.join(OUT, "INDEX.json"), "w").write(json.dumps(index, indent=2))
print(f"built {len(index)} trees (1 control + {len(MUTS)} mutants) under mutants/")
for n in index:
    print(f"  {n}")
