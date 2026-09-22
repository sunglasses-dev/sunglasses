"""Run the pre-built mutant trees. THE REVIEWER WRITES NOTHING.

r1 refused this item and was right: the previous driver opened
head/sunglasses/patterns.py for writing, which the prompt forbade, checked the
word "failed" in pytest's last stdout line instead of the return code, and
bracketed the whole battery with one baseline rather than proving the harness
around each row.

All three are fixed by moving the writes OUT of the round. Every tree under
mutants/ was built and verified before the round started; this driver only
reads and executes.

M0 IS A CONTROL, not a mutant: a verbatim copy of head with no defect. It must
come back GREEN. If it is red, the battery is broken and no KILLED row below it
means anything -- which is the thing a kill count cannot tell you by itself.
"""
import json, os, subprocess, sys

D = sys.argv[1]
OUT = os.path.join(D, "mutants")
LOGS = os.path.join(D, "logs", "r2")
names = json.load(open(os.path.join(OUT, "INDEX.json")))

def run(tree):
    """-> (returncode, last stdout line).

    A KILL is pytest rc==1 AND a line reporting failed tests. Round 2 flagged
    that ANY non-zero counted, so a collection error (rc 2), an internal error
    (rc 3), a usage error (rc 4) or "no tests ran" (rc 5) would all have scored
    as kills -- a mutant that broke the harness would have looked like a mutant
    the harness caught. That is a FALSE KILL, the mirror image of the false
    negatives we usually hunt.
    """
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
    p = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider",
         "tests/test_sd010_embedded_boundary.py", "-q"],
        cwd=tree, capture_output=True, text=True, env=env)
    tail = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else "(no output)"
    return p.returncode, tail

rc0, tail0 = run(os.path.join(OUT, names[0]))
print(f"  {names[0]:28} rc={rc0} {tail0}")
if rc0 != 0:
    print("  *** THE CONTROL TREE IS RED. The battery is broken and every row "
          "below is meaningless. Treat this as a harness defect, not a product "
          "finding. ***")
    sys.exit(2)

killed = 0
mutants = names[1:]
# AN EMPTY BATTERY IS NOT A PASSING ONE. `killed == len(mutants)` is 0 == 0 when
# nothing was built, so a builder that wrote no trees -- a renamed directory, a
# glob that stopped matching, a failed pre-build -- printed "0/0 killed, control
# green" and exited 0. That is the most expensive version of a reassuring zero
# available here, because the mutation battery is the strongest evidence in the
# package and a reviewer reads its exit code first.
if not mutants:
    print("  *** NO MUTANT TREES. The battery injected NOTHING, so 0/0 is not "
          "a score. Harness defect, not a product finding. ***")
    sys.exit(2)
for n in mutants:
    rc, tail = run(os.path.join(OUT, n))
    # rc 1 = tests ran and failed. Anything else is the harness breaking, and
    # it is reported as such rather than banked as a kill.
    ok = (rc == 1) and (" failed" in tail)
    if rc not in (0, 1):
        print(f"  {n:28} *** HARNESS rc={rc} ({tail}) -- NOT a kill ***")
    killed += ok
    label = "KILLED  " if ok else ("*SURVIVED*" if rc == 0 else "*HARNESS* ")
    print(f"  {n:28} rc={rc} {label} {tail}")

print(f"MUTATIONS {killed}/{len(mutants)} killed, control green")
sys.exit(0 if killed == len(mutants) else 1)
