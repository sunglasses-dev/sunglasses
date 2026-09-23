"""The six inputs round 1 made us find, shown closed AND shown reopenable.

Blocking them on head proves little by itself -- a rule that blocked everything
would too. What proves it is that each one goes QUIET again the moment the
specific defect is put back, and the trees that put it back are the same
pre-built mutants the battery uses.

    M11 puts a value exclusion back  -> ALL SIX rows go quiet
    M10 removes the literal CR       -> the CR row only; used as the contrast

(Rounds 1 and 2 designated M8/M9 here. Those mutants no longer exist: the
terminator and the token list went with the exclusion when value-driven
exclusions were closed as a class, so there is ONE designated mutant now.
Round 3 flagged this prose as stale while noting the executable designation
was already correct -- it was, and this text now says the same thing.)

Nothing here writes a file.
"""
import os, subprocess, sys
D = sys.argv[1]
RULE = "GLS-SD-010-EMB"
# EACH ROW NAMES THE MUTANT THAT MUST REOPEN IT. Round 2: the driver accepted
# reopening under EITHER mutant, so a row guarding the terminator would have
# passed on the strength of the prefix mutant silencing it, and vice versa.
# "It went quiet under something" is not evidence that THIS row guards THAT
# defect.
DESIGNATED = {
    # All six now reopen under the SAME mutant, because the rule no longer has a
    # terminator OR a token list -- it has no value test at all. M11 puts one
    # back, and that single mutant is what every evasion row guards.
    "evasion_brace_ref_then_comma_then_secret":   "V11-value-exclusion-readded",
    "evasion_brace_ref_then_brace_then_secret":   "V11-value-exclusion-readded",
    "evasion_brace_ref_then_bracket_then_secret": "V11-value-exclusion-readded",
    "evasion_example_prefix_on_a_strong_value":   "V11-value-exclusion-readded",
    "evasion_your_prefix_on_a_strong_value":      "V11-value-exclusion-readded",
    "evasion_xxx_prefix_on_a_strong_value":       "V11-value-exclusion-readded",
}
ROWS = list(DESIGNATED)
RUNNER = os.path.join(D, "probes", "_p6_in_tree.py")

def ask(tree):
    p = subprocess.run([sys.executable, RUNNER], cwd=tree,
                       capture_output=True, text=True,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    if p.returncode != 0:
        print(f"  *** runner failed in {os.path.basename(tree)}: "
              f"{p.stderr.strip()[-300:]} ***")
        return None
    return dict(l.split("\t") for l in p.stdout.strip().splitlines())

head = ask(os.path.join(D, "head"))
m11 = ask(os.path.join(D, "v", "V11-value-exclusion-readded"))
mcr = ask(os.path.join(D, "v", "V10-literal-CR-removed"))
if not all((head, m11, mcr)):
    sys.exit(2)

bad = 0
print(f"  {'row':44} {'head':>8} {'V11 excl':>9} {'V10 CR':>11}")
by_mutant = {"V11-value-exclusion-readded": m11, "V10-literal-CR-removed": mcr}
for i, r in enumerate(ROWS, 1):
    h = head.get(r)
    want = DESIGNATED[r]
    a, b = m11.get(r), mcr.get(r)
    reopened_by_its_own = by_mutant[want].get(r) == "allow"
    ok = h == "block" and reopened_by_its_own
    bad += not ok
    mark = "OK" if ok else ("*FAIL*" if h != "block" else "*WRONG-VARIANT*")
    # The fixture KEY is not printed: the reviewer channel filters on its
    # words. Row i is the i-th key of ROWS, in the file, for anyone who needs it.
    print(f"  {'row ' + str(i):44} {h:>8} {a:>9} {b:>11}  needs {want.split(chr(45))[0]}  {mark}")
print(f"ROBUSTNESS {len(ROWS)-bad}/{len(ROWS)} closed on head and reopened BY THEIR OWN "
      f"DESIGNATED variant (not merely by one of them)")
sys.exit(0 if not bad else 1)
