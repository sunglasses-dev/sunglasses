#!/usr/bin/env python3
"""Prove the CLI-level controls red, the same way as the module-level ones.

Separate from `mutate_install.py` because these mutate `sunglasses/cli.py` and
the suite they prove is `test_install_cli.py`. Same rules: bytecode off, green
baseline first, a mutation the suite survives is a SURVIVOR and a gap.
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = ROOT / "sunglasses" / "cli.py"
SUITE = "tests/proxy/test_install_cli.py"

MUTATIONS = [
    ("H1", "the default wiring target reaches into the user's HOME",
     '    return _pl.Path(args.config) if args.config else _pl.Path.cwd() / ".mcp.json"',
     '    return _pl.Path(args.config) if args.config else _pl.Path.home() / ".claude.json"',
     "test_install_default_target_is_the_project_config_not_the_home_one"),

    ("H2", "an unresolvable artifact exits 0 instead of 2",
     '        print(f"\\n  {RED}SUNGLASSES install refused{RESET} — {e}")\n'
     '        print(f"  {DIM}target: {target}{RESET}\\n")\n'
     '        sys.exit(2)\n'
     '    except (_inst.ConfigConflict, _inst.ConfigIOError) as e:',
     '        print(f"\\n  {RED}SUNGLASSES install refused{RESET} — {e}")\n'
     '        print(f"  {DIM}target: {target}{RESET}\\n")\n'
     '        sys.exit(0)\n'
     '    except (_inst.ConfigConflict, _inst.ConfigIOError) as e:',
     "test_install_exits_2_and_says_why_when_the_artifact_is_absent"),

    # First form of this row mutated install()'s `artifact=` argument, and it
    # SURVIVED because `resolve_artifact()` on the line above raises first, so
    # the mutated line is unreachable. A fail row is a harness defect until the
    # stimulus is proven, and so is a survivor: this one proved the mutation,
    # not the code. Mutating the resolve call itself is the reachable form.
    ("H3", "install wires whatever is at hand instead of the real artifact",
     '        artifact = _inst.resolve_artifact()',
     '        artifact = target',
     "test_install_never_writes_outside_the_named_config"),

    ("H4", "uninstall without a record exits 0 instead of 2",
     '        print(f"\\n  {RED}SUNGLASSES uninstall refused{RESET} — {e}")\n'
     '        print(f"  {DIM}target: {target}{RESET}\\n")\n'
     '        sys.exit(2)',
     '        print(f"\\n  {RED}SUNGLASSES uninstall refused{RESET} — {e}")\n'
     '        print(f"  {DIM}target: {target}{RESET}\\n")\n'
     '        sys.exit(0)',
     "test_uninstall_without_a_record_exits_2_and_does_not_mutate"),

    ("H5", "--config is ignored and the default is used regardless",
     '    return _pl.Path(args.config) if args.config else _pl.Path.cwd() / ".mcp.json"',
     '    return _pl.Path.cwd() / ".mcp.json"',
     "test_install_accepts_an_explicit_config_path"),
]


def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-B", "-m", "pytest", SUITE, "-q", "--no-header",
         "-p", "no:cacheprovider"],
        cwd=str(ROOT), env=env, capture_output=True, text=True)


def main():
    original = TARGET.read_text()
    base = run()
    if base.returncode != 0:
        print("BASELINE IS RED. A kill count on a red suite is not a kill count.")
        print(base.stdout[-2000:])
        return 1
    print(f"baseline GREEN — {base.stdout.strip().splitlines()[-1]}\n")

    killed, survived = [], []
    for mid, why, old, new, control in MUTATIONS:
        if original.count(old) != 1:
            print(f"  {mid:5} ANCHOR LOST ({original.count(old)} matches)")
            survived.append((mid, why, "anchor"))
            continue
        TARGET.write_text(original.replace(old, new))
        try:
            r = run()
        finally:
            TARGET.write_text(original)
        fails = [l.split("::")[-1].split()[0]
                 for l in r.stdout.splitlines() if l.startswith("FAILED")]
        if r.returncode != 0 and control in fails:
            print(f"  {mid:5} KILLED by {control}  ({len(fails)} failed)")
            killed.append(mid)
        elif r.returncode != 0:
            print(f"  {mid:5} red but NOT by {control} — fails: {fails}")
            survived.append((mid, why, f"wrong control: {fails}"))
        else:
            print(f"  {mid:5} SURVIVOR — {why}")
            survived.append((mid, why, "survived"))

    assert TARGET.read_text() == original, "target not restored"
    print(f"\nkilled {len(killed)}/{len(MUTATIONS)}")
    if survived:
        print("\nSURVIVORS (each one is a gap):")
        for mid, why, how in survived:
            print(f"  {mid}: {why}  [{how}]")
        return 1
    print("every mutation killed by its own control")
    return 0


if __name__ == "__main__":
    sys.exit(main())
