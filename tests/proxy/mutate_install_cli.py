#!/usr/bin/env python3
"""Prove the CLI-level controls red, the same way as the module-level ones.

Separate from `mutate_install.py` because these mutate `sunglasses/cli.py` and
the suite they prove is `test_install_cli.py`. Same rules: bytecode off, green
baseline first, a mutation the suite survives is a SURVIVOR and a gap.
"""
import atexit
import hashlib
import os
import pathlib
import shutil
import tempfile
import subprocess
import sys

# THE TREE THIS MUTATES IS A PRIVATE COPY, and that is the whole of this block.
#
# Until 2026-09-19 the harness rewrote `sunglasses/cli.py` IN PLACE. Two things
# followed, and both were paid for on the same night:
#
#   * a kill STRANDS A MUTANT. Interrupt the run between the write and the
#     restore -- a platform budget cut, a Ctrl-C, an OOM -- and the working tree
#     keeps a mutated product. The next battery then refuses with BASELINE IS
#     RED, and that is the LUCKY case; the unlucky one is a reader that trusts
#     the file.
#   * it rewrites a tree OTHER PROCESSES READ. A reviewer working in the same
#     directory saw a mutated product mid-review and its round was void.
#
# So: copy the tree once, mutate the copy, point pytest at the copy. The real
# source is opened for reading and never for writing, and `_assert_source_untouched`
# proves that rather than asserting it in a comment.
SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE_TARGET = SOURCE_ROOT / "sunglasses/cli.py"


def _digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


_SOURCE_DIGEST_AT_START = _digest(SOURCE_TARGET)


def _assert_source_untouched(when):
    """Refuse LOUDLY if the real product moved while we ran.

    A silent mismatch is how the in-place version did its damage: nothing said
    anything until a later run found a red baseline and had to work backwards.
    """
    now = _digest(SOURCE_TARGET)
    if now != _SOURCE_DIGEST_AT_START:
        raise SystemExit(
            f"REFUSING: {SOURCE_TARGET} changed {when} this battery "
            f"({_SOURCE_DIGEST_AT_START[:16]} -> {now[:16]}). This harness "
            f"mutates a private copy and must never write the source tree.")


def _sweep_abandoned_copies(prefix, keep_hours=6):
    """Remove OUR OWN older copies, because an uncatchable kill skips `atexit`.

    The copy costs about 18 MB. A kill -9 -- which is exactly the case this
    harness now survives -- leaves it behind, so without this the fix trades a
    corrupted source tree for an unbounded pile of temp trees. The age floor is
    what keeps a CONCURRENT battery safe: a run younger than `keep_hours` is
    never touched, so two harnesses can run at once without eating each other.
    """
    import time
    root = pathlib.Path(tempfile.gettempdir())
    cutoff = time.time() - keep_hours * 3600
    for stale in root.glob(prefix + "*"):
        try:
            if stale.is_dir() and stale.stat().st_mtime < cutoff:
                shutil.rmtree(stale, ignore_errors=True)
        except OSError:
            pass

_sweep_abandoned_copies("mutate-install-cli-")
_WORK = pathlib.Path(tempfile.mkdtemp(prefix="mutate-install-cli-")) / "tree"
shutil.copytree(SOURCE_ROOT, _WORK,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
atexit.register(shutil.rmtree, _WORK.parent, True)

ROOT = _WORK
TARGET = ROOT / "sunglasses/cli.py"
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
    _assert_source_untouched("before the baseline")
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
    _assert_source_untouched("after the last mutant")
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
