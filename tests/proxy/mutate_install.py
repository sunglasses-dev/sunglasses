#!/usr/bin/env python3
"""Prove each control red by the defect it exists to catch.

A control that has never been seen to fail is decoration. For each row below we
apply the mutation to `sunglasses/install.py`, run the suite, and require that
at least one test FAILS and that the named control is among the failures. A
mutation the suite survives is reported as SURVIVOR and is a gap, not a pass.

Bytecode is disabled for every child run. A cached .pyc ran the PREVIOUS mutant
on 2026-09-14 and produced false kills.

    python3 tests/proxy/mutate_install.py
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = ROOT / "sunglasses" / "install.py"
SUITE = "tests/proxy/test_install_transaction.py"

# (id, why, old, new, the control that must be among the failures)
MUTATIONS = [
    ("C1", "uninstall restores a re-serialisation instead of the retained bytes",
     '        retained = pathlib.Path(rec["original_bytes_path"]).read_bytes()',
     '        retained = (json.dumps(json.loads(pathlib.Path(rec["original_bytes_path"])\n'
     '            .read_bytes().decode("utf-8")), indent=2) + "\\n").encode("utf-8")',
     "test_uninstall_restores_the_retained_bytes_exactly"),

    ("C2", "install wraps an already-wrapped entry",
     '    if classify(entry, artifact=artifact) == "WRAPPED":\n        return',
     '    if False:\n        return',
     "test_install_is_idempotent_and_never_wraps_the_wrapper"),

    ("C3", "uninstall rebuilds the file from the entry it knows, dropping the rest",
     '    servers[name] = rec["original_entry"]\n'
     '    _atomic_write(config_path, (json.dumps(doc, indent=2) + "\\n").encode("utf-8"))',
     '    doc = {"mcpServers": {name: rec["original_entry"]}}\n'
     '    _atomic_write(config_path, (json.dumps(doc, indent=2) + "\\n").encode("utf-8"))',
     "test_uninstall_does_entry_only_inverse_when_the_file_moved"),

    ("C4a", "an interrupted write reports success instead of refusing",
     '        raise ConfigIOError(f"write to {config_path} was interrupted: {e}") from e',
     '        return',
     "test_interrupted_write_leaves_the_original_intact"),

    ("C4b", "an interrupted write leaves its temp file behind",
     '        try:\n            os.unlink(tmp)\n        except OSError:\n            pass\n',
     '        pass\n',
     "test_interrupted_write_leaves_no_temp_file_behind"),

    # Re-pinned: the original anchor `        raise ArtifactUnresolved(` became
    # ambiguous the moment resolve_artifact() gained its own raise, and an
    # ambiguous anchor is reported ANCHOR LOST and proves nothing. This one is
    # unique to install()'s digest guard.
    ("C5", "install proceeds when the artifact cannot be resolved",
     '    try:\n        digest = _digest_file(artifact)\n    except OSError as e:',
     '    try:\n        digest = _digest_file(artifact)\n    except OSError as e:\n'
     '        digest = "0" * 64\n    if False:',
     "test_install_refuses_when_the_artifact_cannot_be_resolved"),

    # Control corrected after the first battery run: the row originally named
    # test_a_wrapper_naming_a_different_artifact_is_unverified, which passes on
    # the DIGEST because that test's other artifact also has other content. The
    # mutation was red but by the wrong test, and a true result under a false
    # label is not a result. The control that isolates the path half is the
    # byte-identical twin at another location.
    ("C6a", "WRAPPED without comparing the artifact path",
     '    if meta.get("artifact") != str(pathlib.Path(artifact).resolve()):\n'
     '        return "UNVERIFIED"',
     '    if False:\n        return "UNVERIFIED"',
     "test_an_identical_artifact_at_a_different_path_is_not_wrapped"),

    ("C6b", "WRAPPED without comparing the artifact digest",
     '    if meta.get("sha256") != actual:\n        return "UNVERIFIED"',
     '    if False:\n        return "UNVERIFIED"',
     "test_classify_is_content_addressed_not_path_addressed"),

    ("C6c", "a command that merely names us counts as wrapped",
     '    meta = entry.get(MARKER)\n'
     '    if not isinstance(meta, dict):\n'
     '        return "DIRECT"',
     '    meta = entry.get(MARKER)\n'
     '    if not isinstance(meta, dict):\n'
     '        return "WRAPPED" if "sunglasses" in repr(entry) else "DIRECT"',
     "test_a_command_that_merely_names_us_is_not_wrapped"),

    ("R4argv", "the -- argv form silently ignores the supplied argv",
     '        servers[name] = {"command": argv[0], "args": list(argv[1:])}',
     '        servers[name] = {"command": "npx", "args": []}',
     "test_install_with_argv_creates_and_wraps_a_new_entry"),

    ("MODE", "the atomic replace does not preserve the file mode",
     '        os.chmod(tmp, mode)',
     '        os.chmod(tmp, 0o600)',
     "test_install_preserves_the_file_mode"),
]


def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-B", "-m", "pytest", SUITE, "-q", "--no-header", "-p",
         "no:cacheprovider"],
        cwd=str(ROOT), env=env, capture_output=True, text=True)


def main():
    original = TARGET.read_text()

    base = run()
    if base.returncode != 0:
        print("BASELINE IS RED. A kill count on a red suite is not a kill count.")
        print(base.stdout[-2500:])
        return 1
    print(f"baseline GREEN — {base.stdout.strip().splitlines()[-1]}\n")

    killed, survived = [], []
    for mid, why, old, new, control in MUTATIONS:
        if original.count(old) != 1:
            print(f"  {mid:8} ANCHOR LOST ({original.count(old)} matches) — "
                  f"the mutation could not be applied, so this row proves nothing")
            survived.append((mid, why, "anchor"))
            continue
        TARGET.write_text(original.replace(old, new))
        try:
            r = run()
        finally:
            TARGET.write_text(original)

        fails = [l.split("::")[-1].split()[0]
                 for l in r.stdout.splitlines() if l.startswith("FAILED")]
        broke = r.returncode != 0
        named = control in fails
        if broke and named:
            print(f"  {mid:8} KILLED by {control}  ({len(fails)} failed)")
            killed.append(mid)
        elif broke:
            print(f"  {mid:8} red, but NOT by its control {control} — fails: {fails}")
            survived.append((mid, why, f"wrong control: {fails}"))
        else:
            print(f"  {mid:8} SURVIVOR — {why}")
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
