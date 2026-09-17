#!/usr/bin/env python3
"""Prove each control red by the defect it exists to catch. Round 2.

Round 1 shipped 11/11 and then failed 24 of 48 independent property controls.
The reason is written here rather than in a commit nobody re-reads: those
mutations were chosen by reading the implementation, so each one asked whether
the code did what it already did. This battery is rebuilt from the CONTRACT
rows and from every control ASTRA's review found failing, so a row can fail.

Two standing rules this file enforces on itself:

  An anchor is a claim about the source and goes stale like any other. Round 1
  published 11/11 from a run taken before `resolve_artifact()` existed, and on
  the pushed head one anchor matched twice and proved nothing. Anchor
  uniqueness is asserted when this file is generated AND checked again here at
  run time, and an ambiguous anchor is a SURVIVOR, never a skip.

  A kill count on a red baseline is not a kill count, and bytecode is disabled,
  because a cached .pyc ran the previous mutant on 2026-09-14 and produced
  false kills.

    python3 tests/proxy/mutate_install.py
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = ROOT / "sunglasses" / "proxy" / "doctor.py"
SUITE = "tests/proxy/test_doctor_reconciled.py tests/proxy/test_doctor_selftest.py"

# (id, the defect, old source, mutated source, the control that must fail)
MUTATIONS = [
    # ── Round 2. ASTRA's three blockers, one mutation per fix ─────────────
    ('R2-ABSENCE', 'a source we cannot read is reported absent instead of named',
     '        except OSError:\n            unreadable.append(str(path))\n            continue',
     '        except OSError:\n            continue',
     'test_an_unsearchable_parent_is_named_unreadable_not_absent'),
    ('R2-CHECKS-LOCAL', "a route's checks overwrite the self-test's evidence",
     '        passed, route_result = launch(entry)',
     '        passed, route_result = launch(entry); checks = route_result',
     'test_the_self_tests_checks_are_not_overwritten_by_a_route'),
    ('R2-MEASURED', 'the report carries a zero instead of the measured duration',
     '                  self_test_measured_ms=measured_ms,',
     '                  self_test_measured_ms=0,',
     'test_the_measured_figure_is_taken_and_not_handed_to_us'),
    ('ONE-CLASSIFIER', "the doctor classifies with its own rule instead of install's",
     '                state=_install.classify(spec, artifact=artifact)))',
     '                state=WRAPPED if isinstance(spec, dict) and _install.MARKER in spec else DIRECT))',
     'test_the_doctor_and_install_never_disagree'),
    ('ONE-PARSER', 'a duplicate-key config is read as fine instead of unreadable',
     '            doc = _install._parse(raw, path)',
     '            doc = json.loads(raw.decode("utf-8"))',
     'test_a_duplicate_key_config_is_unreadable_not_quietly_resolved'),
    ('IDENTITY', 'artifact identity is the interpreter again, not the entry point',
     '    path = pathlib.Path(artifact) if artifact is not None else artifact_path()[0]',
     '    path = pathlib.Path(sys.executable)',
     'test_artifact_identity_is_the_proxy_entry_point_not_the_interpreter'),
    ('EXIT2', 'an unreadable source falls through to doubt instead of operational',
     '    if unreadable:\n        return EXIT_OPERATIONAL',
     '    if False:\n        return EXIT_OPERATIONAL',
     'test_an_unreadable_source_is_exit_2_and_names_the_file'),
    ('EXIT2-NOT-3', 'a clean DIRECT inventory is reported as operational',
     '    if unreadable:\n        return EXIT_OPERATIONAL\n    return outcome.exit_code',
     '    return EXIT_OPERATIONAL',
     'test_a_clean_direct_inventory_is_still_3_not_2'),
    ('SELFTEST-FIRST', 'an unreadable source outranks a failed self-test',
     '    if not self_test_ok:\n        return EXIT_FAILED',
     '    if unreadable:\n        return EXIT_OPERATIONAL\n    if not self_test_ok:\n        return EXIT_FAILED',
     'test_a_failed_self_test_outranks_an_unreadable_source'),
    ('DEADLINE-CLASS', 'a deadline miss is reported as an ordinary schema failure',
     '        cls = DEADLINE if failed == ["deadline"] else SCHEMA',
     '        cls = SCHEMA',
     'test_a_deadline_miss_is_its_own_class_not_a_schema_miss'),
    ('DEADLINE-FAIL', 'a deadline miss is downgraded to a warning',
     '    return SelfTestVerdict(ok=bool(valid and not failed),',
     '    return SelfTestVerdict(ok=bool(valid and (not failed or failed == ["deadline"])),',
     'test_a_deadline_miss_is_a_real_failure_not_a_warning'),
    ('DEADLINE-BOUND', 'the bound is softened',
     'DEADLINE_BOUND_MS = 2250',
     'DEADLINE_BOUND_MS = 9999',
     'test_the_bound_is_the_contracts_figure_and_is_not_configurable'),
    ('MEASURED', 'the report prints a verdict without the measured figure',
     '    return f"deadline {measured_ms} ms measured against a {DEADLINE_BOUND_MS} ms bound"',
     '    return "deadline exceeded"',
     'test_the_report_prints_measured_beside_bound'),
    ('SKIPPED-CTL', 'skipped_invocation becomes optional again',
     'REQUIRED_CONTROLS = ("constant_allow", "constant_deny", SKIPPED_INVOCATION_CONTROL)',
     'REQUIRED_CONTROLS = ("constant_allow", "constant_deny")',
     'test_the_skipped_invocation_control_is_required_not_optional'),
    ('CONTROL-VOID', 'a control that PASSES no longer voids the run',
     '    return all(value == CONTROL_MUST_BE for value in controls.values())',
     '    return True',
     'test_a_control_that_passes_voids_the_whole_run'),
    ('LEAK', 'a check verdict carrying upstream text is passed through',
     '    return {name: value for name, value in dict(checks or {}).items()\n            if name in SELF_TEST_CHECKS and value in CHECK_RESULTS}',
     '    return dict(checks or {})',
     'test_a_check_verdict_carrying_an_exception_string_is_dropped'),
    ('NO-ARTIFACT', 'a build with no entry point still claims routes are wrapped',
     '        return pathlib.Path(_install.__file__).resolve().parent / "proxy" / "__main__.py", False',
     '        return pathlib.Path(sys.executable), True',
     'test_a_build_with_no_entry_point_verifies_nothing'),
]


def run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-B", "-m", "pytest", *SUITE.split(), "-q", "--no-header",
         "-p", "no:cacheprovider"],
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
        hits = original.count(old)
        if hits != 1:
            print(f"  {mid:12} ANCHOR LOST ({hits} matches) — proves nothing")
            survived.append((mid, why, f"anchor x{hits}"))
            continue
        TARGET.write_text(original.replace(old, new))
        try:
            r = run()
        finally:
            TARGET.write_text(original)

        fails = [l.split("::")[-1].split()[0].split("[")[0]
                 for l in r.stdout.splitlines() if l.startswith("FAILED")]
        if r.returncode != 0 and control in fails:
            print(f"  {mid:12} KILLED by {control}  ({len(fails)} failed)")
            killed.append(mid)
        elif r.returncode != 0:
            print(f"  {mid:12} red but NOT by {control} — fails: {sorted(set(fails))[:3]}")
            survived.append((mid, why, "wrong control"))
        else:
            print(f"  {mid:12} SURVIVOR — {why}")
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
