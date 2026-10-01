#!/usr/bin/env python3
"""Mutants for CU-M8 (one route verdict) and CU-M6 (NO_COLOR, non-tty).

Same rules as `mutate_doctor.py`, restated because they are the reason a kill
count can be believed: the mutations are applied to a PRIVATE COPY of the tree
(the real source is never written), bytecode is off, the baseline must be green
before any kill is counted, and an anchor that does not match exactly once is a
SURVIVOR and never a skip.

    python3 tests/proxy/mutate_doctor_verdict.py

A mutant is KILLED when the suite goes red. The last column names the control
that is expected to catch it; it is printed beside the result so a kill by the
wrong control is visible rather than assumed.
"""
import atexit
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
WATCHED = ("sunglasses/proxy/doctor.py", "sunglasses/cli.py")


def _digests():
    return {p: hashlib.sha256((SOURCE_ROOT / p).read_bytes()).hexdigest()
            for p in WATCHED}


_AT_START = _digests()
_WORK = pathlib.Path(tempfile.mkdtemp(prefix="mutate-verdict-")) / "tree"
shutil.copytree(SOURCE_ROOT, _WORK,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
atexit.register(shutil.rmtree, _WORK.parent, True)

SUITE = "tests/proxy/test_doctor_verdict_and_color.py"
DOCTOR, CLI = "sunglasses/proxy/doctor.py", "sunglasses/cli.py"

# (id, file, the defect, old source, mutated source, control expected to fail)
MUTATIONS = [
    ('M8-LAUNCHER-FALSE', DOCTOR,
     'a build with no launcher says False again, so never-launched reads as FAIL',
     '    return None, {}\n\n\ndef _route_result',
     '    return False, {}\n\n\ndef _route_result',
     'test_a_route_nothing_launched_is_not_run_and_never_fail'),
    ('M8-NONE-IS-FAIL', DOCTOR,
     'the verdict function maps "no launch" to FAIL',
     '    if passed is None:\n        return NOT_RUN',
     '    if passed is None:\n        return "FAIL"',
     'test_a_route_nothing_launched_is_not_run_and_never_fail'),
    ('M8-FAIL-SOFTENED', DOCTOR,
     'a launcher that watched the route fail is reported NOT_RUN',
     '    return "PASS" if passed else "FAIL"',
     '    return "PASS" if passed else NOT_RUN',
     'test_every_route_verdict_agrees_between_text_and_json'),
    ('M8-AGGREGATE-REVERT', DOCTOR,
     'aggregate derives the verdict from `passed` again, bypassing the one field',
     '                    "result": e.result}',
     '                    "result": "PASS" if e.passed else "FAIL"}',
     'test_a_route_nothing_launched_is_not_run_and_never_fail'),
    ('M8-JSON-SPLIT', DOCTOR,
     'the JSON rendering says FAIL while the text reads the field',
     '        "per_wrapper": report.outcome.per_wrapper,',
     '        "per_wrapper": [dict(w, result="FAIL") for w in report.outcome.per_wrapper],',
     'test_a_route_nothing_launched_is_not_run_and_never_fail'),
    ('M8-TEXT-SILENT', CLI,
     'the text report stops printing a route verdict',
     '            verdict = route_verdict.get((row["name"], row["source"]))',
     '            verdict = None',
     'test_text_and_json_carry_the_same_verdict_for_a_wrapped_route'),
    ('M8-TEXT-OWN-VERDICT', CLI,
     'the text computes its own verdict instead of reading the JSON field',
     '    route_verdict = {(w["name"], w["source"]): w["result"]\n                     for w in rendered["per_wrapper"]}',
     '    route_verdict = {(w["name"], w["source"]): "NOT_RUN"\n                     for w in rendered["per_wrapper"]}',
     'test_every_route_verdict_agrees_between_text_and_json'),
    ('M8-TEXT-SAYS-FAIL', CLI,
     'the text prints FAIL for every route while the JSON carries the real field',
     '    route_verdict = {(w["name"], w["source"]): w["result"]\n                     for w in rendered["per_wrapper"]}',
     '    route_verdict = {(w["name"], w["source"]): "FAIL"\n                     for w in rendered["per_wrapper"]}',
     'test_text_and_json_carry_the_same_verdict_for_a_wrapped_route'),
    ('M8-EXIT-SOFT', DOCTOR,
     'a route launched and failed no longer exits 1',
     '    if any(w["result"] == "FAIL" for w in outcome.per_wrapper):\n        return EXIT_FAILED',
     '    if False:\n        return EXIT_FAILED',
     'test_a_failed_launch_still_exits_one_and_a_clean_launch_verifies'),
    ('M6-POLICY-NOT-APPLIED', CLI,
     'colour is restored: the policy is never applied before dispatch',
     '    _apply_color_policy()\n    parser = _MachineAwareParser(',
     '    parser = _MachineAwareParser(',
     'test_a_pipe_carries_zero_escape_sequences'),
    ('M6-IGNORE-NO-COLOR', CLI,
     'NO_COLOR is ignored',
     '    if env.get("NO_COLOR"):\n        return False',
     '    if False:\n        return False',
     'test_no_color_on_a_real_terminal_carries_zero_escape_sequences'),
    ('M6-IGNORE-TTY', CLI,
     'a pipe is treated as a terminal',
     '        return bool(stream.isatty())',
     '        return True',
     'test_a_pipe_carries_zero_escape_sequences'),
    ('M6-EMPTY-NO-COLOR', CLI,
     'an EMPTY NO_COLOR switches colour off (spec says non-empty only)',
     '    if env.get("NO_COLOR"):',
     '    if "NO_COLOR" in env:',
     'test_an_empty_no_color_does_not_switch_colour_off'),
    ('M6-ALWAYS-OFF', CLI,
     'colour is off even on a real terminal (over-correction)',
     '    return bool(stream.isatty())',
     '    return False',
     'test_control_a_real_terminal_without_no_color_still_gets_colour'),
]


def _run():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-B", "-m", "pytest", SUITE, "-q", "--no-header",
         "-p", "no:cacheprovider"],
        cwd=str(_WORK), env=env, capture_output=True, text=True)


def main():
    if _digests() != _AT_START:
        raise SystemExit("REFUSING: the source changed while this harness was starting")
    originals = {p: (_WORK / p).read_text() for p in WATCHED}

    base = _run()
    if base.returncode != 0:
        print("BASELINE IS RED. A kill count on a red suite is not a kill count.")
        print(base.stdout[-2500:])
        return 1
    print(f"baseline GREEN - {base.stdout.strip().splitlines()[-1]}\n")

    killed, survived = [], []
    for mid, rel, why, old, new, control in MUTATIONS:
        src = originals[rel]
        hits = src.count(old)
        if hits != 1:
            print(f"  {mid:26} ANCHOR LOST ({hits} matches) - proves nothing")
            survived.append(mid)
            continue
        (_WORK / rel).write_text(src.replace(old, new))
        try:
            proc = _run()
        finally:
            (_WORK / rel).write_text(src)
        failed = sorted({line.split("::")[-1].split("[")[0].split(" ")[0]
                         for line in proc.stdout.splitlines()
                         if line.startswith("FAILED")})
        red = proc.returncode != 0
        by = "expected control" if control in failed else "OTHER control"
        (killed if red else survived).append(mid)
        print(f"  {mid:26} {'KILLED  ' if red else 'SURVIVED'} "
              f"{by if red else ''}  ({why})")
        if red and control not in failed:
            print(f"      expected {control}; failed: {', '.join(failed) or 'none'}")
    if _digests() != _AT_START:
        raise SystemExit("REFUSING: the real source changed during the run")
    print(f"\n{len(killed)}/{len(MUTATIONS)} killed, {len(survived)} survived"
          + (f": {', '.join(survived)}" if survived else ""))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
