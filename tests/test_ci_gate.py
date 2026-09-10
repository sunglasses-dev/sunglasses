"""
Guards for the CI gate split (2026-09-10; ASTRA round-1 NO-GO applied).

Two things are protected here, and both were shown breakable by text-grep
guards in review:
  1. scripts/ci_classify.py — the fail-closed docs-vs-code classifier that
     decides whether a PR needs the full six-Python matrix.
  2. .github/workflows/pattern-integrity.yml — loaded as YAML and checked
     SEMANTICALLY: every trigger, job, condition and command that the merge
     rule depends on. `check_workflow()` returns a list of problems so the
     same checker can be run against mutated documents; ASTRA's four
     round-1 mutations are negative controls below and must each FAIL it.
PyYAML is a declared dev extra (setup.py) so this collects in CI.
"""
from __future__ import annotations

import copy
import importlib.util
import shlex
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows" / "pattern-integrity.yml"
CLASSIFIER = ROOT / "scripts" / "ci_classify.py"

spec = importlib.util.spec_from_file_location("ci_classify", CLASSIFIER)
ci = importlib.util.module_from_spec(spec)
sys.modules["ci_classify"] = ci
spec.loader.exec_module(ci)

GATE_COMMANDS = (
    "pytest tests/test_pattern_integrity.py -v",
    "pytest tests/test_dogfood_bugs.py -v",
    "pytest tests/test_false_positives.py -v",
    "python test_customer_zero.py",
    "pytest tests/test_v056_round8.py -q -p no:cacheprovider",
)
FAST_IGNORES = {"tests/test_v056_matrix.py", "tests/test_repair_v056.py"}

# Approved executable template for the classify job's decide step. Specified
# here, independently of the workflow file, so the guard compares the file to
# the contract rather than to itself (ASTRA round 3, R3-1).
CANONICAL_DECIDE_RUN = 'if [ "$EVENT" != "pull_request" ]; then\n  echo "full=true  # event=$EVENT: not a pull request, the matrix always runs"\n  echo "full=true" >> "$GITHUB_OUTPUT"\n  exit 0\nfi\n# Judge with the classifier from the protected branch, never with the\n# copy inside the PR under judgement (T8 review, 2026-09-10): a PR\n# that edits scripts/ci_classify.py must not be able to classify\n# itself as documentation. actions/checkout with fetch-depth: 0 makes\n# origin/main available. If main has no classifier yet, fail to FULL.\nif ! git show origin/main:scripts/ci_classify.py > "$RUNNER_TEMP/ci_classify.py" 2>/dev/null; then\n  echo "full=true  # origin/main has no scripts/ci_classify.py; defaulting to FULL"\n  echo "full=true" >> "$GITHUB_OUTPUT"\n  exit 0\nfi\npython "$RUNNER_TEMP/ci_classify.py" --base "$BASE" --head "$HEAD"\n'
# Approved shape of the coverage job (ASTRA round 3, R3-2): one plain shell
# step, no step-level env/shell/if/with, job env = exactly the four bindings.
CANONICAL_COVERAGE_RUN = 'echo "classify=$CLASSIFY full=$FULL fast=$FAST integrity=$INTEGRITY"\n[ "$CLASSIFY" = "success" ] || { echo "COVERAGE FAIL: classify did not succeed"; exit 1; }\n[ "$FAST" = "success" ]     || { echo "COVERAGE FAIL: fast lane did not succeed"; exit 1; }\nif [ "$FULL" = "true" ]; then\n  [ "$INTEGRITY" = "success" ] || { echo "COVERAGE FAIL: full matrix required and not green ($INTEGRITY)"; exit 1; }\n  echo "COVERAGE OK: full matrix required and green"\nelse\n  [ "$FULL" = "false" ] || { echo "COVERAGE FAIL: classify output is neither true nor false ($FULL)"; exit 1; }\n  echo "COVERAGE OK: documentation-only change, fast lane green"\nfi\n'
COVERAGE_JOB_KEYS = {"needs", "if", "runs-on", "timeout-minutes", "env", "steps"}
COVERAGE_STEP_KEYS = {"name", "run"}
COVERAGE_ENV = {"CLASSIFY": "${{ needs.classify.result }}", "FULL": "${{ needs.classify.outputs.full }}",
                "FAST": "${{ needs.fast.result }}", "INTEGRITY": "${{ needs.integrity.result }}"}


# ----------------------------------------------------------------- classifier

@pytest.mark.parametrize("paths", [
    ["README.md"],
    ["README.md", "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md", "LICENSE"],
    ["docs/integrations/claude-code.md"],
    [".github/ISSUE_TEMPLATE/bug_report.yml", ".github/PULL_REQUEST_TEMPLATE.md", "CODE_OF_CONDUCT.md"],
])
def test_classifier_docs_only_is_not_full(paths):
    assert ci.classify(paths) is False


@pytest.mark.parametrize("paths", [
    [],                                              # empty change list → full
    ["README.md", "sunglasses/patterns.py"],         # mixed
    ["docs/reader.py"],                              # ASTRA F1: executable under docs/
    ["docs/example.sh"],
    [".github/ISSUE_TEMPLATE/run.py"],               # ASTRA F1: non-template file type
    ["tests/repo_ladder_corpus/x/README.md"],        # protected markdown fixture
    ["demo/sixty-seconds.sh"],                       # code strangers are told to run
    [".github/CODEOWNERS"],                          # ownership policy = full review
    [".github/workflows/pattern-integrity.yml"],
    ["setup.py"], ["pyproject.toml"], ["verify_ai_citations.py"], ["stats/x.json"],
    ["README.md ", "SECURITY.md"],                   # malformed path → not docs
    ["/README.md"], ["../README.md"],
])
def test_classifier_anything_else_is_full(paths):
    assert ci.classify(paths) is True


def test_classifier_rename_uses_both_names(tmp_path):
    """Renaming code to a .md name must still count as code (old path)."""
    import subprocess
    r = lambda *a: subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True, text=True)
    r("init", "-q"); r("config", "user.email", "t@t"); r("config", "user.name", "t")
    (tmp_path / "tool.py").write_text("print(1)\n"); (tmp_path / "README.md").write_text("a\n")
    r("add", "."); r("commit", "-q", "-m", "base"); base = r("rev-parse", "HEAD").stdout.strip()
    r("mv", "tool.py", "NOTES.md"); r("commit", "-q", "-m", "rename")
    head = r("rev-parse", "HEAD").stdout.strip()
    paths = ci.changed_paths(base, head, str(tmp_path))
    assert set(paths) == {"tool.py", "NOTES.md"}
    assert ci.classify(paths) is True
    # and a pure docs commit on the same repo classifies false
    (tmp_path / "README.md").write_text("b\n"); r("commit", "-qam", "docs")
    head2 = r("rev-parse", "HEAD").stdout.strip()
    assert ci.classify(ci.changed_paths(head, head2, str(tmp_path))) is False


def test_classifier_git_failure_defaults_to_full(capsys):
    assert ci.main(["--base", "deadbeef", "--head", "deadbeef", "--repo", str(ROOT)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("full=true") and "defaulting to FULL" in out


def test_classifier_rejects_non_sha_inputs():
    with pytest.raises(ValueError):
        ci.changed_paths("main", "HEAD", str(ROOT))


# ------------------------------------------------------------------- workflow

def _load():
    return yaml.safe_load(WF.read_text())


def _on(doc):
    return doc.get("on", doc.get(True))


def _run_lines(job):
    return [s.get("run", "") for s in job.get("steps", [])]


def check_workflow(doc) -> list[str]:
    """Return every way `doc` fails the gate contract (empty = compliant)."""
    p: list[str] = []
    on = _on(doc) or {}
    pr = on.get("pull_request")
    if not isinstance(pr, dict) or pr.get("branches") != ["main"]:
        p.append("pull_request trigger on main missing")
    else:
        for k in ("paths", "paths-ignore"):
            if k in pr:
                p.append(f"pull_request.{k} present: GitHub path filters are not the classifier")
    push = on.get("push") or {}
    if push.get("branches") != ["main"]:
        p.append("push: main missing (ship binding)")
    if push.get("tags") != ["v*"]:
        p.append("push: tags v* missing")
    if "workflow_dispatch" not in on:
        p.append("workflow_dispatch missing")
    if "schedule" not in on:
        p.append("schedule missing")
    jobs = doc.get("jobs", {})
    for name in ("classify", "fast", "integrity", "coverage"):
        if name not in jobs:
            p.append(f"job {name} missing")
    if p:
        return p
    classify, fast, integrity, coverage = (jobs[n] for n in ("classify", "fast", "integrity", "coverage"))
    for name, job in (("classify", classify), ("fast", fast)):
        if "if" in job:
            p.append(f"job {name} has an `if` (it must run unconditionally)")
        if job.get("needs"):
            p.append(f"job {name} must not depend on other jobs")
    cls_run = "\n".join(_run_lines(classify))
    if 'git show origin/main:scripts/ci_classify.py > "$RUNNER_TEMP/ci_classify.py"' not in cls_run \
            or 'python "$RUNNER_TEMP/ci_classify.py" --base "$BASE" --head "$HEAD"' not in cls_run:
        p.append("classify must judge with origin/main's classifier copied to RUNNER_TEMP, never the PR's own scripts/ci_classify.py")
    if "python scripts/ci_classify.py" in cls_run:
        p.append("classify invokes the PR's own copy of the classifier (self-modification hole)")
    if not any((s.get("with") or {}).get("fetch-depth") == 0 for s in classify.get("steps", []) if "checkout" in str(s.get("uses", ""))):
        p.append("classify checkout is shallow (complete change list needs fetch-depth: 0)")
    if integrity.get("needs") != "classify" or integrity.get("if") != "needs.classify.outputs.full == 'true'":
        p.append("integrity must need classify and run iff full == 'true'")
    versions = (integrity.get("strategy") or {}).get("matrix", {}).get("python-version")
    if versions != ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14"]:
        p.append(f"integrity matrix changed: {versions}")
    if coverage.get("if") != "always()" or sorted(coverage.get("needs") or []) != ["classify", "fast", "integrity"]:
        p.append("coverage must run always() and need classify, fast, integrity")
    cov = "\n".join(_run_lines(coverage))
    for must in ('[ "$CLASSIFY" = "success" ]', '[ "$FAST" = "success" ]', '[ "$INTEGRITY" = "success" ]', '[ "$FULL" = "false" ]'):
        if must not in cov:
            p.append(f"coverage rule missing {must}")
    fast_runs = _run_lines(fast)
    integ_runs = _run_lines(integrity)
    for cmd in GATE_COMMANDS:
        if not any(cmd in r for r in fast_runs):
            p.append(f"fast lane dropped gate: {cmd}")
        if not any(cmd in r for r in integ_runs):
            p.append(f"matrix dropped gate: {cmd}")
    suite = [r for r in fast_runs if "--ignore=" in r]
    if len(suite) != 1:
        p.append("fast lane must have exactly one suite step with --ignore")
    else:
        toks = shlex.split(suite[0].replace("\\\n", " "))
        ignores = {t.split("=", 1)[1] for t in toks if t.startswith("--ignore=")}
        if ignores != FAST_IGNORES:
            p.append(f"fast suite ignore set is {sorted(ignores)}, must be exactly {sorted(FAST_IGNORES)}")
        if toks[:2] != ["pytest", "-q"] or any(t.startswith(("-k", "-m", "--deselect")) for t in toks):
            p.append("fast suite narrows collection beyond the two --ignore flags")
    for name, job in (("classify", classify), ("fast", fast), ("coverage", coverage)):
        if "timeout-minutes" not in job:
            p.append(f"job {name} has no timeout-minutes (a hang must fail, not wait)")

    # --- ASTRA round 2: data bindings, required execution, exact suite scope ---
    # Bindings: the classifier's decision must flow through unbroken references.
    if (classify.get("outputs") or {}).get("full") != "${{ steps.decide.outputs.full }}":
        p.append("classify.outputs.full is not bound to steps.decide.outputs.full")
    decide = [st for st in classify.get("steps", []) if st.get("id") == "decide"]
    if len(decide) != 1:
        p.append("classify must have exactly one step with id: decide")
    else:
        env = decide[0].get("env") or {}
        want = {"EVENT": "${{ github.event_name }}",
                "BASE": "${{ github.event.pull_request.base.sha }}",
                "HEAD": "${{ github.event.pull_request.head.sha }}"}
        for k, v in want.items():
            if env.get(k) != v:
                p.append(f"classify decide step env {k} is not bound to {v}")
        if env != want:
            p.append(f"classify decide step env must be exactly {sorted(want)}: got {sorted(env)}")
        if decide[0].get("run") != CANONICAL_DECIDE_RUN:
            p.append("classify decide step body differs from the approved executable template")
        if set(decide[0].keys()) - {"name", "id", "env", "run"}:
            p.append(f"classify decide step has unexpected keys {sorted(set(decide[0].keys()) - {'name', 'id', 'env', 'run'})}")
    if (coverage.get("env") or {}) != COVERAGE_ENV:
        p.append(f"coverage job env must be exactly the four needs bindings: got {coverage.get('env')}")
    if set(coverage.keys()) - COVERAGE_JOB_KEYS:
        p.append(f"coverage job has unexpected keys {sorted(set(coverage.keys()) - COVERAGE_JOB_KEYS)} (defaults/container/shell/step env are not reviewed shapes)")
    if coverage.get("runs-on") != "ubuntu-latest":
        p.append("coverage must run on ubuntu-latest (bash -e is the documented default shell there)")
    cov_steps = coverage.get("steps") or []
    if len(cov_steps) != 1 or set(cov_steps[0].keys()) - COVERAGE_STEP_KEYS:
        p.append("coverage must be exactly one step with only name+run (a step-level env/shell would override the job bindings)")
    elif cov_steps[0].get("run") != CANONICAL_COVERAGE_RUN:
        p.append("coverage step body differs from the approved executable template")
    if "defaults" in doc or any("defaults" in j for j in jobs.values()):
        p.append("workflow/job `defaults` present (could change the shell the coverage body runs under)")
    # Required execution: no step in any job may be conditional or failure-tolerant.
    for name, job in (("classify", classify), ("fast", fast), ("integrity", integrity), ("coverage", coverage)):
        for st in job.get("steps", []):
            for bad in ("if", "continue-on-error"):
                if bad in st:
                    p.append(f"job {name} step {st.get('name') or st.get('uses')!r} has `{bad}` (required work must run and must fail loudly)")
        if job.get("continue-on-error"):
            p.append(f"job {name} has continue-on-error")
    # The matrix's own full-suite step must exist and be the canonical command.
    if "pytest -q" not in [r.strip() for r in integ_runs]:
        p.append("integrity job must run the full suite as exactly `pytest -q`")
    # Effective matrix: exactly six versions, no include/exclude, fail-fast off.
    strat = integrity.get("strategy") or {}
    if set(strat.keys()) - {"fail-fast", "matrix"} or strat.get("fail-fast") is not False:
        p.append(f"integrity strategy keys/fail-fast changed: {strat}")
    if set((strat.get("matrix") or {}).keys()) != {"python-version"}:
        p.append(f"integrity matrix has extra keys (include/exclude?): {sorted((strat.get('matrix') or {}).keys())}")
    # Exact fast-suite command shape: every token allowed, nothing positional.
    if len(suite) == 1:
        toks = shlex.split(suite[0].replace("\\\n", " "))
        canonical = ["pytest", "-q", "-p", "no:cacheprovider",
                     "--ignore=tests/test_v056_matrix.py", "--ignore=tests/test_repair_v056.py", "--durations=15"]
        if toks != canonical:
            p.append(f"fast suite command is not the canonical token list: {toks}")
        if suite[0].count("pytest") != 1 or ";" in suite[0] or "&&" in suite[0] or "||" in suite[0]:
            p.append("fast suite step contains more than the single pytest command")
    # Gate steps in fast must be byte-identical to the matrix's gate steps.
    integ_gate_runs = {r.strip() for r in integ_runs if any(g in r for g in GATE_COMMANDS)}
    fast_gate_runs = {r.strip() for r in fast_runs if any(g in r for g in GATE_COMMANDS)}
    if integ_gate_runs != fast_gate_runs or len(integ_gate_runs) != len(GATE_COMMANDS):
        p.append("fast lane gate steps are not byte-identical to the matrix gate steps")
    return p


def test_workflow_matches_the_gate_contract():
    assert check_workflow(_load()) == []


def test_fast_lane_receipt_and_preflight_match_the_matrix():
    doc = _load()
    fast = doc["jobs"]["fast"]; integ = doc["jobs"]["integrity"]
    names = lambda j: [s.get("name", s.get("uses")) for s in j["steps"]]
    assert names(fast)[:-1] == [n.replace("${{ matrix.python-version }}", "3.12") for n in names(integ)[:-1]], "fast steps must mirror the matrix steps except the final suite step"
    fr = "\n".join(_run_lines(fast))
    for receipt in ("pip -V", "ffprobe -version", "tesseract --version", "ffmpeg -version"):
        assert receipt in fr, f"fast receipt lost {receipt}"
    assert "qr-injection.png" in fr and "qr-ordinary.png" in fr


# ---------------------------------------------- ASTRA round-1 negative controls

def _mutate(fn):
    doc = _load(); fn(doc); return doc


def test_control_path_filter_reintroduced():
    def m(d): _on(d)["pull_request"]["paths"] = ["**", "!**.md"]
    assert check_workflow(_mutate(m))


def test_control_path_ignore_reintroduced_single_quoted_style_irrelevant():
    # quoting style cannot hide a policy change once the document is parsed
    def m(d): _on(d)["pull_request"]["paths-ignore"] = ["tools/**"]
    assert check_workflow(_mutate(m))


def test_control_disabled_fast_job():
    def m(d): d["jobs"]["fast"]["if"] = "${{ false }}"
    assert check_workflow(_mutate(m))


def test_control_extra_fast_suite_ignore():
    def m(d):
        for s in d["jobs"]["fast"]["steps"]:
            if "--ignore=" in s.get("run", ""):
                s["run"] += " --ignore=tests/test_input_cap.py"
    assert check_workflow(_mutate(m))


def test_control_matrix_made_unconditional_or_detached():
    def m(d): d["jobs"]["integrity"]["if"] = "true"
    assert check_workflow(_mutate(m))
    def m2(d): d["jobs"]["coverage"]["if"] = "success()"
    assert check_workflow(_mutate(m2))


def test_control_gate_command_removed_from_fast():
    def m(d):
        for s in d["jobs"]["fast"]["steps"]:
            if "test_false_positives" in s.get("run", ""):
                s["run"] = "echo skipped"
    assert check_workflow(_mutate(m))


def test_control_coverage_rule_weakened():
    def m(d):
        s = d["jobs"]["coverage"]["steps"][0]
        s["run"] = s["run"].replace('[ "$INTEGRITY" = "success" ]', 'true')
    assert check_workflow(_mutate(m))


def test_control_coverage_accepts_cancelled_or_skipped_matrix():
    """T8 review: job results are success/failure/cancelled/skipped and always()
    runs coverage for all of them, so the matrix check must be strict equality
    with 'success' — '!= failure' would pass a cancelled matrix."""
    def m(d):
        s = d["jobs"]["coverage"]["steps"][0]
        s["run"] = s["run"].replace('[ "$INTEGRITY" = "success" ]', '[ "$INTEGRITY" != "failure" ]')
    assert check_workflow(_mutate(m))
    def m2(d):
        s = d["jobs"]["coverage"]["steps"][0]
        s["run"] = s["run"].replace('[ "$FAST" = "success" ]', '[ "$FAST" != "failure" ]')
    assert check_workflow(_mutate(m2))


# --------------------------------------------- coverage script: run it for real

import itertools
import os
import subprocess

RESULTS = ("success", "failure", "cancelled", "skipped")


def _coverage_script(doc):
    steps = doc["jobs"]["coverage"]["steps"]
    assert len(steps) == 1, "coverage must be a single shell step"
    return steps[0]["run"]


def _expected(classify, full, fast, integrity):
    if classify != "success" or fast != "success":
        return False
    if full == "true":
        return integrity == "success"
    return full == "false"


def _run_script_file(body, env, cwd=None, timeout=10):
    """Execute a `run:` body the way the ubuntu runner does: written to a file,
    invoked as `bash -e <file>` (NOT `bash -c`, whose $0 differs — ASTRA R4-1)."""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
        fh.write(body); path = fh.name
    try:
        return subprocess.run(["bash", "-e", path], env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    finally:
        os.unlink(path)


def _run_coverage(script, classify, full, fast, integrity):
    env = dict(os.environ, CLASSIFY=classify, FULL=full, FAST=fast, INTEGRITY=integrity)
    return _run_script_file(script, env).returncode == 0


def coverage_truth_table_holds(doc) -> list[str]:
    # The table is only meaningful for the reviewed shape: a single plain step
    # whose ONLY environment is the job's four bindings. Any other shape means
    # the values we inject are not the values the step would see.
    shape = [x for x in check_workflow(doc) if x.startswith("coverage")]
    if shape:
        return shape
    script = _coverage_script(doc)
    bad = []
    for classify, full, fast, integrity in itertools.product(RESULTS, ("true", "false", "", "yes", "TRUE"), RESULTS, RESULTS):
        got = _run_coverage(script, classify, full, fast, integrity)
        if got != _expected(classify, full, fast, integrity):
            bad.append(f"CLASSIFY={classify} FULL={full!r} FAST={fast} INTEGRITY={integrity}: exit ok={got}, expected {_expected(classify, full, fast, integrity)}")
    return bad


def test_coverage_script_matches_policy_for_every_input_combination():
    assert coverage_truth_table_holds(_load()) == []


def test_control_coverage_premature_exit_zero():
    def m(d):
        s = d["jobs"]["coverage"]["steps"][0]
        s["run"] = "exit 0\n" + s["run"]
    doc = _mutate(m)
    # substrings all still present → the structural checker alone is not enough; the executed truth table catches it
    assert coverage_truth_table_holds(doc)


# --------------------------------------- ASTRA round-2 negative controls (7)

def test_control_classifier_output_constant_false():
    def m(d): d["jobs"]["classify"]["outputs"]["full"] = "false"
    assert check_workflow(_mutate(m))


def test_control_classifier_output_bound_to_wrong_step_or_inputs():
    def m(d): d["jobs"]["classify"]["outputs"]["full"] = "${{ steps.other.outputs.full }}"
    assert check_workflow(_mutate(m))
    def m2(d):
        for st in d["jobs"]["classify"]["steps"]:
            if st.get("id") == "decide":
                st["env"]["HEAD"] = "${{ github.sha }}"
    assert check_workflow(_mutate(m2))
    def m3(d): d["jobs"]["coverage"]["env"]["INTEGRITY"] = "success"
    assert check_workflow(_mutate(m3))


def _full_suite_step(d):
    for st in d["jobs"]["integrity"]["steps"]:
        if st.get("run", "").strip() == "pytest -q":
            return st
    raise AssertionError("full suite step not found")


def test_control_matrix_full_suite_skipped():
    def m(d): _full_suite_step(d)["if"] = "${{ false }}"
    assert check_workflow(_mutate(m))


def test_control_matrix_full_suite_noop():
    def m(d): _full_suite_step(d)["run"] = "echo full suite"
    assert check_workflow(_mutate(m))


def test_control_matrix_full_suite_failure_tolerated():
    def m(d): _full_suite_step(d)["continue-on-error"] = True
    assert check_workflow(_mutate(m))
    def m2(d): d["jobs"]["integrity"]["continue-on-error"] = True
    assert check_workflow(_mutate(m2))


def test_control_matrix_excludes_a_version():
    def m(d): d["jobs"]["integrity"]["strategy"]["matrix"]["exclude"] = [{"python-version": "3.14"}]
    assert check_workflow(_mutate(m))
    def m2(d): d["jobs"]["integrity"]["strategy"]["fail-fast"] = True
    assert check_workflow(_mutate(m2))


def test_control_fast_positional_subset_or_shell_shortcut():
    def m(d):
        for st in d["jobs"]["fast"]["steps"]:
            if "--ignore=" in st.get("run", ""):
                st["run"] = st["run"].replace("--durations=15", "--durations=15 tests/test_ci_gate.py")
    assert check_workflow(_mutate(m))
    def m2(d):
        for st in d["jobs"]["fast"]["steps"]:
            if "--ignore=" in st.get("run", ""):
                st["run"] = "true || " + st["run"]
    assert check_workflow(_mutate(m2))
    def m3(d):
        for st in d["jobs"]["fast"]["steps"]:
            if "test_dogfood_bugs" in st.get("run", ""):
                st["run"] = st["run"] + " -k nothing"
    assert check_workflow(_mutate(m3))


# ------------------------------------------ classify decide step: run it for real

def _decide_step(doc):
    return [st for st in doc["jobs"]["classify"]["steps"] if st.get("id") == "decide"][0]


def _scratch_pr_repo(tmp_path, classifier_on_main=True):
    """A clone whose origin/main carries the REAL classifier (or none), with a
    docs-only commit and a code commit on top. Returns (repo, base, docs, code)."""
    origin = tmp_path / "origin.git"; repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    subprocess.run(["git", "clone", "-q", str(origin), str(repo)], check=True, capture_output=True)
    r = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout.strip()
    r("config", "user.email", "t@t"); r("config", "user.name", "t"); r("checkout", "-q", "-b", "main")
    if classifier_on_main:
        (repo / "scripts").mkdir(); (repo / "scripts" / "ci_classify.py").write_text(CLASSIFIER.read_text())
    (repo / "README.md").write_text("a\n"); (repo / "code.py").write_text("x = 1\n")
    r("add", "."); r("commit", "-q", "-m", "base"); r("push", "-q", "-u", "origin", "main"); base = r("rev-parse", "HEAD")
    (repo / "README.md").write_text("b\n"); r("commit", "-qam", "docs"); docs = r("rev-parse", "HEAD")
    (repo / "code.py").write_text("x = 2\n"); r("commit", "-qam", "code"); code = r("rev-parse", "HEAD")
    return repo, base, docs, code


def _run_decide(body, tmp_path, repo, event, base, head, tag):
    shim = tmp_path / "bin"
    if not shim.exists():
        shim.mkdir(); (shim / "python").symlink_to(sys.executable)
    rt = tmp_path / f"runner-temp-{tag}"; rt.mkdir(exist_ok=True)
    out = tmp_path / f"out-{tag}"; out.write_text("")
    env = dict(os.environ, PATH=f"{shim}{os.pathsep}{os.environ['PATH']}", EVENT=event, BASE=base, HEAD=head,
               GITHUB_OUTPUT=str(out), RUNNER_TEMP=str(rt))
    cp = _run_script_file(body, env, cwd=repo, timeout=30)
    return cp.returncode, out.read_text().strip().splitlines()


def decide_behaviour_holds(doc, tmp_path) -> list[str]:
    """Execute the decide step's ACTUAL body (file mode, like the runner) in a
    scratch clone whose origin/main carries the real classifier, and check what
    it emits to GITHUB_OUTPUT — including when the PR's OWN copy of the
    classifier is tampered with (T8 review) and when main has no classifier."""
    body = _decide_step(doc)["run"]
    bad = []
    repo, base, docs, code = _scratch_pr_repo(tmp_path / "honest")
    for tag, (event, b, h, want) in {
        "code":  ("pull_request", base, code, ["full=true"]),
        "docs":  ("pull_request", base, docs, ["full=false"]),
        "code2": ("pull_request", docs, code, ["full=true"]),
        "push":  ("push",         base, code, ["full=true"]),
    }.items():
        rc, lines = _run_decide(body, tmp_path, repo, event, b, h, tag)
        if rc != 0 or lines != want:
            bad.append(f"{tag}: rc={rc} output={lines} (expected {want})")
    # T8 control: the PR replaces scripts/ci_classify.py with one that always says docs.
    # The step must still say full=true for a CODE change because it judges with main's copy.
    (repo / "scripts" / "ci_classify.py").write_text(
        'import os\nprint("full=false  # tampered")\n'
        'open(os.environ["GITHUB_OUTPUT"], "a").write("full=false\\n")\n')
    subprocess.run(["git", "-C", str(repo), "commit", "-qam", "tamper classifier"], check=True)
    tampered = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    rc, lines = _run_decide(body, tmp_path, repo, "pull_request", base, tampered, "tampered")
    if rc != 0 or lines != ["full=true"]:
        bad.append(f"tampered PR classifier: rc={rc} output={lines} (expected ['full=true'] from main's copy)")
    # Main has no classifier at all (the very first PR that adds it) → FULL.
    repo2, base2, docs2, code2 = _scratch_pr_repo(tmp_path / "nomain", classifier_on_main=False)
    rc, lines = _run_decide(body, tmp_path, repo2, "pull_request", base2, docs2, "nomain")
    if rc != 0 or lines != ["full=true"]:
        bad.append(f"no classifier on main: rc={rc} output={lines} (expected ['full=true'])")
    return bad


def test_decide_step_body_is_the_approved_template_and_behaves(tmp_path):
    doc = _load()
    assert _decide_step(doc)["run"] == CANONICAL_DECIDE_RUN
    assert decide_behaviour_holds(doc, tmp_path) == []


def test_control_classifier_premature_false(tmp_path):
    """ASTRA R3-1: keep every original line, but write full=false and exit first."""
    def m(d):
        st = _decide_step(d)
        st["run"] = 'echo "full=false" >> "$GITHUB_OUTPUT"\nexit 0\n' + st["run"]
    doc = _mutate(m)
    assert check_workflow(doc), "template check must reject a modified decide body"
    assert decide_behaviour_holds(doc, tmp_path), "executed check must see the code PR classified false"


def test_control_coverage_step_env_override():
    """ASTRA R3-2: a step-level env overrides the job bindings on GitHub."""
    def m(d): d["jobs"]["coverage"]["steps"][0]["env"] = {"FULL": "false"}
    doc = _mutate(m)
    assert check_workflow(doc)
    assert coverage_truth_table_holds(doc)
    def m2(d): d["jobs"]["coverage"]["steps"][0]["shell"] = "bash {0}"
    assert check_workflow(_mutate(m2))
    def m3(d): d["jobs"]["coverage"]["defaults"] = {"run": {"shell": "sh"}}
    assert check_workflow(_mutate(m3))
    def m4(d): d["jobs"]["coverage"]["env"]["FULL"] = "false"
    assert check_workflow(_mutate(m4))


def test_coverage_body_is_the_approved_template():
    assert _coverage_script(_load()) == CANONICAL_COVERAGE_RUN


def test_control_coverage_file_mode_success():
    """ASTRA R4-1: a body that succeeds early only when run from a script file
    ($0 is an existing file under `bash -e {0}`, not under `bash -c`)."""
    def m(d):
        st = d["jobs"]["coverage"]["steps"][0]
        st["run"] = 'if [ -f "$0" ]; then exit 0; fi\n' + st["run"]
    doc = _mutate(m)
    assert check_workflow(doc), "template check must reject the modified body"
    # and the executed table, now run from a file like the runner, must ALSO catch it on its own
    body = _coverage_script(doc)
    env = dict(os.environ, CLASSIFY="success", FULL="true", FAST="success", INTEGRITY="failure")
    assert _run_script_file(body, env).returncode == 0, "sanity: the mutation does pass in file mode"
    assert coverage_truth_table_holds(doc)


def test_run_script_file_is_file_mode():
    cp = _run_script_file('[ -f "$0" ] && echo file || echo cmd\n', dict(os.environ))
    assert cp.stdout.strip() == "file"


def test_control_decide_uses_pr_copy_of_classifier(tmp_path):
    """T8 finding: judging with `python scripts/ci_classify.py` runs the PR's own copy."""
    def m(d):
        st = _decide_step(d)
        st["run"] = st["run"].replace('python "$RUNNER_TEMP/ci_classify.py"', "python scripts/ci_classify.py")
    doc = _mutate(m)
    assert check_workflow(doc), "template check must reject the PR-copy invocation"
    assert any("tampered" in b for b in decide_behaviour_holds(doc, tmp_path)), "executed check must see the tampered PR classify itself as docs"
