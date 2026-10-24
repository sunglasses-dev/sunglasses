"""The pattern-perf workflow: a job the pull request under judgement cannot shape.

.github/workflows/pattern-perf.yml is a pull_request_target workflow, so the platform runs the copy on the
base branch. These tests pin the properties that make that true, as exact text over the WHOLE file
(not per step): the trigger, the permissions, the only checkout, the pinned actions, the set of
environment variables, the words that must never appear, the way the head is read (as data, by sha),
the way the base's waivers are read, and a status that names the sha it judged and is a success only
on a successful gate. Changing the workflow means changing this file in the same pull request, and
the change takes effect for later pull requests only.
"""
import hashlib
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "pattern-perf.yml"
SCRIPT = ROOT / "scripts" / "pattern_perf_gate.py"
TEXT = WORKFLOW.read_text(encoding="utf-8")

# Update only after re-reading every assertion below against the new text.
WORKFLOW_SHA256 = "55e2a8e91cebbd29d05a948f32fed1b62a1d539a905a3d8b93902b5fe7f73b5f"

ENV_NAMES = {"GH_TOKEN", "REPO", "HEAD", "RUN_URL", "PR", "BASE", "OUTCOME"}
FORBIDDEN = (
    "BASH_ENV", "ENV:", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONWARNINGS",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STATE",
    "secrets.", "pip install", "pip3 install", "setup.py", "npm ", "npx ", "make ", "source ", "eval ",
    "git checkout", "git switch", "git merge", "git worktree", "git pull", "git submodule",
    "pull_request:", "workflow_run", "workflow_dispatch", "schedule:", "issue_comment",
    "github.head_ref", "github.event.pull_request.head.ref", "github.event.pull_request.title",
    "github.event.pull_request.body", "github.event.pull_request.head.repo",
)


def _lines():
    return TEXT.splitlines()


def _code_lines():
    return [ln for ln in _lines() if not ln.lstrip().startswith("#")]


def test_the_whole_file_is_the_reviewed_text():
    assert hashlib.sha256(WORKFLOW.read_bytes()).hexdigest() == WORKFLOW_SHA256, (
        "the pattern-perf workflow changed: re-read every test in this file against it, then update the digest")


def test_the_trigger_is_pull_request_target_only():
    code = "\n".join(_code_lines())
    assert re.search(r"^on:\n  pull_request_target:\n    types: \[opened, synchronize, reopened\]\n", code, re.M)
    assert len(re.findall(r"^on:", code, re.M)) == 1
    assert len(re.findall(r"^  [a-z_]+:", code.split("\non:\n", 1)[1].split("\npermissions:", 1)[0], re.M)) == 1


def test_permissions_are_empty_at_the_top_and_minimal_on_the_job():
    code = "\n".join(_code_lines())
    assert "\npermissions: {}\n" in code
    job = code.split("\njobs:\n", 1)[1]
    perms = re.findall(r"^      ([\w-]+): (\w+)$", job.split("    steps:", 1)[0], re.M)
    assert dict(perms) == {"contents": "read", "statuses": "write"}
    assert len(re.findall(r"^\s+permissions:", code, re.M)) == 1 + 1      # the top-level and the job's


def test_there_is_one_job_and_it_is_not_matrix_or_reusable():
    code = "\n".join(_code_lines())
    job_names = re.findall(r"^  ([\w-]+):$", code.split("\njobs:\n", 1)[1], re.M)
    assert job_names == ["pattern-perf"]
    for word in ("matrix:", "strategy:", "needs:", "container:", "services:", "outputs:"):
        assert word not in code


def test_every_action_is_pinned_by_a_full_sha_and_there_is_exactly_one_checkout_without_a_ref():
    uses = re.findall(r"^\s+uses: (\S+)", "\n".join(_code_lines()), re.M)
    assert [u.split("@")[0] for u in uses] == ["actions/checkout", "actions/setup-python"]
    for u in uses:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u), u
    checkout = TEXT.split("uses: actions/checkout@", 1)[1].split("\n      - name:", 1)[0]
    assert "ref:" not in checkout and "repository:" not in checkout and "token:" not in checkout
    assert "persist-credentials: false" in checkout


def test_the_only_environment_variables_are_the_allowlist_and_all_come_from_the_event_or_the_token():
    names = set()
    for m in re.finditer(r"^ {10}([A-Z_]+): (.*)$", TEXT, re.M):
        names.add(m.group(1))
        value = m.group(2)
        assert re.fullmatch(r"\$\{\{ [a-z_.]+( \}\}/\$\{\{ [a-z_.]+ \}\}/actions/runs/\$\{\{ [a-z_.]+)? \}\}", value) \
            or value.startswith("${{ "), value
    assert names == ENV_NAMES
    for m in re.finditer(r"\$\{\{ ([^}]+) \}\}", TEXT):
        expr = m.group(1).strip()
        assert re.fullmatch(
            r"github\.(token|repository|run_id|server_url|event\.pull_request\.(number|head\.sha|base\.sha))"
            r"|steps\.gate\.outcome", expr) or expr.startswith("github.event.pull_request.number"), expr


def test_no_forbidden_word_appears_anywhere_in_the_file():
    for word in FORBIDDEN:
        assert word not in TEXT, word


def test_the_gate_step_has_no_token_and_is_the_only_step_that_runs_the_script():
    gate = TEXT.split("- name: Time the patterns this change touches", 1)[1].split("\n      - name:", 1)[0]
    assert "GH_TOKEN" not in gate and "github.token" not in gate
    assert 'run: python3 -I scripts/pattern_perf_gate.py --base "$BASE" --head "$HEAD"' in gate
    assert TEXT.count("pattern_perf_gate.py") == 2 and TEXT.count("python3") == 1      # one comment, one run
    assert "id: gate" in gate


def test_the_head_is_fetched_as_objects_only_and_checked_against_the_event_sha():
    step = TEXT.split("- name: Fetch the head commit as data", 1)[1].split("\n      - name:", 1)[0]
    assert 'git fetch --no-tags --quiet origin "+refs/pull/${PR}/head:refs/pull-head/${PR}"' in step
    assert '[ "$(git rev-parse "refs/pull-head/${PR}")" = "$HEAD" ] ||' in step and "exit 1" in step
    assert TEXT.count("git fetch") == 1


def test_the_status_is_pending_first_then_success_only_on_a_successful_gate_and_names_the_sha():
    posts = re.findall(r'gh api "repos/\$REPO/statuses/\$HEAD" -f state=(\S+) -f context=pattern-perf', TEXT)
    assert posts == ["pending", '"$STATE"']
    final = TEXT.split("- name: Post the verdict", 1)[1]
    assert "if: always()" in final
    assert "STATE=failure\n          if [ \"$OUTCOME\" = \"success\" ]; then STATE=success; fi" in final
    assert "OUTCOME: ${{ steps.gate.outcome }}" in final
    assert TEXT.count('${HEAD:0:12}') == 2                       # the description of both posts names the sha
    assert TEXT.count("context=pattern-perf") == 2


def test_the_waivers_and_the_rule_tables_are_read_from_git_objects_by_sha_and_not_from_the_tree():
    src = SCRIPT.read_text(encoding="utf-8")
    assert 'git_show(args.repo, args.head, p)' in src and 'git_show(args.repo, args.base, p)' in src
    assert 'git_show(args.repo, args.base, WAIVERS)' in src and 'git_show(args.repo, args.head, WAIVERS)' in src
    assert "SHA.fullmatch(args.base) and SHA.fullmatch(args.head)" in src
    # the PR-mode branch of main() opens no file of the working tree
    pr_branch = src.split("if not (SHA.fullmatch(args.base)", 1)[1]
    assert "open(" not in pr_branch and "import_module" not in pr_branch and "__import__" not in pr_branch
    assert not re.search(r"^\s*(import|from) (sunglasses|patterns)", src, re.M)


def _guards():
    return [ln.strip() for ln in _code_lines() if ln.strip().startswith("[[ ") and "unexpected" in ln]


def test_every_step_that_uses_the_event_values_checks_their_shape_first():
    guards = _guards()
    assert len(guards) == 3
    assert sum('"$PR" =~ ^[0-9]+$' in g for g in guards) == 1
    assert all('"$HEAD" =~ ^[0-9a-f]{40}$' in g for g in guards)
    for step, first in (("Post the pending status", "unexpected head sha"),
                        ("Fetch the head commit as data", "unexpected pull request number or head sha"),
                        ("Post the verdict", "unexpected head sha")):
        body = TEXT.split(f"- name: {step}", 1)[1].split("\n      - name:", 1)[0]
        run = body.split("run: |\n", 1)[1].splitlines()[0]
        assert first in run and run.strip().startswith("[["), step


def test_the_shape_checks_accept_a_sha_and_a_number_and_nothing_else():
    import subprocess
    guard = next(g for g in _guards() if '"$PR"' in g)
    good_sha, good_pr = "0123456789abcdef0123456789abcdef01234567", "485"
    def passes(pr, head):
        return subprocess.run(["bash", "-c", guard], env={"PR": pr, "HEAD": head, "PATH": "/usr/bin:/bin"},
                              capture_output=True).returncode == 0
    assert passes(good_pr, good_sha)
    for bad_pr in ("", "4 85", "485\n", "485;id", "-1", "a"):
        assert not passes(bad_pr, good_sha), repr(bad_pr)
    for bad_sha in ("", good_sha[:39], good_sha + "0", good_sha + "\n", good_sha.upper(), "g" * 40,
                    good_sha[:20] + "$(id)" + good_sha[25:], good_sha[:39] + "\n"):
        assert not passes(good_pr, bad_sha), repr(bad_sha)
