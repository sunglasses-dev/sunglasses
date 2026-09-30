"""0.6.5 CU-M8 and CU-M6 -- what `sunglasses doctor` says, and in what bytes.

CU-M8. A cold-user dry run on the released 0.6.4 wheel wrapped one server and ran
`doctor` twice. The JSON said `per_wrapper: [{"result": "FAIL"}]`; the text said
nothing about that route except the self-test's "NOT RUN", and the README says an
unavailable self-test is "NOT RUN with no check marked failed". Two renderings of
one state, disagreeing.

The cause was one line. `default_launcher` returns `(False, {})`, and `False`
means "we launched it and it failed" to everything downstream. The shipped build
has no launcher, so NOTHING was launched, and "never launched" was recorded as
"launched and failed". The fix is that the route verdict is a three-valued field
(PASS, FAIL, NOT_RUN) written ONCE, and both renderers read that field.

These rows assert two separate things, because either alone passes a bad tree:
  * AGREEMENT: the verdict the text prints for a route equals the verdict the
    JSON carries for it. A fix that changed only one side fails here.
  * TRUTH: for a route that was never launched that verdict is NOT_RUN, and for
    one a launcher watched fail it is FAIL. Agreement alone is satisfied by both
    renderers saying the same wrong thing.

CU-M6. Colour was printed into a pipe and `NO_COLOR=1` did not turn it off: 9
escape sequences in `sunglasses doctor` both ways. The count is asserted as ZERO
on every non-terminal and on a terminal with NO_COLOR set, and as NONZERO on a
real pty without it, because a counter that cannot see colour would report zero
on the broken tree too.
"""
import json
import os
import re
import subprocess
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from sunglasses import cli  # noqa: E402
from sunglasses import install as inst  # noqa: E402
from sunglasses.proxy import doctor  # noqa: E402

_CONTROLS = {c: "FAIL" for c in doctor.REQUIRED_CONTROLS}
_PASSING = {c: "PASS" for c in doctor.SELF_TEST_CHECKS}
_ESC = re.compile(r"\x1b")


def _env(home, **extra):
    env = {k: v for k, v in os.environ.items()
           if k not in ("NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE")}
    env.update({"PYTHONPATH": REPO, "HOME": str(home),
                "PYTHONDONTWRITEBYTECODE": "1"})
    env.update(extra)
    return env


def _cli(args, tmp_path, **extra):
    return subprocess.run(
        [sys.executable, "-m", "sunglasses.cli", *args],
        capture_output=True, text=True, cwd=str(tmp_path),
        env=_env(tmp_path / "home", **extra))


@pytest.fixture
def wrapped(tmp_path):
    """One server wrapped by the real `install`, in an isolated HOME (install
    records under `Path.home()`, which has no override, so HOME is the only
    way to keep the record out of the developer's real tree)."""
    (tmp_path / "home").mkdir()
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "demo": {"command": "python3", "args": ["x.py"]}}}))
    proc = _cli(["install", "demo"], tmp_path)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    return cfg


def _text_route_verdict(text, name):
    """The verdict the TEXT report prints for one wrapped route: the token that
    follows `route` on that server's line. None if the line carries none."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)  # the in-process rows keep colour
    for line in text.splitlines():
        if re.search(rf"\bWRAPPED\b.*\b{re.escape(name)}\b", line):
            m = re.search(r"\broute\s+([A-Z_]+)\b", line)
            return m.group(1) if m else None
    return None


# ---------------------------------------------------------------------------
# CU-M8 -- one verdict, read by both renderers
# ---------------------------------------------------------------------------

def test_text_and_json_carry_the_same_verdict_for_a_wrapped_route(wrapped, tmp_path):
    text = _cli(["doctor", "--config", str(wrapped)], tmp_path).stdout
    data = json.loads(_cli(["doctor", "--config", str(wrapped), "--json"],
                           tmp_path).stdout)
    [row] = data["per_wrapper"]
    assert _text_route_verdict(text, "demo") == row["result"], (
        f"text says {_text_route_verdict(text, 'demo')!r}, JSON says "
        f"{row['result']!r}\n{text}")


def test_a_route_nothing_launched_is_not_run_and_never_fail(wrapped, tmp_path):
    """TRUTH half. RED-FIRST on 5316b572: JSON `FAIL`, text prints no verdict."""
    text = _cli(["doctor", "--config", str(wrapped)], tmp_path).stdout
    data = json.loads(_cli(["doctor", "--config", str(wrapped), "--json"],
                           tmp_path).stdout)
    assert data["per_wrapper"][0]["result"] == "NOT_RUN", data["per_wrapper"]
    assert _text_route_verdict(text, "demo") == "NOT_RUN", text
    # The README's own sentence: an unavailable self-test is NOT RUN with no
    # check marked failed. Nothing in either rendering may say FAIL.
    assert data["self_test"]["failed"] == []
    assert all(w["result"] != "FAIL" for w in data["per_wrapper"])
    assert "FAIL" not in text


def test_exit_stays_one_on_the_shipped_build_and_the_aggregate_is_unverified(
        wrapped, tmp_path):
    """The fix must not soften the exit: 1 because the self-test is absent."""
    proc = _cli(["doctor", "--config", str(wrapped), "--json"], tmp_path)
    data = json.loads(proc.stdout)
    assert proc.returncode == 1 and data["exit_code"] == 1
    assert data["aggregate"] == doctor.ROUTE_UNVERIFIED


def _report(tmp_path, launcher, self_test_ok=True):
    (tmp_path / "artifact").mkdir(parents=True, exist_ok=True)
    artifact = tmp_path / "artifact" / "__main__.py"
    artifact.write_text("# proxy entry point\n", encoding="utf-8")
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "server-github"]}}}))
    home = tmp_path / "sgh"
    inst.install(cfg, "github", artifact=artifact, home=home)
    kwargs = {} if launcher is None else {"launcher": launcher}
    return doctor.run(
        sources=[("project", cfg)], artifact=artifact, home=home,
        self_test=lambda: (self_test_ok, _CONTROLS, dict(_PASSING)), **kwargs)


def _text_from(report, capsys):
    args = type("A", (), {"config": None, "json": False})()
    with pytest.raises(SystemExit):
        cli.cmd_doctor(args, _run=lambda **kw: report)
    return capsys.readouterr().out


@pytest.mark.parametrize("launcher,expected", [
    (lambda e: (True, dict(_PASSING)), "PASS"),
    (lambda e: (False, dict(_PASSING, s1_forward_byte_equal="FAIL")), "FAIL"),
    (None, "NOT_RUN"),
])
def test_every_route_verdict_agrees_between_text_and_json(
        tmp_path, capsys, launcher, expected):
    """All three values through the same two renderers. A launcher that ran and
    failed is still FAIL: the fix turns "never launched" into NOT_RUN, it does
    not turn failures into anything softer."""
    report = _report(tmp_path, launcher)
    rendered = doctor.render(report)
    assert rendered["per_wrapper"][0]["result"] == expected
    assert _text_route_verdict(_text_from(report, capsys), "github") == expected


def test_a_failed_launch_still_exits_one_and_a_clean_launch_verifies(tmp_path):
    failed = _report(tmp_path / "f", lambda e: (False, {}))
    assert failed.exit_code == 1
    ok = _report(tmp_path / "p", lambda e: (True, dict(_PASSING)))
    assert ok.exit_code == 0 and ok.outcome.aggregate == doctor.ROUTE_VERIFIED


def test_a_route_that_was_never_launched_is_doubt_not_failure(tmp_path):
    """With a passing self-test and no launcher, nothing failed in front of us
    and nothing was proven: R3's 3, the code for "I could not prove it", and
    not 1, the code for "I watched it fail"."""
    report = _report(tmp_path, None)
    assert report.exit_code == doctor.EXIT_DOUBT
    assert report.outcome.aggregate == doctor.ROUTE_UNVERIFIED


# ---------------------------------------------------------------------------
# CU-M6 -- NO_COLOR and non-terminals
# ---------------------------------------------------------------------------

def _pty_run(args, tmp_path, **extra):
    """Run the CLI with stdout on a real pseudo-terminal, so `isatty()` is true
    and the only thing that can turn colour off is NO_COLOR."""
    import pty
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "sunglasses.cli", *args],
            stdout=slave, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            cwd=str(tmp_path), env=_env(tmp_path / "home", **extra))
        os.close(slave)
        chunks = []
        while True:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        proc.wait(timeout=60)
    finally:
        os.close(master)
    return b"".join(chunks).decode("utf-8", "replace")


def test_a_pipe_carries_zero_escape_sequences(wrapped, tmp_path):
    out = _cli(["doctor", "--config", str(wrapped)], tmp_path).stdout
    assert out.strip(), "the control is empty, the count below would mean nothing"
    assert len(_ESC.findall(out)) == 0, repr(out)


def test_no_color_on_a_pipe_carries_zero_escape_sequences(wrapped, tmp_path):
    out = _cli(["doctor", "--config", str(wrapped)], tmp_path, NO_COLOR="1").stdout
    assert out.strip()
    assert len(_ESC.findall(out)) == 0, repr(out)


@pytest.mark.skipif(sys.platform == "win32", reason="needs a pty")
def test_control_a_real_terminal_without_no_color_still_gets_colour(wrapped, tmp_path):
    """The positive control. If this reads zero, the two zero-counts around it
    prove the counter is blind, not that colour is off."""
    out = _pty_run(["doctor", "--config", str(wrapped)], tmp_path)
    assert len(_ESC.findall(out)) > 0, repr(out)


@pytest.mark.skipif(sys.platform == "win32", reason="needs a pty")
def test_no_color_on_a_real_terminal_carries_zero_escape_sequences(wrapped, tmp_path):
    out = _pty_run(["doctor", "--config", str(wrapped)], tmp_path, NO_COLOR="1")
    assert "WRAPPED" in out, repr(out)
    assert len(_ESC.findall(out)) == 0, repr(out)


@pytest.mark.skipif(sys.platform == "win32", reason="needs a pty")
def test_an_empty_no_color_does_not_switch_colour_off(wrapped, tmp_path):
    """no-color.org: the variable counts when present AND non-empty."""
    out = _pty_run(["doctor", "--config", str(wrapped)], tmp_path, NO_COLOR="")
    assert len(_ESC.findall(out)) > 0, repr(out)
