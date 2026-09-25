"""test_doctor_key_unusable.py — the doctor names a signing key that cannot
sign (T9 RULING 21 b, doctor's half).

Signing on and the key unusable means every wrapped route's proxy refuses to
start (R24b a) and every hook call asks (R21 a). The doctor is where a user
goes to ask why, so it says KEY_UNUSABLE with the same cause and command
`receipts --verify` prints, and exits 1: a route that cannot start is a route
we know fails, whatever a launch in a test double reported.
"""
import json
import os

import pytest

from sunglasses import install as inst
from sunglasses.proxy import doctor
from sunglasses.receipts import keys

_CONTROLS = {c: "FAIL" for c in doctor.REQUIRED_CONTROLS}
_PASSING = {c: "PASS" for c in doctor.SELF_TEST_CHECKS}


@pytest.fixture
def artifact(tmp_path):
    a = tmp_path / "artifact" / "__main__.py"
    a.parent.mkdir(parents=True)
    a.write_text("# proxy entry point\n", encoding="utf-8")
    return a


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "server-github"]},
    }}, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "sgh"
    keys.init(home)
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    return home


def _run(cfg, artifact):
    return doctor.run(sources=[("project", cfg)], artifact=artifact,
                      self_test=lambda: (True, _CONTROLS, _PASSING),
                      launcher=lambda e: (True, dict(_PASSING)))


def test_an_exposed_key_is_key_unusable_with_the_cause_and_exit_1(cfg, home, artifact):
    inst.install(cfg, "github", artifact=artifact, home=home)
    os.chmod(keys.private_path(home), 0o644)
    report = _run(cfg, artifact)
    rendered = doctor.render(report)
    assert rendered["receipts_key"]["status"] == "KEY_UNUSABLE"
    assert str(keys.private_path(home)) in rendered["receipts_key"]["cause"]
    assert "chmod 600" in rendered["receipts_key"]["cause"]
    assert report.exit_code == doctor.EXIT_FAILED


def test_a_deleted_key_under_a_live_hook_chain_is_key_unusable(cfg, home, artifact):
    from sunglasses.firewall import run_hook
    run_hook(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                         "tool_input": {"command": "echo hi"}}), home=home)
    keys.private_path(home).unlink()
    rendered = doctor.render(_run(cfg, artifact))
    assert rendered["receipts_key"]["status"] == "KEY_UNUSABLE"
    assert "receipts off" in rendered["receipts_key"]["cause"]


def test_the_control_a_usable_key_changes_nothing(cfg, home, artifact):
    inst.install(cfg, "github", artifact=artifact, home=home)
    report = _run(cfg, artifact)
    assert doctor.render(report)["receipts_key"] == {"status": "ON", "cause": ""}
    assert report.exit_code == doctor.EXIT_VERIFIED


def test_the_control_no_key_is_off_and_changes_nothing(cfg, tmp_path, artifact,
                                                       monkeypatch):
    monkeypatch.setenv("SUNGLASSES_HOME", str(tmp_path / "empty"))
    report = _run(cfg, artifact)
    assert doctor.render(report)["receipts_key"] == {"status": "OFF", "cause": ""}
    assert report.exit_code == 3                      # a DIRECT inventory, as before
