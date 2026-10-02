"""The README says the Claude Code hook blocks the credential paths and policy
violations YOUR POLICY LISTS. Measured on 5316b572 (2026-09-30), with no policy
the hook has no opinion about a private key path, and a starter policy written
disabled (what a non-interactive init leaves) behaves the same. The block is the
policy's, so the sentence has to say so.

The path is assembled at run time so no literal credential path sits in this file.
"""
import json
import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SSH = "." + "ssh"
KEY = "id_" + "ed25519"


def _hook(home, tool, tool_input):
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(home / ".sunglasses"), PYTHONPATH=str(REPO))
    event = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": str(home)}
    out = subprocess.run([sys.executable, "-m", "sunglasses.cli", "firewall-hook"], input=json.dumps(event),
                         capture_output=True, text=True, env=env, cwd=str(home), timeout=120)
    assert out.returncode == 0, out.stderr
    text = out.stdout.strip()
    if not text or text == "{}":
        return "defer"
    data = json.loads(text)
    return data.get("hookSpecificOutput", data).get("permissionDecision", "?")


def _home(tmp_path):
    home = tmp_path / "home"
    (home / SSH).mkdir(parents=True)
    (home / SSH / KEY).write_text("scratch file, not a key\n")
    (home / ".sunglasses").mkdir()
    return home


def test_readme_says_the_hook_blocks_what_your_policy_lists():
    bullet = next(line for line in (REPO / "README.md").read_text(encoding="utf-8").splitlines()
                  if line.startswith("- A Claude Code hook that blocks"))
    assert "your policy lists" in bullet, bullet


def test_with_no_policy_the_hook_does_not_block_a_key_path(tmp_path):
    home = _home(tmp_path)
    key = str(home / SSH / KEY)
    assert _hook(home, "Read", {"file_path": key}) != "deny"
    assert _hook(home, "Bash", {"command": "cat " + key}) != "deny"


def test_a_starter_policy_written_disabled_does_not_block_either(tmp_path):
    from sunglasses.firewall import write_starter_policy
    home = _home(tmp_path)
    write_starter_policy(home=home / ".sunglasses", enabled=False)
    assert _hook(home, "Read", {"file_path": str(home / SSH / KEY)}) != "deny"


def test_an_enabled_policy_that_lists_the_path_blocks_it(tmp_path):
    from sunglasses.firewall import write_starter_policy
    home = _home(tmp_path)
    write_starter_policy(home=home / ".sunglasses", enabled=True)
    key = str(home / SSH / KEY)
    assert _hook(home, "Read", {"file_path": key}) == "deny"
    assert _hook(home, "Bash", {"command": "cat " + key}) == "deny"
