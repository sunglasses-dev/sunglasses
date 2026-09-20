"""install -> first call -> approve at a terminal -> forwarded, as rows.

These are T8's proxy-enforcement transcripts and T10's install measurement,
turned into rows that run. Both existed only as prose in warroom notes and were
reproducible only by hand, which is how the two halves disagreed for a day
without anyone noticing: the mediator was measured through `-m` and `install`
was measured on its own, and nobody ran one into the other.

EVERY ROW BUILDS ITS OWN WORLD. `HOME` and `SUNGLASSES_HOME` both point inside a
tmp_path, because `serve.state_root()` is HOME-derived and deliberately reads no
environment variable of its own, while `install` honours `SUNGLASSES_HOME` —
isolating one and not the other is exactly the mistake that hid the captures for
half a day.
"""
import json
import os
import pty
import subprocess
import sys
import threading
import time

import pytest

TREE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "row", "version": "1"}}}
LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
CALL = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "hello"}}}
CREDENTIAL = "sk-" + "a" * 32          # GLS-SD-001-API, api_response channel


class Wrapped:
    """A really-installed server, driven over real pipes."""

    def __init__(self, tmp_path, inject=None):
        self.work = tmp_path
        self.home = tmp_path / "home"
        self.home.mkdir(exist_ok=True)
        args = ["-m", "sunglasses.proxy.echo_server"]
        if inject:
            args += ["--inject", inject]
        self.cfg = tmp_path / ".mcp.json"
        self.cfg.write_text(json.dumps(
            {"mcpServers": {"echo": {"command": "python3", "args": args}}}))
        self.env = dict(os.environ, PYTHONPATH=TREE, PYTHONDONTWRITEBYTECODE="1",
                        HOME=str(self.home), SUNGLASSES_HOME=str(self.home))
        r = subprocess.run([sys.executable, "-m", "sunglasses", "install", "echo",
                            "--config", str(self.cfg)],
                           capture_output=True, text=True, env=self.env,
                           cwd=self.work)
        assert r.returncode == 0, r.stderr
        self.entry = json.loads(self.cfg.read_text())["mcpServers"]["echo"]

    @property
    def state_root(self):
        return self.home / ".sunglasses" / "proxy"

    def talk(self, messages, settle=4.0):
        """Send each message over a LIVE pipe, then read. The control channel
        needs the session up to run its own list, so the pipe is held open."""
        p = subprocess.Popen([self.entry["command"]] + self.entry["args"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env=self.env,
                             cwd=self.work, bufsize=1)
        out = []
        threading.Thread(target=lambda: [out.append(l) for l in p.stdout],
                         daemon=True).start()
        for message in messages:
            p.stdin.write(json.dumps(message) + "\n")
            p.stdin.flush()
            time.sleep(1.2)
        time.sleep(settle)
        try:
            p.stdin.close()
            p.wait(timeout=10)
        except Exception:
            p.kill()
        return [json.loads(line) for line in out if line.strip()]

    def approve_at_a_terminal(self, server_id, snapshot):
        """A REAL pty, because the gate refuses a pipe by design and a fixture
        that fakes the terminal would be approving on the human's behalf."""
        primary, secondary = pty.openpty()
        proc = subprocess.Popen(
            [sys.executable, "-m", "sunglasses", "proxy", "approve",
             server_id, "--snapshot", snapshot],
            stdin=secondary, stdout=secondary, stderr=secondary,
            env=self.env, cwd=self.work, text=True)
        os.close(secondary)
        time.sleep(1.5)
        try:
            os.write(primary, b"y\n")
        except OSError:
            pass
        code = proc.wait(timeout=30)
        os.close(primary)
        return code


def _refusal(frames, request_id):
    for frame in frames:
        if frame.get("id") == request_id and frame.get("error"):
            return frame["error"]["data"]
    return None


@pytest.fixture
def wrapped(tmp_path):
    return Wrapped(tmp_path)


def test_a_freshly_wrapped_server_withholds_and_says_what_to_approve(wrapped):
    """The first thing a user meets. Withheld is correct; silent is not."""
    frames = wrapped.talk([INIT, LIST])
    data = _refusal(frames, 2)
    assert data and data["reason_code"] == "APPROVAL_REQUIRED"
    assert data["rule"] == "S4"
    assert data["status"] == "not_run"
    # the two ids the approve command needs, in the refusal itself
    assert data["server_id"] and data["snapshot_sha256"]


def test_the_first_listing_writes_a_snapshot_to_approve(wrapped):
    """Nothing can be approved until something has been captured, and the
    capture is named after the ids the refusal just handed out."""
    data = _refusal(wrapped.talk([INIT, LIST]), 2)
    capture = (wrapped.state_root / "captures" /
               f"{data['server_id']}.{data['snapshot_sha256']}.json")
    assert capture.exists(), sorted(
        p.name for p in (wrapped.state_root / "captures").glob("*"))


def test_approval_from_the_payloads_ids_opens_the_route(wrapped):
    """The whole chain, using ONLY what the client was told.

    No directory is listed and no `--state-root` is passed: if either were
    needed, this row could not be written from a user's point of view.
    """
    data = _refusal(wrapped.talk([INIT, LIST]), 2)
    assert wrapped.approve_at_a_terminal(
        data["server_id"], data["snapshot_sha256"]) == 0

    frames = wrapped.talk([INIT, LIST, CALL])
    listing = next(f for f in frames if f.get("id") == 2)
    assert [t["name"] for t in listing["result"]["tools"]] == ["echo"]
    answer = next(f for f in frames if f.get("id") == 3)
    assert answer["result"]["content"][0]["text"] == "hello"


def test_a_credential_in_the_result_is_withheld_after_approval(tmp_path):
    """T8's response-direction row, and the control the others need.

    Without it, every row above is satisfied by a proxy that forwards
    everything once approved. The refusal here must be PROHIBITED_CONTENT and
    not APPROVAL_REQUIRED: the difference is 'inspected and blocked' versus
    'never looked'.
    """
    hostile = Wrapped(tmp_path, inject=f"here you go: {CREDENTIAL}")
    data = _refusal(hostile.talk([INIT, LIST]), 2)
    assert hostile.approve_at_a_terminal(
        data["server_id"], data["snapshot_sha256"]) == 0

    frames = hostile.talk([INIT, LIST, CALL])
    answer = next(f for f in frames if f.get("id") == 3)
    assert "result" not in answer, "the credential reached the client"
    blocked = answer["error"]["data"]
    assert blocked["reason_code"] == "PROHIBITED_CONTENT"
    assert blocked["status"] == "complete"
    assert blocked["inspection_complete"] is True
    assert blocked["rule_ids"], "a block that names no rule cannot be audited"
