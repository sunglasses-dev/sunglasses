"""An approval is bound to the folder the server was started from, and says so.

The server identity includes the working directory. Started from another folder, the same
server has another identity, finds no approval, and lists no tool; nothing said why. The
capture a person is shown, the record `proxy approve` writes and `doctor` now carry the
folder, and the approve command prints it.
"""
import io
import json
import os

import pytest

from sunglasses.proxy import approvals, commands, doctor

SHA = "a" * 64
TOOLS = {"read": {"descriptor_sha256": "b" * 64}}


def _capture(root, server_id, folder):
    os.makedirs(folder, exist_ok=True)
    old = os.getcwd()
    os.chdir(folder)
    try:
        store = approvals.Store(root, server_id=server_id)
        store.capture(SHA, {"sha256": SHA, "tools_by_name": TOOLS})
    finally:
        os.chdir(old)
    return store


def _approve(root, server_id):
    out, err = io.StringIO(), io.StringIO()
    code = commands._approve(server_id, {"snapshot": SHA, "state-root": str(root)}, out, err,
                             confirm=lambda: True)
    return code, out.getvalue(), err.getvalue()


def test_capture_records_the_folder_the_proxy_was_started_from(tmp_path):
    folder = tmp_path / "proj"
    store = _capture(tmp_path / "root", "s" * 32, folder)
    stored = json.loads((store.captures / f"{'s' * 32}.{SHA}.json").read_text())
    assert stored["folder"] == os.path.realpath(folder) or stored["folder"] == str(folder)


def test_approve_prints_the_folder_the_approval_is_bound_to(tmp_path):
    folder = tmp_path / "proj"
    _capture(tmp_path / "root", "s" * 32, folder)
    code, out, _err = _approve(tmp_path / "root", "s" * 32)
    assert code == 0 and "approved" in out
    line = next(l for l in out.splitlines() if l.startswith("approval bound to folder"))
    assert "proj" in line
    assert "start the server from there" in line and "approve again" in line


def test_the_approval_record_carries_the_folder(tmp_path):
    folder = tmp_path / "proj"
    _capture(tmp_path / "root", "s" * 32, folder)
    _approve(tmp_path / "root", "s" * 32)
    record = json.loads((tmp_path / "root" / "approvals" / f"{'s' * 32}.json").read_text())
    assert "proj" in record["folder"]


def test_an_old_capture_without_a_folder_says_unknown_and_still_approves(tmp_path):
    store = approvals.Store(tmp_path / "root", server_id="s" * 32)
    (store.captures / f"{'s' * 32}.{SHA}.json").write_text(
        json.dumps({"sha256": SHA, "tools_by_name": TOOLS}))
    code, out, _err = _approve(tmp_path / "root", "s" * 32)
    assert code == 0 and "unknown (recorded before folders were kept)" in out


def test_a_folder_with_a_control_character_is_never_echoed():
    assert "\x1b" not in approvals.folder_text("/tmp/\x1b[31mred")
    assert "control characters" in approvals.folder_text("/tmp/a\nb")


def test_doctor_lists_each_approval_with_its_folder(tmp_path):
    root = tmp_path / "home" / "proxy"
    _capture(root, "s" * 32, tmp_path / "one")
    _approve(root, "s" * 32)
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"d": {"command": "python3", "args": ["x.py"]}}}))
    rendered = doctor.render(doctor.run(sources=[("project", cfg)], home=tmp_path / "home"))
    row, = rendered["approvals"]
    assert row["state"] == "APPROVED" and "one" in row["folder"]
    assert row["server"] == "s" * 12 and row["tools"] == 1 and row["snapshot"] == SHA[:12]


def test_doctor_names_a_record_it_cannot_read(tmp_path):
    root = tmp_path / "home" / "proxy"
    (root / "approvals").mkdir(parents=True)
    (root / "approvals" / f"{'t' * 32}.json").write_text("{not json")
    rows = approvals.approval_rows(root)
    assert rows == [{"server": "t" * 12, "state": "UNREADABLE", "folder": None,
                     "snapshot": None, "tools": None}]


def test_doctor_with_no_approvals_lists_none_and_creates_nothing(tmp_path):
    root = tmp_path / "home" / "proxy"
    assert approvals.approval_rows(root) == []
    assert not root.exists()
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"d": {"command": "python3", "args": ["x.py"]}}}))
    rendered = doctor.render(doctor.run(sources=[("project", cfg)], home=tmp_path / "home"))
    assert "approvals" not in rendered


def test_the_human_doctor_report_prints_the_approvals_block(tmp_path, capsys):
    from sunglasses import cli
    rendered = {"self_test": {"valid": True, "failure_class": "", "failed": [], "deadline": "",
                              "controls": {}, "checks": {}, "detail": "", "measured_ms": 0,
                              "bound_ms": 0},
                "per_wrapper": [], "inventory": [], "aggregate": "ok", "route_checks": {},
                "receipts_key": {"status": "OFF", "cause": ""}, "exit_code": 0,
                "approvals": [{"server": "s" * 12, "state": "APPROVED", "folder": "/work/proj",
                               "snapshot": SHA[:12], "tools": 3}]}
    real = doctor.render
    doctor.render = lambda r: rendered
    try:
        args = type("A", (), {"config": None, "json": False})()
        with pytest.raises(SystemExit):
            cli.cmd_doctor(args, _run=lambda **kw: object())
    finally:
        doctor.render = real
    out = capsys.readouterr().out
    assert "Approvals" in out and "folder /work/proj" in out and "3 tool(s)" in out
