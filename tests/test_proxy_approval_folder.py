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
    assert "start the proxy from it" in line and "approve the capture" in line


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


def _row(server, state):
    return {"server": server, "state": state, "folder": None, "snapshot": None, "tools": None}


def test_doctor_names_a_record_the_store_would_refuse(tmp_path):
    root = tmp_path / "home" / "proxy"
    (root / "approvals").mkdir(parents=True)
    (root / "approvals" / f"{'t' * 32}.json").write_text("{not json")
    assert approvals.approval_rows(root) == [_row("t" * 12, "INVALID")]


def test_a_record_with_only_a_folder_and_stem_is_invalid_not_approved(tmp_path):
    root = tmp_path / "root"
    (root / "approvals").mkdir(parents=True)
    stem = "stem-of-the-command"
    for name, text in (("a" * 32, json.dumps({"folder": "/not-approved", "command_stem": stem})),
                       ("b" * 32, "{}"),
                       ("c" * 32, '{"approved_by": "human", "approved_by": "human"}')):
        (root / "approvals" / f"{name}.json").write_text(text)
        # The Store, which is what admits a call, says the same.
        assert approvals.Store(root, server_id=name).state() == approvals.INVALID
    rows = approvals.approval_rows(root)
    assert [r["state"] for r in rows] == ["INVALID"] * 3
    assert approvals.other_folders(root, stem, "/here") == []


def test_a_duplicate_key_in_a_real_record_makes_it_invalid(tmp_path):
    root = tmp_path / "root"
    _capture(root, "s" * 32, tmp_path / "one")
    _approve(root, "s" * 32)
    path = root / "approvals" / f"{'s' * 32}.json"
    text = path.read_text()
    assert approvals.approval_rows(root)[0]["state"] == "APPROVED"
    path.write_text(text.replace('"approved_by"', '"approved_by": "human", "approved_by"', 1))
    assert approvals.approval_rows(root)[0]["state"] == "INVALID"


def test_a_file_name_with_an_escape_is_never_a_label(tmp_path):
    root = tmp_path / "root"
    _capture(root, "s" * 32, tmp_path / "one")
    _approve(root, "s" * 32)
    good = root / "approvals" / f"{'s' * 32}.json"
    bad = root / "approvals" / "\x1b[31mBAD.json"
    bad.write_text(good.read_text())
    bad2 = root / "approvals" / "\x1b[31mWORSE.json"
    bad2.write_text("{not json")
    for row in approvals.approval_rows(root):
        assert row["server"].isprintable()
    assert [r["state"] for r in approvals.approval_rows(root)].count("APPROVED") == 2


def test_the_human_report_escapes_a_label_whatever_the_row_says(tmp_path, capsys):
    out = _human_doctor([{"server": "\x1b[31mBAD", "state": "APPROVED", "folder": "/w",
                          "snapshot": SHA[:12], "tools": 1},
                         {"server": "\x1b[31mWORSE", "state": "INVALID", "folder": None,
                          "snapshot": None, "tools": None}], capsys)
    assert "\x1b[31m" not in out and "\\x1b[31mBAD" in out and "\\x1b[31mWORSE" in out
    assert "INVALID" in out


def test_a_file_of_bytes_that_are_not_text_does_not_stop_the_listing_or_the_hint(tmp_path, capsys):
    root = tmp_path / "home" / "proxy"
    _approved_from(root, tmp_path / "there")
    (root / "approvals" / "000bad.json").write_bytes(b"\xff\xfe not text \xff")
    (root / "approvals" / "unrelated.json").write_bytes(b"\xc3\x28")
    rows = approvals.approval_rows(root)
    assert sorted(r["state"] for r in rows) == ["APPROVED", "INVALID", "INVALID"]
    # The hint still finds the good record that sorts after the bad one.
    stem = serve._command_stem(ARGV)
    assert approvals.other_folders(root, stem, "/here") == [os.path.realpath(tmp_path / "there")] or \
        approvals.other_folders(root, stem, "/here") == [str(tmp_path / "there")]
    # doctor, as data and as the printed report, still reports.
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"d": {"command": "python3", "args": ["x.py"]}}}))
    rendered = doctor.render(doctor.run(sources=[("project", cfg)], home=tmp_path / "home"))
    assert [r["state"] for r in rendered["approvals"]].count("INVALID") == 2
    out = _human_doctor(rendered["approvals"], capsys)
    assert out.count("INVALID") == 2 and "APPROVED" in out


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs a directory this user cannot list")
def test_an_approvals_folder_that_cannot_be_listed_is_reported_not_empty(tmp_path):
    root = tmp_path / "root"
    _capture(root, "s" * 32, tmp_path / "one")
    _approve(root, "s" * 32)
    folder = root / "approvals"
    os.chmod(folder, 0)
    try:
        assert approvals.approval_rows(root) == [_row("(the approvals folder)", "UNREADABLE")]
    finally:
        os.chmod(folder, 0o700)
    assert approvals.approval_rows(root)[0]["state"] == "APPROVED"


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs a file this user cannot read")
def test_a_record_that_cannot_be_read_is_unreadable_not_invalid(tmp_path):
    root = tmp_path / "root"
    _capture(root, "s" * 32, tmp_path / "one")
    _approve(root, "s" * 32)
    path = root / "approvals" / f"{'s' * 32}.json"
    os.chmod(path, 0)
    try:
        assert approvals.approval_rows(root) == [_row("s" * 12, "UNREADABLE")]
    finally:
        os.chmod(path, 0o600)


def test_doctor_with_no_approvals_lists_none_and_creates_nothing(tmp_path):
    root = tmp_path / "home" / "proxy"
    assert approvals.approval_rows(root) == []
    assert not root.exists()
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"d": {"command": "python3", "args": ["x.py"]}}}))
    rendered = doctor.render(doctor.run(sources=[("project", cfg)], home=tmp_path / "home"))
    assert "approvals" not in rendered


def _human_doctor(rows, capsys):
    from sunglasses import cli
    rendered = {"self_test": {"valid": True, "failure_class": "", "failed": [], "deadline": "",
                              "controls": {}, "checks": {}, "detail": "", "measured_ms": 0,
                              "bound_ms": 0},
                "per_wrapper": [], "inventory": [], "aggregate": "ok", "route_checks": {},
                "receipts_key": {"status": "OFF", "cause": ""}, "exit_code": 0,
                "approvals": rows}
    real = doctor.render
    doctor.render = lambda r: rendered
    try:
        args = type("A", (), {"config": None, "json": False})()
        with pytest.raises(SystemExit):
            cli.cmd_doctor(args, _run=lambda **kw: object())
    finally:
        doctor.render = real
    return capsys.readouterr().out


def test_the_human_doctor_report_prints_the_approvals_block(tmp_path, capsys):
    out = _human_doctor([{"server": "s" * 12, "state": "APPROVED", "folder": "/work/proj",
                          "snapshot": SHA[:12], "tools": 3}], capsys)
    assert "Approvals" in out and "folder /work/proj" in out and "3 tool(s)" in out


# --- the proxy's own stderr notice (the agent-facing reply stays as it was) ---------------

from sunglasses.proxy import envelope, serve

ARGV = ["/bin/echo", "server"]


def _notice(root, folder):
    err = io.StringIO()
    old = os.getcwd()
    os.makedirs(folder, exist_ok=True)
    os.chdir(folder)
    try:
        serve.approval_notice(err, root, serve._command_stem(ARGV))("i" * 32, SHA)
    finally:
        os.chdir(old)
    return err.getvalue()


def _approved_from(root, folder):
    os.makedirs(folder, exist_ok=True)
    old = os.getcwd()
    os.chdir(folder)
    try:
        sid = serve._identity(ARGV)
        approvals.Store(root, server_id=sid, command_stem=serve._command_stem(ARGV)).capture(
            SHA, {"sha256": SHA, "tools_by_name": TOOLS})
    finally:
        os.chdir(old)
    _approve(root, sid)


def test_the_stem_is_the_identity_without_the_folder(tmp_path):
    old = os.getcwd()
    ids, stems = [], []
    try:
        for name in ("a", "b"):
            (tmp_path / name).mkdir()
            os.chdir(tmp_path / name)
            ids.append(serve._identity(ARGV))
            stems.append(serve._command_stem(ARGV))
    finally:
        os.chdir(old)
    assert ids[0] != ids[1]
    assert stems[0] == stems[1]
    assert serve._command_stem(["/bin/echo", "other"]) != stems[0]


def test_the_notice_names_the_folder_this_run_is_in(tmp_path):
    text = _notice(tmp_path / "root", tmp_path / "here")
    assert "bound to the folder the server is started from" in text and "here" in text
    assert "already approved from" not in text


def test_the_notice_is_one_line_and_never_prints_a_folder_with_control_characters(tmp_path):
    for hostile in ("a\nb", "a\x1b[2Jb", "a\rb"):
        text = _notice(tmp_path / "root", tmp_path / hostile)
        assert len(text.splitlines()) == 1 and text.endswith("\n"), repr(text)
        assert "\x1b" not in text and hostile not in text
        assert "this run is in (a folder whose name has control characters)" in text


def test_the_notice_names_the_folder_that_holds_an_approval_for_the_same_command(tmp_path):
    root = tmp_path / "root"
    _approved_from(root, tmp_path / "there")
    text = _notice(root, tmp_path / "here")
    line = next(l for l in text.splitlines() if "already approved from" in l)
    assert "there" in line and "approve this run's capture with the command above" in line


def test_a_different_command_is_not_reported_as_approved_elsewhere(tmp_path):
    root = tmp_path / "root"
    _approved_from(root, tmp_path / "there")
    err = io.StringIO()
    serve.approval_notice(err, root, serve._command_stem(["/bin/echo", "other"]))("i" * 32, SHA)
    assert "already approved from" not in err.getvalue()


def test_the_agent_facing_envelope_has_no_folder_in_it():
    body = envelope.withheld(request_id=1, reason_code="APPROVAL_REQUIRED", rule="S4",
                             accepted=False, status="not_run", inspection_complete=False,
                             inspected_utf8_bytes=0, observed_content_bytes=0, elapsed_ms=0,
                             server_id="s" * 32, snapshot_sha256=SHA, folder="/work/secret")
    assert "folder" not in json.dumps(body) and "/work/secret" not in json.dumps(body)
