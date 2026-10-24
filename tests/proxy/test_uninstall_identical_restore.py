"""R38 (0.6.1) -- uninstall says "byte-identical" when the end state IS the
original, and warns only when it is not.

Two wraps on one file, uninstalled first-installed-first (FIFO), put the file
back byte for byte, and each uninstall still printed "file not byte-identical:
it changed after the install". The second of those is a false statement to the
user: the file in front of them is exactly what they had before either install.

The first FIFO uninstall keeps its warning, and a row below pins that: at that
moment the second install's wrapper is still in the file, so the file really is
not what it was before the first install.

Why the config here is written by `json.dumps(indent=2)` with a trailing
newline: an entry-only restore renders the file that way, so only a config
already in that form CAN come back byte-identical through two entry-only
restores. The odd-format fixture in test_install_transaction.py can never
return identical this way, and the warning there is true.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses import install as inst

REPO = str(pathlib.Path(__file__).resolve().parents[2])

CANON = (json.dumps({"mcpServers": {
    "echo": {"command": "echo-server", "args": ["--stdio"]},
    "fetch": {"command": "fetch-server", "args": ["--stdio"]},
}}, indent=2) + "\n").encode("utf-8")

CANON3 = (json.dumps({"mcpServers": {
    "echo": {"command": "echo-server", "args": ["--stdio"]},
    "fetch": {"command": "fetch-server", "args": ["--stdio"]},
    "time": {"command": "time-server", "args": ["--stdio"]},
}}, indent=2) + "\n").encode("utf-8")

EARLIER = "(byte-identical to the file before an earlier install)"
WARNING = "not byte-identical"
CHANGED = "changed after the install"


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_bytes(CANON)
    return p


@pytest.fixture
def home(tmp_path):
    return tmp_path / "sgh"


@pytest.fixture
def artifact(tmp_path):
    a = tmp_path / "artifact" / "proxy_main.py"
    a.parent.mkdir(parents=True)
    a.write_text("# proxy entry point\n", encoding="utf-8")
    return a


def read(p):
    return pathlib.Path(p).read_bytes()


def foreign_edit(p):
    d = json.loads(read(p).decode("utf-8"))
    d["mcpServers"]["added-later"] = {"command": "other", "args": []}
    p.write_bytes((json.dumps(d, indent=2) + "\n").encode("utf-8"))


# ------------------------------------------------------------ library rows

def test_fifo_second_uninstall_reports_identical_when_the_end_state_is_the_original(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    first = inst.uninstall(cfg, "echo", home=home)
    last = inst.uninstall(cfg, "fetch", home=home)

    assert read(cfg) == CANON            # the premise, measured, not assumed
    assert first.byte_exact is False     # fetch is still wrapped at that point
    assert last.byte_exact is True
    assert last.earlier is True          # the match is with an earlier original


def test_three_installs_undone_first_installed_first_end_at_the_first_original(
        tmp_path, home, artifact):
    cfg3 = tmp_path / "three.json"
    cfg3.write_bytes(CANON3)
    for name in ("echo", "fetch", "time"):
        inst.install(cfg3, name, artifact=artifact, home=home)

    steps = [inst.uninstall(cfg3, name, home=home) for name in ("echo", "fetch", "time")]

    assert read(cfg3) == CANON3
    assert [r.byte_exact for r in steps] == [False, False, True]
    assert steps[2].earlier is True


def test_fifo_first_uninstall_still_warns_while_the_other_wrapper_is_in_the_file(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    first = inst.uninstall(cfg, "echo", home=home)

    assert read(cfg) != CANON
    assert inst.classify(json.loads(read(cfg))["mcpServers"]["fetch"],
                         artifact=artifact) == "WRAPPED"
    assert first.byte_exact is False


def test_control_a_real_foreign_edit_still_warns_on_fifo(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    foreign_edit(cfg)

    inst.uninstall(cfg, "echo", home=home)
    last = inst.uninstall(cfg, "fetch", home=home)

    assert read(cfg) != CANON
    assert "added-later" in json.loads(read(cfg))["mcpServers"]
    assert last.byte_exact is False


def test_control_a_real_foreign_edit_still_warns_on_a_single_wrap(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    foreign_edit(cfg)

    res = inst.uninstall(cfg, "echo", home=home)

    assert read(cfg) != CANON
    assert res.byte_exact is False


def test_a_reformat_only_edit_comes_back_identical_to_this_installs_original(
        cfg, home, artifact):
    """The other half of "compare the final file to the pre-install original":
    an editor that re-indents the wrapped file moves it off the after-image, so
    the restore is entry-only, and it still lands on the exact original."""
    inst.install(cfg, "echo", artifact=artifact, home=home)
    cfg.write_bytes(json.dumps(json.loads(read(cfg)), indent=4).encode("utf-8"))

    res = inst.uninstall(cfg, "echo", home=home)

    assert read(cfg) == CANON
    assert res.byte_exact is True
    assert res.earlier is False


def test_lifo_is_unchanged(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    assert inst.uninstall(cfg, "fetch", home=home).byte_exact is True
    assert inst.uninstall(cfg, "echo", home=home).byte_exact is True
    assert read(cfg) == CANON


def test_single_wrap_is_unchanged(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    assert inst.uninstall(cfg, "echo", home=home).byte_exact is True
    assert read(cfg) == CANON


def test_an_unreadable_earlier_digest_list_falls_back_to_the_warning(
        cfg, home, artifact):
    """The earlier digests only ever change WORDING, and a record whose list is
    not a list of digests gets the conservative sentence, never the claim."""
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    rec = pathlib.Path(home) / "proxy" / "installs" / "fetch.json"
    body = json.loads(rec.read_text(encoding="utf-8"))
    assert "earlier_sha_before" in body
    body["earlier_sha_before"] = "not a list"
    rec.write_text(json.dumps(body, indent=2), encoding="utf-8")

    inst.uninstall(cfg, "echo", home=home)
    last = inst.uninstall(cfg, "fetch", home=home)

    assert read(cfg) == CANON
    assert last.byte_exact is False


# ---------------------------------------------------------------- CLI rows

def sg(*args, cwd, home):
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(home),
               PYTHONPATH=REPO, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", "-m", "sunglasses.cli", *args],
                          cwd=str(cwd), env=env, capture_output=True, text=True)


@pytest.fixture
def project(tmp_path):
    d = tmp_path / "work"
    d.mkdir()
    (d / ".mcp.json").write_bytes(CANON)
    return d


def _run(project, home, *steps):
    out = []
    for step in steps:
        r = sg(*step, cwd=project, home=home)
        assert r.returncode == 0, (step, r.stdout, r.stderr)
        out.append(r.stdout)
    return out


def test_cli_fifo_never_prints_changed_when_the_end_state_is_the_original(
        project, tmp_path):
    home = tmp_path / "h"
    out = _run(project, home, ("install", "echo"), ("install", "fetch"),
               ("uninstall", "echo"), ("uninstall", "fetch"))

    assert read(project / ".mcp.json") == CANON
    assert "Restored 'fetch'" in out[3]
    assert WARNING not in out[3]
    assert CHANGED not in out[3]
    assert EARLIER in out[3]


def test_cli_three_installs_undone_first_installed_first_name_the_earlier_original(
        tmp_path):
    work = tmp_path / "work3"
    work.mkdir()
    (work / ".mcp.json").write_bytes(CANON3)
    out = _run(work, tmp_path / "h", ("install", "echo"), ("install", "fetch"),
               ("install", "time"), ("uninstall", "echo"), ("uninstall", "fetch"),
               ("uninstall", "time"))

    assert read(work / ".mcp.json") == CANON3
    assert EARLIER not in out[3] and EARLIER not in out[4]
    assert "Restored 'time'" in out[5]
    assert EARLIER in out[5]
    assert WARNING not in out[5]


def test_cli_control_a_foreign_edit_still_prints_the_warning(project, tmp_path):
    home = tmp_path / "h"
    _run(project, home, ("install", "echo"), ("install", "fetch"))
    foreign_edit(project / ".mcp.json")
    out = _run(project, home, ("uninstall", "echo"), ("uninstall", "fetch"))

    assert read(project / ".mcp.json") != CANON
    assert WARNING in out[1]
    assert CHANGED in out[1]
    assert all(EARLIER not in printed for printed in out)


def test_cli_lifo_and_single_wrap_wording_is_unchanged(project, tmp_path):
    home = tmp_path / "h"
    out = _run(project, home, ("install", "echo"), ("install", "fetch"),
               ("uninstall", "fetch"), ("uninstall", "echo"),
               ("install", "echo"), ("uninstall", "echo"))

    assert read(project / ".mcp.json") == CANON
    for printed in (out[2], out[3], out[5]):
        assert "(byte-identical)" in printed
        assert WARNING not in printed


# ------------------------------------------- the stack link, one rule at a time

def _record(home, name):
    return json.loads(read(home / "proxy" / "installs" / f"{name}.json"))


def test_control_an_install_on_the_wrapper_of_an_earlier_one_carries_its_original(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    rec = _record(home, "echo")

    got = inst._earlier_originals(home, "fetch", rec["target_path"], rec["file_sha_after"])

    assert got == [rec["file_sha_before"]]


def test_a_record_for_another_file_is_not_a_link(cfg, home, artifact, tmp_path):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    rec = _record(home, "echo")
    elsewhere = str((tmp_path / "elsewhere.json").resolve())

    assert inst._earlier_originals(home, "fetch", elsewhere, rec["file_sha_after"]) == []


def test_a_file_that_is_not_the_earlier_wrapper_is_not_a_link(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    rec = _record(home, "echo")

    assert inst._earlier_originals(home, "fetch", rec["target_path"], "0" * 64) == []


def test_an_install_is_not_stacked_on_its_own_record(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    rec = _record(home, "echo")

    assert inst._earlier_originals(home, "echo", rec["target_path"], rec["file_sha_after"]) == []


def test_a_carried_list_with_one_bad_entry_is_not_read_at_all():
    good = "a" * 64
    assert inst._earlier_of({"earlier_sha_before": [good]}) == (good,)
    assert inst._earlier_of({"earlier_sha_before": [good, 5]}) == ()
    assert inst._earlier_of({"earlier_sha_before": good}) == ()
    assert inst._earlier_of({}) == ()


# ------------------------------------------------ deeper stacks and bad records

def test_four_installs_undone_first_installed_first_end_at_the_first_original(
        tmp_path, home, artifact):
    names = ("echo", "fetch", "time", "fourth")
    original = (json.dumps({"mcpServers": {
        n: {"command": n + "-server", "args": ["--stdio"]} for n in names}},
        indent=2) + "\n").encode("utf-8")
    cfg4 = tmp_path / "four.json"
    cfg4.write_bytes(original)
    for name in names:
        inst.install(cfg4, name, artifact=artifact, home=home)

    steps = [inst.uninstall(cfg4, name, home=home) for name in names]

    assert read(cfg4) == original
    assert [r.byte_exact for r in steps] == [False, False, False, True]
    assert [r.earlier for r in steps] == [False, False, False, True]


@pytest.mark.parametrize("depth", [5, 6])
def test_deeper_stacks_undone_first_installed_first_end_at_the_first_original(
        tmp_path, home, artifact, depth):
    names = ("echo", "fetch", "time", "fourth", "fifth", "sixth")[:depth]
    original = (json.dumps({"mcpServers": {
        n: {"command": n + "-server", "args": ["--stdio"]} for n in names}},
        indent=2) + "\n").encode("utf-8")
    cfg_n = tmp_path / "deep.json"
    cfg_n.write_bytes(original)
    for name in names:
        inst.install(cfg_n, name, artifact=artifact, home=home)

    steps = [inst.uninstall(cfg_n, name, home=home) for name in names]

    assert read(cfg_n) == original
    assert [r.byte_exact for r in steps] == [False] * (depth - 1) + [True]
    assert [r.earlier for r in steps] == [False] * (depth - 1) + [True]


def test_an_unreadable_earlier_digest_list_does_not_override_the_own_original(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    rec = pathlib.Path(home) / "proxy" / "installs" / "echo.json"
    body = json.loads(rec.read_text(encoding="utf-8"))
    body["earlier_sha_before"] = "not a list"
    rec.write_text(json.dumps(body, indent=2), encoding="utf-8")
    cfg.write_bytes(json.dumps(json.loads(read(cfg)), indent=4).encode("utf-8"))

    res = inst.uninstall(cfg, "echo", home=home)

    assert read(cfg) == CANON
    assert res.byte_exact is True
    assert res.earlier is False
