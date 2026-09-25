"""R76: a removal the kernel refuses is retained by name, and the proof stays.

`_unlink_under_proof` swallowed the OSError from the unlink and returned True,
so both stale collectors went on to remove the OWNER file: the one thing a
later collect needs to prove the alias's writer has ended. Measured on main
801ca97d with a real kernel refusal (chflags uchg): the collect returned []
with the alias still there and its owner gone, and every collect after it kept
the alias forever as "no owner file to prove anything with".

The alias here is left the way a real death leaves it: a forget killed the
instant `os.link` returns (the `_KILLED_FORGET` driver of
test_install_transaction). The refusal is a PermissionError raised for the
alias only, so it runs on any platform; chflags is a BSD tool.
"""
import errno
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys

import pytest

from sunglasses import install as inst

pytestmark = pytest.mark.skipif(
    inst.LOCKING is None, reason="the collectors prove nothing without locking")

RAW_CONFIG = (
    '{\n  "mcpServers": {\n    "github": {\n'
    '      "args": ["-y", "@modelcontextprotocol/server-github"],\n'
    '      "command": "npx"\n    }\n  }\n}')

_KILLED_FORGET = """
import os, pathlib, signal, sys
sys.path.insert(0, %r)
from sunglasses import install as inst
mine = os.getpid()
real_link = os.link
def link_then_die(src, dst, *a, **kw):
    out = real_link(src, dst, *a, **kw)
    os.kill(mine, signal.SIGKILL)
    return out
os.link = link_then_die
inst._forget_take(pathlib.Path(sys.argv[1]), "an-older-take")
"""


@pytest.fixture
def dead_alias(tmp_path):
    """A held file, its note, and the alias + owner file a killed forget left."""
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(RAW_CONFIG, encoding="utf-8")
    home = tmp_path / "sgh"
    art = tmp_path / "artifact" / "proxy_main.py"
    art.parent.mkdir(parents=True)
    art.write_text("# proxy entry point\n", encoding="utf-8")
    inst.install(cfg, "github", artifact=art, home=home)
    records = home / "proxy" / "installs"
    held = records / "github.original.discarding-1-a"
    held.write_bytes((records / "github.original").read_bytes())
    note = records / "github.taking"
    note.write_text(json.dumps(
        {"canonical": "github.original", "held": held.name,
         "owner": "an-interrupted-take", "sha256": inst._digest_file(held)}),
        encoding="utf-8")
    driver = tmp_path / "killed_forget.py"
    driver.write_text(_KILLED_FORGET % str(
        pathlib.Path(inst.__file__).resolve().parents[1]), encoding="utf-8")
    done = subprocess.run(
        [sys.executable, "-B", str(driver), str(note)],
        env=dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(home),
                 PYTHONDONTWRITEBYTECODE="1"),
        capture_output=True, timeout=30)
    assert done.returncode == -signal.SIGKILL, (
        "the forget was not killed at the link, so there is no dead alias: "
        "rc=%r %r" % (done.returncode, done.stderr[-300:]))
    aliases = sorted(records.glob("github.taking*.forgetting-*"))
    assert len(aliases) == 1, aliases
    alias = aliases[0]
    owner = inst._owner_file(alias)
    assert owner.is_file(), "the killed forget left no owner file"
    return records, held, alias, owner


def _refuse(monkeypatch, victim):
    real = pathlib.Path.unlink

    def unlink(self, *a, **kw):
        if self == victim:
            raise PermissionError(errno.EPERM, "Operation not permitted",
                                  str(self))
        return real(self, *a, **kw)
    monkeypatch.setattr(pathlib.Path, "unlink", unlink)


def _stale(records, held, alias):
    private = records / "github.taking.forgetting-collector-private"
    return inst._collect_stale_aliases(records, private, inst._read_note(alias))


def _discharged(records, held, alias):
    held.unlink()                       # the bytes are back: every note is spent
    return inst._collect_discharged_notes(records, held.name)


COLLECTORS = pytest.mark.parametrize(
    "collect", [_stale, _discharged], ids=["stale_aliases", "discharged_notes"])


def _names(retained, path):
    return [r for r in retained if r.startswith(str(path) + ": ")]


@COLLECTORS
def test_a_refused_removal_is_retained_by_name_and_keeps_its_owner(
        dead_alias, monkeypatch, collect):
    records, held, alias, owner = dead_alias
    _refuse(monkeypatch, alias)
    retained = collect(records, held, alias)
    assert alias.exists(), "the stimulus did not hold: the alias was removed"
    assert owner.is_file(), (
        "the removal was refused and the collector removed the owner file "
        "anyway, so no later collect can prove this alias's writer has ended")
    named = _names(retained, alias)
    assert named, (
        "the alias is still on disk and the collector reported nothing "
        "retained: %r" % (retained,))
    assert "PermissionError" in named[0] and "EPERM" in named[0], named


@COLLECTORS
def test_the_alias_is_collected_once_the_refusal_clears(
        dead_alias, monkeypatch, collect):
    records, held, alias, owner = dead_alias
    _refuse(monkeypatch, alias)
    collect(records, held, alias)
    monkeypatch.undo()
    if collect is _discharged:
        again = inst._collect_discharged_notes(records, held.name)
    else:
        again = _stale(records, held, alias)
    assert not alias.exists() and not owner.exists(), (
        "with the refusal gone the collect could not finish: alias %s, owner "
        "%s, retained %r" % (alias.exists(), owner.exists(), again))
    assert not _names(again, alias), again


# R76 fold (T9 ruling 81 (3)). `_collect_discharged_notes` returned `retained`
# BEFORE assigning it when it was handed no held name, and recovery hands it
# exactly that for a note `_read_note` refuses but `_reclaim_one` accepts: one
# with a valid `held` and `sha256` and no `owner`. The bytes went back and the
# note was removed, then UnboundLocalError escaped `_reclaim_taken` and the
# orphan sweep after it never ran. Measured on main 801ca97d, off lock.

@pytest.mark.parametrize("held_name", [None, ""], ids=["none", "empty"])
def test_a_note_with_no_held_name_collects_nothing(tmp_path, held_name):
    assert inst._collect_discharged_notes(tmp_path, held_name) == []


@pytest.mark.parametrize("owner", [None, "an-interrupted-take"],
                         ids=["no_owner", "control_owner"])
def test_recovery_from_a_note_without_an_owner_finishes(tmp_path, owner):
    records, _, _, bytes_path = inst._record_paths(tmp_path, "github")
    records.mkdir(parents=True)
    held = records / "github.original.discarding-1-a"
    held.write_bytes(b'{"a": 1}\n')
    note = {"held": held.name,
            "sha256": hashlib.sha256(held.read_bytes()).hexdigest()}
    if owner is not None:
        note["owner"] = owner
    (records / "github.taking").write_text(json.dumps(note), encoding="utf-8")
    read = inst._read_note(records / "github.taking")
    assert (read is None) == (owner is None), (
        "the stimulus did not hold: _read_note answered %r" % (read,))
    assert inst._reclaim_taken(tmp_path, "github") is True
    assert bytes_path.read_bytes() == b'{"a": 1}\n'
    assert sorted(p.name for p in records.iterdir()) == ["github.original"]

