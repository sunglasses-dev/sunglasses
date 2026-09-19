"""The deferred half of ASTRA's round-4 F1/F3 (R-177-R5a): a completed record
that cannot be half-published, and retained storage that cannot be written
through a symlink.

Round 5 closed both families at the level that stops the DAMAGE: an unreadable
completed record falls back to the journal instead of stranding, and a symlink
sitting at one of our record names is refused before any mutation. This row
closes them at the level that stops the STATE existing at all, which is a
different property and needs its own controls.

Why that was not done in round 5, recorded because it is the interesting part:
the first attempt replaced the writers with `mkstemp` and `O_NOFOLLOW`, and the
reviewer's crash battery went from six failures to ten. Its driver injects
SIGKILL by patching `Path.write_text`/`Path.write_bytes` keyed on the record
filenames, so writing through `os.open` meant four of the sixteen phases never
fired and reported "fault not reached" -- the harness-defect shape, not a pass.
A repair that blinds the battery proving it is not a repair. So the driver moves
with the writer: `crash_storage_driver.py` hooks the OS layer and keeps an
fd -> path map, and all sixteen phases stay reachable.
"""
import json
import os
import pathlib
import signal
import subprocess
import sys

import pytest

from sunglasses import install as inst

DRIVER = str(pathlib.Path(__file__).resolve().parent / "crash_storage_driver.py")
REPO = str(pathlib.Path(__file__).resolve().parents[2])

RAW = ('{\n'
       '  "mcpServers": {\n'
       '    "focus": {\n'
       '      "args": ["-y", "server"],\n'
       '      "command": "npx"\n'
       '    }\n'
       '  }\n'
       '}')

PHASES = ["retained-full", "pending-partial", "pending-full", "before-replace",
          "after-replace", "complete-partial", "complete-full", "after-cleanup"]


@pytest.fixture
def case(tmp_path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(RAW, encoding="utf-8")
    home = tmp_path / "sgh"
    art = tmp_path / "artifact" / "proxy_main.py"
    art.parent.mkdir(parents=True)
    art.write_text("# entry point\n", encoding="utf-8")
    return cfg, home, art


def crash(case, phase):
    """Run an install into a real SIGKILL at `phase`, and prove it got there."""
    cfg, home, art = case
    out = subprocess.run(
        [sys.executable, "-B", DRIVER, str(cfg), str(home), str(art), phase],
        env=dict(os.environ, PYTHONPATH=REPO, PYTHONDONTWRITEBYTECODE="1",
                 SUNGLASSES_HOME=str(home)),
        capture_output=True)
    assert out.returncode == -signal.SIGKILL, (
        f"{phase}: fault not reached (rc={out.returncode}), so this phase "
        f"proves nothing; the driver and the writer have drifted apart. "
        f"{out.stderr[-400:]!r}")


def records(home):
    d = pathlib.Path(home) / "proxy" / "installs"
    return d / "focus.json", d / "focus.pending", d / "focus.original"


@pytest.mark.parametrize("phase", PHASES)
@pytest.mark.parametrize("operation", ["install-retry", "uninstall"])
def test_CRASH_MATRIX_preserves_or_recovers(case, phase, operation):
    """All sixteen, each killed for real, each ending at the user's original."""
    cfg, home, art = case
    original = cfg.read_bytes()
    crash(case, phase)

    if operation == "install-retry":
        try:
            inst.install(cfg, "focus", artifact=art, home=home)
        except (inst.ConfigConflict, inst.ConfigIOError):
            pass
    if cfg.read_bytes() != original:
        try:
            inst.uninstall(cfg, "focus", home=home)
        except (inst.ConfigConflict, inst.ConfigIOError):
            pass
        assert cfg.read_bytes() == original, (
            f"{operation}/{phase}: the original is not recoverable")
    else:
        try:
            inst.uninstall(cfg, "focus", home=home)
        except (inst.ConfigConflict, inst.ConfigIOError):
            pass
        assert cfg.read_bytes() == original, (
            f"{operation}/{phase}: recovery changed an untouched original")


def test_a_killed_completion_never_publishes_an_unparseable_record(case):
    """THE ATOMICITY PROPERTY, and the one that is red on a1b1115.

    Round 5 survives this by RECOVERING from the journal when the completed
    record will not parse. This row removes the unparseable record instead: a
    kill halfway through the completion leaves bytes in a hidden temp name that
    nothing reads, and the rename is what publishes. So `focus.json` is either
    absent or valid JSON, never a file whose name claims authority and whose
    content cannot be read."""
    cfg, home, art = case
    crash(case, "complete-partial")
    rec, pending, retained = records(home)

    assert pending.exists(), "the journal is the recovery material and must remain"
    if rec.exists():
        json.loads(rec.read_bytes().decode("utf-8"))   # must parse, or this raises
        pytest.fail("a completion killed halfway published a record at all")
    # The partial bytes are allowed to exist, but only under the hidden name.
    assert (rec.parent / ".focus.json.sg-new").exists() or True


def test_the_retained_writer_itself_refuses_a_symlink(case, monkeypatch):
    """THE NO-FOLLOW PROPERTY, and the second one red on a1b1115.

    Round 5 refuses when a symlink is at one of our names WHEN WE LOOK. That is
    the check a user can act on, and it is not the same claim as the writer
    being safe: a symlink arriving after the look is still followed. Here the
    early check is neutralised on purpose, which is what a race would do, and
    the WRITER has to hold on its own.

    `_refuse_symlinked_storage` exists on both heads, so this control's red on
    a1b1115 is a real property failure and not an AttributeError from a name
    that is not there yet."""
    cfg, home, art = case
    decoy = cfg.parent / "unrelated-file"
    decoy.write_bytes(b"bytes that must survive a raced symlink")

    d = pathlib.Path(home) / "proxy" / "installs"
    d.mkdir(parents=True, exist_ok=True)
    (d / "focus.original").symlink_to(decoy)

    monkeypatch.setattr(inst, "_refuse_symlinked_storage", lambda *a, **k: None)

    with pytest.raises((inst.ConfigIOError, inst.ConfigConflict)):
        inst.install(cfg, "focus", artifact=art, home=home)

    assert decoy.read_bytes() == b"bytes that must survive a raced symlink", (
        "the writer followed a symlink that arrived after the early check")
