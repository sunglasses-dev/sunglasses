"""The install records live under the SAME root as captures and approvals.

#204 was three state roots that disagreed and nothing saying so: `approve`
defaulted to the current directory, the proxy wrote its captures under
`state_root()`, and the flow was not broken but UNREACHABLE. That PR fixed
`approve`. It deliberately left the other half of the disagreement alone, and
this is that half:

    install  ->  $SUNGLASSES_HOME/proxy/installs   (an environment variable)
    proxy    ->  ~/.sunglasses/proxy               (an argument, never a variable)

The ruling (T9, 2026-09-20) is that the approval store stays an ARGUMENT, and
install does not gain a `--state-root`: a path chosen at config-write time is
the same hole one layer up. So the disagreement resolves on install's side --
its records and locks move under `serve.state_root()`, and `SUNGLASSES_HOME`
governs scanner state (receipts, policy, pins) and nothing in the proxy lane.

`cmd_install` is where the two roots met in one function: it printed
`state_root() / 'captures'` to tell the user where the snapshot would land,
while writing its own record somewhere else entirely.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses import install as inst
from sunglasses.proxy import serve

REPO = str(pathlib.Path(__file__).resolve().parents[2])

RAW_CONFIG = (
    '{\n'
    '  "mcpServers": {\n'
    '    "github": {\n'
    '      "args": ["-y", "server-github"],\n'
    '      "command": "npx"\n'
    '    }\n'
    '  }\n'
    '}'
)


def sg(*args, cwd, home, scanner_home):
    """Run the real CLI with BOTH roots isolated and pointed at DIFFERENT trees.

    Isolating only one of them is how the last one of these went wrong: with
    `SUNGLASSES_HOME` set and `HOME` left alone, a proxy run wrote five captures
    into a real user's `~/.sunglasses` while the test read an empty sandbox and
    called it proof. Two homes, two directories, and each assertion names which
    one it means.
    """
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(scanner_home),
               PYTHONPATH=REPO, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", "-m", "sunglasses.cli", *args],
                          cwd=str(cwd), env=env, capture_output=True, text=True)


@pytest.fixture
def homes(tmp_path):
    home = tmp_path / "home"
    scanner_home = tmp_path / "scanner-home"
    home.mkdir()
    scanner_home.mkdir()
    return home, scanner_home


@pytest.fixture
def config(tmp_path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(RAW_CONFIG, encoding="utf-8")
    return cfg


def test_the_record_lands_under_the_proxy_state_root(homes, config, tmp_path):
    home, scanner_home = homes
    r = sg("install", "github", "--config", str(config), cwd=tmp_path,
           home=home, scanner_home=scanner_home)
    assert r.returncode == 0, r.stdout + r.stderr

    record = home / ".sunglasses" / "proxy" / "installs" / "github.json"
    assert record.exists(), (
        "install reported success and wrote no record under the proxy state "
        f"root. stdout:\n{r.stdout}\nstderr:\n{r.stderr}")
    assert set(json.loads(record.read_text())) >= {
        "original_entry", "installed_entry", "file_sha_before",
        "file_sha_after", "original_bytes_path"}, \
        "a file is in the right place but it is not an install record"

    # And the OTHER root is not a second place records can hide. This is the
    # assertion the old wiring fails: it put the record here instead.
    strays = [p for p in scanner_home.rglob("*") if p.is_file()]
    assert not strays, f"$SUNGLASSES_HOME holds proxy state: {strays}"


def test_the_captures_path_install_prints_and_the_record_share_one_root(
        homes, config, tmp_path):
    """The two halves of the message have to describe the same tree.

    `install` tells the user the snapshot will be written under
    `state_root()/captures` and then tells them to approve it. If its own record
    lives somewhere else, the user is being handed two directories and told they
    are one story -- which is the shape of #204, one layer up.
    """
    home, scanner_home = homes
    r = sg("install", "github", "--config", str(config), cwd=tmp_path,
           home=home, scanner_home=scanner_home)
    assert r.returncode == 0, r.stdout + r.stderr

    printed = home / ".sunglasses" / "proxy" / "captures"
    assert str(printed) in r.stdout, (
        f"the message does not name the captures directory under the state "
        f"root it will actually use. stdout:\n{r.stdout}")
    record = home / ".sunglasses" / "proxy" / "installs" / "github.json"
    assert record.exists()
    assert record.parent.parent == printed.parent, (
        "the captures directory the message names and the record it wrote do "
        "not share a root")


def test_uninstall_reads_the_root_the_install_wrote(homes, config, tmp_path):
    home, scanner_home = homes
    before = config.read_bytes()
    assert sg("install", "github", "--config", str(config), cwd=tmp_path,
              home=home, scanner_home=scanner_home).returncode == 0
    assert config.read_bytes() != before

    # The record must be THERE before its absence can mean anything. Without
    # this line the row is green on the old wiring too, for the worst possible
    # reason: the file it then declares gone was never written.
    record = home / ".sunglasses" / "proxy" / "installs" / "github.json"
    assert record.exists(), "nothing to uninstall from the proxy state root"

    r = sg("uninstall", "github", "--config", str(config), cwd=tmp_path,
           home=home, scanner_home=scanner_home)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "byte-identical" in r.stdout, r.stdout
    assert config.read_bytes() == before
    assert not record.exists()


def test_the_root_follows_state_root_when_state_root_moves(monkeypatch,
                                                          tmp_path):
    """EQUALITY IS NOT DERIVATION, and the row below only proves equality.

    ASTRA made this exact point reviewing the first version of this file: two
    paths that match today also match if the second one is a hardcoded literal
    that happens to agree, and the row cannot tell those apart. So this one
    MOVES `state_root()` to a sentinel and requires the record paths to follow
    it. A hardcoded root does not follow, which is the whole difference.
    """
    sentinel = tmp_path / "somewhere-else" / "proxy"
    monkeypatch.setattr(serve, "state_root", lambda override=None: sentinel)

    assert serve.install_records_home() == sentinel.parent
    assert inst._record_paths(serve.install_records_home(),
                              "github")[0] == sentinel / "installs"
    assert inst._lock_path(serve.install_records_home(),
                           tmp_path / "x.json").parent == sentinel / "locks"


def test_the_roots_agree_by_construction_not_by_two_literals(monkeypatch,
                                                             tmp_path):
    """Derived from `state_root()`, so a move on either side moves both.

    Written as an identity rather than as two hardcoded paths on purpose: two
    string literals that happen to match today is exactly how the three roots
    of #204 stayed wrong for as long as they did.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
    # $SUNGLASSES_HOME is pointed SOMEWHERE ELSE on purpose. With it unset, the
    # scanner home and the proxy root coincide, and this row passes against a
    # `install_records_home` that returns the old one -- measured: that mutant
    # survived here while four other rows killed it.
    monkeypatch.setenv("SUNGLASSES_HOME", str(tmp_path / "scanner-home"))

    root = serve.state_root()
    records_dir, record, pending, original = inst._record_paths(
        serve.install_records_home(), "github")
    assert records_dir == root / "installs"
    assert record.parent == records_dir
    assert pending.parent == records_dir and original.parent == records_dir
    assert inst._lock_path(serve.install_records_home(),
                           tmp_path / "x.json").parent == root / "locks"


def test_sunglasses_home_still_governs_scanner_state(monkeypatch, tmp_path):
    """The control for over-reach.

    The ruling moves the PROXY lane off the variable. It does not take the
    variable away from the scanner, whose receipts, policy and pins are exactly
    what it exists to relocate -- and a test that only proved the first half
    would pass over a change that had quietly broken the second.
    """
    from sunglasses import firewall

    monkeypatch.setenv("SUNGLASSES_HOME", str(tmp_path / "elsewhere"))
    assert firewall.sunglasses_home() == tmp_path / "elsewhere"
    monkeypatch.delenv("SUNGLASSES_HOME")
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
    assert firewall.sunglasses_home() == tmp_path / ".sunglasses"


def test_the_environment_cannot_move_the_approval_store(monkeypatch, tmp_path):
    """`state_root()` stays an argument. No variable relocates it.

    Both names are tried, because the fix for this row would be `os.environ` in
    `state_root()` and a reader should see that door closed rather than assume.
    """
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
    for name in ("SUNGLASSES_HOME", "SUNGLASSES_STATE_ROOT", "SUNGLASSES_PROXY_HOME"):
        monkeypatch.setenv(name, str(tmp_path / "attacker"))
    assert serve.state_root() == tmp_path / ".sunglasses" / "proxy"
    assert serve.install_records_home() == tmp_path / ".sunglasses"
    assert serve.state_root("/explicit/override") == pathlib.Path("/explicit/override")


def test_the_readme_already_named_this_path_and_the_code_disagreed(monkeypatch,
                                                                   tmp_path):
    """The shipped documentation was right the whole time.

    README names `~/.sunglasses/proxy/installs/` and mentions `SUNGLASSES_HOME`
    nowhere, so for any user who had that variable set the sentence was simply
    false and nothing compared the two. This pins the claim to the product in
    both directions: the path README prints is the path install writes, and it
    moves only with `HOME`.
    """
    claimed = "~/.sunglasses/proxy/installs/"
    readme = (pathlib.Path(REPO) / "README.md").read_text(encoding="utf-8")
    assert claimed in readme, (
        "README no longer names the install records directory, so this row "
        "cannot pin anything -- update the row with the sentence, do not "
        "delete it")
    assert "SUNGLASSES_HOME" not in readme, (
        "README now mentions SUNGLASSES_HOME; if it claims the variable "
        "relocates proxy state, that claim is false")

    monkeypatch.setenv("SUNGLASSES_HOME", str(tmp_path / "scanner-home"))
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
    written = inst._record_paths(serve.install_records_home(), "github")[0]
    assert written == pathlib.Path(claimed.replace("~", str(tmp_path)))
