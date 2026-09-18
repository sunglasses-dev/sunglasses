"""T10.R4/R5/R6 — the install transaction over an MCP config file.

Contract: GATE3_CONTRACT_v5_2026-09-13.md, rows T10.R4, T10.R5, T10.R6, plus
the two rules T9 adopted from the 2026-09-15 design note: install REFUSES when
it cannot resolve the artifact it is about to wire, and every assertion re-reads
bytes from disk rather than the object we serialised.

Why the fixture config below is written by hand with odd formatting instead of
`json.dump`: R5 says byte-exact restore, and a restore built from a
re-serialisation would still parse equal while differing in bytes. The odd
indent, the key order and the absent trailing newline are the discriminator. A
fixture `json.dump` produced would let C1 pass against a re-serialising
implementation, which is the whole defect the control exists to catch.
"""
import json
import os
import pathlib

import pytest

from sunglasses import install as inst


# Two-space indent, no trailing newline, "args" before "command", and a key
# ordering `json.dumps(sort_keys=...)` would not reproduce either way.
RAW_CONFIG = (
    '{\n'
    '  "mcpServers": {\n'
    '    "github": {\n'
    '      "args": ["-y", "@modelcontextprotocol/server-github"],\n'
    '      "command": "npx"\n'
    '    },\n'
    '    "filesystem": {\n'
    '      "args": ["/srv"],\n'
    '      "command": "mcp-fs"\n'
    '    }\n'
    '  }\n'
    '}'
)


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_text(RAW_CONFIG, encoding="utf-8")
    p.chmod(0o640)
    return p


@pytest.fixture
def home(tmp_path):
    return tmp_path / "sgh"


@pytest.fixture
def artifact(tmp_path):
    """A stand-in for the installed proxy: a real file with a real digest."""
    a = tmp_path / "artifact" / "proxy_main.py"
    a.parent.mkdir(parents=True)
    a.write_text("# proxy entry point\n", encoding="utf-8")
    return a


def read(p):
    """Every assertion re-reads BYTES from disk. Never the object we wrote."""
    return pathlib.Path(p).read_bytes()


def servers(p):
    return json.loads(read(p).decode("utf-8"))["mcpServers"]


# --------------------------------------------------------------- R4, install

def test_install_wraps_the_named_entry(cfg, home, artifact):
    inst.install(cfg, "github", artifact=artifact, home=home)
    entry = servers(cfg)["github"]
    assert inst.classify(entry, artifact=artifact) == "WRAPPED"


def test_install_records_the_five_contract_fields(cfg, home, artifact):
    before = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec = json.loads((home / "proxy" / "installs" / "github.json").read_text())
    assert set(rec) >= {
        "original_entry", "installed_entry",
        "file_sha_before", "file_sha_after", "original_bytes_path",
    }
    # The retained bytes are the bytes, not a re-rendering of them.
    assert read(rec["original_bytes_path"]) == before


def test_install_leaves_unrelated_entries_untouched(cfg, home, artifact):
    """Collected by property, never by position. Entry order is not ours."""
    before = servers(cfg)["filesystem"]
    inst.install(cfg, "github", artifact=artifact, home=home)
    assert servers(cfg)["filesystem"] == before


def test_install_preserves_the_file_mode(cfg, home, artifact):
    mode = cfg.stat().st_mode & 0o777
    inst.install(cfg, "github", artifact=artifact, home=home)
    assert cfg.stat().st_mode & 0o777 == mode


def test_install_never_wraps_the_wrapper(cfg, home, artifact):
    """C2. The second install must not re-wrap.

    Round 1 asserted this as a silent no-op that still returned success, and
    ASTRA's C2-REPEAT showed that is the wrong contract: a user who asks twice
    was told it worked twice. The property that matters is unchanged (never wrap
    the wrapper) but the outcome is an explicit refusal, so the assertion moved
    with it. The old wording encoded the defect it was meant to prevent.
    """
    inst.install(cfg, "github", artifact=artifact, home=home)
    once = read(cfg)

    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "github", artifact=artifact, home=home)

    assert read(cfg) == once
    # and the original recorded is still the PRE-wrap entry, not the wrapper
    rec = json.loads((home / "proxy" / "installs" / "github.json").read_text())
    assert inst.classify(rec["original_entry"], artifact=artifact) != "WRAPPED"


def test_install_refuses_when_the_artifact_cannot_be_resolved(cfg, home, tmp_path):
    """C5. Wiring a config to an artifact that is not there leaves the user
    looking protected by nothing."""
    before = read(cfg)
    missing = tmp_path / "artifact" / "absent.py"
    with pytest.raises(inst.ArtifactUnresolved):
        inst.install(cfg, "github", artifact=missing, home=home)
    assert read(cfg) == before
    assert not (home / "proxy" / "installs" / "github.json").exists()


def test_install_refuses_invalid_json_without_mutating(tmp_path, home, artifact):
    p = tmp_path / ".mcp.json"
    p.write_text('{"mcpServers": {', encoding="utf-8")
    before = read(p)
    with pytest.raises(inst.ConfigIOError):
        inst.install(p, "github", artifact=artifact, home=home)
    assert read(p) == before


def test_install_refuses_an_unknown_server_name(cfg, home, artifact):
    before = read(cfg)
    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "nope", artifact=artifact, home=home)
    assert read(cfg) == before


# ------------------------------------------------------------- R5, uninstall

def test_uninstall_restores_the_retained_bytes_exactly(cfg, home, artifact):
    """C1. `==` on bytes. Not key equality, not a subset, not 'the entries we
    know about match'. A re-serialisation parses equal and fails this."""
    before = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    assert read(cfg) != before
    inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == before


def test_uninstall_reports_byte_exact_when_the_file_did_not_move(cfg, home, artifact):
    inst.install(cfg, "github", artifact=artifact, home=home)
    assert inst.uninstall(cfg, "github", home=home).byte_exact is True


def test_uninstall_does_entry_only_inverse_when_the_file_moved(cfg, home, artifact):
    """R5 second clause. A third party edited the file after we installed."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    d = json.loads(read(cfg).decode("utf-8"))
    d["mcpServers"]["added-later"] = {"command": "other", "args": []}
    cfg.write_text(json.dumps(d, indent=2), encoding="utf-8")

    res = inst.uninstall(cfg, "github", home=home)

    assert res.byte_exact is False
    after = servers(cfg)
    assert inst.classify(after["github"], artifact=artifact) != "WRAPPED"
    assert "added-later" in after          # C3: unrelated entry survives
    assert "filesystem" in after           # C3: and so does the untouched one


def test_uninstall_refuses_an_unknown_install(cfg, home):
    before = read(cfg)
    with pytest.raises(inst.ConfigConflict):
        inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == before


def test_uninstall_refuses_when_the_entry_is_no_longer_ours(cfg, home, artifact):
    """Conflicting state: someone replaced our wrapper with their own command."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    d = json.loads(read(cfg).decode("utf-8"))
    d["mcpServers"]["github"] = {"command": "something-else", "args": []}
    cfg.write_text(json.dumps(d, indent=2), encoding="utf-8")
    before = read(cfg)
    with pytest.raises(inst.ConfigConflict):
        inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == before


# ---------------------------------------------------------------------- R6

def test_interrupted_write_leaves_the_original_intact(cfg, home, artifact, monkeypatch):
    """C4. No half-written JSON, no success return, original byte-intact."""
    before = read(cfg)
    real = inst.os.replace

    def boom(src, dst):
        raise OSError("interrupted")

    monkeypatch.setattr(inst.os, "replace", boom)
    with pytest.raises(inst.ConfigIOError):
        inst.install(cfg, "github", artifact=artifact, home=home)
    monkeypatch.setattr(inst.os, "replace", real)

    assert read(cfg) == before
    json.loads(read(cfg).decode("utf-8"))      # still parses: not half-written
    assert not (home / "proxy" / "installs" / "github.json").exists()


def test_interrupted_write_leaves_no_temp_file_behind(cfg, home, artifact, monkeypatch):
    monkeypatch.setattr(inst.os, "replace", lambda s, d: (_ for _ in ()).throw(OSError()))
    with pytest.raises(inst.ConfigIOError):
        inst.install(cfg, "github", artifact=artifact, home=home)
    # By property, not by position: the temp files are the ones we name, and
    # tmp_path also holds the `home` and `artifact` fixtures.
    assert [p.name for p in cfg.parent.glob(".sg-*")] == []


# ------------------------------------------------- C6, classification by hash

def test_a_command_that_merely_names_us_is_not_wrapped(artifact):
    """C6. WRAPPED requires the artifact's path AND hash, never a name match.
    'Recognising the name is not recognising the call' — Sep-12."""
    impostor = {"command": "python3", "args": ["-m", "sunglasses.proxy"]}
    assert inst.classify(impostor, artifact=artifact) != "WRAPPED"


def test_a_wrapper_naming_a_different_artifact_is_unverified(cfg, home, artifact, tmp_path):
    inst.install(cfg, "github", artifact=artifact, home=home)
    entry = servers(cfg)["github"]
    other = tmp_path / "artifact" / "other.py"
    other.write_text("# a different build\n", encoding="utf-8")
    assert inst.classify(entry, artifact=other) == "UNVERIFIED"


def test_an_untouched_entry_is_direct(cfg, artifact):
    assert inst.classify(servers(cfg)["filesystem"], artifact=artifact) == "DIRECT"


def test_classify_is_content_addressed_not_path_addressed(cfg, home, artifact):
    """The artifact at the recorded path changed under us. Same path, new bytes,
    so the route is no longer verified against the build we wired."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    entry = servers(cfg)["github"]
    assert inst.classify(entry, artifact=artifact) == "WRAPPED"
    artifact.write_text("# rebuilt, different bytes\n", encoding="utf-8")
    assert inst.classify(entry, artifact=artifact) == "UNVERIFIED"


# ------------------------------------------- R4, the `-- <argv>` form

def test_install_with_argv_creates_and_wraps_a_new_entry(cfg, home, artifact):
    """R4 is spelled `install <name> -- <argv>`. With argv the name need not
    already exist; the supplied argv becomes the upstream command."""
    inst.install(cfg, "brave", artifact=artifact, home=home,
                 argv=["npx", "-y", "@modelcontextprotocol/server-brave"])
    entry = servers(cfg)["brave"]
    assert inst.classify(entry, artifact=artifact) == "WRAPPED"
    assert entry["args"][entry["args"].index("--") + 1:] == [
        "npx", "-y", "@modelcontextprotocol/server-brave"]
    rec = json.loads((home / "proxy" / "installs" / "brave.json").read_text())
    assert rec["original_entry"]["command"] == "npx"


def test_install_with_argv_leaves_existing_entries_untouched(cfg, home, artifact):
    before = servers(cfg)
    inst.install(cfg, "brave", artifact=artifact, home=home, argv=["npx"])
    after = servers(cfg)
    for k in before:
        assert after[k] == before[k]


def test_an_identical_artifact_at_a_different_path_is_not_wrapped(cfg, home, artifact, tmp_path):
    """The path check, isolated.

    Found by the mutation battery: deleting the artifact-path comparison
    survived every test, because the only test that named a different artifact
    gave it different CONTENT, so the digest check caught it and the path check
    was never exercised. Same shape as the anchored-suite row that passed with
    window merging broken. R2 says path AND hash, so this pins the path half
    with a byte-identical artifact at another location.
    """
    inst.install(cfg, "github", artifact=artifact, home=home)
    entry = servers(cfg)["github"]

    twin = tmp_path / "elsewhere" / "proxy_main.py"
    twin.parent.mkdir(parents=True)
    twin.write_bytes(artifact.read_bytes())
    assert read(twin) == read(artifact)          # identical bytes, other path

    assert inst.classify(entry, artifact=twin) == "UNVERIFIED"


# ------------------------------------- resolving the artifact to wire

def test_resolve_artifact_refuses_when_the_entry_point_is_absent(tmp_path):
    """On main there is no `sunglasses/proxy/__main__.py`, so this refuses and
    `install` is inert until the proxy lane ships it. That is the honest state,
    and it is C5 at the level of the package rather than the argument."""
    pkg = tmp_path / "sunglasses"
    (pkg / "proxy").mkdir(parents=True)
    with pytest.raises(inst.ArtifactUnresolved):
        inst.resolve_artifact(package_root=pkg)


def test_resolve_artifact_returns_the_entry_point_when_present(tmp_path):
    pkg = tmp_path / "sunglasses"
    (pkg / "proxy").mkdir(parents=True)
    main = pkg / "proxy" / "__main__.py"
    main.write_text("# entry point\n", encoding="utf-8")
    assert inst.resolve_artifact(package_root=pkg) == main


def test_resolve_artifact_on_the_real_package_matches_what_is_shipped(tmp_path):
    """Whatever the real package is, resolve_artifact agrees with the file
    system rather than with an assumption. Passes before and after the proxy
    lands, and fails if the two ever disagree."""
    import sunglasses
    pkg = pathlib.Path(sunglasses.__file__).parent
    exists = (pkg / "proxy" / "__main__.py").exists()
    if exists:
        assert inst.resolve_artifact() == pkg / "proxy" / "__main__.py"
    else:
        with pytest.raises(inst.ArtifactUnresolved):
            inst.resolve_artifact()


# ═══════════════════════════════════════════════════════════════════════════
# Round 2. Every control ASTRA's review found failing on 0c184de, landed here.
#
# These were red on round 1 and the red was reproduced before the rewrite, not
# assumed: 24 of 48 independent property controls failed, and each test below
# corresponds to one of them. Round 1's own 16 mutations all passed, which is
# the lesson: mutations chosen from the implementation ask whether the code does
# what it already does. These ask what the contract requires.
# ═══════════════════════════════════════════════════════════════════════════

def _wrapped(cfg, home, artifact, name="github"):
    inst.install(cfg, name, artifact=artifact, home=home)
    return servers(cfg)[name]


# ---------------------------------------------------- C2-REPEAT / C2-DRIFT

def test_a_second_install_refuses_instead_of_reporting_success(cfg, home, artifact):
    """C2-REPEAT. Round 1 made a matching wrapper a silent no-op and then
    printed a fresh success, so a user asking twice was told it worked twice."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    before = read(cfg)
    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "github", artifact=artifact, home=home)
    assert read(cfg) == before


def test_a_wrapper_with_a_changed_digest_is_never_wrapped_again(cfg, home, artifact):
    """C2-DRIFT. Round 1 only skipped re-wrapping when the wrapper VERIFIED, so
    rebuilding the artifact made install nest a second wrapper and overwrite the
    retained original. R4 says never wrap the wrapper, not never wrap a wrapper
    we happen to recognise."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    before = read(cfg)
    rec = json.loads((home / "proxy" / "installs" / "github.json").read_text())
    retained = read(rec["original_bytes_path"])

    artifact.write_text("# rebuilt\n", encoding="utf-8")
    # Remove the completed record so the OUTSTANDING-RECORD refusal cannot fire
    # and the any-marker check is the only gate left. Round 3 added that record
    # check and it began answering this test, which would have left the marker
    # check uncovered — the same "a different check fires first" shape as C6a.
    (home / "proxy" / "installs" / "github.json").unlink()

    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "github", artifact=artifact, home=home)
    assert read(cfg) == before
    assert read(rec["original_bytes_path"]) == retained


def test_a_byte_identical_artifact_elsewhere_is_never_wrapped_again(cfg, home, artifact, tmp_path):
    """C2-DRIFT, path form. The twin verifies on digest and differs on path."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    before = read(cfg)
    twin = tmp_path / "artifact" / "twin.py"
    twin.write_bytes(artifact.read_bytes())

    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "github", artifact=twin, home=home)
    assert read(cfg) == before


# --------------------------------------------------------------- R5-RETAINED

def test_uninstall_refuses_retained_bytes_that_do_not_match_the_record(cfg, home, artifact):
    """R5-RETAINED, the worst defect in round 1 and reachable from the public
    CLI with no proxy involved. `file_sha_before` was recorded and never read,
    so altering the retained file made uninstall copy corrupted bytes into the
    user's config and report byte-exact success."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    installed = read(cfg)
    rec = json.loads((home / "proxy" / "installs" / "github.json").read_text())
    pathlib.Path(rec["original_bytes_path"]).write_bytes(b'{"corrupted":true}')

    # ROUND 10 TRIED TO SOFTEN THIS AND MEASURED THAT IT MUST NOT. An
    # entry-only fallback for every unusable retained copy looks like the
    # no-stranded-wrapper invariant and is not: it changes R5 behaviour that
    # five of the reviewer's own rows pin, and they went red the moment it was
    # tried. A record whose retained copy is corrupt is a record about a
    # transaction we can no longer describe. The fallback exists only for a
    # record promoted from a standby whose bytes had already failed, where the
    # bytes were never that record's to begin with and refusing would strand a
    # wrapper; that case is pinned separately.
    with pytest.raises(inst.ConfigConflict):
        inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == installed


def test_uninstall_refuses_when_the_retained_bytes_are_gone(cfg, home, artifact):
    """R5-MISSING. Round 1 let this escape as an uncaught file error."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    installed = read(cfg)
    rec = json.loads((home / "proxy" / "installs" / "github.json").read_text())
    pathlib.Path(rec["original_bytes_path"]).unlink()

    with pytest.raises(inst.ConfigConflict):
        inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == installed


# ------------------------------------------------------------ R5-RECORD shapes

@pytest.mark.parametrize("corrupt", ["truncated", "missing_field", "wrong_type"])
def test_uninstall_refuses_a_record_it_cannot_read(cfg, home, artifact, corrupt):
    """R5-RECORD. Each of these crashed round 1 with an uncaught error rather
    than a typed refusal. A record we cannot read is a record whose retained
    original we cannot trust."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    installed = read(cfg)
    rec_path = home / "proxy" / "installs" / "github.json"
    rec = json.loads(rec_path.read_text())

    if corrupt == "truncated":
        rec_path.write_bytes(rec_path.read_bytes()[:11])
    elif corrupt == "missing_field":
        del rec["original_bytes_path"]
        rec_path.write_text(json.dumps(rec))
    else:
        rec_path.write_text(json.dumps(list(rec)))

    with pytest.raises(inst.ConfigConflict):
        inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == installed


# ------------------------------------------------------- R4/R5-COLLISION

def test_the_same_name_in_a_second_config_does_not_steal_the_first_record(cfg, home, artifact, tmp_path):
    """R4/R5-COLLISION. The record was keyed by name alone, so installing the
    same name into a second config overwrote the first record and its retained
    bytes, and uninstalling the FIRST file then restored the SECOND file's
    original. A record belongs to a target, not to a name."""
    original = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)

    second = tmp_path / "second.json"
    second.write_bytes(RAW_CONFIG.encode("utf-8") + b" \n")
    with pytest.raises(inst.ConfigConflict):
        inst.install(second, "github", artifact=artifact, home=home)

    res = inst.uninstall(cfg, "github", home=home)
    assert res.byte_exact is True
    assert read(cfg) == original


# ------------------------------------------------------------- R5-INVERSE

def test_uninstall_removes_an_entry_that_install_created(cfg, home, artifact):
    """R5-INVERSE. When install created a previously absent server, round 1's
    entry-only inverse put the ORIGINAL entry back, leaving behind a direct
    entry that had never existed. The inverse of creating is removing."""
    inst.install(cfg, "added", artifact=artifact, home=home, argv=["new-command"])
    d = json.loads(read(cfg).decode("utf-8"))
    d["later"] = 123                      # an unrelated edit, so not byte-exact
    cfg.write_text(json.dumps(d, indent=2), encoding="utf-8")
    expected = json.loads(read(cfg).decode("utf-8"))
    del expected["mcpServers"]["added"]

    res = inst.uninstall(cfg, "added", home=home)

    assert res.byte_exact is False
    assert json.loads(read(cfg).decode("utf-8")) == expected


# ------------------------------------------------------- R4-SHAPE / R4-DUPKEY

@pytest.mark.parametrize("payload", [
    b'[]',
    b'null',
    b'{"mcpServers":{"github":null}}',
    b'{"mcpServers":{"github":{"args":1}}}',
    # A VALID command with bad args. Without this the args check is never
    # exercised: every other payload fails the command check first, so deleting
    # the args validation survived the battery. Same shape as round 1's C6a.
    b'{"mcpServers":{"github":{"command":"npx","args":1}}}',
    b'{"mcpServers":{"github":{"command":"npx","args":["ok",7]}}}',
])
def test_install_refuses_an_invalid_shape_without_mutating(tmp_path, home, artifact, payload):
    """R4-SHAPE. Valid JSON, invalid document or entry. Round 1 raised uncaught
    errors on all four and the CLI exited 1 instead of refusing."""
    p = tmp_path / ".mcp.json"
    p.write_bytes(payload)
    with pytest.raises(inst.ConfigIOError):
        inst.install(p, "github", artifact=artifact, home=home)
    assert read(p) == payload


def test_install_refuses_duplicate_json_keys_rather_than_dropping_data(tmp_path, home, artifact):
    """R4-DUPKEY. `json.loads` resolves a duplicate key silently by keeping the
    last one, so round 1 rewrote the file and deleted an entry the user can
    still see in their own config. Ambiguous input is refused."""
    p = tmp_path / ".mcp.json"
    p.write_bytes(b'{"mcpServers":{"github":{"command":"x"},'
                  b'"keep":{"command":"first"},"keep":{"command":"second"}}}')
    before = read(p)
    with pytest.raises(inst.ConfigIOError):
        inst.install(p, "github", artifact=artifact, home=home)
    assert read(p) == before


# ----------------------------------------------------------------- C6-ROUTE

@pytest.mark.parametrize("change", ["command", "argv", "removed_artifact"])
def test_wrapped_requires_the_entry_to_actually_launch_the_artifact(cfg, home, artifact, change):
    """C6-ROUTE. Round 1 checked the marker's path and digest and never checked
    that the entry executes them, so a correct marker beside any command at all
    still classified WRAPPED. Both comparisons existed; neither was tied to what
    would run."""
    entry = _wrapped(cfg, home, artifact)
    if change == "command":
        entry["command"] = "/bin/echo"
    elif change == "argv":
        entry["args"] = [str(artifact.with_name("different.py")), "--", "run"]
    else:
        entry["args"] = []
    assert inst.classify(entry, artifact=artifact) == "UNVERIFIED"


# --------------------------------------------------------------- R4-OPTIONS

def test_wrapping_preserves_the_entrys_execution_options(cfg, home, artifact):
    """R4-OPTIONS. Round 1 rebuilt the entry from command and args alone, so a
    server's env and cwd were silently dropped and it would have started in the
    wrong directory without its variables."""
    d = json.loads(read(cfg).decode("utf-8"))
    d["mcpServers"]["github"]["env"] = {"TOKEN_NAME": "fixture"}
    d["mcpServers"]["github"]["cwd"] = str(cfg.parent)
    cfg.write_text(json.dumps(d, indent=2), encoding="utf-8")
    before = servers(cfg)["github"]

    inst.install(cfg, "github", artifact=artifact, home=home)

    after = servers(cfg)["github"]
    assert after.get("env") == before["env"]
    assert after.get("cwd") == before["cwd"]


# ------------------------------------------------------------------ C4-IO

@pytest.mark.parametrize("target_name", ["stat", "mkstemp"])
def test_every_transaction_io_fault_is_one_typed_refusal(cfg, home, artifact, monkeypatch, target_name):
    """C4-IO. Round 1 normalised faults inside `_atomic_write`'s write phase and
    let the stat and the mkstemp escape, so the CLI exited 1 on a catchable
    operational error."""
    before = read(cfg)

    def boom(*a, **kw):
        raise OSError("injected")

    if target_name == "stat":
        real = pathlib.Path.stat
        monkeypatch.setattr(pathlib.Path, "stat",
                            lambda p, *a, **k: boom() if p.name == ".mcp.json"
                            else real(p, *a, **k))
    else:
        monkeypatch.setattr(inst.tempfile, "mkstemp", boom)

    with pytest.raises(inst.ConfigIOError):
        inst.install(cfg, "github", artifact=artifact, home=home)
    assert read(cfg) == before


def test_a_failed_record_write_restores_the_target(cfg, home, artifact, monkeypatch):
    """C4-RECORD. Round 1 replaced the target and THEN wrote the record, so a
    failure there left a wrapped config with no record, and the follow-up
    uninstall refused because no record existed. Replace and record are one
    recoverable transaction."""
    before = read(cfg)
    real = pathlib.Path.write_text

    def write_text(p, *a, **kw):
        if p.name == "github.json":
            raise OSError("injected")
        return real(p, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "write_text", write_text)

    with pytest.raises(inst.ConfigIOError):
        inst.install(cfg, "github", artifact=artifact, home=home)

    assert read(cfg) == before
    assert not (home / "proxy" / "installs" / "github.json").exists()


def test_install_refuses_an_unreadable_config(tmp_path, home, artifact):
    """Config-read handling, at module level with a resolvable artifact.

    The CLI cannot reach the parser while the real artifact is absent, so this
    is where the read boundary is proven rather than in a CLI test that stops
    one step earlier.
    """
    missing = tmp_path / "nowhere" / ".mcp.json"
    with pytest.raises(inst.ConfigIOError):
        inst.install(missing, "github", artifact=artifact, home=home)


def test_install_refuses_a_config_that_is_not_utf8(tmp_path, home, artifact):
    p = tmp_path / ".mcp.json"
    p.write_bytes(b'\xff\xfe{"mcpServers":{}}')
    before = read(p)
    with pytest.raises(inst.ConfigIOError):
        inst.install(p, "github", artifact=artifact, home=home)
    assert read(p) == before


def test_a_marker_naming_a_different_artifact_than_it_launches_is_unverified(cfg, home, artifact, tmp_path):
    """The marker's artifact path, isolated.

    Found by the battery: deleting the marker path comparison survived, because
    the argv binding already catches a wrapper pointing at another artifact. The
    one case it does not catch is an entry whose argv launches THIS artifact
    while its marker claims a different one, which is exactly a wrapper telling
    us something other than what it runs. Pinned so the comparison cannot be
    dropped as redundant.
    """
    inst.install(cfg, "github", artifact=artifact, home=home)
    entry = servers(cfg)["github"]
    assert inst.classify(entry, artifact=artifact) == "WRAPPED"

    elsewhere = tmp_path / "artifact" / "claimed.py"
    elsewhere.write_bytes(artifact.read_bytes())
    entry[inst.MARKER]["artifact"] = str(elsewhere.resolve())

    assert inst.classify(entry, artifact=artifact) == "UNVERIFIED"


# ═══════════════════════════════════════════════════════════════════════════
# Round 3. The ten controls ASTRA's review of 6be355d found failing.
#
# Round 2 passed all 48 of round 1's controls and its own 28-row battery, and
# still failed ten NEW ones. Same lesson one level up: a battery generated from
# the corrections you already made cannot find the corrections you did not.
# These are red against 6be355d, verified before the fix, and the rule they
# share is R-177-R3's: the pending record is a recovery JOURNAL that install and
# uninstall both consume — recover or refuse, never strand.
# ═══════════════════════════════════════════════════════════════════════════

def _paths(home, name="github"):
    d = home / "proxy" / "installs"
    return d / f"{name}.json", d / f"{name}.pending", d / f"{name}.original"


# ─────────────────────────────────────────────── C6-COMMAND-BINDING

def test_a_marker_cannot_vouch_for_a_command_that_runs_nothing(cfg, home, artifact):
    """C6-COMMAND-BINDING, the worst of the ten.

    Setting BOTH the entry's command and the marker's command to `/usr/bin/true`
    made them agree, and round 2 only checked that they agreed. `/usr/bin/true`
    exits 0 and runs nothing, so a route that could never mediate anything
    classified WRAPPED. The marker is untrusted data in a file anything can
    edit; it cannot be its own witness.
    """
    inst.install(cfg, "github", artifact=artifact, home=home)
    entry = servers(cfg)["github"]
    assert inst.classify(entry, artifact=artifact) == "WRAPPED"

    entry["command"] = "/usr/bin/true"
    entry[inst.MARKER]["command"] = "/usr/bin/true"
    assert inst.classify(entry, artifact=artifact) == "UNVERIFIED"


# ──────────────────────────────────── R4-IDENTITY-BEFORE-DIGEST

def test_install_refuses_while_a_completed_record_is_outstanding(cfg, home, artifact):
    """R4-IDENTITY-BEFORE-DIGEST. The config was edited back to unwrapped and
    installed again: same path, different identity. Round 2 overwrote the record
    and the retained bytes, destroying the only route back to what the first
    install had captured."""
    original = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, _, bytes_path = _paths(home)
    retained_before = read(bytes_path)

    d = json.loads(original.decode("utf-8"))      # the PRE-wrap document
    d["review_changed"] = True
    cfg.write_text(json.dumps(d), encoding="utf-8")
    changed = read(cfg)

    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "github", artifact=artifact, home=home)
    assert read(cfg) == changed
    assert read(bytes_path) == retained_before
    assert read(rec_path) == read(rec_path)


# ──────────────────────────────────────── the journal, both directions

def test_uninstall_recovers_a_transaction_that_crashed_after_the_replace(cfg, home, artifact):
    """C4-REPLACE-CRASH-RECOVERY. The replace committed and the process died
    before the record completed. Round 2 said "no recorded install" and left the
    user's config wrapped with nothing claiming to own it."""
    before = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, pending_path, bytes_path = _paths(home)
    # the state a crash between replace and completion leaves behind
    rec = json.loads(read(rec_path).decode("utf-8"))
    rec["state"] = "pending"
    pending_path.write_text(json.dumps(rec), encoding="utf-8")
    rec_path.unlink()

    res = inst.uninstall(cfg, "github", home=home)

    assert res.byte_exact is True
    assert read(cfg) == before
    assert not pending_path.exists()


def test_install_resumes_a_transaction_that_crashed_before_the_replace(cfg, home, artifact):
    """C4-PENDING-CRASH-RECOVERY. The journal exists and the target is still
    byte-for-byte what it captured, so completing is safe.

    A REGRESSION PIN, not a correction: this passed on 6be355d too, because a
    round-2 install ignored the journal and simply installed fresh, which
    happens to be the right outcome when the target was never replaced. It is
    here so the journal handling added for the after-replace case cannot break
    the before-replace case.
    """
    before = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, pending_path, bytes_path = _paths(home)
    rec = json.loads(read(rec_path).decode("utf-8"))
    rec["state"] = "pending"
    pending_path.write_text(json.dumps(rec), encoding="utf-8")
    rec_path.unlink()
    cfg.write_bytes(before)                       # pre-replace: target untouched

    inst.install(cfg, "github", artifact=artifact, home=home)

    assert inst.classify(servers(cfg)["github"], artifact=artifact) == "WRAPPED"
    assert not pending_path.exists()
    assert rec_path.exists()


def test_install_refuses_a_journal_that_captured_a_different_version(cfg, home, artifact):
    """Recover or refuse, never guess. If the target is neither the journal's
    original nor its installed form, we cannot tell what is on disk."""
    before = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, pending_path, _ = _paths(home)
    rec = json.loads(read(rec_path).decode("utf-8"))
    rec["state"] = "pending"
    rec["file_sha_before"] = "0" * 64
    pending_path.write_text(json.dumps(rec), encoding="utf-8")
    rec_path.unlink()
    # Unwrapped, so the already-wrapped refusal CANNOT fire and the journal
    # comparison is the only thing left that can refuse. Round 2 passed this
    # test through the marker check while ignoring the journal entirely.
    cfg.write_bytes(before)
    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "github", artifact=artifact, home=home)


# ──────────────────────────────── C4-PENDING-PARTIAL / ROLLBACK-DURABILITY

def test_a_half_written_journal_is_removed_not_left_behind(cfg, home, artifact, monkeypatch):
    """C4-PENDING-PARTIAL. A half-written journal is worse than none: it is
    unparseable recovery material the next run has to refuse."""
    before = read(cfg)
    real = pathlib.Path.write_text

    def write_text(p, text, *a, **kw):
        if p.name == "github.pending":
            real(p, text[: len(text) // 2], *a, **kw)
            raise OSError("injected")
        return real(p, text, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "write_text", write_text)
    with pytest.raises(inst.ConfigIOError):
        inst.install(cfg, "github", artifact=artifact, home=home)

    rec_path, pending_path, bytes_path = _paths(home)
    assert read(cfg) == before
    assert not pending_path.exists()
    assert not rec_path.exists()
    assert not bytes_path.exists()


def test_a_failed_rollback_keeps_the_only_way_back(cfg, home, artifact, monkeypatch):
    """C4-ROLLBACK-DURABILITY. The completion failed AND the rollback failed, so
    the target is still wrapped and the retained bytes are the only route to the
    user's original. Round 2 deleted them, stranding it permanently."""
    before = read(cfg)
    real_write, real_replace = pathlib.Path.write_text, inst.os.replace
    calls = {"n": 0}

    def write_text(p, *a, **kw):
        if p.name == "github.json":
            raise OSError("injected")
        return real_write(p, *a, **kw)

    def replace(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:                       # the rollback
            raise OSError("injected")
        return real_replace(src, dst)

    monkeypatch.setattr(pathlib.Path, "write_text", write_text)
    monkeypatch.setattr(inst.os, "replace", replace)
    with pytest.raises(inst.ConfigIOError):
        inst.install(cfg, "github", artifact=artifact, home=home)
    monkeypatch.undo()

    rec_path, pending_path, bytes_path = _paths(home)
    assert read(cfg) != before                    # still wrapped, honestly
    assert bytes_path.is_file() and read(bytes_path) == before
    assert pending_path.is_file()


# ─────────────────────────────────────── the record, validated like a config

@pytest.mark.parametrize("corrupt,why", [
    ("path_type", "R5-RECORD-PATH-TYPE: original_bytes_path is null"),
    ("no_target", "R5-RECORD-TARGET-REQUIRED: no target_path at all"),
    ("wrong_state", "R5-RECORD-STATE: a completed record marked pending"),
    ("dup_key", "R5-RECORD-DUPKEY: duplicate key in the record itself"),
])
def test_uninstall_validates_a_record_as_strictly_as_a_config(cfg, home, artifact, corrupt, why):
    """A record is a file anything can edit, and it tells us which bytes to
    write into the user's configuration. Reading it with a laxer parser than the
    config was read with is how a document we refused comes back in through the
    recovery path."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    installed = read(cfg)
    rec_path, _, _ = _paths(home)
    rec = json.loads(read(rec_path).decode("utf-8"))

    if corrupt == "path_type":
        rec["original_bytes_path"] = None
        rec_path.write_text(json.dumps(rec))
    elif corrupt == "no_target":
        del rec["target_path"]
        rec_path.write_text(json.dumps(rec))
    elif corrupt == "wrong_state":
        rec["state"] = "pending"
        rec_path.write_text(json.dumps(rec))
    else:
        raw = json.dumps(rec)
        rec_path.write_text(raw[:-1] + ',"file_sha_before":'
                            + json.dumps(rec["file_sha_before"]) + "}")

    with pytest.raises(inst.ConfigConflict):
        inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == installed


# ──────────────────────────────────────────── R4-JSON grammar

def test_install_refuses_a_config_with_nan(tmp_path, home, artifact):
    """R4-JSON-NONFINITE. `NaN` is Python's extension, not JSON. `json.loads`
    accepts it by default, so round 2 parsed it and would have round-tripped a
    file no other JSON reader can use."""
    p = tmp_path / ".mcp.json"
    p.write_text('{"mcpServers":{"github":{"command":"npx"}},"extra":NaN}',
                 encoding="utf-8")
    before = read(p)
    with pytest.raises(inst.ConfigIOError):
        inst.install(p, "github", artifact=artifact, home=home)
    assert read(p) == before


def test_install_refuses_a_config_nested_past_the_parser(tmp_path, home, artifact):
    """R4-JSON-DEPTH. A RecursionError is an operational refusal, not a crash."""
    p = tmp_path / ".mcp.json"
    p.write_bytes(b"[" * 1100 + b"0" + b"]" * 1100)
    with pytest.raises(inst.ConfigIOError):
        inst.install(p, "github", artifact=artifact, home=home)


# ═══════════════════════════════════════════════════════════════════════════
# Round 4. T8's second-reader findings on 8b16d96, each proven red on that head
# before the repair (F1-UNINSTALL, F1-JOURNAL, F1-SYMLINK, F2-SHIM).
#
# F1 is one defect reachable through two callers, so there is a control per
# caller rather than one control and an assumption. The digest check that was
# already there vouches for the BYTES; a record supplies both the path and the
# digest, so it was proving itself.
# ═══════════════════════════════════════════════════════════════════════════


def _decoy_with(tmp_path, raw: bytes):
    """A file OUTSIDE the record directory whose bytes an attacker knows."""
    d = tmp_path / "elsewhere" / "keepme.txt"
    d.parent.mkdir(parents=True, exist_ok=True)
    d.write_bytes(raw)
    return d


def test_uninstall_refuses_a_record_whose_retained_path_is_not_the_canonical_one(
        cfg, home, artifact, tmp_path):
    """F1-UNINSTALL. The record named an unrelated file, the digest agreed
    because the record supplied that too, and uninstall wrote the decoy's bytes
    into the user's config and then deleted the decoy, byte_exact=True."""
    before = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, _, canonical = _paths(home)

    decoy = _decoy_with(tmp_path, before)          # same bytes, so the digest passes
    rec = json.loads(read(rec_path).decode("utf-8"))
    rec["original_bytes_path"] = str(decoy)
    rec_path.write_text(json.dumps(rec), encoding="utf-8")

    with pytest.raises(inst.ConfigConflict) as e:
        inst.uninstall(cfg, "github", home=home)

    assert str(canonical) in str(e.value), e.value
    assert decoy.exists(), "the decoy outside the record directory was deleted"
    assert read(decoy) == before
    assert read(cfg) != before, "the wrapped config was restored from a file we do not own"


def test_journal_recovery_refuses_a_retained_path_outside_the_record_directory(
        cfg, home, artifact, tmp_path):
    """F1-JOURNAL. The same defect down the crash-recovery path, which is why
    the check belongs in `_retained_of` and not in `uninstall`. A repair applied
    only at the `uninstall` call site leaves this control red."""
    before = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, pending_path, canonical = _paths(home)

    decoy = _decoy_with(tmp_path, before)
    rec = json.loads(read(rec_path).decode("utf-8"))
    rec["state"] = "pending"
    rec["original_bytes_path"] = str(decoy)
    pending_path.write_text(json.dumps(rec), encoding="utf-8")
    rec_path.unlink()                               # the shape a crash leaves

    with pytest.raises(inst.ConfigConflict) as e:
        inst.uninstall(cfg, "github", home=home)

    assert str(canonical) in str(e.value), e.value
    assert decoy.exists(), "journal recovery deleted a file outside its own directory"
    assert pending_path.exists(), "the journal was consumed by a refused recovery"


def test_uninstall_refuses_when_the_canonical_retained_path_is_a_symlink(
        cfg, home, artifact, tmp_path):
    """F1-SYMLINK. The path now matches the canonical name, so the name check
    passes and this is what stops it. `resolve()`ing both sides would have made
    the two agree on the attacker's target, which is why the name comparison is
    lexical and this control exists separately."""
    before = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    _, _, canonical = _paths(home)

    decoy = _decoy_with(tmp_path, before)
    canonical.unlink()
    canonical.symlink_to(decoy)                     # right name, wrong file

    with pytest.raises(inst.ConfigConflict) as e:
        inst.uninstall(cfg, "github", home=home)

    assert "symlink" in str(e.value), e.value
    assert decoy.exists(), "restoring through a symlink deleted the target"


def test_a_command_that_merely_names_a_python_is_unverified_not_wrapped(
        cfg, home, artifact, tmp_path):
    """F2-SHIM. Round 3 asked whether the basename started with "python", which
    is a resemblance. A shim by that name that exits 0 and runs nothing was
    WRAPPED, so a route was reported protected while the artifact never ran.

    UNVERIFIED is the right answer and not DIRECT: the marker IS present, we
    simply cannot vouch for what executes."""
    shim = tmp_path / "bin" / "python-shim"
    shim.parent.mkdir(parents=True, exist_ok=True)
    shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shim.chmod(0o755)

    resolved = str(pathlib.Path(artifact).resolve())
    entry = {
        "command": str(shim),
        "args": [resolved, "--", "npx", "-y", "@modelcontextprotocol/server-github"],
        inst.MARKER: {"artifact": resolved,
                      "sha256": inst._digest_file(artifact),
                      "command": str(shim)},
    }

    assert inst.classify(entry, artifact=artifact) == "UNVERIFIED"


def test_every_mutation_anchor_is_still_present_in_install_py():
    """The instrument, not the product. A mutation whose anchor text has
    drifted does not fail loudly, it fails to APPLY, and the harness then
    reports a kill count for mutants that were never introduced. Round 4 moved
    the `_recover_from_journal` call and its JOURNAL-RECOVER anchor went stale
    in the same edit, which is exactly how the count would have lied."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_mutate_install", pathlib.Path(__file__).resolve().parent / "mutate_install.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    source = pathlib.Path(inst.__file__).read_text(encoding="utf-8")
    counts = {row[0]: source.count(row[2]) for row in mod.MUTATIONS}
    missing = sorted(k for k, v in counts.items() if v == 0)
    # UNIQUENESS, not presence. Round 5 is why this assertion changed: the F1
    # never-strand repair created a SECOND identical `if pending_path.exists()`
    # call site, so JOURNAL-RECOVER's anchor matched twice, the harness could
    # not place the mutant unambiguously and reported it as a SURVIVOR. The
    # presence-only version of this test passed while that was true, which
    # makes presence the weaker claim and this the honest one.
    duplicated = sorted(k for k, v in counts.items() if v > 1)
    assert not missing, f"mutation anchors no longer in install.py: {missing}"
    assert not duplicated, (
        f"mutation anchors that match more than once, so the mutant cannot be "
        f"placed: {duplicated}")


# ═══════════════════════════════════════════════════════════════════════════
# Round 5. ASTRA's four round-4 families, each reproduced here so the
# protection lives in the repo and not only in a reviewer's temp directory.
# Every one of these was RED on da5f6eb; the reviewer's own controls were the
# source, not my reading of my own diff.
# ═══════════════════════════════════════════════════════════════════════════


def _journal_from_record(home, name="github"):
    """The shape a crash between replace and completion leaves: a pending
    journal, no completed record."""
    rec_path, pending_path, _ = _paths(home, name)
    rec = json.loads(read(rec_path).decode("utf-8"))
    rec["state"] = "pending"
    pending_path.write_text(json.dumps(rec), encoding="utf-8")
    rec_path.unlink()
    return pending_path


def test_uninstall_recovers_from_the_journal_when_the_completed_record_is_unreadable(
        cfg, home, artifact):
    """R4-COMPLETE-PARTIAL. A SIGKILL halfway through writing the completed
    record left a file whose NAME claimed authority and whose CONTENT could not
    be parsed. Uninstall refused with exit 2 and never looked at the valid
    journal sitting beside it: a stranded transaction with its own recovery
    material present on disk. The filename no longer outranks the journal."""
    original = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, pending_path, _ = _paths(home)
    complete = read(rec_path)
    rec = json.loads(complete.decode("utf-8"))
    rec["state"] = "pending"
    pending_path.write_text(json.dumps(rec), encoding="utf-8")
    rec_path.write_bytes(complete[:len(complete) // 2])   # the half-written half

    res = inst.uninstall(cfg, "github", home=home)

    assert res.byte_exact is True
    assert read(cfg) == original, "the valid journal was stranded"
    assert not pending_path.exists(), "recovery left the journal open"


def test_journal_recovery_refuses_a_target_edited_since_the_crash(
        cfg, home, artifact):
    """R5-JOURNAL-CONFLICT. Recovery checked the journal's target path and its
    retained digest, both of which describe the JOURNAL, and then copied the
    whole retained original over whatever was on disk. An edit made after the
    interrupted install was erased with exit 0. A pending journal does not
    waive R5."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    pending_path = _journal_from_record(home)

    doc = json.loads(read(cfg).decode("utf-8"))
    doc["an_unrelated_setting"] = {"keep": "this"}
    cfg.write_text(json.dumps(doc), encoding="utf-8")
    edited = read(cfg)

    with pytest.raises(inst.ConfigConflict) as e:
        inst.uninstall(cfg, "github", home=home)

    assert "edited" in str(e.value), e.value
    assert read(cfg) == edited, "a refused recovery still overwrote the edit"
    assert pending_path.exists(), (
        "the refusal consumed the journal, which makes the refusal permanent")


def test_journal_recovery_still_restores_the_state_we_actually_left(
        cfg, home, artifact):
    """The other side of the same guard, so the refusal is not a blanket one:
    when the target IS the wrapper we wrote, recovery proceeds."""
    original = read(cfg)
    inst.install(cfg, "github", artifact=artifact, home=home)
    pending_path = _journal_from_record(home)

    res = inst.uninstall(cfg, "github", home=home)

    assert res.byte_exact is True
    assert read(cfg) == original
    assert not pending_path.exists()


def test_install_refuses_when_a_symlink_occupies_a_record_name(
        cfg, home, artifact, tmp_path):
    """F1-JOURNAL-RETRY-SYMLINK. `_retained_of` guarded both uninstall paths
    and the install RETRY path never called it, then wrote through
    `write_bytes`, which follows a symlink planted at the canonical retained
    name and overwrote an unrelated file with exit 0. Guarding the READERS of a
    resource is not guarding the resource.

    Refused before any mutation, so the unrelated file AND the recovery state
    both survive."""
    decoy = tmp_path / "elsewhere" / "must-survive.txt"
    decoy.parent.mkdir(parents=True, exist_ok=True)
    decoy.write_bytes(b"unrelated bytes that must survive")
    before = read(cfg)

    d = home / "proxy" / "installs"
    d.mkdir(parents=True, exist_ok=True)
    (d / "github.original").symlink_to(decoy)

    with pytest.raises(inst.ConfigConflict) as e:
        inst.install(cfg, "github", artifact=artifact, home=home)

    assert "symlink" in str(e.value), e.value
    assert read(decoy) == b"unrelated bytes that must survive"
    assert read(cfg) == before, "a refused install still touched the config"


def test_uninstall_refuses_a_complete_record_whose_after_digest_is_not_a_digest(
        cfg, home, artifact):
    """R5-AFTER-NULL / R5-AFTER-LIST. Presence of `file_sha_after` was checked
    and its TYPE was not, so a record carrying null or [] was accepted and the
    restore proceeded through the inverse."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, _, _ = _paths(home)
    for bad in (None, []):
        rec = json.loads(read(rec_path).decode("utf-8"))
        rec["file_sha_after"] = bad
        rec_path.write_text(json.dumps(rec), encoding="utf-8")
        before = read(cfg)
        with pytest.raises(inst.ConfigConflict):
            inst.uninstall(cfg, "github", home=home)
        assert read(cfg) == before
        assert rec_path.exists(), "a refused uninstall consumed the record"


def test_uninstall_refuses_a_record_whose_entry_existed_is_not_a_bool(
        cfg, home, artifact):
    """R5-EXISTED-LIST. `entry_existed` decides between putting an entry BACK
    and DELETING it. A list is falsey, so an entry that existed before the
    install was deleted on uninstall with exit 0."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, _, _ = _paths(home)
    rec = json.loads(read(rec_path).decode("utf-8"))
    rec["entry_existed"] = []
    rec_path.write_text(json.dumps(rec), encoding="utf-8")
    # The edit that made the old behaviour visible: the file has moved on, so
    # uninstall takes the entry-inverse path rather than the byte-exact one.
    doc = json.loads(read(cfg).decode("utf-8"))
    doc["later"] = "preserve"
    cfg.write_text(json.dumps(doc), encoding="utf-8")
    before = read(cfg)

    with pytest.raises(inst.ConfigConflict):
        inst.uninstall(cfg, "github", home=home)

    assert read(cfg) == before
    assert "github" in servers(cfg), "an entry that existed before install was deleted"


# ═══════════════════════════════════════════════════════════════════════════
# Round 6. ASTRA's two deterministic recovery RACES. Both were pre-existing on
# da5f6eb, neither was a regression of round 5, and both are closed at the
# moment of the mutation rather than before it -- because a caller's view of
# the directory is already stale by the time the unlink or the rename happens.
# The controls below pin the two mechanisms directly, without a subprocess, so
# they fail for one reason each.
# ═══════════════════════════════════════════════════════════════════════════


def test_discard_never_removes_a_retained_original_a_record_still_claims(
        cfg, home, artifact):
    """R5-RECOVERY-RETRY-RACE. A recovery paused inside its own cleanup, a
    second install of the same name completed, and the cleanup then deleted
    THAT install's retained original by path and reported success. The target
    was left wrapped by an install whose only way back we had just removed."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, pending_path, retained = _paths(home)
    pending_path.write_text(read(rec_path).decode("utf-8"), encoding="utf-8")
    claimed = read(retained)

    # What the racing recovery's cleanup call looks like: its own journal plus
    # the retained bytes, with a completed record now sitting beside them.
    inst._discard(pending_path, retained)

    assert retained.is_file(), "the cleanup removed bytes a record still claims"
    assert read(retained) == claimed
    assert not pending_path.exists(), "the cleanup left its own journal behind"


def test_discard_does_remove_the_retained_original_once_nothing_claims_it(
        cfg, home, artifact):
    """The other side, so the guard is not a blanket refusal: a caller
    discarding its OWN complete transaction still cleans up, because records
    are removed before retained bytes in the same call."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, pending_path, retained = _paths(home)

    inst._discard(rec_path, pending_path, retained)

    assert not rec_path.exists() and not retained.exists()


def test_a_declared_write_refuses_when_the_target_changed_underneath(tmp_path):
    """R5-RECOVERY-OTHER-RACE. A recovery validated that the target was the
    wrapper it wrote, paused, and a second install added ANOTHER server to the
    same file and succeeded. The recovery resumed and wrote its stale whole-file
    original over it. The comparison is at the rename now, which is the last
    instant that can still refuse for free."""
    target = tmp_path / ".mcp.json"
    target.write_bytes(b'{"mcpServers": {}}')
    expected = inst._digest_bytes(read(target))

    target.write_bytes(b'{"mcpServers": {"z": {"command": "npx"}}}')  # the racer
    after_race = read(target)

    with pytest.raises(inst.ConfigConflict) as e:
        with inst._expect_unchanged(target, expected):
            inst._atomic_write(target, b'{"mcpServers": {}}')

    assert "changed while this transaction was in flight" in str(e.value)
    assert read(target) == after_race, "a refused write still overwrote the racer"
    assert not list(tmp_path.glob(".sg-*")), "the refused write leaked a temp file"


def test_a_declared_write_proceeds_when_the_target_is_what_we_expected(tmp_path):
    """And the positive side, so the compare is a compare and not a veto."""
    target = tmp_path / ".mcp.json"
    target.write_bytes(b'{"mcpServers": {}}')
    with inst._expect_unchanged(target, inst._digest_bytes(read(target))):
        inst._atomic_write(target, b'{"mcpServers": {"a": 1}}')
    assert read(target) == b'{"mcpServers": {"a": 1}}'


def test_the_expectation_does_not_outlive_its_scope(tmp_path):
    """A dynamically scoped expectation that leaked would silently turn every
    later write in the process into a compare against a stale digest."""
    target = tmp_path / ".mcp.json"
    target.write_bytes(b"one")
    with inst._expect_unchanged(target, inst._digest_bytes(b"one")):
        pass
    target.write_bytes(b"two")
    inst._atomic_write(target, b"three")          # no expectation in force
    assert read(target) == b"three"


# ═══════════════════════════════════════════════════════════════════════════
# Round 7. ASTRA's four round-6 interleavings. Two of his rows go green here
# exactly as written; the other two cannot, and the reason is measured rather
# than asserted: both put a racing install INSIDE our critical section and
# require it to SUCCEED there, so any mutual exclusion is a circular wait
# (pids in the PR body) and any ownership taken by rename stops firing the
# `Path.unlink` his barrier is keyed on. The stimulus survives in the two rows
# below; only the racer's shape changes.
# ═══════════════════════════════════════════════════════════════════════════


def test_discard_takes_the_retained_bytes_before_it_asks_about_them(
        cfg, home, artifact, monkeypatch):
    """R7-OWNER-CHECK-UNLINK. Round 6 asked whether a record claimed the
    retained original and then unlinked it, and a second install completed
    between the two: it published its own retained original at that very name
    and the unlink removed THAT one, leaving a wrapped config whose only way
    back had just been deleted by somebody else's cleanup.

    Moving the question closer to the unlink cannot fix it, because a question
    and an unlink are two operations on a NAME. Taking the bytes first makes
    the second operation act on an inode we already hold."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, pending_path, retained = _paths(home)
    pending_path.write_text(read(rec_path).decode("utf-8"), encoding="utf-8")
    rec_path.unlink()

    competitor = b'{"the second install": "its own retained original"}'
    # Captured NOW: the journal this cleanup is about to delete cannot be read
    # from inside the patch below, and a FileNotFoundError raised in there is
    # swallowed by the cleanup's own `except OSError` -- which is how the first
    # version of this row reported the defect it was not actually reaching.
    record_text = read(pending_path).decode("utf-8")
    real_unlink = pathlib.Path.unlink
    raced = []

    def unlink(self, *a, **kw):
        # Keyed on the removal of the RETAINED BYTES, under whatever name they
        # are held at that moment -- `github.original` on a build that unlinks
        # the canonical name, `github.original.discarding-*` on one that takes
        # them first. Keyed on the canonical name alone this row fires on the
        # journal's unlink instead, the guard sees a record that this very
        # patch has just written, and it passes on the defect. It did, once.
        if not raced and self.name.startswith(retained.name):
            # A second install of the same name completes right here: the
            # instant after anyone could have looked, and before the removal.
            raced.append(True)
            rec_path.write_text(record_text, encoding="utf-8")
            retained.write_bytes(competitor)
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "unlink", unlink)
    inst._discard(pending_path, retained)

    assert raced, "the removal boundary was never reached"
    assert retained.is_file(), (
        "the second install's retained original was deleted by our cleanup")
    assert read(retained) == competitor, (
        "the second install's retained original was replaced by ours")


def test_a_declared_write_refuses_bytes_that_are_the_same_file_no_longer(
        tmp_path):
    """R7-ABA. The round-6 comparison was a digest, and a digest cannot see
    A -> B -> A: a second install uninstalled and installed again, re-rendered
    byte-for-byte what the crashed transaction had written, and the stale
    recovery's compare-and-swap found exactly what it expected and overwrote a
    completed install. Every publication here is a rename, so the inode moves
    even when the bytes do not, and identity is what the expectation carries."""
    target = tmp_path / ".mcp.json"
    target.write_bytes(b"one")
    current, identity = inst._read_bytes_and_identity(target)

    # The A -> B -> A a second transaction leaves behind: same bytes, new file.
    replacement = tmp_path / "second"
    replacement.write_bytes(b"one")
    os.replace(replacement, target)

    assert read(target) == current, "the fixture must not change the BYTES"
    assert inst._identity(target) != identity, "the fixture must move the file"

    with pytest.raises(inst.ConfigConflict) as e:
        with inst._expect_unchanged(target, inst._digest_bytes(current),
                                    identity):
            inst._atomic_write(target, b"the stale recovery's whole file")
    assert "no longer the same file" in str(e.value)
    assert read(target) == b"one", "the refusal still wrote"


def test_an_install_cancelled_while_it_writes_does_not_report_success(
        cfg, home, artifact, monkeypatch):
    """R7-CANCELLED-IN-FLIGHT. A concurrent uninstall found our PENDING journal
    while we were inside the replace, could not tell an interrupted transaction
    from a live one, and discarded our journal and our retained bytes. We then
    published the wrapper and wrote a completed record pointing at retained
    bytes that no longer existed: an install that looked successful and had no
    inverse. The transaction that cannot see the other one is the one that has
    to check, so ownership of our own material is re-checked at the commit."""
    original = read(cfg)
    real_write = inst._atomic_write

    def cancelled(target, data):
        # The racing uninstall, at the only instant that matters.
        _, _, pending_path, retained = inst._record_paths(home, "github")
        for q in (pending_path, retained):
            if q.exists():
                q.unlink()
        return real_write(target, data)

    monkeypatch.setattr(inst, "_atomic_write", cancelled)
    with pytest.raises(inst.ConfigConflict) as e:
        inst.install(cfg, "github", artifact=artifact, home=home)

    assert "cancelled by another process" in str(e.value)
    assert read(cfg) == original, "the target was left wrapped after a refusal"
    rec_path, _, _ = _paths(home)
    assert not rec_path.exists(), (
        "a completed record survived a transaction that refused")


# ═══════════════════════════════════════════════════════════════════════════
# Round 8. ASTRA's three compositions, each one an instance of a single
# invariant: a wrapped config must never be left without a usable inverse.
# His own rows are the acceptance; these pin the three mechanisms directly so
# each fails for one reason.
# ═══════════════════════════════════════════════════════════════════════════


def test_a_writer_that_read_before_the_lock_re_derives_under_it(
        cfg, home, artifact, monkeypatch, tmp_path):
    """R8-WAITING-WRITER. Round 7 locked the compare and the rename. A writer
    that had read the whole config BEFORE waiting for that lock still published
    a whole-file rendering built from what it read, so while it waited a
    recovery could restore another server and remove that server's record,
    journal and retained original, and the waiter would resurrect the wrapper
    it had seen with nothing left to undo it. Locking a write says nothing
    about the read it was derived from."""
    doc = json.loads(read(cfg))
    doc["mcpServers"]["other"] = {"command": "other", "args": []}
    cfg.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    inst.install(cfg, "github", artifact=artifact, home=home)
    wrapped_state = read(cfg)
    restored_state = None

    real_write = inst._atomic_write

    fired = []

    def recovery_lands_first(target, data):
        nonlocal restored_state
        if not fired:
            # Set BEFORE the recovery runs: it writes through this same
            # boundary, and a guard that is only set afterwards re-enters.
            fired.append(True)
            # What the waiting installer will find when it finally looks:
            # github restored, and its recovery material gone with it.
            inst.uninstall(cfg, "github", home=home)
            restored_state = read(cfg)
        return real_write(target, data)

    monkeypatch.setattr(inst, "_atomic_write", recovery_lands_first)
    inst.install(cfg, "other", artifact=artifact, home=home)
    monkeypatch.setattr(inst, "_atomic_write", real_write)

    assert restored_state is not None and restored_state != wrapped_state
    servers = json.loads(read(cfg))["mcpServers"]
    assert inst.classify(servers["other"], artifact=artifact) == "WRAPPED", (
        "the second install did not survive")
    assert inst.classify(servers["github"], artifact=artifact) != "WRAPPED", (
        "a stale rendering resurrected a wrapper whose inverse was removed")


def test_a_cancelled_install_whose_rollback_refuses_still_has_an_inverse(
        cfg, home, artifact, monkeypatch):
    """R8-INVERSE-LAST. Cancellation plus a rollback that legitimately cannot
    happen — the write errors, or its compare-and-swap refuses because another
    install landed — left a wrapper on disk with no record, no journal and no
    retained original, and a message asking for the file to be reconciled by
    hand. The bytes are still in hand at that point, so the inverse is rebuilt
    before the refusal is raised."""
    original = read(cfg)
    real_write = inst._atomic_write
    calls = []

    def cancelled_then_no_rollback(target, data):
        calls.append(True)
        if len(calls) == 1:
            _, _, pending_path, retained = inst._record_paths(home, "github")
            for q in (pending_path, retained):
                if q.exists():
                    q.unlink()
            return real_write(target, data)
        raise inst.ConfigIOError("the rollback write cannot happen")

    monkeypatch.setattr(inst, "_atomic_write", cancelled_then_no_rollback)
    with pytest.raises(inst.ConfigConflict) as e:
        inst.install(cfg, "github", artifact=artifact, home=home)
    monkeypatch.setattr(inst, "_atomic_write", real_write)

    assert len(calls) == 2, "the rollback boundary was never reached"
    rec_path, _, retained = _paths(home)
    assert rec_path.is_file() and retained.is_file(), (
        "the wrapper was left with nothing that can undo it")

    inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == original, "the rebuilt inverse did not restore"
    # Checked last on purpose: the wording is the least of it, and a row that
    # goes red on a message before it goes red on the property reports the
    # wrong defect.
    assert "uninstall" in str(e.value), "the refusal does not say what to do"


def test_bytes_taken_by_an_interrupted_cleanup_are_reclaimed_by_digest(
        cfg, home, artifact, monkeypatch):
    """R8-TAKE-JOURNALLED. The take is atomic, but a process that ends between
    the take and the question leaves the bytes under a name no recovery path
    looks for while the record that claims them points at a file that is gone.
    The note written before the move is what makes them findable, and the
    digest in it is what makes them trustworthy."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    _, _, retained = _paths(home)
    records = retained.parent

    # The interruption is driven through the real cleanup, and the note under
    # test is the one the PRODUCT writes. An earlier version of this row built
    # the note by hand, so it proved the reader and said nothing about whether
    # anything ever writes one: removing the write left this row green and the
    # mutation harness caught it. KeyboardInterrupt because a dying process is
    # not an OSError and must not be swallowed by the cleanup's own handlers.
    real_rename = pathlib.Path.rename

    def rename_then_die(self, dst):
        result = real_rename(self, dst)
        if self == retained:
            raise KeyboardInterrupt("the process ends between take and check")
        return result

    monkeypatch.setattr(pathlib.Path, "rename", rename_then_die)
    with pytest.raises(KeyboardInterrupt):
        inst._discard(retained)
    monkeypatch.setattr(pathlib.Path, "rename", real_rename)

    assert list(records.glob("github.original.discarding-*")), (
        "the bytes were not taken")
    assert not retained.exists(), "the canonical name still holds the bytes"

    # Through the PUBLIC path, not the helper: a row that calls a function only
    # the fix has goes red with an AttributeError on the old build, which says
    # "this is new" rather than "this was broken".
    original = read(cfg)
    inst.uninstall(cfg, "github", home=home)
    assert read(cfg) != original, "the wrapper was never undone"
    assert inst.classify(json.loads(read(cfg))["mcpServers"]["github"],
                         artifact=artifact) != "WRAPPED", (
        "the bytes survived under the held name and nothing found them")
    assert not (records / "github.taking").exists(), "the spent note was kept"


def test_a_leftover_is_not_reclaimed_on_the_strength_of_its_name(
        cfg, home, artifact):
    """The other side, and the reason the note carries a digest: a file whose
    name merely resembles taken material is not recovery material. Restoring a
    user's config from something we recognised by convention is worse than
    refusing."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    _, _, retained = _paths(home)
    records = retained.parent
    claimed = read(retained)
    retained.unlink()

    impostor = records / (retained.name + ".discarding-1-a")
    impostor.write_bytes(b'{"not": "the retained original"}')

    # No note at all: nothing to reclaim, and nothing to complain about either.
    assert inst._reclaim_taken(home, "github") is False
    assert not retained.exists()

    # A note, but the held bytes do not hash to what it says was taken. Round 9
    # makes this a TYPED refusal rather than a quiet False: a note is recovery
    # material, and material that fails its own check is a thing to say out
    # loud, not to step over and fail later for a different reason.
    (records / "github.taking").write_text(json.dumps(
        {"canonical": retained.name, "held": impostor.name,
         "sha256": inst._digest_bytes(claimed)}), encoding="utf-8")
    with pytest.raises(inst.ConfigConflict) as e:
        inst._reclaim_taken(home, "github")
    assert "does not hash" in str(e.value)
    assert not retained.exists(), "bytes that failed their digest were restored"

    # And the shapes that reached `.get` as an AttributeError through the
    # public uninstall before round 9.
    for body in ("[]", "null", '"a string"'):
        (records / "github.taking").write_text(body, encoding="utf-8")
        with pytest.raises(inst.ConfigConflict):
            inst._reclaim_taken(home, "github")


# ═══════════════════════════════════════════════════════════════════════════
# Round 9. The three compositions from round 8's review, all of them in the
# recovery paths round 8 added. The shape of the mistake was the same each
# time: a plan that only exists once something goes wrong is a plan that has
# never been run.
# ═══════════════════════════════════════════════════════════════════════════


def test_the_inverse_is_on_disk_before_the_wrapper_it_undoes(
        cfg, home, artifact, monkeypatch):
    """R9-INVERSE-FIRST. Round 8 rebuilt the inverse from bytes held in memory
    once it noticed it had been cancelled, and a rebuild that has to WRITE can
    fail: failing the retained write, or the record write, left a wrapper with
    nothing behind it either way. A second copy now goes down BEFORE the
    wrapper is published, under a name a competing cleanup does not take, so
    the rebuild is two renames of files that already exist."""
    seen = []
    real_replace = inst.os.replace

    def watch(src, dst):
        if pathlib.Path(dst) == cfg:
            # At the instant of publication, the inverse must already be
            # somewhere on disk that a cleanup of the canonical pair misses.
            records = home / "proxy" / "installs"
            seen.append(sorted(q.name for q in records.glob("*.inflight-*")))
        return real_replace(src, dst)

    monkeypatch.setattr(inst.os, "replace", watch)
    inst.install(cfg, "github", artifact=artifact, home=home)
    monkeypatch.setattr(inst.os, "replace", real_replace)

    assert seen, "the publication boundary was never reached"
    assert len(seen[0]) == 2, (
        f"the inverse was not on disk before the wrapper: {seen[0]}")
    records = home / "proxy" / "installs"
    assert not list(records.glob("*.inflight-*")), (
        "the standby copy was left behind after an ordinary install")


def test_a_rebuild_that_cannot_write_still_leaves_a_usable_inverse(
        cfg, home, artifact, monkeypatch):
    """The composition itself: cancelled, the rollback refuses, and then every
    WRITE fails too. The inverse still has to be there, because it was put
    there before any of this started."""
    original = read(cfg)
    real_write = inst._atomic_write
    real_write_bytes = pathlib.Path.write_bytes
    real_write_text = pathlib.Path.write_text
    calls = []

    def cancelled_then_no_rollback(target, data):
        calls.append(True)
        if len(calls) == 1:
            _, _, pending_path, retained = inst._record_paths(home, "github")
            for q in (pending_path, retained):
                if q.exists():
                    q.unlink()
            return real_write(target, data)
        raise inst.ConfigIOError("the rollback write cannot happen")

    def no_writes_at_all(self, *a, **kw):
        if len(calls) >= 2:
            raise OSError("nothing may be written from here on")
        return (real_write_bytes if isinstance(a[0] if a else b"", bytes)
                else real_write_text)(self, *a, **kw)

    monkeypatch.setattr(inst, "_atomic_write", cancelled_then_no_rollback)
    monkeypatch.setattr(pathlib.Path, "write_bytes", no_writes_at_all)
    monkeypatch.setattr(pathlib.Path, "write_text", no_writes_at_all)
    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "github", artifact=artifact, home=home)
    monkeypatch.setattr(pathlib.Path, "write_bytes", real_write_bytes)
    monkeypatch.setattr(pathlib.Path, "write_text", real_write_text)
    monkeypatch.setattr(inst, "_atomic_write", real_write)

    assert len(calls) == 2, "the rollback boundary was never reached"
    inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == original, (
        "a rebuild that could not write left the wrapper with no way back")


def test_a_second_cleanup_does_not_remove_the_first_cleanups_note(
        cfg, home, artifact, monkeypatch):
    """R9-NOTE-OWNERSHIP. The note lives at one name because that is the name
    recovery looks for, so a second take would overwrite the first one's note
    and the first one's bytes would be left under a held name nothing could
    find. A take that a live note still answers for is not ours to overwrite."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    _, _, retained = _paths(home)
    records = retained.parent
    note = records / "github.taking"
    claimed = read(retained)

    # An interrupted take: the note and the held bytes are both there, and
    # nothing has answered for them yet.
    real_rename = pathlib.Path.rename

    def take_then_stop(self, dst):
        result = real_rename(self, dst)
        if self == retained:
            raise KeyboardInterrupt("the first cleanup ends here")
        return result

    monkeypatch.setattr(pathlib.Path, "rename", take_then_stop)
    with pytest.raises(KeyboardInterrupt):
        inst._discard(retained)
    monkeypatch.setattr(pathlib.Path, "rename", real_rename)

    first_note = note.read_text()
    held = records / json.loads(first_note)["held"]
    assert held.is_file() and note.is_file()

    # A competing install republishes the canonical retained original, and a
    # second cleanup comes along for it while the first take is still open.
    retained.write_bytes(b'{"a second install": "its own retained original"}')
    inst._discard(retained)

    assert note.read_text() == first_note, (
        "a second take overwrote the note the first one is answered for by")
    assert held.is_file() and read(held) == claimed, (
        "the first take's bytes were lost")
    assert retained.is_file(), (
        "the second cleanup removed bytes while refusing to note the take")


def test_a_take_whose_note_cannot_be_written_does_not_happen(
        cfg, home, artifact, monkeypatch):
    """R9-NOTE-FIRST. Round 8 swallowed the note-write error and took the bytes
    anyway, which is the worst of both: they are moved, and nothing records
    where. A take that cannot be recovered from does not happen, so the bytes
    stay at the name the public path already knows."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    _, _, retained = _paths(home)
    claimed = read(retained)
    real_write_text = pathlib.Path.write_text

    def no_note(self, *a, **kw):
        if self.suffix == ".taking":
            raise OSError("the note cannot be written")
        return real_write_text(self, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "write_text", no_note)
    with pytest.raises(inst.ConfigIOError) as e:
        inst._discard(retained)
    monkeypatch.setattr(pathlib.Path, "write_text", real_write_text)

    assert "take note" in str(e.value)
    assert retained.is_file() and read(retained) == claimed, (
        "the bytes were taken although nothing recorded where they went")
    assert not list(retained.parent.glob("*.discarding-*"))


def test_a_new_owners_note_survives_an_older_cleanups_forget(
        cfg, home, artifact, monkeypatch):
    """R10-NOTE-FORGET-ATOMIC, substitution for
    `R9_NOTE_REPLACED_BETWEEN_CHECK_AND_UNLINK`. His row drives the same
    stimulus through `Path.unlink` of the note, which ruling (c) replaced with
    a rename-to-private-then-unlink, so his boundary never fires. The race is
    the same: an older cleanup decides the note is its own, a new owner
    publishes a note in the gap, and the older cleanup must not delete it."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    _, _, retained = _paths(home)
    records = retained.parent
    note = records / "github.taking"

    # An interrupted take leaves a note this cleanup believes is its own.
    real_rename = pathlib.Path.rename

    def take_then_stop(self, dst):
        result = real_rename(self, dst)
        if self == retained:
            raise KeyboardInterrupt("the first cleanup ends here")
        return result

    monkeypatch.setattr(pathlib.Path, "rename", take_then_stop)
    with pytest.raises(KeyboardInterrupt):
        inst._discard(retained)
    monkeypatch.setattr(pathlib.Path, "rename", real_rename)
    mine = json.loads(note.read_text())["held"]

    # A NEW owner publishes its note in the window between the older cleanup
    # READING the note and acting on what it read. The injection is keyed on
    # the read, which both builds do, rather than on the removal, which round 9
    # did by path and round 10 does by rename: a row keyed on the removal can
    # only be red on one of them.
    newly_held = records / "github.original.discarding-999-new"
    newly_held.write_bytes(b'{"the new owner": "its own bytes"}')
    new_note = json.dumps(
        {"canonical": retained.name, "held": newly_held.name,
         "sha256": inst._digest_file(newly_held)})
    real_read_text = pathlib.Path.read_text
    replaced = []

    def replace_after_reading(self, *a, **kw):
        out = real_read_text(self, *a, **kw)
        if self.name.startswith("github.taking") and not replaced:
            replaced.append(True)
            note.write_text(new_note, encoding="utf-8")
        return out

    monkeypatch.setattr(pathlib.Path, "read_text", replace_after_reading)
    inst._forget_take(note, mine)
    monkeypatch.setattr(pathlib.Path, "read_text", real_read_text)

    assert replaced, "the note was never read, so the window was not reached"

    assert note.is_file(), "the older cleanup deleted the new owner's note"
    assert json.loads(note.read_text())["held"] == newly_held.name
    assert newly_held.is_file(), "the new owner's bytes were lost with its note"


def test_a_standby_left_by_an_ended_publisher_is_discovered(
        cfg, home, artifact, monkeypatch):
    """R10-DISCOVERABLE. Round 9 put the inverse on disk before the wrapper,
    which was right, and then made it reachable ONLY through the promotion
    inside the transaction that wrote it. A process that ended between
    publishing and promoting left a perfectly good inverse that no public path
    would look at. Two fallible renames may stay only because every state
    between them is discoverable from the outside."""
    original = read(cfg)
    real_write = inst._atomic_write
    ended = []

    def end_after_publishing(target, data):
        out = real_write(target, data)
        if not ended:
            ended.append(True)
            # A racing uninstall takes the canonical journal and retained copy
            # the way one really does, so the standby is the ONLY inverse left
            # -- otherwise journal recovery answers this and the row proves
            # nothing about the standby at all. It did, once.
            _, _, pending_path, retained = inst._record_paths(home, "github")
            for q in (pending_path, retained):
                if q.exists():
                    q.unlink()
            raise KeyboardInterrupt("the publisher ends here")
        return out

    monkeypatch.setattr(inst, "_atomic_write", end_after_publishing)
    with pytest.raises(KeyboardInterrupt):
        inst.install(cfg, "github", artifact=artifact, home=home)
    monkeypatch.setattr(inst, "_atomic_write", real_write)

    records = home / "proxy" / "installs"
    assert ended and read(cfg) != original, "the wrapper was never published"
    assert list(records.glob("*.standby")), "no standby was left behind"
    assert not (records / "github.json").exists(), "the record was promoted"

    # The public path, with nothing at the canonical names to go on.
    inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == original, (
        "the inverse the dead publisher left could not be discovered")


def test_a_standby_whose_bytes_no_longer_match_is_not_promoted(
        cfg, home, artifact, monkeypatch):
    """R10-STANDBY-VALIDATED. A standby is only an inverse while it still
    hashes to what its record says. Promoting one that does not would put a
    guess where the user's original was; the record still says what the entry
    was, so it is promoted alone and marked, and the copy that failed stays as
    the evidence."""
    original = read(cfg)
    real_write = inst._atomic_write
    corrupted = []

    def corrupt_the_standby(target, data):
        if not corrupted:
            corrupted.append(True)
            _, _, pending_path, retained = inst._record_paths(home, "github")
            for q in (pending_path, retained):
                if q.exists():
                    q.unlink()
            out = real_write(target, data)
            for standby in (home / "proxy" / "installs").glob("*.standby"):
                standby.write_bytes(b'{"not": "the original"}')
            return out
        raise inst.ConfigIOError("the rollback write cannot happen")

    monkeypatch.setattr(inst, "_atomic_write", corrupt_the_standby)
    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "github", artifact=artifact, home=home)
    monkeypatch.setattr(inst, "_atomic_write", real_write)

    assert corrupted
    records = home / "proxy" / "installs"
    rec_path, _, retained = _paths(home)
    assert rec_path.is_file(), "the record was not promoted"
    # The property first, the marker second: a row that goes red on a missing
    # key before it goes red on promoted bytes reports the wrong defect.
    assert not retained.exists(), "bytes that failed their digest were promoted"
    # ROUND 11: no field decides this, the state does. The record names the
    # copy that failed and the digest it failed with, and both are checked on
    # disk before an entry-only restore is allowed. A forged key buys nothing.
    claim = json.loads(read(rec_path))
    failed = records / claim["failed_bytes_name"]
    assert failed.is_file() and inst._digest_file(failed) == claim[
        "failed_bytes_sha256"]
    assert list(records.glob("*.failed-*")), "the failed copy was not kept"

    # And the wrapper still comes off, entry-only, without those bytes.
    result = inst.uninstall(cfg, "github", home=home)
    assert result.byte_exact is False
    assert inst.classify(json.loads(read(cfg))["mcpServers"]["github"],
                         artifact=artifact) != "WRAPPED"
    assert b'"not": "the original"' not in read(cfg)


def test_a_put_back_loses_to_a_new_owner_of_the_name(
        cfg, home, artifact, monkeypatch):
    """R11-PUTBACK-CONTESTS-THE-NAME, substitution for
    `R10_NOTE_IO_BOUNDARIES[putback]`, whose fault is injected on a rename out
    of the private name that ruling (a) replaced with a link. The race is the
    one that matters: the rename is exclusive on the INODE and says nothing
    about the destination NAME, so a new owner can claim it while an older
    cleanup holds the old note privately."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    _, _, retained = _paths(home)
    records = retained.parent
    note = records / "github.taking"
    note.write_text(json.dumps(
        {"canonical": retained.name, "held": "somebody-elses", "sha256": "0" * 64}),
        encoding="utf-8")

    real_read_text = pathlib.Path.read_text
    published = []

    def a_new_owner_claims_the_name(self, *a, **kw):
        out = real_read_text(self, *a, **kw)
        if ".forgetting-" in self.name and not published:
            published.append(True)
            # The name is free for exactly this moment, and a new owner takes
            # it. Whatever the older cleanup is holding is stale by definition.
            note.write_text(json.dumps(
                {"canonical": retained.name, "held": "the-new-owners",
                 "sha256": "1" * 64}), encoding="utf-8")
        return out

    monkeypatch.setattr(pathlib.Path, "read_text", a_new_owner_claims_the_name)
    inst._forget_take(note, "an-older-take")
    monkeypatch.setattr(pathlib.Path, "read_text", real_read_text)

    assert published, "the put-back window was never reached"
    assert json.loads(read(note))["held"] == "the-new-owners", (
        "the put-back overwrote a note published while it held the old one")
    # ROUND 12 CORRECTS WHAT THIS ROW USED TO ASSERT. It used to require the
    # private note to be gone, which is the defect the reviewer found: EEXIST
    # says somebody holds a NAME, not that the bytes the old note points at
    # have been dealt with. A delayed claimant can win the freed name having
    # moved nothing. The old note stays, under a name reclaim scans, until its
    # bytes are answered for.
    kept = list(records.glob("*.forgetting-*"))
    assert kept, "a note was discarded on a name contest, answering for nothing"
    assert json.loads(read(kept[0]))["held"] == "somebody-elses"


def test_a_private_note_is_dropped_once_its_bytes_are_answered_for(
        cfg, home, artifact, monkeypatch):
    """The other side of R12: a note IS spent once what it points at is back at
    the canonical name. Keeping it then would leave reclaim chasing bytes that
    are already where they belong."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    _, _, retained = _paths(home)
    records = retained.parent
    note = records / "github.taking"
    held = records / "github.original.discarding-1-a"
    held.write_bytes(read(retained))
    note.write_text(json.dumps(
        {"canonical": retained.name, "held": held.name,
         "sha256": inst._digest_file(held)}), encoding="utf-8")

    real_read_text = pathlib.Path.read_text
    published = []

    def a_new_owner_claims_the_name(self, *a, **kw):
        out = real_read_text(self, *a, **kw)
        if ".forgetting-" in self.name and not published:
            published.append(True)
            note.write_text(json.dumps(
                {"canonical": retained.name, "held": "the-new-owners",
                 "sha256": "1" * 64}), encoding="utf-8")
        return out

    monkeypatch.setattr(pathlib.Path, "read_text", a_new_owner_claims_the_name)
    inst._forget_take(note, "an-older-take")
    monkeypatch.setattr(pathlib.Path, "read_text", real_read_text)

    assert published
    # The canonical retained copy is present and hashes to what the old note
    # recorded, so those bytes are answered for and the note is spent.
    assert not list(records.glob("*.forgetting-*")), (
        "a note whose bytes are already back was kept")


def test_a_forged_marker_does_not_license_an_entry_only_restore(
        cfg, home, artifact):
    """R11-NO-FIELD-DECIDES. Round 10 let a record carry a field that meant
    "you may restore entry-only without bytes", so editing that field into an
    ordinary record and corrupting the retained copy turned a refusal into a
    silent lossy restore. A record is not a capability."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    rec_path, _, retained = _paths(home)
    installed = read(cfg)

    for forged in (True, "yes", 1, {"any": "truthy thing"}):
        claim = json.loads(read(rec_path))
        claim["inverse_unusable"] = forged
        claim["failed_bytes_name"] = "github.failed-1-a.original"
        claim["failed_bytes_sha256"] = "0" * 64
        rec_path.write_text(json.dumps(claim), encoding="utf-8")
        retained.write_bytes(b'{"corrupted":true}')

        with pytest.raises(inst.ConfigConflict):
            inst.uninstall(cfg, "github", home=home)
        assert read(cfg) == installed, (
            f"a forged {forged!r} bought an entry-only restore")


def test_the_standby_that_describes_the_live_file_is_the_one_adopted(
        cfg, home, artifact, monkeypatch):
    """R11-ADOPT-THE-CURRENT-ONE. More than one standby can be on disk, and
    round 10 took the first by name order, which is the oldest. A standby is
    the inverse of a PARTICULAR published wrapper, so the one to adopt is the
    one whose record describes the file that is actually there."""
    original = read(cfg)
    real_write = inst._atomic_write
    ended = []

    def end_after_publishing(target, data):
        out = real_write(target, data)
        if not ended:
            ended.append(True)
            _, _, pending_path, retained = inst._record_paths(home, "github")
            for q in (pending_path, retained):
                if q.exists():
                    q.unlink()
            raise KeyboardInterrupt("the publisher ends here")
        return out

    monkeypatch.setattr(inst, "_atomic_write", end_after_publishing)
    with pytest.raises(KeyboardInterrupt):
        inst.install(cfg, "github", artifact=artifact, home=home)
    monkeypatch.setattr(inst, "_atomic_write", real_write)

    records = home / "proxy" / "installs"
    live = sorted(records.glob("*.standbyrecord"))
    assert len(live) == 1

    # A STALE pair from an earlier transaction, sorting FIRST by name, whose
    # record describes a file that is no longer there.
    stale_record = records / "github.inflight-000000-0.standbyrecord"
    stale_bytes = records / "github.inflight-000000-0.standby"
    claim = json.loads(read(live[0]))
    stale_bytes.write_bytes(b'{"an older original":true}')
    stale_record.write_text(json.dumps(
        {**claim, "file_sha_before": inst._digest_file(stale_bytes),
         "file_sha_after": "2" * 64}), encoding="utf-8")

    inst.uninstall(cfg, "github", home=home)
    assert read(cfg) == original, (
        "a stale standby was adopted ahead of the one describing the live file")


def test_evidence_swapped_after_the_gate_does_not_license_the_restore(
        cfg, home, artifact, monkeypatch):
    """R12-AUTHORISE-AT-THE-MOMENT-OF-USE. The gate that decides an entry-only
    restore is worth attempting runs before everything between it and the
    write. Evidence read then can be swapped after, so what licenses the write
    is taken again immediately before it, on one fresh descriptor. A check
    whose answer is carried across other work is a check about the past."""
    original = read(cfg)
    real_write = inst._atomic_write
    ended = []

    def corrupt_the_standby(target, data):
        if not ended:
            ended.append(True)
            _, _, pending_path, retained = inst._record_paths(home, "github")
            for q in (pending_path, retained):
                if q.exists():
                    q.unlink()
            out = real_write(target, data)
            for standby in (home / "proxy" / "installs").glob("*.standby"):
                standby.write_bytes(b'{"not": "the original"}')
            return out
        raise inst.ConfigIOError("the rollback write cannot happen")

    monkeypatch.setattr(inst, "_atomic_write", corrupt_the_standby)
    with pytest.raises(inst.ConfigConflict):
        inst.install(cfg, "github", artifact=artifact, home=home)
    monkeypatch.setattr(inst, "_atomic_write", real_write)

    records = home / "proxy" / "installs"
    set_aside = next(records.glob("*.failed-*"))
    real_gate = inst._failed_copy_is_present
    swapped = []

    def swap_after_the_gate(*a, **kw):
        answer = real_gate(*a, **kw)
        if answer and not swapped:
            swapped.append(True)
            set_aside.write_bytes(b'{"swapped after the gate said yes":true}')
        return answer

    monkeypatch.setattr(inst, "_failed_copy_is_present", swap_after_the_gate)
    with pytest.raises(inst.ConfigConflict):
        inst.uninstall(cfg, "github", home=home)
    monkeypatch.setattr(inst, "_failed_copy_is_present", real_gate)

    assert swapped, "the gate was never reached"
    assert read(cfg) != original, "the fixture never published a wrapper"
    assert inst.classify(json.loads(read(cfg))["mcpServers"]["github"],
                         artifact=artifact) == "WRAPPED", (
        "a restore was licensed by evidence that had already been swapped")
