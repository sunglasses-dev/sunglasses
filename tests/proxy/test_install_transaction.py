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


def test_install_is_idempotent_and_never_wraps_the_wrapper(cfg, home, artifact):
    """C2. The second install must detect already-wrapped and not re-wrap."""
    inst.install(cfg, "github", artifact=artifact, home=home)
    once = read(cfg)
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
