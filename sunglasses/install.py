"""T10.R4/R5/R6 — wire an MCP server entry to this artifact, and unwire it.

Contract rows: GATE3_CONTRACT_v5_2026-09-13.md T10.R4, T10.R5, T10.R6.

Three properties here are deliberate and each one is guarded by a control in
`tests/proxy/test_install_transaction.py`. They are written down because each is
the kind of thing a later edit makes "simpler" by breaking it.

**Refusing to wire an artifact we cannot resolve.** An install that succeeds
against a missing artifact leaves a config that reads as protected and a route
that runs nothing. `ArtifactUnresolved` is raised before the file is touched.

**Byte-exact means `==` on bytes.** R5 restores the retained original bytes, not
a re-serialisation of the parsed original. A re-serialisation compares equal
under `json.loads` and differs on disk, so it would satisfy a key-equality
assertion while silently reformatting a file we do not own. The original bytes
are kept on disk for exactly this reason.

**WRAPPED is content-addressed.** A route counts as wrapped only when the
recorded artifact path AND its current digest both match. A command that merely
mentions us is DIRECT, and a wrapper whose artifact has been rebuilt under it is
UNVERIFIED rather than WRAPPED. Recognising the name is not recognising the call.
"""
import hashlib
import json
import os
import pathlib
import sys
import tempfile

MARKER = "x-sunglasses"


class ConfigConflict(Exception):
    """Unknown or conflicting state (R5). Never mutates."""


class ConfigIOError(Exception):
    """Unparseable, or an interrupted write (R6). Original left intact."""


class ArtifactUnresolved(Exception):
    """The artifact we were asked to wire cannot be resolved (C5)."""


class UninstallResult:
    """`byte_exact` False means the entry was restored but the file is not
    byte-identical, which R5 requires us to report rather than paper over."""

    __slots__ = ("byte_exact",)

    def __init__(self, byte_exact):
        self.byte_exact = byte_exact


def _digest_bytes(b):
    return hashlib.sha256(b).hexdigest()


def _digest_file(p):
    return _digest_bytes(pathlib.Path(p).read_bytes())


def _load(config_path):
    """Read and parse, or refuse. Returns (raw_bytes, doc, servers)."""
    try:
        raw = pathlib.Path(config_path).read_bytes()
    except OSError as e:
        raise ConfigIOError(f"cannot read {config_path}: {e}") from e
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ConfigIOError(f"{config_path} is not valid JSON: {e}") from e
    servers = doc.get("mcpServers")
    if not isinstance(servers, dict):
        raise ConfigIOError(f"{config_path} has no mcpServers object")
    return raw, doc, servers


def _atomic_write(config_path, data: bytes):
    """Replace in place, preserving mode. On failure the original is untouched
    and no temp file is left behind (R6)."""
    p = pathlib.Path(config_path)
    mode = p.stat().st_mode & 0o777
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".sg-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, str(p))
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ConfigIOError(f"write to {config_path} was interrupted: {e}") from e


def _records_dir(home):
    d = pathlib.Path(home) / "proxy" / "installs"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(d), 0o700)
    except OSError:
        pass
    return d


def resolve_artifact(*, package_root=None):
    """The artifact a wrapper must point at: this package's proxy entry point.

    Refuses when it is absent rather than returning a path that cannot run. On a
    tree without the proxy lane's `__main__.py` that means `install` refuses
    every time, which is the honest state and is C5 one level up from the
    argument check.
    """
    if package_root is None:
        package_root = pathlib.Path(__file__).resolve().parent
    entry = pathlib.Path(package_root) / "proxy" / "__main__.py"
    if not entry.is_file():
        raise ArtifactUnresolved(
            f"no proxy entry point at {entry}; this build cannot wire a route, "
            f"so refusing rather than writing a config that runs nothing"
        )
    return entry


def classify(entry, *, artifact):
    """DIRECT (never wrapped) · WRAPPED (this artifact, this digest) ·
    UNVERIFIED (a wrapper, but not one we can vouch for)."""
    if not isinstance(entry, dict):
        return "UNVERIFIED"
    meta = entry.get(MARKER)
    if not isinstance(meta, dict):
        return "DIRECT"
    try:
        actual = _digest_file(artifact)
    except OSError:
        return "UNVERIFIED"
    if meta.get("artifact") != str(pathlib.Path(artifact).resolve()):
        return "UNVERIFIED"
    if meta.get("sha256") != actual:
        return "UNVERIFIED"
    return "WRAPPED"


def install(config_path, name, *, artifact, home, argv=None):
    """Wrap one entry. Idempotent, entry-level, atomic, mode-preserving."""
    artifact = pathlib.Path(artifact)
    try:
        digest = _digest_file(artifact)
    except OSError as e:
        raise ArtifactUnresolved(
            f"cannot resolve the artifact to wire ({artifact}); refusing to "
            f"write a config that would look protected and run nothing"
        ) from e

    raw, doc, servers = _load(config_path)

    if name not in servers:
        if argv is None:
            raise ConfigConflict(f"no MCP server named {name!r} in {config_path}")
        servers[name] = {"command": argv[0], "args": list(argv[1:])}

    entry = servers[name]
    if classify(entry, artifact=artifact) == "WRAPPED":
        return                                  # C2: never wrap the wrapper

    original_entry = json.loads(json.dumps(entry))
    upstream = [original_entry.get("command")] + list(original_entry.get("args") or [])
    servers[name] = {
        "command": sys.executable,
        "args": [str(artifact), "--", *upstream],
        MARKER: {"artifact": str(artifact.resolve()), "sha256": digest},
    }

    rec_dir = _records_dir(home)
    bytes_path = rec_dir / f"{name}.original"
    bytes_path.write_bytes(raw)

    new_raw = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
    try:
        _atomic_write(config_path, new_raw)
    except ConfigIOError:
        try:
            bytes_path.unlink()                 # C4: no record for a failed write
        except OSError:
            pass
        raise

    (rec_dir / f"{name}.json").write_text(json.dumps({
        "original_entry": original_entry,
        "installed_entry": servers[name],
        "file_sha_before": _digest_bytes(raw),
        "file_sha_after": _digest_bytes(pathlib.Path(config_path).read_bytes()),
        "original_bytes_path": str(bytes_path),
    }, indent=2), encoding="utf-8")


def uninstall(config_path, name, *, home):
    """Restore. Byte-exact when the file has not moved, entry-only when it has,
    and a refusal when the state is not one we put there."""
    rec_path = _records_dir(home) / f"{name}.json"
    if not rec_path.exists():
        raise ConfigConflict(f"no recorded install for {name!r}")
    rec = json.loads(rec_path.read_text(encoding="utf-8"))

    current = pathlib.Path(config_path).read_bytes()

    if _digest_bytes(current) == rec.get("file_sha_after"):
        retained = pathlib.Path(rec["original_bytes_path"]).read_bytes()
        _atomic_write(config_path, retained)    # C1: the bytes, not a re-render
        rec_path.unlink()
        return UninstallResult(byte_exact=True)

    # The file moved under us. Put the entry back and leave everything else
    # alone, collected by property rather than by position (C3).
    _, doc, servers = _load(config_path)
    if name not in servers:
        raise ConfigConflict(f"{name!r} is no longer in {config_path}")
    installed = rec.get("installed_entry")
    if servers[name] != installed:
        raise ConfigConflict(
            f"the {name!r} entry is not the one we installed; refusing to "
            f"overwrite a change we did not make"
        )
    servers[name] = rec["original_entry"]
    _atomic_write(config_path, (json.dumps(doc, indent=2) + "\n").encode("utf-8"))
    rec_path.unlink()
    return UninstallResult(byte_exact=False)
