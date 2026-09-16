"""T10.R4/R5/R6 — wire an MCP server entry to this artifact, and unwire it.

Contract rows: GATE3_CONTRACT_v5_2026-09-13.md T10.R4, T10.R5, T10.R6.
Round 2, rebuilt against ASTRA's NO GO on 0c184de and T9's ruling R-177-R2.

Round 1 passed 16 of its own mutations and failed 24 of 48 independent property
controls. The gap was not effort, it was that the mutations were chosen from the
implementation, so they asked whether the code did what it already did. These
notes record the properties the controls actually check, because they are the
ones a later edit will quietly break.

**The record is bound to the target it describes.** `installs/<name>.json` is
keyed by name alone, so the same name installed into a second config used to
overwrite the first record and its retained bytes, and uninstalling the first
file then restored the second file's original. A record carries `target_path`
and a name occupied by another target is refused.

**Retained bytes are validated before they are restored.** Round 1 recorded
`file_sha_before` and never read it, so altering the `.original` file made
uninstall copy corrupted bytes into the config and report byte-exact success.
That was reachable from the public CLI with no proxy involved. Retention is now
checked against the recorded digest and a mismatch is a refusal.

**Replace and record are one recoverable transaction.** A pending record is
written first, then the target is replaced, then the record is completed. If
completion fails the target is rolled back to the retained bytes, so the
original-intact outcome holds on a catchable fault rather than leaving a changed
target with no record to undo it.

**An existing wrapper is never wrapped again.** Round 1 only skipped re-wrapping
when the wrapper verified against the current artifact, so a changed digest or a
byte-identical artifact at another path nested a second wrapper. Any marker at
all is now a stop: verified means refuse as already installed, anything else
means refuse as unverifiable.

**WRAPPED is bound to what the entry executes.** Matching metadata is not
enough. The command and the leading argv must actually launch the recorded
artifact, or the route is UNVERIFIED.

**Every fault and every bad shape refuses before mutating.** Operational errors
are one type across the whole transaction boundary so the CLI can return 2
rather than leaking a traceback, duplicate JSON keys are rejected instead of
silently collapsed, and execution options the entry carries are preserved.
"""
import hashlib
import json
import os
import pathlib
import sys
import tempfile

MARKER = "x-sunglasses"

# The five fields T10.R4 names. A record may carry more, never fewer.
RECORD_FIELDS = ("original_entry", "installed_entry", "file_sha_before",
                 "file_sha_after", "original_bytes_path")


class ConfigConflict(Exception):
    """Unknown or conflicting state (R5). Never mutates."""


class ConfigIOError(Exception):
    """Unusable input, or an interrupted write (R6). Original left intact."""


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


def _reject_duplicate_keys(pairs):
    """A duplicate key makes the document ambiguous and `json.loads` resolves it
    silently by keeping the last one. Rewriting such a file drops data the user
    can still see in their own config, so it is refused instead."""
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _read_bytes(path):
    try:
        return pathlib.Path(path).read_bytes()
    except OSError as e:
        raise ConfigIOError(f"cannot read {path}: {e}") from e


def _parse(raw, path):
    try:
        return json.loads(raw.decode("utf-8"),
                          object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, UnicodeDecodeError) as e:
        raise ConfigIOError(f"{path} is not usable JSON: {e}") from e


def _servers(doc, path):
    if not isinstance(doc, dict):
        raise ConfigIOError(f"{path}: the top level is not a JSON object")
    servers = doc.get("mcpServers")
    if not isinstance(servers, dict):
        raise ConfigIOError(f"{path}: no mcpServers object")
    return servers


def _validate_entry(entry, name, path):
    """Shape of the entry we are about to read and rewrite. Checked before any
    mutation so a malformed entry is a typed refusal, not a traceback."""
    if not isinstance(entry, dict):
        raise ConfigIOError(f"{path}: the {name!r} entry is not an object")
    command = entry.get("command")
    if not isinstance(command, str) or not command:
        raise ConfigIOError(f"{path}: the {name!r} entry has no string command")
    args = entry.get("args")
    if args is not None and not (isinstance(args, list)
                                 and all(isinstance(a, str) for a in args)):
        raise ConfigIOError(f"{path}: the {name!r} args are not a list of strings")


def _atomic_write(path, data: bytes):
    """Replace in place, preserving mode. On failure the original is untouched
    and no temp file is left behind (R6). Every OSError on this boundary becomes
    ConfigIOError, including the stat and the mkstemp."""
    p = pathlib.Path(path)
    try:
        mode = p.stat().st_mode & 0o777
    except OSError as e:
        raise ConfigIOError(f"cannot stat {path}: {e}") from e
    try:
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".sg-", suffix=".tmp")
    except OSError as e:
        raise ConfigIOError(f"cannot create a temporary file beside {path}: {e}") from e
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
        raise ConfigIOError(f"write to {path} was interrupted: {e}") from e


def _record_paths(home, name):
    d = pathlib.Path(home) / "proxy" / "installs"
    return d, d / f"{name}.json", d / f"{name}.pending", d / f"{name}.original"


def _records_dir(home, name):
    d, *rest = _record_paths(home, name)
    try:
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(str(d), 0o700)
    except OSError as e:
        raise ConfigIOError(f"cannot prepare {d}: {e}") from e
    return (d, *rest)


def _discard(*paths):
    for p in paths:
        try:
            pathlib.Path(p).unlink()
        except OSError:
            pass


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
    """DIRECT (no wrapper) · WRAPPED (this artifact, and the entry really runs
    it) · UNVERIFIED (a wrapper we cannot vouch for).

    Matching metadata is not enough. C6-ROUTE: with a correct path and digest in
    the marker, changing the command, changing the argv or emptying it still
    left round 1 calling the route WRAPPED. Classification is bound to what the
    entry executes.
    """
    if not isinstance(entry, dict):
        return "UNVERIFIED"
    meta = entry.get(MARKER)
    if not isinstance(meta, dict):
        return "DIRECT"
    try:
        actual = _digest_file(artifact)
    except OSError:
        return "UNVERIFIED"
    resolved = str(pathlib.Path(artifact).resolve())
    if meta.get("artifact") != resolved or meta.get("sha256") != actual:
        return "UNVERIFIED"
    if entry.get("command") != meta.get("command"):
        return "UNVERIFIED"
    args = entry.get("args")
    if not isinstance(args, list) or args[:2] != [resolved, "--"]:
        return "UNVERIFIED"
    return "WRAPPED"


def install(config_path, name, *, artifact, home, argv=None):
    """Wrap one entry. Validates everything, then mutates recoverably."""
    artifact = pathlib.Path(artifact)
    try:
        digest = _digest_file(artifact)
    except OSError as e:
        raise ArtifactUnresolved(
            f"no proxy entry point at {artifact}; refusing to write a config "
            f"that would look protected and run nothing"
        ) from e
    resolved = str(artifact.resolve())

    target = pathlib.Path(config_path)
    raw = _read_bytes(target)
    doc = _parse(raw, target)
    servers = _servers(doc, target)

    # Any marker at all stops us, verified or not (C2-REPEAT, C2-DRIFT).
    existing = servers.get(name)
    if isinstance(existing, dict) and MARKER in existing:
        if classify(existing, artifact=artifact) == "WRAPPED":
            raise ConfigConflict(
                f"{name!r} is already wrapped in {target}; nothing to do")
        raise ConfigConflict(
            f"{name!r} already carries a wrapper this build cannot verify; "
            f"refusing to nest another inside it")

    if name in servers:
        _validate_entry(existing, name, target)
        original_entry = json.loads(json.dumps(existing))
        entry_existed = True
    else:
        if argv is None:
            raise ConfigConflict(f"no MCP server named {name!r} in {target}")
        if not (isinstance(argv, (list, tuple)) and argv
                and all(isinstance(a, str) for a in argv)):
            raise ConfigIOError("the supplied argv is not a non-empty list of strings")
        original_entry = {"command": argv[0], "args": list(argv[1:])}
        entry_existed = False

    target_id = str(target.resolve())
    _, rec_path, pending_path, bytes_path = _records_dir(home, name)

    # R4/R5-COLLISION: a record belongs to one target, not to a name.
    if rec_path.exists():
        try:
            prior = json.loads(rec_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prior = None
        prior_target = prior.get("target_path") if isinstance(prior, dict) else None
        if prior_target != target_id:
            raise ConfigConflict(
                f"a record for {name!r} already belongs to {prior_target}; "
                f"refusing to overwrite it and lose that original")

    # R4-OPTIONS: env, cwd and anything else the entry carries survive.
    wrapper = {k: v for k, v in original_entry.items() if k not in ("command", "args")}
    wrapper["command"] = sys.executable
    wrapper["args"] = [resolved, "--", original_entry["command"],
                       *(original_entry.get("args") or [])]
    wrapper[MARKER] = {"artifact": resolved, "sha256": digest,
                       "command": sys.executable}
    servers[name] = wrapper
    new_raw = (json.dumps(doc, indent=2) + "\n").encode("utf-8")

    record = {
        "original_entry": original_entry,
        "installed_entry": wrapper,
        "file_sha_before": _digest_bytes(raw),
        "file_sha_after": None,
        "original_bytes_path": str(bytes_path),
        "target_path": target_id,
        "entry_existed": entry_existed,
    }

    try:
        bytes_path.write_bytes(raw)
    except OSError as e:
        raise ConfigIOError(f"cannot retain the original bytes: {e}") from e
    try:
        pending_path.write_text(json.dumps({**record, "state": "pending"}, indent=2),
                                encoding="utf-8")
    except OSError as e:
        _discard(bytes_path)
        raise ConfigIOError(f"cannot write the pending record: {e}") from e

    try:
        _atomic_write(target, new_raw)
    except ConfigIOError:
        _discard(bytes_path, pending_path)
        raise

    # C4-RECORD: completion is part of the transaction. If it fails, put the
    # target back rather than leaving a wrapped config with nothing to undo it.
    try:
        record["file_sha_after"] = _digest_bytes(_read_bytes(target))
        rec_path.write_text(json.dumps({**record, "state": "complete"}, indent=2),
                            encoding="utf-8")
    except (OSError, ConfigIOError) as e:
        rolled_back = True
        try:
            _atomic_write(target, raw)
        except ConfigIOError:
            rolled_back = False
        _discard(bytes_path, pending_path, rec_path)
        raise ConfigIOError(
            f"could not record the install: {e}"
            + ("; the target was restored" if rolled_back else
               "; THE TARGET IS STILL WRAPPED and could not be restored")
        ) from e

    _discard(pending_path)


def uninstall(config_path, name, *, home):
    """Restore. Byte-exact when the file has not moved, entry-only when it has,
    and a typed refusal whenever the state is not one we can vouch for."""
    target = pathlib.Path(config_path)
    _, rec_path, pending_path, _ = _record_paths(home, name)

    if not rec_path.exists():
        raise ConfigConflict(f"no recorded install for {name!r}")
    try:
        record = json.loads(rec_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ConfigConflict(
            f"the record for {name!r} is not readable JSON, so the original it "
            f"points at cannot be trusted: {e}") from e
    if not isinstance(record, dict):
        raise ConfigConflict(f"the record for {name!r} is not an object")
    missing = [f for f in RECORD_FIELDS if f not in record]
    if missing:
        raise ConfigConflict(
            f"the record for {name!r} is missing {', '.join(missing)}")

    recorded_target = record.get("target_path")
    if recorded_target is not None and recorded_target != str(target.resolve()):
        raise ConfigConflict(
            f"the record for {name!r} describes {recorded_target}, not {target}")

    # R5-RETAINED: the retained bytes are validated before they are trusted.
    retained_path = pathlib.Path(record["original_bytes_path"])
    try:
        retained = retained_path.read_bytes()
    except OSError as e:
        raise ConfigConflict(
            f"the retained original for {name!r} is missing: {e}") from e
    if _digest_bytes(retained) != record.get("file_sha_before"):
        raise ConfigConflict(
            f"the retained original for {name!r} does not match the digest "
            f"recorded at install; refusing to restore bytes we cannot vouch for")

    current = _read_bytes(target)

    if _digest_bytes(current) == record.get("file_sha_after"):
        _atomic_write(target, retained)
        _discard(rec_path, pending_path, retained_path)
        return UninstallResult(byte_exact=True)

    # The file moved under us. Put the entry back, or remove it if we created
    # it, and leave every unrelated property alone, collected by property
    # rather than by position (C3, R5-INVERSE).
    doc = _parse(current, target)
    servers = _servers(doc, target)
    if name not in servers:
        raise ConfigConflict(f"{name!r} is no longer in {target}")
    if servers[name] != record.get("installed_entry"):
        raise ConfigConflict(
            f"the {name!r} entry is not the one we installed; refusing to "
            f"overwrite a change we did not make")
    if record.get("entry_existed", True):
        servers[name] = record["original_entry"]
    else:
        del servers[name]
    _atomic_write(target, (json.dumps(doc, indent=2) + "\n").encode("utf-8"))
    _discard(rec_path, pending_path, retained_path)
    return UninstallResult(byte_exact=False)
