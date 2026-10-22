"""
baseline.py -- a list of findings a team has already looked at, for `scan --baseline`.

A baseline lets a CI job fail on what is NEW instead of on everything ever found. It is
deliberately narrow, because a suppression list is the first place a real finding can hide:

  * An entry matches only the same rule, in the same file (path relative to the scan root),
    with the same file content (sha256). Edit the file and the entry stops matching.
  * A matched finding is still printed, still counted, still in the JSON and SARIF -- marked
    known, never removed.
  * A critical finding is never matched by an entry. The scan command line has to name the
    rule id (`--accept-critical GLS-...`), so the exception is visible in the CI config
    instead of sitting in a data file.
  * A baseline says nothing about coverage. It cannot make an unread file read.

No imports from cli.py: this module only reads, checks, matches and writes the file.
"""
import hashlib
import json
import os
import re
import stat
import tempfile

SCHEMA = 1
# A baseline larger than this is refused instead of read into memory.
MAX_BYTES = 16 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")

# Higher is worse. `review` is the engine's own label for a negated match; it is below `low`.
SEVERITY_RANK = {"review": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# The levels `--fail-on` accepts, and the lowest severity rank each one fails on.
# `any` fails on everything (today's behaviour); `none` fails on nothing.
FAIL_ON_LEVELS = {"any": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "none": 99}


class BaselineError(Exception):
    """The baseline cannot be used. The caller turns this into the usage exit, never a pass."""


def file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def posix_path(rel_path: str) -> str:
    """One spelling of a relative path, so a baseline written on one OS applies on another."""
    return rel_path.replace(os.sep, "/")


def _entry_key(entry_id, file, sha):
    return (entry_id, file, sha)


class Baseline:
    def __init__(self, entries, scanner_version=None):
        self.entries = list(entries)
        self.scanner_version = scanner_version
        self._keys = {_entry_key(e["id"], e["file"], e["file_sha256"]) for e in self.entries}

    def __len__(self):
        return len(self.entries)

    def matches(self, finding_id, file, sha):
        return _entry_key(finding_id, file, sha) in self._keys


def _canonical_path(value) -> bool:
    """A relative POSIX path with no empty, `.` or `..` part: the spelling `posix_path` writes."""
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def _entry_ok(entry) -> bool:
    """One rule both directions use: what `load` accepts is exactly what `write` may record."""
    return bool(isinstance(entry, dict)
                and isinstance(entry.get("id"), str) and entry.get("id")
                and _canonical_path(entry.get("file"))
                and isinstance(entry.get("file_sha256"), str)
                and _SHA256.fullmatch(entry.get("file_sha256")))


def _read_regular_file(path: str) -> bytes:
    """Read at most MAX_BYTES from a regular file; never block on a pipe or device."""
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK
    except AttributeError:  # no O_NONBLOCK on this platform
        flags = os.O_RDONLY
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BaselineError(f"could not read baseline {path}: {exc.strerror or exc}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise BaselineError(f"baseline {path} is not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        raise BaselineError(f"could not read baseline {path}: {exc.strerror or exc}") from None
    finally:
        os.close(fd)
    if len(raw) > MAX_BYTES:
        raise BaselineError(
            f"baseline {path} is larger than {MAX_BYTES // (1024 * 1024)} MiB; refusing to read it")
    return raw


def load(path: str) -> Baseline:
    raw = _read_regular_file(path)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise BaselineError(f"baseline {path} is not valid JSON") from None
    schema = doc.get("schema") if isinstance(doc, dict) else None
    if type(schema) is not int or schema != SCHEMA:
        raise BaselineError(
            f"baseline {path} has an unknown schema (this scanner reads schema {SCHEMA})")
    entries = doc.get("entries")
    if not isinstance(entries, list):
        raise BaselineError(f"baseline {path} has no entries list")
    clean = []
    for position, entry in enumerate(entries):
        if not _entry_ok(entry):
            raise BaselineError(
                f"baseline {path}: entry {position} needs an id, a canonical relative file "
                "path (forward slashes, no . or .. parts) and a 64-character lowercase "
                "hex file_sha256")
        severity = entry.get("severity", "")
        clean.append({"id": entry["id"], "file": entry["file"],
                      "file_sha256": entry["file_sha256"],
                      "severity": severity if isinstance(severity, str) else ""})
    version = doc.get("scanner_version")
    return Baseline(clean, version if isinstance(version, str) else None)


def classify(findings, baseline, accept_critical=()):
    """Split findings into known and new.

    `findings` is a list of dicts with id, file, file_sha256 and severity. Returns
    (known_flags, stale): one bool per finding (True = known), and the number of baseline
    entries that no finding matched this run.
    """
    accepted = set(accept_critical)
    known, present = [], set()
    for finding in findings:
        key = _entry_key(finding["id"], finding["file"], finding["file_sha256"])
        present.add(key)
        hit = baseline is not None and key in baseline._keys
        if hit and finding.get("severity") == "critical" and finding["id"] not in accepted:
            hit = False
        known.append(hit)
    # Stale = listed, but the finding is gone. A critical entry that is still found but not
    # accepted is not stale: it is inert, and the finding is reported as new.
    stale = 0 if baseline is None else len(baseline._keys - present)
    return known, stale


def entries_for(findings):
    """Baseline entries for a list of findings: one per rule, file and content, in stable order."""
    seen, out = set(), []
    for finding in findings:
        key = _entry_key(finding["id"], finding["file"], finding["file_sha256"])
        if key in seen:
            continue
        seen.add(key)
        out.append({"id": finding["id"], "file": finding["file"],
                    "file_sha256": finding["file_sha256"],
                    "severity": finding.get("severity", "")})
    out.sort(key=lambda e: (e["file"], e["id"], e["file_sha256"]))
    return out


def check_destination(path: str) -> None:
    """Refuse a baseline destination that is not an ordinary file (or a new one) in a writable folder.

    Called before the scan starts and again just before the file is moved into place. A
    symlink is refused rather than followed or replaced: a baseline path that points
    somewhere else is almost never what the CI config meant.
    """
    folder = os.path.dirname(os.path.abspath(path))
    if os.path.islink(path):
        raise BaselineError(f"could not write baseline {path}: it is a symbolic link")
    if os.path.lexists(path):
        if os.path.isdir(path):
            raise BaselineError(f"could not write baseline {path}: it is a directory")
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise BaselineError(f"could not write baseline {path}: it is not a regular file")
    if not os.path.isdir(folder):
        raise BaselineError(f"could not write baseline {path}: folder does not exist")
    if not os.access(folder, os.W_OK | os.X_OK):
        raise BaselineError(f"could not write baseline {path}: folder is not writable")


def write(path: str, findings, scanner_version: str) -> int:
    """Write a baseline for `findings` and return the number of entries.

    The file is written beside the target and moved into place, so a failed write never
    leaves a half-written baseline that the next run would read as a different list.
    """
    entries = entries_for(findings)
    for entry in entries:
        if not _entry_ok(entry):
            raise BaselineError(
                f"could not write baseline {path}: {entry['file']!r} cannot be recorded "
                "(a baseline path uses forward slashes with no empty, . or .. part, no backslash "
                "and no NUL); nothing was written")
    doc = {"schema": SCHEMA, "scanner_version": scanner_version, "entries": entries}
    payload = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_BYTES:
        raise BaselineError(
            f"could not write baseline {path}: {len(entries)} entries make a file larger than "
            f"{MAX_BYTES // (1024 * 1024)} MiB, which a later run would refuse to read; "
            "nothing was written")
    directory = os.path.dirname(os.path.abspath(path))
    check_destination(path)
    try:
        fd, tmp = tempfile.mkstemp(prefix=".baseline-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:       # exactly the bytes that were measured
                handle.write(payload)
            check_destination(path)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise BaselineError(f"could not write baseline {path}: {exc.strerror or exc}") from None
    return len(entries)


def fails(severities, level: str) -> bool:
    """True when any severity in the list reaches the `--fail-on` level."""
    threshold = FAIL_ON_LEVELS[level]
    return any(SEVERITY_RANK.get(s, 1) >= threshold for s in severities)
