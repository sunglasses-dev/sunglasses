"""T10's doctor, and the difference between doubt and a finding.

Written against `tests/test_proxy_doctor.py` and
`tests/test_proxy_doctor_reader.py`, both committed first from the rows.

This module answers one question, "is my traffic actually going through the
proxy", and the hard part is not the checking, it is what it is allowed to say
when it does not know. T10.R3 makes that asymmetric on purpose. ROUTE_VERIFIED
requires every known source readable, every entry WRAPPED, and every wrapped
route PASSED. Everything else is ROUTE_UNVERIFIED, an unreadable file and an
empty config included, because a config we could not parse is not a config with
nothing in it and an unknown source is not an absent one. A doctor that reports
"verified" on the strength of a file it never opened has told an operator their
traffic is mediated when it may not be, which is the most expensive sentence
this tool can say.

Three codes, and they are three different statements. 0 says verified. 3 says
doubt, some part of the picture is unknown. 1 says a thing we ran failed in
front of us, which is not doubt, and R3 gives it precedence over both.

WHAT IS NOT BUILT YET, stated here rather than stubbed quietly: R1's live
self-test spawns `sys.executable -m sunglasses.proxy` against a bundled echo
server, and neither `sunglasses/proxy/__main__.py` nor that echo server exists
on this branch. `default_self_test` and `default_launcher` therefore report
failure with SELF_TEST_UNAVAILABLE and `run()` exits 1, which is the safe
direction, a doctor that cannot demonstrate mediation must never imply it. They
are the seam the real spawn lands in, and they are injectable so the decision
logic above them is exercised today.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ── classification states (T10.R2) ─────────────────────────────────────────
WRAPPED = "WRAPPED"
DIRECT = "DIRECT"
UNVERIFIED = "UNVERIFIED"

# ── aggregate labels and exit codes (T10.R3) ───────────────────────────────
ROUTE_VERIFIED = "ROUTE_VERIFIED"
ROUTE_UNVERIFIED = "ROUTE_UNVERIFIED"

EXIT_VERIFIED = 0
EXIT_FAILED = 1
EXIT_DOUBT = 3

# ── the self-test (T10.R1) ─────────────────────────────────────────────────
SELF_TEST_CHECKS = ("initialized", "s1_forward_byte_equal", "s2_block_schema",
                    "deadline", "disconnect")
REQUIRED_CONTROLS = ("constant_allow", "constant_deny")
SKIPPED_INVOCATION_CONTROL = "skipped_invocation"
CONTROL_MUST_BE = "FAIL"
CHECK_RESULTS = ("PASS", "FAIL", "SKIPPED")
SELF_TEST_UNAVAILABLE = "SELF_TEST_UNAVAILABLE"

# The module a wrapped command has to be invoking for the entry to be ours.
PROXY_MODULE = "sunglasses.proxy"
ARGV_SEPARATOR = "--"

REASON_CONFIG_CONFLICT = "CONFIG_CONFLICT"
REASON_RESTORED = "RESTORED"
REASON_RESTORED_ENTRY = "RESTORED_ENTRY"


class ConfigIOError(Exception):
    """T10.R6. The config could not be read, parsed or replaced."""


class ConfigConflict(Exception):
    """T10.R4/R5. The config is in a state this tool refuses to guess about."""


@dataclass
class Entry:
    """One server in one source. `passed` defaults to False because nothing has
    been launched yet, and an entry is not proven by having been read."""
    name: str
    source: str
    state: str
    passed: bool = False
    detail: str = ""


@dataclass
class Outcome:
    """R3's three lines, kept as three fields. Collapsing them loses which of
    the three a reader is looking at, and an operator needs the inventory most
    precisely when the aggregate is a failure."""
    aggregate: str
    exit_code: int
    per_wrapper: list = field(default_factory=list)
    inventory: list = field(default_factory=list)


@dataclass
class UninstallOutcome:
    reason: str
    byte_exact: bool
    detail: str
    mutated: bool


@dataclass
class Report:
    outcome: Outcome
    exit_code: int
    self_test_ok: bool
    self_test_controls: dict = field(default_factory=dict)
    self_test_checks: dict = field(default_factory=dict)
    self_test_detail: str = ""
    route_checks: dict = field(default_factory=dict)


# ── T10.R1 · an instrument that cannot fail proves nothing ─────────────────

def self_test_valid(controls) -> bool:
    """True only when both named controls ran and every control that ran FAILED.

    A control is a detector rigged to trip. One reporting PASS means the checks
    agreed with something that always says the same thing, which is exactly as
    much evidence as running nothing, so the whole run is void rather than the
    one control being noted and ignored.
    """
    controls = dict(controls or {})
    if any(name not in controls for name in REQUIRED_CONTROLS):
        return False
    return all(value == CONTROL_MUST_BE for value in controls.values())


def default_self_test():
    """The seam R1's live self-test lands in. See the module docstring: the
    artifact it has to spawn does not exist on this branch, so this reports
    failure rather than an empty pass."""
    return False, {}


def default_launcher(entry):
    """The seam R2's per-route launch lands in. Same reason, same direction."""
    return False, {}


# ── T10.R2 · classification, path AND hash ─────────────────────────────────

def classify(command, artifact, artifact_sha, command_sha=None) -> str:
    """WRAPPED only when the command invokes our module AND resolves to this
    artifact by path and by hash.

    A wrapper naming a DIFFERENT artifact is UNVERIFIED, not WRAPPED, and that
    distinction is the interesting one: something is mediating that traffic and
    it is not this, so reporting it as wrapped would credit our guarantees to a
    binary we have never seen.
    """
    argv = [str(part) for part in (command or [])]
    if not argv:
        return UNVERIFIED
    if not _is_wrapper(argv):
        return DIRECT
    if not _same_path(argv[0], artifact):
        return UNVERIFIED
    if not _same_sha(command_sha, artifact_sha):
        return UNVERIFIED
    return WRAPPED


def _is_wrapper(argv) -> bool:
    """Our module named before the argv separator.

    Only before it. Everything after `--` is the upstream server's own command
    line, and a server that happens to mention this module in its arguments is
    not a wrapper, it is the thing being wrapped.
    """
    head = []
    for part in argv:
        if part == ARGV_SEPARATOR:
            break
        head.append(str(part))
    for part in head:
        if part == PROXY_MODULE or part.startswith(PROXY_MODULE + "."):
            return True
    if head and os.path.basename(head[0]) == "sunglasses" and head[1:2] == ["proxy"]:
        return True
    return False


def _same_path(candidate, artifact) -> bool:
    if not candidate or not artifact:
        return False
    return os.path.realpath(str(candidate)) == os.path.realpath(str(artifact))


def _same_sha(candidate, artifact_sha) -> bool:
    """An absent hash is not a matching hash. R2 says path AND hash, so a
    command we could not hash is unverified rather than given the benefit."""
    if not candidate or not artifact_sha:
        return False
    return str(candidate).lower() == str(artifact_sha).lower()


def artifact_identity():
    """This artifact, by path and by hash of that path's bytes."""
    path = sys.executable
    return path, _sha256_of_file(path)


def default_sources():
    return [("project", Path.cwd() / ".mcp.json"),
            ("user", Path.home() / ".claude.json")]


def read_sources(sources=None, artifact=None, artifact_sha=None, hash_of=None):
    """Read every known source, classify every entry, and name what we could
    not read. Returns (entries, unreadable).

    An unparseable file goes into `unreadable`, never silently into "no entries
    here", because those two produce very different aggregates and only one of
    them is true.
    """
    sources = list(default_sources() if sources is None else sources)
    identity_path, identity_sha = (None, None)
    if artifact is None or artifact_sha is None:
        identity_path, identity_sha = artifact_identity()
    artifact = artifact if artifact is not None else identity_path
    artifact_sha = artifact_sha if artifact_sha is not None else identity_sha
    hash_of = hash_of or _sha256_of_file

    entries, unreadable = [], []
    for label, path in sources:
        path = Path(path)
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            servers = data.get("mcpServers", {})
            if not isinstance(servers, dict):
                raise ValueError("mcpServers is not an object")
        except (OSError, ValueError):
            unreadable.append(str(path))
            continue
        for name, spec in servers.items():
            argv = _argv_of(spec)
            command_sha = hash_of(argv[0]) if argv and _is_wrapper(argv) else None
            entries.append(Entry(
                name=name, source=label,
                state=classify(argv, artifact, artifact_sha,
                               command_sha=command_sha)))
    return entries, unreadable


# ── T10.R3 · the aggregate, and what doubt does to it ──────────────────────

def aggregate(sources_readable, entries, unreadable=()) -> Outcome:
    entries = list(entries)
    unreadable = list(unreadable or [])

    per_wrapper = [{"name": e.name, "source": e.source,
                    "result": "PASS" if e.passed else "FAIL"}
                   for e in entries if e.state == WRAPPED]
    inventory = [{"name": e.name, "source": e.source, "state": e.state}
                 for e in entries]
    # An unreadable source is NAMED, never omitted. Omitting it is how a file
    # we could not open becomes, in a reader's head, a file with nothing in it.
    inventory += [{"name": None, "source": path, "state": UNVERIFIED,
                   "detail": "source could not be read"} for path in unreadable]

    verified = (bool(sources_readable)
                and not unreadable
                and bool(entries)
                and all(e.state == WRAPPED and e.passed for e in entries))
    return Outcome(
        aggregate=ROUTE_VERIFIED if verified else ROUTE_UNVERIFIED,
        exit_code=EXIT_VERIFIED if verified else EXIT_DOUBT,
        per_wrapper=per_wrapper,
        inventory=inventory)


def process_exit_code(outcome, self_test_ok) -> int:
    """R3's precedence. A failed self-test is exit 1 regardless of how clean the
    inventory reads, because an instrument that failed has no standing to report
    on anything else, and a launched route that failed is exit 1 because we
    watched it fail. Only what is merely unknown gets the doubt code."""
    if not self_test_ok:
        return EXIT_FAILED
    if any(w["result"] == "FAIL" for w in outcome.per_wrapper):
        return EXIT_FAILED
    return outcome.exit_code


def run(sources=None, artifact=None, artifact_sha=None, hash_of=None,
        self_test=None, launcher=None) -> Report:
    """Read, classify, self-test, launch every wrapped route, then aggregate.

    Every part above is called from here. On 2026-09-13 a review of this lane
    found five components built and a reader that invoked none of them, so the
    order below is the product and the helpers are not.
    """
    entries, unreadable = read_sources(sources=sources, artifact=artifact,
                                       artifact_sha=artifact_sha,
                                       hash_of=hash_of)

    ok, controls = (self_test or default_self_test)()
    controls = dict(controls or {})
    self_test_ok = bool(ok) and self_test_valid(controls)
    detail = "" if controls else SELF_TEST_UNAVAILABLE

    launch = launcher or default_launcher
    route_checks = {}
    for entry in entries:
        if entry.state != WRAPPED:
            continue
        passed, checks = launch(entry)
        entry.passed = bool(passed)
        route_checks[f"{entry.source}:{entry.name}"] = _safe_checks(checks)

    outcome = aggregate(sources_readable=not unreadable, entries=entries,
                        unreadable=unreadable)
    return Report(outcome=outcome,
                  exit_code=process_exit_code(outcome, self_test_ok),
                  self_test_ok=self_test_ok,
                  self_test_controls={k: v for k, v in controls.items()
                                      if v in CHECK_RESULTS},
                  self_test_checks={},
                  self_test_detail=detail,
                  route_checks=route_checks)


def _safe_checks(checks) -> dict:
    """Named checks with allowlisted verdicts, nothing else.

    R3's last sentence is that the doctor never prints upstream stderr, and the
    way that promise gets broken is a dict passed through whole. Both the key
    and the value are allowlisted, because a check name we recognise carrying an
    exception string is the same leak by a shorter route.
    """
    return {name: value for name, value in dict(checks or {}).items()
            if name in SELF_TEST_CHECKS and value in CHECK_RESULTS}


def render(report) -> dict:
    """The three lines plus the self-test, as data, carrying nothing that came
    from an upstream process except an allowlisted verdict."""
    return {
        "self_test": {"valid": report.self_test_ok,
                      "controls": report.self_test_controls,
                      "detail": report.self_test_detail},
        "per_wrapper": report.outcome.per_wrapper,
        "inventory": report.outcome.inventory,
        "aggregate": report.outcome.aggregate,
        "route_checks": report.route_checks,
        "exit_code": report.exit_code,
    }


# ── T10.R4 to R6 · the install transaction ─────────────────────────────────

def install(config, name, argv, root=None, fail_write=None) -> dict:
    """Wrap one entry, transactionally, recording enough to undo it exactly."""
    config = Path(config)
    root = _root(root)
    raw, data = _load(config)
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or name not in servers:
        raise ConfigConflict(f"no server named {name} in {config}")

    entry = servers[name]
    store = root / "proxy" / "installs"
    if _is_wrapper(_argv_of(entry)):
        # R4: idempotent, and never a wrapper around a wrapper. That one
        # inspects its own output, which is a loop as well as a lie.
        record = _read_record(store, name) or {}
        sha = _sha256_bytes(raw)
        return {**record,
                "original_entry": record.get("original_entry", entry),
                "installed_entry": entry,
                "file_sha_before": sha,
                "file_sha_after": sha,
                "original_bytes_path": record.get("original_bytes_path"),
                "already_wrapped": True}

    installed = _wrap(entry, list(argv))
    store.mkdir(parents=True, exist_ok=True)
    bytes_path = store / f"{name}.original.json"
    record_path = store / f"{name}.json"
    record = {"name": name,
              "config": str(config),
              "original_entry": entry,
              "installed_entry": installed,
              "file_sha_before": _sha256_bytes(raw),
              "file_sha_after": None,
              "original_bytes_path": str(bytes_path),
              "status": "pending"}

    # The record before the thing it records. If we die between these two
    # writes the original bytes exist and no record claims an install, which
    # uninstall reads as CONFIG_CONFLICT and refuses to touch. The other order
    # loses the original at exactly the moment it becomes the only copy.
    _atomic_write_bytes(bytes_path, raw)
    _atomic_write_bytes(record_path, _json_bytes(record))

    updated = dict(data)
    updated["mcpServers"] = {**servers, name: installed}
    new_raw = _json_bytes(updated)
    try:
        _atomic_write_bytes(config, new_raw, fail_write=fail_write,
                            preserve_mode=True)
    except OSError as exc:
        # R6: original intact, no half-written JSON, no success output, and no
        # record left behind pointing at an install that did not happen.
        record_path.unlink(missing_ok=True)
        bytes_path.unlink(missing_ok=True)
        raise ConfigIOError(str(exc)) from exc

    record["file_sha_after"] = _sha256_bytes(new_raw)
    record["status"] = "installed"
    _atomic_write_bytes(record_path, _json_bytes(record))
    return {**record, "already_wrapped": False}


def uninstall(config, name, root=None) -> UninstallOutcome:
    """Byte-exact when the file has not moved on, entry-only when it has, and
    nothing at all when the state is not one we recognise."""
    config = Path(config)
    store = _root(root) / "proxy" / "installs"
    record = _read_record(store, name)
    try:
        raw, data = _load(config)
    except ConfigIOError:
        return UninstallOutcome(REASON_CONFIG_CONFLICT, False,
                                "the config could not be read", False)

    servers = data.get("mcpServers")
    if (record is None or record.get("status") != "installed"
            or not isinstance(servers, dict) or name not in servers):
        return UninstallOutcome(
            REASON_CONFIG_CONFLICT, False,
            "no install record for this entry, so the original is not known",
            False)
    if servers[name] != record.get("installed_entry"):
        return UninstallOutcome(
            REASON_CONFIG_CONFLICT, False,
            "the entry on disk is not the one this tool installed", False)

    if _sha256_bytes(raw) == record.get("file_sha_after"):
        original = Path(record["original_bytes_path"]).read_bytes()
        _atomic_write_bytes(config, original, preserve_mode=True)
        return UninstallOutcome(REASON_RESTORED, True,
                                "byte-exact restore of the retained original",
                                True)

    # R5: somebody else edited this file after we wrote it, so a byte-exact
    # restore would throw their edit away. Invert our entry, say what we could
    # not promise, and leave every other entry where it is.
    updated = dict(data)
    updated["mcpServers"] = {**servers, name: record["original_entry"]}
    _atomic_write_bytes(config, _json_bytes(updated), preserve_mode=True)
    return UninstallOutcome(REASON_RESTORED_ENTRY, False,
                            "entry restored, file not byte-identical", True)


# ── plumbing ───────────────────────────────────────────────────────────────

def _root(root):
    return Path(root) if root is not None else Path.home() / ".sunglasses"


def _argv_of(spec):
    if isinstance(spec, str):
        return [spec]
    if not isinstance(spec, dict):
        return []
    command = spec.get("command")
    if not command:
        return []
    return [command] + [str(a) for a in spec.get("args", []) or []]


def _wrap(entry, argv):
    installed = {"command": argv[0],
                 "args": list(argv[1:]) + [ARGV_SEPARATOR] + _argv_of(entry)}
    if isinstance(entry, dict) and entry.get("env"):
        installed["env"] = entry["env"]
    return installed


def _load(config):
    try:
        raw = Path(config).read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ConfigIOError(str(exc)) from exc
    if not isinstance(data, dict):
        raise ConfigIOError("the config is not a JSON object")
    return raw, data


def _read_record(store, name):
    try:
        return json.loads((Path(store) / f"{name}.json").read_text("utf-8"))
    except (OSError, ValueError):
        return None


def _json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def _sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha256_of_file(path):
    try:
        return _sha256_bytes(Path(path).read_bytes())
    except OSError:
        return None


def _atomic_write_bytes(path, data, fail_write=None, preserve_mode=False):
    """tmp, fsync, replace. The replace is the only moment the target changes,
    so an interruption anywhere before it leaves the original exactly as it
    was, which is R6."""
    path = Path(path)
    mode = None
    if preserve_mode and path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
    tmp = path.with_name(f"{path.name}.sg-tmp-{os.getpid()}")
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if fail_write is not None:
            raise fail_write
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
