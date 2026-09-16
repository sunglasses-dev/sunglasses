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
import pathlib
from pathlib import Path

from .. import install as _install

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
EXIT_OPERATIONAL = 2   # R-DOCTOR-R3a: we could not open it. Not doubt, not clean.

# ── the self-test (T10.R1) ─────────────────────────────────────────────────
SELF_TEST_CHECKS = ("initialized", "s1_forward_byte_equal", "s2_block_schema",
                    "deadline", "disconnect")
REQUIRED_CONTROLS = ("constant_allow", "constant_deny")
SKIPPED_INVOCATION_CONTROL = "skipped_invocation"
# All three are REQUIRED. skipped_invocation is the product-level form of the
# defect that let nine of eighteen CLI tests pass against a process which never
# started: a route self-test that cannot tell "inspected and allowed" from
# "never asked" is that bug with stakes.
REQUIRED_CONTROLS = ("constant_allow", "constant_deny", SKIPPED_INVOCATION_CONTROL)

# R-DOCTOR-R3b. The contract's figure. Not an argument, not an environment
# variable: a bound a caller can move is not a bound. A miss is a FAIL like any
# other check, and the honesty lives in the printed figure rather than in a
# softer number or a retry.
DEADLINE_BOUND_MS = 2250
DEADLINE = "DEADLINE"
SCHEMA = "SCHEMA"
CONTROL_MUST_BE = "FAIL"
CHECK_RESULTS = ("PASS", "FAIL", "SKIPPED")
SELF_TEST_UNAVAILABLE = "SELF_TEST_UNAVAILABLE"

# The only details this report will ever print. An allowlist rather than a
# string, because `detail` is the field a future caller reaches for when it has
# an exception to explain, and the doctor's report is read in a terminal by the
# operator T10.R3 forbids showing upstream stderr to.
DETAILS = ("", SELF_TEST_UNAVAILABLE)

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
    self_test_failure_class: str = ""
    self_test_failed_checks: list = field(default_factory=list)


# ── T10.R1 · an instrument that cannot fail proves nothing ─────────────────

@dataclass
class SelfTestVerdict:
    """Kept as fields rather than a bool so a reader can tell WHICH check failed.
    An operator repairs a slow box and a malformed block differently."""
    ok: bool
    failed_checks: list = field(default_factory=list)
    failure_class: str = ""
    controls_valid: bool = True


def deadline_line(measured_ms) -> str:
    """The measured figure beside the bound. R-DOCTOR-R3b: an operator who sees
    `3100 ms measured against a 2250 ms bound` learns something true and
    actionable; one who sees "the machine may have been busy" learns to ignore
    the doctor."""
    return f"deadline {measured_ms} ms measured against a {DEADLINE_BOUND_MS} ms bound"


def judge_self_test(checks, controls) -> SelfTestVerdict:
    """The whole R1 decision, in one place.

    Controls first: if the instrument agreed with something that always says the
    same thing, nothing the checks report means anything, so the run is void
    rather than the control being noted and ignored.
    """
    controls = dict(controls or {})
    valid = self_test_valid(controls)
    failed = [name for name in SELF_TEST_CHECKS
              if dict(checks or {}).get(name) != "PASS"]
    cls = ""
    if failed:
        cls = DEADLINE if failed == ["deadline"] else SCHEMA
    return SelfTestVerdict(ok=bool(valid and not failed),
                           failed_checks=failed,
                           failure_class=cls,
                           controls_valid=valid)


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


def _sha256_of_file(path):
    """`install`'s digest, so a hash the doctor prints and a hash `install`
    recorded can never be computed two different ways."""
    return _install._digest_file(path)


def artifact_path():
    """The proxy entry point, or the path it WOULD have, when this build has
    none.

    A build without `proxy/__main__.py` cannot verify any route, and that is a
    fact about the build rather than an error to raise at a reader. Returning
    the absent path lets `install.classify` do what it already does with an
    artifact it cannot digest: report UNVERIFIED. Nothing is WRAPPED against an
    artifact that is not there, which is the honest answer and the safe one.
    """
    try:
        return _install.resolve_artifact(), True
    except _install.ArtifactUnresolved:
        return pathlib.Path(_install.__file__).resolve().parent / "proxy" / "__main__.py", False


def artifact_identity(artifact=None):
    """This artifact, by path and by hash of that path's bytes.

    The artifact is the proxy ENTRY POINT that `install` wires, not the
    interpreter. The starting version returned `sys.executable`, and since every
    wrapper on the machine runs under some python, hashing the interpreter makes
    the hash half of "path AND hash" agree with anything sharing a python. A
    build with no entry point raises, which is the same refusal `install` makes.
    """
    path = pathlib.Path(artifact) if artifact is not None else artifact_path()[0]
    return str(path), _sha256_of_file(path)


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
    # `install.classify` digests the artifact itself, so there is no second
    # hash to pass around and no way for the two to disagree.
    artifact = artifact if artifact is not None else artifact_path()[0]

    entries, unreadable = [], []
    for label, path in sources:
        path = Path(path)
        if not path.exists():
            continue
        # The SAME parser `install` uses, so a document install REFUSES is
        # never read here as if it were fine. A duplicate-key config resolves
        # silently under bare `json.loads`, and reporting on a document we
        # quietly resolved on the user's behalf is a different file than theirs.
        try:
            raw = path.read_bytes()
            doc = _install._parse(raw, path)
            servers = _install._servers(doc, path)
        except (OSError, _install.ConfigIOError):
            unreadable.append(str(path))
            continue
        for name, spec in servers.items():
            entries.append(Entry(
                name=name, source=label,
                state=_install.classify(spec, artifact=artifact)))
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


def process_exit_code(outcome, self_test_ok, unreadable=()) -> int:
    """R3's precedence, `1 > 2 > 3 > 0` (R-DOCTOR-R3a, and AGENTS.md's own
    order).

    A failed self-test is 1 regardless of how clean the inventory reads, because
    an instrument that failed has no standing to report on anything else, and a
    launched route that failed is 1 because we watched it fail. A file we could
    not open is 2: an operational error about our own access, not doubt about a
    route, and it must never read as 3 and never as 0. Only what is genuinely
    unknown about a route gets the doubt code.
    """
    if not self_test_ok:
        return EXIT_FAILED
    if any(w["result"] == "FAIL" for w in outcome.per_wrapper):
        return EXIT_FAILED
    if unreadable:
        return EXIT_OPERATIONAL
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

    result = (self_test or default_self_test)()
    # 2-tuple is the seam's original shape; 3-tuple adds the named checks so a
    # deadline miss is distinguishable from a schema miss in the report.
    if len(result) == 3:
        ok, controls, checks = result
    else:
        ok, controls = result
        checks = {}
    controls = dict(controls or {})
    verdict = judge_self_test(checks, controls)
    self_test_ok = bool(ok) and verdict.ok
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
                  exit_code=process_exit_code(outcome, self_test_ok,
                                             unreadable=unreadable),
                  self_test_ok=self_test_ok,
                  self_test_controls={k: v for k, v in controls.items()
                                      if v in CHECK_RESULTS},
                  self_test_checks=_safe_checks(checks),
                  self_test_failure_class=verdict.failure_class,
                  self_test_failed_checks=list(verdict.failed_checks),
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
                      "checks": report.self_test_checks,
                      "failed": report.self_test_failed_checks,
                      "failure_class": report.self_test_failure_class,
                      "detail": (report.self_test_detail
                                 if report.self_test_detail in DETAILS else "")},
        "per_wrapper": report.outcome.per_wrapper,
        "inventory": report.outcome.inventory,
        "aggregate": report.outcome.aggregate,
        "route_checks": report.route_checks,
        "exit_code": report.exit_code,
    }


# ── T10.R4 to R6 ───────────────────────────────────────────────────────────
#
# Not here. R-DOCTOR-OWNER (2026-09-15): `sunglasses/install.py` is the one
# implementation of install, uninstall and classify, because it is the one that
# has been through 48 independent property controls. The doctor imports it and
# never redefines it, so R2's classifier and R4's already-wrapped check are the
# same function by construction rather than by two authors agreeing.
