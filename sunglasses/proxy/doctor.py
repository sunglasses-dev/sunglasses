"""The doctor, and the difference between doubt and a finding.

Written against `tests/test_proxy_doctor.py` and
`tests/test_proxy_doctor_reader.py`, both committed first from the rows.

This module answers one question, "is my traffic actually going through the
proxy", and the hard part is not the checking, it is what it is allowed to say
when it does not know. Contract row 10.3 makes that asymmetric on purpose. ROUTE_VERIFIED
requires every known source readable, every entry WRAPPED, and every wrapped
route PASSED. Everything else is ROUTE_UNVERIFIED, an unreadable file and an
empty config included, because a config we could not parse is not a config with
nothing in it and an unknown source is not an absent one. A doctor that reports
"verified" on the strength of a file it never opened has told an operator their
traffic is mediated when it may not be, which is the most expensive sentence
this tool can say.

Three codes, and they are three different statements. 0 says verified. 3 says
doubt, some part of the picture is unknown. 1 says a thing we ran failed in
front of us, which is not doubt, and contract row 10.3 gives it precedence over both.
An instrument that never ran is doubt, not a failure: a self-test that was not
run is 3, and only a self-test that ran and did not pass is 1.

PER-ROUTE LAUNCH (contract row 10.2). `default_launcher` starts nothing, so a plain
`doctor` leaves every wrapped route NOT_RUN and exits 3 (not verifiable), never 0: a doctor
that cannot demonstrate mediation of a route must never imply it. Starting the user's own
servers is opt-in: `run(launch_routes=True)` (`doctor --launch-routes`) builds a
`route_launch.RouteLauncher`, which starts each wrapped route in the user's own file once. It
reads no word from the route into the report: only the verdicts and the codes named in this module.
Where the self-test cannot come up (no process groups, the system refuses its folder or a
process, it runs out of time, or the proxy never answers `initialize`) it reports
that nothing ran, with failure_class SELF_TEST_UNAVAILABLE and the five checks
rendered NOT_RUN. Both are injectable so the decision logic above them is
exercised without a spawn.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import sys
import time
from dataclasses import dataclass, field
import pathlib
from pathlib import Path

from .. import install as _install

# ── classification states ────────────────────────────────────────────────
WRAPPED = "WRAPPED"
DIRECT = "DIRECT"
UNVERIFIED = "UNVERIFIED"

# ── aggregate labels and exit codes ──────────────────────────────────────
ROUTE_VERIFIED = "ROUTE_VERIFIED"
ROUTE_UNVERIFIED = "ROUTE_UNVERIFIED"

EXIT_VERIFIED = 0
EXIT_FAILED = 1
EXIT_DOUBT = 3
EXIT_OPERATIONAL = 2   # we could not open it. Not doubt, not clean.

# ── the self-test ───────────────────────────────────────────────────────
SELF_TEST_CHECKS = ("initialized", "s1_forward_byte_equal", "s2_block_schema",
                    "deadline", "disconnect")
REQUIRED_CONTROLS = ("constant_allow", "constant_deny")
SKIPPED_INVOCATION_CONTROL = "skipped_invocation"
# All three are REQUIRED. skipped_invocation is the product-level form of the
# defect that let nine of eighteen CLI tests pass against a process which never
# started: a route self-test that cannot tell "inspected and allowed" from
# "never asked" is that bug with stakes.
REQUIRED_CONTROLS = ("constant_allow", "constant_deny", SKIPPED_INVOCATION_CONTROL)

# The contract's figure. Not an argument, not an environment
# variable: a bound a caller can move is not a bound. A miss is a FAIL like any
# other check, and the honesty lives in the printed figure rather than in a
# softer number or a retry.
DEADLINE_BOUND_MS = 2250
DEADLINE = "DEADLINE"
SCHEMA = "SCHEMA"
CONTROL_MUST_BE = "FAIL"
CHECK_RESULTS = ("PASS", "FAIL", "SKIPPED")
SELF_TEST_UNAVAILABLE = "SELF_TEST_UNAVAILABLE"
# The live self-test started the proxy and it never answered `initialize`
# (no answer in time, or it exited first). The instrument did not come up:
# nothing was checked, so nothing failed. Doubt, with the reason printed.
SELF_TEST_NO_INITIALIZE = "SELF_TEST_NO_INITIALIZE"
# The self-test could not make its private folder or start a process (the
# operating system refused), or it spent its whole allowance with nothing yet
# red. Neither is a completed check, so neither is a failure: doubt, with the
# reason printed.
SELF_TEST_COULD_NOT_START = "SELF_TEST_COULD_NOT_START"
SELF_TEST_OUT_OF_TIME = "SELF_TEST_OUT_OF_TIME"
# OUR word about OUR build, and deliberately NOT in
# CHECK_RESULTS: `_safe_checks` allowlists what an upstream process is allowed
# to say about itself, and a spawned proxy that can report its own checks as
# NOT_RUN can describe away a failure it just produced. This value is only ever
# synthesised in `render`, from a class this module decided.
NOT_RUN = "NOT_RUN"
# A route's verdict is ONE field with three values, written once (`_route_result`)
# and read by every renderer. PASS and FAIL are what a launcher reported; NOT_RUN
# is "nothing launched it", which is not a failure and must never be spelled as one.
ROUTE_RESULTS = ("PASS", "FAIL", NOT_RUN)

# Why a route is NOT_RUN, when `--launch-routes` was given. Codes of our own, never
# a word the route or the operating system said; the sentence for each is ours too.
REASON_NOT_USER_FILE = "NOT_USER_FILE"
REASON_CAP = "CAP"
REASON_NO_INITIALIZE = "NO_INITIALIZE"
REASON_COULD_NOT_START = "COULD_NOT_START"
REASON_OUT_OF_TIME = "OUT_OF_TIME"
REASON_UNSUPPORTED = "UNSUPPORTED"
ROUTE_REASON_TEXT = {
    REASON_NOT_USER_FILE: "project file or other file, not started (only entries in your own "
                          "~/.claude.json are started)",
    REASON_CAP: "not started: cap (16 routes, or fewer than 30 s of the 120 s left)",
    REASON_NO_INITIALIZE: "no `initialize` result in 20 s; this may be the server and not the proxy",
    REASON_COULD_NOT_START: "it could not be started",
    REASON_OUT_OF_TIME: "it used its 30 s allowance before the check could finish",
    REASON_UNSUPPORTED: "it was not started: this machine has no process groups or no readable process list, so its server could not be stopped",
}

# The only details this report will ever print. An allowlist rather than a
# string, because `detail` is the field a future caller reaches for when it has
# an exception to explain, and the doctor's report is read in a terminal by the
# operator who must never be shown upstream stderr.
DETAILS = ("", SELF_TEST_UNAVAILABLE, SELF_TEST_NO_INITIALIZE,
           SELF_TEST_COULD_NOT_START, SELF_TEST_OUT_OF_TIME)

# The module a wrapped command has to be invoking for the entry to be ours.
PROXY_MODULE = "sunglasses.proxy"
ARGV_SEPARATOR = "--"

REASON_CONFIG_CONFLICT = "CONFIG_CONFLICT"
REASON_RESTORED = "RESTORED"
REASON_RESTORED_ENTRY = "RESTORED_ENTRY"


# ONE exception family, install's. Re-exported rather than redefined: two
# `ConfigConflict` types means an `except` in one module silently misses the
# other's, which turns a refusal into a crash.
ConfigIOError = _install.ConfigIOError
ConfigConflict = _install.ConfigConflict


@dataclass
class Entry:
    """One server in one source. `passed` defaults to False because nothing has
    been launched yet, and an entry is not proven by having been read."""
    name: str
    source: str
    state: str
    passed: bool = False
    detail: str = ""
    # `passed` alone cannot say "never launched": False meant both that
    # and "launched and failed", and the JSON rendered the first as FAIL.
    result: str = NOT_RUN
    # The entry as the file holds it, for the launcher alone. Never rendered, never
    # compared, never in a repr: it carries the route's arguments and environment.
    spec: dict = field(default=None, repr=False, compare=False)
    # True for the user's own file (`~/.claude.json`): the only file whose entries
    # `--launch-routes` will start.
    user_file: bool = False
    # Why NOT_RUN, one of the codes above; "" when nothing needs saying.
    reason: str = ""


@dataclass
class Outcome:
    """Contract row 10.3's three lines, kept as three fields. Collapsing them loses which of
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
    # Required controls whose process could not be started: absent from
    # `self_test_controls` because they neither failed nor passed.
    self_test_not_run_controls: list = field(default_factory=list)
    # The self-test's own wall duration, measured in `run`. A field rather than
    # a formatted string so the number can be compared as well as read.
    self_test_measured_ms: int = 0
    # R21 (b): OFF, ON, or KEY_UNUSABLE with the cause `receipts --verify`
    # prints. Our own sentence, never anything an upstream process said.
    receipts_key: str = "OFF"
    receipts_key_cause: str = ""
    # Each stored approval with the folder it is bound to. A server started from another
    # folder has another identity and finds none of these.
    approvals: list = field(default_factory=list)


# ── an instrument that cannot fail proves nothing ───────────────────────

@dataclass
class SelfTestVerdict:
    """Kept as fields rather than a bool so a reader can tell WHICH check failed.
    An operator repairs a slow box and a malformed block differently."""
    ok: bool
    failed_checks: list = field(default_factory=list)
    failure_class: str = ""
    controls_valid: bool = True


def deadline_line(measured_ms) -> str:
    """The measured figure beside the bound. An operator who sees
    `3100 ms measured against a 2250 ms bound` learns something true and
    actionable; one who sees "the machine may have been busy" learns to ignore
    the doctor."""
    return f"deadline {measured_ms} ms measured against a {DEADLINE_BOUND_MS} ms bound"


def judge_self_test(checks, controls) -> SelfTestVerdict:
    """The whole contract row 10.1 decision, in one place.

    Controls first: if the instrument agreed with something that always says the
    same thing, nothing the checks report means anything, so the run is void
    rather than the control being noted and ignored.
    """
    controls = dict(controls or {})
    checks = dict(checks or {})
    valid = self_test_valid(controls)
    failed = [name for name in SELF_TEST_CHECKS if checks.get(name) != "PASS"]

    # Nothing reported at all -- no checks AND no controls -- is an instrument that
    # never ran, and it is a different fact from an instrument that ran and
    # disagreed with us. `default_self_test`'s `(False, {})` must not fall through
    # to SCHEMA with all five names in `failed_checks`: a build without a live
    # self-test would tell its operator that five checks had failed when not one of
    # them had been performed. A name in `failed_checks` is an assertion that the
    # check RAN and did not pass.
    #
    # The boundary is the controls, not the checks. A control is rigged to
    # trip, so a run that produced controls is a run that happened, and a check
    # missing from it is a real miss that stays SCHEMA. Absence is only ever
    # the whole instrument.
    #
    # `ok` is untouched, so the self-test still does not count as passed and
    # `process_exit_code` returns 3 here (doubt, never 0): a doctor that cannot
    # demonstrate mediation must never imply it. The exit code is honest; the
    # words must be too.
    if not checks and not controls:
        return SelfTestVerdict(ok=False,
                               failed_checks=[],
                               failure_class=SELF_TEST_UNAVAILABLE,
                               controls_valid=False)

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
    """The seam contract row 10.1's live self-test lands in.

    Spawns the installed proxy in front of the bundled echo server
    (`live_selftest`). Where processes cannot be grouped (Windows) it reports
    `(False, {})`, which is "never ran", never an empty pass.
    """
    from . import live_selftest
    return live_selftest.run()


def default_launcher(entry):
    """The seam contract row 10.2's per-route launch lands in. Same reason, same direction.

    `None`, not `False`: `False` is what every reader takes to mean "launched
    and failed", so a build with no launcher would report every wrapped route as
    FAIL in `--json` while the text said nothing was marked failed. Nothing was
    launched, and the verdict says so.
    """
    return None, {}


def _route_result(passed) -> str:
    """The one place a launcher's answer becomes a verdict: True is PASS, False
    is FAIL, and `None` (no launch happened) is NOT_RUN."""
    if passed is None:
        return NOT_RUN
    return "PASS" if passed else "FAIL"


# ── classification, path AND hash ───────────────────────────────────────

# ONE classifier, install's. Re-exported rather than
# redefined. The original lived here with a different signature, unreachable
# from inside this module and perfectly reachable as `doctor.classify(...)`
# from outside, which is exactly the disagreement a single classifier prevents.
classify = _install.classify


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


def _is_user_file(label, path) -> bool:
    """The user's own `~/.claude.json`: its own label, or a `--config` path that names it.

    A project file is never the user's, whatever it resolves to: a `.mcp.json` that is a
    link to the user file would otherwise start the user's servers from a cloned folder.
    That holds for a path named with `--config` too, so the path is compared as it was
    written (no links followed, no `..`), and only the user file's own name matches.
    """
    if label == "project":
        return False
    if label == "user":
        return True
    try:
        if ".." in Path(path).parts:
            return False
        return os.path.abspath(path) == os.path.abspath(Path.home() / ".claude.json")
    except (OSError, ValueError):
        return False


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
        # ABSENCE IS ENOENT AND NOTHING ELSE. This used to be
        # `if not path.exists(): continue`, and `Path.exists()` answers False
        # for EACCES and ENOTDIR as well as for a file that is not there. So a
        # real config inside a directory with search permission removed was
        # reported as ABSENT: never named, never counted unreadable, and the
        # run exited 0 while the other source read WRAPPED. "I could not look"
        # collapsed into "there was nothing to see", which is the single
        # collapse this rule exists to prevent, and it collapsed the safe way round.
        #
        # We probe by READING. An error on a real path is operational, is
        # named, and drives exit 2.
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            continue
        except OSError:
            unreadable.append(str(path))
            continue
        # The SAME parser `install` uses, so a document install REFUSES is
        # never read here as if it were fine. A duplicate-key config resolves
        # silently under bare `json.loads`, and reporting on a document we
        # quietly resolved on the user's behalf is a different file than theirs.
        try:
            doc = _install._parse(raw, path)
            servers = _install._servers(doc, path)
        except (OSError, _install.ConfigIOError):
            unreadable.append(str(path))
            continue
        user_file = _is_user_file(label, path)
        for name, spec in servers.items():
            entries.append(Entry(
                name=name, source=label,
                state=_install.classify(spec, artifact=artifact),
                spec=spec, user_file=user_file))
    return entries, unreadable


# ── the aggregate, and what doubt does to it ────────────────────────────

def aggregate(sources_readable, entries, unreadable=()) -> Outcome:
    entries = list(entries)
    unreadable = list(unreadable or [])

    per_wrapper = [{"name": e.name, "source": e.source,
                    "result": e.result,
                    # Only where there is a reason, so a report without a launch is
                    # the document it always was.
                    **({"reason": e.reason} if e.reason in ROUTE_REASON_TEXT else {})}
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


def receipts_key_status(home=None):
    """(OFF | ON | KEY_UNUSABLE, cause). Signing on with a key that cannot
    sign stops every wrapped route's proxy before it starts, so the
    doctor names it rather than leaving the user a route that will not start
    and no reason. No key imports none of the signing code."""
    import pathlib
    if home is None:
        from ..firewall import sunglasses_home
        home = sunglasses_home()
    home = pathlib.Path(home)
    from ..receipts import optin
    try:
        # R56: a directory that cannot be listed is never OFF. The route's
        # proxy would refuse to start on it, so the doctor says why.
        if not optin.opted_in(home):
            return "OFF", ""
        optin.signer(home)
    except (optin.KeyUnusable, OSError) as cause:
        return "KEY_UNUSABLE", str(cause)
    return "ON", ""


def process_exit_code(outcome, self_test_ok, unreadable=(), key_unusable=False,
                      self_test_unavailable=False) -> int:
    """Contract row 10.3's precedence as this function applies it: a failure
    we know about is 1, an operational error is 2, doubt about a route is 3, and
    a clean run is 0.

    A self-test that ran and did not pass is 1 regardless of how clean the
    inventory reads, because an instrument that failed has no standing to report
    on anything else, and a launched route that failed is 1 because we watched it
    fail. A self-test that never ran (`self_test_unavailable`) is not a failure
    we watched: it is doubt, 3, and it is never 0 whatever the routes say. A file
    we could not open is 2: an operational error about our own access, not doubt
    about a route, and it must never read as 3 and never as 0. Only what is
    genuinely unknown about a route gets the doubt code.
    """
    if not self_test_ok and not self_test_unavailable:
        return EXIT_FAILED
    if any(w["result"] == "FAIL" for w in outcome.per_wrapper):
        return EXIT_FAILED
    if key_unusable:
        # R21 (b): every wrapped route refuses to start and every hook call
        # asks. That is a failure we know, not doubt, whatever a launch said.
        return EXIT_FAILED
    if unreadable:
        return EXIT_OPERATIONAL
    if self_test_unavailable:
        return EXIT_DOUBT
    return outcome.exit_code


def run(sources=None, artifact=None, artifact_sha=None, hash_of=None,
        self_test=None, launcher=None, home=None, approvals_root=None,
        launch_routes=False) -> Report:
    """Read, classify, self-test, launch every wrapped route, then aggregate.

    Every part above is called from here. On 2026-09-13 a review of this lane
    found five components built and a reader that invoked none of them, so the
    order below is the product and the helpers are not.
    """
    entries, unreadable = read_sources(sources=sources, artifact=artifact,
                                       artifact_sha=artifact_sha,
                                       hash_of=hash_of)

    # MEASURED HERE, so the figure in the report is one we
    # took rather than one we were handed. `deadline_line` existed, was called
    # by nothing, and my own control exercised the formatter alone -- so it
    # passed while the product emitted neither the measurement nor the bound.
    # A helper with a test and no caller is not a feature.
    started = time.monotonic_ns()
    result = (self_test or default_self_test)()
    measured_ms = (time.monotonic_ns() - started) // 1_000_000
    # 2-tuple is the seam's original shape; 3-tuple adds the named checks so a
    # deadline miss is distinguishable from a schema miss in the report; the
    # 4th is the live self-test's own timing and reason, which are ours to
    # take from it: a whole-call figure would charge the spawns to the bound.
    info = {}
    if len(result) == 4:
        ok, controls, checks, info = result
        info = dict(info or {})
        if "deadline_ms" in info:
            measured_ms = int(info["deadline_ms"])
    elif len(result) == 3:
        ok, controls, checks = result
    else:
        ok, controls = result
        checks = {}
    controls = dict(controls or {})
    verdict = judge_self_test(checks, controls)
    # Never ran, as against ran and did not pass: the seam said "not ok" and
    # reported neither checks nor controls. An instrument that claims ok with
    # nothing to show for it is contradicting itself, and stays a failure.
    # A control whose process could not be started was not run, which is neither
    # a catch nor a miss: the checks beside it ran against an instrument nobody
    # could vouch for. The whole self-test is then unavailable, and every check
    # keeps the state it really had.
    not_run_controls = [name for name in (info.get("not_run_controls") or ())
                        if name in REQUIRED_CONTROLS]
    failure_class = verdict.failure_class
    failed_checks = list(verdict.failed_checks)
    if not_run_controls:
        ok = False
        failure_class = SELF_TEST_UNAVAILABLE
        failed_checks = []
    self_test_ok = bool(ok) and verdict.ok and not not_run_controls
    self_test_unavailable = (not ok) and failure_class == SELF_TEST_UNAVAILABLE
    detail = info.get("detail") or ("" if controls else SELF_TEST_UNAVAILABLE)

    route_checks = {}
    # `launch_routes` starts the user's own servers, so it is asked for by name and
    # the launcher is only built when there is a wrapped route to start. A launcher
    # handed in by a caller is used as given.
    with contextlib.ExitStack() as stack:
        launch = launcher
        if launch is None and launch_routes and any(e.state == WRAPPED for e in entries):
            from . import route_launch
            launch = stack.enter_context(route_launch.RouteLauncher())
        launch = launch or default_launcher
        for entry in entries:
            if entry.state != WRAPPED:
                continue
            # `route_result` and not `checks`. This loop used to
            # assign the launcher's checks to the SAME local that held the
            # self-test's, so `self_test_checks` below stored the LAST route's
            # checks: the rendered self-test said its deadline check PASSED while
            # the failure class said DEADLINE. The exit code survived and the
            # evidence named the wrong thing, which is worse than a wrong exit
            # because it is the part an operator reads.
            passed, route_result = launch(entry)
            entry.result = _route_result(passed)
            entry.passed = entry.result == "PASS"
            route_checks[f"{entry.source}:{entry.name}"] = _safe_checks(route_result)

    outcome = aggregate(sources_readable=not unreadable, entries=entries,
                        unreadable=unreadable)
    key_status, key_cause = receipts_key_status(home)
    from . import approvals as _approvals
    if approvals_root is None:
        # The proxy's own tree (`state_root()`), unless this report was given a home of its
        # own, in which case that home's `proxy` folder: a throwaway home reads itself.
        from .serve import state_root
        approvals_root = (pathlib.Path(home) / "proxy") if home is not None else state_root()
    approval_list = _approvals.approval_rows(approvals_root)
    return Report(outcome=outcome,
                  approvals=approval_list,
                  exit_code=process_exit_code(
                      outcome, self_test_ok, unreadable=unreadable,
                      key_unusable=key_status == "KEY_UNUSABLE",
                      self_test_unavailable=self_test_unavailable),
                  receipts_key=key_status,
                  receipts_key_cause=key_cause,
                  self_test_ok=self_test_ok,
                  self_test_controls={k: v for k, v in controls.items()
                                      if v in CHECK_RESULTS},
                  self_test_checks=_safe_checks(checks),
                  self_test_failure_class=failure_class,
                  self_test_failed_checks=failed_checks,
                  self_test_not_run_controls=not_run_controls,
                  self_test_detail=detail,
                  self_test_measured_ms=measured_ms,
                  route_checks=route_checks)


def _safe_checks(checks) -> dict:
    """Named checks with allowlisted verdicts, nothing else.

    Contract row 10.3's last sentence is that the doctor never prints upstream stderr, and the
    way that promise gets broken is a dict passed through whole. Both the key
    and the value are allowlisted, because a check name we recognise carrying an
    exception string is the same leak by a shorter route.
    """
    return {name: value for name, value in dict(checks or {}).items()
            if name in SELF_TEST_CHECKS and value in CHECK_RESULTS}


def render(report) -> dict:
    """The three lines plus the self-test, as data, carrying nothing that came
    from an upstream process except an allowlisted verdict."""
    rendered = {
        "self_test": {"valid": report.self_test_ok,
                      "controls": report.self_test_controls,
                      # An empty dict renders as no information,
                      # and a reader fills that in with whatever they already
                      # believed. The five names carrying NOT_RUN say the true
                      # thing out loud instead.
                      "checks": ({name: NOT_RUN for name in SELF_TEST_CHECKS}
                                 if report.self_test_failure_class
                                 == SELF_TEST_UNAVAILABLE
                                 and not report.self_test_checks
                                 else report.self_test_checks),
                      "failed": report.self_test_failed_checks,
                      "failure_class": report.self_test_failure_class,
                      "detail": (report.self_test_detail
                                 if report.self_test_detail in DETAILS else ""),
                      # Measured beside the bound, both as the number and as
                      # the line an operator reads. The contract asks for the
                      # figure, and a figure the product never prints is not a
                      # figure anybody gets.
                      "measured_ms": report.self_test_measured_ms,
                      "bound_ms": DEADLINE_BOUND_MS,
                      "deadline": deadline_line(report.self_test_measured_ms)},
        "per_wrapper": report.outcome.per_wrapper,
        "inventory": report.outcome.inventory,
        "aggregate": report.outcome.aggregate,
        "route_checks": report.route_checks,
        "receipts_key": {"status": report.receipts_key,
                         "cause": report.receipts_key_cause},
        "exit_code": report.exit_code,
    }
    if report.self_test_not_run_controls:
        rendered["self_test"]["not_run_controls"] = list(report.self_test_not_run_controls)
    # Only when there are approvals to show: a machine with none prints the document it always
    # printed, byte for byte.
    if report.approvals:
        rendered["approvals"] = report.approvals
    return rendered


# ── install and uninstall ───────────────────────────────────────────────
#
# Not here. `sunglasses/install.py` is the one implementation of install,
# uninstall and classify, so there is one implementation to test and to trust.
# The doctor imports it and never redefines it,
# so the classifier and the already-wrapped check are the same function by
# construction rather than by two authors agreeing.
