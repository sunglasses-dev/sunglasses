"""A CPU time limit for each rule of one scan, and an optional one for the scan as a whole: once the scan's limit is used, no further rule expression starts.

What it is for. A rule's expression can take far longer on one text than its length
explains. The limit ends that rule alone, says so in the result, and the scan goes on
with the other rules.

Whose timer it is. The limit counts the CPU seconds of this process (ITIMER_VIRTUAL and
SIGVTALRM), so a busy machine cannot make an honest scan late, and the SIGALRM and the
real-time timer a host program may use (the agent hook's own lane limit among them) are
never touched. The timer is taken only when it is free: a POSIX process, the main thread,
SIGVTALRM not blocked, no virtual timer running and the handler at its default. Anything
else belongs to the host, so it is left exactly as found and the answer is
`TimeLimitUnavailable`, never a scan that quietly runs with no limit.

What the limit counts. ONE rule's CPU seconds, summed over every place the scan visits that
rule (each view, the negation check, the occurrence walk) and over every scan that shares the
time limit (the UTF-7 view, a file scan's pieces). A rule that ended is not visited again.

What a limit does not do. It does not stop the work of a scan outside its rules, and it acts after the limit is reached, not at it: the timer counts user CPU, and its signal is handled when the interpreter next checks for one. A scan that reaches a limit takes longer than that limit.

Scans that nest. Every engine that scans inside one scope shares its time limit. A rule counts at its own severity, and at the stricter one where two engines carry one id at two severities. A scan call that starts inside another one adds to the same record. When a rule's open window reaches a limit, every rule asked for inside that window is reported as not finished with it. The CPU seconds a rule uses inside another rule's open window count for the rule whose window is open. A rule that has ended is not run again at any depth, and each scan call that asks for it names it.

The two stop signals are BaseException on purpose: the engine has `except Exception` blocks,
and a stop that one of them could swallow is not a stop. Each is raised only while a rule's
call is live and is caught by the call that armed the timer.
"""

import contextlib
import signal
import threading
import time

# The limits the command line and the MCP server use: CPU seconds for one rule in one scan, and CPU seconds for one scan as a whole.
DEFAULT_RULE_S = 60.0
DEFAULT_SCAN_S = 600.0

_NEEDED = ("setitimer", "getitimer", "ITIMER_VIRTUAL", "SIGVTALRM", "pthread_sigmask", "SIG_BLOCK")


class TimeLimitUnavailable(Exception):
    """The time limit cannot be taken here, so the scan did not run.

    It derives from Exception directly, never from RuntimeError or ValueError: a caller who
    catches those around a scan must not swallow this and carry on without a limit."""


class _RuleTimeout(BaseException):
    """The rule's CPU seconds are used up."""


class _ScanTimeout(BaseException):
    """The scan's CPU seconds are used up."""


class TimeLimit:
    """The two limits, in CPU seconds. `scan_s` None means no limit on the whole scan.

    `clock` is the CPU clock the accounting reads (time.process_time); a test may pass a
    stub. The timer itself is always the process's own virtual timer."""

    def __init__(self, rule_s=DEFAULT_RULE_S, scan_s=DEFAULT_SCAN_S, clock=None):
        if isinstance(rule_s, bool) or not isinstance(rule_s, (int, float)) or not rule_s > 0:
            raise ValueError("the rule time limit must be a number of seconds above 0")
        if scan_s is not None and (isinstance(scan_s, bool) or not isinstance(scan_s, (int, float))
                                   or not scan_s > 0):
            raise ValueError("the scan time limit must be a number of seconds above 0, or None")
        self.rule_s = float(rule_s)
        self.scan_s = None if scan_s is None else float(scan_s)
        self.clock = clock or time.process_time


def unavailable_reason():
    """Why this process cannot own the virtual timer right now, or None when it can."""
    if not all(hasattr(signal, name) for name in _NEEDED):
        return "this platform has no process CPU timer"
    if threading.current_thread() is not threading.main_thread():
        return "the scan is not on the main thread"
    if signal.SIGVTALRM in signal.pthread_sigmask(signal.SIG_BLOCK, ()):
        return "the host blocks the timer's signal"
    if any(signal.getitimer(signal.ITIMER_VIRTUAL)):
        return "the host has a CPU timer running"
    if signal.getsignal(signal.SIGVTALRM) != signal.SIG_DFL:
        return "the host has its own handler for the timer's signal"
    return None


class _Run:
    """The state of one time limit: what each rule has spent, which ended, and what the current
    scan call has to report. One per outermost scan, kept on the thread (`_SCAN_LOCAL.time_limit`)."""

    def __init__(self, limit, severity_of):
        self.limit = limit
        self.clock = limit.clock
        self.severity_of = severity_of          # rule id -> its severity
        self.t0 = self.clock()
        self.spent = {}                         # rule id -> CPU seconds used so far
        self.ended = {}                         # rule id -> "rule_limit", for the whole run
        self.scan_over = False
        self.live = False                       # True only while a rule's call is armed
        self.depth = 0
        self.window = None                      # the rule whose window is open
        self.inner = []                         # other rules asked for while that window is open
        self.call_depth = 0                     # scan calls open inside one another
        self.engines = {}                       # id of each engine whose severities are in `severity_of`
        self.kind = None                        # which limit the armed timer is for
        self.deadline = None                    # the clock value at which the armed limit is used
        self.call_ended = {}                    # this scan call: rule id -> reason
        self.call_scan_cut = None               # this scan call: [first rule id, worst severity]

    # -- the signal handler (installed once per outermost scan) ----------------------
    def on_signal(self, signum, frame):
        # Idempotent: a signal that arrives while nothing is live (between disarm and arm,
        # or a second one after the first) does nothing and raises nothing.
        if not self.live:
            return
        self.live = False
        raise _ScanTimeout() if self.kind == "scan" else _RuleTimeout()

    # -- one scan call ---------------------------------------------------------------
    def begin_call(self):
        """Open a scan call. Only the outermost one starts a fresh record of ends: a call that
        starts inside another adds to the record that is open, and its answer carries that record."""
        if self.call_depth == 0:
            self.call_ended = {}
            self.call_scan_cut = None
        self.call_depth += 1

    def end_call(self):
        self.call_depth -= 1

    def add_severities(self, engine, severities):
        """Take in the severities of an engine that scans inside this scope. Where both carry an id
        the stricter counts; an id this run does not carry counts at its own severity."""
        if id(engine) in self.engines:
            return
        self.engines[id(engine)] = engine
        for rid, severity in severities.items():
            seen = self.severity_of.get(rid)
            if seen is None or self._rank(severity) > self._rank(seen):
                self.severity_of[rid] = severity

    def _rank(self, severity):
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 3)

    def _cut(self, rid):
        severity = self.severity_of.get(rid, "high")   # a rule we cannot place counts as the strict side
        if self.call_scan_cut is None:
            self.call_scan_cut = [rid, severity]
        elif self._rank(severity) > self._rank(self.call_scan_cut[1]):
            self.call_scan_cut[1] = severity

    def _rule_end(self, rid):
        self.ended[rid] = "rule_limit"
        self.call_ended[rid] = "rule_limit"

    def _scan_end(self, rid):
        self.scan_over = True
        self._cut(rid)

    def admit(self):
        """An ask for an expression inside an open window. Once the limit the window is armed for is used, the ask
        is not started and the window ends the way the timer ends it."""
        if self.depth and self.clock() >= self.deadline:
            self.live = False
            raise _ScanTimeout() if self.kind == "scan" else _RuleTimeout()

    # -- the window around one rule's work ---------------------------------------------
    def call(self, rid, fn, fallback):
        """Run `fn()` inside rule `rid`'s window. Returns its value, or `fallback` when the
        rule or the scan ended (or had ended before). Work done inside an open window (the
        occurrence walk of a rule that is already running) is part of that window."""
        if rid in self.ended:
            self.call_ended.setdefault(rid, "rule_limit")
            return fallback
        if self.scan_over:
            self._cut(rid)
            return fallback
        if self.depth:
            if rid != self.window and rid not in self.inner:
                self.inner.append(rid)
            self.admit()
            return fn()
        clock = self.clock
        started = clock()
        rem_rule = self.limit.rule_s - self.spent.get(rid, 0.0)
        rem_scan = float("inf") if self.limit.scan_s is None else self.limit.scan_s - (started - self.t0)
        if rem_scan <= 0:
            self._scan_end(rid)
            return fallback
        if rem_rule <= 0:
            self._rule_end(rid)
            return fallback
        if rem_scan <= rem_rule:
            delay, self.kind = rem_scan, "scan"
        else:
            delay, self.kind = rem_rule, "rule"
        self.deadline = started + delay
        self.depth = 1
        self.window = rid
        self.inner = []
        try:
            try:
                try:
                    self.live = True
                    signal.setitimer(signal.ITIMER_VIRTUAL, max(delay, 1e-4))
                    return fn()
                finally:
                    # Disarmed before the timer is cancelled, so a signal already pending
                    # when the call finished is a no-op instead of an escape.
                    self.live = False
                    signal.setitimer(signal.ITIMER_VIRTUAL, 0)
            except _RuleTimeout:
                self._rule_end(rid)
                for other in self.inner:
                    self._rule_end(other)
                return fallback
            except _ScanTimeout:
                self._scan_end(rid)
                for other in self.inner:
                    self._cut(other)
                return fallback
        finally:
            self.depth = 0
            self.window = None
            used = self.spent.get(rid, 0.0) + max(clock() - started, 0.0)
            self.spent[rid] = used
            if used >= self.limit.rule_s and rid not in self.ended:
                # The call finished past the limit (the timer had not fired yet): its result
                # stands, and the rule is not visited again.
                self._rule_end(rid)
                for other in self.inner:
                    self._rule_end(other)
            if (self.limit.scan_s is not None and not self.scan_over
                    and clock() - self.t0 >= self.limit.scan_s):
                # The scan's limit was used inside this window (the timer had not fired yet): the
                # call's result stands, and the scan is over at this rule.
                self._scan_end(rid)
                for other in self.inner:
                    self._cut(other)
            self.inner = []


@contextlib.contextmanager
def installed(run):
    """Take the virtual timer for the length of the block, or raise TimeLimitUnavailable.

    The restore is the OUTER finally, entered before anything is armed, so a signal raised
    anywhere inside (even at the first line of the inner cleanup) still puts the host's
    handler back. The order of the cleanup is the agent hook's: disarm flag, timer to 0,
    ignore (which discards a pending signal), then the host's handler."""
    reason = unavailable_reason()
    if reason is not None:
        raise TimeLimitUnavailable(reason)
    try:
        signal.signal(signal.SIGVTALRM, run.on_signal)
    except ValueError:
        raise TimeLimitUnavailable("signals can only be set from the main thread of the main interpreter") from None
    try:
        try:
            yield run
        finally:
            run.live = False        # nothing raises past this line: the handler is a no-op unless live
            signal.setitimer(signal.ITIMER_VIRTUAL, 0)
            signal.signal(signal.SIGVTALRM, signal.SIG_IGN)
    finally:
        signal.signal(signal.SIGVTALRM, signal.SIG_DFL)


# -- what the doors say (one vocabulary: "time limit") ---------------------------------------
def time_limit_warning(entry):
    """The one warning line for one end: the CLI prints it, the MCP server prints it, and both
    find it again in a result by building it from the end's own record."""
    if entry.get("reason") == "scan_limit":
        return "the scan did not finish within its time limit; the rules after this point did not run"
    return (f"rule {entry.get('rule_id')} did not finish within its time limit; "
            "this input is not fully checked by that rule")


def coverage_causes(result):
    """(something was not read, the time-limit ends of this result) for a result of any door.

    The time limit's own warnings are not a part of the input that went unread: a rule that
    ended says so, and nothing else is claimed. Anything else in `extraction_warnings`, a
    truncation, or an incomplete result that no end explains, is a part that was not read."""
    ended = list(getattr(result, "time_limit_ended", None) or [])
    own = {time_limit_warning(e) for e in ended}
    others = [w for w in (getattr(result, "extraction_warnings", None) or []) if w not in own]
    unread = (bool(getattr(result, "truncated", False)) or bool(others)
              or (not getattr(result, "extraction_complete", True) and not ended))
    return unread, ended


def incomplete_detail(unread_phrase, unread, ended):
    """The words after INCOMPLETE SCAN: the cause that is true, and both when both are.

    `unread_phrase` is the door's own words for a part that was not read ("part of this file was
    not read"); `ended` is a list of time-limit end records. With neither cause named (a
    caller that names no cause) the sentence is the unread one."""
    parts = []
    if unread or not ended:
        parts.append(unread_phrase)
    if any(e.get("reason") != "scan_limit" for e in ended):
        parts.append("a rule did not finish within its time limit")
    if any(e.get("reason") == "scan_limit" for e in ended):
        parts.append("the scan did not finish within its time limit")
    if len(parts) == 1:
        return parts[0]
    return ". ".join([parts[0]] + [p[0].upper() + p[1:] for p in parts[1:]])


LIMIT_ID = "GLS-TIME-LIMIT"


def finding_name(reason):
    """The finding's name for the cause that is true: one rule, or the whole scan."""
    if reason == "scan_limit":
        return "Scan did not finish within its time limit"
    return "Rule did not finish within its time limit"


def threats_only(findings):
    """The findings that are something the text said. A time-limit finding says only that checking
    did not finish, so no printed threat count includes it."""
    return [f for f in findings if f.get("id") != LIMIT_ID]


def ended_counts(ended):
    """The unfinished rules, counted beside the threat count in the one vocabulary; "" when none."""
    rules = sum(1 for e in ended if e.get("reason") != "scan_limit")
    parts = []
    if rules:
        parts.append(f"{rules} rule(s) did not finish within their time limit")
    if any(e.get("reason") == "scan_limit" for e in ended):
        parts.append("the scan did not finish within its time limit")
    return ", ".join(parts)


def rule_limit_ended(ended):
    """True when a rule (not the whole scan) reached its limit: the one case the option can change."""
    return any(e.get("reason") != "scan_limit" for e in ended)


def ended_union(*sources):
    """Every rule end carried by these engine results or scan documents, once each, in the order met.

    A document built from several parts (an image's OCR and EXIF text, a PDF's pages, an email's body
    and attachments) carries the union of what its parts carry: the same rule that ended in two parts
    is one end, as it is one warning line. A source with no `time_limit_ended` adds nothing."""
    out, seen = [], set()
    for source in sources:
        ended = source.get("time_limit_ended") if isinstance(source, dict) else getattr(source, "time_limit_ended", None)
        for entry in ended or []:
            key = (entry.get("rule_id"), entry.get("reason"), entry.get("limit_s"))
            if key not in seen:
                seen.add(key)
                out.append(dict(entry))
    return out


def ended_extra(*sources):
    """`{"time_limit_ended": [...]}` for the document's extra fields, or `{}` when no rule ended: the key is
    absent on a document exactly as it is absent on an engine result."""
    ended = ended_union(*sources)
    return {"time_limit_ended": ended} if ended else {}
