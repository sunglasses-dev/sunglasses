"""The host factor of the cost rows.

host_seconds() runs WORKLOAD, a fixed piece of work with str and re over invented text that uses nothing of the package, four times in
this process, the first run not timed and the next three timed, and returns the median of the three timed runs. host_factor() is host_seconds() divided by REFERENCE_SECONDS, never below 1.0
and never above CAP, and it is read once per process. seconds_limit(limit) is limit times host_factor(). A cost row passes when the
seconds of its scan are under seconds_limit of the limit constant of its own file.
best_seconds(run, limit) is the row's measure when one shot of a short scan can meet a stall of the host after the factor was read: it
runs the scan up to three times, stops at the first shot under the limit, and returns the smallest reading, so a host at its reference
speed pays one shot and a scan that is slow in every shot is still over the limit. A first shot that is over the limit is kept with the
id of the row (set by tests/conftest.py) and is printed at the end of the run, whether or not a later shot passed.
Every text below is invented.
"""
import re
import statistics
import time

REFERENCE_SECONDS = 0.104
CAP = 2.0
RUNS = 3

_SENTENCES = (
    "The lamp ships in two days and every order includes a spare bulb. Returns are free within thirty days of delivery, and the shop "
    "answers questions about sizes and colours by mail. Is the shade linen? Yes! It is washed and pressed before it is packed. "
)
_TEXT = _SENTENCES * 8000
_factor = []
_host = []
ROW = []
_first_over = []


def WORKLOAD():
    words = _TEXT.split()
    found = len(re.findall(r"[a-z]+(?:-[a-z]+)*", _TEXT))
    found += len(re.sub(r"\s+", " ", _TEXT))
    found += sum(1 for word in words if word.endswith("s"))
    found += len(re.findall(r"(?:^|[.!?]\s+)[A-Z][a-z]+\s+[a-z]+", _TEXT))
    return found


def host_seconds():
    WORKLOAD()
    seconds = []
    for _ in range(RUNS):
        start = time.perf_counter()
        WORKLOAD()
        seconds.append(time.perf_counter() - start)
    return statistics.median(seconds)


def host_factor():
    if not _factor:
        seconds = host_seconds()
        _host[:] = [seconds]
        _factor.append(min(CAP, max(1.0, seconds / REFERENCE_SECONDS)))
    return _factor[0]


def report_line():
    """One line with the workload seconds and the factor of this run, or None when no row has asked for the factor."""
    if not _factor or not _host:
        return None
    return "cost rows: host workload %.3f s, reference %.3f s, factor %.2f (floor 1.0, cap %.1f)" % (
        _host[0], REFERENCE_SECONDS, _factor[0], CAP)


def seconds_limit(limit):
    return limit * host_factor()


def best_seconds(run, limit, tries=3):
    """Run `run` up to `tries` times and return the smallest reading, stopping at the first reading under `limit`.

    A row passes when at least one executed shot is under the limit: a slow first shot is discarded when a later shot is fast, however long
    the slow one was, and nothing interrupts a shot or adds up the shots. A row that checks a result puts the check inside `run`, so every
    shot is checked. A first shot at or over the limit is kept with its row and printed at the end of the run.
    """
    best = None
    for shot in range(tries):
        start = time.perf_counter()
        run()
        seconds = time.perf_counter() - start
        if shot == 0 and seconds >= limit:
            _first_over.append((ROW[0] if ROW else "?", seconds, limit))
        best = seconds if best is None else min(best, seconds)
        if best < limit:
            break
    return best


def first_over_lines():
    """One line per first shot that was over its limit: the row, the reading and the limit. Empty when no first shot was over."""
    return ["cost rows: first shot over its limit: %s read %.3f s against %.3f s" % row for row in _first_over]
