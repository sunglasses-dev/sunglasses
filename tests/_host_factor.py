"""The host factor of the cost rows.

host_seconds() runs WORKLOAD, a fixed piece of work with str and re over invented text that uses nothing of the package, four times in
this process, the first run not timed and the next three timed, and returns the median of the three timed runs. host_factor() is host_seconds() divided by REFERENCE_SECONDS, never below 1.0
and never above CAP, and it is read once per process. seconds_limit(limit) is limit times host_factor(). A cost row passes when the
seconds of its scan are under seconds_limit of the limit constant of its own file.
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
