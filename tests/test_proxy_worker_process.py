"""T4.R1's worker as a REAL CHILD, specified before it exists.

Today the engine runs in the proxy's own process, which means T8.R4's kill on
deadline and T8.R7's stdout bound have nothing to apply to: a scan that hangs
stalls the session and a scan that floods has nothing stopping it. Nothing is
released by either, so the direction was always safe, but "safe because the
thing it protects against cannot be stopped" is not a bound, it is a hope.

Three properties, and all three are about a scan that misbehaves rather than
one that works.

THE DEADLINE IS A KILL, not a wait that gives up. A worker past T8.R4 is still
holding a CPU and a pipe, and a runner that stops reading and returns leaves it
running for as long as it likes. The group is signalled, the grace passes, and
the group is signalled again, the same shape serve.py already uses on the
upstream.

THE STDOUT BOUND IS ENFORCED WHILE READING, not measured afterwards. Reading a
gigabyte to discover it was over a megabyte is the fault the bound exists to
prevent, performed in the act of checking for it.

AND EXACTLY ONE COMPLETION per invocation. A worker that prints two results has
answered a question nobody asked twice, and taking either one means a scan can
choose which verdict the proxy settles on.
"""
import json
import os
import signal
import sys
import time

import pytest

worker_process = pytest.importorskip(
    "sunglasses.proxy.worker_process",
    reason="the worker process is the slice being specified")

from sunglasses.proxy import bounds  # noqa: E402

BINDING = {"digest": "d" * 64, "channel": "message", "generation": 1,
           "invocation_token": "tok"}


def _script(body):
    """A stand-in worker, so each bound is driven by a real misbehaving child."""
    return [sys.executable, "-c", body]


def _ok_worker(result=None):
    payload = json.dumps(result or {"binding": BINDING, "accepted": True,
                                    "status": "complete",
                                    "inspection_complete": True,
                                    "decision": "allow",
                                    "inspected_utf8_bytes": 0,
                                    "observed_content_bytes": 0,
                                    "elapsed_ms": 1, "findings": []})
    return _script(f"import sys;sys.stdin.read();print({payload!r})")


# ── the ordinary path, or none of the rest is a worker ───────────────────

def test_a_worker_that_answers_returns_its_result(tmp_path):
    out = worker_process.run({"params": {}}, argv=_ok_worker(),
                             binding=BINDING)
    assert out["decision"] == "allow"
    assert out["status"] == "complete"


def test_the_payload_reaches_the_child_on_stdin():
    """The child is a separate process, so the only way it learns what to scan
    is the pipe. A runner that forgot to write it would scan nothing and report
    a clean result, which is the most dangerous shape a scan can take."""
    echo = _script("import sys,json;d=sys.stdin.read();"
                   "print(json.dumps({'seen':len(d)}))")
    out = worker_process.run({"params": {"text": "hello"}}, argv=echo,
                             binding=BINDING, raw=True)
    assert out["seen"] > 0


# The anti-hang bound is ARMED AROUND the blocking call by
# `fails_rather_than_hangs` (conftest), not asserted after it. What proves
# these rows is the RECORDED OUTCOME -- `status: deadline`, `status:
# exception`, the child being gone. The old numbers were 5 s and 10 s against
# operations bounded at 200 ms and 5 s: a 20-125x margin on an idle box, and
# they reran anyway, because the failure is the tail and not the mean.
HANG_GUARD_S = 60


# ── T8.R4 · the deadline is a kill ───────────────────────────────────────

def test_a_worker_past_the_deadline_is_killed_and_not_merely_abandoned(
        tmp_path, fails_rather_than_hangs):
    """The property is that the PROCESS is gone, not that the call returned."""
    marker = tmp_path / "pid"
    hang = _script(
        f"import os,sys,time;open({str(marker)!r},'w').write(str(os.getpid()));"
        "sys.stdin.read();time.sleep(300)")
    started = time.monotonic()
    with fails_rather_than_hangs(HANG_GUARD_S):
        out = worker_process.run({"params": {}}, argv=hang, binding=BINDING,
                                 timeout_ms=200)
    waited = time.monotonic() - started
    # THE DEADLINE FIRED, and `status: deadline` below is what says so. This
    # says it fired because the 200 ms deadline elapsed and not instantly for
    # another reason; a lower bound is the direction load cannot break.
    assert waited >= 0.200, (
        f"it reported a deadline after {waited:.3f}s against a 200 ms bound")
    assert out["status"] == "deadline"
    assert out["accepted"] is False
    pid = int(marker.read_text())
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("the worker was abandoned, not killed")


def test_a_worker_that_ignores_sigterm_is_killed_anyway(tmp_path):
    """T8.R4's grace is a grace, not a promise. TERM alone leaves anything that
    traps it running for ever."""
    marker = tmp_path / "pid"
    stubborn = _script(
        "import os,signal,sys,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        f"open({str(marker)!r},'w').write(str(os.getpid()));"
        "sys.stdin.read();time.sleep(300)")
    out = worker_process.run({"params": {}}, argv=stubborn, binding=BINDING,
                             timeout_ms=200, grace_ms=200)
    assert out["status"] == "deadline"
    pid = int(marker.read_text())
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("a worker that traps SIGTERM outlived its deadline")


@pytest.mark.parametrize("sleep_ms,expected", [(0, "complete"), (900, "deadline")])
def test_the_deadline_is_the_named_number(sleep_ms, expected):
    """At the limit and one either side, driven by a child that actually
    sleeps rather than by a clock the test controls."""
    body = ("import sys,time,json;sys.stdin.read();"
            f"time.sleep({sleep_ms}/1000.0);"
            "print(json.dumps({'binding':%r,'accepted':True,'status':'complete',"
            "'inspection_complete':True,'decision':'allow',"
            "'inspected_utf8_bytes':0,'observed_content_bytes':0,"
            "'elapsed_ms':1,'findings':[]}))" % BINDING)
    out = worker_process.run({"params": {}}, argv=_script(body),
                             binding=BINDING, timeout_ms=500)
    assert out["status"] == expected


# ── T8.R7 · the stdout bound is enforced while reading ───────────────────

def test_a_flooding_worker_is_stopped_rather_than_read_to_the_end(
        tmp_path, fails_rather_than_hangs):
    """Reading a gigabyte to discover it was over a megabyte performs the
    fault in the act of checking for it."""
    flood = _script("import sys;sys.stdin.read();\n"
                    "w=sys.stdout.write\n"
                    "while True: w('x'*65536)")
    started = time.monotonic()
    with fails_rather_than_hangs(HANG_GUARD_S):
        out = worker_process.run({"params": {}}, argv=flood, binding=BINDING,
                                 stdout_limit=200_000, timeout_ms=5_000)
    waited = time.monotonic() - started
    # WHICH BOUND STOPPED THE READ IS IN `status`, and this comment used to
    # say the opposite. `run()` has always separated them:
    #
    #     return _fault(binding,
    #                   STATUS_EXCEPTION if collected.get("over")
    #                   else STATUS_DEADLINE)
    #
    # The stdout bound reports `exception`, the deadline reports `deadline`.
    # So `out["status"] == "exception"` below IS the mechanism assertion, and
    # the row underneath this one -- the same call with a child that never
    # writes -- is its control: without a row that produces `deadline` through
    # this call shape, `exception` here is not known to mean anything.
    #
    # THE OLD COMMENT WAS WRONG BECAUSE THE MUTATION BEHIND IT NEVER FIRED. It
    # raised `stdout_limit` to 10 GB expecting the read to run to the deadline
    # instead, and read the two identical results as proof that `status` cannot
    # tell the bounds apart. But this flood writes 10 GB in about 3.7 s, well
    # inside the 5 s deadline, so BOTH runs tripped the stdout bound: that was
    # one code path measured twice, which can only ever agree with itself. A
    # mutation that does not create the condition it names proves nothing.
    #
    # Measured on 0a9db8e with a stimulus that does create it:
    #
    #     quiet child, stdout_limit=200_000    1.04 s   status=deadline
    #     this flood,  stdout_limit=200_000    0.06 s   status=exception
    #
    # THE CLOCK STAYS, for a different and smaller reason than the one it used
    # to carry: it is an anti-slow-read bound, not a mechanism discriminator.
    # A build whose stdout limit stops the read but only after reading far too
    # much still reports `exception` and still satisfies the assertion below,
    # and this is what catches that. 1.5 s sits about 20x over the working
    # case and well under the 5 s deadline, so a failure here is a slow read
    # and not a deadline in disguise.
    assert waited < 1.5, (
        f"the read took {waited:.2f}s against a 5 s deadline; the stdout "
        f"bound is what is supposed to stop it, and at this duration the "
        f"deadline did")
    assert out["status"] == "exception"
    assert out["accepted"] is False


def test_a_quiet_worker_past_its_deadline_reports_deadline_not_the_stdout_bound(
        fails_rather_than_hangs):
    """The control for the row above: the same call, the same stdout limit, a
    child that never writes -- so the only bound left to trip is the clock."""
    # WITHOUT THIS ROW THE ONE ABOVE IS UNFALSIFIABLE ON ITS OWN. `_fault` is
    # reached by both bounds, so a build that collapsed them into one status
    # would still return "exception" for the flood and the assertion up there
    # would still pass. Driven for real -- `else STATUS_DEADLINE` changed to
    # `else STATUS_EXCEPTION`, the edit confirmed present at the line before
    # running -- the flood row stayed GREEN and this row went red.
    #
    # WHAT THIS ROW IS NOT: the only thing that catches that collapse. The same
    # mutation also reddens three T8.R4 rows, and saying otherwise would be a
    # claim the measurement refutes. What it is, is the only row that produces
    # `deadline` through THIS call shape -- same binding, same
    # stdout_limit=200_000, only the child differs -- so it is what keeps the
    # flood row's `exception` a statement about a mechanism rather than a
    # restating of whatever `_fault` happens to return.
    quiet = _script("import sys,time;sys.stdin.read();time.sleep(30)")
    started = time.monotonic()
    with fails_rather_than_hangs(HANG_GUARD_S):
        out = worker_process.run({"params": {}}, argv=quiet, binding=BINDING,
                                 stdout_limit=200_000, timeout_ms=1_000)
    waited = time.monotonic() - started
    assert out["status"] == "deadline", (
        f"a child that wrote nothing reported {out['status']!r}; if the stdout "
        f"bound can report that, `exception` above names no mechanism")
    assert out["accepted"] is False
    # It waited for the deadline rather than falling out instantly, which is
    # what makes "deadline" the reason and not a label on some earlier failure.
    assert waited >= 1.0, (
        f"it reported a deadline after {waited:.3f}s against a 1 s bound")


@pytest.mark.parametrize("size,expected", [(64, "complete"), (400_000, "exception")])
def test_the_stdout_bound_is_the_named_number(size, expected):
    """One under and one well over, with the limit supplied so the test does
    not have to write a megabyte to prove a megabyte."""
    # THE CHILD MAKES ITS OWN PADDING. This used to build the 400 KB pad here
    # and hand it to `_ok_worker`, which interpolates the payload into a
    # `python -c` BODY -- one argv argument of 400 KB. Linux caps a SINGLE
    # argument at MAX_ARG_STRLEN, 131072 bytes, so the exec failed with OSError
    # Errno 7 before the child ever ran; macOS has no equivalent per-argument
    # cap, which is why the archive receipt was green and every Linux leg was
    # red. The product never does this -- `worker_process.run` writes the
    # request to the child's stdin, which `test_the_payload_reaches_the_child_
    # on_stdin` asserts -- so the 400 KB crossing argv was this test's own
    # stand-in worker and nothing else.
    #
    # The row's subject is unchanged: a real child, a stdout larger than the
    # named limit, and the status that follows. Only `size` crosses argv now,
    # as an integer literal.
    body = (
        "import sys,json;sys.stdin.read();"
        "r={'binding':%r,'accepted':True,'status':'complete',"
        "'inspection_complete':True,'decision':'allow',"
        "'inspected_utf8_bytes':0,'observed_content_bytes':0,"
        "'elapsed_ms':1,'findings':[],'pad':'x'*%d};"
        "print(json.dumps(r))" % (BINDING, size))
    out = worker_process.run({"params": {}}, argv=_script(body),
                             binding=BINDING, stdout_limit=200_000)
    assert out["status"] == expected


# ── T4.R2 · exactly one completion ───────────────────────────────────────

def test_a_worker_that_answers_twice_is_a_fault_and_not_a_choice():
    """Taking either one lets a scan pick which verdict the proxy settles on."""
    twice = _script(
        "import sys,json;sys.stdin.read();"
        "r=json.dumps({'binding':%r,'accepted':True,'status':'complete',"
        "'inspection_complete':True,'decision':'allow',"
        "'inspected_utf8_bytes':0,'observed_content_bytes':0,"
        "'elapsed_ms':1,'findings':[]});print(r);print(r)" % BINDING)
    out = worker_process.run({"params": {}}, argv=twice, binding=BINDING)
    assert out["status"] == "exception"
    assert out["accepted"] is False


def test_a_worker_that_says_nothing_is_a_fault():
    silent = _script("import sys;sys.stdin.read()")
    out = worker_process.run({"params": {}}, argv=silent, binding=BINDING)
    assert out["status"] == "exception"


def test_a_worker_that_prints_rubbish_is_a_fault_and_never_a_verdict():
    noise = _script("import sys;sys.stdin.read();print('not json at all')")
    out = worker_process.run({"params": {}}, argv=noise, binding=BINDING)
    assert out["status"] == "exception"
    assert out["decision"] != "allow"


# ── the fault results are still worker results ───────────────────────────

def test_every_fault_carries_the_binding_it_was_asked_about():
    """A fault result is settled like any other, so it has to be bound to the
    invocation that produced it or T4.R2 rejects it as another item's answer."""
    out = worker_process.run({"params": {}}, argv=_script("import sys;sys.stdin.read()"),
                             binding=BINDING)
    assert out["binding"] == BINDING


def test_a_fault_never_carries_the_childs_own_words():
    """The child's stdout is peer-adjacent once it is scanning peer bytes, and
    a traceback is the most natural thing for it to print."""
    shouty = _script("import sys;sys.stdin.read();"
                     "print('SECRET-FROM-THE-WORKER');sys.exit(3)")
    out = worker_process.run({"params": {}}, argv=shouty, binding=BINDING)
    assert "SECRET-FROM-THE-WORKER" not in json.dumps(out)


def test_the_worker_runs_in_its_own_process_group(tmp_path):
    """T8.R12, and the reason the kill is safe to send.

    `stop_group` signals a GROUP. If the child shared ours, the deadline kill
    would land on the proxy itself, so this property is what makes every other
    test in this file survivable. It is asserted directly rather than by
    mutation: the mutant that sets start_new_session=False kills whatever runs
    it, which on 2026-09-14 included a harness that then left three mutants in
    the working tree. Some mutants are not worth executing to learn from.
    """
    marker = tmp_path / "group"
    report = _script(
        f"import os,sys;open({str(marker)!r},'w').write(str(os.getpgid(0)));"
        "sys.stdin.read()")
    worker_process.run({"params": {}}, argv=report, binding=BINDING,
                       timeout_ms=300)
    assert int(marker.read_text()) != os.getpgid(0), \
        "the worker shares our group, so its deadline kill would hit us"
