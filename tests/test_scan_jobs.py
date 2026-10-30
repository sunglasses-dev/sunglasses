"""`scan --dir` and `--repo` read up to `--jobs N` files at once and report what one at a time reports.

What these tests pin:

1. The report does not depend on N: the same tree gives the same JSON, SARIF and text (the
   run-time figure aside) and the same exit code for 1, 4 and 8, whatever order the files finish in.
2. Results are counted in walk order: when the first file is the slowest, the lines and the
   `--verbose` output are still in walk order.
3. The deadline belongs to each child: one file that does not finish is incomplete, the others are
   read, and nothing is left running afterwards.
4. SIGTERM and SIGINT stop every child, including the ones in the middle of a file.
5. No more than `2 * N` files are held at a time, and no more than N are read at a time.
6. The flag is refused, before anything is scanned, when it is not a whole number from 1 to 64 and
   when it is given with a single file or with text; without a deadline or a way to stop a child the files are read one
   at a time and the command says so.

The slow file is simulated the way `test_scan_file_deadline` does it: a stand-in child sleeps when it
is handed a marked file.
"""

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

import pytest

from test_scan_file_deadline import (  # noqa: F401  (rig is a fixture)
    CLEAN, EXIT_CLEAN, EXIT_INCOMPLETE, EXIT_THREAT, EXIT_USAGE, SLOW, THREAT,
    REPO, _env, _file, _refused_by_the_scan, _scan, _starts, _tree, rig)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="the scanner child is stopped by process group")


def _mixed_tree(rig, slow=False):
    files = {f"clean_{i:02d}.txt": CLEAN for i in range(10)}
    files.update({f"sub/more_{i}.txt": CLEAN for i in range(4)})
    files["sub/threat_a.txt"] = THREAT
    files["threat_b.txt"] = THREAT
    if slow:
        files["aa_slow.txt"] = SLOW
    return _tree(rig, files)


def _without_the_run_time(text, output):
    if output == "json":
        doc = json.loads(text)
        doc.pop("scan_time_ms", None)
        doc.pop("event_id", None)  # new on every run, like the SARIF branch below
        return doc
    if output == "human":
        return re.sub(r"^.*Scan time:.*$", "", text, flags=re.M)

    def scrub(node):
        # An event id is new on every run, even two runs of the same command, and so is a latency.
        if isinstance(node, dict):
            return {k: ("" if k in ("event_id", "latency_ms") else scrub(v)) for k, v in node.items()}
        if isinstance(node, list):
            return [scrub(v) for v in node]
        return node
    return scrub(json.loads(text))


# ── 1. the report does not depend on N ─────────────────────────────────────

@pytest.mark.parametrize("output", ["json", "sarif", "human"])
def test_the_report_is_the_same_for_1_4_and_8(rig, output):
    root = _mixed_tree(rig)
    runs = {n: _scan(rig, "--dir", str(root), "-o", output, "--jobs", str(n)) for n in (1, 4, 8)}
    for n, proc in runs.items():
        assert proc.returncode == EXIT_THREAT, (n, proc.stdout, proc.stderr)
    one = _without_the_run_time(runs[1].stdout, output)
    assert one, runs[1].stderr
    for n in (4, 8):
        assert _without_the_run_time(runs[n].stdout, output) == one, n


def test_the_report_is_the_same_with_a_file_that_does_not_finish_and_one_that_cannot_be_read(rig):
    root = _mixed_tree(rig, slow=True)
    locked = root / "locked.txt"
    locked.write_text(CLEAN)
    locked.chmod(0)
    try:
        runs = {n: _scan(rig, "--dir", str(root), "-o", "json", "--file-deadline", "2", "--jobs", str(n))
                for n in (1, 4, 8)}
    finally:
        locked.chmod(0o644)
    for n, proc in runs.items():
        assert proc.returncode == EXIT_THREAT, (n, proc.stdout, proc.stderr)
    one = _without_the_run_time(runs[1].stdout, "json")
    assert [item["file"] for item in one["partially_read"]] == ["aa_slow.txt"], one
    for n in (4, 8):
        assert _without_the_run_time(runs[n].stdout, "json") == one, n


def test_the_cap_and_the_lockfile_rule_give_the_same_report(rig):
    root = _mixed_tree(rig)
    (root / "package-lock.json").write_text("{}\n")
    args = ("--dir", str(root), "-o", "json", "--max-files", "9", "--skip-lockfiles")
    one = _scan(rig, *args, "--jobs", "1")
    four = _scan(rig, *args, "--jobs", "4")
    assert one.returncode == four.returncode
    assert _without_the_run_time(four.stdout, "json") == _without_the_run_time(one.stdout, "json")


# ── 2. walk order ──────────────────────────────────────────────────────────

def test_the_first_file_finishing_last_does_not_change_the_order_of_anything(rig):
    root = _tree(rig, {"a_first.txt": SLOW, **{f"b_{i}.txt": CLEAN for i in range(8)}})
    one = _scan(rig, "--dir", str(root), "--verbose", "--file-deadline", "30", "--jobs", "1", slow_seconds=3)
    four = _scan(rig, "--dir", str(root), "--verbose", "--file-deadline", "30", "--jobs", "4", slow_seconds=3)
    assert one.returncode == four.returncode == EXIT_CLEAN, (one.stderr, four.stderr)
    assert _without_the_run_time(four.stdout, "human") == _without_the_run_time(one.stdout, "human")
    names = re.findall(r"(?:PASS|THREAT|INCOMPLETE)\s+(\S+)", four.stdout)
    assert names == ["a_first.txt"] + [f"b_{i}.txt" for i in range(8)], names
    progress = re.findall(r"\[(\d+)/9\]\s+\S+\s+(\S+)", four.stderr)
    assert [name for _, name in progress] == names, progress
    assert [int(k) for k, _ in progress] == list(range(1, 10))


def test_in_one_merged_stream_progress_runs_ahead_of_results_and_each_keeps_the_walk_order(rig):
    root = _tree(rig, {"a_first.txt": SLOW, **{f"b_{i}.txt": CLEAN for i in range(8)}})
    proc = subprocess.run(
        [sys.executable, str(rig / "launcher.py"), str(rig / "stand_in.py"), "scan", "--dir", str(root),
         "--verbose", "--file-deadline", "30", "--jobs", "4"],
        cwd=rig / "cwd", env={**_env(rig, 3), "PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
    assert proc.returncode == EXIT_CLEAN, proc.stdout
    lines = proc.stdout.splitlines()
    walk = ["a_first.txt"] + [f"b_{i}.txt" for i in range(8)]
    progress = [(i, m.group(1)) for i, line in enumerate(lines) if (m := re.search(r"\[\d+/9\]\s+\S+\s+(\S+)", line))]
    results = [(i, m.group(1)) for i, line in enumerate(lines) if (m := re.match(r"\s*(?:PASS|THREAT|INCOMPLETE)\s+(\S+)", line))]
    assert [name for _, name in progress] == walk, lines
    assert [name for _, name in results] == walk, lines
    first_result = results[0][0]
    assert any(i < first_result and name != "a_first.txt" for i, name in progress), (
        "no later file was handed out before the slow first file had its result", lines)


# ── 3. the deadline belongs to each child ──────────────────────────────────

def test_one_file_that_does_not_finish_costs_only_itself(rig):
    root = _tree(rig, {"m_slow.txt": SLOW, **{f"f_{i:02d}.txt": CLEAN for i in range(12)}})
    proc = _scan(rig, "--dir", str(root), "-o", "json", "--file-deadline", "2", "--jobs", "4")
    assert proc.returncode == EXIT_INCOMPLETE, proc.stdout + proc.stderr
    doc = json.loads(proc.stdout)
    assert [item["file"] for item in doc["partially_read"]] == ["m_slow.txt"], doc
    assert doc["files_scanned"] == 13 and doc["files_incomplete"] == 1
    assert proc.seconds < 40, "the other children waited for the one that did not finish"
    pids = _starts(rig)
    assert 2 <= len(pids) <= 6, pids          # up to 4 at once, plus the replacement
    for pid in pids:
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid), 0)


def test_a_small_tree_starts_no_more_children_than_files(rig):
    root = _tree(rig, {"a.txt": CLEAN, "b.txt": CLEAN})
    proc = _scan(rig, "--dir", str(root), "--file-deadline", "30", "--jobs", "8")
    assert proc.returncode == EXIT_CLEAN, proc.stdout + proc.stderr
    assert 1 <= len(_starts(rig)) <= 2, _starts(rig)


# ── 4. signals ─────────────────────────────────────────────────────────────

def _pids_in(path):
    return set(path.read_text().split()) if path.exists() else set()


def _wait_until(condition, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.05)
    return condition()


def _default_signals():
    # A test run started in the background of a non-interactive shell has SIGINT ignored, and a
    # process started from it keeps that: Python then installs no KeyboardInterrupt handler and the
    # command would not stop. The command under test gets the signal disposition of a terminal.
    signal.signal(signal.SIGINT, signal.SIG_DFL)


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM], ids=["sigint", "sigterm"])
def test_a_signal_stops_every_child_even_in_the_middle_of_a_file(rig, signum):
    root = _tree(rig, {f"s_{i}.txt": SLOW for i in range(8)})
    reading = rig / "reading.log"
    proc = subprocess.Popen(
        [sys.executable, str(rig / "launcher.py"), str(rig / "stand_in.py"), "scan", "--dir", str(root),
         "--file-deadline", "100", "--jobs", "4"],
        cwd=rig / "cwd", env={**_env(rig, 120), "READING_LOG": str(reading)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=_default_signals)
    try:
        # Each of the four children has written its pid as it began to read its file.
        assert _wait_until(lambda: len(_pids_in(reading)) == 4, 90), (_starts(rig), _pids_in(reading))
        assert len(_starts(rig)) == 4, _starts(rig)
        began = time.monotonic()
        proc.send_signal(signum)
        proc.communicate(timeout=60)
        assert time.monotonic() - began < 30, "the command waited for the children instead of stopping them"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    for pid in _starts(rig):
        def gone(pid=pid):
            try:
                os.kill(int(pid), 0)
            except ProcessLookupError:
                return True
            return False
        assert _wait_until(gone, 10), f"child {pid} is still running after the command ended"


# ── 5. how many files are held and read at once ────────────────────────────

class _CountingWorker:
    """A child stand-in that scans in this process and counts how many are reading at once."""
    reading = 0
    most_reading = 0
    lock = threading.Lock()
    created = []

    def __init__(self, deadline_s):
        self.deadline_s = deadline_s
        self.closed = False
        self.aborted = False
        type(self).created.append(self)

    def start(self):
        pass

    def scan_file(self, target):
        from sunglasses.engine import SunglassesEngine
        cls = type(self)
        with cls.lock:
            cls.reading += 1
            cls.most_reading = max(cls.most_reading, cls.reading)
        try:
            time.sleep(0.02)
            return SunglassesEngine().scan_file(target)
        finally:
            with cls.lock:
                cls.reading -= 1

    def abort(self):
        self.aborted = True

    def close(self):
        self.closed = True


def _tree_args(root, jobs, output="json"):
    from sunglasses import cli
    return cli.argparse.Namespace(json=(output == "json"), output=output, verbose=False, max_files=None,
                                  directory=str(root), skip_lockfiles=False, channel="file",
                                  file_deadline=30, jobs=jobs)


def test_no_more_than_2n_files_are_held_and_no_more_than_n_are_read(rig, monkeypatch, capsys):
    from sunglasses import cli, scan_worker
    _CountingWorker.reading = _CountingWorker.most_reading = 0
    _CountingWorker.created = []
    monkeypatch.setattr(scan_worker, "ScanWorker", _CountingWorker)
    monkeypatch.setattr(scan_worker, "available", lambda: True)

    held = {"now": 0, "most": 0}
    lock = threading.Lock()
    real_submit, real_result = cli._ScanPool.submit, cli._PoolTask.result

    def submit(self, snapshot):
        with lock:
            held["now"] += 1
            held["most"] = max(held["most"], held["now"])
        return real_submit(self, snapshot)

    def result(self):
        try:
            return real_result(self)
        finally:
            with lock:
                held["now"] -= 1

    monkeypatch.setattr(cli._ScanPool, "submit", submit)
    monkeypatch.setattr(cli._PoolTask, "result", result)

    root = _tree(rig, {f"f_{i:03d}.txt": CLEAN for i in range(60)})
    with pytest.raises(SystemExit) as stop:
        cli._scan_tree(_tree_args(root, "3"), cli.SunglassesEngine(), str(root),
                       source=str(root), kind="directory")
    assert stop.value.code == EXIT_CLEAN
    assert json.loads(capsys.readouterr().out)["files_scanned"] == 60
    assert held["most"] <= 6, held
    assert _CountingWorker.most_reading <= 3, _CountingWorker.most_reading
    assert _CountingWorker.most_reading >= 2, "the files were not read at the same time"
    assert 2 <= len(_CountingWorker.created) <= 3
    assert all(w.closed for w in _CountingWorker.created)


def test_an_error_one_file_raises_is_counted_at_that_file_in_walk_order(rig, monkeypatch, capsys):
    from sunglasses import cli, scan_worker
    from sunglasses.extractors.dispatch import UnreadableFile

    class Worker(_CountingWorker):
        def scan_file(self, target):
            if getattr(target, "name", "") == "b_bad.txt" or "b_bad" in str(getattr(target, "path", target)):
                raise UnreadableFile("b_bad.txt", OSError("stand-in cannot read this one"))
            return super().scan_file(target)

    monkeypatch.setattr(scan_worker, "ScanWorker", Worker)
    monkeypatch.setattr(scan_worker, "available", lambda: True)
    root = _tree(rig, {"a.txt": CLEAN, "b_bad.txt": CLEAN, "c.txt": CLEAN})
    with pytest.raises(SystemExit) as stop:
        cli._scan_tree(_tree_args(root, "3"), cli.SunglassesEngine(), str(root),
                       source=str(root), kind="directory")
    doc = json.loads(capsys.readouterr().out)
    assert doc["files_scanned"] == 2, doc
    skipped = [item["file"] if isinstance(item, dict) else item[0] for item in doc.get("skipped", [])]
    assert skipped == ["b_bad.txt"], doc
    assert stop.value.code == EXIT_INCOMPLETE


# ── 6. the flag ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value", ["0", "-1", "1.5", "nan", "inf", "", "two", "65", "1e1", "٣", "9" * 5000, "0" * 5000 + "1x",
                                   pytest.param("0" * 5000 + "1", id="5000-zeros-then-1"),
                                   pytest.param("0" * 5000, id="5000-zeros"),
                                   pytest.param("0" * 17 + "1", id="17-chars")])
def test_a_value_that_is_not_a_whole_number_from_1_to_64_is_refused_before_any_scan(rig, value):
    root = _tree(rig, {"a.txt": CLEAN})
    proc = _scan(rig, "--dir", str(root), "--jobs", value)
    _refused_by_the_scan(proc)
    assert "--jobs must be a whole number from 1 to 64" in proc.stdout + proc.stderr
    assert _starts(rig) == []


def test_jobs_with_file_is_refused_naming_dir_and_repo(rig):
    proc = _scan(rig, "--file", str(_file(rig, CLEAN)), "--jobs", "2")
    _refused_by_the_scan(proc)
    assert "--dir and --repo" in proc.stdout + proc.stderr
    assert _starts(rig) == []


@pytest.mark.parametrize("value", ["2", "0", "nope", pytest.param("0" * 5000 + "1", id="5000-zeros-then-1")])
@pytest.mark.parametrize("mode", ["text", "stdin", "positional"])
def test_jobs_given_to_text_is_refused_not_ignored(rig, mode, value):
    args = {"text": ["--text", "hello there"], "stdin": ["--stdin"], "positional": ["hello there"]}[mode]
    proc = subprocess.run(
        [sys.executable, str(rig / "launcher.py"), str(rig / "stand_in.py"), "scan", *args, "--jobs", value],
        cwd=rig / "cwd", env=_env(rig, 60), input="hello there", capture_output=True, text=True, timeout=120)
    _refused_by_the_scan(proc)
    assert "--jobs" in proc.stdout + proc.stderr
    assert _starts(rig) == []


def test_jobs_given_to_an_unreachable_repo_is_a_usage_error_not_a_crash(rig):
    proc = _scan(rig, "--repo", "https://invalid.invalid/none.git", "--jobs", "0")
    _refused_by_the_scan(proc)


def test_without_a_deadline_the_files_are_read_one_at_a_time_and_an_explicit_jobs_says_so(rig):
    root = _mixed_tree(rig)
    quiet = _scan(rig, "--dir", str(root), "-o", "json", "--file-deadline", "0")
    said = _scan(rig, "--dir", str(root), "-o", "json", "--file-deadline", "0", "--jobs", "4")
    assert quiet.returncode == said.returncode == EXIT_THREAT
    assert "--jobs needs a file deadline" not in quiet.stderr
    assert "note: --jobs needs a file deadline; with --file-deadline 0 files are read one at a time." in said.stderr
    assert _starts(rig) == []                # no child at all
    assert _without_the_run_time(said.stdout, "json") == _without_the_run_time(quiet.stdout, "json")


def test_jobs_1_starts_one_child_and_the_default_is_the_same_run(rig):
    root = _mixed_tree(rig)
    one = _scan(rig, "--dir", str(root), "-o", "json", "--jobs", "1")
    assert len(_starts(rig)) == 1
    default = _scan(rig, "--dir", str(root), "-o", "json")
    assert default.returncode == one.returncode == EXIT_THREAT
    assert _without_the_run_time(default.stdout, "json") == _without_the_run_time(one.stdout, "json")


def test_the_help_names_the_range_and_the_default(rig):
    proc = subprocess.run([sys.executable, "-m", "sunglasses", "scan", "--help"], cwd=rig / "cwd",
                          env={**os.environ, "PYTHONPATH": str(REPO), "COLUMNS": "200"},
                          capture_output=True, text=True, timeout=60)
    flat = " ".join(proc.stdout.split())
    assert "--jobs N" in flat and "1 to 64" in flat and "default: 1" in flat
    assert "byte-identical" not in flat and "event ids" in flat and "ahead of the results" in flat


# ── abort: the pool stops a child that is in the middle of a file ──────────

_SILENT_CHILD = """
import struct, sys, time
def put(body):
    sys.stdout.buffer.write(struct.pack(">I", len(body)) + body)
    sys.stdout.buffer.flush()
put(b'{"ready": true}')
size = struct.unpack(">I", sys.stdin.buffer.read(4))[0]
sys.stdin.buffer.read(size)
time.sleep(120)
"""


def _is_gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def test_abort_during_a_file_ends_the_read_at_once_and_leaves_no_child(rig):
    from sunglasses import scan_worker
    worker = scan_worker.ScanWorker(120, argv=[sys.executable, "-c", _SILENT_CHILD], startup_s=10)
    outcome = {}
    path = str(_file(rig, CLEAN))

    def read():
        outcome["result"] = worker.scan_file(path)

    reader = threading.Thread(target=read, daemon=True)
    started = time.monotonic()
    try:
        reader.start()
        while worker.pid is None and time.monotonic() - started < 10:
            time.sleep(0.05)
        pid = worker.pid
        assert pid is not None, "the child never started"
        time.sleep(0.5)                      # the child has the request and is sitting on it
        worker.abort()
        reader.join(15)
        assert not reader.is_alive(), "the read kept waiting for the deadline after abort"
        assert time.monotonic() - started < 30
        result = outcome["result"]
        assert not result.is_clean and result.extraction_complete is False
    finally:
        worker.close()
    deadline = time.monotonic() + 5
    while not _is_gone(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert _is_gone(pid), "the child outlived abort and close"


# ── abort: a worker that was aborted never starts a child again ───────────

def test_a_file_handed_to_an_aborted_worker_starts_no_child(rig):
    from sunglasses import scan_worker
    worker = scan_worker.ScanWorker(120, argv=[sys.executable, "-c", _SILENT_CHILD], startup_s=10)
    try:
        worker.abort()
        started = time.monotonic()
        result = worker.scan_file(str(_file(rig, CLEAN)))
        assert time.monotonic() - started < 5
        assert not result.is_clean and result.extraction_complete is False
        assert "stopped" in "; ".join(result.extraction_warnings)
        assert worker.pid is None
        worker.start()
        assert worker.pid is None, "an aborted worker started a child"
    finally:
        worker.close()


def test_abort_while_a_read_is_being_prepared_does_not_bring_a_child_back(rig, monkeypatch):
    """The window the reviewer reproduced: the previous file ran out its deadline, the next read is still
    building its request, the pool closes, and the read goes on to start a new child."""
    from sunglasses import scan_worker
    worker = scan_worker.ScanWorker(120, argv=[sys.executable, "-c", _SILENT_CHILD], startup_s=10)
    in_prepare, release = threading.Event(), threading.Event()
    real = scan_worker.ScanWorker._request

    def slow_request(target):
        in_prepare.set()
        release.wait(20)
        return real(target)

    monkeypatch.setattr(scan_worker.ScanWorker, "_request", staticmethod(slow_request))
    outcome = {}
    path = str(_file(rig, CLEAN))
    reader = threading.Thread(target=lambda: outcome.update(result=worker.scan_file(path)), daemon=True)
    try:
        reader.start()
        assert in_prepare.wait(10)
        assert worker.pid is None              # nothing to stop yet
        worker.abort()
        release.set()
        started = time.monotonic()
        reader.join(15)
        assert not reader.is_alive()
        assert time.monotonic() - started < 10, "the read waited out its deadline after abort"
        assert worker.pid is None, "a child was started after abort"
        assert outcome["result"].extraction_complete is False
    finally:
        release.set()
        worker.close()


def test_closing_a_pool_with_a_read_still_being_prepared_ends_at_once(rig, monkeypatch):
    from sunglasses import cli, scan_worker
    in_prepare, release = threading.Event(), threading.Event()
    real = scan_worker.ScanWorker._request

    def slow_request(target):
        in_prepare.set()
        release.wait(20)
        return real(target)

    monkeypatch.setattr(scan_worker.ScanWorker, "_request", staticmethod(slow_request))
    monkeypatch.setattr(scan_worker, "default_argv", lambda: [sys.executable, "-c", _SILENT_CHILD])
    pool = cli._ScanPool(120, 2)
    path = str(_file(rig, CLEAN))
    task = pool.submit(path)
    try:
        assert in_prepare.wait(10)
        threading.Timer(0.3, release.set).start()
        started = time.monotonic()
        pool.close()
        assert time.monotonic() - started < 10
        assert task._done.wait(10)
        assert pool._outstanding == 0
        assert all(w.pid is None for w in pool._workers)
    finally:
        release.set()
