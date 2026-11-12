#!/usr/bin/env python3
"""
Generate the published scan-performance numbers from a real measurement.

Audit finding H1: `stats/current.json` carried `scan_speed_avg_ms: 0.261` and
`scans_per_second_single_thread: 3830`, propagated to 8+ homepage placements, the
README and llms.txt — and NO script in the repository produced either value. An
independent audit measured 0.26ms to be the cost of scanning an EMPTY STRING on the
hardware the README names. The project's own `sunglasses demo` printed 2.78ms.

A number nobody can regenerate is a claim, not a measurement. This script is the
generator: it measures, it stamps what it measured on, and it writes the result.

    python3 tools/gen_perf_stats.py            # print, do not write
    python3 tools/gen_perf_stats.py --write    # update stats/current.json
    python3 tools/gen_perf_stats.py --hook-only --write   # refresh only hook_speed

Corpus — public, in-repo, no network, no randomness:
  quickstart   the exact string the README quickstart tells a reader to run
  attacks      all positives in tests/benchmark/attacks.json
  readme_docs  the real-world README corpus in tests/fp_real_world_corpus/

Reported as a DISTRIBUTION, not a single headline. Scan cost is linear in input
length, so one number cannot describe both an 18-character command and an 8 KB
document. Publishing the smallest one as "average" is how H1 happened.

The firewall hook is a different cost from a scan: it is a whole child process per tool
call (interpreter start, imports, the check, exit). `hook_speed` records that, with the
scope in the key names, so a page or README that quotes a per-call hook time cites one
dated block instead of a number typed by hand:
  hook_lane_off_*   the command the installer writes (`<python> -m <HOOK_MARKER>`, the marker is
                    imported from sunglasses.firewall, never typed here) on a benign Bash call,
                    warn lane off
  hook_lane_on_*    the same with the lane marker present (`<SUNGLASSES_HOME>/warn-lane`)
  python_start_*    a bare interpreter start (`python -c pass`), the floor under both
Each is the minimum and the median of `repeats` runs of the whole child process, wall
clock, in a throwaway HOME so nothing under the real ~/.sunglasses is read or written.
The first run of each case is discarded (cold file cache).
"""

import argparse
import glob
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

from sunglasses import __version__ as SUNGLASSES_VERSION  # noqa: E402
from sunglasses.engine import SunglassesEngine  # noqa: E402
from sunglasses.firewall import HOOK_MARKER  # noqa: E402

QUICKSTART_STRING = "some text to check"
WARMUP = 20
REPEATS = 200
DOC_REPEATS = 5      # 8 KB documents are ~100x the cost; fewer reps, same method
HOOK_REPEATS = 15    # whole-process runs per case; min + median are reported
HOOK_INPUT = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "ls -la"},
    "session_id": "perf-stats",
})


def _median_ms(engine, text, repeats):
    for _ in range(WARMUP if repeats > 20 else 2):
        engine.scan(text)
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        engine.scan(text)
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples), statistics.mean(samples)


def _process_ms(argv, env, stdin, repeats):
    """Wall-clock ms of the whole child process: (minimum, median) over `repeats` runs.

    One discarded run first. A non-zero exit is an error, not a sample: a hook that
    crashed in 5 ms would otherwise publish a flattering number.
    """
    samples = []
    for i in range(repeats + 1):
        start = time.perf_counter()
        done = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                              env=env, cwd=REPO, check=False)
        elapsed = (time.perf_counter() - start) * 1000
        if done.returncode != 0:
            raise RuntimeError(f"{argv[-1]} exited {done.returncode}: {done.stderr[-200:]}")
        if i:
            samples.append(elapsed)
    return min(samples), statistics.median(samples)


def hook_argv():
    """The argv of the hook the installer registers: `<python> -m <HOOK_MARKER>`.

    Built from the same HOOK_MARKER `build_hook_entry` uses, so the number measured is the cost of
    the command that actually runs on every tool call, not of a sibling entry point.
    """
    return [sys.executable, "-m", HOOK_MARKER]


def measure_hook(repeats=HOOK_REPEATS):
    """The whole-hook process time with the warn lane off and on, and the interpreter floor."""
    result = {}
    ran = {}  # the argv each case actually ran, so the ledger names what was timed
    with tempfile.TemporaryDirectory() as off_home, tempfile.TemporaryDirectory() as on_home:
        open(os.path.join(on_home, "warn-lane"), "w").close()
        hook = hook_argv()
        cases = (("hook_lane_off", hook, off_home, HOOK_INPUT),
                 ("hook_lane_on", hook, on_home, HOOK_INPUT),
                 ("python_start", [sys.executable, "-c", "pass"], off_home, None))
        for name, argv, home, stdin in cases:
            env = {"HOME": home, "SUNGLASSES_HOME": home,
                   "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
            ran[name] = list(argv)
            low, mid = _process_ms(argv, env, stdin, repeats)
            result[f"{name}_min_ms"] = round(low, 1)
            result[f"{name}_median_ms"] = round(mid, 1)
    result.update({
        "repeats": repeats,
        "command": " ".join(["python"] + ran["hook_lane_off"][1:]),
        "command_shape": "benign Bash call (ls -la)",
        "scope": "whole child process wall clock, interpreter start included",
        "version": SUNGLASSES_VERSION,
        "measured_on": {
            "machine": platform.machine(),
            "system": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
        },
        "measured_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "generated_by": "tools/gen_perf_stats.py",
    })
    return result


def write_hook_only(path, hook):
    """Replace only `hook_speed` in the stats file; every other key is left as it was."""
    with open(path) as fh:
        stats = json.load(fh)
    stats["hook_speed"] = hook
    with open(path, "w") as fh:
        json.dump(stats, fh, indent=2)
        fh.write("\n")


def measure():
    engine = SunglassesEngine()

    with open(os.path.join(REPO, "tests/benchmark/attacks.json")) as fh:
        attacks = [a["text"] for a in json.load(fh)["attacks"]]

    docs = []
    for path in sorted(glob.glob(os.path.join(REPO, "tests/fp_real_world_corpus/*.md"))):
        with open(path, errors="ignore") as fh:
            docs.append(fh.read())

    quickstart_median, _ = _median_ms(engine, QUICKSTART_STRING, REPEATS)

    attack_medians = [_median_ms(engine, t, 20)[0] for t in attacks]
    attack_median = statistics.median(attack_medians)

    doc_medians, doc_bytes = [], []
    for text in docs:
        median, _ = _median_ms(engine, text, DOC_REPEATS)
        doc_medians.append(median)
        doc_bytes.append(len(text.encode("utf-8")))
    doc_median = statistics.median(doc_medians)

    # Throughput from the document corpus: the only figure that stays meaningful
    # across input sizes, because per-scan cost does not.
    kb_per_sec = statistics.median(
        (b / 1024) / (m / 1000) for b, m in zip(doc_bytes, doc_medians)
    )

    return {
        "scan_speed": {
            "quickstart_median_ms": round(quickstart_median, 3),
            "quickstart_input_chars": len(QUICKSTART_STRING),
            "attack_median_ms": round(attack_median, 3),
            "attack_corpus_n": len(attacks),
            "document_median_ms": round(doc_median, 1),
            "document_corpus_n": len(docs),
            "document_median_bytes": int(statistics.median(doc_bytes)),
            "throughput_kb_per_sec": round(kb_per_sec, 1),
        },
        # Public copy renders THESE strings verbatim. Director's ruling, 2026-08-30:
        # two independent runs of this script differed by 6% (0.725 vs 0.774), which
        # proves that hand-typing a perf number into a page re-creates H1 in
        # miniature. A page that needs a different phrasing shape gets a new field
        # here; it never gets a number typed by a human.
        "scan_speed_display": _display(quickstart_median, attack_median),
        "scan_speed_display_short": _display(quickstart_median, attack_median),
        "scan_speed_display_long": _display_long(
            quickstart_median, attack_median, kb_per_sec),
        "scan_speed_measured_on": {
            "machine": platform.machine(),
            "processor": platform.processor() or platform.machine(),
            "system": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
        },
        "hook_speed": measure_hook(),
        "scan_speed_generated_by": "tools/gen_perf_stats.py",
        "scan_speed_generated_at": datetime.now(timezone.utc)
            .astimezone().isoformat(timespec="seconds"),
    }


def _display(quickstart_ms, attack_ms):
    """One short public phrase, covering the range rather than its floor."""
    return f"~{quickstart_ms:.1f}ms short input, ~{attack_ms:.1f}ms typical attack string"


def _display_long(quickstart_ms, attack_ms, kb_per_sec):
    """The fuller phrase, for pages with room to be precise.

    Leads with the fact that makes the single-number claim impossible — cost
    scales with input length — and names the script, so the reader can check it
    rather than trust it.
    """
    return (f"Scan cost scales with input length: ~{quickstart_ms:.1f}ms on a short "
            f"input, ~{attack_ms:.1f}ms on a typical attack string, "
            f"~{kb_per_sec:.0f} KB/sec sustained. Every figure here is regenerated "
            f"by tools/gen_perf_stats.py.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true",
                        help="update stats/current.json in place")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--hook-only", action="store_true",
                        help="measure only hook_speed; with --write, touch nothing else")
    args = parser.parse_args()

    if args.hook_only:
        hook = measure_hook()
        print(json.dumps(hook, indent=2))
        if args.write:
            path = os.path.join(REPO, "stats", "current.json")
            write_hook_only(path, hook)
            print(f"wrote hook_speed in {path}")
        return

    measured = measure()

    if args.json:
        print(json.dumps(measured, indent=2))
    else:
        s = measured["scan_speed"]
        print("\nSUNGLASSES scan performance — measured, not asserted")
        print(f"  machine            {measured['scan_speed_measured_on']['processor']}, "
              f"Python {measured['scan_speed_measured_on']['python']}")
        print(f"  quickstart string  {s['quickstart_median_ms']:.3f} ms "
              f"({s['quickstart_input_chars']} chars)")
        print(f"  attack strings     {s['attack_median_ms']:.3f} ms "
              f"(median of {s['attack_corpus_n']})")
        print(f"  real READMEs       {s['document_median_ms']:.1f} ms "
              f"(median of {s['document_corpus_n']}, median {s['document_median_bytes']} bytes)")
        print(f"  throughput         {s['throughput_kb_per_sec']:.1f} KB/sec single-threaded")
        print(f"  public phrase      {measured['scan_speed_display']}\n")

    if args.write:
        path = os.path.join(REPO, "stats", "current.json")
        with open(path) as fh:
            stats = json.load(fh)
        # The unreproducible fields go. Leaving them beside the measured ones would
        # let a page keep reading the old key and stay wrong.
        for dead in ("scan_speed_avg_ms", "scans_per_second_single_thread"):
            stats.pop(dead, None)
        stats.update(measured)
        # Engine-truth counts, from the same source CHECK 24 validates against.
        # publish.sh writes these at ship time; regenerating them here keeps the
        # repo copy honest between ships, which is when the site copy is edited.
        from sunglasses.patterns import PATTERNS
        info = SunglassesEngine().info()
        stats.pop("patterns", None)
        stats["patterns_with_matcher"] = info["patterns_with_matcher"]
        stats["listed_patterns"] = info["listed_patterns"]
        stats["keywords"] = info["keywords"]
        stats["categories"] = len({(p.get("category") or "").strip()
                                   for p in PATTERNS if (p.get("category") or "").strip()})
        with open(path, "w") as fh:
            json.dump(stats, fh, indent=2)
            fh.write("\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
