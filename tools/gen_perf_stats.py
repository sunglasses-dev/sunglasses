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

Corpus — public, in-repo, no network, no randomness:
  quickstart   the exact string the README quickstart tells a reader to run
  attacks      all positives in tests/benchmark/attacks.json
  readme_docs  the real-world README corpus in tests/fp_real_world_corpus/

Reported as a DISTRIBUTION, not a single headline. Scan cost is linear in input
length, so one number cannot describe both an 18-character command and an 8 KB
document. Publishing the smallest one as "average" is how H1 happened.
"""

import argparse
import glob
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

from sunglasses.engine import SunglassesEngine  # noqa: E402

QUICKSTART_STRING = "some text to check"
WARMUP = 20
REPEATS = 200
DOC_REPEATS = 5      # 8 KB documents are ~100x the cost; fewer reps, same method


def _median_ms(engine, text, repeats):
    for _ in range(WARMUP if repeats > 20 else 2):
        engine.scan(text)
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        engine.scan(text)
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples), statistics.mean(samples)


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
        "scan_speed_display": _display(quickstart_median, attack_median),
        "scan_speed_measured_on": {
            "machine": platform.machine(),
            "processor": platform.processor() or platform.machine(),
            "system": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
        },
        "scan_speed_generated_by": "tools/gen_perf_stats.py",
        "scan_speed_generated_at": datetime.now(timezone.utc)
            .astimezone().isoformat(timespec="seconds"),
    }


def _display(quickstart_ms, attack_ms):
    """One short public phrase, covering the range rather than its floor."""
    return f"~{quickstart_ms:.1f}ms short input, ~{attack_ms:.0f}ms typical attack string"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true",
                        help="update stats/current.json in place")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

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
        with open(path, "w") as fh:
            json.dump(stats, fh, indent=2)
            fh.write("\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
