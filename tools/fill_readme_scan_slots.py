#!/usr/bin/env python3
"""Fill every measured figure in the README from `stats/current.json`; no figure is typed by hand.

The README carries `@@NAME@@` slots in three places: the scan-speed table and the sentence under
it (`@@SCAN_*@@`, from `scan_speed` and `scan_speed_provenance`), the WARN-lane bullet and the
"Cost" line (`@@LANE_ON_MS@@ @@LANE_OFF_MS@@ @@PY_START_MS@@ @@REPEATS@@ @@VERSION@@ @@DATE@@
@@MACHINE_CLASS@@`, from `hook_speed`). `tools/gen_perf_stats.py` wrote those blocks, so the
README can only say what the generator measured, on which version, when. It runs once at the
release cut, on the README that ships.

    python3 -I tools/fill_readme_scan_slots.py [--readme README.md] [--stats stats/current.json]
    python3 -I tools/fill_readme_scan_slots.py --check     # exit 1 if any @@X slot is left

It refuses (exit 1, nothing written) when a slot is missing from the README, a stats key is
missing, a value is not usable (a measurement must be a finite number above zero; version, date
and machine must be present and well formed), or any `@@` + capital letter is left after
filling, so an unfilled or unknown slot cannot ship.
"""
import argparse
import json
import math
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# slot -> (where it comes from in the stats file, how it is written, what a usable value is)
def _ms0(v):
    return f"{v:.0f}"


def _ms1(v):
    return f"{v:.1f}"


def _int(v):
    return f"{int(v)}"


def _date(v):
    return v.strip()[:10]


def _machine(v):
    return f"{v['machine'].strip()}, {v['system'].strip()}"


SLOTS = {
    "@@SCAN_SHORT_CHARS@@": (("scan_speed", "quickstart_input_chars"), _int, "num"),
    "@@SCAN_SHORT_MS@@": (("scan_speed", "quickstart_median_ms"), _ms1, "num"),
    "@@SCAN_ATTACK_N@@": (("scan_speed", "attack_corpus_n"), _int, "num"),
    "@@SCAN_ATTACK_MS@@": (("scan_speed", "attack_median_ms"), _ms1, "num"),
    "@@SCAN_DOC_N@@": (("scan_speed", "document_corpus_n"), _int, "num"),
    "@@SCAN_DOC_BYTES@@": (("scan_speed", "document_median_bytes"), lambda v: f"{int(v):,}", "num"),
    "@@SCAN_DOC_MS@@": (("scan_speed", "document_median_ms"), _ms0, "num"),
    "@@SCAN_KBPS@@": (("scan_speed", "throughput_kb_per_sec"), _ms0, "num"),
    "@@SCAN_PROVENANCE@@": (("scan_speed_provenance",), lambda v: str(v).strip(), "text"),
    "@@LANE_ON_MS@@": (("hook_speed", "hook_lane_on_min_ms"), _ms0, "num"),
    "@@LANE_OFF_MS@@": (("hook_speed", "hook_lane_off_min_ms"), _ms0, "num"),
    "@@PY_START_MS@@": (("hook_speed", "python_start_min_ms"), _ms0, "num"),
    "@@REPEATS@@": (("hook_speed", "repeats"), _int, "num"),
    "@@VERSION@@": (("hook_speed", "version"), lambda v: v.strip(), "version"),
    "@@DATE@@": (("hook_speed", "measured_at"), _date, "date"),
    "@@MACHINE_CLASS@@": (("hook_speed", "measured_on"), _machine, "machine"),
}
MARKER = re.compile(r"@@[A-Z]")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T|$)")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _text(v):
    return isinstance(v, str) and bool(v.strip())


def _usable(kind, value):
    """num: finite, above zero, not a bool. The rest: present and well formed."""
    if kind == "num":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0
    if kind == "text":
        return _text(value)
    if kind == "version":
        return _text(value) and bool(_VERSION_RE.match(value.strip()))
    if kind == "date":
        return _text(value) and bool(_DATE_RE.match(value.strip()))
    if kind == "machine":
        return isinstance(value, dict) and _text(value.get("machine")) and _text(value.get("system"))
    return False


def fill(readme_text, stats):
    """Return the README with every slot written from `stats`, or raise ValueError."""
    out = readme_text
    for slot, (path, fmt, kind) in SLOTS.items():
        if out.count(slot) < 1:
            raise ValueError(f"slot {slot} is not in the README")
        value = stats
        for key in path:
            if not isinstance(value, dict) or key not in value:
                raise ValueError(f"stats has no {'.'.join(path)} for {slot}")
            value = value[key]
        if not _usable(kind, value):
            raise ValueError(f"stats value for {slot} is not usable: {value!r}")
        out = out.replace(slot, fmt(value))
    if MARKER.search(out):
        raise ValueError("a @@ slot marker is left after filling")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--readme", default=str(ROOT / "README.md"))
    ap.add_argument("--stats", default=str(ROOT / "stats" / "current.json"))
    ap.add_argument("--check", action="store_true", help="only report whether a slot is left")
    args = ap.parse_args(argv)
    readme = pathlib.Path(args.readme)
    text = readme.read_text(encoding="utf-8")
    if args.check:
        left = len(MARKER.findall(text))
        print(f"{left} @@ slot marker(s) left in {readme.name}")
        return 1 if left else 0
    try:
        stats = json.loads(pathlib.Path(args.stats).read_text(encoding="utf-8"))
        new = fill(text, stats)
    except (ValueError, TypeError, OSError) as exc:
        print(f"fill_readme_slots: refused: {exc}", file=sys.stderr)
        return 1
    readme.write_text(new, encoding="utf-8")
    print(f"filled {len(SLOTS)} slots in {readme.name} from {pathlib.Path(args.stats).name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
