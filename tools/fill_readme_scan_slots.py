#!/usr/bin/env python3
"""Fill the README scan-speed table from `stats/current.json`; no figure is typed by hand.

The README's "Performance" table and the sentence under it carry nine `@@SCAN_*@@` slots. This
tool writes them from the `scan_speed` block and `scan_speed_provenance` of the stats file that
`tools/gen_perf_stats.py` produced, so the README can only say what the generator measured and
when. It runs at the release cut, on the README that ships.

    python3 -I tools/fill_readme_scan_slots.py [--readme README.md] [--stats stats/current.json]
    python3 -I tools/fill_readme_scan_slots.py --check     # exit 1 if any @@SCAN_*@@ slot is left

It refuses (exit 1, nothing written) when a slot is missing from the README, a stats key is
missing, or a `@@SCAN_` marker is left after filling, so an unfilled slot cannot ship.
"""
import argparse
import json
import math
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# slot -> (where it comes from in the stats file, how it is written)
SLOTS = {
    "@@SCAN_SHORT_CHARS@@": (("scan_speed", "quickstart_input_chars"), lambda v: f"{int(v)}"),
    "@@SCAN_SHORT_MS@@": (("scan_speed", "quickstart_median_ms"), lambda v: f"{v:.1f}"),
    "@@SCAN_ATTACK_N@@": (("scan_speed", "attack_corpus_n"), lambda v: f"{int(v)}"),
    "@@SCAN_ATTACK_MS@@": (("scan_speed", "attack_median_ms"), lambda v: f"{v:.1f}"),
    "@@SCAN_DOC_N@@": (("scan_speed", "document_corpus_n"), lambda v: f"{int(v)}"),
    "@@SCAN_DOC_BYTES@@": (("scan_speed", "document_median_bytes"), lambda v: f"{int(v):,}"),
    "@@SCAN_DOC_MS@@": (("scan_speed", "document_median_ms"), lambda v: f"{v:.0f}"),
    "@@SCAN_KBPS@@": (("scan_speed", "throughput_kb_per_sec"), lambda v: f"{v:.0f}"),
    "@@SCAN_PROVENANCE@@": (("scan_speed_provenance",), lambda v: str(v).strip()),
}
MARKER = "@@SCAN_"
PROVENANCE = "@@SCAN_PROVENANCE@@"


def _usable(slot, value):
    """A measurement is a finite positive number; the provenance is a non-empty string."""
    if slot == PROVENANCE:
        return isinstance(value, str) and bool(value.strip())
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def fill(readme_text, stats):
    """Return the README with every scan slot written from `stats`, or raise ValueError."""
    out = readme_text
    for slot, (path, fmt) in SLOTS.items():
        if out.count(slot) < 1:
            raise ValueError(f"slot {slot} is not in the README")
        value = stats
        for key in path:
            if not isinstance(value, dict) or key not in value:
                raise ValueError(f"stats has no {'.'.join(path)} for {slot}")
            value = value[key]
        if not _usable(slot, value):
            raise ValueError(f"stats value for {slot} is not usable: {value!r}")
        out = out.replace(slot, fmt(value))
    if MARKER in out:
        raise ValueError("a @@SCAN_ marker is left after filling")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--readme", default=str(ROOT / "README.md"))
    ap.add_argument("--stats", default=str(ROOT / "stats" / "current.json"))
    ap.add_argument("--check", action="store_true", help="only report whether a scan slot is left")
    args = ap.parse_args(argv)
    readme = pathlib.Path(args.readme)
    text = readme.read_text(encoding="utf-8")
    if args.check:
        left = text.count(MARKER)
        print(f"{left} @@SCAN_ marker(s) left in {readme.name}")
        return 1 if left else 0
    try:
        stats = json.loads(pathlib.Path(args.stats).read_text(encoding="utf-8"))
        new = fill(text, stats)
    except (ValueError, TypeError, OSError) as exc:
        print(f"fill_readme_scan_slots: refused: {exc}", file=sys.stderr)
        return 1
    readme.write_text(new, encoding="utf-8")
    print(f"filled {len(SLOTS)} scan slots in {readme.name} from {pathlib.Path(args.stats).name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
