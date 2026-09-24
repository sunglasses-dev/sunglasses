"""How a capability-map review is RECORDED, and how `load_map` checks it.

T9 row 2026-09-23. `review_state: reviewed` was a string anyone could type, and
two test fixtures did. Now a review is a RECEIPT:

  reviews/<revision>.receipt.json   map revision + map CONTENT sha256 (every
                                    field except review_state and
                                    review_receipt) + verdict + reviewer +
                                    round + recorded_at + verdict file + sha256
  reviews/<revision>.VERDICT.md     the reviewer's verdict text, committed

`record()` is the only writer: it refuses a verdict whose text does not say the
verdict it is recorded as, then sets review_state and review_receipt. `verify()`
refuses: reviewed with no receipt · a receipt for other content (the map moved
after its review) · a NO GO · a verdict file that is missing or rewritten.

LIMIT, said out loud: a receipt does not AUTHENTICATE the reviewer. It turns a
typed string into a hash-bound artifact in git, carrying the verdict text a
reader can check, and it makes the typed string alone fail.

  python3 gauntlet/report/review.py record --verdict-file V.md --verdict GO \\
      --reviewer ASTRA --round <round-id>          (records against the real map)
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import sys

REVIEW_FIELDS = ("review_state", "review_receipt")
VERDICTS = ("GO", "NO GO")


class ReviewInvalid(Exception):
    """The review record does not establish a GO for this map's content."""


def content_sha256(data: dict) -> str:
    body = {k: v for k, v in data.items() if k not in REVIEW_FIELDS}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def _says(text: str) -> str | None:
    """The verdict the TEXT states: NO GO wins over GO when both appear."""
    if re.search(r"\bNO[\s-]+GO\b", text):
        return "NO GO"
    if re.search(r"\bGO\b", text):
        return "GO"
    return None


def record(map_path, verdict_text: str, *, verdict: str, reviewer: str, round_id: str,
           now: str | None = None) -> pathlib.Path:
    map_path = pathlib.Path(map_path)
    if verdict not in VERDICTS:
        raise ReviewInvalid(f"verdict {verdict!r} is not one of {VERDICTS}")
    said = _says(verdict_text)
    if said != verdict:
        raise ReviewInvalid(f"the verdict text says {said!r} and the record claims {verdict!r}")
    if not reviewer or not round_id:
        raise ReviewInvalid("a review names its reviewer and its round")
    data = json.loads(map_path.read_text())
    rev = data.get("revision") or "unrevised"
    reviews = map_path.parent / "reviews"
    reviews.mkdir(exist_ok=True)
    vfile = reviews / f"{rev}.VERDICT.md"
    vfile.write_text(verdict_text)
    receipt = {
        "map_revision": rev, "map_content_sha256": content_sha256(data),
        "verdict": verdict, "reviewer": reviewer, "round": round_id,
        "recorded_at": now or datetime.datetime.now().isoformat(timespec="seconds"),
        "verdict_file": str(vfile.relative_to(map_path.parent)),
        "verdict_sha256": hashlib.sha256(vfile.read_bytes()).hexdigest(),
    }
    rfile = reviews / f"{rev}.receipt.json"
    rfile.write_text(json.dumps(receipt, indent=1) + "\n")
    data["review_state"] = "reviewed" if verdict == "GO" else "rejected"
    data["review_receipt"] = str(rfile.relative_to(map_path.parent))
    raw = map_path.read_text()
    map_path.write_text(json.dumps(data, indent=1, ensure_ascii=raw.isascii()) + "\n")
    return rfile


def verify(map_path, data: dict) -> dict:
    """The receipt behind `reviewed`, or ReviewInvalid naming what is wrong."""
    base = pathlib.Path(map_path).parent
    name = data.get("review_receipt")
    if not name:
        raise ReviewInvalid("review_state is 'reviewed' with no review_receipt: a typed "
                            "state is not a review. Record one with review.py record")
    try:
        receipt = json.loads((base / name).read_text())
    except Exception as exc:
        raise ReviewInvalid(f"review receipt {name} is unreadable: {exc}") from None
    missing = [f for f in ("map_content_sha256", "verdict", "reviewer", "round",
                           "verdict_file", "verdict_sha256") if not receipt.get(f)]
    if missing:
        raise ReviewInvalid(f"review receipt {name} lacks {missing}")
    if receipt["verdict"] != "GO":
        raise ReviewInvalid(f"the recorded review is {receipt['verdict']!r} (NO GO), not a GO")
    if receipt["map_content_sha256"] != content_sha256(data):
        raise ReviewInvalid("the map content changed after its review (content sha256 differs "
                            "from the receipt): the review is about a different map")
    vpath = base / receipt["verdict_file"]
    if not vpath.is_file():
        raise ReviewInvalid(f"the verdict file {receipt['verdict_file']} is missing")
    if hashlib.sha256(vpath.read_bytes()).hexdigest() != receipt["verdict_sha256"]:
        raise ReviewInvalid("the verdict file was rewritten after it was recorded")
    if _says(vpath.read_text()) != "GO":
        raise ReviewInvalid("the verdict text does not state GO")
    return receipt


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record")
    r.add_argument("--verdict-file", required=True)
    r.add_argument("--verdict", required=True, choices=VERDICTS)
    r.add_argument("--reviewer", required=True)
    r.add_argument("--round", required=True)
    r.add_argument("--map", default=str(pathlib.Path(__file__).with_name("capability_map.json")))
    a = ap.parse_args(argv)
    out = record(a.map, pathlib.Path(a.verdict_file).read_text(), verdict=a.verdict,
                 reviewer=a.reviewer, round_id=a.round)
    print(f"recorded {a.verdict} -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
