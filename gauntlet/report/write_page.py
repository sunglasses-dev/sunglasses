"""Write the gauntlet page into a landing checkout, or refuse and leave it alone.

Design: warroom/GAUNTLET_LANDING_WRITER_2026-09-23.md, T9 rulings 2026-09-23.

The landing repo never imports scanner code. It receives ONE file,
`<landing>/gauntlet.html`, through a normal landing PR, and its own gates
(`_tools/gauntlet_dryrun.py` and the claims gate) judge it there. Nothing here
deploys.

Three rules, in order:

  VALIDATE AND RENDER FIRST. An artifact that does not validate writes nothing
  and records nothing: the page already up stays byte for byte, and ages out on
  the reader's side (render's freshness script, `expired()` below).

  SELECT THROUGH THE PERSISTED HISTORY. `publish.select_persisted` applies the
  same "latest attempt, never latest success; never older over newer" rule as
  the in-memory publisher, across processes, and records refusals too.

  A REFUSED RUN IS STILL A PAGE. An unreviewed map or a failed run produces a
  schema-valid refused report (produce.py, E5); it renders, it is selected like
  any attempt, and it replaces a green page. That is the Oct 12 default: a page
  that says refused and why, never a blank and never yesterday's green.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import publish                                             # noqa: E402
import render                                              # noqa: E402

EVIDENCE = pathlib.Path(__file__).resolve().parents[1] / "boundary" / "evidence"
REPORT_PATH = EVIDENCE / "nightly.json"
ATTEMPTS_PATH = EVIDENCE / "attempts.jsonl"
PAGE_NAME = "gauntlet.html"


class WriterRefused(Exception):
    """The writer was pointed somewhere it will not write."""


def write(report_path: pathlib.Path, landing: pathlib.Path,
          attempts: pathlib.Path = ATTEMPTS_PATH) -> pathlib.Path:
    """The written page's path. Raises instead of writing a page it cannot stand behind."""
    landing = pathlib.Path(landing)
    if not landing.is_dir():
        raise WriterRefused(f"landing checkout {landing} is not a directory")
    raw = pathlib.Path(report_path).read_bytes()
    report = json.loads(raw)
    page = render.render(report)                      # WillNotRender: nothing recorded
    publish.select_persisted(report, attempts,        # StaleOverwrite: recorded, not written
                             digest=hashlib.sha256(raw).hexdigest())
    target = landing / PAGE_NAME
    # Atomic: a reader or a git add never sees half a page.
    fd, tmp = tempfile.mkstemp(dir=landing, prefix=".gauntlet-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(page)
        os.replace(tmp, target)
    except BaseException:
        pathlib.Path(tmp).unlink(missing_ok=True)
        raise
    return target


def expired(attempts: pathlib.Path = ATTEMPTS_PATH,
            now: datetime.datetime | None = None) -> bool:
    """Is what is up older than its own policy? Read from the history, not memory.

    Only the SELECTED attempt counts: a refused straggler is not what is up, and
    must not refresh anything. No history at all is expired, never green.
    """
    try:
        lines = [json.loads(x) for x in pathlib.Path(attempts).read_text().splitlines()
                 if x.strip()]
    except OSError:
        return True
    selected = [x for x in lines if x.get("selected")]
    if not selected:
        return True
    site = publish.Published(report={"freshness": {
        "measured_at": selected[-1].get("measured_at"),
        "policy_hours": selected[-1].get("policy_hours")}})
    return site.expired(now)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--report", type=pathlib.Path, default=REPORT_PATH)
    parser.add_argument("--landing", type=pathlib.Path, required=True,
                        help="a landing checkout; gauntlet.html is written at its root")
    parser.add_argument("--attempts", type=pathlib.Path, default=ATTEMPTS_PATH)
    args = parser.parse_args(argv)
    try:
        target = write(args.report, args.landing, args.attempts)
    except (render.WillNotRender, publish.StaleOverwrite, WriterRefused,
            OSError, ValueError) as exc:
        print(f"REFUSED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    state = "EXPIRED" if expired(args.attempts) else "within policy"
    print(f"wrote {target} ({state})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
