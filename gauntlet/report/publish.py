"""Choose which attempt the page shows, and refuse to let an old one win.

Separated from the producer on purpose (E5). The producer measures and always
emits, including when it refuses. The publisher decides what is committed, and
it has exactly two jobs it must not get wrong:

  NEVER SELECT "LAST SUCCESS" AS "LATEST". Picking the newest run that happened
  to be green is how a dashboard shows a system that has been failing for a week
  as though it were passing. The latest ATTEMPT is what the page shows, whatever
  it says.

  NEVER LET AN OLDER ATTEMPT OVERWRITE A NEWER ONE. Two runs overlapping, the
  slower one finishing second, and yesterday's numbers land on top of today's.

It keeps the attempt history immutable, so a mutable latest pointer cannot erase
the failures it points past.
"""
from __future__ import annotations

import dataclasses
import datetime
import fcntl
import json
import os
import pathlib


class StaleOverwrite(Exception):
    """An attempt that finished earlier tried to replace a later one."""


@dataclasses.dataclass
class Published:
    report: dict | None = None
    finished_at: str | None = None
    history: list = dataclasses.field(default_factory=list)

    def select(self, report: dict) -> dict:
        """Publish this attempt, or refuse it for being behind what is up."""
        finished = (report.get("run") or {}).get("finished_at")
        if not finished:
            raise StaleOverwrite("an attempt with no finish time cannot be ordered")
        self.history.append({"id": report["run"].get("id"),
                             "finished_at": finished,
                             "outcome": report["run"].get("outcome")})
        if self.finished_at is not None and finished <= self.finished_at:
            # Refused, and the history still records that it happened.
            raise StaleOverwrite(
                f"attempt finished {finished} is not newer than the published "
                f"{self.finished_at}. An older attempt finishing second must "
                "not replace what is up.")
        # LATEST ATTEMPT, not latest success. A refusal replaces a green page.
        self.report, self.finished_at = report, finished
        return report

    def expired(self, now: datetime.datetime | None = None) -> bool:
        """True when what is published is older than its own policy allows.

        Expiry is the backstop for a publisher that stopped entirely: if no
        attempt arrives at all, nothing here can notice, so the page must age
        out on the reader's side rather than stay green forever.
        """
        if self.report is None:
            return True
        fresh = self.report.get("freshness") or {}
        measured, hours = fresh.get("measured_at"), fresh.get("policy_hours")
        if not measured or not hours:
            return True
        now = now or datetime.datetime.now(datetime.timezone.utc)
        try:
            when = datetime.datetime.fromisoformat(measured)
        except ValueError:
            return True
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        return (now - when).total_seconds() > hours * 3600


def select_persisted(report: dict, history: pathlib.Path, *, digest: str) -> dict:
    """`Published.select`, with the history in a FILE every process reads.

    The nightly and a manual rerun are two processes. An in-memory refusal
    protects neither from the other, so the ordering rule reads the append-only
    history under an exclusive lock, applies the SAME `select` as above, and
    appends what happened, including a refusal.

    The one addition: the attempt that is already up, offered again (same
    report bytes), is a RETRY. A writer that recorded its selection and then
    failed to write the page must be able to finish, and a retried landing PR
    must not grow the history.
    """
    history = pathlib.Path(history)
    history.parent.mkdir(parents=True, exist_ok=True)
    run = report.get("run") or {}
    fresh = report.get("freshness") or {}
    with open(history, "a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        lines = [json.loads(x) for x in fh.read().splitlines() if x.strip()]
        selected = [x for x in lines if x.get("selected")]
        current = selected[-1] if selected else None
        if current is not None and current.get("report_sha256") == digest:
            return current
        entry = {"run_id": run.get("id"), "finished_at": run.get("finished_at"),
                 "outcome": run.get("outcome"), "report_sha256": digest,
                 "measured_at": fresh.get("measured_at"),
                 "policy_hours": fresh.get("policy_hours"), "selected": False}
        site = Published(finished_at=current["finished_at"] if current else None)
        try:
            site.select(report)
            entry["selected"] = True
        finally:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry
