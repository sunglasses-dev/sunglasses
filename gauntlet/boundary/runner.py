"""One scenario, one ordered timeline, three layers.

Consumes the reviewer's package as delivered: `manifest.json` names the scenarios,
each directory carries `scenario.json` and `expected.json`, and this file does not
rebuild any of it. The output is one JSONL timeline per scenario with a shared
`run_id` and a monotonic `seq`, so a reader follows a single ordered story across
the client, the proxy and the destination instead of correlating three logs by
timestamp.

Replay is the default and it makes ZERO live calls. `--live` is refused without a
ledger, and the ledger is the thing the run cannot proceed without: every call is
appended to it before it is made, so a crashed run still leaves a count. A budget
enforced only in memory is a budget that disappears with the process.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from client.observe import InstrumentedClient, Mode, SpendNotAuthorised  # noqa: E402
from destination.sink import Destination                                 # noqa: E402
from proxy.passthrough import Passthrough                                # noqa: E402

PACKAGE = pathlib.Path.home() / ".claude" / "state" / "warroom" / "GATE2_SCENARIOS"


class LedgerRequired(RuntimeError):
    """A live batch was started without a durable call ledger."""


class Ledger:
    """Every live call, on disk, BEFORE it is made.

    A budget kept in memory vanishes with the process, and a crashed run then
    looks like a run that never spent anything. This is append-only and it is
    read back at startup, so a second invocation cannot quietly restart the count.
    """

    def __init__(self, path: pathlib.Path, budget: int):
        self.path = pathlib.Path(path)
        self.budget = budget
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Count CHARGES, not lines. The probe wrote a second line recording its
        # outcome and the ledger read it as another call: 3 calls reported as 4.
        # Over-counting is the safe direction and it is still wrong, and the same
        # bug under-counting would have quietly raised the ceiling.
        self.spent = 0
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get("charge") is True:
                    self.spent += 1

    def remaining(self) -> int:
        return self.budget - self.spent

    def charge(self, scenario_id: str, variant: str, note: str = "") -> None:
        if self.spent >= self.budget:
            raise SpendNotAuthorised(
                f"the ledger at {self.path} already records {self.spent} calls "
                f"against a budget of {self.budget}. Stop and report the count; "
                f"raising the ceiling is not this run's decision.")
        with self.path.open("a") as fh:
            fh.write(json.dumps({"charge": True, "at": time.time(),
                                 "scenario_id": scenario_id,
                                 "variant": variant, "note": note}) + "\n")
        self.spent += 1


class Timeline:
    """The three layers' receipts, merged, ordered, one file."""

    def __init__(self, run_id: str, scenario_id: str, variant: str):
        self.run_id = run_id
        self.scenario_id = scenario_id
        self.variant = variant
        self.rows: list[dict] = []

    def add(self, layer: str, kind: str, **fields) -> None:
        self.rows.append({"run_id": self.run_id, "seq": len(self.rows),
                          "at": time.time(), "layer": layer, "kind": kind,
                          "scenario_id": self.scenario_id, "variant": self.variant,
                          **fields})

    def absorb(self, layer: str, events: list[dict]) -> None:
        for event in events:
            self.add(layer, event.get("kind", "event"),
                     **{k: v for k, v in event.items()
                        if k not in ("kind", "run_id", "seq", "at")})

    def write(self, directory: pathlib.Path) -> pathlib.Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{self.scenario_id}.{self.variant}.timeline.jsonl"
        with path.open("w") as fh:
            for row in self.rows:
                fh.write(json.dumps(row) + "\n")
        return path


def load_manifest(package: pathlib.Path = PACKAGE) -> dict:
    manifest = json.loads((package / "manifest.json").read_text())
    assert manifest["schema_version"] == 1, manifest["schema_version"]
    return manifest


def scenario_of(entry: dict, package: pathlib.Path = PACKAGE) -> dict:
    return json.loads((package / entry["directory"] / "scenario.json").read_text())


def run_variant(entry, variant, *, outdir, package=PACKAGE, live=False,
                ledger: Ledger | None = None, client=None) -> Timeline:
    """One variant, replay by default. The control route runs with no proxy."""
    run_id = uuid.uuid4().hex[:12]
    timeline = Timeline(run_id, entry["id"], variant["name"])
    scenario = scenario_of(entry, package)
    setup = scenario["setup"]
    timeline.add("runner", "SCENARIO_OPENED", slot=scenario["slot"],
                 detector_channel=variant.get("detector_channel"),
                 deadline_ms=variant.get("deadline_ms", setup["size_policy"]["deadline_ms"]),
                 watchdog_ms=variant.get("watchdog_ms"),
                 mode="live" if live else "replay")
    if live:
        if ledger is None:
            raise LedgerRequired(
                "a live batch needs a durable ledger; refusing to spend against "
                "an in-memory count that a crash would erase")
        ledger.charge(entry["id"], variant["name"])
        timeline.add("runner", "CALL_CHARGED", spent=ledger.spent,
                     remaining=ledger.remaining())
    destination = Destination(run_id=run_id, drop_dir=outdir / "drop")
    timeline.add("destination", "SINK_READY", listened=False)
    proxy = Passthrough(
        deadline_ms=variant.get("deadline_ms", setup["size_policy"]["deadline_ms"]),
        watchdog_ms=variant.get("watchdog_ms", 3000),
        wire_frame_limit=setup["size_policy"]["wire_frame_byte_limit"],
        byte_budget=setup["size_policy"]["inspection_byte_budget"])
    timeline.absorb("proxy", proxy.events)
    timeline.add("destination", "SINK_RECEIPT", **destination.receipt())
    if client is not None:
        transcript = outdir / f"{entry['id']}.{variant['name']}.transcript.jsonl"
        observation = client.replay(entry["id"], variant["name"], transcript)
        timeline.add("client", "OBSERVATION", **observation.as_record())
    timeline.add("runner", "SCENARIO_CLOSED")
    return timeline


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--package", type=pathlib.Path, default=PACKAGE)
    parser.add_argument("--outdir", type=pathlib.Path, required=True)
    parser.add_argument("--only", help="one scenario id, e.g. G2-09")
    parser.add_argument("--live", action="store_true",
                        help="spend real model calls; needs --ledger and --budget")
    parser.add_argument("--ledger", type=pathlib.Path)
    parser.add_argument("--budget", type=int, default=0)
    parser.add_argument("--model", default="claude-haiku-4-5-20251001")
    args = parser.parse_args(argv)

    manifest = load_manifest(args.package)
    ledger = None
    if args.live:
        if not args.ledger or args.budget <= 0:
            raise LedgerRequired("--live needs --ledger PATH and --budget N")
        ledger = Ledger(args.ledger, args.budget)
    client = InstrumentedClient(
        args.outdir, mode=Mode.OBSERVED if args.live else Mode.REPLAY,
        live_call_budget=args.budget if args.live else 0, model=args.model)
    written = []
    for entry in manifest["scenarios"]:
        if args.only and entry["id"] != args.only:
            continue
        for variant in scenario_of(entry, args.package)["variants"]:
            timeline = run_variant(entry, variant, outdir=args.outdir,
                                   package=args.package, live=args.live,
                                   ledger=ledger, client=client)
            written.append(str(timeline.write(args.outdir)))
    print(json.dumps({"timelines": len(written), "live": args.live,
                      "calls_spent": ledger.spent if ledger else 0,
                      "outdir": str(args.outdir)}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
