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
import contextlib
import fcntl
import hashlib
import json
import os
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


class LedgerUnreadable(RuntimeError):
    """The ledger contains a line that cannot be read as a charge or not a charge.

    Separate from SpendNotAuthorised because it is a different answer: not "you
    have spent enough" but "I cannot tell you what has been spent", and the two
    must never be confused by a caller deciding whether to make a call.
    """


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
        self.spent = len(self._charges())

    def _charges(self) -> dict:
        """Every charge on disk, by id. A line it cannot read is FATAL.

        Count CHARGES, not lines. The probe wrote a second line recording its
        outcome and the ledger read it as another call: 3 calls reported as 4.
        Over-counting is the safe direction and it is still wrong, and the same
        bug under-counting would have quietly raised the ceiling.

        AND AN UNREADABLE LINE IS NOT A LINE THAT SAYS NOTHING. This used to
        `continue` past anything that failed to parse, which is under-counting
        by exactly the mechanism the paragraph above calls dangerous: a truncated
        write, a partial flush, or two writers interleaving produces garbage that
        silently buys another call. A ledger that cannot be read in full cannot
        authorise anything, so it refuses instead.
        """
        charges: dict = {}
        if not self.path.exists():
            return charges
        for number, line in enumerate(self.path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as broken:
                raise LedgerUnreadable(
                    f"{self.path} line {number} is not readable JSON ({broken}). "
                    f"A ledger that cannot be read in full cannot authorise a "
                    f"call, because an unreadable line is indistinguishable from "
                    f"a charge. Repair or archive it deliberately.") from broken
            if not isinstance(row, dict):
                raise LedgerUnreadable(f"{self.path} line {number} is not an object")
            if "charge" not in row:
                continue                      # a terminal row, not a charge
            if row["charge"] is not True:
                raise LedgerUnreadable(
                    f"{self.path} line {number} has an ambiguous charge field "
                    f"{row['charge']!r}. Only the literal true is a charge.")
            charge_id = row.get("charge_id")
            if not charge_id:
                raise LedgerUnreadable(
                    f"{self.path} line {number} is a charge with no charge_id, "
                    f"so no terminal artifact can be tied to it.")
            if charge_id in charges:
                raise LedgerUnreadable(
                    f"{self.path} records charge_id {charge_id!r} twice.")
            charges[charge_id] = row
        return charges

    def remaining(self) -> int:
        return self.budget - self.spent

    @contextlib.contextmanager
    def _exclusive(self):
        """One writer at a time, across PROCESSES.

        Two runners could each read `spent` and each decide there was room, so a
        budget of 35 buys 36 calls and the receipt shows neither writer doing
        anything wrong. The count is re-read from disk INSIDE the lock, because
        the number this instance remembers is exactly the stale thing.
        """
        with self.path.open("a+") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield handle
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def charge(self, scenario_id: str, variant: str, note: str = "") -> str:
        charge_id = uuid.uuid4().hex[:12]
        with self._exclusive() as handle:
            spent = len(self._charges())
            if spent >= self.budget:
                self.spent = spent
                raise SpendNotAuthorised(
                    f"the ledger at {self.path} already records {spent} calls "
                    f"against a budget of {self.budget}. Stop and report the "
                    f"count; raising the ceiling is not this run's decision.")
            handle.write(json.dumps({"charge": True, "charge_id": charge_id,
                                     "at": time.time(),
                                     "scenario_id": scenario_id,
                                     "variant": variant, "note": note}) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            self.spent = spent + 1
        return charge_id

    def settle(self, charge_id: str, artifact: str, outcome: str = "") -> None:
        """Tie a charge to the thing it produced.

        A charge written before a call and never answered is a call whose result
        nobody can find, and the exam had rows in exactly that state. Recording
        the terminal artifact makes the gap visible instead of arithmetical.
        """
        with self._exclusive() as handle:
            handle.write(json.dumps({"settled": charge_id, "at": time.time(),
                                     "artifact": artifact,
                                     "outcome": outcome}) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def unsettled(self) -> list:
        """Charges with no terminal artifact behind them."""
        charges = self._charges()
        settled = set()
        for line in self.path.read_text().splitlines() if self.path.exists() else []:
            if not line.strip():
                continue
            row = json.loads(line)
            if isinstance(row, dict) and row.get("settled"):
                settled.add(row["settled"])
        return [row for charge_id, row in charges.items() if charge_id not in settled]


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


def resolve_payload_ref(variant: dict) -> bytes:
    """The bytes a second generation variant points at, verified by hash.

    G2-13 onwards reuse the earlier seeds' payloads by reference rather than
    copying them, which keeps one stimulus in one place and makes a drifted
    source a silent change of stimulus for every seed pointing at it. So the
    reference is resolved HERE, once, with the digest checked, rather than in
    each consumer: a resolver that trusts the path and not the hash turns the
    saving into the hazard.

    Raises rather than returning something plausible. A stimulus that is not the
    one the seed names is the defect this whole harness spent today fixing.
    """
    ref = variant.get("payload_ref")
    if not ref:
        raise KeyError(f"variant {variant.get('name')!r} has no payload_ref")
    path = pathlib.Path(ref["path"])
    if not path.is_file():
        raise FileNotFoundError(
            f"{variant.get('name')!r} points at {path}, which is not there")
    body = path.read_bytes()
    actual = hashlib.sha256(body).hexdigest()
    if actual != ref["sha256"]:
        raise ValueError(
            f"{variant.get('name')!r} points at {path}, which hashes to "
            f"{actual} and the seed names {ref['sha256']}. The stimulus has "
            f"drifted from what the fixture describes.")
    return body


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
