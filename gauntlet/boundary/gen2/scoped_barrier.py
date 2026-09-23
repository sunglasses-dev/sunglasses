#!/usr/bin/env python3
"""Hold ONE item at the barrier, scan every other item normally.

WHY THIS EXISTS. The scanner command is fixed for the whole session, so
`fault_worker.py barrier` held EVERY scan, not the one item an `arm_fault` kind
names. On G2-20.typed_ids the secondary was held by the primary's fault, killed
at SCAN_DEADLINE, and the independence row read held:true for a completion that
was a refusal. The product does not do that: on 1cae43a it scans inline on one
reader thread per direction (serve.py:199, route.py:462), so a held result
stalls only the frames AFTER it. A barrier that also catches frames before it
is the harness authoring a stall the product would not have.

The mediator names the item it is scanning in GAUNTLET_ITEM (id and direction,
as JSON so "2001" and 2001 stay two ids). The executor names the item the fault
is aimed at in `--item-file`. Match: exec the delivered worker in `barrier`
mode. Anything else, including an item the mediator did not name: `scan`.
The delivered `fault_worker.py` is not modified.
"""
import argparse
import json
import os
import pathlib
import sys

ITEM_ENV = "GAUNTLET_ITEM"


def _key(item):
    """Type-aware identity: json.dumps keeps "2001" and 2001 apart."""
    return (json.dumps(item.get("id"), sort_keys=True), item.get("direction"))


def is_target(named: dict | None, target: dict) -> bool:
    """Whether the item the mediator named is the one the fault is aimed at.

    An unnamed item is NOT the target. Holding it would re-create the
    session-wide barrier for any mediator that forgot to name its items, and
    that failure would look exactly like the product stalling.
    """
    if not named or "id" not in named or "direction" not in named:
        return False
    return _key(named) == _key(target)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--fault-worker", required=True, type=pathlib.Path)
    p.add_argument("--item-file", required=True, type=pathlib.Path)
    p.add_argument("--release", required=True, type=pathlib.Path)
    p.add_argument("--engine-root", type=pathlib.Path)
    # Appended by the mediator to every scanner argv; passed straight through.
    p.add_argument("--channel")
    args = p.parse_args(argv)
    target = json.loads(args.item_file.read_text())
    try:
        named = json.loads(os.environ.get(ITEM_ENV, "null"))
    except ValueError:
        named = None
    mode = "barrier" if is_target(named, target) else "scan"
    if mode == "barrier":
        # MEASURED, NOT CONFIGURED. What actually entered the barrier, written
        # before the hold starts, so a reader counts holds rather than trusting
        # the item file to have been obeyed.
        with open(args.item_file.with_name("barrier.held.jsonl"), "a") as log:
            log.write(json.dumps(named) + "\n")
    child = [sys.executable, str(args.fault_worker), mode]
    if mode == "barrier":
        child += ["--release", str(args.release)]
    if args.engine_root:
        child += ["--engine-root", str(args.engine_root)]
    if args.channel:
        child += ["--channel", args.channel]
    os.execv(sys.executable, child)


if __name__ == "__main__":
    main()
