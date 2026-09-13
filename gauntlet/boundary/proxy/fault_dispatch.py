#!/usr/bin/env python3
"""Select the scanner fault the scenario declares, by direction and held payload.

ASTRA's requirement-2 finding, in his words: "all six generated G2-08/09/11
batch configurations select ordinary scan mode: the examiner dispatcher was
necessary and is not a candidate capability". He had to write a dispatcher to
run those scenarios at all, which means the instrument could not exercise its
own fault seeds and every one of those rows was measuring an unfaulted scan.

`batch` configures ONE scanner for a whole session and the proxy hands it one
message at a time, so the mode cannot be chosen when the config is written: the
same session carries the faulted message and the healthy one that proves the
fault was not global. G2-11 is exactly that shape, a held request cancelled
while a second request with id 112 must still complete. So the choice is made
per scan, here, from the payload actually held.

Matching is by DIGEST of the held text against the variant's own payload file,
never by "this is the first message" or by size. The healthy message in a
barrier scenario is a different document, and a dispatcher that faulted on
arrival order would fault the wrong one the moment the pump stopped waiting.

Anything this does not recognise runs an ordinary scan. A dispatcher that
guessed would inject a fault into a scenario that never asked for one, which is
a worse failure than not injecting the one that did: the row would still produce
a verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys

PACKAGE = pathlib.Path.home() / ".claude" / "state" / "warroom" / "GATE2_SCENARIOS"
FAULT_WORKER = PACKAGE / "fault_worker.py"

# The modes this dispatcher can select. Named in the argv on purpose: a
# configuration has to show which faults the session is able to inject, so a
# reader of the config can see the capability without running it.
SELECTABLE = ("exception", "hang", "barrier")


def declared_fault(run_dir: pathlib.Path, held: str):
    """The mode this scenario declares for the payload actually held, or None.

    Reads the materialised run directory, not the package: the run directory is
    what this session was built from, and reaching back into the package would
    let a dispatcher fault a message the session never materialised.
    """
    manifest = run_dir / "materialised.fault.json"
    if not manifest.is_file():
        return None
    try:
        record = json.loads(manifest.read_text())
    except ValueError:
        return None
    digest = hashlib.sha256(held.encode("utf-8", "surrogatepass")).hexdigest()
    if record.get("payload_sha256") != digest:
        return None
    kind = (record.get("fault") or {}).get("kind") or ""
    # `barrier_hold` in the package, `barrier` on the worker's command line. The
    # scenario names the behaviour and the worker names the flag.
    mode = kind.replace("_hold", "")
    return mode if mode in SELECTABLE else None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="select the declared scanner fault")
    parser.add_argument("--run-dir", type=pathlib.Path, required=True)
    parser.add_argument("--engine-root", type=pathlib.Path)
    parser.add_argument("--channel", default="api_response")
    parser.add_argument("--modes", nargs="+", default=list(SELECTABLE),
                        help="the fault modes this session is able to select")
    args = parser.parse_args(argv)

    held = sys.stdin.buffer.read().decode("utf-8", "surrogatepass")
    mode = declared_fault(args.run_dir, held) or "scan"
    if mode not in args.modes and mode != "scan":
        mode = "scan"

    command = [sys.executable, str(FAULT_WORKER), mode]
    if args.engine_root:
        command += ["--engine-root", str(args.engine_root)]
    command += ["--channel", args.channel,
                "--started", str(args.run_dir / f"fault.{mode}.started")]
    if mode == "barrier":
        # The worker refuses a barrier without one rather than guessing a
        # duration, which is the right refusal: a timing guess would settle the
        # scenario on the clock instead of on the cancellation.
        command += ["--release", str(args.run_dir / "fault.release")]

    completed = subprocess.run(command, input=held.encode("utf-8", "surrogatepass"),
                               stdout=None, stderr=None,
                               env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
