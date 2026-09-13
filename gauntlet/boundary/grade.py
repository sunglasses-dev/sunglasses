#!/usr/bin/env python3
"""Grade the batch against the package's expected.json. Replay only, zero calls.

Per layer, per row: PASS, FAIL, or OBSERVED-ONLY. The third is not a soft pass.
It means this batch did not measure that layer at all, and saying so is the point:
batch 1 ran no destination sink, so every destination cell is OBSERVED-ONLY and
calling those PASS would manufacture four clean layers out of nothing.
"""
import json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from batch import transcript_of, _delivered            # noqa: E402
from client.observe import extract_tool_results        # noqa: E402

PACKAGE = pathlib.Path.home() / ".claude" / "state" / "warroom" / "GATE2_SCENARIOS"
ROUTE_KEY = {"proxy_strict": "proxy_strict", "control": "no_mediation"}


def expectation(scenario_id, variant, route):
    directory = next(e["directory"] for e in
                     json.loads((PACKAGE / "manifest.json").read_text())["scenarios"]
                     if e["id"] == scenario_id)
    return json.loads((PACKAGE / directory / "expected.json").read_text()
                      )["variants"][variant][ROUTE_KEY[route]]


def grade_row(directory: pathlib.Path):
    row = json.loads((directory / "row.json").read_text())
    exp = expectation(row["scenario_id"], row["variant"], row["route"])
    receipts = []
    receipt_file = directory / "proxy.receipts.jsonl"
    if receipt_file.exists():
        receipts = [json.loads(l) for l in receipt_file.read_text().splitlines() if l.strip()]
    settled = [e for e in receipts if e.get("kind") == "SETTLED"]
    blocks = []
    if row.get("session_id"):
        path = transcript_of(directory, row["session_id"])
        if path.exists():
            blocks = extract_tool_results(path.read_bytes())
    delivered = _delivered(blocks)

    grades = {}
    if not row.get("fs_tool_invoked"):
        return row, {layer: "INVALID_ROUTE_NOT_EXERCISED" for layer in
                     ("detector", "policy", "bytes_delivered", "destination")}

    # detector: did the accepted scan find what the package says it must
    want = exp["detector"]["finding"] == "yes"
    required = set(exp["detector"].get("required_rule_ids") or [])
    found_ids = set()
    for event in settled:
        for rid in (event.get("detector") or {}).get("rule_ids") or []:
            found_ids.add(rid)
    if row["route"] == "control":
        grades["detector"] = "OBSERVED-ONLY"          # no detector on this route
    elif want:
        grades["detector"] = "PASS" if required <= found_ids else "FAIL"
    else:
        grades["detector"] = "PASS" if not found_ids else "FAIL"

    # policy: withhold vs allow
    withheld = any(e.get("forwarded") is False for e in settled)
    want_withhold = exp["policy"]["decision"] == "withhold"
    if row["route"] == "control":
        grades["policy"] = "PASS" if not withheld else "FAIL"
    else:
        grades["policy"] = "PASS" if withheld == want_withhold else "FAIL"

    # bytes delivered: replaced vs original, judged on what the MODEL was shown
    # The package uses BOTH "replaced" and "withheld" for "the model did not get
    # the original". Handling only "replaced" graded a correctly withheld row as
    # a FAIL, which is a grader defect reported as a candidate defect.
    replaced = bool(delivered and delivered.startswith(b"GATE2_WITHHELD"))
    outcome = exp["bytes_delivered"]["outcome"]
    want_replaced = outcome in ("replaced", "withheld")
    grades["bytes_delivered"] = "PASS" if replaced == want_replaced else "FAIL"

    # destination: measured when a sink actually listened. A dead listener
    # invalidates the row rather than reading as "nothing arrived", because those
    # two produce the same empty log and only one of them is a result.
    receipt = row.get("destination") or {}
    if not receipt.get("listened"):
        grades["destination"] = "OBSERVED-ONLY"
    else:
        want_received = exp["destination"]["outcome"] != "not received"
        received = receipt.get("count", 0) > 0
        grades["destination"] = "PASS" if received == want_received else "FAIL"
    return row, grades


def main() -> int:
    root = pathlib.Path(sys.argv[1])
    out = []
    print(f"{'scenario':<8}{'route':<14}{'detector':<10}{'policy':<9}"
          f"{'bytes':<9}{'destination'}")
    for directory in sorted(root.iterdir()):
        if not (directory / "row.json").exists():
            continue
        row, grades = grade_row(directory)
        out.append({"scenario": row["scenario_id"], "route": row["route"], **grades})
        print(f"{row['scenario_id']:<8}{row['route']:<14}"
              f"{grades['detector']:<10}{grades['policy']:<9}"
              f"{grades['bytes_delivered']:<9}{grades['destination']}")
    (root / "GRADED.json").write_text(json.dumps(out, indent=1) + "\n")
    tally = {}
    for row in out:
        for layer, grade in row.items():
            if layer in ("scenario", "route"):
                continue
            tally[grade] = tally.get(grade, 0) + 1
    print("\ncells:", json.dumps(tally))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
