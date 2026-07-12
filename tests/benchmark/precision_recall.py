#!/usr/bin/env python3
"""
Sunglasses reproducible precision / recall benchmark — "Receipts".

Runs the SHIPPED scanner engine over a labeled dataset and prints
precision, recall, and F1. Deterministic: same clone + same command ->
byte-identical results, verified by the SHA-256 of the metrics block.

    python3 tests/benchmark/precision_recall.py            # human-readable
    python3 tests/benchmark/precision_recall.py --json     # machine-readable

Dataset
-------
POSITIVES  tests/benchmark/attacks.json  — labeled agent-input attacks
           (an attack is CAUGHT when decision is 'block' or 'quarantine').
NEGATIVES  tests/fp_real_world_corpus/*.md — real famous-repo READMEs that
           MUST stay clean (a flag on one is a false positive).

No randomness, no network, no LLM judge. Draws the engine from the local
package so it measures exactly what ships.
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)

from sunglasses.engine import SunglassesEngine  # noqa: E402

CAUGHT = {"block", "quarantine"}          # a real detection
CORPUS = os.path.join(REPO, "tests", "fp_real_world_corpus")


def load_positives():
    with open(os.path.join(HERE, "attacks.json")) as f:
        data = json.load(f)
    return sorted(data["attacks"], key=lambda a: a["id"])


def load_negatives():
    files = sorted(f for f in os.listdir(CORPUS) if f.endswith(".md"))
    out = []
    for name in files:
        with open(os.path.join(CORPUS, name), errors="ignore") as fh:
            out.append((name, fh.read()))
    return out


def run():
    engine = SunglassesEngine()
    positives = load_positives()
    negatives = load_negatives()

    tp = fn = 0
    misses = []
    for a in positives:
        decision = engine.scan(a["text"], a.get("channel", "message")).decision
        if decision in CAUGHT:
            tp += 1
        else:
            fn += 1
            misses.append({"id": a["id"], "category": a["category"], "decision": decision})

    fp = tn = 0
    false_positives = []
    for name, text in negatives:
        decision = engine.scan(text, "file").decision
        if decision in CAUGHT:
            fp += 1
            false_positives.append(name)
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    metrics = {
        "engine_version": engine.info()["version"],
        "positives": len(positives),
        "negatives": len(negatives),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }
    # Determinism receipt: SHA-256 over the canonicalized metrics.
    metrics["sha256"] = hashlib.sha256(
        json.dumps(metrics, sort_keys=True).encode()
    ).hexdigest()

    return {"metrics": metrics, "misses": misses, "false_positives": sorted(false_positives)}


def main():
    result = run()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        return
    m = result["metrics"]
    print(f"\n  Sunglasses benchmark — engine v{m['engine_version']}")
    print(f"  {'-' * 46}")
    print(f"  positives (attacks) : {m['positives']:>4}   caught {m['true_positives']}  missed {m['false_negatives']}")
    print(f"  negatives (readmes) : {m['negatives']:>4}   clean  {m['true_negatives']}  flagged {m['false_positives']}")
    print(f"  {'-' * 46}")
    print(f"  precision : {m['precision']*100:5.1f}%")
    print(f"  recall    : {m['recall']*100:5.1f}%")
    print(f"  F1        : {m['f1']:.3f}")
    print(f"  sha256    : {m['sha256'][:16]}…  (reproducible)")
    if result["misses"]:
        print(f"\n  missed ({len(result['misses'])}): "
              + ", ".join(f"{x['id']}[{x['decision']}]" for x in result["misses"]))
    if result["false_positives"]:
        print(f"  false positives ({len(result['false_positives'])}): "
              + ", ".join(result["false_positives"]))
    print()


if __name__ == "__main__":
    main()
