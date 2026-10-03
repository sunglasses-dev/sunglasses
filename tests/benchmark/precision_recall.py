#!/usr/bin/env python3
"""
Sunglasses reproducible precision / recall benchmark — "Receipts".

Runs the SHIPPED scanner engine over a labeled dataset and prints
precision, recall, and F1. Deterministic: same clone + same command ->
byte-identical results, verified by the SHA-256 of the metrics block.

    python3 tests/benchmark/precision_recall.py            # human-readable
    python3 tests/benchmark/precision_recall.py --json     # machine-readable
    python3 tests/benchmark/precision_recall.py --installed  # the pip installed package

By default the engine comes from this checkout. --installed measures the
package on the normal import path (what `pip install sunglasses` put there)
against the same dataset, and refuses when that package turns out to be the
checkout (an editable install, or PYTHONPATH pointing at the repo).

Dataset
-------
POSITIVES  tests/benchmark/attacks.json  — labeled agent-input attacks
           (an attack is CAUGHT when decision is 'block' or 'quarantine').
NEGATIVES  tests/fp_real_world_corpus/*.md — real famous-repo READMEs that
           MUST stay clean (a flag on one is a false positive).

No randomness, no network, no LLM judge. The report says which engine it
measured, so a source tree run and a wheel run cannot be told apart by hand.
"""

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

CAUGHT = {"block", "quarantine"}          # a real detection
CORPUS = os.path.join(REPO, "tests", "fp_real_world_corpus")


def _inside_checkout(path):
    real = os.path.realpath(path)
    root = os.path.realpath(REPO)
    return real == root or real.startswith(root + os.sep)


def _refuse(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def load_engine(installed=False):
    """Return (engine class, "checkout" or "installed", path of the engine module).

    Default: the checkout goes first on sys.path, so the source tree is measured.
    installed=True leaves sys.path alone and takes whatever the interpreter
    finds, then refuses if that is the checkout, because calling a source tree
    "installed" is the one mistake this flag exists to prevent."""
    if not installed and (not sys.path or sys.path[0] != REPO):
        sys.path.insert(0, REPO)
    try:
        from sunglasses.engine import SunglassesEngine
    except ImportError as exc:
        if not installed:
            raise
        _refuse(f"no installed sunglasses package to measure ({exc}). pip install sunglasses, then run again.")
    where = os.path.realpath(sys.modules["sunglasses.engine"].__file__)
    if installed and _inside_checkout(where):
        _refuse(f"the importable sunglasses package is the checkout ({where}), not an installed one. "
                "Run from an environment where the wheel is installed and the repo is not on the import path.")
    return SunglassesEngine, ("installed" if installed else "checkout"), where


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


def run(installed=False):
    engine_cls, source, engine_path = load_engine(installed)
    engine = engine_cls()
    positives = load_positives()
    negatives = load_negatives()

    # Segment by KIND, because the aggregate recall hides the only number a
    # reader actually needs. "Novel-semantic" attacks — paraphrases of an intent
    # no rule has seen, carrying no shape any static rule can key on — are the
    # documented limit of static input scanning, ours and everyone's. Reporting
    # 79% flat invites the reader to assume the misses are spread evenly. They
    # are not: they are entirely in that one segment, and saying so is the whole
    # point of publishing a benchmark instead of a marketing number.
    KNOWN_SHAPE = {"canonical", "paraphrase", "obfuscated", "obfuscated_hardening"}

    tp = fn = 0
    misses = []
    seg = {}
    for a in positives:
        decision = engine.scan(a["text"], a.get("channel", "message")).decision
        kind = a.get("kind", "unspecified")
        bucket = "known_shape" if kind in KNOWN_SHAPE else "novel_semantic"
        s = seg.setdefault(bucket, {"total": 0, "caught": 0})
        s["total"] += 1
        if decision in CAUGHT:
            tp += 1
            s["caught"] += 1
        else:
            fn += 1
            misses.append({"id": a["id"], "category": a["category"],
                           "kind": kind, "decision": decision})
    for s in seg.values():
        s["recall"] = round(s["caught"] / s["total"], 4) if s["total"] else 0.0

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
        "recall_by_segment": seg,
    }
    # Determinism receipt: SHA-256 over the canonicalized metrics.
    metrics["sha256"] = hashlib.sha256(
        json.dumps(metrics, sort_keys=True).encode()
    ).hexdigest()

    # "engine" sits beside the metrics, not inside, so the sealed block (and
    # every published hash of it) means exactly what it did before.
    return {"engine": {"source": source, "path": engine_path},
            "metrics": metrics, "misses": misses, "false_positives": sorted(false_positives)}


def main():
    ap = argparse.ArgumentParser(description="Sunglasses precision / recall benchmark.", allow_abbrev=False)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--installed", action="store_true",
                    help="measure the installed package instead of this checkout")
    args = ap.parse_args()
    result = run(installed=args.installed)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    m = result["metrics"]
    print(f"\n  Sunglasses benchmark — engine v{m['engine_version']}")
    print(f"  engine    : {result['engine']['source']}  ({result['engine']['path']})")
    print(f"  {'-' * 46}")
    print(f"  positives (attacks) : {m['positives']:>4}   caught {m['true_positives']}  missed {m['false_negatives']}")
    print(f"  negatives (readmes) : {m['negatives']:>4}   clean  {m['true_negatives']}  flagged {m['false_positives']}")
    print(f"  {'-' * 46}")
    print(f"  precision : {m['precision']*100:5.1f}%")
    print(f"  recall    : {m['recall']*100:5.1f}%")
    print(f"  F1        : {m['f1']:.3f}")
    seg = m.get("recall_by_segment", {})
    if seg:
        print(f"  {'-' * 46}")
        print("  recall by segment (the number that matters):")
        for label, key in (("known-shape  ", "known_shape"),
                           ("novel-semantic", "novel_semantic")):
            s = seg.get(key)
            if s:
                print(f"    {label} : {s['recall']*100:5.1f}%  "
                      f"({s['caught']}/{s['total']})")
    print(f"  {'-' * 46}")
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
