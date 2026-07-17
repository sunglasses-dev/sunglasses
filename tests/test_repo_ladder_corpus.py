"""
test_repo_ladder_corpus.py — THE CLEAN-CORPUS GATE (troll test as CI).

Born Jul 17 2026, the morning the verdict redesign shipped. The scenario this
guards: someone hostile (or a sponsor doing due diligence) scans famous,
legitimate repos trying to make Sunglasses look like an accusation machine.
Every repo snapshotted in tests/repo_ladder_corpus/ must roll up
clean or clean_notes on the policy ladder — a red or yellow verdict on any
of them fails CI before it can reach users.

Snapshots are committed (offline, deterministic). Refresh with:
    python3 tests/repo_ladder_corpus/fetch_snapshots.py

If this test fails after a pattern change: the pattern is publicly accusing
a famous legit repo. Retune the pattern or tier it down — do NOT loosen the
assertion, and do NOT remove the repo from the corpus. The corpus only grows.
"""

import os

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.policy import rollup_repo

CORPUS = os.path.join(os.path.dirname(__file__), "repo_ladder_corpus")
REPO_DIRS = sorted(
    d for d in os.listdir(CORPUS)
    if os.path.isdir(os.path.join(CORPUS, d)) and not d.startswith("_")
)

ACCEPTABLE = ("clean", "clean_notes")

engine = SunglassesEngine()


@pytest.mark.parametrize("repo_dir", REPO_DIRS)
def test_famous_repo_rolls_up_clean(repo_dir):
    files = []
    for name in sorted(os.listdir(os.path.join(CORPUS, repo_dir))):
        path = os.path.join(CORPUS, repo_dir, name)
        with open(path, errors="ignore") as f:
            text = f.read()
        result = engine.scan(text, channel="file")
        files.append({"name": name.replace("__", "/"), "findings": result.findings})

    rollup = rollup_repo(files)
    detail = "; ".join(
        f"{r['file']}: {','.join(r['categories'])}" for r in rollup["review"]
    ) or "; ".join(f"{h['file']}: {h['id']}" for h in rollup["signature_hits"])
    assert rollup["overall"] in ACCEPTABLE, (
        f"{repo_dir.replace('__', '/')} rolls up '{rollup['overall']}' "
        f"({detail}) — a famous legit repo may never wear a verdict. "
        f"Retune or tier down the offending pattern; never loosen this gate."
    )


def test_corpus_is_not_empty():
    assert len(REPO_DIRS) >= 10, "clean corpus shrank — the corpus only grows"
