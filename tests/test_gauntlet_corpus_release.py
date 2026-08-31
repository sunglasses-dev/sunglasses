"""
WO-C (old WO ①) — `corpus_release` must be DERIVED from disk, never echoed.

`gauntlet.py` wrote `"corpus_release": args.release or "unfrozen"` — whatever the
caller typed on the command line, recorded as fact. A run invoked with
`--release 0.5.0` claimed a frozen scoring corpus whether or not one existed, and the
Gauntlet page is meant to publish scores against a corpus that provably cannot drift
after the fact. A field that repeats its own input verifies nothing.

Same disease as the 0.26ms figure in this batch: a published value with no
measurement behind it. The cure is the same — derive it, or do not claim it.
"""

import json
import os
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

import gauntlet  # noqa: E402


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    root = tmp_path / "corpus"
    (root / "frozen").mkdir(parents=True)
    monkeypatch.setattr(gauntlet, "CORPUS", str(root))
    return root


def _freeze(corpus, release, frozen_at="2026-08-30T06:41:23-07:00"):
    target = corpus / "frozen" / release
    target.mkdir(parents=True)
    (target / "manifest.json").write_text(json.dumps(
        {"release": release, "frozen_at": frozen_at, "cases": [], "tuned_from_excluded": []}
    ))


def test_reports_unfrozen_when_nothing_is_frozen(corpus):
    assert gauntlet.derive_corpus_release("0.5.0") == "unfrozen"


def test_reports_the_release_that_is_actually_frozen(corpus):
    _freeze(corpus, "0.5.0")
    assert gauntlet.derive_corpus_release("0.5.0") == "0.5.0"


def test_a_claimed_release_with_no_frozen_set_is_not_believed(corpus):
    """The echo defect itself: --release 0.5.1 must not manufacture a frozen corpus."""
    assert gauntlet.derive_corpus_release("0.5.1", claimed="0.5.1") == "unfrozen"


def test_a_frozen_set_for_a_different_version_is_not_claimed(corpus):
    """0.5.0 is frozen; we are running 0.5.1. That is not 0.5.1's scoring corpus."""
    _freeze(corpus, "0.5.0")
    assert gauntlet.derive_corpus_release("0.5.1") == "unfrozen"


def test_a_manifest_that_disagrees_with_its_own_directory_is_rejected(corpus):
    """Directory says 0.5.0, manifest says 9.9.9 — an edited manifest is not truth."""
    target = corpus / "frozen" / "0.5.0"
    target.mkdir(parents=True)
    (target / "manifest.json").write_text(json.dumps({"release": "9.9.9", "cases": []}))
    assert gauntlet.derive_corpus_release("0.5.0") == "unfrozen"


def test_an_unreadable_manifest_is_not_a_freeze(corpus):
    target = corpus / "frozen" / "0.5.0"
    target.mkdir(parents=True)
    (target / "manifest.json").write_text("{ this is not json")
    assert gauntlet.derive_corpus_release("0.5.0") == "unfrozen"


def test_an_empty_directory_is_not_a_freeze(corpus):
    (corpus / "frozen" / "0.5.0").mkdir(parents=True)
    assert gauntlet.derive_corpus_release("0.5.0") == "unfrozen"


def test_derivation_ignores_the_claim_entirely_when_disk_disagrees(corpus):
    """Whatever the caller says, disk wins. Both directions."""
    _freeze(corpus, "0.5.0")
    assert gauntlet.derive_corpus_release("0.5.0", claimed="9.9.9") == "0.5.0"
    assert gauntlet.derive_corpus_release("0.5.0", claimed=None) == "0.5.0"
