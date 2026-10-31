"""A scan reports the same thing with or without the optional pyahocorasick extension.

The engine can look for its keywords with an Aho-Corasick automaton (when the
extension is installed) or with plain string search (when it is not). The two used
to pick a rule's first keyword hit differently, so the excerpt and the order of the
findings could differ between a machine with the extension and one without, for the
same input. Both now report where each keyword first stands and take the hits in one
order, (start, end, keyword).

The corpus is the quickstart string, the benchmark attacks and the real-world false
positive documents. Each run is a fresh interpreter so the choice of path is not
undone by an import cache. Set SUNGLASSES_REQUIRE_FAST=1 (the CI leg that installs
the extension does) and a missing extension fails instead of skipping.
"""
import glob
import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHILD = r'''
import glob, json, os, sys
mode, root = sys.argv[1], sys.argv[2]
if mode == "without":
    sys.modules["ahocorasick"] = None
sys.path.insert(0, root)
import sunglasses.engine as E
eng = E.SunglassesEngine()
if mode == "reversed":
    eng._keyword_to_patterns = dict(reversed(list(eng._keyword_to_patterns.items())))
texts = [("quickstart", "some text to check")]
attacks = json.load(open(os.path.join(root, "tests", "benchmark", "attacks.json")))["attacks"]
texts += [("attack:%d" % i, a["text"]) for i, a in enumerate(attacks)]
for p in sorted(glob.glob(os.path.join(root, "tests", "fp_real_world_corpus", "*.md"))):
    texts.append(("doc:" + os.path.basename(p), open(p, errors="ignore").read()))
results = {}
for name, text in texts:
    r = eng.scan(text)
    results[name] = {"decision": r.decision, "severity": r.severity,
                     "findings": json.loads(json.dumps(r.findings, sort_keys=True, default=str))}
print(json.dumps({"extension_in_use": E.HAS_AHOCORASICK and eng._automaton is not None,
                  "texts": len(texts), "results": results}, sort_keys=True))
'''


def _run(mode):
    out = subprocess.run([sys.executable, "-c", CHILD, mode, ROOT], capture_output=True,
                         text=True, timeout=600, cwd=ROOT)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout)


def _have_extension():
    return importlib.util.find_spec("ahocorasick") is not None


def test_the_corpus_is_the_size_the_comparison_assumes():
    plain = _run("without")
    assert plain["extension_in_use"] is False
    assert plain["texts"] > 100
    assert sum(len(v["findings"]) for v in plain["results"].values()) > 50


def test_findings_do_not_depend_on_the_order_keywords_are_stored_in():
    forward = _run("without")
    backward = _run("reversed")
    assert json.dumps(forward["results"], sort_keys=True) == json.dumps(backward["results"], sort_keys=True)


def test_findings_are_byte_identical_with_and_without_the_extension():
    if not _have_extension():
        if os.environ.get("SUNGLASSES_REQUIRE_FAST") == "1":
            pytest.fail("SUNGLASSES_REQUIRE_FAST=1 but the pyahocorasick extension is not installed")
        pytest.skip("pyahocorasick is not installed")
    fast = _run("with")
    plain = _run("without")
    assert fast["extension_in_use"] is True
    assert plain["extension_in_use"] is False
    assert fast["texts"] == plain["texts"]
    assert json.dumps(fast["results"], sort_keys=True) == json.dumps(plain["results"], sort_keys=True)
