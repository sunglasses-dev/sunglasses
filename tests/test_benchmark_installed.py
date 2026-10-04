"""tests/benchmark/precision_recall.py can measure the INSTALLED package, and it says which one it measured.

The README command measures the source tree, because the script puts the checkout first on sys.path.
Someone who wants the numbers for the wheel they pip installed had no flag for it, and had to export the
dataset to a directory with no sunglasses package beside it to get there (the 0.6.5 receipts did exactly that).

--installed measures the package found on the normal import path instead, and refuses when that package is
the checkout itself (an editable install or PYTHONPATH pointing at the repo would otherwise be reported as
"installed" while measuring source). The default stays the checkout. A flag nobody recognises is an error,
because a typo that silently fell back to the checkout would print the wrong leg with a straight face.

The installed package is stood in for by a stub whose engine allows everything and reports its own version,
so a run that read it cannot be mistaken for a run that read the checkout.
"""
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
BENCH = REPO / "tests" / "benchmark" / "precision_recall.py"
STUB_VERSION = "stub-9.9.9"


def _stub_site(tmp_path):
    site = tmp_path / "site"
    pkg = site / "sunglasses"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text('__version__ = "%s"\n' % STUB_VERSION, encoding="utf-8")
    (pkg / "engine.py").write_text(
        "class _R:\n    decision = 'allow'\n\n"
        "class SunglassesEngine:\n"
        "    def scan(self, text, channel='message'):\n        return _R()\n"
        "    def info(self):\n        return {'version': '%s'}\n" % STUB_VERSION,
        encoding="utf-8")
    return site


def _run(args, tmp_path, pythonpath=None, no_site=False):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    if pythonpath is not None:
        env["PYTHONPATH"] = str(pythonpath)
    cmd = [sys.executable] + (["-S"] if no_site else []) + [str(BENCH)] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(tmp_path), timeout=300)


def _json(out):
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.fixture(scope="module")
def checkout_json(tmp_path_factory):
    """The default `--json` run with no PYTHONPATH, the plain checkout leg.

    Two tests read this same document, so it runs once. The runs with a stub site on the path or with the
    plain report differ from it on purpose, which is what those tests prove, and they keep their own runs."""
    return _run(["--json"], tmp_path_factory.mktemp("bench_checkout"))


def test_installed_flag_measures_the_installed_package_not_the_checkout(tmp_path):
    site = _stub_site(tmp_path)
    got = _json(_run(["--installed", "--json"], tmp_path, pythonpath=site))
    assert got["metrics"]["engine_version"] == STUB_VERSION, got["metrics"]
    assert got["metrics"]["true_positives"] == 0
    assert got["engine"]["source"] == "installed"
    assert got["engine"]["path"].startswith(str(site)), got["engine"]


def test_installed_leg_still_uses_the_checkout_dataset(tmp_path, checkout_json):
    site = _stub_site(tmp_path)
    ran = _json(_run(["--installed", "--json"], tmp_path, pythonpath=site))
    assert ran["engine"]["source"] == "installed"
    inst = ran["metrics"]
    default = _json(checkout_json)["metrics"]
    assert (inst["positives"], inst["negatives"]) == (default["positives"], default["negatives"])


def test_default_stays_the_checkout_even_with_an_installed_copy_on_the_path(tmp_path):
    site = _stub_site(tmp_path)
    got = _json(_run(["--json"], tmp_path, pythonpath=site))
    assert got["engine"]["source"] == "checkout"
    assert got["metrics"]["engine_version"] != STUB_VERSION
    assert got["metrics"]["recall"] > 0.9
    assert pathlib.Path(got["engine"]["path"]).resolve().is_relative_to(REPO)


def test_installed_refuses_when_the_importable_package_is_the_checkout(tmp_path):
    out = _run(["--installed", "--json"], tmp_path, pythonpath=REPO)
    assert out.returncode == 2, (out.returncode, out.stderr)
    assert "checkout" in out.stderr
    assert out.stdout.strip() == ""


def test_installed_says_so_when_nothing_is_installed(tmp_path):
    out = _run(["--installed", "--json"], tmp_path, no_site=True)
    assert out.returncode == 2, (out.returncode, out.stderr)
    assert "pip install sunglasses" in out.stderr
    assert out.stdout.strip() == ""


def test_an_unknown_flag_is_an_error_not_a_silent_fallback_to_the_checkout(tmp_path):
    out = _run(["--instaled", "--json"], tmp_path)
    assert out.returncode == 2, (out.returncode, out.stdout[:200])
    assert "--instaled" in out.stderr
    assert out.stdout.strip() == ""


def test_the_metrics_block_is_unchanged_so_the_published_hash_still_means_the_same(checkout_json):
    keys = set(_json(checkout_json)["metrics"])
    assert keys == {"engine_version", "positives", "negatives", "true_positives", "false_negatives",
                    "false_positives", "true_negatives", "precision", "recall", "f1",
                    "recall_by_segment", "sha256"}


def test_the_plain_report_names_which_package_it_measured(tmp_path):
    site = _stub_site(tmp_path)
    assert re.search(r"engine\s*:\s*installed", _run(["--installed"], tmp_path, pythonpath=site).stdout)
    assert re.search(r"engine\s*:\s*checkout", _run([], tmp_path).stdout)


def _readme():
    return (REPO / "README.md").read_text(encoding="utf-8")


def test_readme_keeps_the_default_command_and_documents_the_installed_leg():
    text = _readme()
    assert "```bash\ngit clone https://github.com/sunglasses-dev/sunglasses && cd sunglasses\npython3 tests/benchmark/precision_recall.py\n```" in text
    assert "python3 tests/benchmark/precision_recall.py --installed" in text
    section = text[text.index("## Benchmark, the receipts"):]
    assert "--installed" in section.split("\n## ")[0]
