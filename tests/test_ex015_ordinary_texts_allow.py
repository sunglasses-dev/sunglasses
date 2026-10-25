"""Ordinary documentation texts must scan clean.

Every `ordinary__*` text in the first three EX-015 probe packets under `tests/fixtures/ex015_corpus/`
is plain setup or reference prose that mentions secrets, credentials or config files. Each one must
get decision `allow` on the `file` channel, with GLS-EX-015 absent.

`tests/test_ex015_probe_corpus.py` pins the answer each text gets. This file states the answer
each one should get. The texts that are blocked are listed in `STILL_BLOCKED`; they are strict
expected failures, so when one of them is allowed this file fails until it is taken off the list.
"""
import os

import pytest

_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ex015_corpus")
_PACKETS = ("c470r1", "c470r2", "c470r3")

STILL_BLOCKED = {
    "c470r1/ordinary__old_sink_substring.txt",
    "c470r2/ordinary__dotenv_port.txt",
    "c470r2/ordinary__secret_mask.txt",
    "c470r3/ordinary__dotenv_readme_local.txt",
    "c470r3/ordinary__ssh_setup_fingerprint.txt",
    "c470r3/ordinary__ssh_setup_public.txt",
}


def _ordinary():
    return [f"{p}/{n}" for p in _PACKETS
            for n in sorted(os.listdir(os.path.join(_ROOT, p))) if n.startswith("ordinary__")]


def _param(case):
    marks = [pytest.mark.xfail(strict=True, reason="blocked")] if case in STILL_BLOCKED else []
    return pytest.param(case, id=case, marks=marks)


@pytest.fixture(scope="module")
def engine():
    from sunglasses.engine import SunglassesEngine
    return SunglassesEngine()


def test_every_still_blocked_entry_is_a_real_ordinary_case():
    assert STILL_BLOCKED <= set(_ordinary())


@pytest.mark.parametrize("case", [_param(c) for c in _ordinary()])
def test_ordinary_text_is_allowed(engine, case):
    with open(os.path.join(_ROOT, case), encoding="utf-8") as fh:
        result = engine.scan(fh.read(), channel="file")
    assert result.decision == "allow"
    assert not any(f["id"] == "GLS-EX-015" for f in result.findings)
