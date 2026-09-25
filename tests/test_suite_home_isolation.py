"""test_suite_home_isolation.py — the control for conftest's isolated home.

A real key planted where the product would find it on a dev box, the user's
~/.sunglasses under a fake $HOME, must not reach a test that never set
SUNGLASSES_HOME itself: a proxy session there writes the legacy log, unsigned.
"""
import os

from sunglasses.firewall import sunglasses_home
from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.proxy.serve import state_root
from sunglasses.receipts import keys


def test_a_developers_real_key_never_signs_a_test(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    real = tmp_path / ".sunglasses"
    keys.init(real)                                  # the dev box's own key
    assert sunglasses_home() != real
    log = proxy_receipts.Log(state_root(), run_id="a" * 32, header={})
    log.close()
    assert log.path.is_file()                        # legacy jsonl, no chain
    assert not list(real.rglob("segment-*.chain"))


def test_the_control_a_test_that_sets_its_home_is_obeyed(tmp_path, monkeypatch):
    home = tmp_path / "mine"
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    assert sunglasses_home() == home
    assert os.environ["SUNGLASSES_HOME"] == str(home)
