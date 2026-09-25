"""test_receipts_proxy_key_unusable.py — the proxy with a key it cannot use
stops, and says why (#172, T9 RULINGS 21 and 24b(a)).

A key means the user opted in, for the proxy as for the hook. A key that cannot
sign is the receipt failure the proxy already has (RECEIPT_IO_ERROR): nothing is
mediated, no unsigned log is started, and the message names the cause and the
one command that clears it. "Legacy unchanged" covers only installs with no key.
"""
import io
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.proxy import serve
from sunglasses.receipts import keys

TREE = pathlib.Path(__file__).resolve().parents[1]
UPSTREAM = [sys.executable, "-c", "import sys; sys.stdin.read()"]


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    return home


def _nothing_written(state):
    receipts = state / "receipts"
    return not receipts.exists() or not any(receipts.iterdir())


def test_an_exposed_key_refuses_to_open_the_log(home, tmp_path):
    os.chmod(keys.private_path(home), 0o644)
    with pytest.raises(proxy_receipts.ReceiptIOError) as raised:
        proxy_receipts.Log(tmp_path / "state", run_id="r", header={}, home=home)
    assert "chmod 600" in str(raised.value)
    assert str(keys.private_path(home)) in str(raised.value)
    assert _nothing_written(tmp_path / "state")


def test_the_proxy_stops_before_the_server_starts_and_names_the_cause(home, tmp_path):
    os.chmod(keys.private_path(home), 0o644)
    stderr = io.StringIO()
    code = serve.main(["--state-root", str(tmp_path / "state"), "--", *UPSTREAM],
                      stdin=io.BytesIO(b""), stdout=io.BytesIO(), stderr=stderr)
    assert code != 0
    assert "chmod 600" in stderr.getvalue()
    assert "receipt" in stderr.getvalue().lower()
    assert _nothing_written(tmp_path / "state")


def test_the_extra_removed_stops_the_proxy_with_the_install_command(home, tmp_path):
    script = ("import sys; sys.modules['cryptography'] = None\n"
              "from sunglasses.proxy import serve\n"
              f"sys.exit(serve.main(['--state-root', {str(tmp_path / 'state')!r}, "
              f"'--', *{UPSTREAM!r}]))\n")
    proc = subprocess.run([sys.executable, "-c", script], cwd=TREE, input=b"",
                          capture_output=True,
                          env={**os.environ, "SUNGLASSES_HOME": str(home)})
    assert proc.returncode != 0
    assert b"sunglasses[receipts]" in proc.stderr
    assert _nothing_written(tmp_path / "state")


def test_the_control_a_usable_key_opens_a_signed_run(home, tmp_path):
    log = proxy_receipts.Log(tmp_path / "state", run_id="r", header={}, home=home)
    log.event("TEARDOWN")
    log.close()
    assert list(log.path.glob("segment-*.chain"))
