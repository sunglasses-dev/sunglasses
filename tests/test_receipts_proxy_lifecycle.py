"""test_receipts_proxy_lifecycle.py — what the verifier can say about a proxy
run's chain, and what it says it cannot (#172, T9 RULING 24).

A proxy chain's lifecycle is the SESSION: it opens with HEADER and ends with a
terminal event, the same two facts the legacy verifier checks. The items
inside it are recorded but not paired: most SETTLED rows carry no id_token, so
there is no key to pair an ADMITTED by, and pairing them anyway would collapse
every tokenless row into one (finding #10). Until R24-A lands the verifier
says that limit by name, PAIRING_UNKEYED, which is neither a pass nor a
failure. A closed session is never called LIFECYCLE_COMPLETE, because that
code says every opening has its terminal, and nobody checked.

The proxy's own writer makes every chain here.
"""
import pytest

from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.receipts import codes, keys, verify

TOKEN = "0123456789abcdef"


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    return home


def _run(home, *events, close=True):
    log = proxy_receipts.Log(home / "proxy", run_id="r" * 32,
                             header={"session_id": "r" * 32}, home=home)
    for kind, fields in events:
        log.event(kind, **fields)
    if close:
        log.close()
    return log.path


def _lifecycle(home, path):
    signer = keys.load(home)
    public = keys.public_path(home, signer.fingerprint).read_bytes()
    return verify.verify_log(path, public).results["lifecycle"]


def test_the_verifier_knows_exactly_the_proxys_vocabulary():
    assert verify.PROXY_EVENTS == proxy_receipts.EVENTS
    assert verify.PROXY_TERMINALS == proxy_receipts.TERMINAL_EVENTS


@pytest.mark.parametrize("terminal", sorted(proxy_receipts.TERMINAL_EVENTS))
def test_a_session_that_ended_names_the_pairing_limit(home, terminal):
    path = _run(home, ("ADMITTED", {"id_token": TOKEN}),
                ("SETTLED", {"id_token": TOKEN}), (terminal, {}))
    assert _lifecycle(home, path) == "PAIRING_UNKEYED"


def test_the_pairing_limit_is_neither_a_pass_nor_a_failure():
    assert "PAIRING_UNKEYED" in codes.CODES
    assert "R24" in codes.CODES["PAIRING_UNKEYED"]
    passing = {"key_trust": "KEY_TRUSTED", "chain_integrity": "CHAIN_OK",
               "unsigned_tail": "NO_VISIBLE_TAIL",
               "expected_endpoint": "ENDPOINT_CONFIRMED"}
    # A limit (T9 rulings 46 and 48): exit 3, and 1 when strict.
    assert codes.exit_code(dict(passing, lifecycle="PAIRING_UNKEYED")) == 3
    assert codes.strict_exit_code(dict(passing, lifecycle="PAIRING_UNKEYED")) == 1
    assert codes.strict_exit_code(dict(passing, lifecycle="LIFECYCLE_ORPHAN")) == 1


def test_an_unsettled_admitted_item_is_not_judged_complete(home):
    """R24 control: the legacy collapse would let a tokenless SETTLED settle
    every tokenless ADMITTED. Here nothing is paired, and nothing says it was."""
    path = _run(home, ("ADMITTED", {}), ("ADMITTED", {}), ("SETTLED", {}),
                ("TEARDOWN", {}))
    assert _lifecycle(home, path) != "LIFECYCLE_COMPLETE"


def test_a_session_with_no_ending_is_an_orphan(home):
    path = _run(home, ("ADMITTED", {"id_token": TOKEN}))
    assert _lifecycle(home, path) == "LIFECYCLE_ORPHAN"


def test_the_render_prints_the_limit_by_name(home):
    path = _run(home, ("TEARDOWN", {}))
    signer = keys.load(home)
    public = keys.public_path(home, signer.fingerprint).read_bytes()
    text = verify.render_log(verify.verify_log(path, public))
    assert "lifecycle: PAIRING_UNKEYED" in text
