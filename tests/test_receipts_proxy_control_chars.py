"""test_receipts_proxy_control_chars.py — a peer's control character or lone
surrogate does not switch the audit off (#172, the off switch left after T9
ruling 41, flagged to T9 as R43 item 2).

The wire refuses a string holding a control character or a lone surrogate:
there is no one canonical byte form for it. The proxy writes strings a peer
chose (a server's name, the methods it advertises, a reason it gave), so a
peer that puts `\\x00`, `\\n` or a lone `\\udc80` in one got its row refused,
and the proxy kept the refusal and refused every later row. T9 ruling 43 part
2: a receipt is never refused for what the peer sent. A control character
becomes its JSON escape as text (`\\u0000`), so a newline can never split a
record in two; a lone surrogate becomes U+FFFD; `sanitized` counts the
replacements per field, and the rest of the row is kept.

Red first. On the head before the fix the row is refused and the next receipt
stops as RECEIPT_IO_ERROR; each assertion below says which of the two it saw.
The other side, a forced serializer overflow still stopping sticky, is
test_receipts_proxy_bounds.py.
"""
import pytest

from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.proxy.serve import state_root
from sunglasses.receipts import chain, keys, verify, wire

HEADER = {"session_id": "0" * 32, "budget_version": "sg-proxy-budget/1",
          "catalog_version": "sg-proxy-catalog/1",
          "contract_version": "GATE3_CONTRACT_v5.1"}
TOKEN = "0123456789abcdef"
RUN = "c" * 32
HOSTILE = {"nul": "srv\x00name", "escape": "srv\x1b[2Jname",
           "surrogate": "srv\udc80name",
           "all": "srv\x00a\nb\udc80c\x7f"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".sunglasses"
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    keys.init(home)
    assert state_root() == home / "proxy"
    return home


def _lines(home):
    directory = state_root() / "receipts" / RUN
    return [line for segment in sorted(directory.glob(chain.SEGMENT_GLOB))
            for line in segment.read_bytes().splitlines(keepends=True)]


def _rows(home, event):
    return [record["body"] for record in map(wire.decode_strict, _lines(home))
            if record.get("event") == event]


def _verified(home):
    public = keys.public_path(home, keys.load(home).fingerprint).read_bytes()
    return verify.verify_log(state_root() / "receipts" / RUN, public).results


def _continues(log, kind, **fields):
    stop = log.record_or_stop(kind, **fields)
    assert not stop.stopped, f"{kind} refused: the session stopped as {stop.reason}"


def _end(log):
    _continues(log, "SESSION_TORN_DOWN", settled=True)
    log.close()


def _replaced(text):
    """By hand, not by the code under test: a control character becomes its
    six character JSON escape as text, a lone surrogate U+FFFD."""
    out = []
    for c in text:
        if ord(c) < 0x20 or ord(c) == 0x7F:
            out.append("\\u%04x" % ord(c))
        elif 0xD800 <= ord(c) <= 0xDFFF:
            out.append("�")
        else:
            out.append(c)
    return "".join(out)


def _count(text):
    return sum(1 for c in text if ord(c) < 0x20 or ord(c) == 0x7F
               or 0xD800 <= ord(c) <= 0xDFFF)


@pytest.mark.parametrize("which", sorted(HOSTILE))
def test_a_hostile_server_name_is_replaced_and_the_session_continues(home, which):
    hostile = HOSTILE[which]
    try:
        log = proxy_receipts.Log(state_root(), run_id=RUN,
                                 header=dict(HEADER, server_identity=hostile))
    except proxy_receipts.ReceiptIOError as refused:
        pytest.fail(f"the header was refused, so no receipt was written: {refused}")
    _continues(log, "SCAN_STARTED", id_token=TOKEN)
    _end(log)

    (row,) = _rows(home, "HEADER")
    assert row["server_identity"] == _replaced(hostile)
    assert row["sanitized"] == {"server_identity": _count(hostile)}
    assert "truncated" not in row
    assert row["session_id"] == HEADER["session_id"]      # the rest is kept
    assert _rows(home, "SCAN_STARTED") == [{"id_token": TOKEN}]
    assert _verified(home)["chain_integrity"] == "CHAIN_OK"


@pytest.mark.parametrize("which", sorted(HOSTILE))
def test_a_hostile_peer_string_mid_session_does_not_stop_every_later_receipt(
        home, which):
    """The sticky proof. A row carrying the peer's string, then an ordinary
    row: the second must be written, and so must the first, repaired."""
    hostile = HOSTILE[which]
    log = proxy_receipts.Log(state_root(), run_id=RUN, header=HEADER)
    _continues(log, "SETTLED", reason=hostile, advertised=["tools/list", hostile],
               status="complete")
    _continues(log, "SCAN_STARTED", id_token=TOKEN)
    _end(log)

    (row,) = _rows(home, "SETTLED")
    assert row["reason"] == _replaced(hostile)
    assert row["advertised"] == ["tools/list", _replaced(hostile)]
    assert row["sanitized"] == {"reason": _count(hostile),
                                "advertised": _count(hostile)}
    assert row["status"] == "complete"
    assert _rows(home, "SCAN_STARTED") == [{"id_token": TOKEN}]
    assert _verified(home)["chain_integrity"] == "CHAIN_OK"


def test_the_control_a_clean_string_carries_no_marker(home):
    log = proxy_receipts.Log(state_root(), run_id=RUN,
                             header=dict(HEADER, server_identity="srv name"))
    _end(log)
    (row,) = _rows(home, "HEADER")
    assert row["server_identity"] == "srv name"
    assert "truncated" not in row and "sanitized" not in row


def test_the_replacement_is_deterministic_and_a_newline_cannot_split_a_record(
        home):
    hostile = "a\nb\r\n{\"event\":\"forged\"}"
    log = proxy_receipts.Log(state_root(), run_id=RUN,
                             header=dict(HEADER, server_identity=hostile))
    _continues(log, "SETTLED", reason=hostile)
    _end(log)
    lines = _lines(home)
    assert all(line.count(b"\n") == 1 for line in lines)
    (header,) = _rows(home, "HEADER")
    (settled,) = _rows(home, "SETTLED")
    assert header["server_identity"] == settled["reason"] == _replaced(hostile)
    assert _verified(home)["chain_integrity"] == "CHAIN_OK"


def test_a_long_hostile_name_is_escaped_then_cut_and_both_are_counted(home):
    hostile = "\x00" * 20480
    log = proxy_receipts.Log(state_root(), run_id=RUN,
                             header=dict(HEADER, server_identity=hostile))
    _continues(log, "SCAN_STARTED", id_token=TOKEN)
    _end(log)
    (row,) = _rows(home, "HEADER")
    assert row["sanitized"] == {"server_identity": 20480}
    assert row["truncated"] == {"server_identity": 6 * 20480}
    assert _replaced(hostile).startswith(row["server_identity"])
    assert all(len(line) <= wire.MAX_LINE for line in _lines(home))


def test_a_caller_cannot_write_the_sanitized_marker_itself(home):
    log = proxy_receipts.Log(state_root(), run_id=RUN, header=HEADER)
    log.event("SETTLED", reason="ok", sanitized={"reason": 3})
    _end(log)
    (row,) = _rows(home, "SETTLED")
    assert row == {"reason": "ok"}
