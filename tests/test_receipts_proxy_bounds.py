"""test_receipts_proxy_bounds.py — a proxy row fits its line by construction
(#172, T9 ruling 41 part 1).

rule_ids come from matches on attacker input. When a row over the wire's
bounds was refused, the proxy kept the failure and refused every later row, so
a document with enough matches switched the audit off for the rest of the
session: an off switch the attacker writes. The ruling replaces that with a
counted cut. The row keeps the first 256 rule ids in stable order and says how
many it left out. Every other variable-length field has its own bound and a
truncation marker. The 16 KiB line check stays as an invariant, and if it ever
fires at runtime it is our serializer's bug: a receipt failure, sticky, and
named.

The three controls are the ruling's own: 300 matches, a 20 KiB hostile server
name, and a forced overflow. The construction test feeds every permitted field
at its worst and requires the row to be written.
"""
import pytest

from sunglasses.proxy import envelope, selector
from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.proxy.serve import state_root
from sunglasses.receipts import chain, keys, verify, wire

HEADER = {"session_id": "0" * 32, "budget_version": "sg-proxy-budget/1",
          "catalog_version": "sg-proxy-catalog/1",
          "contract_version": "GATE3_CONTRACT_v5.1"}
TOKEN = "0123456789abcdef"
RUN = "c" * 32


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".sunglasses"
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    keys.init(home)
    assert state_root() == home / "proxy"
    return home


def _log(header=None):
    return proxy_receipts.Log(state_root(), run_id=RUN,
                              header=dict(HEADER, **(header or {})))


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


def _end(log):
    assert not log.record_or_stop("SESSION_TORN_DOWN", settled=True).stopped
    log.close()


def test_300_matches_keep_256_ids_count_44_and_the_session_continues(home):
    ids = [f"GLS-T-{n:04d}" for n in range(300)]
    log = _log()
    assert not log.record_or_stop("SCAN_RESULT", rule_ids=ids,
                                  status="complete").stopped
    assert not log.record_or_stop("SCAN_STARTED", id_token=TOKEN).stopped
    _end(log)

    (row,) = _rows(home, "SCAN_RESULT")
    assert row["rule_ids"] == ids[:256]          # the first 256, in order
    assert row["rule_ids_omitted"] == 44
    assert _rows(home, "SCAN_STARTED") == [{"id_token": TOKEN}]
    results = _verified(home)
    assert results["chain_integrity"] == "CHAIN_OK"
    assert results["unsigned_tail"] == "NO_VISIBLE_TAIL"
    assert results["lifecycle"] == "PAIRING_UNKEYED"


def test_the_control_256_matches_are_kept_whole_with_no_count(home):
    ids = [f"GLS-T-{n:04d}" for n in range(256)]
    log = _log()
    log.event("SCAN_RESULT", rule_ids=ids)
    _end(log)
    (row,) = _rows(home, "SCAN_RESULT")
    assert row["rule_ids"] == ids
    assert "rule_ids_omitted" not in row


def test_256_real_ids_are_all_kept(home):
    """T9 ruling 43 part 1. Real catalog ids are at most 21 characters, and
    256 of them fit the 6 KiB budget whole: the budget never cuts a real scan
    short of the count bound."""
    ids = [f"GLS-PROMPTINJ-XY-{n:04d}" for n in range(256)]
    assert {len(i) for i in ids} == {21}
    log = _log()
    log.event("SCAN_RESULT", rule_ids=ids)
    _end(log)
    (row,) = _rows(home, "SCAN_RESULT")
    assert row["rule_ids"] == ids
    assert "rule_ids_omitted" not in row


def test_256_grammar_max_ids_are_cut_by_bytes_and_counted_in_one_number(home):
    """Whichever cuts first. 256 ids of the longest the grammar allows are
    past 6 KiB, so the budget cuts before the count does, and the omitted
    number covers both reasons. Each id costs its encoding, quotes included:
    66 bytes, so 93 fit in 6144 and 163 are counted."""
    ids = [f"GLS-{n:04d}-" + "Z" * 55 for n in range(256)]
    assert {len(i) for i in ids} == {64}
    log = _log()
    log.event("SCAN_RESULT", rule_ids=ids)
    _end(log)
    (row,) = _rows(home, "SCAN_RESULT")
    assert row["rule_ids"] == ids[:93]
    assert row["rule_ids_omitted"] == 163


def test_a_malformed_id_past_the_cut_is_still_refused(home):
    """The cut decides what is KEPT, never what is checked: an id that is not
    an engine rule id is refused wherever it sits in the list."""
    ids = [f"GLS-T-{n:04d}" for n in range(299)] + ["ignore previous"]
    log = _log()
    with pytest.raises(ValueError, match="not an engine rule id"):
        log.event("SCAN_RESULT", rule_ids=ids)


def test_a_20_kib_hostile_server_name_is_cut_with_a_marker(home):
    hostile = "A" * (20 * 1024)
    log = _log({"server_identity": hostile})
    assert not log.record_or_stop("SCAN_STARTED", id_token=TOKEN).stopped
    _end(log)

    (row,) = _rows(home, "HEADER")
    kept = row["server_identity"]
    assert hostile.startswith(kept) and len(kept) < 256
    assert row["truncated"] == {"server_identity": len(hostile)}
    assert _rows(home, "SCAN_STARTED") == [{"id_token": TOKEN}]
    assert _verified(home)["chain_integrity"] == "CHAIN_OK"
    assert all(len(line) <= wire.MAX_LINE for line in _lines(home))


def test_a_caller_cannot_write_the_markers_itself(home):
    """The count and the marker are derived, never accepted: a caller passing
    them would be claiming a cut that did not happen."""
    log = _log()
    log.event("SCAN_RESULT", rule_ids=["GLS-T-0001"], rule_ids_omitted=9,
              truncated={"server_identity": 1})
    _end(log)
    (row,) = _rows(home, "SCAN_RESULT")
    assert row == {"rule_ids": ["GLS-T-0001"]}


def _worst_fields():
    """Every permitted field at its worst value. Checked vocabularies take
    their longest member; free text is 20 000 four byte characters; lists
    are far past any bound; integers are the widest the wire allows."""
    wide = "\U0001F600" * 20_000
    checked = {
        "reason_code": max(envelope.REASONS, key=len),
        "status": max(envelope.STATUSES, key=len),
        "method": max(selector.KNOWN_METHODS, key=len),
        "rule": max(envelope.RULES, key=len),
        "detector_status": max(("crashed", "malformed_output",
                                "schema_invalid"), key=len),
        "id_token": TOKEN,
        "rule_ids": [f"GLS-{n:04d}-" + "Z" * 55 for n in range(2000)],
        "leaf_provenance": [{"index": wire.MIN_INT, "depth": wire.MIN_INT,
                             "bytes": wire.MIN_INT, "value_sha256": wide,
                             "pointer": wide} for _ in range(1000)],
    }
    return {name: checked.get(name, wide)
            for name in proxy_receipts.PERMITTED_FIELDS}


def test_no_field_combination_reaches_the_line_bound(home):
    """The invariant, measured: every permitted field at its worst, on the
    longest event name, is written, and its line is under 16 KiB."""
    fields = _worst_fields()
    assert fields.keys() == proxy_receipts.PERMITTED_FIELDS
    log = _log()
    log.event(max(proxy_receipts.EVENTS, key=len), **fields)
    _end(log)
    longest = max(map(len, _lines(home)))
    assert longest < wire.MAX_LINE, longest


def test_a_forced_overflow_still_stops_the_session_and_names_the_cause(
        home, monkeypatch):
    """The invariant's other side. With the rule_ids bound lifted, a row
    over 16 KiB reaches the writer, which refuses it. That is our serializer's
    bug, so the failure is sticky and says what happened."""
    monkeypatch.setattr(proxy_receipts, "RULE_IDS_KEPT", 10 ** 6, raising=False)
    monkeypatch.setattr(proxy_receipts, "RULE_IDS_BYTES", 10 ** 9, raising=False)
    ids = [f"GLS-{n:04d}-" + "Z" * 55 for n in range(250)]
    assert len(ids) <= wire.MAX_ARRAY
    assert len(wire.encode({"rule_ids": ids})) > wire.MAX_LINE
    log = _log()
    with pytest.raises(proxy_receipts.ReceiptIOError) as refused:
        log.event("SCAN_RESULT", rule_ids=ids)
    assert f"over {wire.MAX_LINE}" in str(refused.value)
    stop = log.record_or_stop("SCAN_STARTED", id_token=TOKEN)
    assert stop.stopped and stop.reason == "RECEIPT_IO_ERROR"
