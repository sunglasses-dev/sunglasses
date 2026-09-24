"""The four readiness rows of the wire readiness note, each tested, not restated.

1. Canonical encoding is exact: equal records written with different bytes.
2. Domain separation holds: a checkpoint signature made over any other prefix,
   digest or chain, replayed onto a checkpoint line.
3. The three limitations survive contact: a report over a log that is valid and
   false, and over one truncated at a valid checkpoint, still prints LC01..LC03.
4. No single boolean: the library half. The CLI half waits for the CLI.

Chains are built by `_Chain` in test_verify from the wire alone, never by the
writer. Every refusal has its positive control in the same parametrize.
"""
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import codes                                               # noqa: E402
import verify                                              # noqa: E402
import wire                                                # noqa: E402
from test_verify import FP, PUBLIC, _Chain, _sealed_chain  # noqa: E402


# --- row 1 · equal but different bytes --------------------------------------

@pytest.mark.parametrize("line", [
    b'{"a":"\\u0061"}\n',              # an escaped ASCII letter
    b'{"a":"\\/"}\n',                  # an escaped solidus
    b'{"a":"\\u00e9"}\n',              # escaped non ASCII
    b'{"a":"\\ud83d\\ude00"}\n',       # an escaped surrogate pair
    b'{"\\u0061":1}\n',                # an escaped key
    b'{"a":-0}\n',                     # negative zero
    b'{"a":1}\r\n',                    # CRLF
    b'{"a":1} \n',                     # trailing space
    b'\xef\xbb\xbf{"a":1}\n',          # a byte order mark
    b'{"a":1,"\\u0061":2}\n',          # a duplicate hidden by an escape
])
def test_row1_an_equal_record_in_other_bytes_is_refused(line):
    with pytest.raises(wire.NotCanonical):
        wire.decode_strict(line)


@pytest.mark.parametrize("line", [
    '{"a":"é"}\n'.encode(), '{"a":"😀"}\n'.encode(), b'{"a":1}\n'])
def test_row1_control_the_canonical_bytes_are_accepted(line):
    assert wire.encode(wire.decode_strict(line)) == line


@pytest.mark.parametrize("line", [
    b'{"a":"\\ud800"}\n', b'{"a":"\\udfff"}\n', b'{"\\ud800":1}\n'])
def test_row1_a_lone_surrogate_is_refused_as_not_canonical(line):
    """A lone surrogate parses to a str that UTF-8 cannot carry. The refusal
    must be the wire's own, not a codec error a caller never catches."""
    with pytest.raises(wire.NotCanonical):
        wire.decode_strict(line)


@pytest.mark.parametrize("record", [{"a": "\ud800"}, {"\udfff": 1},
                                    {"body": {"x": ["\ud83d"]}}])
def test_row1_a_lone_surrogate_is_not_encodable(record):
    with pytest.raises(wire.NotEncodable):
        wire.encode(record)


def test_row1_unicode_is_not_normalized():
    """NFC and NFD render alike and are two records: nothing is normalized."""
    nfc, nfd = wire.encode({"a": "\u00e9"}), wire.encode({"a": "e\u0301"})
    assert wire.decode_strict(nfc) != wire.decode_strict(nfd)
    assert wire.record_hash(nfc) != wire.record_hash(nfd)


# --- row 2 · a checkpoint signature from anywhere else ----------------------

def _resign(c, how):
    last = wire.decode_strict(c.lines[-1])
    unsigned = {k: v for k, v in last.items() if k != wire.SIGNATURE_MEMBER}
    sig = how(c, unsigned)
    c.lines[-1] = wire.encode(dict(unsigned, signature=sig.hex()))
    return c


REPLAYS = {
    "fingerprint domain": lambda c, u: c.key.sign(
        wire.FINGERPRINT_DOMAIN + wire.encode(u)),
    "no domain": lambda c, u: c.key.sign(wire.encode(u)),
    "checkpoint domain without the LF": lambda c, u: c.key.sign(
        wire.CHECKPOINT_DOMAIN + wire.encode(u)[:-1]),
    "the record hash digest": lambda c, u: c.key.sign(
        bytes.fromhex(wire.record_hash(wire.encode(u)))),
    "covering its own signature member": lambda c, u: c.key.sign(
        wire.CHECKPOINT_DOMAIN + wire.encode(dict(u, signature=""))),
    "an earlier checkpoint's signature": lambda c, u: bytes.fromhex(
        wire.decode_strict(c.lines[1])[wire.SIGNATURE_MEMBER]),
    "the same checkpoint in another chain": lambda c, u: c.key.sign(
        wire.checkpoint_signing_bytes(dict(u, chain_id="chain-other"))),
}


@pytest.mark.parametrize("name", sorted(REPLAYS))
def test_row2_a_signature_made_for_other_bytes_is_invalid(name):
    c = _resign(_sealed_chain(), REPLAYS[name])
    report = verify.verify(c.data(), PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "SIGNATURE_INVALID"
    assert report.first_failure_line == len(c.lines)


def test_row2_control_the_checkpoint_domain_signature_holds():
    c = _resign(_sealed_chain(),
                lambda c, u: c.key.sign(wire.checkpoint_signing_bytes(u)))
    report = verify.verify(c.data(), PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "CHAIN_OK"


def test_row2_a_signature_member_does_not_make_a_line_a_checkpoint():
    """A valid checkpoint signature pasted onto an ordinary event: the line is
    counted in the unsigned tail, and nothing after the real seal is verified."""
    c = _sealed_chain()
    last = wire.decode_strict(c.lines[-1])
    first_seal = 1
    c.lines[-1] = wire.encode(dict(last, event="decision"))
    report = verify.verify(c.data(), PUBLIC, expected_fingerprint=FP,
                           expected_endpoint=c.endpoint(len(c.lines) - 1))
    assert report.results["unsigned_tail"] == "UNVERIFIED_TAIL"
    assert report.verified_through["line"] == first_seal + 1
    assert report.results["expected_endpoint"] != "ENDPOINT_CONFIRMED"


# --- row 3 · the limitations print where the results do --------------------

def _valid_and_false():
    c = _Chain()
    c.seal("genesis")
    c.event("in_flight", eval_id="e1", note="the scanner ran")   # it did not
    c.event("decision", eval_id="e1", decision="allow")
    return c, c.seal()


def _truncated_at_a_valid_checkpoint():
    c = _sealed_chain()
    c.call("e2")
    c.seal()
    return b"".join(c.lines[:2])


@pytest.mark.parametrize("case", ["valid and false", "truncated"])
def test_row3_every_limitation_prints_with_the_report(case):
    if case == "valid and false":
        c, end = _valid_and_false()
        report = verify.verify(c.data(), PUBLIC, expected_fingerprint=FP,
                               expected_endpoint=c.endpoint(end))
    else:
        report = verify.verify(_truncated_at_a_valid_checkpoint(), PUBLIC,
                               expected_fingerprint=FP)
    rendered = verify.render(report)
    for code in ("LC01", "LC02", "LC03"):
        assert code in rendered
    assert "clean" not in rendered.lower()


def test_row3_truncated_log_never_reaches_a_zero_exit():
    report = verify.verify(_truncated_at_a_valid_checkpoint(), PUBLIC,
                           expected_fingerprint=FP)
    assert report.results["expected_endpoint"] == "HISTORY_EXTENT_UNKNOWN"
    assert codes.strict_exit_code(report.results) != 0


# --- row 4 · no single boolean (library half) -------------------------------

def test_row4_the_report_carries_no_boolean_verdict():
    c, end = _valid_and_false()
    report = verify.verify(c.data(), PUBLIC, expected_fingerprint=FP,
                           expected_endpoint=c.endpoint(end))
    public = {k: v for k, v in vars(report).items() if not k.startswith("_")}
    assert not [k for k, v in public.items() if isinstance(v, bool)]
    assert set(report.results) == set(codes.RESULT_KINDS)
    assert all(isinstance(v, str) for v in report.results.values())
