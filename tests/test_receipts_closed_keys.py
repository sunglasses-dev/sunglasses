"""test_receipts_closed_keys.py — the keys of a signed row are OURS (#172, T9
ruling 44).

R43 escaped a control character in a peer's string. Applied to an object's
KEYS, that escape can make two keys one: `"a\\x00"` escapes to the six
characters `a\\u0000`, which is exactly the key `"a\\\\u0000"`, and the row
keeps one of them with nothing saying the other existed. Ruling 44 closes the
class rather than the collision. No peer object is ever spliced into a row as
an object: it is written as ONE string, its canonical JSON (or that string's
digest when over the field's budget). And the verifier holds a CLOSED key set
for every record kind, so a row carrying a key outside it is a red verdict,
`UNKNOWN_FIELD`, never a quiet overwrite.

Three parts, as ruled. (1) The colliding object ends as one string with both
keys visible, and the row verifies. (2) A hand-written row with a key outside
the schema fails as UNKNOWN_FIELD. (3) No writer site splices a caller's or a
peer's mapping into a row; the reader of that is checked against a planted
violation first, so a clean result is a measurement and not a blind spot.
"""
import ast
import hashlib
import json
import pathlib
import sys

import pytest

from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.proxy.serve import state_root
from sunglasses.receipts import chain, codes, hook_rows, keys, verify, wire

# The vector builder is written for the standalone bundle and imports its
# neighbours flat, as test_verify.py does.
sys.path.insert(0, str(pathlib.Path(verify.__file__).parent))
from make_vectors import TEST_SEED, WireChain, public_bytes  # noqa: E402

HEADER = {"session_id": "0" * 32, "budget_version": "sg-proxy-budget/1",
          "catalog_version": "sg-proxy-catalog/1",
          "contract_version": "GATE3_CONTRACT_v5.1"}
RUN = "c" * 32
# Two keys that are different to the peer and the same once a control
# character is escaped as text.
COLLIDING = {"a\x00": 1, "a\\u0000": 2}
ROOT = pathlib.Path(__file__).resolve().parents[1] / "sunglasses"


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


def _written(home, **fields):
    log = proxy_receipts.Log(state_root(), run_id=RUN, header=HEADER)
    stop = log.record_or_stop("SETTLED", **fields)
    assert not stop.stopped, f"SETTLED refused: the session stopped as {stop.reason}"
    assert not log.record_or_stop("SESSION_TORN_DOWN", settled=True).stopped
    log.close()
    (row,) = _rows(home, "SETTLED")
    return row


def _canonical(value):
    """By hand, not by the code under test."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"))


# ── (1) a peer object is one string, never an object in the row ────────────────

def test_colliding_keys_end_as_one_string_with_both_keys_visible(home):
    row = _written(home, supported=COLLIDING)
    assert row["supported"] == '{"a\\u0000":1,"a\\\\u0000":2}'
    assert json.loads(row["supported"]) == COLLIDING      # both, exactly
    assert "sanitized" not in row and "truncated" not in row
    results = _verified(home)
    assert results["chain_integrity"] == "CHAIN_OK"
    assert results["lifecycle"] == "PAIRING_UNKEYED"


def test_lone_surrogate_keys_stay_two_keys(home):
    """U+FFFD would make these two one; the canonical JSON escapes them."""
    peer = {"k\udc80": 1, "k\udc81": 2}
    row = _written(home, supported=peer)
    assert row["supported"] == _canonical(peer)
    assert json.loads(row["supported"]) == peer
    assert _verified(home)["chain_integrity"] == "CHAIN_OK"


def test_the_control_del_is_escaped_too_so_the_wire_never_refuses_it(home):
    """The wire refuses U+007F as it refuses U+0000 to U+001F. The canonical
    JSON escapes it, so an object carrying it is still one written string."""
    peer = {"a\x7f": "\x7f"}
    row = _written(home, supported=peer)
    assert row["supported"] == '{"a\\u007f":"\\u007f"}'
    assert json.loads(row["supported"]) == peer
    assert _verified(home)["chain_integrity"] == "CHAIN_OK"


def test_an_object_inside_a_list_makes_the_whole_value_one_string(home):
    peer = ["tools/list", {"a\x00": 1, "a\\u0000": 2}]
    row = _written(home, offered=peer)
    assert row["offered"] == _canonical(peer)
    assert json.loads(row["offered"]) == peer


def test_the_control_a_list_of_strings_is_still_a_list(home):
    row = _written(home, advertised=["tools/list", "tools/call"])
    assert row["advertised"] == ["tools/list", "tools/call"]


def test_an_object_over_the_budget_is_written_as_its_digest(home):
    peer = {f"key{n:03d}": "v" * 20 for n in range(40)}
    text = _canonical(peer)
    assert len(text) > proxy_receipts.FIELD_BYTES
    row = _written(home, supported=peer)
    assert row["supported"] == hashlib.sha256(text.encode("ascii")).hexdigest()
    assert row["digested"] == {"supported": len(text)}
    assert "truncated" not in row
    assert _verified(home)["lifecycle"] == "PAIRING_UNKEYED"


def test_a_caller_cannot_write_the_digested_marker_itself(home):
    row = _written(home, reason="ok", digested={"reason": 3})
    assert row == {"reason": "ok"}


# ── (2) the verifier's key set is closed per record kind ──────────────────────

def _proxy_chain(**settled):
    c = WireChain(producer="proxy")
    c.event("HEADER", **HEADER)
    c.event("SETTLED", **settled)
    c.event("SESSION_TORN_DOWN", settled=True)
    c.seal("close")
    return c


def _judge(c):
    report = verify.verify(c.data(), public_bytes(TEST_SEED))
    return report.results


def test_the_control_an_honest_proxy_row_is_judged_as_before():
    results = _judge(_proxy_chain(reason="ok", status="complete"))
    assert results["chain_integrity"] == "CHAIN_OK"
    assert results["lifecycle"] == "PAIRING_UNKEYED"


@pytest.mark.parametrize("settled", [
    {"reason": "ok", "smuggled": "x"},                  # a body key
    {"supported": {"a": 1}},                             # a key inside a field
    {"truncated": {"not_a_field": 3}},                   # a key inside a marker
    {"leaf_provenance": [{"index": 0, "pointer": "/x"}]},  # inside a leaf
], ids=["body", "field", "marker", "leaf"])
def test_a_hand_written_proxy_row_with_a_key_outside_the_schema_fails(settled):
    results = _judge(_proxy_chain(**settled))
    assert results["chain_integrity"] == "CHAIN_OK"     # the bytes are fine
    assert results["lifecycle"] == "UNKNOWN_FIELD"
    assert codes.strict_exit_code(results) == 1


def test_a_key_outside_the_envelope_fails():
    c = WireChain(producer="proxy")
    c.event("HEADER", **HEADER)
    c._add({"event": "SESSION_TORN_DOWN", "body": {"settled": True},
            "smuggled": 1})
    c.seal("close")
    assert _judge(c)["lifecycle"] == "UNKNOWN_FIELD"


def test_a_hook_row_with_a_key_outside_the_schema_fails():
    c = WireChain(producer="hook")
    c.event("in_flight", eval_id="0" * 16)
    c.event("decision", eval_id="0" * 16, decision="allow", smuggled=1)
    c.seal("close")
    assert _judge(c)["lifecycle"] == "UNKNOWN_FIELD"


def test_the_control_an_honest_hook_row_is_complete():
    c = WireChain(producer="hook")
    c.event("in_flight", eval_id="0" * 16)
    c.event("decision", eval_id="0" * 16, decision="allow",
            cleared_canaries=[{"rule_id": "GLS-X-1", "fingerprint": "sha256:" + "0" * 8}])
    c.seal("close")
    assert _judge(c)["lifecycle"] == "LIFECYCLE_COMPLETE"


def test_unknown_field_is_a_failure_code():
    assert "UNKNOWN_FIELD" in codes.CODES
    assert codes.strict_exit_code({"lifecycle": "UNKNOWN_FIELD"}) == 1


def test_the_verifier_proxy_fields_are_the_writer_fields():
    """The verifier stands alone and imports nothing from the product, so it
    carries its own copy; this holds the copy equal to the writer's."""
    assert verify.PROXY_FIELDS == proxy_receipts.PERMITTED_FIELDS


def test_every_key_the_hook_writer_can_produce_is_in_the_verifier_schema():
    row = {name: None for name in hook_rows._DECISION}
    row.update(eval_id="0" * 16, tool_name="Bash", session_id="s",
               input_sha256=None, decision="allow", lane="fuzzy",
               rule_id="GLS-X-1", degraded=True, fuzzy_lane=True,
               pin_state_stale=True, policy_state="ok", pin_source="ok",
               pin_reach="ok", pin_checked_at="2026-09-24T00:00:00Z",
               elapsed_ms=1, pin_state_age_s=1,
               cleared_canaries=[{"rule_id": "GLS-X-1",
                                  "fingerprint": "sha256:" + "0" * 8}],
               input_sha256_reason="unencodable", junk_name=1)
    row[3] = "unnamed"
    body = hook_rows.decision(row, error_types=["ValueError"])
    assert set(hook_rows._DECISION) <= set(body) | {"input_sha256"}
    assert {"elapsed_us", "pin_state_age_s", "cleared_canaries", "error_types",
            "input_digest", "withheld", "withheld_unnamed"} <= set(body)
    assert set(body) <= set(verify.HOOK_FIELDS)


# ── (3) no writer site splices a mapping into a row ────────────────────────────

# The receipt entry points, and the modules that call them or build rows.
ENTRY_POINTS = {"_record", "event", "record_or_stop", "_write_row"}
CALLERS = ["proxy/receipts.py", "proxy/route.py", "proxy/serve.py",
           "proxy/pump.py", "receipts/chain.py", "receipts/hook_rows.py",
           "receipts/optin.py"]
# Where a row dict is built: a splat or an update here must be a schema
# constant or the allowlist's own output, never a mapping handed in.
ROW_BUILDERS = ["proxy/receipts.py", "receipts/chain.py",
                "receipts/hook_rows.py", "receipts/optin.py"]


def _splices(source, *, builder):
    """Every place `source` puts a mapping it did not name into a row."""
    found = []

    def visit(node, own):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            own = node.args.kwarg.arg if node.args.kwarg else None
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", getattr(node.func, "id", None))
            if name in ENTRY_POINTS:
                for keyword in node.keywords:
                    # A forward of the function's OWN keywords passes on
                    # names its callers wrote; anything else is a mapping.
                    if keyword.arg is None and not (
                            isinstance(keyword.value, ast.Name)
                            and keyword.value.id == own):
                        found.append((node.lineno, f"{name}(**...)"))
            if name == "Log":
                for keyword in node.keywords:
                    if keyword.arg == "header" and not (
                            isinstance(keyword.value, ast.Dict)
                            and all(isinstance(k, ast.Constant)
                                    for k in keyword.value.keys)):
                        found.append((node.lineno, "Log(header=<not a literal>)"))
            if builder and name == "update" and not (
                    node.args and isinstance(node.args[0], ast.Call)
                    and getattr(node.args[0].func, "attr", None) == "_clean"):
                found.append((node.lineno, ".update(...)"))
        if builder and isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is None and not (isinstance(value, ast.Name)
                                        and value.id.lstrip("_").isupper()):
                    found.append((node.lineno, "{**...}"))
        for child in ast.iter_child_nodes(node):
            visit(child, own)

    visit(ast.parse(source), None)
    return sorted(set(found))


def test_the_reader_finds_a_planted_splice():
    """The control that proves the reader: each shape the test forbids,
    planted, is found. Without it a clean result could be a blind reader."""
    planted = (
        "def a(log, peer):\n    log.event('SETTLED', **peer)\n"
        "def b(row, peer):\n    row.update(peer)\n"
        "def c(peer):\n    return {'event': 'x', **peer}\n"
        "def d(root, peer):\n    Log(root, run_id='r', header=peer)\n"
        "def e(self, event, **fields):\n    self.log.record_or_stop(event, **fields)\n"
    )
    assert [what for _, what in _splices(planted, builder=True)] == [
        "event(**...)", ".update(...)", "{**...}", "Log(header=<not a literal>)"]


@pytest.mark.parametrize("path", CALLERS)
def test_no_writer_site_splices_a_mapping_into_a_row(path):
    source = (ROOT / path).read_text(encoding="utf-8")
    assert _splices(source, builder=path in ROW_BUILDERS) == []
