"""T2's selector table and T3.R1's accounting, specified from the rows.

Committed before the implementation, like the three slices before it.

The row that governs the rest is T2.R0, and it freezes TWO accountings that are
easy to collapse into one and mean different things:

  SCAN COVERAGE is what gets inspected. Every string leaf AND every object KEY
  of the whole result, params or error object, recursively, including `_meta`,
  `annotations`, `uri`, `mimeType`, `title`, `name` and `description`. Only the
  fixed protocol scalars validated by schema are excluded.

  CONTENT BYTES is what counts against the budget. Only decoded UTF-8 bytes of
  string VALUES at content positions. Object keys are EXCLUDED. The schema
  discriminants `type` and `role` are EXCLUDED. Duplicates count twice.
  Separators are excluded.

A key is therefore INSPECTED and does not COUNT. Writing one function and using
it for both is the obvious economy and it is wrong in both directions at once:
it either lets a key escape inspection or charges it against a budget the row
says it is not charged against. The reference points the contract gives are
exact, so they are asserted exactly.
"""
import json

import pytest

selector = pytest.importorskip(
    "sunglasses.proxy.selector",
    reason="the selector is the slice being specified here")


# ── T2.R0 and T3.R1: the two accountings are not the same number ──────────

def test_an_object_key_is_inspected_but_does_not_count_against_the_budget():
    """The distinction the whole table rests on."""
    message = {"result": {"content": [{"type": "text", "text": "hi"}]}}
    covered = selector.coverage_leaves(message["result"])
    values = [value for _path, value in covered]
    assert "content" in values, "the KEY was not inspected"
    assert "text" in values, "the nested key was not inspected"

    counted = selector.content_bytes(message["result"])
    assert counted == len("hi".encode()), (
        f"keys or discriminants were charged against the budget: {counted}")


@pytest.mark.parametrize("discriminant,value", [("type", "text"), ("role", "user")])
def test_the_schema_discriminants_are_inspected_and_not_counted(discriminant, value):
    """T3.R1 names `type` and `role` explicitly. They are fixed vocabulary, so
    charging them makes an identical payload cost more in one shape than
    another."""
    result = {"content": [{discriminant: value, "text": "abc"}]}
    values = [v for _p, v in selector.coverage_leaves(result)]
    assert value in values, f"{discriminant} was not inspected"
    assert selector.content_bytes(result) == 3


def test_a_duplicate_string_counts_twice():
    """T3.R1: duplicates count twice. A budget that deduplicates can be walked
    under by repeating one payload."""
    result = {"content": [{"type": "text", "text": "abc"},
                          {"type": "text", "text": "abc"}]}
    assert selector.content_bytes(result) == 6


def test_content_bytes_are_utf8_not_characters():
    """A three byte character is three bytes. Counting characters gives an
    attacker three times the budget in any non-ASCII script."""
    result = {"content": [{"type": "text", "text": "中文"}]}
    assert selector.content_bytes(result) == 6


def test_numbers_and_booleans_are_covered_as_strings_but_do_not_count():
    """T3.R1: numbers and bools are stringified in JSON form FOR COVERAGE, and
    only string values count."""
    result = {"total": 42, "isError": False, "text": "x"}
    values = [v for _p, v in selector.coverage_leaves(result)]
    assert "42" in values and "false" in values
    assert selector.content_bytes(result) == 1


def test_every_leaf_carries_its_path():
    """T3.R1 wants leaves in document order as (pointer, value). The path is
    what makes a finding locatable."""
    result = {"content": [{"type": "text", "text": "hi"}]}
    paths = [path for path, _v in selector.coverage_leaves(result)]
    assert any("content" in path for path in paths)


# ── the channel each row names ─────────────────────────────────────────────

@pytest.mark.parametrize("method,direction,channel", [
    ("initialize", "request", "message"),          # T2.R1
    ("initialize", "result", "api_response"),      # T2.R2
    ("tools/call", "request", "message"),          # T2.R3
    ("tools/call", "result", "api_response"),      # T2.R4
    ("resources/read", "request", "message"),      # T2.R8
    ("resources/read", "result", "api_response"),  # T2.R9
    ("prompts/get", "request", "message"),         # T2.R10
    ("prompts/get", "result", "api_response"),     # T2.R11
])
def test_each_row_selects_the_channel_the_table_names(method, direction, channel):
    """The channel is not a default. A rule is scoped to a channel, so selecting
    the wrong one silently disables every rule written for the right one."""
    assert selector.channel_for(method, direction) == channel


def test_tools_list_request_is_the_control_channel():
    """T2.R6. The proxy re-lists in its own id namespace."""
    assert selector.channel_for("tools/list", "request") == "control"


def test_a_client_notification_is_the_message_channel():
    """T2.R13."""
    assert selector.channel_for("notifications/cancelled", "request") == "message"


def test_an_upstream_notification_is_the_api_response_channel():
    """T2.R12."""
    assert selector.channel_for("notifications/message", "result") == "api_response"


# ── T2.R14: zero leaves is COMPLETE, for three shapes only ────────────────

@pytest.mark.parametrize("method,message", [
    ("ping", {}),
    ("notifications/initialized", {}),
    ("tools/call", {"content": []}),
])
def test_the_three_shapes_with_no_leaves_are_complete(method, message):
    assert selector.zero_leaves_is_complete(method, message) is True


def test_an_empty_content_with_other_members_is_not_one_of_the_three():
    """T2.R14 says `content` is `[]` WITH NO OTHER MEMBERS. A result carrying
    an empty content list beside a structuredContent object has leaves, and
    treating it as complete would pass the other members uninspected."""
    assert selector.zero_leaves_is_complete(
        "tools/call", {"content": [], "structuredContent": {"a": "b"}}) is False


def test_any_other_method_with_no_leaves_is_not_complete():
    assert selector.zero_leaves_is_complete("resources/read", {}) is False


# ── unsupported content, per row ──────────────────────────────────────────

@pytest.mark.parametrize("method,result", [
    ("tools/call", {"content": [{"type": "image", "data": "..."}]}),      # R4
    ("tools/call", {"content": [{"type": "audio", "data": "..."}]}),      # R4
    ("tools/call", {"content": [{"type": "resource",
                                 "resource": {"blob": "..."}}]}),         # R4
    ("resources/read", {"contents": [{"blob": "..."}]}),                  # R9
    ("prompts/get", {"messages": [{"role": "user",
                                   "content": {"type": "image"}}]}),      # R11
])
def test_binary_content_is_unsupported_not_merely_skipped(method, result):
    """The rows say UNSUPPORTED_CONTENT. Skipping a blob and inspecting the rest
    reports a clean scan of a message we did not read."""
    assert selector.unsupported(method, result) == "UNSUPPORTED_CONTENT"


def test_ordinary_text_content_is_supported():
    """Or the check above would be refusing everything."""
    assert selector.unsupported(
        "tools/call", {"content": [{"type": "text", "text": "hi"}]}) is None


# ── T2.R15 and R16: who is answered, and who never sees it ────────────────

@pytest.mark.parametrize("method", [
    "sampling/createMessage", "roots/list", "elicitation/create", "made/up",
])
def test_an_upstream_request_is_answered_upstream_and_the_client_never_sees_it(method):
    """T2.R15. Forwarding it to the client would let upstream drive the client
    through us, which is the whole thing a mediator exists to prevent."""
    action = selector.refusal(method, "request", origin="upstream")
    assert action.reason == "UNINSPECTED_METHOD"
    assert action.answer_to == "upstream"
    assert action.forward is False


def test_a_client_unknown_method_is_answered_to_the_client():
    """T2.R16, and upstream never sees it."""
    action = selector.refusal("x/unknown", "request", origin="client")
    assert action.reason == "UNINSPECTED_METHOD"
    assert action.answer_to == "client"
    assert action.forward is False


@pytest.mark.parametrize("method", ["tools/call", "resources/read", "prompts/get"])
def test_a_known_method_is_not_refused(method):
    assert selector.refusal(method, "request", origin="client") is None
