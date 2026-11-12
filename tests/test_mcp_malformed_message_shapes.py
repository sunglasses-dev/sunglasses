"""A message the MCP server cannot read as a request gets ONE error reply, and the server keeps running.

Before this change a JSON-RPC batch (a JSON array) as the first line crashed the
process: `msg.get` raised AttributeError, and the error handler then read `msg_id`,
which had never been assigned, so the handler itself raised and the server died with a
traceback. After an earlier request the same array was answered with an error that
carried the EARLIER request's id, because `msg_id` still held it.

The rule, from JSON-RPC 2.0 section 5.1: an Invalid Request answers with code -32600
and id null when the id cannot be read. MCP removed batching in its 2025-06-18
revision, so an array is not a request this server serves; it is one Invalid Request,
not one answer per element.

The cases cover every JSON value that is not an object (null included: it used to read
as end of input and stop the server), a blank line (it did the same and is now skipped),
and the id rule: no reply ever carries an id the message in front of it did not have.
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _run(*lines):
    """Feed the lines to a real server process, return (answers, stderr)."""
    done = subprocess.run([sys.executable, "-m", "sunglasses.mcp"],
                          input="".join(line + "\n" for line in lines),
                          capture_output=True, text=True, timeout=120, cwd=ROOT)
    answers = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
    return answers, done.stderr


def _req(id_, method="tools/list"):
    return json.dumps({"jsonrpc": "2.0", "id": id_, "method": method})


INVALID = {"jsonrpc": "2.0", "id": None,
           "error": {"code": -32600, "message": "Invalid Request"}}


def _is_invalid_request(answer):
    return (answer.get("jsonrpc") == "2.0" and answer.get("id", "absent") is None
            and answer["error"]["code"] == -32600 and "result" not in answer)


@pytest.mark.parametrize("line", [
    '[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]',     # a batch of one
    '[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]',
    "[]",                                                    # an empty batch
    "5", '"text"', "true", "1.5", "null",
])
def test_a_non_object_message_gets_one_invalid_request_and_the_server_lives(line):
    answers, _stderr = _run(line, _req(2))
    assert len(answers) == 2, answers
    assert _is_invalid_request(answers[0]), answers[0]
    assert answers[1]["id"] == 2 and "tools" in answers[1]["result"]


def test_a_batch_as_the_first_message_does_not_crash_the_process():
    done = subprocess.run([sys.executable, "-m", "sunglasses.mcp"],
                          input='[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]\n',
                          capture_output=True, text=True, timeout=120, cwd=ROOT)
    assert "Traceback" not in done.stderr, done.stderr
    assert done.returncode == 0, (done.returncode, done.stderr)
    assert _is_invalid_request(json.loads(done.stdout.splitlines()[0]))


def test_a_batch_after_a_request_does_not_borrow_the_earlier_id():
    answers, _stderr = _run(_req(5, "no/such/method"),
                            '[{"jsonrpc":"2.0","id":3,"method":"tools/list"}]')
    assert answers[0]["id"] == 5 and answers[0]["error"]["code"] == -32601
    assert len(answers) == 2, answers
    assert _is_invalid_request(answers[1]), answers[1]


def test_a_request_whose_handler_fails_is_answered_under_its_own_id_only():
    """A tools/call with params that make the handler raise is answered once, with id 7;
    the next message is not answered with 7 again."""
    answers, _stderr = _run(
        json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": []}),
        "[1]")
    assert answers[0]["id"] == 7 and "error" in answers[0]
    assert len(answers) == 2 and _is_invalid_request(answers[1]), answers


def test_a_blank_line_is_not_a_message_and_does_not_end_the_server():
    answers, _stderr = _run("", "   ", _req(1), "", _req(2))
    assert [a["id"] for a in answers] == [1, 2], answers


def test_ordinary_requests_are_unchanged():
    answers, _stderr = _run(_req(1), _req(2, "no/such/method"),
                            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                            _req(3))
    assert [a["id"] for a in answers] == [1, 2, 3]
    assert "tools" in answers[0]["result"]
    assert answers[1]["error"]["code"] == -32601
    assert "tools" in answers[2]["result"]


def _raw(stdin_text):
    """Run a real server process on exactly this stdin text (no newline added)."""
    return subprocess.run([sys.executable, "-m", "sunglasses.mcp"], input=stdin_text,
                          capture_output=True, text=True, timeout=120, cwd=ROOT)


def test_closed_stdin_with_no_input_exits_zero_and_prints_nothing():
    """End of input is its own path now (a sentinel, separate from a blank line)."""
    done = _raw("")
    assert done.returncode == 0, (done.returncode, done.stderr)
    assert done.stdout == "" and "Traceback" not in done.stderr, (done.stdout, done.stderr)


def test_closed_stdin_after_one_request_exits_zero_with_exactly_that_answer():
    done = _raw(_req(1) + "\n")
    assert done.returncode == 0, (done.returncode, done.stderr)
    assert "Traceback" not in done.stderr, done.stderr
    answers = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
    assert len(answers) == 1 and answers[0]["id"] == 1 and "tools" in answers[0]["result"], answers


@pytest.mark.parametrize("blank", ["   ", "\t", " \t  ", "\r"])
def test_a_whitespace_only_line_is_treated_like_a_blank_line(blank):
    """Spaces, tabs and a bare carriage return are skipped, not answered and not the end."""
    answers, stderr = _run(blank, _req(1), blank, _req(2), blank)
    assert [a["id"] for a in answers] == [1, 2], (answers, stderr)
    assert "Traceback" not in stderr, stderr


def test_a_whitespace_only_last_line_with_no_newline_still_ends_cleanly():
    done = _raw(_req(1) + "\n" + "   ")
    assert done.returncode == 0, (done.returncode, done.stderr)
    answers = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
    assert [a["id"] for a in answers] == [1], answers
