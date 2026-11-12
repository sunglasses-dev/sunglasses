"""The MCP server answers `initialize` with a protocol version it can honour.

`sunglasses/mcp.py` used to answer every `initialize` with "2024-11-05", whatever
the client offered. The lifecycle page of the 2025-11-25 revision (read
2026-11-11, modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle,
"Version Negotiation") says:

    "If the server supports the requested protocol version, it MUST respond with the
    same version. Otherwise, the server MUST respond with another protocol version it
    supports. This SHOULD be the latest version supported by the server."

A client that offered 2025-11-25 (current Claude Code does) was therefore answered
with a version it had not asked for although the server could speak the one it
asked for.

WHICH VERSIONS. The set is a closed list and membership is exact: a version is
answered because it is IN the list, never because it resembles one that is.

* 2024-11-05, 2025-06-18 and 2025-11-25 are in it. Between them the revisions add
  HTTP headers, authorization, client features and optional fields; none puts a new
  obligation on a stdio server that offers three tools.
* 2025-03-26 is NOT in it. Its basic-protocol page says implementations "MUST support
  receiving JSON-RPC batches" (read 2026-11-11, specification/2025-03-26/basic,
  "Batching"). This server reads one object per line and does not take a batch, and
  the 2025-06-18 changelog lists "Remove support for JSON-RPC batching". Offered
  2025-03-26, it answers with the latest version it supports, as the rule above says
  for any version it does not support.

Every version the server can answer must also be one the proxy accepts, or the proxy
would close the session on our own server's answer.
"""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sunglasses import mcp                                   # noqa: E402
from sunglasses.proxy import handshake                       # noqa: E402

LATEST = "2025-11-25"
SUPPORTED = ("2024-11-05", "2025-06-18", "2025-11-25")


def _offer(value):
    return {"protocolVersion": value, "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"}}


def test_the_supported_set_is_exactly_this_list():
    assert tuple(mcp.SUPPORTED_PROTOCOL_VERSIONS) == SUPPORTED
    assert mcp.PROTOCOL_VERSION == LATEST


@pytest.mark.parametrize("version", SUPPORTED)
def test_a_supported_offer_is_answered_with_the_same_version(version):
    assert mcp.handle_initialize(_offer(version))["protocolVersion"] == version


@pytest.mark.parametrize("value", [
    "2025-03-26",          # real revision, needs batch receive, which we do not do
    "2099-01-01",          # a later revision than any we know
    "2024-11-04",          # one day off a supported version
    "2025-11-25 ",         # trailing space: membership, not prefix
    "2025-11-25-beta",
    "2025",
    "",
])
def test_an_unsupported_string_is_answered_with_the_latest(value):
    assert mcp.handle_initialize(_offer(value))["protocolVersion"] == LATEST


@pytest.mark.parametrize("value", [7, 1.5, None, True, ["2025-06-18"], {"v": "2025-06-18"}])
def test_a_non_string_offer_is_answered_with_the_latest(value):
    assert mcp.handle_initialize(_offer(value))["protocolVersion"] == LATEST


@pytest.mark.parametrize("params", [None, [], "x", 7, {}, {"capabilities": {}}])
def test_no_readable_offer_is_answered_with_the_latest(params):
    assert mcp.handle_initialize(params)["protocolVersion"] == LATEST


@pytest.mark.parametrize("version", SUPPORTED + ("2025-03-26", "2099-01-01"))
def test_the_rest_of_the_answer_does_not_change(version):
    answer = mcp.handle_initialize(_offer(version))
    assert answer["capabilities"] == {"tools": {}}
    assert answer["serverInfo"] == {"name": mcp.SERVER_NAME, "version": mcp.SERVER_VERSION}
    assert set(answer) == {"protocolVersion", "capabilities", "serverInfo"}


def test_every_version_we_answer_is_one_the_proxy_accepts():
    for version in SUPPORTED:
        assert version in handshake.SUPPORTED_VERSIONS, version


@pytest.mark.parametrize("offered, expected", [
    ("2025-11-25", "2025-11-25"),
    ("2025-06-18", "2025-06-18"),
    ("2024-11-05", "2024-11-05"),
    ("2025-03-26", "2025-11-25"),
])
def test_over_stdio_the_server_answers_as_the_rule_says(offered, expected):
    """The real process, one newline-delimited request, one answer."""
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": _offer(offered)}) + "\n"
    root = os.path.join(os.path.dirname(__file__), "..")
    done = subprocess.run([sys.executable, "-m", "sunglasses.mcp"], input=request,
                          capture_output=True, text=True, timeout=60, cwd=root)
    answers = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
    assert len(answers) == 1, (done.stdout, done.stderr)
    assert answers[0]["id"] == 1
    assert answers[0]["result"]["protocolVersion"] == expected
