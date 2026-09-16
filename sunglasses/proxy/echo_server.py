"""A real MCP stdio server, bundled so the self test has something to spawn.

T10.R1 spawns the installed artifact against this and T12.R1 requires real
pipes and real upstreams. Nothing here is clever on purpose: a self test whose
server is a mock proves the mock agrees with us, and an echo whose output a
test cannot predict exactly gives S1's byte equality check nothing to compare.

The one deliberate feature is the ingress file. Every raw line this process
receives is appended to the path given by `--ingress` and flushed immediately,
so a test can read how many bytes of a protected payload arrived HERE rather
than asking the proxy whether it withheld them. That reading is taken on the
far side of the thing being measured, which is the whole reason it is
trustworthy.

It is an ARGUMENT and not an environment variable. This file ships inside the
wheel, and `test_package_reads_no_undeclared_environment_variables` exists
because an undeclared environment read in a shipped package is a switch nobody
documented that anything in the process tree can flip. Declaring a fourth
variable would have satisfied the guard; needing none satisfies the reason it
is there.
"""
from __future__ import annotations

import json
import os
import sys

PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
SERVER_INFO = {"name": "sunglasses-echo", "version": "1"}

TOOLS = [{
    "name": "echo",
    "description": "Return the text it was given.",
    "inputSchema": {"type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"]},
}]

METHOD_NOT_FOUND = -32601


def parse(argv):
    """`--ingress PATH`, and nothing this file could read from the environment."""
    argv = list(argv or [])
    options = {}
    index = 0
    while index < len(argv):
        if argv[index] == "--ingress" and index + 1 < len(argv):
            options["ingress"] = argv[index + 1]
            index += 2
            continue
        index += 1
    return options


def _ingress(path, raw):
    """Append and flush. A buffered instrument reads as a zero when the process
    it is measuring is killed, which is exactly the case under test."""
    if not path:
        return
    with open(path, "ab") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def handle(message):
    """One message to one reply, or None when there is nothing to say."""
    method = message.get("method")
    if "id" not in message:
        # A notification has no response. Answering one means inventing an id.
        return None
    request_id = message["id"]

    if method == "initialize":
        params = message.get("params") or {}
        wanted = params.get("protocolVersion")
        version = wanted if wanted in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[-1]
        return _ok(request_id, {"protocolVersion": version,
                                "capabilities": {"tools": {}},
                                "serverInfo": dict(SERVER_INFO)})
    if method == "ping":
        return _ok(request_id, {})
    if method == "tools/list":
        return _ok(request_id, {"tools": [dict(tool) for tool in TOOLS]})
    if method == "tools/call":
        params = message.get("params") or {}
        arguments = params.get("arguments") or {}
        text = arguments.get("text", "")
        return _ok(request_id, {"content": [{"type": "text",
                                             "text": str(text)}]})
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": METHOD_NOT_FOUND, "message": f"no such method: {method}"}}


def _ok(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main(argv=None, stdin=None, stdout=None):
    options = parse(sys.argv[1:] if argv is None else argv)
    ingress = options.get("ingress")
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer
    for raw in stdin:
        _ingress(ingress, raw)
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(message, dict):
            continue
        reply = handle(message)
        if reply is None:
            continue
        stdout.write((json.dumps(reply) + "\n").encode("utf-8"))
        stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
