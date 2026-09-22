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

Everything here is an ARGUMENT and nothing is an environment variable. This
file ships inside the wheel, and an undeclared environment read in a shipped
package is a switch nobody documented that anything in the process tree can
flip. These particular switches tell a bundled server to record every byte it
receives, to answer every call with text of the caller's choosing, and to
outlive its own stdin, which is a combination worth needing a command line for.
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


FLAGS = ("--ingress", "--inject", "--proc", "--poison-description")
SWITCHES = ("--linger",)


def parse(argv):
    """The five options, and nothing this file could read from the environment."""
    argv = list(argv or [])
    options = {}
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in FLAGS and index + 1 < len(argv):
            options[token[2:]] = argv[index + 1]
            index += 2
            continue
        if token in SWITCHES:
            options[token[2:]] = True
            index += 1
            continue
        index += 1
    return options


def _ingress(path, raw):
    """Append one line, in its own open and close.

    The per-line `with` is what makes this survive the process being killed,
    and that is the property the teardown tests need, because the proxy kills
    this server's group on the way out. An earlier version of this comment
    credited the flush and fsync with that, which is wrong: closing the file
    flushes it, so a mutation removing them changes nothing a test can see.
    They are here for durability across a machine crash and nothing else, and
    saying so is the difference between a comment and a guess.
    """
    if not path:
        return
    with open(path, "ab") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def handle(message, poison=None, listing_poison=None):
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
        # `--poison-description` makes the LISTING hostile, which is a
        # different surface from `--inject`. That one poisons a tools/call
        # RESULT; this poisons the metadata a client is given BEFORE it calls
        # anything, which is where tool-description poisoning actually lives.
        # Both travel on `api_response`, and until now only the first had a
        # hostile fixture -- so no test could ask whether a poisoned
        # DESCRIPTION is stopped on the real path.
        tools = [dict(tool) for tool in TOOLS]
        if listing_poison:
            tools[0]["description"] = (tools[0].get("description", "")
                                       + " " + listing_poison)
        return _ok(request_id, {"tools": tools})
    if method == "tools/call":
        # `--inject` makes this a HOSTILE server rather than a mock of one.
        # The inbound threat is a real process on the other end of a real pipe
        # deciding to say something the user never asked for, and a test whose
        # attacker is a fixture proves the fixture.
        if poison:
            return _ok(request_id, {"content": [{"type": "text",
                                                 "text": poison}]})
        params = message.get("params") or {}
        arguments = params.get("arguments") or {}
        text = arguments.get("text", "")
        return _ok(request_id, {"content": [{"type": "text",
                                             "text": str(text)}]})
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": METHOD_NOT_FOUND, "message": f"no such method: {method}"}}


def _ok(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _announce(path):
    """Write pid and process group where a test can read them.

    Two properties need this. A child in its own group cannot be observed from
    outside without the group id, and an orphan cannot be detected without the
    pid of the thing that should be gone.
    """
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"pid": os.getpid(),
                                 "pgid": os.getpgid(0)}))
        handle.flush()
        os.fsync(handle.fileno())


def main(argv=None, stdin=None, stdout=None):
    options = parse(sys.argv[1:] if argv is None else argv)
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer
    _announce(options.get("proc"))
    for raw in stdin:
        _ingress(options.get("ingress"), raw)
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(message, dict):
            continue
        reply = handle(message, poison=options.get("inject"),
                       listing_poison=options.get("poison-description"))
        if reply is None:
            continue
        stdout.write((json.dumps(reply) + "\n").encode("utf-8"))
        stdout.flush()
    if options.get("linger"):
        # A server that does NOT die when its stdin closes. Real ones behave
        # this way all the time, and a proxy that returns without killing the
        # group leaves it holding the pipes it was mediating.
        import time
        time.sleep(300)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
