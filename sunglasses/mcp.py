#!/usr/bin/env python3
"""
SUNGLASSES MCP Server — Model Context Protocol server for AI agent security scanning.

Exposes SUNGLASSES as a tool that Claude Code (or any MCP client) can call.
Uses raw stdio JSON-RPC 2.0 — zero external dependencies beyond the sunglasses package.

Usage:
    sunglasses-mcp

Register with Claude Code:
    claude mcp add sunglasses -- sunglasses-mcp
"""

import argparse
import json
import sys
import os
import threading

# Ensure the package is importable when run as a module
_pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _pkg_dir not in sys.path:
    sys.path.append(_pkg_dir)   # at the END: the package is already imported, and this must never go ahead of the standard library

from sunglasses import __version__
from sunglasses.door_mask import mask_document, secret_strings, shown_match
from sunglasses import _time_limit
from sunglasses.engine import SunglassesEngine
from sunglasses.scanner import SunglassesScanner
from sunglasses.extractors.dispatch import UnreadableFile

# Protocol constants
JSONRPC = "2.0"
SERVER_NAME = "sunglasses"
SERVER_VERSION = __version__
# The protocol versions this server answers `initialize` with. A closed list, matched
# by exact membership. 2025-03-26 is left out on purpose: that revision requires
# implementations to accept JSON-RPC batches, and this server reads one object per line.
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-06-18", "2025-11-25")
PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[-1]  # the latest, the answer for any offer we do not support


def _make_response(id, result):
    return {"jsonrpc": JSONRPC, "id": id, "result": result}


def _make_error(id, code, message):
    return {"jsonrpc": JSONRPC, "id": id, "error": {"code": code, "message": message}}


def _make_notification(method, params=None):
    msg = {"jsonrpc": JSONRPC, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _negotiated_version(params):
    """The version to answer with: the client's offer if we support it, else our latest.

    MCP lifecycle, version negotiation: a server that supports the requested version
    responds with the same one, otherwise with another version it supports, which
    should be its latest. An offer that is missing, is not a string, or names a
    version outside the list gets the latest.
    """
    offered = params.get("protocolVersion") if isinstance(params, dict) else None
    if isinstance(offered, str) and offered in SUPPORTED_PROTOCOL_VERSIONS:
        return offered
    return PROTOCOL_VERSION


def handle_initialize(params):
    """Handle initialize request — return server capabilities."""
    return {
        "protocolVersion": _negotiated_version(params),
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        }
    }


def handle_tools_list(params):
    """Handle tools/list — return available tools."""
    return {
        "tools": [
            {
                "name": "scan_text",
                # Pinned word for word by tests/test_mcp_scan_text_descriptor.py.
                # The proxy approves a server by the sha of its whole tools/list,
                # so editing this retires every proxy approval of this server.
                "description": (
                    "Scan text for prompt injection, data exfiltration, credential leaks and "
                    "other AI agent security threats. Returns findings, a severity, a decision "
                    "(allow, block, quarantine or allow_redacted) and inspection_complete. "
                    "The decision is reported to the caller and is not enforced. This tool "
                    "blocks nothing and returns the matched words of each finding; a secret "
                    "shows its first 4 characters, its length and its rule id. "
                    "isError false means the scan ran, not that the input is clean. "
                    "Read is_clean and inspection_complete in the result."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The text content to scan for security threats."
                        },
                        "channel": {
                            "type": "string",
                            "description": "The input channel type. Affects which patterns are checked. Unknown channels are rejected (fail closed).",
                            "enum": ["message", "file", "api_response", "web_content", "log_memory", "tool_output", "agent_input", "code", "prompt"],
                            "default": "message"
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "scan_file",
                "description": (
                    "Scan a file for prompt injection and security threats. "
                    "Supports text files, images (with OCR), PDFs, and more. "
                    "For audio/video files, returns a notice that DEEP scan is needed."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to the file to scan."
                        },
                        "allow_deep": {
                            "type": "boolean",
                            "description": "Allow slow DEEP scans for audio/video files. Default: false.",
                            "default": False
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "scanner_info",
                "description": (
                    "Get SUNGLASSES scanner info: version, pattern count, "
                    "keyword count, supported channels."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
    }


def handle_tools_call(params):
    """Handle tools/call — execute a tool and return results."""
    tool_name = params.get("name")
    arguments = params.get("arguments", {})

    try:
        if tool_name == "scan_text":
            return _tool_scan_text(arguments)
        elif tool_name == "scan_file":
            return _tool_scan_file(arguments)
        elif tool_name == "scanner_info":
            return _tool_scanner_info(arguments)
        else:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                "isError": True,
            }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Error: {str(e)}"}],
            "isError": True,
        }



# ── one engine per process ──────────────────────────────────────────────────
#
# The MCP server is long-lived: `main()` reads requests in a loop for as long as
# the client keeps it open. Building the engine inside each tool call made every
# request pay the whole ruleset compile, and the compile is three orders of
# magnitude more expensive than the work it enables -- measured on main at
# 1,519 ms to build against 1.35 ms to scan, so a scan_text call was 1,526 ms of
# which about a millisecond was scanning. On a slow box it is nearer three
# seconds, per call, forever.
#
# Built on FIRST USE rather than at import, so importing the module stays cheap
# and a client that never calls a tool never pays. The lock is what makes two
# requests arriving together compile once instead of twice; the second check
# inside it is what makes the first check outside it safe.
_ENGINE = None
_ENGINE_LOCK = threading.Lock()


def _engine():
    """The process's engine, built once, reused for every tool call."""
    global _ENGINE
    if _ENGINE is None:
        with _ENGINE_LOCK:
            if _ENGINE is None:
                _ENGINE = SunglassesEngine()
    return _ENGINE


def _coverage_detail(result):
    """The cause of an incomplete scan, in the same words the command line uses."""
    unread, ended = _time_limit.coverage_causes(result)
    return _time_limit.incomplete_detail("part of the input was not read", unread, ended)


def _time_limit_lines(result):
    """One warning line per rule (or scan) that ended at its time limit: the command line's own text."""
    return "".join(f"\n  ! {_time_limit.time_limit_warning(e)}"
                   for e in (getattr(result, "time_limit_ended", None) or []))


def _call_time_limit():
    """The time limit a tool call scans under, and why there is none.

    Returns (TimeLimit, None), or (None, reason) when this process cannot own the CPU timer (the
    server's handlers run on its main thread, so that is a platform or host-program answer). The
    server may scan with no limit but must say so: the note is the first line of the tool's text."""
    reason = _time_limit.unavailable_reason()
    if reason is not None:
        return None, reason
    return _time_limit.TimeLimit(_time_limit.DEFAULT_RULE_S, _time_limit.DEFAULT_SCAN_S), None


def _off_note(why):
    return (f"Note: the rule time limit is off for this scan ({why}); "
            f"a rule that never finishes is not stopped.\n\n") if why else ""


# ── what a result carries ───────────────────────────────────────────────────
#
# A tool result is read by a model and written to its logs, so it is built for that
# reader. Per finding it carries the rule id, the name, the category, the severity,
# the channel the input came in on and the words that matched -- never the rule's own
# keyword list or regex list, and each finding once. A finding of a secret class shows
# its marker (see door_mask); the full secret does not leave the process through this door.
# At most MAX_FINDINGS findings are listed, then one entry counts the rest by category,
# and the whole result is at most MAX_RESULT_BYTES.
MAX_FINDINGS = 50
MAX_RESULT_BYTES = 64 * 1024
MAX_SHOWN_CHARS = 300


def _shown_words(finding):
    """The words listed for a finding. A document handed to this function has been through mask_document at
    the door, so the words are already a marker for a secret; here they are only cut to a readable length."""
    matched = finding.get("matched_text")
    if not isinstance(matched, str) or not matched:
        return None
    if len(matched) > MAX_SHOWN_CHARS:
        return matched[:MAX_SHOWN_CHARS] + "\u2026"
    return matched


def _compact_findings(findings, channel):
    """Each finding once, as id, name, category, severity, channel, shown words; capped.

    Returns (listed, rest) where rest is None or {"count": n, "by_category": {...}}.
    """
    listed, seen, rest = [], set(), {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        shown = _shown_words(f)
        key = (f.get("id"), shown)
        if key in seen:
            continue
        seen.add(key)
        if len(listed) >= MAX_FINDINGS:
            category = str(f.get("category"))
            rest[category] = rest.get(category, 0) + 1
            continue
        entry = {"id": f.get("id"), "name": f.get("name"),
                 "category": f.get("category"), "severity": f.get("severity"),
                 "channel": channel}
        if shown is not None:
            entry["matched_text"] = shown
        listed.append(entry)
    if not rest:
        return listed, None
    return listed, {"count": sum(rest.values()), "by_category": rest}


def _door_document(doc):
    """The result a caller gets: the scan document without the rule objects, findings compacted."""
    out = {k: v for k, v in doc.items() if k not in ("threats", "findings")}
    channel = doc.get("channel")
    # scan_file's document lists every finding twice, under `threats` and `findings`.
    source = doc.get("findings") if doc.get("findings") is not None else doc.get("threats")
    listed, rest = _compact_findings(source, channel)
    out["findings"] = listed
    if rest:
        out["more_findings"] = rest
    return out


def _fit(doc, header=""):
    """Render the document, shrinking it until header + JSON are at most MAX_RESULT_BYTES."""
    def render():
        return header + json.dumps(doc, indent=2, default=str)
    text = render()
    if len(text.encode("utf-8")) <= MAX_RESULT_BYTES:
        return text
    doc = dict(doc)
    for key in ("warnings", "extraction_warnings"):
        if isinstance(doc.get(key), list) and len(doc[key]) > 5:
            doc[key] = doc[key][:5] + [f"\u2026 {len(doc[key]) - 5} more not shown"]
    findings = list(doc.get("findings") or [])
    dropped = {}
    while findings:
        text = render()
        if len(text.encode("utf-8")) <= MAX_RESULT_BYTES:
            break
        f = findings.pop()
        category = str(f.get("category"))
        dropped[category] = dropped.get(category, 0) + 1
        doc["findings"] = findings
        more = dict((doc.get("more_findings") or {}).get("by_category", {}))
        for c, n in dropped.items():
            more[c] = more.get(c, 0) + n
        doc["more_findings"] = {"count": sum(more.values()), "by_category": more}
    text = render()
    if len(text.encode("utf-8")) > MAX_RESULT_BYTES:
        doc = {k: doc[k] for k in ("decision", "severity", "channel", "threat_found", "inspection_complete",
                                   "is_clean", "truncated", "bytes_scanned", "more_findings") if k in doc}
        text = render()
    return text


def _tool_scan_text(arguments):
    """Execute scan_text tool."""
    channel = arguments.get("channel", "message")

    # v0.5.6: `if not text` collapsed two different situations into one
    # error. A MISSING `text` argument is a usage error -- the caller broke the
    # tool's API contract and nothing was submitted. An EMPTY STRING is content:
    # the caller submitted a document that happens to have no bytes in it, and the
    # honest answer is a clean, complete scan of 0 bytes -- which is also what the
    # CLI now says for `--text ""` and empty stdin, so the two surfaces agree.
    if "text" not in arguments:
        return {
            "content": [{"type": "text", "text": "Error: 'text' parameter is required."}],
            "isError": True,
        }
    text = arguments.get("text")
    if not isinstance(text, str):
        return {
            "content": [{"type": "text",
                         "text": "Error: 'text' parameter must be a string."}],
            "isError": True,
        }

    engine = _engine()
    budget, why = _call_time_limit()
    try:
        try:
            result = (engine.scan(text, channel=channel, time_limit=budget) if budget is not None
                      else engine.scan(text, channel=channel))
        except _time_limit.TimeLimitUnavailable as exc:
            why = str(exc)
            result = engine.scan(text, channel=channel)
    except ValueError as e:
        # Unknown channel fails CLOSED: an explicit error, never a clean PASS.
        return {
            "content": [{"type": "text", "text": f"Error: {e}"}],
            "isError": True,
        }
    # The JSON this door hands a model is the same result with a marker in place of a found secret: the server
    # has no option to print the full match, because nothing at the other end of this door is a person reading
    # their own terminal (see door_mask).
    result_dict = mask_document(result.to_dict())

    # Build a human-readable summary + JSON
    # threat_found, not is_clean: a truncated-but-findingless scan must not render
    # as "ALLOW — 0 threat(s) found", and must not render as PASS either.
    if not result.threat_found:
        if result.inspection_complete:
            if not result.bytes_scanned:
                summary = (f"PASS — 0 bytes inspected: the input was empty, so "
                           f"nothing was found because there was nothing to read "
                           f"({result.latency_ms}ms)")
            else:
                summary = f"PASS — No threats detected ({result.latency_ms}ms)"
        else:
            summary = (f"INCOMPLETE SCAN — no findings in the inspected scope "
                       f"({result.latency_ms}ms); {_coverage_detail(result)}. "
                       f"This is NOT a clean result.")
    else:
        _unfinished = _time_limit.ended_counts(list(getattr(result, "time_limit_ended", None) or []))
        summary = (
            f"{result.decision.upper()} — {len(_time_limit.threats_only(result.findings))} threat(s) found"
            + (f", {_unfinished}" if _unfinished else "")
            + f", severity: {result.severity} ({result.latency_ms}ms)"
        )
        secrets = secret_strings(result.findings)
        for i, f in enumerate(result.findings[:MAX_FINDINGS], 1):
            summary += f"\n  {i}. [{f['severity'].upper()}] {f['name']}"
            if f.get("matched_text"):
                # This result is read by a model and written to its logs: a secret leaves as its marker only.
                shown = shown_match(f, f["matched_text"], False, secrets)
                summary += f' — matched: "{shown[:MAX_SHOWN_CHARS]}"'
        if len(result.findings) > MAX_FINDINGS:
            summary += f"\n  … {len(result.findings) - MAX_FINDINGS} more findings, counted by category below"
        if not result.inspection_complete:
            # A finding does not cancel a coverage failure, and the agent reads
            # the FIRST LINE. This surface announced only "BLOCK — 5 threats" on
            # a truncated input, so the part that was never read vanished behind
            # the part that was. Same defect the CLI human threat screen had.
            if not _time_limit.threats_only(result.findings):
                summary = f"INCOMPLETE SCAN — {_coverage_detail(result)}.\n" + summary
            else:
                summary = (f"INCOMPLETE SCAN — {_coverage_detail(result)}, AND threats were found "
                           + ("in what was checked" if getattr(result, "time_limit_ended", None)
                              else "in the part that was") + ".\n" + summary)

    # Both branches now open with the same "INCOMPLETE SCAN" prefix that
    # `scan_file` uses. An agent keying on the first line should not have to
    # learn two vocabularies for one fact.

    summary += _time_limit_lines(result)
    output = _fit(_door_document(result_dict), header=f"{_off_note(why)}{summary}\n\n")

    return {
        "content": [{"type": "text", "text": output}],
        "isError": False,
    }


def _one_line(text):
    """A name in a notice must not start a line of its own: line breaks become spaces."""
    return " ".join(str(text).splitlines())


def _tool_scan_file(arguments):
    """Execute scan_file tool."""
    file_path = arguments.get("file_path", "")
    allow_deep = arguments.get("allow_deep", False)

    # The tool's own schema says string and boolean; a string "false" is truthy and must not
    # open the deep branch.
    if not isinstance(file_path, str):
        return {
            "content": [{"type": "text", "text": "Error: 'file_path' parameter must be a string."}],
            "isError": True,
        }
    if not isinstance(allow_deep, bool):
        return {
            "content": [{"type": "text", "text": "Error: 'allow_deep' parameter must be true or false."}],
            "isError": True,
        }

    if not file_path:
        return {
            "content": [{"type": "text", "text": "Error: 'file_path' parameter is required."}],
            "isError": True,
        }

    if not os.path.exists(file_path):
        return {
            "content": [{"type": "text", "text": f"Error: File not found: {json.dumps(file_path)}"}],
            "isError": True,
        }

    scanner = SunglassesScanner()
    budget, why = _call_time_limit()
    try:
        try:
            with scanner.engine.time_limit_scope(budget):
                result = scanner.scan_auto(file_path, allow_deep=allow_deep)
        except _time_limit.TimeLimitUnavailable as exc:
            why = str(exc)
            result = scanner.scan_auto(file_path, allow_deep=allow_deep)
    except UnreadableFile as exc:
        # An operational failure must surface as an error, not as a scan result.
        # Returning a "0 threats" document here would be the same lie the
        # exit-code repair removes from the CLI.
        return {
            "content": [{"type": "text", "text": f"Error: {_one_line(exc)} — NOT inspected. Nothing was scanned."}],
            "isError": True,
        }

    # An explicit error document from the library is an operational failure.
    if isinstance(result, dict) and result.get("error"):
        return {
            "content": [{"type": "text", "text": f"Error: {result['error']} — nothing was scanned."}],
            "isError": True,
        }

    # Everything past this point is a scan document, so it goes through the one
    # normalizer before an agent ever sees it. The deep branch used to hand back
    # `scan_audio`'s dependency-warning dict verbatim -- `file`, `warning`,
    # `scan_time_seconds` and NOT ONE of the three axes -- which this server then
    # published as a successful call with no incompleteness notice, because the
    # notice below keys off `inspection_complete is False` and the key was absent.
    # An absent axis is now false, not clean.
    from .result import normalize
    result = normalize(result, source=file_path)

    # A completed invocation over content we could not fully read is a SUCCESSFUL
    # tool call whose document says "incomplete, not clean". It is not isError --
    # nothing went wrong operationally -- but it must never read as a clean scan.
    # Prepending the notice matters: an agent reading the first line of this text
    # is the caller we are actually protecting.
    if isinstance(result, dict) and result.get("inspection_complete") is False:
        warnings = result.get("warnings") or []
        ended = list(result.get("time_limit_ended") or [])
        if ended:
            own = {_time_limit.time_limit_warning(e) for e in ended}
            others = [w for w in warnings if w not in own]
            reason = _time_limit.incomplete_detail(_one_line(others[0]) if others else "content was not fully inspected",
                                                    bool(others), ended)
            notice = (f"INCOMPLETE SCAN — {reason}. This is NOT a clean result; "
                      f"do not treat {json.dumps(file_path)} as inspected.\n"
                      + "".join(f"  ! {_time_limit.time_limit_warning(e)}\n" for e in ended) + "\n")
        else:
            reason = _one_line(warnings[0]) if warnings else "content was not fully inspected"
            notice = (f"INCOMPLETE SCAN — {reason} This is NOT a clean result; "
                      f"do not treat {json.dumps(file_path)} as inspected.\n\n")
    else:
        notice = ""

    # The same door rule as scan_text: a found secret leaves this server as its marker, never as the key.
    door = mask_document(result)
    output = _fit(_door_document(door), header=_off_note(why) + notice) if isinstance(door, dict) \
        else _off_note(why) + notice + json.dumps(door, indent=2, default=str)
    return {
        "content": [{"type": "text", "text": output}],
        "isError": False,
    }


def _tool_scanner_info(arguments):
    """Execute scanner_info tool."""
    engine = _engine()
    info = engine.info()
    output = json.dumps(info, indent=2)
    return {
        "content": [{"type": "text", "text": output}],
        "isError": False,
    }


# =========================================================================
# MCP stdio transport — JSON-RPC 2.0 over stdin/stdout
# =========================================================================

def handle_ping(params):
    """ping: the protocol asks for an empty result."""
    return {}


HANDLERS = {
    "initialize": handle_initialize,
    "ping": handle_ping,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
}

# Notifications that require no response
NOTIFICATION_METHODS = {"notifications/initialized", "notifications/cancelled"}


_EOF = object()

# One request is one line. The longest honest one is a scan_text call whose text is the 1 MB scan
# limit with every character escaped (six bytes each), so the cap is 8 MiB; a line past it is
# discarded in chunks (never held in memory) and answered with one error.
MAX_FRAME_BYTES = 8 * 1024 * 1024


class _FrameTooLarge(Exception):
    pass


def read_message():
    """Read the next JSON value from stdin (newline-delimited JSON).

    Returns `_EOF` when the client closed the stream and nothing else. A blank line
    is not a message and is skipped; a line that parses to `null` is a message (an
    invalid one), so neither of them ends the server.
    """
    while True:
        line = sys.stdin.readline(MAX_FRAME_BYTES + 1)
        if not line:
            return _EOF
        if len(line) > MAX_FRAME_BYTES and not line.endswith("\n"):
            while True:
                rest = sys.stdin.readline(1024 * 1024)
                if not rest or rest.endswith("\n"):
                    break
            raise _FrameTooLarge()
        line = line.strip()
        if line:
            return json.loads(line)


def write_message(msg):
    """Write a JSON-RPC message to stdout (newline-delimited JSON)."""
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _parse_args(argv):
    """Answer --help and --version before anything reads stdin.

    Before this fix main() never looked at argv, so `--help` started the server and
    read the operator's terminal as JSON-RPC. Any other argument is still
    ignored, as it always was, so a client config that passes one keeps working,
    but the server now says on stderr which ones it ignored.
    """
    parser = argparse.ArgumentParser(
        prog="python -m sunglasses.mcp",
        # A prefix such as --ver must not count as --version. Ignored arguments
        # start the server, and an abbreviation would turn one into an exit.
        allow_abbrev=False,
        description="Run the SUNGLASSES MCP server. It speaks JSON-RPC over stdio, "
                    "so an MCP client starts it and writes to its stdin. "
                    "Tools: scan_text, scan_file, scanner_info.",
    )
    parser.add_argument("--version", action="version", version=f"sunglasses-mcp {SERVER_VERSION}")
    return parser.parse_known_args(argv)


def main(argv=None):
    """Run the SUNGLASSES MCP server on stdio."""
    _, ignored = _parse_args(sys.argv[1:] if argv is None else argv)
    if ignored:
        sys.stderr.write(f"[sunglasses-mcp] Ignoring arguments: {' '.join(ignored)}\n")
    # Log to stderr so it doesn't interfere with the JSON-RPC protocol
    sys.stderr.write(f"[sunglasses-mcp] Starting SUNGLASSES MCP server v{SERVER_VERSION}\n")
    sys.stderr.flush()

    while True:
        # Reset for every message: the error reply in the handler below is addressed to
        # THIS message's id, so it must never see the id of the one before it.
        msg_id = None
        try:
            msg = read_message()
            if msg is _EOF:
                # EOF — client disconnected
                break

            # JSON-RPC 2.0 section 5.1: a message that is not an object (a batch array,
            # a number, a string, null) is an Invalid Request, answered once with id null.
            # MCP dropped batching in its 2025-06-18 revision, so an array is not served.
            if not isinstance(msg, dict):
                write_message(_make_error(None, -32600, "Invalid Request"))
                continue

            method = msg.get("method")
            msg_id = msg.get("id")
            params = msg.get("params", {})

            # Notifications (no id) — acknowledge silently
            if msg_id is None or method in NOTIFICATION_METHODS:
                continue

            handler = HANDLERS.get(method)
            if handler:
                result = handler(params)
                write_message(_make_response(msg_id, result))
            else:
                write_message(_make_error(msg_id, -32601, f"Method not found: {method}"))

        except json.JSONDecodeError as e:
            sys.stderr.write(f"[sunglasses-mcp] JSON decode error: {e}\n")
            sys.stderr.flush()
            # JSON-RPC 2.0 section 5.1: a frame that is not JSON is a Parse error, answered
            # once with id null (the id cannot be read).
            write_message(_make_error(None, -32700, "Parse error"))
        except _FrameTooLarge:
            write_message(_make_error(None, -32600, f"Invalid Request: a message is at most {MAX_FRAME_BYTES} bytes"))
        except KeyboardInterrupt:
            break
        except Exception as e:
            sys.stderr.write(f"[sunglasses-mcp] Error: {e}\n")
            sys.stderr.flush()
            if msg_id is not None:
                write_message(_make_error(msg_id, -32603, str(e)))

    sys.stderr.write("[sunglasses-mcp] Server stopped.\n")
    sys.stderr.flush()


if __name__ == "__main__":
    main()
