#!/usr/bin/env python3
"""
SUNGLASSES MCP Server — Model Context Protocol server for AI agent security scanning.

Exposes SUNGLASSES as a tool that Claude Code (or any MCP client) can call.
Uses raw stdio JSON-RPC 2.0 — zero external dependencies beyond the sunglasses package.

Usage:
    python -m sunglasses.mcp

Register with Claude Code:
    claude mcp add sunglasses -- python -m sunglasses.mcp
"""

import json
import sys
import os

# Ensure the package is importable when run as a module
_pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

from sunglasses.engine import SunglassesEngine
from sunglasses.scanner import SunglassesScanner

# Protocol constants
JSONRPC = "2.0"
SERVER_NAME = "sunglasses"
SERVER_VERSION = "0.2.4"
PROTOCOL_VERSION = "2024-11-05"


def _make_response(id, result):
    return {"jsonrpc": JSONRPC, "id": id, "result": result}


def _make_error(id, code, message):
    return {"jsonrpc": JSONRPC, "id": id, "error": {"code": code, "message": message}}


def _make_notification(method, params=None):
    msg = {"jsonrpc": JSONRPC, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def handle_initialize(params):
    """Handle initialize request — return server capabilities."""
    return {
        "protocolVersion": PROTOCOL_VERSION,
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
                "description": (
                    "Scan text for prompt injection attacks, data exfiltration attempts, "
                    "credential leaks, and other AI agent security threats. "
                    "Returns a decision (allow/block/quarantine), severity, and detailed findings."
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
                            "description": "The input channel type. Affects which patterns are checked.",
                            "enum": ["message", "file", "api_response", "web_content", "log_memory"],
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


def _tool_scan_text(arguments):
    """Execute scan_text tool."""
    text = arguments.get("text", "")
    channel = arguments.get("channel", "message")

    if not text:
        return {
            "content": [{"type": "text", "text": "Error: 'text' parameter is required."}],
            "isError": True,
        }

    engine = SunglassesEngine()
    result = engine.scan(text, channel=channel)
    result_dict = result.to_dict()

    # Build a human-readable summary + JSON
    if result.is_clean:
        summary = f"PASS — No threats detected ({result.latency_ms}ms)"
    else:
        summary = (
            f"{result.decision.upper()} — {len(result.findings)} threat(s) found, "
            f"severity: {result.severity} ({result.latency_ms}ms)"
        )
        for i, f in enumerate(result.findings, 1):
            summary += f"\n  {i}. [{f['severity'].upper()}] {f['name']}"
            if f.get("matched_text"):
                summary += f' — matched: "{f["matched_text"]}"'

    output = f"{summary}\n\n{json.dumps(result_dict, indent=2)}"

    return {
        "content": [{"type": "text", "text": output}],
        "isError": False,
    }


def _tool_scan_file(arguments):
    """Execute scan_file tool."""
    file_path = arguments.get("file_path", "")
    allow_deep = arguments.get("allow_deep", False)

    if not file_path:
        return {
            "content": [{"type": "text", "text": "Error: 'file_path' parameter is required."}],
            "isError": True,
        }

    if not os.path.exists(file_path):
        return {
            "content": [{"type": "text", "text": f"Error: File not found: {file_path}"}],
            "isError": True,
        }

    scanner = SunglassesScanner()
    result = scanner.scan_auto(file_path, allow_deep=allow_deep)

    output = json.dumps(result, indent=2, default=str)
    return {
        "content": [{"type": "text", "text": output}],
        "isError": False,
    }


def _tool_scanner_info(arguments):
    """Execute scanner_info tool."""
    engine = SunglassesEngine()
    info = engine.info()
    output = json.dumps(info, indent=2)
    return {
        "content": [{"type": "text", "text": output}],
        "isError": False,
    }


# =========================================================================
# MCP stdio transport — JSON-RPC 2.0 over stdin/stdout
# =========================================================================

HANDLERS = {
    "initialize": handle_initialize,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
}

# Notifications that require no response
NOTIFICATION_METHODS = {"notifications/initialized", "notifications/cancelled"}


def read_message():
    """Read a JSON-RPC message from stdin (newline-delimited JSON)."""
    line = sys.stdin.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    return json.loads(line)


def write_message(msg):
    """Write a JSON-RPC message to stdout (newline-delimited JSON)."""
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main():
    """Run the SUNGLASSES MCP server on stdio."""
    # Log to stderr so it doesn't interfere with the JSON-RPC protocol
    sys.stderr.write(f"[sunglasses-mcp] Starting SUNGLASSES MCP server v{SERVER_VERSION}\n")
    sys.stderr.flush()

    while True:
        try:
            msg = read_message()
            if msg is None:
                # EOF — client disconnected
                break

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
