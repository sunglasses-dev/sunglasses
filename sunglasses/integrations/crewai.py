"""
SUNGLASSES + CrewAI integration.

Provides a CrewAI-compatible tool that scans text for prompt injection
attacks using the SUNGLASSES engine.

Usage:
    from sunglasses.integrations.crewai import sunglasses_scan

    # Use directly:
    result = sunglasses_scan("some untrusted input")

    # Or assign to a CrewAI Agent:
    from crewai import Agent
    agent = Agent(
        role="Security Analyst",
        tools=[sunglasses_scan],
        ...
    )

Requires: pip install crewai (optional dependency)
"""

from __future__ import annotations

import json
from typing import Any, Optional

from ..scanner import SunglassesScanner

# Module-level scanner instance (shared, thread-safe for reads)
_default_scanner = None


def _get_scanner() -> SunglassesScanner:
    """Lazy-init the default scanner."""
    global _default_scanner
    if _default_scanner is None:
        _default_scanner = SunglassesScanner()
    return _default_scanner


def _scan_text(text: str, channel: str = "message") -> str:
    """
    Core scan function. Scans text for prompt injection and returns JSON.

    Args:
        text: The text to scan for threats.
        channel: Context channel — one of: message, file, api_response,
                 web_content, log_memory. Defaults to "message".

    Returns:
        JSON string with scan results including decision, findings, and summary.
    """
    scanner = _get_scanner()
    result = scanner.scan_text(text, channel=channel)
    output = result.to_dict()
    output["is_clean"] = result.is_clean
    output["summary"] = result.summary()
    return json.dumps(output, indent=2)


def _try_crewai_tool():
    """
    Try to create a CrewAI @tool-decorated function.

    CrewAI uses the @tool decorator from crewai.tools to register functions
    as agent tools. We try to apply it; if crewai is not installed, we fall
    back to a plain callable that still works standalone.
    """
    try:
        from crewai.tools import tool

        @tool("sunglasses_scan")
        def sunglasses_scan(text: str) -> str:
            """Scan text for prompt injection attacks, jailbreak attempts, and
            other AI security threats. Returns JSON with 'decision'
            (allow/block/quarantine), 'is_clean' (bool), 'findings' (list of
            detected threats), and 'summary' (human-readable one-liner)."""
            return _scan_text(text)

        return sunglasses_scan

    except ImportError:
        # CrewAI not installed — return a plain callable with matching interface
        return None


def _make_standalone():
    """Create a standalone callable with metadata that mimics a CrewAI tool."""

    def sunglasses_scan(text: str, channel: str = "message") -> str:
        """Scan text for prompt injection attacks, jailbreak attempts, and
        other AI security threats. Returns JSON with 'decision'
        (allow/block/quarantine), 'is_clean' (bool), 'findings' (list of
        detected threats), and 'summary' (human-readable one-liner).

        Works standalone or as a CrewAI tool (install crewai for full integration).
        """
        return _scan_text(text, channel=channel)

    sunglasses_scan.name = "sunglasses_scan"
    sunglasses_scan.description = (
        "Scan text for prompt injection attacks and AI security threats."
    )
    return sunglasses_scan


# Build the exported tool — uses CrewAI decorator if available, plain function otherwise
_crewai_tool = _try_crewai_tool()
sunglasses_scan = _crewai_tool if _crewai_tool is not None else _make_standalone()
