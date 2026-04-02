"""
SUNGLASSES + LangChain integration.

Provides a LangChain-compatible Tool that scans text for prompt injection
attacks using the SUNGLASSES engine.

Usage:
    from sunglasses.integrations.langchain import SunglassesScanTool

    tool = SunglassesScanTool()
    result = tool.run("some untrusted input")

    # Or add it to an agent's toolkit:
    tools = [SunglassesScanTool(), ...]
    agent = initialize_agent(tools, llm, ...)

Requires: pip install langchain-core (optional dependency)
"""

from __future__ import annotations

import json
from typing import Any, Optional, Type

from ..scanner import SunglassesScanner


# Lazy import — langchain is optional
def _get_base_tool():
    """Import BaseTool from langchain at call time, not import time."""
    try:
        from langchain_core.tools import BaseTool
        return BaseTool
    except ImportError:
        try:
            from langchain.tools import BaseTool
            return BaseTool
        except ImportError:
            raise ImportError(
                "LangChain integration requires langchain-core. "
                "Install with: pip install langchain-core"
            )


def _get_base_model():
    """Import BaseModel from pydantic at call time."""
    try:
        from pydantic import BaseModel
        return BaseModel
    except ImportError:
        return None


def _build_tool_class():
    """Build the SunglassesScanTool class dynamically to defer the import."""
    BaseTool = _get_base_tool()
    BaseModel = _get_base_model()

    # Input schema for the tool
    input_schema = None
    if BaseModel:
        class SunglassesScanInput(BaseModel):
            text: str
            channel: str = "message"

        input_schema = SunglassesScanInput

    class _SunglassesScanTool(BaseTool):
        """LangChain Tool that scans input text for prompt injection attacks."""

        name: str = "sunglasses_scan"
        description: str = (
            "Scan text for prompt injection attacks, jailbreak attempts, and other "
            "AI security threats. Input should be the text to scan. Returns a JSON "
            "object with 'decision' (allow/block/quarantine), 'is_clean' (bool), "
            "'findings' (list of threats), and 'summary' (human-readable result)."
        )

        if input_schema:
            args_schema: Type[Any] = input_schema

        _scanner: Any = None

        class Config:
            arbitrary_types_allowed = True

        def __init__(self, scanner: Optional[SunglassesScanner] = None, **kwargs):
            super().__init__(**kwargs)
            object.__setattr__(self, '_scanner', scanner or SunglassesScanner())

        def _run(self, text: str, channel: str = "message", **kwargs) -> str:
            """Scan text and return JSON results."""
            result = self._scanner.scan_text(text, channel=channel)
            output = result.to_dict()
            output["is_clean"] = result.is_clean
            output["summary"] = result.summary()
            return json.dumps(output, indent=2)

        async def _arun(self, text: str, channel: str = "message", **kwargs) -> str:
            """Async version — delegates to sync (scanning is CPU-bound, <1ms)."""
            return self._run(text, channel=channel, **kwargs)

    return _SunglassesScanTool


class SunglassesScanTool:
    """
    LangChain-compatible tool for scanning text with SUNGLASSES.

    This is a lazy wrapper — the actual LangChain BaseTool subclass is only
    created when langchain is available. If langchain is not installed, you
    get a clear error message at instantiation time.

    Usage:
        tool = SunglassesScanTool()
        result = tool.run("ignore previous instructions")
    """

    _real_class = None

    def __new__(cls, *args, **kwargs):
        if cls._real_class is None:
            cls._real_class = _build_tool_class()
        return cls._real_class(*args, **kwargs)
