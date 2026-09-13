"""The instrumented client: what the model was ACTUALLY shown.

This is the layer the whole experiment's strength turns on. Every other receipt
says what SHOULD have reached the model. Only the transcript says what did, and
only if it is read as bytes and compared against what the proxy emitted.

Two modes, and the distinction is recorded in every receipt rather than assumed:

  OBSERVED  a real headless `claude -p` run; the receipt is the transcript's
            `tool_result` block, byte-compared to the proxy's emitted frame.
  REPLAY    a transcript saved by an earlier OBSERVED run, read from disk.

There is deliberately no third mode. An earlier draft of the design note had the
client INFER what the model saw from surrounding text when the transcript was
unavailable, and an inference recorded beside two byte-level receipts reads like
a third measurement while being an opinion.

SPENDING IS NOT MINE TO START. A live run costs real usage on AZ's account, and
`live=True` is refused unless the caller passes an explicit budget the run may
not exceed. The harness builds, validates and replays without ever calling a
model; firing it is a separate, deliberate act.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import time
import uuid


class SpendNotAuthorised(RuntimeError):
    """A live run was requested without an explicit call budget."""


class Mode:
    OBSERVED = "observed"
    REPLAY = "replay"


class Observation:
    """One scenario's view of what reached the model."""

    __slots__ = ("scenario_id", "variant", "mode", "run_id", "transcript_path",
                 "tool_result_bytes", "proxy_emitted_bytes", "identical",
                 "calls_made", "elapsed_ms", "note")

    def __init__(self, **fields):
        for slot in self.__slots__:
            setattr(self, slot, fields.get(slot))

    def as_record(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "variant": self.variant,
            "mode": self.mode,
            "run_id": self.run_id,
            "transcript_path": str(self.transcript_path) if self.transcript_path else None,
            "tool_result_len": len(self.tool_result_bytes or b""),
            "tool_result": (self.tool_result_bytes or b"").decode("latin-1"),
            "proxy_emitted_len": len(self.proxy_emitted_bytes or b""),
            "proxy_emitted": (self.proxy_emitted_bytes or b"").decode("latin-1"),
            "identical": self.identical,
            "calls_made": self.calls_made,
            "elapsed_ms": self.elapsed_ms,
            "note": self.note,
        }


class InstrumentedClient:
    def __init__(self, workdir, mode: str = Mode.REPLAY, live_call_budget: int = 0,
                 model: str | None = None, binary: str = "claude"):
        self.workdir = pathlib.Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.live_call_budget = live_call_budget
        self.model = model
        self.binary = binary
        self.calls_made = 0
        self.run_id = uuid.uuid4().hex[:12]
        if mode == Mode.OBSERVED and live_call_budget <= 0:
            raise SpendNotAuthorised(
                "an OBSERVED run spends real model usage on AZ's account. Pass "
                "live_call_budget=<n> explicitly. The harness builds, validates "
                "and replays without ever calling a model; firing it is a "
                "separate decision and it is not this code's to take.")

    # ── observed ────────────────────────────────────────────────────────────
    def run_live(self, scenario_id: str, variant: str, prompt: str,
                 mcp_config: pathlib.Path) -> Observation:
        if self.mode != Mode.OBSERVED:
            raise SpendNotAuthorised(
                f"this client is in {self.mode!r} mode and run_live would spend")
        if self.calls_made >= self.live_call_budget:
            raise SpendNotAuthorised(
                f"the live call budget of {self.live_call_budget} is used up "
                f"after {self.calls_made} calls; raise it deliberately or stop")
        if not shutil.which(self.binary):
            raise RuntimeError(f"{self.binary!r} is not on PATH")
        transcript = self.workdir / f"{scenario_id}.{variant}.transcript.jsonl"
        argv = [self.binary, "-p", prompt, "--output-format", "stream-json",
                "--verbose", "--mcp-config", str(mcp_config)]
        if self.model:
            argv += ["--model", self.model]
        started = time.perf_counter()
        proc = subprocess.run(argv, capture_output=True, cwd=self.workdir)
        elapsed_ms = (time.perf_counter() - started) * 1000
        self.calls_made += 1
        transcript.write_bytes(proc.stdout)
        return self._read(scenario_id, variant, transcript, Mode.OBSERVED,
                          elapsed_ms)

    # ── replay ──────────────────────────────────────────────────────────────
    def replay(self, scenario_id: str, variant: str,
               transcript: pathlib.Path) -> Observation:
        return self._read(scenario_id, variant, pathlib.Path(transcript),
                          Mode.REPLAY, None)

    def _read(self, scenario_id, variant, transcript, mode, elapsed_ms) -> Observation:
        raw = transcript.read_bytes() if transcript.exists() else b""
        block = extract_tool_result(raw)
        return Observation(
            scenario_id=scenario_id, variant=variant, mode=mode,
            run_id=self.run_id, transcript_path=transcript,
            tool_result_bytes=block, proxy_emitted_bytes=None, identical=None,
            calls_made=self.calls_made, elapsed_ms=elapsed_ms,
            note=None if block is not None else
            "no tool_result block in the transcript; this scenario observed nothing",
        )

    # ── the comparison that makes it evidence ───────────────────────────────
    @staticmethod
    def compare(observation: Observation, proxy_emitted: bytes) -> Observation:
        """Byte equality, never a rendered or re-serialised form.

        `json.loads(a) == json.loads(b)` would call a reordered or re-encoded
        result identical, and the whole question is what bytes arrived.
        """
        observation.proxy_emitted_bytes = proxy_emitted
        observation.identical = (observation.tool_result_bytes == proxy_emitted)
        return observation


def extract_tool_result(raw: bytes) -> bytes | None:
    """The `tool_result` content of the transcript, as BYTES.

    Line-delimited JSON, read one line at a time, so a line that does not parse
    costs that line and not the file. Returns None when there is no such block,
    which is a finding rather than an empty string: "the model was shown nothing"
    and "we could not tell" must not render the same.
    """
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        for block in _tool_result_blocks(event):
            content = block.get("content")
            if isinstance(content, str):
                return content.encode("utf-8", "surrogatepass")
            if content is not None:
                return json.dumps(content, sort_keys=True,
                                  separators=(",", ":")).encode()
    return None


def _tool_result_blocks(event):
    message = event.get("message") if isinstance(event, dict) else None
    content = (message or {}).get("content") if isinstance(message, dict) else None
    for block in content or []:
        if isinstance(block, dict) and block.get("type") == "tool_result":
            yield block
