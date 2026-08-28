"""
firewall.py — the v0.4 runtime firewall for AI agents (deterministic lane).

    "Even if detection misses, the agent still can't leak secrets, trust a
     changed tool descriptor, or act without an audit trail."
                                            (v0.4-A milestone sentence, Aug 7 2026)

SUNGLASSES up to v0.3 is a *detector*: it reads text and reports evidence. This
module is the first piece that is a *control*. It sits on a Claude Code
PreToolUse hook and answers one question per tool call: does this specific
action violate a fact we can prove?

THE ONE LOCKED RULE — the split this whole module is built to protect:

    Deterministic facts  → HARD BLOCK.
        A secret in an outbound payload. A tool descriptor whose hash changed
        under us. A rule the user wrote down themselves. These are checkable.
        Being wrong about them is a bug, not a judgement call.

    Fuzzy / intent signals → WARN, human-escalate. NEVER auto-block.
        "Does this action fit the task?" is the pattern engine's lane. It is
        probabilistic. Wiring probability to a hard deny is detection through
        the side door, and it is how a security tool becomes the thing that
        breaks the user's work.

The two lanes are kept physically apart in this file: everything above the
`# ── FUZZY LANE` banner is forbidden from importing or consulting the pattern
engine, and `tests/test_firewall_fp.py::test_no_fuzzy_in_deterministic_lane`
reads this file's own source to enforce that.

Design constraints (all load-bearing):
  * < 100ms, zero network calls. This runs on EVERY tool call. Local-first is
    the moat — nothing about the user's work leaves their machine.
  * Fail-open, but CONFESS. A crashed firewall must not brick the agent; it
    must also not silently vanish. Errors return `defer` (fall through to Claude
    Code's own permission flow) and write a receipt saying the firewall failed.
  * FP rate 0 on the clean corpus before this lane is allowed to deny anything.
    A guard that greps a bare pattern shoots healthy agents (Jul 22 2026).
"""

from __future__ import annotations

import hashlib
import re

# Import budget note: this module is on the hot path — it is imported once per
# tool call, so every import is paid thousands of times a day. `dataclasses`
# measured +6.6ms and `typing` +1.8ms of interpreter start on this Mac, which is
# ~8% of the 100ms budget spent on syntax sugar for two tiny classes. Hence the
# plain `__slots__` classes below and string-only annotations (`from __future__
# import annotations` means they are never evaluated). Keep new imports out of
# module scope; lazy-import inside the function that needs them.


# ── Decision ────────────────────────────────────────────────────────────────

class Decision:
    """One firewall verdict. `action` maps 1:1 onto the PreToolUse contract."""

    __slots__ = ("action", "lane", "rule_id", "reason")

    def __init__(self, action: str, lane: str, rule_id: str, reason: str):
        self.action = action      # "deny" | "ask" | "defer" | "allow"
        self.lane = lane          # "deterministic" | "fuzzy" | "error"
        self.rule_id = rule_id    # stable id, goes in the receipt
        self.reason = reason      # shown to user/agent — NEVER the material

    def __repr__(self):
        return f"Decision({self.action!r}, {self.lane!r}, {self.rule_id!r})"

    def __eq__(self, other):
        return isinstance(other, Decision) and all(
            getattr(self, f) == getattr(other, f) for f in self.__slots__)

    def to_hook_output(self) -> dict:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": self.action,
                "permissionDecisionReason": self.reason,
            }
        }


# ═════════════════════════════════════════════════════════════════════════════
# DETERMINISTIC LANE — hard block only. No pattern engine below this line.
# ═════════════════════════════════════════════════════════════════════════════

# ── Secret MATERIAL, by exact format ────────────────────────────────────────
# Every rule matches a credential's published *shape*. No entropy scoring, no
# "looks random enough" — that is a fuzzy judgement and it belongs to the WARN
# lane. If a provider's format is not precise enough to write down here, it does
# not get to block.

class SecretRule:
    """One credential format. Plain class for the same import-budget reason."""

    __slots__ = ("id", "name", "regex")

    def __init__(self, id: str, name: str, regex):
        self.id = id
        self.name = name
        self.regex = regex


SECRET_RULES: tuple = (
    SecretRule("GLS-FW-SEC-AWS", "AWS access key id",
               re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretRule("GLS-FW-SEC-GITHUB", "GitHub token",
               re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    SecretRule("GLS-FW-SEC-ANTHROPIC", "Anthropic API key",
               re.compile(r"\bsk-ant-[A-Za-z0-9]{2,}[A-Za-z0-9_\-]{20,}\b")),
    SecretRule("GLS-FW-SEC-OPENAI", "OpenAI API key",
               re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}\b")),
    SecretRule("GLS-FW-SEC-SLACK", "Slack token",
               re.compile(r"\bxox[baprse]-[A-Za-z0-9\-]{20,}\b")),
    SecretRule("GLS-FW-SEC-GOOGLE", "Google API key",
               re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    SecretRule("GLS-FW-SEC-STRIPE", "Stripe live secret key",
               re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    SecretRule("GLS-FW-SEC-PEM", "private key block",
               re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    # Bearer credentials: only when the token itself has a checkable format.
    # A bare long opaque string after "Bearer" is an entropy guess, so it is
    # deliberately NOT here — it goes to the fuzzy lane. Signed JWTs have a
    # literal structure (base64url header.payload.signature, header starts
    # `eyJ`), which is a format, so they qualify.
    SecretRule("GLS-FW-SEC-JWT", "signed JWT",
               re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
)

# ── Invisible-character normalization ───────────────────────────────────────
# A single U+200B inside `AKIA…` splits the token and defeats every rule above,
# while the credential still arrives usable at the far end — the attacker strips
# one character. Found Aug 12 2026 by an adversarial pass against the published
# 0.4.0 wheel, where all nine rules missed a key that was sitting in plain sight
# in the tool call.
#
# This is not entropy scoring and not fuzzy matching, so it does not weaken the
# "only block provable facts" rule: format characters (Unicode Cf) carry no
# meaning inside a credential, so removing them cannot change what a real key is
# — and cannot invent one, because every real credential format is a run of
# base62/base64url characters with no whitespace to bridge.
#
# Enumerated as a literal class rather than `unicodedata.category(c) == "Cf"`
# on purpose: it is auditable at a glance and costs no import on the hot path.
_INVISIBLE = re.compile(
    "[­​-‏‪-‮⁠-⁤⁦-⁩﻿]"
)


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi and other format characters. Length may shrink;
    nothing else about the text changes."""
    return _INVISIBLE.sub("", text) if text else text


# ── Placeholder guard ───────────────────────────────────────────────────────
# Docs, examples and *correct* credential handling all produce secret-SHAPED
# strings that carry no secret: `$TOKEN`, `<YOUR_KEY>`, `sk-ant-REPLACE_ME`.
# This is not entropy scoring — it is a literal check for characters and words
# that real credential material never contains (real keys are base62/base64url).
_PLACEHOLDER_CHARS = ("$", "<", ">", "{", "}", "(", ")", "%", "…")
_PLACEHOLDER_WORDS = (
    "example", "your", "placeholder", "redacted", "replace", "changeme",
    "dummy", "sample", "insert", "here", "todo", "fixme", "notreal",
    "xxxx", "abcdef", "123456", "aaaa", "0000",
)


def is_placeholder(token: str) -> bool:
    """True if this secret-shaped string is demonstrably not live material."""
    if any(c in token for c in _PLACEHOLDER_CHARS):
        return True
    low = token.lower()
    return any(word in low for word in _PLACEHOLDER_WORDS)


# ── Known public canaries ───────────────────────────────────────────────────
# Credential-format strings that are *published test fixtures* — they appear in
# vendor docs and in security tools' own READMEs, so an agent handling them is
# doing normal work, not leaking.
#
# This list is the ONLY sanctioned way to clear a clean-corpus false positive.
# The alternative — loosening a regex — silently opens a hole for every real
# key of that shape. Each entry is a full literal credential and is asserted to
# still match a rule, so a stale entry cannot rot into a wildcard.
# Note on what is NOT here: AWS's own docs key `AKIAIOSFODNN7EXAMPLE` needs no
# entry — the placeholder guard already clears it on the literal word EXAMPLE.
# Listing it anyway would be a dead entry that reads as coverage while proving
# nothing, so the canary test asserts every entry still matches a rule.
KNOWN_PUBLIC_CANARIES: frozenset = frozenset({
    # trufflehog's detector fixture, published verbatim in its README (and so
    # in our clean corpus). A revoked key Truffle Security uses to demo
    # detection — it carries no EXAMPLE marker, so only enumeration clears it.
    "AKIAYVP4CIPPERUVIFXG",
})


def find_secret_material(text: str) -> list:
    """Every credential-format string in `text` that is not a placeholder.

    Returns dicts: {rule_id, name, match}. Canary filtering is deliberately NOT
    applied here — callers that block apply it, while tests and receipts can
    still see the raw format hits.

    `match` is the credential with format characters removed, so a key smuggled
    with a zero-width character fingerprints identically to the same key sent
    plainly. Two receipts of one leak must correlate.
    """
    if not text:
        return []
    text = strip_invisible(text)
    hits = []
    seen = set()
    for rule in SECRET_RULES:
        for match in rule.regex.finditer(text):
            token = match.group(0)
            if token in seen or is_placeholder(token):
                continue
            seen.add(token)
            hits.append({"rule_id": rule.id, "name": rule.name, "match": token})
    return hits


# ── Egress surface ──────────────────────────────────────────────────────────
# Scanning a tool call that cannot send anything anywhere is pure false-positive
# surface with zero safety value: `Read`ing ~/.aws/credentials is not a leak,
# and blocking it is exactly the "shoots healthy agents" failure.

_NETWORK_BINARIES = frozenset({
    "curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp",
    "rsync", "ftp", "sftp", "socat", "http", "httpie", "xh",
    "aws", "gcloud", "az", "gh", "glab", "heroku", "fly", "wrangler",
    "twine", "npm", "yarn", "pnpm", "docker", "kubectl", "helm",
    "sendmail", "mail", "mailx", "openssl",
})
_WORD = re.compile(r"[A-Za-z0-9_\-]+")
_URL = re.compile(r"\bhttps?://", re.IGNORECASE)

# Native tools that reach the network by definition.
_EGRESS_TOOLS = frozenset({"WebFetch", "WebSearch"})


def is_egress_tool(tool_name: str, tool_input: dict) -> bool:
    """True if this call could put bytes on a wire.

    MCP tools count unconditionally: an MCP server is a separate process on the
    far side of a transport, so anything handed to one has already left the
    agent's trust boundary.
    """
    if not tool_name:
        return False
    if tool_name in _EGRESS_TOOLS or tool_name.startswith("mcp__"):
        return True
    if tool_name == "Bash":
        command = str((tool_input or {}).get("command", ""))
        if _URL.search(command):
            return True
        return any(w in _NETWORK_BINARIES for w in _WORD.findall(command))
    return False


def egress_surface_text(tool_name: str, tool_input: dict) -> str:
    """The text that would actually go out. Values only — keys are our own."""
    if not tool_input:
        return ""
    if tool_name == "Bash":
        return str(tool_input.get("command", ""))
    return "\n".join(str(v) for v in tool_input.values())


def _fingerprint(token: str) -> str:
    """Short SHA-256 prefix. Lets two receipts be correlated without either one
    carrying the secret — a receipt that echoes material IS the leak."""
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()[:12]


def check_egress_secrets(tool_name: str, tool_input: dict) -> "Decision | None":
    """HARD BLOCK if live credential material is heading out on this call.

    Returns None when there is nothing to say — the caller then continues to the
    other deterministic checks.
    """
    if not is_egress_tool(tool_name, tool_input):
        return None
    hits = [h for h in find_secret_material(egress_surface_text(tool_name, tool_input))
            if h["match"] not in KNOWN_PUBLIC_CANARIES]
    if not hits:
        return None
    first = hits[0]
    extra = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
    return Decision(
        action="deny",
        lane="deterministic",
        rule_id=first["rule_id"],
        reason=(
            f"SUNGLASSES firewall: blocked — {first['name']} material detected in an "
            f"outbound {tool_name} call{extra}. "
            f"Fingerprint sha256:{_fingerprint(first['match'])} (material withheld). "
            f"Pass credentials by environment variable or secret manager instead. "
            f"If this key is a published test fixture, add it to KNOWN_PUBLIC_CANARIES."
        ),
    )


# ── MCP tool-descriptor pinning ─────────────────────────────────────────────
# An MCP server can change a tool's description between calls. The agent reads
# that description as instructions, so a silent edit is a rug-pull: the tool the
# user approved on Monday is not the tool that runs on Tuesday. A hash either
# matches or it does not — that is a fact, so it may block.

class PolicyError(Exception):
    """User configuration we refuse to guess at.

    Raised, never swallowed: a pins/policy file that does not parse means a
    control the user believes is running is NOT running, and that has to be
    visible. Callers turn this into a `defer` plus a confession receipt.
    """


def descriptor_hash(descriptor) -> str:
    """SHA-256 over a canonical form of an MCP tool descriptor.

    Canonical = sorted keys, no insignificant whitespace, so reordering a JSON
    object is not reported as a change. Hashing the raw bytes would make the
    check cry wolf on every server restart and get itself turned off.
    """
    import json as _json
    canonical = _json.dumps(descriptor, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_pins(path) -> dict:
    """Read pins.json. Absent = empty. Corrupt = PolicyError (never 'trust all')."""
    import json as _json
    import pathlib
    p = pathlib.Path(path)
    if not p.exists():
        return {"tools": {}}
    try:
        data = _json.loads(p.read_text())
    except (ValueError, OSError) as exc:
        raise PolicyError(f"pins file at {p} is unreadable: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("tools", {}), dict):
        raise PolicyError(f"pins file at {p} has an unexpected shape")
    data.setdefault("tools", {})
    return data


def check_pin(tool_name: str, descriptor, pins: dict) -> "Decision | None":
    """Compare a live MCP tool descriptor against its recorded pin.

    Three outcomes:
      pinned + match     → None (nothing to say)
      pinned + mismatch  → deny. The approved tool changed underneath the user.
      not pinned         → ask (trust-on-first-use). Blocking every unseen tool
                           would make a fresh install unusable, and a safety
                           config that kills the mission gets uninstalled.
    """
    if not tool_name or not tool_name.startswith("mcp__") or descriptor is None:
        return None

    recorded = (pins or {}).get("tools", {}).get(tool_name)
    live = descriptor_hash(descriptor)

    if recorded is None:
        return Decision(
            action="ask",
            lane="deterministic",
            rule_id="GLS-FW-PIN-TOFU",
            reason=(
                f"SUNGLASSES firewall: '{tool_name}' has no recorded descriptor pin. "
                f"Approving pins it at sha256:{live[:12]}; later silent changes to this "
                f"tool's description will be blocked."
            ),
        )

    pinned = str(recorded.get("sha256", ""))
    if pinned == live:
        return None

    # The new descriptor is attacker-controllable text. Report hashes only —
    # quoting it back would turn this very block into an injection channel.
    return Decision(
        action="deny",
        lane="deterministic",
        rule_id="GLS-FW-PIN-MISMATCH",
        reason=(
            f"SUNGLASSES firewall: blocked — the descriptor for '{tool_name}' changed "
            f"since you pinned it (pinned sha256:{pinned[:12]}, now sha256:{live[:12]}). "
            f"The tool you approved is not the tool about to run. Review the server, then "
            f"re-run `sunglasses pin` to accept the new descriptor."
        ),
    )


def check_pin_by_name(tool_name: str, pins: dict) -> "Decision | None":
    """The hook-time pin check — deliberately weaker than `check_pin`.

    PreToolUse stdin does not carry the tool descriptor (verified against the
    live docs, Aug 7 2026), and fetching one means an MCP `tools/list`
    round-trip, which breaks both the <100ms and the zero-network rules. A
    timeboxed search of the on-disk `claude-cli-nodejs` cache found no durable
    descriptor store either — descriptors appeared in exactly one file across
    the whole cache, and only inside an error-path debug line. So at hook time
    the only fact available is *whether this tool is pinned at all*.

    That is a real blind spot: a descriptor swapped between two `sunglasses pin`
    runs is caught by `sunglasses pin --check`, not here. The code says so, the
    user-facing reason says so, and the receipt records `pin_source`. Overstating
    this would be the one thing worse than the gap itself.
    """
    if not tool_name or not tool_name.startswith("mcp__"):
        return None
    if tool_name in (pins or {}).get("tools", {}):
        return None
    return Decision(
        action="ask",
        lane="deterministic",
        rule_id="GLS-FW-PIN-TOFU",
        reason=(
            f"SUNGLASSES firewall: '{tool_name}' is not pinned — this is the first time "
            f"it has been seen. Run `sunglasses pin` to record its descriptor, then "
            f"`sunglasses pin --check` to detect if the server changes it later."
        ),
    )


# ── Drift state: what the out-of-band check found, enforced at hook time ────
# The hook cannot fetch a descriptor (no descriptor on stdin, and a `tools/list`
# round-trip is ~1,000x the measured hook budget: p50 0.37ms over 429 receipts,
# 2026-08-28). So detection happens out-of-band and leaves a verdict on disk;
# the hook only READS it. That split is what lets a drifted tool be DENIED
# without a single byte of network in the hot path.
#
# Why deny and not ask: measured on this machine 2026-08-28 — a hook `ask` for
# an unpinned MCP tool did not surface to the user at all under their permission
# mode; the call simply ran. An `ask` is advice the harness may decline to give.
# A deny is honored. A rug-pull verdict that resolves to advice is decoration.

PIN_STATE_MAX_AGE_S = 24 * 60 * 60


def load_pin_state(path) -> "dict | None":
    """Read pin_state.json. Absent = None (never checked). Corrupt = PolicyError.

    Absent is NOT an error and must not block: a fresh install has no state yet,
    and a firewall that denies every MCP tool on day one gets uninstalled before
    it ever catches anything.
    """
    import json as _json
    import pathlib as _pathlib
    p = _pathlib.Path(path)
    if not p.exists():
        return None
    try:
        data = _json.loads(p.read_text())
    except (ValueError, OSError) as exc:
        raise PolicyError(f"pin state at {p} is unreadable: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("drifted", {}), dict):
        raise PolicyError(f"pin state at {p} has an unexpected shape")
    data.setdefault("drifted", {})
    return data


def pin_state_age_s(state: dict, now=None) -> "float | None":
    """Seconds since the recorded check. None if unparseable — which callers must
    treat as 'unknown', never as 'fresh'."""
    import datetime as _dt
    stamp = (state or {}).get("checked_at")
    if not stamp:
        return None
    try:
        when = _dt.datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return None
    now = now or _dt.datetime.now(when.tzinfo)
    return (now - when).total_seconds()


def check_pin_drift(tool_name: str, state: dict) -> "Decision | None":
    """Deny a tool whose descriptor changed since it was pinned.

    Staleness deliberately does NOT block. An old state file means we do not
    know, and denying on 'we do not know' is how a control earns a reputation
    for crying wolf and gets switched off. Unknown is reported in the receipt
    (`pin_state_stale`), where an auditor can see it, and nowhere else.
    """
    if not tool_name or not tool_name.startswith("mcp__") or not state:
        return None
    entry = (state.get("drifted") or {}).get(tool_name)
    if not entry:
        return None
    # Hashes only. The changed descriptor is attacker-controlled prose; echoing
    # it into the user's terminal would turn this very block into the injection.
    pinned = str(entry.get("pinned", ""))[:12]
    now_hash = str(entry.get("now", ""))[:12]
    return Decision(
        action="deny",
        lane="deterministic",
        rule_id="GLS-FW-PIN-DRIFT",
        reason=(
            f"SUNGLASSES firewall: blocked — '{tool_name}' changed since you pinned it "
            f"(pinned sha256:{pinned}, now sha256:{now_hash}), found by "
            f"`sunglasses pin --check` at {state.get('checked_at', 'an earlier run')}. "
            f"The tool you approved is not the tool about to run. Review the server, "
            f"then re-run `sunglasses pin` to accept the new descriptor."
        ),
    )


def build_pin_state(previous: dict, current: dict, coverage=None) -> dict:
    """The on-disk verdict `pin --check` leaves for the hook to enforce.

    Records hashes and provenance only — same rule as pins.json, for the same
    reason (this file is shareable and descriptor text is server-controlled).
    """
    drift = diff_pins(previous, current)
    old = (previous or {}).get("tools", {})
    new = (current or {}).get("tools", {})
    return {
        "checked_at": _now_iso(),
        "drifted": {
            name: {"pinned": old[name].get("sha256", ""),
                   "now": new[name].get("sha256", "")}
            for name in drift["changed"]
        },
        "checked_tools": len(new),
        "coverage": coverage or (current or {}).get("coverage") or {},
    }


# ── Reading descriptors out-of-band (`sunglasses pin`) ──────────────────────
# This half runs from the terminal, not the hook, so it may take seconds and may
# talk to servers. Keeping it out of the hot path is what lets the hook stay at
# ~27ms and fully offline.

_MCP_TIMEOUT = 10


# A server that answered with nothing is not the same fact as a server that has
# no tools, and folding the two together is how a coverage hole hides. Every
# probe outcome gets a name (2026-08-28): `sunglasses pin` prints them, and the
# pin file records them so "we pinned 14 tools" can never again be read as
# "14 tools is the whole surface".
PROBE_OK = "ok"                                  # spoke MCP, got descriptors
PROBE_EMPTY = "empty"                            # spoke MCP, server has no tools
PROBE_UNREACHABLE = "unreachable"                # could not start / died / spoke nonsense
PROBE_TIMEOUT = "timeout"                        # started, never finished the exchange
PROBE_UNSUPPORTED = "unsupported_transport"      # not stdio — we cannot read it at all


def probe_server(server_name: str, config: dict, timeout: int = _MCP_TIMEOUT) -> dict:
    """Speak MCP over stdio to one server. Returns {status, tools, detail}.

    Never raises: `sunglasses pin` across a dozen servers must not die because
    one of them is broken. But it no longer LIES BY OMISSION either — the four
    ways of getting zero descriptors are four different facts, and the caller
    needs them apart:

      unsupported_transport  we cannot read this server AT ALL (http/sse). A
                             permanent coverage gap, not a transient miss.
      unreachable            the command would not start, or died mid-exchange.
      timeout                started, never answered inside `timeout`.
      empty                  answered honestly: this server exposes no tools.
      ok                     descriptors in hand.

    `detail` is drawn from a FIXED vocabulary — never server output and never an
    exception message. A descriptor is attacker-controllable text and this
    string gets printed to a terminal and written to a file the user may share.
    """
    import json as _json
    import os
    import subprocess
    import threading

    config = config or {}
    transport = config.get("type") or ("stdio" if config.get("command") else None)
    if transport != "stdio" or not config.get("command"):
        return {"status": PROBE_UNSUPPORTED, "tools": [],
                "detail": f"transport={transport or 'unknown'}; only stdio can be read"}

    env = dict(os.environ)
    env.update({str(k): str(v) for k, v in (config.get("env") or {}).items()})

    try:
        proc = subprocess.Popen(
            [config["command"], *(config.get("args") or [])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, env=env, cwd=config.get("cwd") or None,
        )
    except (OSError, ValueError):
        return {"status": PROBE_UNREACHABLE, "tools": [],
                "detail": "command could not be started"}

    result: list = []
    reached = {"initialize": False, "tools": False}

    def exchange():
        def send(message):
            proc.stdin.write(_json.dumps(message) + "\n")
            proc.stdin.flush()

        def await_id(wanted):
            while True:
                line = proc.stdout.readline()
                if not line:
                    return None
                try:
                    message = _json.loads(line)
                except ValueError:
                    continue  # servers log noise on stdout; skip, don't die
                if message.get("id") == wanted:
                    return message

        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "sunglasses", "version": "0.4"}}})
        if await_id(1) is None:
            return
        reached["initialize"] = True
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        response = await_id(2)
        if response:
            reached["tools"] = True
            result.extend((response.get("result") or {}).get("tools") or [])

    worker = threading.Thread(target=exchange, daemon=True)
    worker.start()
    worker.join(timeout)
    hung = worker.is_alive()

    try:
        proc.kill()
        proc.wait(timeout=2)
    except Exception:  # noqa: BLE001
        pass

    if hung:
        return {"status": PROBE_TIMEOUT, "tools": [],
                "detail": f"no answer within {timeout}s"}
    if not reached["tools"]:
        return {"status": PROBE_UNREACHABLE, "tools": [],
                "detail": ("server closed before answering tools/list"
                           if reached["initialize"] else
                           "server never completed the MCP handshake")}
    if not result:
        return {"status": PROBE_EMPTY, "tools": [], "detail": "server exposes no tools"}
    return {"status": PROBE_OK, "tools": result, "detail": ""}


def list_tools_stdio(server_name: str, config: dict, timeout: int = _MCP_TIMEOUT) -> list:
    """Descriptors only — the thin back-compat face of `probe_server`.

    Kept because callers that genuinely only want the list should not have to
    care about status. Anything reporting COVERAGE must use `probe_server`: a
    bare [] here is exactly the ambiguity that hid a dead server behind a clean
    'pinned successfully' for three weeks.
    """
    return probe_server(server_name, config, timeout)["tools"]


def default_config_paths(cwd=None) -> list:
    """Where MCP servers are declared: the user's global config, then the
    project's `.mcp.json`. Order matters — project entries win, matching how a
    developer expects a project-local override to behave."""
    import pathlib
    cwd = pathlib.Path(cwd or pathlib.Path.cwd())
    return [pathlib.Path.home() / ".claude.json", cwd / ".mcp.json"]


def _looks_like_server_map(data) -> bool:
    """A bare `{"<name>": {...}}` map of server configs, with no `mcpServers`
    wrapper. Plugins ship their `.mcp.json` in exactly that shape, which is why
    a wrapper-only reader found zero plugin servers while their tools were
    live in the session (measured 2026-08-28)."""
    if not isinstance(data, dict) or not data or "mcpServers" in data:
        return False
    return all(
        isinstance(cfg, dict) and ("command" in cfg or "type" in cfg or "url" in cfg)
        for cfg in data.values()
    )


def discover_mcp_servers(paths) -> dict:
    """Collect server declarations from config files. Unreadable files are
    skipped, not fatal: one malformed config must not hide every other server.

    Accepts BOTH shapes — `{"mcpServers": {...}}` and the bare `{"<name>": {...}}`
    that plugin `.mcp.json` files use. Requiring the wrapper was a silent
    coverage hole, not a validation win.
    """
    import json as _json
    import pathlib
    servers: dict = {}
    for path in paths:
        path = pathlib.Path(path)
        if not path.exists():
            continue
        try:
            data = _json.loads(path.read_text())
        except (ValueError, OSError):
            continue
        if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
            servers.update(data["mcpServers"])
        elif _looks_like_server_map(data):
            servers.update(data)
    return servers


def plugin_mcp_paths(installed_plugins_path=None) -> list:
    """Every installed plugin's `.mcp.json`, from the install manifest.

    Read from the manifest rather than globbing the plugin cache on purpose: the
    cache also holds marketplace checkouts that are NOT installed, and pinning a
    server the user does not actually run is noise that makes the coverage line
    lie in the other direction.
    """
    import json as _json
    import pathlib
    path = pathlib.Path(installed_plugins_path or
                        (pathlib.Path.home() / ".claude/plugins/installed_plugins.json"))
    if not path.exists():
        return []
    try:
        data = _json.loads(path.read_text())
    except (ValueError, OSError):
        return []
    out = []
    for plugin_id, entries in (data.get("plugins") or {}).items():
        plugin_name = str(plugin_id).split("@", 1)[0]
        for entry in entries if isinstance(entries, list) else []:
            install = (entry or {}).get("installPath")
            if not install:
                continue
            candidate = pathlib.Path(install) / ".mcp.json"
            if candidate.exists():
                out.append((plugin_name, candidate))
    return out


def discover_plugin_servers(installed_plugins_path=None) -> dict:
    """Plugin-declared MCP servers, keyed the way the HOOK will see them.

    The namespacing is the whole point. A plugin server's tools arrive at the
    hook as `mcp__plugin_<plugin>_<server>__<tool>` (verified against a live
    session, 2026-08-28). Pinning them under the bare server name would produce
    a pins file that looks healthy and matches NOTHING at hook time — coverage
    theatre, which is worse than the gap it appears to close.
    """
    servers: dict = {}
    for plugin_name, path in plugin_mcp_paths(installed_plugins_path):
        for name, config in discover_mcp_servers([path]).items():
            servers[f"plugin_{plugin_name}_{name}"] = config
    return servers


def build_pins(servers: dict, _lister=None) -> dict:
    """Connect to each server, hash every tool descriptor, return a pins dict.

    Stores hashes and provenance only — never the descriptor text. Two reasons:
    a description is server-controlled prose, so `pin --check` printing a diff
    would pipe attacker-chosen text into someone's terminal; and pins.json is a
    file users may reasonably share or commit, where `env` secrets and tool
    prose have no business being.
    """
    tools: dict = {}
    coverage: dict = {}
    for server_name, config in (servers or {}).items():
        if _lister is not None:                      # test seam: descriptors only
            descriptors = _lister(server_name, config)
            status = PROBE_OK if descriptors else PROBE_EMPTY
            detail = ""
        else:
            probe = probe_server(server_name, config)
            descriptors, status, detail = probe["tools"], probe["status"], probe["detail"]
        pinned = 0
        for descriptor in descriptors:
            name = descriptor.get("name")
            if not name:
                continue
            tools[f"mcp__{server_name}__{name}"] = {
                "sha256": descriptor_hash(descriptor),
                "server": server_name,
                "pinned_at": _now_iso(),
            }
            pinned += 1
        # Coverage is recorded even (especially) when it is zero. "We pinned 14
        # tools" is only meaningful next to "and these servers we could not read
        # at all" — without this line a dead server is indistinguishable from a
        # clean one, which is how graphify-brain sat unpinned and unnoticed.
        coverage[server_name] = {"status": status, "pinned": pinned, "detail": detail}
    return {"tools": tools, "coverage": coverage}


def diff_pins(before: dict, after: dict) -> dict:
    """What changed between two pin snapshots. This is where the rug-pull is
    actually caught in v0.4-A."""
    old = (before or {}).get("tools", {})
    new = (after or {}).get("tools", {})
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "changed": sorted(name for name in set(old) & set(new)
                          if old[name].get("sha256") != new[name].get("sha256")),
    }


# ── User-written policy ─────────────────────────────────────────────────────
# The user's own rules are deterministic facts by definition, so they may block.
#
# Parsed by hand rather than with PyYAML on purpose: this package declares zero
# runtime dependencies, and a security control should not import a parser it
# does not need. The schema is deliberately tiny and the parser is strict —
# anything it does not understand is an error, because a policy key we silently
# ignore is worse than no policy at all (the user thinks they are covered).

_POLICY_LIST_KEYS = ("allowed_hosts", "blocked_paths")


def parse_policy(text: str) -> dict:
    """Parse the documented flat subset: `key:` followed by `  - value` items.

    Raises PolicyError on anything outside the schema — including keys that are
    real-sounding but unenforced in this version (`max_spend_usd`), so nobody
    ends up protected only in their own head.
    """
    policy: dict = {}
    current = None
    for lineno, raw in enumerate((text or "").splitlines(), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("- "):
            if current is None:
                raise PolicyError(f"line {lineno}: list item outside any key")
            policy[current].append(line.lstrip()[2:].strip())
            continue
        if line[0].isspace():
            raise PolicyError(f"line {lineno}: unexpected indentation")
        if ":" not in line:
            raise PolicyError(f"line {lineno}: expected 'key:' or '- value'")
        key, _, inline = line.partition(":")
        key, inline = key.strip(), inline.strip()
        if key not in _POLICY_LIST_KEYS:
            raise PolicyError(
                f"line {lineno}: unknown policy key '{key}'. Supported: "
                f"{', '.join(_POLICY_LIST_KEYS)}. (Spend guards are not enforced in "
                f"v0.4 — accepting the key would imply protection that does not exist.)"
            )
        if inline:
            raise PolicyError(
                f"line {lineno}: '{key}' takes a list; write each entry on its own "
                f"'  - value' line"
            )
        policy[key] = []
        current = key
    return policy


def load_policy(path) -> dict:
    """Read policy.yaml. Absent = {} (blocks nothing). Malformed = PolicyError."""
    import pathlib
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    try:
        return parse_policy(p.read_text())
    except OSError as exc:
        raise PolicyError(f"policy file at {p} is unreadable: {exc}") from exc


# `$HOME` and `${HOME}` name the same directory `~` does, so a path rule that
# only understands the tilde is bypassed by typing the variable instead — the
# shell expands both, and the shape a rule is meant to stop does not care which
# spelling gets it there.
#
# Resolved by hand rather than with `os.path.expandvars` on purpose. Expanding
# every variable would let an unrelated (or attacker-set) env var silently
# rewrite what a policy rule covers, and the boundary check in `check_policy`
# is only meaningful if both sides expand the same narrow way. The negative
# lookahead is load-bearing: `$HOMEBREW_PREFIX` is not `$HOME`, and a guard
# that thinks it is starts shooting healthy commands.
_HOME_VAR = r"\$(?:\{HOME\}|HOME(?![A-Za-z0-9_]))"
_HOME_VAR_RE = re.compile("^" + _HOME_VAR)
_PATH_TOKEN_RE = re.compile("(?:" + _HOME_VAR + r"|[~/])[^\s'\"`;|&)>]*")


def _expand(path: str) -> str:
    import os
    path = _HOME_VAR_RE.sub(lambda _m: os.path.expanduser("~"), path, count=1)
    return os.path.normpath(os.path.expanduser(path))


def _referenced_paths(tool_name: str, tool_input: dict) -> list:
    """Path-shaped tokens in a tool call. Values only, never our own keys."""
    values = [str(v) for v in (tool_input or {}).values()]
    tokens: list = []
    for value in values:
        tokens.extend(_PATH_TOKEN_RE.findall(value))
    return tokens


def _hosts_in(tool_name: str, tool_input: dict) -> list:
    text = egress_surface_text(tool_name, tool_input)
    return [m.group(1).lower()
            for m in re.finditer(r"https?://([A-Za-z0-9._\-]+)", text or "")]


def check_policy(tool_name: str, tool_input: dict, policy: dict) -> "Decision | None":
    """Enforce the user's own written rules. Empty policy blocks nothing."""
    if not policy:
        return None

    for blocked in policy.get("blocked_paths") or []:
        target = _expand(blocked)
        for token in _referenced_paths(tool_name, tool_input):
            candidate = _expand(token)
            # Boundary-aware: `~/.ssh` covers `~/.ssh/id_rsa` but never
            # `~/.sshfs-cache`. Bare prefix matching turns a path rule into a
            # wildcard, which is how a guard starts shooting healthy agents.
            if candidate == target or candidate.startswith(target.rstrip("/") + "/"):
                return Decision(
                    action="deny",
                    lane="deterministic",
                    rule_id="GLS-FW-POL-PATH",
                    reason=(
                        f"SUNGLASSES firewall: blocked — your policy lists '{blocked}' under "
                        f"blocked_paths, and this {tool_name} call touches it. "
                        f"Edit ~/.sunglasses/policy.yaml to change this."
                    ),
                )

    allowed = policy.get("allowed_hosts") or []
    if allowed and is_egress_tool(tool_name, tool_input):
        allowed_set = {h.lower() for h in allowed}
        for host in _hosts_in(tool_name, tool_input):
            if host not in allowed_set:
                return Decision(
                    action="deny",
                    lane="deterministic",
                    rule_id="GLS-FW-POL-HOST",
                    reason=(
                        f"SUNGLASSES firewall: blocked — '{host}' is not in your "
                        f"allowed_hosts list. Add it to ~/.sunglasses/policy.yaml to allow it."
                    ),
                )
    return None


# ── Home, receipts, audit trail ─────────────────────────────────────────────
# "…or act without an audit trail" — the third clause of the milestone sentence.
# Append-only JSONL, one line per hook invocation, including the invocations
# where we decided nothing. A log that only records blocks cannot answer "was
# the firewall even running at 3am?", which is the question that actually gets
# asked after an incident.

def sunglasses_home():
    """`$SUNGLASSES_HOME` or `~/.sunglasses`. Overridable so tests (and CI, and
    anyone with an unusual HOME) never write to a real user's audit trail."""
    import os
    import pathlib
    return pathlib.Path(os.environ.get("SUNGLASSES_HOME") or
                        (pathlib.Path.home() / ".sunglasses"))


def _restrict(path, mode: int) -> None:
    """Best-effort `chmod` to owner-only. Repairs anything already on disk with
    looser bits, because the receipts written before this existed are exactly
    the ones a user would never think to go back and fix.

    Deliberately does not raise: a filesystem that cannot express these modes
    (a mounted share, a strange CI image) is a reason to keep auditing, not a
    reason for the firewall to start failing calls over its own logbook.
    """
    import contextlib
    import os
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, mode)


def write_receipt(record: dict, home=None) -> None:
    """Append one JSONL receipt. Raises on I/O failure — the caller decides
    whether a lost audit line is worth changing the decision over (it is not).

    Receipts are 0600 in a 0700 directory. They name which rule fired on which
    tool at what time; that is a map of what the user works on and where their
    secrets live, and a security product that leaves its own audit trail
    world-readable has quietly become the disclosure it was bought to prevent.
    """
    import datetime
    import json as _json
    import os
    home = home or sunglasses_home()
    directory = home / "receipts"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    _restrict(directory, 0o700)
    day = datetime.datetime.now().strftime("%Y-%m-%d")
    path = directory / f"{day}.jsonl"
    if not path.exists():
        # Created restrictively up front rather than chmod'd afterwards: a
        # chmod after the first write leaves a window where today's receipts
        # are readable by everyone on the box.
        os.close(os.open(str(path), os.O_CREAT | os.O_WRONLY, 0o600))
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(_json.dumps(record, ensure_ascii=False, default=str) + "\n")
    _restrict(path, 0o600)


def _input_digest(tool_input) -> str:
    """SHA-256 of the canonical tool input. The receipt stores this and never
    the input itself: an audit trail that quotes the payload becomes the leak."""
    import json as _json
    try:
        canonical = _json.dumps(tool_input, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        canonical = repr(tool_input)
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()


# ── Evaluation ──────────────────────────────────────────────────────────────

_CLEAN = Decision("defer", "deterministic", "GLS-FW-CLEAN",
                  "SUNGLASSES firewall: no deterministic violation.")


def evaluate(payload: dict, home=None) -> "tuple":
    """Run the deterministic lane over one PreToolUse payload.

    Returns (Decision, config_error_or_None, receipt_extras). Config problems
    are returned rather than raised so the caller can both fail open AND
    confess — and, critically, so a broken policy file cannot disarm the checks
    that need no configuration at all (the secret detector).
    """
    home = home or sunglasses_home()
    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}
    extras: dict = {}

    # Checks that need zero configuration run first and unconditionally.
    decision = check_egress_secrets(tool_name, tool_input)
    if decision is not None:
        return decision, None, extras

    # Config failures accumulate instead of returning early. A control that is
    # down has to reach the receipt even when some LATER check produced the
    # verdict — otherwise a corrupt policy.yaml plus a pin TOFU on the same call
    # yields a receipt that never mentions the dead policy control.
    errors = []

    def confession():
        return "; ".join(errors) if errors else None

    try:
        policy = load_policy(home / "policy.yaml")
    except PolicyError as exc:
        errors.append(str(exc))
    else:
        decision = check_policy(tool_name, tool_input, policy)
        if decision is not None:
            return decision, confession(), extras

    if tool_name.startswith("mcp__"):
        # `pin_file` is the only source available at hook time; recording it
        # keeps the blind spot visible to anyone auditing these receipts later,
        # instead of letting "no finding" read as "compared and matched".
        extras["pin_source"] = "pin_file"

        # Drift verdict FIRST. `pin --check` did the descriptor comparison
        # out-of-band and left the answer on disk; reading it costs one small
        # file read and upgrades this lane from "is it pinned at all" to a real
        # hash comparison — the blind spot the docstring above admits to.
        try:
            state = load_pin_state(home / "pin_state.json")
        except PolicyError as exc:
            errors.append(str(exc))
        else:
            if state:
                age = pin_state_age_s(state)
                extras["pin_source"] = "pin_state"
                extras["pin_checked_at"] = state.get("checked_at")
                extras["pin_state_age_s"] = None if age is None else round(age, 1)
                # Stale or unknown-age state is REPORTED, never enforced: we do
                # not know, and denying on not-knowing is how a control gets
                # turned off. The receipt carries the doubt instead.
                if age is None or age > PIN_STATE_MAX_AGE_S:
                    extras["pin_state_stale"] = True
                decision = check_pin_drift(tool_name, state)
                if decision is not None:
                    return decision, confession(), extras

        try:
            pins = load_pins(home / "pins.json")
        except PolicyError as exc:
            errors.append(str(exc))
        else:
            decision = check_pin_by_name(tool_name, pins)
            if decision is not None:
                return decision, confession(), extras

    if fuzzy_enabled(home):
        # Runs LAST and only on the way to "nothing found". Every deterministic
        # answer above outranks it, which keeps a probabilistic signal from ever
        # standing in front of a provable one.
        extras["fuzzy_lane"] = True
        decision = check_fuzzy(tool_name, tool_input)
        if decision is not None:
            if decision.action == "deny":  # pragma: no cover - belt and braces
                raise AssertionError("fuzzy lane produced a deny; that is forbidden")
            return decision, confession(), extras

    return _CLEAN, confession(), extras


def run_hook(stdin_text: str, home=None) -> dict:
    """stdin JSON → hook output dict. NEVER raises, NEVER exits non-zero.

    Every failure mode lands on `defer`: fall through to Claude Code's own
    permission flow. `defer` rather than `allow` is deliberate — a crashed
    firewall must not silently grant something the harness would otherwise have
    asked the user about.
    """
    import json as _json
    import time as _time

    home = home or sunglasses_home()
    started = _time.perf_counter()
    payload, decision, error, extras = {}, None, None, {}

    try:
        payload = _json.loads(stdin_text) if stdin_text.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError("hook payload was not a JSON object")
        decision, error, extras = evaluate(payload, home=home)
    except Exception as exc:  # noqa: BLE001 — fail-open is the whole point
        error = f"{type(exc).__name__}: {exc}"
        decision = Decision(
            "defer", "error", "GLS-FW-ERROR",
            "SUNGLASSES firewall: internal error, deferring to normal permission "
            "flow. This tool call was NOT checked. See ~/.sunglasses/receipts/.",
        )

    if error and decision.lane != "error":
        # A control was down while the rest of the lane worked. `lane` keeps
        # saying which lane actually decided — overloading it with "error" threw
        # that away — and `degraded` plus `error` carry the confession.
        extras = {**extras, "degraded": True}

    try:
        write_receipt({
            "ts": _now_iso(),
            "tool_name": payload.get("tool_name"),
            "session_id": payload.get("session_id"),
            "decision": decision.action,
            "lane": decision.lane,
            "rule_id": decision.rule_id,
            "input_sha256": _input_digest(payload.get("tool_input")),
            "elapsed_ms": round((_time.perf_counter() - started) * 1000, 2),
            **extras,
            **({"error": error} if error else {}),
        }, home=home)
    except Exception:  # noqa: BLE001
        # Losing an audit line must not change a security decision. The block
        # (or the defer) stands either way.
        pass

    return decision.to_hook_output()


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


# ── Installation (`sunglasses init`) ────────────────────────────────────────
# This edits a file the user already depends on. The rules are therefore about
# their data, not ours: never lose a key that was already there, back up before
# writing, refuse to touch a file we cannot parse, and leave nothing behind on
# uninstall.

# Every hook entry we own contains this string, which is how install stays
# idempotent and uninstall stays surgical. Matching on the module path (rather
# than storing a custom marker key) keeps the entry inside the documented hook
# schema — an unrecognised key would be ours to explain forever.
HOOK_MARKER = "sunglasses.firewall"

_HOOK_TIMEOUT = 10


def build_hook_entry(interpreter: str = None) -> dict:
    """The PreToolUse entry we write into settings.json.

    `interpreter` defaults to the ABSOLUTE `sys.executable` of whatever python is
    running `init`. Writing a bare `python3` would resolve through PATH at hook
    time, which under pipx/venv/conda can be a different interpreter with no
    `sunglasses` installed — the hook then fails on every call, invisibly, and
    the firewall is off while looking on.
    """
    import shlex
    import sys as _sys
    interpreter = interpreter or _sys.executable
    # Quoted because the command is run through a shell: an interpreter path
    # containing a space (`/Users/x/My Env/bin/python3` — ordinary for conda and
    # for anyone whose username has a space) would otherwise be split into two
    # words, breaking both the hook and its own self-test.
    interpreter = shlex.quote(interpreter)
    return {
        # Everything, not just egress tools: policy `blocked_paths` has to cover
        # Read/Edit as well, and the module filters in ~0.2ms anyway.
        "matcher": ".*",
        "hooks": [{
            "type": "command",
            "command": f"{interpreter} -m {HOOK_MARKER}",
            # The schema default is 600s. A hook that can hang for ten minutes
            # on every tool call is a worse outage than the attacks it prevents.
            "timeout": _HOOK_TIMEOUT,
        }],
    }


def self_test_hook(command: str) -> "tuple":
    """Spawn the exact command we are about to write and check it answers.

    Returns (ok, detail). This is the difference between finding a broken wire
    at install time and finding it at 3am — a misconfigured hook fails open, so
    without this check the failure mode is completely silent.
    """
    import json as _json
    import subprocess
    probe = _json.dumps({
        "session_id": "sunglasses-self-test",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo sunglasses-self-test"},
        "tool_use_id": "selftest",
    })
    try:
        proc = subprocess.run(command, shell=True, input=probe,
                              capture_output=True, text=True, timeout=30)
    except Exception as exc:  # noqa: BLE001
        return False, f"could not run the hook command: {exc}"
    if proc.returncode != 0:
        return False, f"exit code {proc.returncode}: {(proc.stderr or '').strip()[:300]}"
    try:
        data = _json.loads(proc.stdout)
        decision = data["hookSpecificOutput"]["permissionDecision"]
    except Exception:  # noqa: BLE001
        return False, f"did not return hook JSON: {(proc.stdout or '').strip()[:200]}"
    if decision not in {"allow", "deny", "ask", "defer"}:
        return False, f"unexpected permissionDecision: {decision!r}"
    return True, decision


def _read_settings(path):
    import json as _json
    import pathlib
    path = pathlib.Path(path)
    if not path.exists():
        return {}
    text = path.read_text()
    if not text.strip():
        return {}
    try:
        data = _json.loads(text)
    except ValueError as exc:
        # Refusing is the safe move: overwriting a config we could not parse
        # would destroy settings the user cannot get back.
        raise PolicyError(
            f"{path} is not valid JSON ({exc}). Refusing to modify it — fix the "
            f"file (or move it aside) and re-run.") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{path} does not contain a JSON object. Refusing to modify it.")
    return data


def _write_settings(path, data, backup=True):
    import datetime
    import json as _json
    import pathlib
    import shutil
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if backup and path.exists():
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(path, path.with_name(path.name + f".sunglasses-backup-{stamp}"))
    path.write_text(_json.dumps(data, indent=2) + "\n")


def _strip_our_hooks(pre_tool_use: list) -> list:
    """Drop our entries, keeping everyone else's untouched."""
    kept = []
    for entry in pre_tool_use:
        hooks = [h for h in (entry.get("hooks") or [])
                 if HOOK_MARKER not in str(h.get("command", ""))]
        if hooks:
            kept.append({**entry, "hooks": hooks})
        elif not entry.get("hooks"):
            kept.append(entry)  # someone else's entry we do not understand
    return kept


def install_hook(settings_path, interpreter: str = None) -> dict:
    """Add (or refresh) our PreToolUse hook. Idempotent, merging, backed up."""
    data = _read_settings(settings_path)
    hooks = data.setdefault("hooks", {})
    pre = hooks.get("PreToolUse") or []

    # Strip first, then append: a re-run after the user moved their venv must
    # FIX the stale interpreter, not add a second entry pointing at a dead one.
    pre = _strip_our_hooks(pre)
    pre.append(build_hook_entry(interpreter))
    hooks["PreToolUse"] = pre
    _write_settings(settings_path, data)
    return data


# ── Starter policy ──────────────────────────────────────────────────────────
# The gap this closes, measured Aug 12 2026 against the published 0.4.0 wheel:
# `cat ~/.ssh/id_rsa | curl -d @-` and `curl -d @~/.aws/credentials` — the shape
# a compromised agent is far likelier to take than pasting a key inline — are
# already blocked by `blocked_paths`, and were blocked by nothing, because the
# default policy is empty and nobody knew the file existed. The control was
# built, worked, and shipped switched off.
#
# The fix is a prompt, not a new default. "A fresh install blocks nothing you
# did not ask for" is a spec rule with a test holding it down
# (test_default_policy_blocks_nothing), and it is the right rule: a security
# tool that surprises you with a block gets uninstalled. So `sunglasses init`
# ASKS. Answering yes is the asking.
#
# On the path list: `~/.ssh` as a whole directory is deliberately NOT here.
# It would block `ssh-copy-id ~/.ssh/id_rsa.pub`, `cat ~/.ssh/known_hosts` and
# `~/.ssh/config` — ordinary work — and a rule that shoots healthy agents is the
# failure mode this project cares most about. The private key files are named
# individually instead; `check_policy`'s boundary matching then leaves
# `id_rsa.pub` alone, because it is neither equal to `~/.ssh/id_rsa` nor under
# `~/.ssh/id_rsa/`. `~/.aws` IS listed as a directory: no ordinary command names
# that path, so the blast radius is the attack and nothing else.
STARTER_POLICY_PATHS: tuple = (
    "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_dsa",
    "~/.aws", "~/.config/gcloud", "~/.kube/config", "~/.docker/config.json",
    "~/.netrc", "~/.npmrc", "~/.pypirc",
)

_POLICY_HEADER = """\
# SUNGLASSES policy — your rules, enforced as HARD BLOCKS.
# Written by `sunglasses init`. Edit or delete freely: an empty file (or no
# file at all) enforces nothing.
#
# blocked_paths — any tool call that touches one of these paths is denied.
#   Matching is boundary-aware: `~/.ssh/id_rsa` does NOT cover `id_rsa.pub`,
#   so `ssh-copy-id` and `known_hosts` keep working.
"""

_POLICY_HOSTS_TAIL = """
# allowed_hosts — when set, an outbound call to any host NOT listed is denied.
#   Off by default: an allow-list is only useful once you know your own list,
#   and a half-written one blocks your own work on day two.
# allowed_hosts:
#   - api.github.com
#   - pypi.org
"""


def starter_policy_text(enabled: bool = True) -> str:
    """The recommended policy file. `enabled=False` writes the same rules
    commented out — discoverable, enforcing nothing."""
    prefix = "" if enabled else "# "
    lines = [_POLICY_HEADER]
    if not enabled:
        lines.append("# Not enabled. Uncomment the lines below to turn these blocks on.\n")
    lines.append(f"{prefix}blocked_paths:\n")
    lines.extend(f"{prefix}  - {p}\n" for p in STARTER_POLICY_PATHS)
    lines.append(_POLICY_HOSTS_TAIL)
    return "".join(lines)


def write_starter_policy(home=None, enabled: bool = True):
    """Write `policy.yaml` if there is not one already.

    Returns the path written, or None if the user already has a policy — their
    file is theirs, and silently rewriting the one control they hand-tuned would
    be worse than the gap this closes.

    One exception (0.4.3): if the existing file is byte-identical to OUR OWN
    commented-out starter (a non-interactive first run), `enabled=True` may
    upgrade it in place. Before 0.4.3 that run printed "re-run with --policy"
    and the re-run then hit this exists-guard and changed nothing — a dead end.
    A file the user has edited in any way is still never touched.
    """
    home = home or sunglasses_home()
    path = home / "policy.yaml"
    if path.exists():
        is_our_untouched_disabled = (
            path.read_text(encoding="utf-8") == starter_policy_text(enabled=False))
        if enabled and is_our_untouched_disabled:
            path.write_text(starter_policy_text(enabled=True), encoding="utf-8")
            return path
        return None
    home.mkdir(parents=True, exist_ok=True)
    path.write_text(starter_policy_text(enabled), encoding="utf-8")
    return path


def uninstall_hook(settings_path) -> dict:
    """Remove our hook and any container we would otherwise leave behind."""
    import pathlib
    if not pathlib.Path(settings_path).exists():
        return {}
    data = _read_settings(settings_path)
    hooks = data.get("hooks")
    if not isinstance(hooks, dict) or "PreToolUse" not in hooks:
        return data

    remaining = _strip_our_hooks(hooks["PreToolUse"] or [])
    if remaining:
        hooks["PreToolUse"] = remaining
    else:
        # Leave no config litter: an empty PreToolUse array (or an empty hooks
        # object) we created ourselves should disappear with us.
        hooks.pop("PreToolUse")
        if not hooks:
            data.pop("hooks")
    _write_settings(settings_path, data)
    return data


def settings_path_for(scope_global: bool, cwd=None):
    import pathlib
    if scope_global:
        return pathlib.Path.home() / ".claude" / "settings.json"
    return pathlib.Path(cwd or pathlib.Path.cwd()) / ".claude" / "settings.json"


def main(argv=None) -> int:
    """`python3 -m sunglasses.firewall` — the PreToolUse hook entry point.

    Invoked as a module rather than through `sunglasses.cli` on purpose:
    importing cli.py measured 109ms on this Mac (it pulls in the engine,
    reporter, mailer and sarif at module scope), which is the entire latency
    budget spent before the first check runs. This path imports only stdlib
    plus this module: ~22ms cold.
    """
    import json as _json
    import sys as _sys
    try:
        stdin_text = _sys.stdin.read()
    except Exception:  # noqa: BLE001
        stdin_text = ""
    _sys.stdout.write(_json.dumps(run_hook(stdin_text)))
    return 0


# ── FUZZY LANE ──────────────────────────────────────────────────────────────
# Everything below may consult the pattern engine. NOTHING below may return
# action="deny" — not at critical severity, not ever. That is the locked rule,
# and `test_fuzzy_lane_never_denies_at_any_severity` holds it down.
#
# Why a detection this good still doesn't get to block: the engine answers "does
# this text look like an attack?", which is a probability. A hard deny on a
# probability is how a security tool becomes the thing that breaks the user's
# work — and the day it blocks something legitimate is the day it gets
# uninstalled, after which it protects nothing.
#
# It is also OFF by default. See `fuzzy_enabled()` for the measured reason.

_FUZZY_ENGINE = None


def fuzzy_enabled(home=None) -> bool:
    """Opt-in via `~/.sunglasses/warn-lane` (empty marker file).

    Default OFF, and that is a measurement, not a preference: the pattern engine
    is built to read *content* — documents, web pages, tool output — and a
    PreToolUse hook feeds it *commands*. Turning it on means an escalation
    prompt on ordinary work, and a prompt the user learns to dismiss is worse
    than no prompt at all. On by default would train people to click through.
    """
    home = home or sunglasses_home()
    return (home / "warn-lane").exists()


def check_fuzzy(tool_name: str, tool_input: dict) -> "Decision | None":
    """Pattern-engine pass. Escalates to the human; never decides for them."""
    global _FUZZY_ENGINE
    text = egress_surface_text(tool_name, tool_input)
    if not text:
        return None

    # Imported here, not at module scope: the deterministic path must never pay
    # for the pattern DB, and the hot-path import test enforces that.
    if _FUZZY_ENGINE is None:
        from .engine import SunglassesEngine
        _FUZZY_ENGINE = SunglassesEngine()

    result = _FUZZY_ENGINE.scan(text, channel="message")
    if result.is_clean:
        return None

    from .policy import decide_enforce
    # `decide_enforce` says "block" at high/critical. On THIS surface that
    # verdict is deliberately downgraded to "ask" — the mapping it was written
    # for is the model-input boundary, where blocking text is honest. Here we
    # would be blocking the user's own action on a guess.
    enforcement = decide_enforce(result.findings)
    worst = result.findings[0]
    return Decision(
        action="ask",
        lane="fuzzy",
        rule_id=worst.get("id", "GLS-FW-FUZZY"),
        reason=(
            f"SUNGLASSES firewall: pattern match — {worst.get('name', 'suspicious content')} "
            f"({worst.get('severity', 'unknown')}). This is a DETECTION, not a proven fact, "
            f"so it is your call, not the firewall's "
            f"(enforcement-surface mapping would have said '{enforcement}'). "
            f"Turn this lane off by deleting ~/.sunglasses/warn-lane."
        ),
    )


# ── Entry point ─────────────────────────────────────────────────────────────
# MUST stay the last statement in this file. Under `python3 -m`, the module body
# executes top-to-bottom, so anything defined BELOW this line does not exist yet
# when main() runs. Living mid-file, it made every name after it a NameError in
# the subprocess — invisible in-process, where the whole module is imported
# first. Caught Aug 7 2026 by the fail-open receipt, not by a test.

if __name__ == "__main__":  # pragma: no cover - exercised via subprocess tests
    raise SystemExit(main())
