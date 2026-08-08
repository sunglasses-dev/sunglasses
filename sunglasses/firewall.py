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
    """
    if not text:
        return []
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


def _expand(path: str) -> str:
    import os
    return os.path.normpath(os.path.expanduser(path))


def _referenced_paths(tool_name: str, tool_input: dict) -> list:
    """Path-shaped tokens in a tool call. Values only, never our own keys."""
    values = [str(v) for v in (tool_input or {}).values()]
    tokens: list = []
    for value in values:
        tokens.extend(re.findall(r"[~/][^\s'\"`;|&)>]*", value))
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


def write_receipt(record: dict, home=None) -> None:
    """Append one JSONL receipt. Raises on I/O failure — the caller decides
    whether a lost audit line is worth changing the decision over (it is not)."""
    import datetime
    import json as _json
    home = home or sunglasses_home()
    directory = home / "receipts"
    directory.mkdir(parents=True, exist_ok=True)
    day = datetime.datetime.now().strftime("%Y-%m-%d")
    with open(directory / f"{day}.jsonl", "a", encoding="utf-8") as handle:
        handle.write(_json.dumps(record, ensure_ascii=False, default=str) + "\n")


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

    Returns (Decision, config_error_or_None). Config problems are returned
    rather than raised so the caller can both fail open AND confess — and,
    critically, so a broken policy file cannot disarm the checks that need no
    configuration at all (the secret detector).
    """
    home = home or sunglasses_home()
    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}

    # Checks that need zero configuration run first and unconditionally.
    decision = check_egress_secrets(tool_name, tool_input)
    if decision is not None:
        return decision, None

    config_error = None
    try:
        policy = load_policy(home / "policy.yaml")
    except PolicyError as exc:
        policy, config_error = {}, str(exc)
    else:
        decision = check_policy(tool_name, tool_input, policy)
        if decision is not None:
            return decision, None

    # Descriptor pinning needs a live descriptor, which PreToolUse stdin does
    # not carry (verified against the docs at P0). Wired in P3 once the
    # provenance question is settled; deliberately not faked here.

    return _CLEAN, config_error


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
    payload, decision, error = {}, None, None

    try:
        payload = _json.loads(stdin_text) if stdin_text.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError("hook payload was not a JSON object")
        decision, error = evaluate(payload, home=home)
    except Exception as exc:  # noqa: BLE001 — fail-open is the whole point
        error = f"{type(exc).__name__}: {exc}"
        decision = Decision(
            "defer", "error", "GLS-FW-ERROR",
            "SUNGLASSES firewall: internal error, deferring to normal permission "
            "flow. This tool call was NOT checked. See ~/.sunglasses/receipts/.",
        )

    if error and decision.lane != "error":
        # A config problem while the rest of the lane worked. Keep the real
        # decision, but the receipt must record that a control was not running.
        decision = Decision(decision.action, "error", decision.rule_id, decision.reason)

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


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess tests
    raise SystemExit(main())


# ── FUZZY LANE ──────────────────────────────────────────────────────────────
# Everything below may consult the pattern engine. Nothing below may return
# action="deny". Wired in P5.
