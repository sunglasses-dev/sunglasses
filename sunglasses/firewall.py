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
    must also not silently vanish. Errors return `defer` — on the wire an empty
    `{}`, the documented "no opinion" that falls through to Claude Code's own
    permission flow — and write a receipt saying the firewall failed.
  * FP rate 0 on the clean corpus before this lane is allowed to deny anything.
    A guard that greps a bare pattern shoots healthy agents (Jul 22 2026).
"""

from __future__ import annotations

import os as _os
import stat as _stat
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
        # `defer` is the firewall's internal name for "no opinion — fall through to
        # Claude Code's own permission flow". On the wire that is an EMPTY object,
        # not a permissionDecision. Claude Code documents allow / deny / ask only;
        # an unknown value is fine in an interactive session (it falls through to
        # the permission prompt or bypass mode) but a subagent or a headless
        # `claude -p` run has nowhere to defer to: the tool call is marked
        # deferred, never executes, and the turn ends with an empty result
        # (`terminal_reason: tool_deferred`). Found Sep 3 2026 after six days of
        # "server-side outage" that was this line. The receipt still records
        # `defer`, so the audit trail is unchanged; only the wire shape moved.
        if self.action == "defer":
            return {}
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

    __slots__ = ("id", "name", "regex", "prefixes")

    def __init__(self, id: str, name: str, regex, prefixes=()):
        self.id = id
        self.name = name
        self.regex = regex
        # The literal alternatives this format BEGINS with, written beside the
        # regex they come from. A prefix is part of the FORMAT only for the rule
        # that owns it: `ASIA` is AWS's grammar and plain material anywhere
        # else, which is the whole of ASTRA's R1a. Longest first, so `sk-proj-`
        # is consumed before `sk-`.
        self.prefixes = tuple(sorted(prefixes, key=len, reverse=True))


SECRET_RULES: tuple = (
    SecretRule("GLS-FW-SEC-AWS", "AWS access key id",
               re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
               prefixes=("AKIA", "ASIA")),
    SecretRule("GLS-FW-SEC-GITHUB", "GitHub token",
               re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
               prefixes=("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    SecretRule("GLS-FW-SEC-ANTHROPIC", "Anthropic API key",
               re.compile(r"\bsk-ant-[A-Za-z0-9]{2,}[A-Za-z0-9_\-]{20,}\b"),
               prefixes=("sk-ant-",)),
    SecretRule("GLS-FW-SEC-OPENAI", "OpenAI API key",
               re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}\b"),
               prefixes=("sk-proj-", "sk-svcacct-", "sk-")),
    SecretRule("GLS-FW-SEC-SLACK", "Slack token",
               re.compile(r"\bxox[baprse]-[A-Za-z0-9\-]{20,}\b"),
               prefixes=("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe-")),
    SecretRule("GLS-FW-SEC-GOOGLE", "Google API key",
               re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
               prefixes=("AIza",)),
    SecretRule("GLS-FW-SEC-STRIPE", "Stripe live secret key",
               re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
               prefixes=("sk_live_",)),
    SecretRule("GLS-FW-SEC-PEM", "private key block",
               re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    # Bearer credentials: only when the token itself has a checkable format.
    # A bare long opaque string after "Bearer" is an entropy guess, so it is
    # deliberately NOT here — it goes to the fuzzy lane. Signed JWTs have a
    # literal structure (base64url header.payload.signature, header starts
    # `eyJ`), which is a format, so they qualify.
    SecretRule("GLS-FW-SEC-JWT", "signed JWT",
               re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
               prefixes=("eyJ",)),
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

# The five entries above that are not words but TYPED FILLER: a run of one
# character, or the beginning of the alphabet or the digits. They are matched
# by their shape rather than by length, because `xxxx` and `xxxxxxxx` are the
# same thing to a reader and only one of them is in the tuple.
_MIN_FILLER = 4


def _segments(text: str):
    """The token split on everything that is not alphanumeric.

    `YOUR_KEY_HERE` is three segments; `AKIAHERE4CIPPERUVIFX` is one. That
    difference is the whole fix.

    CASE IS PRESERVED. The caller lowercases for WORD comparison and never for
    SHAPE comparison -- ASTRA's R1b: lowercasing the whole token first turns a
    case-sensitive alphabet into a run of one character, and `qQqQ...` is
    material that only looks like filler after the material has been destroyed.
    """
    out, current = [], []
    for char in text:
        if char.isalnum():
            current.append(char)
        elif current:
            out.append("".join(current))
            current = []
    if current:
        out.append("".join(current))
    return out


def _is_filler(segment: str) -> bool:
    """A run of one character, or a consecutive ascending run.

    The minimum length matters as much as the shapes. Without it a single
    character is trivially "a run of one character", so prefixing any key with
    `a_` would clear it — the substring defect wearing a different hat.

    Ascending means CONSECUTIVE, not "a prefix of the alphabet". The first
    version of this tested `"0123456789".startswith(segment)`, which quietly
    meant a digit run only counted if it started at zero: `12345678` was not
    filler. Anchoring a sequence at its start is the same mistake as anchoring
    a word at a substring — it decides on where the thing sits rather than on
    what it is.
    """
    if len(segment) < _MIN_FILLER:
        return False
    if len(set(segment)) == 1:
        return True
    if segment.isdigit() or segment.isalpha():
        codes = [ord(c) for c in segment]
        return all(b - a == 1 for a, b in zip(codes, codes[1:]))
    return False


# The leading literals, taken from THE RULES THEMSELVES rather than from a
# second list that can drift away from them. A prefix is format only for the
# rule that owns it; the union below is used only when no rule is in hand, and
# even then it is consumed ONCE, at the START of the token, never inside a
# segment further along. ASTRA's R1a is what the old global set allowed: the AWS
# temporary-credential prefix dropped into a GitHub token's BODY was discarded
# as "format", and the q-filler left behind cleared a live credential.
_FORMAT_PREFIX_LITERALS: tuple = tuple(sorted(
    {prefix.lower() for rule in SECRET_RULES for prefix in rule.prefixes},
    key=len, reverse=True))

# Words that DESCRIBE credential material without being any of it. `YOUR_KEY_HERE`
# is a placeholder and `key` is not a placeholder word, so without this the
# all-segments rule would refuse the most common placeholder there is. They are
# nouns a human writes around a secret, never the secret.
_STRUCTURAL_WORDS = frozenset({
    "key", "keys", "token", "secret", "api", "id", "my", "the", "value",
    "pass", "password", "credential", "credentials", "auth", "access", "code",
    # Pronouns a human writes around a secret: REPLACE_ME, PUT_IT_HERE.
    "me", "it", "this", "name", "user",
})


def _strip_leading_format(token: str, prefixes=None) -> str:
    """Remove ONE format literal from the FRONT of the token. Nothing else.

    Two properties, and the defect needed both of them missing:

    POSITION. Only at index 0. `AKIA...` and `AIza...` carry no separator, so
    the prefix and the body are one segment and the body cannot be judged until
    the literal comes off -- but a literal further along is something the SENDER
    put there, and the sender does not get to label their own material as
    format.

    ONCE. A second format literal immediately after the first is material too.
    Stripping repeatedly would hand back the same hole through a longer token.
    """
    low = token.lower()
    for prefix in (_FORMAT_PREFIX_LITERALS if prefixes is None else prefixes):
        prefix = prefix.lower()
        if low.startswith(prefix) and len(token) > len(prefix):
            return token[len(prefix):]
    return token


def is_placeholder(token: str, rule: "SecretRule | None" = None) -> bool:
    """True if this secret-shaped string is demonstrably not live material.

    STATE #54, and the rule took two passes to get right because the same
    mistake has two levels.

    FIRST it decided on a SUBSTRING: any token whose lowercase form contained
    one of the words above was "demonstrably not live". Six of those words are
    four characters (0000, aaaa, here, todo, xxxx, your) and a credential is
    base62, so a real AWS key id carrying `here` in its body was cleared and
    sent while the same shape without one was caught.

    THEN it decided on ANY SEGMENT, which is the identical decision one level
    up: a real token with separators carries a placeholder segment by accident
    exactly as that key carried `here`. A live Slack token whose numeric groups
    happen to run `1234-5678`, and a live Stripe key with a `here` segment in
    its body, were both cleared by the repair.

    The rule is the sentence that was written before either attempt and not
    followed: A PLACEHOLDER IS A TOKEN THAT IS ONE. So the judgement is on the
    whole secret material. Every segment outside the format's own literal
    prefix must be a placeholder word, typed filler, or a structural noun, AND
    at least one of them must actually be a placeholder or filler -- otherwise
    `my_api_token`, which is all structure and no claim, would clear.
    """
    if any(c in token for c in _PLACEHOLDER_CHARS):
        return True
    words = frozenset(_PLACEHOLDER_WORDS)

    # THE RULE THAT MATCHED decides what its own format is. Called without one
    # -- from a test, or from a caller holding a bare string -- the union is
    # used, still only at the front of the token. Either way exactly one
    # literal comes off and every remaining segment is material.
    material = _strip_leading_format(
        token, rule.prefixes if rule is not None else None)

    body = _segments(material)
    if not body:
        # Nothing but format. That is not a statement that the material is
        # fake, so it is not cleared.
        return False

    claimed = False
    for segment in body:
        # Words compare in lowercase; SHAPE is measured on the segment exactly
        # as it arrived. Mixing those two is R1b.
        low = segment.lower()
        if low in words or _is_filler(segment):
            claimed = True
        elif low not in _STRUCTURAL_WORDS:
            return False
    return claimed


# ── Known public canaries ───────────────────────────────────────────────────
# Credential-format strings that are *published test fixtures* — they appear in
# vendor docs and in security tools' own READMEs, so an agent handling them is
# doing normal work, not leaking.
#
# This list is the ONLY sanctioned way to clear a clean-corpus false positive.
# The alternative — loosening a regex — silently opens a hole for every real
# key of that shape. Each entry is a full literal credential and is asserted to
# still match a rule, so a stale entry cannot rot into a wildcard.
# STATE #54 changed what belongs here. This comment used to say AWS's own docs
# key `AKIAIOSFODNN7EXAMPLE` needed no entry because the placeholder guard
# cleared it "on the literal word EXAMPLE" — and that was true only while the
# guard decided on a SUBSTRING, which is the defect that guard just had. EXAMPLE
# is a suffix of that key, not a segment of it, so the repaired guard does not
# clear it and enumeration is now the only thing that can. The note is corrected
# rather than deleted: the reasoning it recorded is exactly what stopped being
# true.
KNOWN_PUBLIC_CANARIES: frozenset = frozenset({
    # trufflehog's detector fixture, published verbatim in its README (and so
    # in our clean corpus). A revoked key Truffle Security uses to demo
    # detection — it carries no EXAMPLE marker, so only enumeration clears it.
    "AKIAYVP4CIPPERUVIFXG",
    # AWS's canonical documentation example. Not a live key and never was. It
    # reached this list because the placeholder guard stopped matching EXAMPLE
    # inside a token (STATE #54); it is a published vendor fixture, which is
    # what this list is for, and the canary test asserts it still matches the
    # AWS rule so it cannot rot into a wildcard.
    #
    # Vendor:   Amazon Web Services
    # Document: Manage access keys for IAM users
    #           https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
    # Read:     2026-09-14 — the page publishes it as "an access key ID (for
    #           example, AKIAIOSFODNN7EXAMPLE)".
    # Re-read on ship day per SHIP_MANUAL: a changed document retires the entry
    # in the same ship.
    "AKIAIOSFODNN7EXAMPLE",
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

    # Every rule's every match, with its span, BEFORE anything is judged.
    # Formats overlap -- `sk-ant-` is also a `sk-` -- so which rule speaks for a
    # given span has to be settled before the guard is asked about it.
    found = []
    for rule in SECRET_RULES:
        for match in rule.regex.finditer(text):
            token = match.group(0)
            found.append((match.start(), match.end(), rule, token,
                          _leading_literal_length(rule, token)))

    owns = _span_owners(found)

    hits = []
    seen = set()
    cleared = set()
    for index, (start, end, rule, token, reach) in enumerate(found):
        if not owns[index]:
            # Somebody else's span. The owner's verdict is the span's verdict,
            # and it is recorded when the owner's own entry comes round.
            continue
        if token in seen or token in cleared:
            continue
        if is_placeholder(token, rule):
            # Judged ONCE per distinct token. A document repeating one cleared
            # token 16,000 times asked the guard 16,000 identical questions.
            cleared.add(token)
            continue
        seen.add(token)
        hits.append({"rule_id": rule.id, "name": rule.name, "match": token})
    return hits


def _span_owners(found: list) -> list:
    """Which occurrences speak for their span. One pass, not one scan each.

    THE FIRST VERSION OF THIS WAS A DENIAL OF SERVICE and ASTRA found it: it
    asked "does anything else contain me?" by walking the ENTIRE match list for
    EVERY occurrence. On a document carrying 16,000 credential-shaped tokens
    that is 256,000,000 comparisons, and the hook's 10-second deadline passed
    with no decision written -- a firewall that fails OPEN on a big input,
    which is worse than the false positive the ownership rule was added to fix.
    Measured before the repair: 1,000 occurrences 0.066 s, 2,000 0.251 s,
    4,000 1.003 s, 8,000 3.653 s, 16,000 never inside the deadline.

    Two observations make it linear in practice:

    IDENTICAL SPANS are the collision that actually happens -- two formats
    matching the same token -- so they are grouped and decided once, by the
    same longest-leading-literal rule.

    STRICT CONTAINMENT needs an ACTIVE SET, not a stack, and the stack was
    wrong: it assumed the intervals NEST, popping any entry whose end lay left
    of the current one's. Intervals from different rules CROSS. ASTRA's
    CROSS-ANTHROPIC-AWS is the shape -- an Anthropic match [0,49), a JWT match
    [10,91) that crosses it, and an AWS match [29,49) inside the Anthropic one.
    The JWT's farther-right end popped the Anthropic entry, so when the AWS
    match arrived its owner was gone and the receipt named AWS where ANTHROPIC
    belonged. Every such document still DENIED -- it is the equivalence
    promise that broke, not the block -- and eight of twenty-four crossing
    shapes reported the wrong rule.

    So: one entry per RULE, because one rule's own matches never overlap and
    the sweep visits them in order, and an entry expires only when it ends
    before the current span BEGINS -- which is the only point at which it can
    no longer contain anything still to come. The set is bounded by the number
    of rules, so this stays linear.
    """
    if not found:
        return []

    # One decision per distinct span.
    groups: dict = {}
    for index, (start, end, _rule, _token, reach) in enumerate(found):
        key = (start, end)
        current = groups.get(key)
        if current is None or reach > found[current][4]:
            groups[key] = index          # ties keep the earlier rule, which is
                                         # SECRET_RULES order, as before
    owns = [False] * len(found)
    winners = sorted(groups.values(), key=lambda i: (found[i][0], -found[i][1]))

    active: dict = {}                    # rule -> its one span that is still open
    for index in winners:
        start, end, rule, _token, reach = found[index]
        # EXPIRE ON START, NOT ON END. A span that ends before this one begins
        # cannot contain this one or anything after it, because every span from
        # here on starts at or after `start`. Expiring on a comparison with
        # `end` is what dropped a live container when a crossing span reached
        # farther right.
        for other_rule, other in list(active.items()):
            if found[other][1] < start:
                del active[other_rule]
        best = index
        for other_rule, other in active.items():
            if other_rule is rule:
                continue
            o_start, o_end, _or, _t, o_reach = found[other]
            if not (o_start <= start and end <= o_end):
                continue
            b_start, b_end, _r, _t2, b_reach = found[best]
            if (o_reach, o_end - o_start) > (b_reach, b_end - b_start):
                best = other
        owns[index] = best == index
        # One entry per rule: a rule's own matches never overlap, so a new one
        # starting means the previous one has already ended.
        active[rule] = index
    return owns


def _leading_literal_length(rule, token: str) -> int:
    """How many bytes of THIS token the rule's own format grammar accounts for."""
    low = token.lower()
    for prefix in rule.prefixes:
        if low.startswith(prefix.lower()):
            return len(prefix)
    return 0


def _owner_of_span(found: list, start: int, end: int, rule, reach: int):
    """Which rule speaks for this span. ASTRA's R3-1, ruling R-173-R4.

    `sk-ant-` + filler is a documented Anthropic placeholder AND a match for the
    broader OpenAI rule, which recognises three of those seven format bytes.
    The Anthropic rule cleared it; the OpenAI rule then read `ant` as material
    and DENIED -- a published placeholder refused by the firewall, which is the
    exact failure this file exists to prevent, arriving through a repair that
    made the guard MORE careful about material.

    The span belongs to the rule whose leading literal is the LONGEST match at
    the front, because that is the rule whose format actually describes the
    string. A rule matching a superset does not get to reinterpret the part of
    another format's literal that its own grammar never claimed.

    Only a span CONTAINED in the owner's is answered by the owner: a longer
    match reaching past it covers bytes the owner never saw, and suppressing
    that would hide material rather than resolve a collision.
    """
    best, best_reach, best_len = rule, reach, end - start
    for other_start, other_end, other_rule, _token, other_reach in found:
        if other_rule is rule:
            continue
        if not (other_start <= start and end <= other_end):
            continue
        length = other_end - other_start
        if (other_reach, length) > (best_reach, best_len):
            best, best_reach, best_len = other_rule, other_reach, length
    return best


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


def egress_secret_hits(tool_name: str, tool_input: dict) -> tuple:
    """(blocking hits, cleared canaries) for one call. Neither list is a
    decision; `check_egress_secrets` turns the first into one and `evaluate`
    puts the second in the receipt.

    THE SECOND LIST EXISTS BECAUSE OF ASTRA'S C01. KNOWN_PUBLIC_CANARIES is the
    only sanctioned way to clear a real format match, and it was also the only
    event in this lane that left no trace: the raw hit was found, dropped here,
    and the call ended on an ordinary clean decision. An exemption nobody can
    see in the receipts is an exemption nobody can audit, and this list is
    short and hand-maintained precisely so that each use of it is reviewable.

    The cleared entry carries the rule and a FINGERPRINT, never the material.
    The published fixtures in that set are public by definition, but a receipt
    that prints credential material is a habit, not a special case, and the
    habit is what leaks the next one.
    """
    if not is_egress_tool(tool_name, tool_input):
        return [], []
    hits, cleared = [], []
    for hit in find_secret_material(egress_surface_text(tool_name, tool_input)):
        if hit["match"] in KNOWN_PUBLIC_CANARIES:
            cleared.append({
                "rule_id": hit["rule_id"],
                "name": hit["name"],
                "fingerprint": f"sha256:{_fingerprint(hit['match'])}",
                "reason": ("cleared by KNOWN_PUBLIC_CANARIES: a published vendor "
                           "or tool fixture, exempted by enumeration and never "
                           "by loosening a rule"),
            })
        else:
            hits.append(hit)
    return hits, cleared


def check_egress_secrets(tool_name: str, tool_input: dict) -> "Decision | None":
    """HARD BLOCK if live credential material is heading out on this call.

    Returns None when there is nothing to say — the caller then continues to the
    other deterministic checks.
    """
    hits, _cleared = egress_secret_hits(tool_name, tool_input)
    return _deny_for_hits(hits, tool_name)


def _deny_for_hits(hits: list, tool_name: str) -> "Decision | None":
    """The block, built from hits that were already found. Separate so that
    `evaluate` does not scan the same call twice to get a decision it can
    already see the inputs for."""
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


def _stat_or_absent(path):
    """`os.stat(path)`, or None when nothing is there (ENOENT). Every other
    OSError reaches the caller.

    STAT FIRST, never `Path.exists()`. `exists()` answers False for more than a
    missing file: a symlink loop and a parent that is a file on every version,
    and a directory the hook cannot search on 3.14 (on 3.11 to 3.13 that one
    raised PermissionError out of the loader instead, and the hook caught it and
    deferred the call to the normal permission flow unchecked). Each loader read
    False as "never installed" and the control went off with nothing on screen
    (T9 ruling 59, Q4).
    """
    try:
        return _os.stat(path)
    except FileNotFoundError:
        return None


def load_pins(path) -> dict:
    """Read pins.json. Absent = empty. Corrupt or unreadable = PolicyError
    (never 'trust all')."""
    import json as _json
    import pathlib
    p = pathlib.Path(path)
    try:
        if _stat_or_absent(p) is None:
            return {"tools": {}}
    except OSError as exc:
        raise PolicyError(f"pins file at {p} is unreadable: {exc}") from exc
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


def pin_reach(tool_name: str, pins: dict) -> str:
    """What the hook can honestly say about a tool's pin status.

    "pinned"       — its descriptor hash is on file.
    "unpinned"     — its server was read by `sunglasses pin` (coverage status ok) but this
                     tool is not on file: a new or renamed tool on a pinnable server.
    "unpinnable"   — `sunglasses pin` has run on this machine (coverage exists) and this
                     server is not in it, or was recorded as unreachable / unsupported
                     transport. Nothing can be hashed, so nothing can be approved.
    "never_pinned" — no coverage at all: `sunglasses pin` has never run here.
    """
    pins = pins or {}
    if tool_name in pins.get("tools", {}):
        return "pinned"
    coverage = pins.get("coverage") or {}
    if not isinstance(coverage, dict) or not coverage:
        return "never_pinned"
    parts = tool_name.split("__")
    server = parts[1] if len(parts) >= 3 else ""
    entry = coverage.get(server)
    if isinstance(entry, dict) and entry.get("status") == "ok":
        return "unpinned"
    return "unpinnable"


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
    if pin_reach(tool_name, pins) == "unpinnable":
        # An ask must be answerable. `sunglasses pin` already probed this machine and
        # could not read this server (browser extension, hosted connector, HTTP/SSE
        # transport, or down), so approving would pin nothing and the same prompt
        # would come back on the very next call — which is exactly what happened to
        # Claude in Chrome users: a permission prompt on every browser action, even in
        # bypass mode, forever. No fact to check means no opinion here; the receipt
        # records `pin_reach: unpinnable` so the blind spot stays visible.
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
    try:
        if _stat_or_absent(p) is None:
            return None
    except OSError as exc:
        raise PolicyError(f"pin state at {p} is unreadable: {exc}") from exc
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


# RED 4 — THE CONTROL IS DOWN AND THE CALL STILL WENT THROUGH.
#
# Every one of these states used to end the same way: the policy lane produced no
# opinion, the hook emitted `{}`, and the call fell through to the normal
# permission flow with nothing on screen to say the control was dead. `{}` is
# indistinguishable from "this call is fine", which is the whole problem: a
# firewall that is quietly off looks exactly like a firewall that looked and
# found nothing.
#
# A dead control now ASKS, and the question names which control died. Asking is
# deliberately annoying. It is supposed to be: the fix is to repair the policy,
# not to learn to click through.
#
# `missing` needs care, and the first draft of it was wrong. "The home directory
# exists" is NOT evidence that a policy was ever installed: `write_receipt`
# creates that directory itself on the first call, so a fresh machine that never
# ran `sunglasses init` would have asked on every call, forever. That is the
# cry-wolf failure this file warns about elsewhere, and it would have been
# shipped as a security feature.
#
# So a missing policy is only a DEAD control when something positively says one
# was installed: the marker `sunglasses init` writes next to it. No marker means
# the firewall was never configured, which is the old silent behaviour and the
# correct one. Installs that predate the marker gain it on their next `init`.
INSTALL_MARKER = "installed"
POLICY_STATES = {
    "missing":     "the policy file is gone",
    "unreadable":  "the policy file cannot be read",
    "empty":       "the policy file is empty",
    "corrupt":     "the policy file does not parse",
    "wrong_type":  "the policy file is not a mapping",
}


class PolicyDown(Exception):
    """A named policy failure state. `state` is one of POLICY_STATES."""

    def __init__(self, state: str, detail: str = ""):
        self.state = state
        self.detail = detail
        super().__init__(f"{POLICY_STATES.get(state, state)}{': ' + detail if detail else ''}")


def _describe_node(mode) -> str:
    """What kind of thing is at that path, for the message the user reads."""
    if _stat.S_ISFIFO(mode):
        return "a FIFO"
    if _stat.S_ISSOCK(mode):
        return "a socket"
    if _stat.S_ISDIR(mode):
        return "a directory"
    if _stat.S_ISCHR(mode) or _stat.S_ISBLK(mode):
        return "a device"
    return "not a regular file"


def load_policy(path) -> dict:
    """Read policy.yaml, or raise PolicyDown naming the state it is in.

    Returns `{}` only for the one honest empty case: no home directory, meaning
    nothing was ever installed.
    """
    import pathlib
    p = pathlib.Path(path)
    # STAT BEFORE READ, and before deciding the file is absent: only ENOENT is
    # absent (see `_stat_or_absent`). A FIFO with no writer blocks in the
    # kernel, so the hook sat past the harness's 10 second timeout with no
    # stdout and no receipt, and a timed-out hook FAILS OPEN. A socket, a device
    # node or a directory in that path is the same class: not a thing we can
    # read, and answering that from metadata costs nothing and cannot block.
    try:
        st = _stat_or_absent(p)
        if st is None:
            marker = p.parent / INSTALL_MARKER
            if _stat_or_absent(marker) is not None:
                raise PolicyDown("missing", str(p))
            return {}
    except OSError as exc:
        raise PolicyDown("unreadable", f"{exc} ({p})") from exc
    if not _stat.S_ISREG(st.st_mode):
        raise PolicyDown(
            "unreadable", f"not a regular file ({_describe_node(st.st_mode)}) ({p})")

    try:
        data = p.read_bytes()
    except OSError as exc:
        raise PolicyDown("unreadable", f"{exc} ({p})") from exc

    # A NUL anywhere in the file means it was not written by a person editing a
    # policy. YAML accepts one inside a value and keeps it, so
    # `- ~/.ssh/id_rsa\x00` parsed cleanly, never matched the path it names, and
    # the call came back CLEAN in 30 ms with no policy_state and no confession.
    # A silent no-match is the worst possible answer from a control: it looks
    # exactly like "checked, nothing found". Checked on the BYTES, before YAML
    # sees them, because by then the NUL is already inside a value.
    if b"\x00" in data:
        raise PolicyDown("corrupt", f"NUL byte in the policy file ({p})")

    try:
        raw = data.decode("utf-8")
    # A policy whose BYTES do not decode is unreadable in exactly the sense F3
    # means, but decoding raises UnicodeDecodeError, which is a ValueError and
    # NOT an OSError. It used to escape the clause below and leave the
    # named-failure lane entirely: the caller returned `{}` with no stated
    # failure state, and the same exception took the later pin TOFU decision
    # down with it. Two junk bytes at the end of the file were enough.
    except UnicodeError as exc:
        raise PolicyDown("unreadable", f"{exc} ({p})") from exc
    if not raw.strip():
        raise PolicyDown("empty", str(p))
    try:
        parsed = parse_policy(raw)
    except PolicyError as exc:
        raise PolicyDown("corrupt", f"{exc} ({p})") from exc
    except OSError as exc:
        raise PolicyDown("unreadable", f"{exc} ({p})") from exc
    if not isinstance(parsed, dict):
        raise PolicyDown("wrong_type", f"parsed as {type(parsed).__name__} ({p})")
    return parsed


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


# -- Action surface ---------------------------------------------------------
# A policy `blocked_paths` rule answers "does this call TOUCH that path?". That
# is not the same question as "does this text MENTION that path?", and until
# 2026-09-10 this lane could not tell them apart: it scanned every value of the
# tool input, so writing documentation that NAMES a protected path was denied
# exactly like writing TO it. Three agents hit it inside ten minutes on 09-10;
# the class was first recorded on 08-28 and went unfixed for thirteen days.
# This change fixes the FILE-TOOL half of that class. The Bash half stays open,
# deliberately, for the reason recorded above `_action_surface`.
#
# Telling the two apart is the same distinction the scanner lane already makes
# -- a blog post that discusses a dangerous install command is not a finding --
# so the firewall lane now makes it too, per FIELD rather than per tool:
#
#   Write / Edit / MultiEdit / NotebookEdit / Read  -> the path fields only.
#       `content`, `new_string` and friends are DATA: the thing being written,
#       not a thing being touched.
#   Bash and anything else -> every value, unchanged. A tool whose grammar we
#       cannot parse is a tool we cannot narrow safely, so it keeps the old
#       behaviour and fails closed. See the note above `_action_surface` for
#       why Bash is on this side of the line and what that still costs.
#
# This never widens what is scanned; it only stops prose being read as action.
# `egress_surface_text` is deliberately NOT reused: for the secrets lane the
# content going out IS the leak, so scanning every value is right there and
# wrong here. One helper for both would re-merge the two questions.

# Per tool: the fields that name a TARGET, and the full documented input
# schema. Both halves are load-bearing. The first says what to look at; the
# second says when we are entitled to look at only that. A call carrying a key
# this schema does not list is not the call we documented, so it is judged on
# all of its values instead -- the same rule Bash lives under. That direction
# is deliberate: a schema that grows upstream re-opens a false positive, which
# is recoverable, rather than opening a hole, which is not.
_PATH_FIELDS = {
    "Write": ("file_path",),
    "Edit": ("file_path",),
    "MultiEdit": ("file_path",),
    "NotebookEdit": ("notebook_path", "file_path"),
    "Read": ("file_path",),
}
_TOOL_SCHEMA = {
    "Write": {"file_path", "content"},
    "Edit": {"file_path", "old_string", "new_string", "replace_all"},
    "MultiEdit": {"file_path", "edits"},
    "NotebookEdit": {"notebook_path", "file_path", "cell_id", "new_source",
                     "cell_type", "edit_mode"},
    "Read": {"file_path", "offset", "limit"},
}

# Bash is deliberately NOT narrowed here, and that is a decision rather than an
# omission. Two cuts of this lane tried to subtract quoted heredoc bodies from a
# command before asking which paths it touches. Both were unsafe, and the second
# was unsafe in a way the first was not: an independent review (ASTRA,
# 2026-09-10) EXECUTED nine shapes where the parser removed text the shell
# really runs. A quoted heredoc fed to `bash`, directly or through a pipeline,
# is not data, it is a program. An apparent opener inside a comment, inside
# ordinary quoted text, or inside an arithmetic shift `$((1 << n))` is not a
# redirection at all, and a delimiter word longer than the captured token
# (`<<true-tail`) is not the delimiter it was read as. Each of those then finds
# its guessed terminator further down and swallows the live commands in
# between. Substitution extraction undercaptures nested and quote-bearing
# parentheses, dropping the very operation that matters.
#
# The lesson underneath: a fallback for a parser that FAILS does nothing for a
# parser that confidently recognises the WRONG construct. Recognising bash well
# enough to subtract from it needs a real grammar -- consumers, pipelines,
# delimiter quoting forms, several documents on one line, line continuations --
# not another alternation bolted on per counter-example. Until that exists a
# Bash command is judged on all of its text, exactly as it was before this lane
# was touched.
#
# The cost is stated rather than hidden: a Bash command whose TEXT names a
# blocked path without touching it is still denied. That false positive is real,
# it is what prompted this work, and for Bash it remains OPEN.

def _action_surface(tool_name: str, tool_input: dict) -> list:
    """The values of a tool call that can act on a path. Values only."""
    if not tool_input:
        return []
    fields = _PATH_FIELDS.get(tool_name)
    if fields and set(tool_input) <= _TOOL_SCHEMA[tool_name]:
        target = [str(tool_input[f]) for f in fields if tool_input.get(f)]
        if target:
            return target
        # The tool NAME is one we know, but its documented target field is
        # missing or empty, so this is not the call we know how to narrow.
        # Self-review 2026-09-10 found eight shapes here -- `Write` with no
        # `file_path`, an empty one, `None`, `0` -- where returning the empty
        # surface ALLOWED a call the baseline denied. Same rule as Bash: an
        # unrecognised shape is judged on all of its values.
    return [str(v) for v in tool_input.values()]


def _referenced_paths(tool_name: str, tool_input: dict) -> list:
    """Path-shaped tokens a tool call can ACT on. Values only, never our keys."""
    tokens = []
    for value in _action_surface(tool_name, tool_input):
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


# ── Receipt field sanitize ──────────────────────────────────────────────────
# Audit finding H2. `tool_name` is chosen by the MCP server, i.e. by the party the
# pin lane exists to defend against, and it was stored and re-rendered verbatim. A
# name carrying ANSI escapes made `sunglasses receipts` clear the screen and print a
# forged all-clear; an embedded newline forged an extra row; a 300-character name
# destroyed the table. An audit trail the audited party can write into is not one.
#
# Applied on WRITE so a poisoned line never lands in the jsonl, and again on RENDER
# so a file written by an older build — or edited on disk — still cannot paint the
# terminal. Sanitizing only on write would leave every existing receipts file live.
RECEIPT_FIELD_LIMIT = 128

# C0 (00-1F), DEL (7F), C1 (80-9F): the escape introducer and its friends.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_receipt_field(value, limit: int = RECEIPT_FIELD_LIMIT):
    """Make an externally-supplied string safe to store and to print.

    Strips control characters and the invisible/bidi set, then truncates. Returns
    non-strings unchanged except that they are rendered with str(); None stays None
    so a missing field stays missing rather than becoming the text "None".

    The name is kept readable on purpose — the point is an audit line you can still
    use, not a redacted one. `\x1b[92mmcp__evil__tool` becomes `[92mmcp__evil__tool`:
    the escape is dead, the identity survives.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    cleaned = strip_invisible(_CONTROL_CHARS.sub("", value))
    if len(cleaned) > limit:
        # Say it was trimmed. A silently truncated audit field is a small lie.
        cleaned = cleaned[: limit - 1] + "\u2026"
    return cleaned


# Every field in a receipt whose value can be influenced from outside the process.
# `decision`, `lane` and `rule_id` are ours on write, but a receipts FILE is just
# bytes on disk, so the render path sanitizes them too.
_UNTRUSTED_RECEIPT_FIELDS = ("tool_name", "session_id", "error", "rule_id")


def _sanitize_record(record: dict) -> dict:
    out = dict(record)
    for field in _UNTRUSTED_RECEIPT_FIELDS:
        if field in out:
            out[field] = sanitize_receipt_field(out[field])
    return out


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
        handle.write(_json.dumps(_sanitize_record(record), ensure_ascii=False,
                                 default=str) + "\n")
    _restrict(path, 0o600)


class _Confession(str):
    """One evaluation's config errors: the text the legacy receipt has always
    carried, plus `types`, their class names, for the signed log, which never
    carries a message (T9 ruling 11 Q3)."""
    types: tuple = ()

    @classmethod
    def of(cls, errors) -> "_Confession":
        text = cls("; ".join(str(e) for e in errors))
        text.types = tuple(type(e).__name__ for e in errors)
        return text


def _present(path) -> bool:
    """Whether any directory entry is at `path`. lstat, so a dangling symlink
    is present (R57). Absence is False; an lstat that fails for any other
    reason raises (R56), so it never reads as absent. And no entry is absent
    only under a directory that can be listed (R62): with a file, a dangling
    symlink, a symlink to a file or an unlistable directory above it, this
    answers True, and the receipts code it hands to raises naming what is in
    the way. The walk is receipts._fs.obstruction's, repeated here so that an
    install without a key still imports nothing of the receipts package."""
    try:
        _os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        import pathlib
        for parent in pathlib.Path(path).parents:
            if not _os.path.lexists(parent):
                continue
            try:
                with _os.scandir(parent):
                    return False
            except OSError:
                return True
        return False
    return True


class _HookReceipts:
    """Where one call's two records go.

    The legacy day file, unchanged, until the user runs `sunglasses receipts
    init`. From then on the signed chain IS the log (T9 ruling 11 Q1): the
    opening is appended unsigned before the work, and the terminal goes with a
    `close` checkpoint that seals the call (ruling 15). Whether a key exists is
    one directory listing; nothing is imported to answer it, so an install
    without a key never loads the signing code.

    A key that exists but cannot be used (unsafe mode, the extra removed) is a
    receipt failure like a full disk: it raises, and the caller's F6 rule
    applies. It never falls back to writing unsigned lines, because a signed
    log that silently turns into an unsigned one is the downgrade the signing
    exists to show.
    """

    def __init__(self, home):
        self.home = home
        # R21: a deleted key is not `receipts off`. A hook chain that the off
        # record has not ended still means the user opted in. R56: a key or
        # chain directory that cannot be listed raises here, never reads as
        # "not opted in", and run_hook's guard asks, naming the cause. With
        # neither directory there, nothing of the receipts package loads.
        self.signed = False
        if _present(home / "keys") or _present(home / "receipts" / "hook"):
            from .receipts import optin
            self.signed = optin.opted_in(home)
        self._chain = None

    def _writer(self):
        if self._chain is None:
            from .receipts import optin
            # Raises KeyUnusable naming the cause, before the signing code or
            # the chain is touched (R21).
            signer = optin.signer(self.home)
            from .receipts import chain
            # One writer for both records: its in-memory note of the opening
            # it wrote is what lets the close seal it (R15d).
            self._chain = chain.Chain(self.home / "receipts" / "hook",
                                      signer, producer="hook",
                                      marker=optin.hook_marker(self.home))
        return self._chain

    def opening(self, row: dict) -> None:
        if not self.signed:
            write_receipt(row, home=self.home)
            return
        from .receipts import hook_rows
        self._writer().write([{"event": "in_flight",
                               "body": hook_rows.in_flight(_sanitize_record(row))}])

    def terminal(self, row: dict, error_types=()) -> None:
        if not self.signed:
            write_receipt(row, home=self.home)
            return
        from .receipts import hook_rows
        body = hook_rows.decision(_sanitize_record(row), error_types=error_types)
        self._writer().write([{"event": "decision", "body": body}], seal="close")


def _input_digest(tool_input):
    """SHA-256 of the canonical tool input. The receipt stores this and never
    the input itself: an audit trail that quotes the payload becomes the leak.

    None when the input cannot be encoded as UTF-8 (a lone surrogate). The
    encode used to substitute `?`, so `x\\ud800`, `x\\ud801` and `x?` hashed
    alike, and a digest that names three inputs names none of them (#8)."""
    import json as _json
    try:
        canonical = _json.dumps(tool_input, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        canonical = repr(tool_input)
    try:
        data = canonical.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return hashlib.sha256(data).hexdigest()


def _input_digest_fields(tool_input) -> dict:
    """The receipt's digest field, plus the reason whenever there is no digest."""
    digest = _input_digest(tool_input)
    if digest is None:
        return {"input_sha256": None, "input_sha256_reason": "unencodable"}
    return {"input_sha256": digest}


# ── Evaluation ──────────────────────────────────────────────────────────────

_CLEAN = Decision("defer", "deterministic", "GLS-FW-CLEAN",
                  "SUNGLASSES firewall: no deterministic violation.")


# ── Input bound ─────────────────────────────────────────────────────────────
# Every step after arrival walks the whole payload: the parse, the surfaces the
# rules read, the digest in the receipt. How deep that walk goes is set by the
# caller, and the tool input is text the model writes. So depth is bounded on
# the raw text, before anything parses it, and an input past the bound is a
# decision in its own right rather than something the later steps attempt.
#
# 64 levels counts the payload object itself. A real tool call sits a handful
# of levels down (payload, tool_input, a list of edits, one edit), and MCP
# arguments that are more than a few dozen deep are not something any tool
# asks for.
MAX_INPUT_NESTING = 64

# One linear pass. A JSON string (including one left open at the end of the
# text) is consumed whole so brackets inside it do not count; outside strings
# only the four structural brackets are matched. The string branch cannot
# backtrack: its two inner alternatives never start on the same character and
# the closing quote is optional.
_NESTING_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?|[\[\]{}]', re.S)


def input_too_deep(text: str, bound: int = MAX_INPUT_NESTING) -> bool:
    """True when `text`, read as JSON, nests more than `bound` levels deep.

    Works on the raw text so it can run before any parser, and stops at the
    first bracket past the bound. Malformed text is judged by its brackets
    alone; a parser would reject it anyway."""
    if text.count("[") + text.count("{") <= bound:
        return False    # the common case: too few openers to get there at all
    depth = 0
    for m in _NESTING_TOKEN.finditer(text):
        c = m.group()
        if c == "[" or c == "{":
            depth += 1
            if depth > bound:
                return True
        elif c == "]" or c == "}":
            depth -= 1
    return False


_TOO_DEEP = Decision(
    "deny", "deterministic", "GLS-FW-SEC-NESTING",
    f"SUNGLASSES firewall: this tool call's input is nested more than "
    f"{MAX_INPUT_NESTING} levels deep, which is past what the firewall accepts. "
    f"Flatten the input and retry.")


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

    # Audit L5: answer only the event we are installed for. The hook accepted any
    # hook_event_name, so a PostToolUse payload was scanned and could come back
    # "deny" — a veto on an action that had already run. Meaningless rather than
    # dangerous, but a firewall that appears to block something it cannot block is
    # a claim it does not hold. Absent is treated as PreToolUse: some harnesses
    # omit the field, and refusing to check a real tool call over a missing label
    # would trade a cosmetic bug for a hole.
    event = payload.get("hook_event_name")
    if event and event != "PreToolUse":
        return (Decision(action="defer", lane="deterministic",
                         rule_id="GLS-FW-NOT-PRETOOLUSE",
                         reason=(f"SUNGLASSES firewall: {event} is not the event this "
                                 f"hook decides. Only PreToolUse can prevent a call.")),
                None, {"skipped_event": event})

    # Checks that need zero configuration run first and unconditionally.
    hits, cleared = egress_secret_hits(tool_name, tool_input)
    if cleared:
        # Rides in extras so it reaches the terminal record whatever decides
        # this call: a canary cleared on a call that is then denied for some
        # OTHER material still has to be visible (ASTRA C01).
        extras["cleared_canaries"] = cleared
    if hits:
        return _deny_for_hits(hits, tool_name), None, extras

    # Config failures accumulate instead of returning early. A control that is
    # down has to reach the receipt even when some LATER check produced the
    # verdict — otherwise a corrupt policy.yaml plus a pin TOFU on the same call
    # yields a receipt that never mentions the dead policy control.
    errors = []
    policy_down = None      # set when the policy control is down; used as the
                            # fallback verdict instead of a silent fall-through

    def confession():
        return _Confession.of(errors) if errors else None

    try:
        policy = load_policy(home / "policy.yaml")
    except PolicyDown as down:
        # Recorded, not returned. A dead control must reach the receipt even when
        # a LATER check produces the verdict — that rule predates this change and
        # still holds, so this does not short-circuit the remaining lanes. What
        # changes is the FALLBACK: where nothing else decided, the answer is no
        # longer `{}` but an ask that names which control is down.
        errors.append(down)
        extras["policy_state"] = down.state
        policy_down = Decision(
            "ask", "error", f"GLS-FW-POLICY-{down.state.upper().replace('_', '-')}",
            f"SUNGLASSES firewall: {POLICY_STATES.get(down.state, down.state)}, so the "
            f"path and egress rules did NOT run on this call. Repair the policy file "
            f"under ~/.sunglasses or run `sunglasses init --policy`. Approve only if "
            f"you would have approved this call unchecked.")
    except PolicyError as exc:
        errors.append(exc)
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
            errors.append(exc)
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
            errors.append(exc)
        else:
            extras["pin_reach"] = pin_reach(tool_name, pins)
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

    # Nothing found anything. If the policy control was down for this call, that
    # is not a clean result and must not look like one.
    return (policy_down or _CLEAN), confession(), extras


def run_hook(stdin_text: str, home=None) -> dict:
    """stdin JSON → hook output dict. NEVER raises, NEVER exits non-zero.

    Every failure mode lands on `defer`: fall through to Claude Code's own
    permission flow (emitted as `{}` — see Decision.to_hook_output for why it
    must never be a literal "defer" on the wire). `defer` rather than `allow` is
    deliberate — a crashed firewall must not silently grant something the harness
    would otherwise have asked the user about.
    """
    import json as _json
    import time as _time

    home = home or sunglasses_home()
    started = _time.perf_counter()
    payload, decision, error, extras = {}, None, None, {}

    # RED 5 — LIFECYCLE RECORDS.
    #
    # A PreToolUse hook that is killed on the harness's timeout FAILS OPEN, and
    # it does so in complete silence: nothing runs to write a receipt, so the
    # audit trail shows no evidence that the call was ever seen. "Every call
    # writes a receipt" was therefore false for exactly the failure that matters
    # most, and the absence was indistinguishable from the hook not being
    # installed at all.
    #
    # So the evidence is written BEFORE the work, not after. An `in_flight`
    # record is appended the moment a call arrives, carrying an evaluation id;
    # the terminal record references that id. A killed or crashed evaluation
    # leaves an in_flight with no terminal partner, and `sunglasses receipts
    # --verify` names it. Silence becomes an orphan, which is a fact you can act on.
    #
    # This does NOT make the hook fail closed — that is the harness's contract,
    # not ours. It makes the failure legible.
    #
    # Checked before either parse below, so an input past the bound is never
    # parsed at all. It still arrives (in_flight) and still gets a decision.
    try:
        too_deep = input_too_deep(stdin_text)
    except Exception:  # noqa: BLE001 — not str: the parse below decides
        too_deep = False
    try:
        payload = (_json.loads(stdin_text)
                   if stdin_text.strip() and not too_deep else {})
        if not isinstance(payload, dict):
            payload = {}
    except Exception:  # noqa: BLE001 — a malformed payload is still an arrival
        payload = {}
    eval_id = _new_eval_id()
    error_types = ()
    # T9 RULING 34. THE RECEIPTS PATH IS INSIDE THE GUARD, construction too.
    # Building `_HookReceipts` decides whether the user opted in, which reads
    # the chain's tail, and it used to run above every `try`: an exception
    # there left `run_hook` altogether and the hook exited 1, which the host
    # does not block on. A failure here is F6 like the terminal's, below: the
    # call asks, naming the cause, and a deny stays a deny.
    receipts = None
    receipts_down = None
    try:
        receipts = _HookReceipts(home)
        receipts.opening({
            "ts": _now_iso(),
            "kind": "in_flight",
            "eval_id": eval_id,
            "tool_name": payload.get("tool_name"),
            "session_id": payload.get("session_id"),
            **_input_digest_fields(payload.get("tool_input")),
        })
    except Exception as exc:  # noqa: BLE001
        receipts_down = exc

    try:
        if too_deep:
            decision = _TOO_DEEP
        else:
            payload = _json.loads(stdin_text) if stdin_text.strip() else {}
            if not isinstance(payload, dict):
                raise ValueError("hook payload was not a JSON object")
            decision, error, extras = evaluate(payload, home=home)
            error_types = getattr(error, "types", ())
    except Exception as exc:  # noqa: BLE001 — fail-open is the whole point
        error = f"{type(exc).__name__}: {exc}"
        error_types = (type(exc).__name__,)
        decision = Decision(
            "defer", "error", "GLS-FW-ERROR",
            "SUNGLASSES firewall: internal error, deferring to normal permission "
            "flow. This tool call was NOT checked. See ~/.sunglasses/receipts/.",
        )

    if error:
        # A control was down on this call. `lane` keeps saying which lane actually
        # decided — overloading it with "error" threw that away — and `degraded`
        # plus `error` carry the confession.
        #
        # Marked whenever there is an error, including when the dead control is
        # itself the verdict (RED 4). The condition used to exclude `lane ==
        # "error"`, which meant the one receipt where a control definitely died
        # was the one receipt not flagged as degraded.
        extras = {**extras, "degraded": True}

    if receipts_down is not None:
        # Decided BEFORE the terminal, so the terminal (if it can be written)
        # records the answer the host is actually given.
        decision, error = _receipts_unwritable(decision, error, receipts,
                                               receipts_down)
    try:
        if receipts is None:
            raise receipts_down
        receipts.terminal({
            "ts": _now_iso(),
            "kind": "decision",
            "eval_id": eval_id,
            "tool_name": payload.get("tool_name"),
            "session_id": payload.get("session_id"),
            "decision": decision.action,
            "lane": decision.lane,
            "rule_id": decision.rule_id,
            **_input_digest_fields(payload.get("tool_input")),
            "elapsed_ms": round((_time.perf_counter() - started) * 1000, 2),
            **extras,
            **({"error": error} if error else {}),
        }, error_types=error_types)
    except Exception as exc:  # noqa: BLE001
        decision, error = _receipts_unwritable(decision, error, receipts, exc)

    return decision.to_hook_output()


def _receipts_unwritable(decision, error, receipts, exc):
    """F6 — THE AUDIT TRAIL IS DOWN.

    Losing an audit line must not WEAKEN a decision, so a deny stays a deny
    and is returned unchanged. But a `defer` or an `allow` that nobody can
    record is a call with no evidence it happened, which is the same silence
    the lifecycle records exist to remove. Those ASK, naming the dead control
    rather than echoing an exception at the user.

    `receipts` is None when building it is what failed (T9 ruling 34). That
    build is the opt-in decision, so it counts as signed: the key is a likely
    cause and the one a directory check would never find.
    """
    if decision.action == "deny":
        return decision, error
    from .receipts import optin
    cause = "KEY_UNUSABLE" if isinstance(exc, optin.KeyUnusable) else "RECEIPT_IO_ERROR"
    check = ("Check the receipts directory under ~/.sunglasses for "
             "permissions and disk space.")
    if receipts is None or receipts.signed:
        check = ("Check the signing key in ~/.sunglasses/keys (private to "
                 "you, and sunglasses[receipts] installed), then the "
                 "receipts directory for permissions and disk space.")
        if isinstance(exc, optin.KeyUnusable):
            # R21 (a): the cause and the one command that clears it.
            check = f"Your signing key (~/.sunglasses/keys) cannot sign: {exc}."
    from .receipts import _fs
    if isinstance(exc, _fs.Unlistable):
        # R56: which directory, and that it could not be listed, not "empty".
        check = (f"A receipts directory {exc}, and a signed log never turns "
                 f"unsigned on a guess. Fix its permissions (chmod 700).")
        if getattr(exc, "blocked_by", None) is not None:
            # R62: the thing in the way is what to fix, not the path under it.
            check = (f"A receipts directory {exc}, and a signed log never "
                     f"turns unsigned on a guess. Fix it: make {exc.blocked_by} "
                     f"a directory, chmod 700.")
    from .receipts import chain as _chain
    if isinstance(exc, _chain.MarkerUnwritable):
        # R62 B: which marker, why, and that the next call tries again.
        check = (f"The hook log's marker {exc}, and no signed log is begun "
                 f"without it. Fix ~/.sunglasses/keys (chmod 700) or free disk "
                 f"space; the next call tries again.")
    decision = Decision(
        "ask", "error", "GLS-FW-RECEIPTS-UNWRITABLE",
        f"SUNGLASSES firewall: the audit trail could not be written ({cause}), "
        f"so this call would leave no record. {check} Approve only if you "
        "would have approved it unrecorded.")
    return decision, f"receipts unwritable: {type(exc).__name__}: {exc}"


def _new_eval_id() -> str:
    """Identifier tying one call's in_flight record to its terminal record.

    Random rather than sequential: a counter would need shared state across
    concurrent hook processes, and the only job here is to pair two lines.
    """
    import os
    return os.urandom(8).hex()


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
    except Exception:  # noqa: BLE001
        return False, f"did not return hook JSON: {(proc.stdout or '').strip()[:200]}"
    if data == {}:
        # A clean probe answers with no opinion — the documented way to fall
        # through to Claude Code's own permission flow (see Decision.to_hook_output).
        return True, "defer"
    try:
        decision = data["hookSpecificOutput"]["permissionDecision"]
    except Exception:  # noqa: BLE001
        return False, f"did not return hook JSON: {(proc.stdout or '').strip()[:200]}"
    # "defer" is still accepted here: an older installed firewall answers the
    # clean probe with it, and a working-but-old hook is not a broken wire.
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

    def _mark_enrolled():
        """Record that a policy lives here, so its later ABSENCE is a dead control.

        This has to run on EVERY path that leaves a policy in place, not only on
        the one that creates the file. An install that predates the marker takes
        the exists-guard or the upgrade branch below, both of which used to
        return before this ran, so the machines most likely to be running an
        older policy were exactly the ones that never got enrolled. On those,
        losing the policy still fell through to `{}` instead of asking, which is
        the failure this marker exists to make impossible.
        """
        marker = home / INSTALL_MARKER
        if marker.exists():
            return
        home.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            "sunglasses wrote a policy here. If policy.yaml is missing, the control "
            "is down and the firewall will ask rather than fall through silently.\n",
            encoding="utf-8")

    if path.exists():
        is_our_untouched_disabled = (
            path.read_text(encoding="utf-8") == starter_policy_text(enabled=False))
        if enabled and is_our_untouched_disabled:
            path.write_text(starter_policy_text(enabled=True), encoding="utf-8")
            _mark_enrolled()
            return path
        _mark_enrolled()
        return None
    home.mkdir(parents=True, exist_ok=True)
    path.write_text(starter_policy_text(enabled), encoding="utf-8")
    _mark_enrolled()
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
    try:
        out = run_hook(stdin_text)
    except Exception as exc:  # noqa: BLE001
        # T9 RULING 35, THE BELT. Anything that escapes `run_hook` would exit
        # 1, and the host proceeds on exit 1: the fail-open. It asks instead,
        # naming the exception's TYPE only -- its text is not trusted to be
        # printable, or even to exist.
        out = Decision(
            "ask", "error", "GLS-FW-HOOK-FAULT",
            f"SUNGLASSES firewall: the hook failed ({type(exc).__name__}), so "
            "this call was not checked and not recorded. Approve only if you "
            "would have approved it unchecked.").to_hook_output()
    _sys.stdout.write(_json.dumps(out))
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
    # `threat_found`, NOT `is_clean` (v0.5.6). `is_clean` is now False for an
    # oversized command that merely got truncated, and this lane reads `findings[0]`
    # two lines down — on `is_clean` that is an IndexError on a benign long command,
    # and the escalation it would raise is the "broad primitive becomes a block"
    # failure the release forbids. A byte we did not read is not a detection.
    if not result.threat_found:
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
