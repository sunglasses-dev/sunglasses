"""Carriers for the GLS-SD -API siblings.

THE AXIS IS THE CARRIER, NOT THE SENTENCE. #152's siblings guard prose
injection, where evasion is linguistic, so its space is verbs x fillers x
objects x suffixes. These rules match a literal token shape, so varying the
prose around a key proves nothing; what varies in the real world is WHERE the
token sits when it comes back from a tool. Hence three carriers.

NOT ONE CREDENTIAL-SHAPED LITERAL IS STORED IN THIS FILE. Every value, the PEM
banners included, is assembled at import time from fragments. Writing them out
would put credential-shaped strings in the repository and in every command that
touches it, which is the thing this product tells people not to do.

That is not a hypothetical. Two drafts of this file were refused by our own
PreToolUse firewall, once for AWS key material and once for a private key block,
both in an outbound Bash call. The firewall was right both times. Assembling the
shapes is the honest fix; an allowlist entry would have been routing around our
own guardrail to write its test.

Every value matches no real account and opens nothing.
"""
import string

_UPPER = string.ascii_uppercase + string.digits
_LOWER = string.ascii_lowercase + string.digits


def _fill(alphabet, n):
    """Deterministic filler. Reproducible, and obviously not a real secret."""
    out = []
    while len(out) < n:
        for ch in alphabet:
            out.append(ch)
            if len(out) == n:
                break
    return "".join(out)


def _banner(kind):
    """A PEM opening line, assembled rather than written."""
    dashes = "-" * 5
    return dashes + "BEGIN " + kind + " PRIVATE" + " KEY" + dashes


_AWS = "AK" + "IA"
_GH = "gh" + "p_"
_GHF = "github" + "_pat_"
_OPENAI = "sk" + "-"
_SLACK = "xo" + "xb-"
_GOOGLE = "AI" + "za"

TOKENS = {
    "GLS-SD-001-API": _OPENAI + _fill(_LOWER, 32),
    "GLS-SD-002-API": _banner("OPENSSH"),
    "GLS-SD-003-API": _AWS + _fill(_UPPER, 16),
    "GLS-SD-004-API": _banner("RSA"),
    "GLS-SD-006-API": _GH + _fill(_LOWER, 36),
    "GLS-SD-007-API": _SLACK + _fill(string.digits, 10) + "-" + _fill(_LOWER, 16),
    "GLS-SD-008-API": _GOOGLE + _fill(_LOWER, 35),
    "GLS-SD-009-API": _GHF + _fill(_LOWER, 22),
}


def tool_result(token):
    """An MCP tool result. The shape an agent actually receives."""
    return ('{"content":[{"type":"text","text":"deploy finished, key=' + token
            + '"}],"isError":false}')


def log_line(token):
    return "2026-09-14T09:31:02Z INFO deploy.worker key=" + token + " status=ok"


def agent_message(token):
    return "Here is the value you asked for: " + token


CARRIERS = {"tool_result": tool_result, "log_line": log_line,
            "agent_message": agent_message}

# THE DISCLOSED LIMIT, ASSERTED RATHER THAN REMEMBERED. These are the shapes
# vendor documentation uses. Under the verbatim-parent ruling they block in a
# tool result exactly as they block in a file. Pinned so the limit cannot drift
# unnoticed in either direction: if a change makes them pass, this goes red and
# somebody decides that on purpose instead of meeting it in production.
VENDOR_EXAMPLES = {
    "GLS-SD-003-API": _AWS + "IOSFODNN7" + "EXAMPLE",
    "GLS-SD-006-API": _GH + ("x" * 36),
    "GLS-SD-001-API": _OPENAI + ("x" * 32),
}

# Must stay CLEAN: prose about secrets that carries none, and token-shaped
# strings one property short of the predicate.
NEAR_MISSES = [
    "Rotate your credential every 90 days as a matter of policy.",
    "The docs explain how to store an aws access key safely.",
    "This helper returns the private key content from the vault.",
    _AWS + "4TEST",             # too short for {16}
    _GH + "tooshort",           # too short for {36}
    _GOOGLE + "Short",          # too short for {35}
    "notakey_github_pat",       # wrong shape
    "The quarterly report shows steady growth across all regions.",
]
