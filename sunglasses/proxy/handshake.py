"""What version we speak, and what we are willing to say the server can do.

T1.R2 fixes the version set and T1.R3 fixes the capability intersection. Written
against `tests/test_proxy_handshake.py`, which was committed first from the rows.

The capability rule is an INTERSECTION and that word is doing work. It is bounded
on both sides, and only one side is intuitive. Not advertising what upstream
lacks is obvious, because the client would call it and get nothing. Not
advertising what WE do not support is the half that gets dropped, because
upstream having it feels like permission; it is not. Anything we advertise, we
have promised to mediate, and a capability this proxy cannot inspect is one it
would be passing through blind while the client believes otherwise.
"""
from __future__ import annotations

# T1.R2. Frozen for 0.6.0. Membership, never prefix or ordering: a version is
# supported because it is IN this set, not because it resembles one that is.
SUPPORTED_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")

# T1.R3, verbatim from the row.
SUPPORTED_CAPABILITIES = frozenset({
    "tools", "resources", "prompts", "logging", "ping",
})
SUPPORTED_NOTIFICATIONS = frozenset({
    "notifications/cancelled",
    "notifications/initialized",
    # T2.R12 names `message` as an upstream notification to INSPECT, and T1.R3
    # advertises the `logging` capability whose only wire traffic this is.
    # Omitting it advertised a capability that could never carry a message and
    # made T2.R12's row unreachable: a rule scoped to it would have read as
    # covered and never fired, which is the check that skips itself.
    "notifications/message",
    "notifications/progress",
    "notifications/roots/list_changed",
    "notifications/tools/list_changed",
})

UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL"

# T2.R16. The methods a CLIENT may send. Anything else is an extension or an
# unknown, and the row answers it to the client without upstream ever seeing it.
# Declared here, once, so the selector table and the reader cannot drift into
# two vocabularies that disagree about what a known method is.
CLIENT_METHODS = frozenset({
    "initialize", "ping", "tools/call", "tools/list", "resources/read",
    "resources/list", "prompts/get", "prompts/list", "logging/setLevel",
}) | SUPPORTED_NOTIFICATIONS


def client_method_known(method):
    return method in CLIENT_METHODS


class Negotiation:
    __slots__ = ("ok", "version", "reason", "close", "detail")

    def __init__(self, ok, version=None, reason=None, close=False, detail=None):
        self.ok = ok
        self.version = version
        self.reason = reason
        self.close = close
        self.detail = detail

    def as_receipt(self):
        """An allowlist, for the third time in this package. The version we
        REFUSED is peer text and does not enter evidence; the fact of the
        refusal and its reason are ours."""
        return {"ok": self.ok, "version": self.version if self.ok else None,
                "reason": self.reason, "close": self.close}

    def __repr__(self):
        return f"<Negotiation {'ok ' + str(self.version) if self.ok else self.reason}>"


def negotiate(params):
    """T1.R2. Exactly one of the frozen versions, or refuse and close.

    Membership in the tuple, not a prefix and not a comparison. `2025-06-18-beta`
    starts with a supported version and is not it; `2025-06` is a truncation of
    one and is not it either. Both are in the tests because "startswith" is the
    natural wrong spelling.
    """
    version = (params or {}).get("protocolVersion")
    if not isinstance(version, str) or version not in SUPPORTED_VERSIONS:
        return Negotiation(
            False, reason=UNSUPPORTED_PROTOCOL, close=True,
            detail=f"the client offered a {type(version).__name__} that is not "
                   f"one of the {len(SUPPORTED_VERSIONS)} supported versions")
    return Negotiation(True, version=version)


# T1.R3 names `resources(read)`. The parenthesis is a restriction and not a
# gloss: a server may advertise `resources` with `subscribe` and `listChanged`,
# and those are separate capabilities the client will use if it is told they
# exist. The frozen subset is the read side only.
_CAPABILITY_SUBSET = {
    "resources": frozenset({"read"}),
}


def advertise(upstream_capabilities):
    """T1.R3. Upstream's capabilities INTERSECTED with what we support.

    The intersection is applied at TWO levels, and the second is the one I
    missed. Filtering the names alone advertises `resources` with whatever
    members upstream attached, so a client told that `subscribe` and
    `listChanged` exist will use them and the proxy has promised to mediate
    traffic it has no rule for. The row says `resources(read)`; the parenthesis
    is the restriction.

    Values are otherwise upstream's own, carried through rather than invented,
    because a value we make up claims a shape we have not seen.
    """
    upstream = upstream_capabilities or {}
    advertised = {}
    for name, value in upstream.items():
        if name not in SUPPORTED_CAPABILITIES:
            continue
        allowed = _CAPABILITY_SUBSET.get(name)
        if allowed is not None and isinstance(value, dict):
            advertised[name] = {member: member_value
                                for member, member_value in value.items()
                                if member in allowed}
        else:
            advertised[name] = value
    return advertised


def notification_supported(method):
    """T1.R3's last sentence: anything unlisted is rejected on arrival.

    Membership again. `notifications/cancelled/extra` is accepted by a prefix
    match and is not the method the row names.
    """
    return method in SUPPORTED_NOTIFICATIONS
