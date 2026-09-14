"""T1.R2's version negotiation and T1.R3's capability intersection, from the rows.

Written before the implementation, like the pump, and committed on its own so
the order is in the log rather than in my word for it.

  T1.R2  the MCP schema version is negotiated in `initialize` from
         {2024-11-05, 2025-03-26, 2025-06-18}, else UNSUPPORTED_PROTOCOL and
         the session closes.
  T1.R3  capabilities advertised to the client are the UPSTREAM'S intersected
         with a fixed set. Everything else is not advertised and is rejected on
         arrival.

The second row is the one with a sharp edge. An intersection is not a filter of
what we think is reasonable; it is bounded on BOTH sides. A capability upstream
does not have must not be advertised because we support it, and a capability we
do not support must not be advertised because upstream has it. A client that is
told a capability exists will use it.
"""
import pytest

handshake = pytest.importorskip(
    "sunglasses.proxy.handshake",
    reason="the handshake is the slice being specified here")


# ── T1.R2: version negotiation ─────────────────────────────────────────────

@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18"])
def test_each_frozen_version_is_accepted_and_echoed_unchanged(version):
    """The set is frozen. A version is accepted as itself, not normalised to
    the newest one we happen to prefer."""
    outcome = handshake.negotiate({"protocolVersion": version})
    assert outcome.ok
    assert outcome.version == version


@pytest.mark.parametrize("version", [
    "2026-01-01",            # newer than anything we know
    "2024-01-01",            # older
    "2025-06-18-beta",       # a prefix of a supported one is not that one
    "2025-06",               # nor is a truncation
    "",
    None,
])
def test_anything_outside_the_frozen_set_is_refused_and_closes(version):
    """T1.R2: else UNSUPPORTED_PROTOCOL and session close.

    The prefix and truncation cases are here because "starts with a version we
    support" is the obvious wrong way to write this, and it accepts a version
    nobody has agreed to.
    """
    outcome = handshake.negotiate({"protocolVersion": version})
    assert not outcome.ok
    assert outcome.reason == "UNSUPPORTED_PROTOCOL"
    assert outcome.close is True


def test_a_missing_protocol_version_is_refused():
    outcome = handshake.negotiate({})
    assert not outcome.ok and outcome.reason == "UNSUPPORTED_PROTOCOL"


@pytest.mark.parametrize("version", [20250618, ["2025-06-18"], {"v": "2025-06-18"}])
def test_a_version_that_is_not_a_string_is_refused(version):
    outcome = handshake.negotiate({"protocolVersion": version})
    assert not outcome.ok and outcome.reason == "UNSUPPORTED_PROTOCOL"


# ── T1.R3: the intersection, bounded on both sides ─────────────────────────

def test_a_capability_upstream_lacks_is_not_advertised():
    """We do not add what upstream cannot do. A client told a capability exists
    will use it, and upstream will not answer."""
    advertised = handshake.advertise({"tools": {}})
    assert "prompts" not in advertised
    assert "tools" in advertised


def test_a_capability_we_do_not_support_is_not_advertised_even_if_upstream_has_it():
    """The other side of the bound, and the one a filter written as "remove the
    ones we dislike" gets wrong by omission."""
    advertised = handshake.advertise({"tools": {}, "experimental": {"x": 1},
                                      "sampling": {}})
    assert "experimental" not in advertised
    assert "sampling" not in advertised


def test_the_advertised_set_is_exactly_the_intersection():
    upstream = {"tools": {}, "prompts": {}, "logging": {}, "sampling": {}}
    advertised = handshake.advertise(upstream)
    assert set(advertised) == {"tools", "prompts", "logging"}


def test_an_empty_upstream_advertises_nothing():
    assert handshake.advertise({}) == {}


def test_the_capability_value_is_carried_through_not_invented():
    """We intersect the NAMES. The value is upstream's own, because inventing
    one claims a shape we have not seen."""
    advertised = handshake.advertise({"tools": {"listChanged": True}})
    assert advertised["tools"] == {"listChanged": True}


def test_the_supported_set_is_the_one_the_row_names():
    """The row lists it explicitly, so it is asserted explicitly rather than
    trusted to whatever the module happens to contain."""
    assert handshake.SUPPORTED_CAPABILITIES == frozenset({
        "tools", "resources", "prompts", "logging", "ping",
    })
    assert handshake.SUPPORTED_NOTIFICATIONS == frozenset({
        "notifications/cancelled", "notifications/initialized",
        "notifications/progress", "notifications/roots/list_changed",
        "notifications/tools/list_changed",
    })


@pytest.mark.parametrize("method", [
    "notifications/cancelled", "notifications/tools/list_changed",
])
def test_a_supported_notification_is_accepted(method):
    assert handshake.notification_supported(method) is True


@pytest.mark.parametrize("method", [
    "notifications/message", "notifications/resources/updated",
    "notifications/", "notifications/cancelled/extra",
])
def test_an_unlisted_notification_is_rejected_on_arrival(method):
    """T1.R3's last sentence. `notifications/cancelled/extra` is here because a
    prefix match accepts it and it is not the method the row names."""
    assert handshake.notification_supported(method) is False
