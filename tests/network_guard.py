"""Refuse every connection a test makes that does not stay on this machine.

A test that reaches a real host is a test whose result and whose cost depend on
the day it runs: a stub that is replaced by a real client, a helper that gains a
URL, a fixture that fetches. Nothing in this repository's tests is meant to leave
the machine, so the suite says so mechanically instead of by habit.

`install(monkeypatch)` replaces the points where Python code starts a
connection, and returns the list that every refusal is also written to. A
refusal raises `NetworkBlocked`, an OSError, so code under test sees an ordinary
connection failure; it is also recorded, so a caller that swallows that failure
cannot hide it. tests/conftest.py fails the test at teardown when the list is
not empty.

Allowed: UNIX-domain sockets, `localhost`, and any loopback address. A bind is
not a connection and is not touched.

Not covered, on purpose: connections made by a child process (a `pip` run, a
`git clone` of a remote). Those are a separate process with its own sockets; the
tests that need one carry the `network` marker and are exempt.
"""
import ipaddress
import socket


class NetworkBlocked(OSError):
    """A test tried to connect to a host that is not this machine."""


def _local(host):
    if host is None or host == "" or isinstance(host, (bytes, bytearray)) and not host:
        return True
    if isinstance(host, (bytes, bytearray)):
        host = bytes(host).decode("ascii", "replace")
    host = str(host).split("%", 1)[0].strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host_of(address):
    """The host part of a socket address, or None for a path (AF_UNIX)."""
    if isinstance(address, (str, bytes, bytearray)):
        return None
    try:
        return address[0]
    except (TypeError, IndexError):
        return None


def install(monkeypatch):
    refused = []

    def refuse(what, host):
        refused.append(f"{what} {host!r}")
        raise NetworkBlocked(f"a test tried to reach {host!r} ({what}); tests stay on this machine")

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def connect(self, address):
        host = _host_of(address)
        if host is not None and not _local(host):
            refuse("connect", host)
        return real_connect(self, address)

    def connect_ex(self, address):
        host = _host_of(address)
        if host is not None and not _local(host):
            refuse("connect_ex", host)
        return real_connect_ex(self, address)

    def getaddrinfo(host, *args, **kwargs):
        if not _local(host):
            refuse("getaddrinfo", host)
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return refused
