"""The suite cannot reach a host that is not this machine.

tests/network_guard.py is installed around every test by tests/conftest.py. Each
test here is a control: it needs the guard to pass, because without it the call
goes to the real network (or to the real resolver) instead of being refused.
"""
import os
import shutil
import socket
import tempfile

import pytest

import network_guard

# TEST-NET-1 (RFC 5737) and the .invalid TLD (RFC 6761): reserved, never routed,
# so even a run with the guard removed cannot reach a real service.
PUBLIC_IP = "192.0.2.1"
PUBLIC_NAME = "tests-must-stay-local.invalid"


def test_a_connection_to_a_public_address_is_refused(network_violations):
    s = socket.socket()
    try:
        with pytest.raises(network_guard.NetworkBlocked):
            s.connect((PUBLIC_IP, 80))
    finally:
        s.close()
    assert network_violations == [f"connect {PUBLIC_IP!r}"]
    network_violations.clear()


def test_connect_ex_and_create_connection_are_refused_too(network_violations):
    s = socket.socket()
    try:
        with pytest.raises(network_guard.NetworkBlocked):
            s.connect_ex((PUBLIC_IP, 80))
    finally:
        s.close()
    with pytest.raises(network_guard.NetworkBlocked):
        socket.create_connection((PUBLIC_IP, 80), timeout=1)
    assert len(network_violations) == 2
    network_violations.clear()


def test_a_name_lookup_for_a_public_host_is_refused(network_violations):
    with pytest.raises(network_guard.NetworkBlocked):
        socket.getaddrinfo(PUBLIC_NAME, 443)
    assert network_violations == [f"getaddrinfo {PUBLIC_NAME!r}"]
    network_violations.clear()


def test_a_refusal_that_the_code_under_test_swallows_is_still_on_record(network_violations):
    try:
        socket.create_connection((PUBLIC_IP, 80), timeout=1)
    except OSError:
        pass  # what a fetcher with a broad except does
    assert network_violations, "a swallowed refusal must stay visible so teardown can fail the test"
    network_violations.clear()


def test_loopback_and_unix_sockets_still_work():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.create_connection(srv.getsockname(), timeout=5)
    conn, _ = srv.accept()
    cli.sendall(b"x")
    assert conn.recv(1) == b"x"
    for sock in (cli, conn, srv):
        sock.close()
    assert socket.getaddrinfo("localhost", 80)
    if not hasattr(socket, "AF_UNIX"):
        return
    d = tempfile.mkdtemp(prefix="g", dir="/tmp")  # a short path: AF_UNIX names are length-limited
    try:
        path = os.path.join(d, "s")
        us = socket.socket(socket.AF_UNIX)
        us.bind(path)
        us.listen(1)
        uc = socket.socket(socket.AF_UNIX)
        uc.connect(path)
        uc.close()
        us.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.9.9.9", "::1", "localhost", "LOCALHOST", "::1%lo0", None, ""])
def test_these_hosts_count_as_this_machine(host):
    assert network_guard._local(host)


@pytest.mark.parametrize("host", [PUBLIC_IP, "8.8.8.8", "2001:db8::1", "example.com", "0.0.0.0", "127.0.0.1.evil.example"])
def test_these_hosts_do_not(host):
    assert not network_guard._local(host)
