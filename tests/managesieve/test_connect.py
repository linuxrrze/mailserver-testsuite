"""ManageSieve (RFC 5804) connection tests."""

import pytest

from lib.managesieve import connect, connect_starttls, make_ssl_context


def test_connects_plain(managesieve_cfg):
    client = connect(managesieve_cfg["host"], managesieve_cfg.get("port", 4190))
    assert client.capabilities, "No capabilities advertised in the greeting"
    client.logout()


def test_starttls_connects(cfg, managesieve_cfg):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    client = connect_starttls(managesieve_cfg["host"], managesieve_cfg.get("port", 4190), ctx)
    assert client is not None
    client.logout()


def test_socket_is_encrypted(cfg, managesieve_cfg):
    """Verify the socket reports a TLS version after STARTTLS."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    client = connect_starttls(managesieve_cfg["host"], managesieve_cfg.get("port", 4190), ctx)
    try:
        sock = client.socket()
        assert hasattr(sock, "version"), "Socket is not an SSLSocket after STARTTLS"
        assert sock.version() is not None
    finally:
        client.logout()


def test_cert_valid(cfg, managesieve_cfg):
    """Connection with strict cert checking must succeed (catches expired/wrong certs)."""
    if cfg.get("no_verify", False):
        pytest.skip("no_verify is set — skipping strict cert check")
    ctx = make_ssl_context(no_verify=False)
    client = connect_starttls(managesieve_cfg["host"], managesieve_cfg.get("port", 4190), ctx)
    client.logout()
