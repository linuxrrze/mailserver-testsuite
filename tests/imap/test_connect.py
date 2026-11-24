"""IMAP connection and authentication tests."""

import imaplib
import ssl
import pytest

from lib.imap import (
    connect_ssl,
    connect_starttls,
    login,
    logout,
    make_ssl_context,
)


def test_imaps_connects(cfg):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    assert imap is not None
    logout(imap)


def test_starttls_connects(cfg):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_starttls(cfg["imap"]["host"], cfg["imap"]["port_starttls"], ctx)
    assert imap is not None
    logout(imap)


def test_login_success(cfg, primary_account):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    login(imap, primary_account["user"], primary_account["password"])
    logout(imap)


def test_login_wrong_password_rejected(cfg, primary_account):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    try:
        with pytest.raises(Exception):
            login(imap, primary_account["user"], "definitively-wrong-password-xyz")
    finally:
        logout(imap)


def test_cert_valid(cfg):
    """Connection with strict cert checking must succeed (catches expired/wrong certs)."""
    if cfg.get("no_verify", False):
        pytest.skip("no_verify is set — skipping strict cert check")
    ctx = make_ssl_context(no_verify=False)
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    logout(imap)


def test_imaps_socket_is_encrypted(cfg):
    """Verify the socket reports a TLS version after connect."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    sock = imap.socket()
    assert hasattr(sock, "version"), "Socket is not an SSLSocket"
    assert sock.version() is not None
    logout(imap)
