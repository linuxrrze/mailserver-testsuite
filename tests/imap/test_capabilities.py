"""IMAP CAPABILITY advertisement tests."""

import pytest

from lib.imap import get_capabilities, connect_ssl, make_ssl_context, logout

REQUIRED_CAPS = []  # IMAP version handled by test_imap_version_advertised
DESIRABLE_CAPS = ["UIDPLUS", "MOVE", "IDLE", "NAMESPACE", "QUOTA"]


def test_imap_version_advertised(cfg):
    """Server must advertise IMAP4rev1 or IMAP4rev2 pre-login.

    Some servers (e.g. Dovecot) drop the version token from the post-login
    capability string, so this test uses a fresh unauthenticated connection.
    """
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    try:
        caps = get_capabilities(imap)
        assert "IMAP4rev1" in caps or "IMAP4rev2" in caps, (
            f"Neither IMAP4rev1 nor IMAP4rev2 in pre-login CAPABILITY; got: {caps}"
        )
    finally:
        logout(imap)


@pytest.mark.parametrize("cap", REQUIRED_CAPS)
def test_required_capability(imap, cap):
    caps = get_capabilities(imap)
    assert cap in caps, f"Required capability {cap!r} not advertised; got: {caps}"


@pytest.mark.parametrize("cap", DESIRABLE_CAPS)
def test_desirable_capability(imap, cap):
    caps = get_capabilities(imap)
    if cap not in caps:
        pytest.xfail(f"Optional capability {cap!r} not advertised")


def test_auth_mechanisms_present(cfg):
    """AUTH= mechanisms must be advertised on a pre-login connection."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    try:
        caps = get_capabilities(imap)
        auth_caps = {c for c in caps if c.startswith("AUTH=")}
        assert auth_caps, f"No AUTH= capabilities advertised pre-login; got: {caps}"
    finally:
        logout(imap)
