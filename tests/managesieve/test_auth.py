"""ManageSieve authentication tests (over the configured TLS mode)."""

import pytest

from lib.managesieve import ManageSieveError


def test_auth_succeeds(sieve_connect, primary_account):
    client = sieve_connect()
    try:
        client.authenticate_plain(primary_account["user"], primary_account["password"])
    finally:
        client.logout()


def test_auth_wrong_password_rejected(sieve_connect, primary_account):
    client = sieve_connect()
    try:
        with pytest.raises(ManageSieveError):
            client.authenticate_plain(primary_account["user"], "definitively-wrong-password-xyz")
    finally:
        client.logout()


def test_auth_mechanisms_advertised(sieve_connect):
    """SASL mechanisms must be advertised once TLS is established."""
    client = sieve_connect()
    try:
        mechs = client.capabilities.get("SASL", "").split()
        assert mechs, "No SASL mechanisms advertised on the encrypted session"
    finally:
        client.logout()


def test_command_rejected_before_auth(sieve_connect):
    """LISTSCRIPTS before AUTHENTICATE must be refused — no session is established yet."""
    client = sieve_connect()
    try:
        with pytest.raises(ManageSieveError):
            client.list_scripts()
    finally:
        client.logout()
