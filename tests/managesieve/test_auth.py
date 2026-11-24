"""ManageSieve authentication tests."""

import pytest

from lib.managesieve import ManageSieveError, connect_starttls, make_ssl_context


def test_auth_succeeds(cfg, managesieve_cfg, primary_account):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    client = connect_starttls(managesieve_cfg["host"], managesieve_cfg.get("port", 4190), ctx)
    client.authenticate_plain(primary_account["user"], primary_account["password"])
    client.logout()


def test_auth_wrong_password_rejected(cfg, managesieve_cfg, primary_account):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    client = connect_starttls(managesieve_cfg["host"], managesieve_cfg.get("port", 4190), ctx)
    try:
        with pytest.raises(ManageSieveError):
            client.authenticate_plain(primary_account["user"], "definitively-wrong-password-xyz")
    finally:
        client.logout()


def test_auth_mechanisms_advertised(cfg, managesieve_cfg):
    """SASL mechanisms must be advertised once TLS is established."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    client = connect_starttls(managesieve_cfg["host"], managesieve_cfg.get("port", 4190), ctx)
    try:
        mechs = client.capabilities.get("SASL", "").split()
        assert mechs, "No SASL mechanisms advertised even after STARTTLS"
    finally:
        client.logout()


def test_command_rejected_before_auth(cfg, managesieve_cfg):
    """LISTSCRIPTS before AUTHENTICATE must be refused — no session is established yet."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    client = connect_starttls(managesieve_cfg["host"], managesieve_cfg.get("port", 4190), ctx)
    try:
        with pytest.raises(ManageSieveError):
            client.list_scripts()
    finally:
        client.logout()
