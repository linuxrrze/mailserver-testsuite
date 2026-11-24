"""Shared pytest fixtures for the mailserver test suite."""

import imaplib
import smtplib
import pytest
import yaml
from pathlib import Path

from lib.imap import connect_ssl, connect_starttls, login as imap_login, logout, make_ssl_context as imap_ssl_ctx
from lib.smtp import connect_smtps, connect_submission, login as smtp_login, quit as smtp_quit, make_ssl_context as smtp_ssl_ctx
from lib.managesieve import ManageSieveClient, connect_starttls as sieve_connect_starttls, login as sieve_login, make_ssl_context as sieve_ssl_ctx


CONFIG_PATH = Path(__file__).parent / "config.yaml"
_EXAMPLE_PATH = Path(__file__).parent / "config.yaml.example"


@pytest.fixture(scope="session")
def cfg():
    if not CONFIG_PATH.exists():
        pytest.exit(
            f"\nconfig.yaml not found. Copy the example and fill in your server details:\n"
            f"  cp {_EXAMPLE_PATH.name} config.yaml\n",
            returncode=1,
        )
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="session")
def primary_account(cfg):
    return cfg["accounts"][0]


@pytest.fixture(scope="session")
def secondary_account(cfg):
    accounts = cfg["accounts"]
    if len(accounts) < 2:
        pytest.skip("Need at least two accounts configured")
    return accounts[1]


# ---------------------------------------------------------------------------
# IMAP fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def imap_ssl(cfg, primary_account):
    """Authenticated IMAPS connection, torn down after each test."""
    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    imap_login(imap, primary_account["user"], primary_account["password"])
    yield imap
    logout(imap)


@pytest.fixture
def imap_starttls(cfg, primary_account):
    """Authenticated STARTTLS IMAP connection, torn down after each test."""
    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_starttls(cfg["imap"]["host"], cfg["imap"]["port_starttls"], ctx)
    imap_login(imap, primary_account["user"], primary_account["password"])
    yield imap
    logout(imap)


@pytest.fixture
def imap(imap_ssl):
    """Default IMAP fixture (IMAPS). Tests that don't care about transport use this."""
    return imap_ssl


# ---------------------------------------------------------------------------
# SMTP fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def smtp_submission(cfg, primary_account):
    """Authenticated SMTP submission (587 + STARTTLS) connection."""
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    smtp_login(smtp, primary_account["user"], primary_account["password"])
    yield smtp
    smtp_quit(smtp)


@pytest.fixture
def smtp_smtps(cfg, primary_account):
    """Authenticated SMTPS (465) connection."""
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    smtp = connect_smtps(cfg["smtp"]["host"], cfg["smtp"]["port_smtps"], ctx)
    smtp_login(smtp, primary_account["user"], primary_account["password"])
    yield smtp
    smtp_quit(smtp)


# ---------------------------------------------------------------------------
# ManageSieve fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def managesieve_cfg(cfg):
    """ManageSieve server config; skips the whole area if unconfigured or unreachable.

    A short preflight that reads the actual greeting (rather than each
    test's own longer connect timeout) keeps a host that doesn't run the
    service from stalling every single ManageSieve test — a plain TCP
    connect can succeed (accepted by a firewall/proxy) even when nothing on
    the other end ever speaks RFC 5804, so this must read past the greeting.
    """
    ms = cfg.get("managesieve")
    if not ms or not ms.get("host"):
        pytest.skip("managesieve not configured in config.yaml — see config.yaml.example")
    host = ms["host"]
    port = ms.get("port", 4190)
    try:
        probe = ManageSieveClient(host, port, timeout=5)
        probe.logout()
    except Exception as e:
        pytest.skip(f"ManageSieve not responding at {host}:{port} ({e}) — is Pigeonhole managesieve enabled?")
    return ms


@pytest.fixture
def sieve(cfg, managesieve_cfg, primary_account):
    """Authenticated ManageSieve connection (STARTTLS), torn down after each test."""
    ctx = sieve_ssl_ctx(cfg.get("no_verify", False))
    client = sieve_connect_starttls(managesieve_cfg["host"], managesieve_cfg.get("port", 4190), ctx)
    sieve_login(client, primary_account["user"], primary_account["password"])
    yield client
    client.logout()
