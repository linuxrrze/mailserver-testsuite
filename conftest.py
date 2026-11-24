"""Shared pytest fixtures for the mailserver test suite."""

import os

import pytest
import yaml
from pathlib import Path

from lib.imap import connect_ssl, connect_starttls, login as imap_login, logout, make_ssl_context as imap_ssl_ctx
from lib.smtp import connect_smtps, connect_submission, login as smtp_login, quit as smtp_quit, make_ssl_context as smtp_ssl_ctx
from lib.managesieve import (
    connect as sieve_connect_plain_raw,
    connect_secure as sieve_connect_secure,
    login as sieve_login,
    make_ssl_context as sieve_ssl_ctx,
)
from lib.probe import endpoints_from_config, managesieve_tls_mode, probe_command_channel, probe_greeting
from lib.tls import make_context, register_servername


# MAILTEST_CONFIG overrides the location (e.g. to keep several server configs).
CONFIG_PATH = Path(os.environ.get("MAILTEST_CONFIG") or Path(__file__).parent / "config.yaml")
_EXAMPLE_PATH = Path(__file__).parent / "config.yaml.example"


@pytest.fixture(scope="session")
def cfg():
    if not CONFIG_PATH.exists():
        pytest.exit(
            f"\n{CONFIG_PATH} not found. Copy the example and fill in your server details:\n"
            f"  cp {_EXAMPLE_PATH.name} config.yaml\n",
            returncode=1,
        )
    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)
    # Per-protocol TLS server name (SNI) override — see lib/tls.py. Every
    # TLS context made through lib/imap, lib/smtp, lib/managesieve picks it up.
    for section in ("imap", "smtp", "managesieve"):
        sec = config.get(section) or {}
        if sec.get("host"):
            register_servername(section, sec["host"], sec.get("tls_servername"))
    return config


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
# Greeting probe (reverse-proxy awareness)
# ---------------------------------------------------------------------------

GREETING_TEST = "tests/proxy/test_greeting.py::test_server_greeting"
SIEVE_GREETING_TEST = "tests/managesieve/test_connect.py::test_greeting_received"


@pytest.fixture(scope="session")
def greeting_probe(cfg):
    """Return probe(endpoint_name) -> lib.probe.GreetingResult, cached per session.

    Endpoint names: imap-ssl, imap-starttls, smtp-submission, smtp-smtps,
    managesieve. A stalled port costs `proxy.greeting_timeout` (+ the same
    again for the probe reply) once per run, not once per test.
    """
    proxy = cfg.get("proxy") or {}
    timeout = float(proxy.get("greeting_timeout", 5))
    endpoints = endpoints_from_config(cfg)
    cache = {}

    def _probe(name):
        if name not in cache:
            if name not in endpoints:
                pytest.skip(f"endpoint {name} not configured")
            ctx = make_context(cfg.get("no_verify", False), protocol=endpoints[name].protocol)
            cache[name] = probe_greeting(
                endpoints[name], ssl_ctx=ctx, greeting_timeout=timeout, reply_timeout=timeout
            )
        return cache[name]

    return _probe


@pytest.fixture(scope="session")
def command_channel_probe(cfg):
    """Return probe(endpoint_name) -> lib.probe.CommandChannelResult, cached per session.

    Sends one benign command after the greeting to catch an unconsumed
    PROXY-protocol header (the greeting alone arrives clean). Implicit-TLS
    endpoints are skipped — there the same fault breaks the TLS handshake and
    the greeting test reports it.
    """
    proxy = cfg.get("proxy") or {}
    timeout = float(proxy.get("greeting_timeout", 5))
    endpoints = endpoints_from_config(cfg)
    cache = {}

    def _probe(name):
        if name not in endpoints:
            pytest.skip(f"endpoint {name} not configured")
        ep = endpoints[name]
        if ep.implicit_tls:
            pytest.skip(
                f"{name}: implicit-TLS endpoint — an unconsumed PROXY header breaks the "
                "TLS handshake, which the greeting test reports"
            )
        if name not in cache:
            cache[name] = probe_command_channel(ep, greeting_timeout=timeout, reply_timeout=timeout)
        return cache[name]

    return _probe


def require_greeting(greeting_probe, name, test_ref=GREETING_TEST):
    """Skip the calling fixture/test unless `name` greets normally.

    The root cause is reported as a FAILURE by the dedicated greeting test
    (`test_ref`); everything that depends on the endpoint skips with the same
    diagnosis instead of each hanging on its own read timeout.
    """
    result = greeting_probe(name)
    if not result.ok:
        ref = f"{test_ref}[{name}]" if test_ref == GREETING_TEST else test_ref
        pytest.skip(f"{name}: no usable greeting ({result.status}) — diagnosis in {ref}")
    return result


# ---------------------------------------------------------------------------
# IMAP fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def imap_ssl(cfg, primary_account, greeting_probe):
    """Authenticated IMAPS connection, torn down after each test."""
    require_greeting(greeting_probe, "imap-ssl")
    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    imap_login(imap, primary_account["user"], primary_account["password"])
    yield imap
    logout(imap)


@pytest.fixture
def imap_starttls(cfg, primary_account, greeting_probe):
    """Authenticated STARTTLS IMAP connection, torn down after each test."""
    require_greeting(greeting_probe, "imap-starttls")
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
def smtp_submission(cfg, primary_account, greeting_probe):
    """Authenticated SMTP submission (587 + STARTTLS) connection."""
    require_greeting(greeting_probe, "smtp-submission")
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    smtp_login(smtp, primary_account["user"], primary_account["password"])
    yield smtp
    smtp_quit(smtp)


@pytest.fixture
def smtp_smtps(cfg, primary_account, greeting_probe):
    """Authenticated SMTPS (465) connection."""
    require_greeting(greeting_probe, "smtp-smtps")
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    smtp = connect_smtps(cfg["smtp"]["host"], cfg["smtp"]["port_smtps"], ctx)
    smtp_login(smtp, primary_account["user"], primary_account["password"])
    yield smtp
    smtp_quit(smtp)


# ---------------------------------------------------------------------------
# ManageSieve fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def managesieve_endpoint(cfg, greeting_probe):
    """ManageSieve config + greeting probe result, WITHOUT requiring a greeting.

    Skips only when the area does not apply: not configured, host does not
    resolve, or the TCP connection is refused/unreachable. A port that
    accepts TCP but never greets is NOT a skip here — the dedicated
    test_greeting_received test fails with the probe's diagnosis.
    """
    ms = cfg.get("managesieve")
    if not ms or not ms.get("host"):
        pytest.skip("managesieve not configured in config.yaml — see config.yaml.example")
    try:
        managesieve_tls_mode(ms)
    except ValueError as e:
        pytest.fail(str(e))
    result = greeting_probe("managesieve")
    if result.not_reachable:
        pytest.skip(f"ManageSieve not reachable — {result.diagnosis}")
    return ms, result


@pytest.fixture(scope="session")
def managesieve_cfg(managesieve_endpoint):
    """ManageSieve server config for tests that need a working server.

    The session-cached greeting probe (not a plain TCP connect) is the
    preflight: a proxy can accept TCP and then never forward a greeting.
    In that case every dependent test skips with the diagnosis and a
    reference to the one test that fails for it, instead of each test
    hanging on its own read timeout.
    """
    ms, result = managesieve_endpoint
    if not result.ok:
        pytest.skip(f"no usable ManageSieve greeting ({result.status}) — diagnosis in {SIEVE_GREETING_TEST}")
    return ms


@pytest.fixture(scope="session")
def sieve_tls_mode(managesieve_cfg):
    """'starttls' (default) or 'implicit', from managesieve.tls."""
    return managesieve_tls_mode(managesieve_cfg)


@pytest.fixture
def sieve_connect(cfg, managesieve_cfg, sieve_tls_mode):
    """Factory: open an encrypted, unauthenticated ManageSieve client.

    Honours managesieve.tls (STARTTLS or implicit TLS). Pass
    no_verify=False to force strict certificate checking.
    """
    def _connect(no_verify=None, timeout=15.0):
        if no_verify is None:
            no_verify = cfg.get("no_verify", False)
        ctx = sieve_ssl_ctx(no_verify)
        return sieve_connect_secure(
            managesieve_cfg["host"], managesieve_cfg.get("port", 4190), ctx,
            mode=sieve_tls_mode, timeout=timeout,
        )
    return _connect


@pytest.fixture
def sieve_connect_plain(managesieve_cfg, sieve_tls_mode):
    """Factory: open a plaintext (pre-STARTTLS) client; skips in implicit-TLS mode."""
    if sieve_tls_mode == "implicit":
        pytest.skip(
            "STARTTLS-specific check: managesieve.tls is 'implicit', so there is "
            "no plaintext phase to test"
        )

    def _connect(timeout=15.0):
        return sieve_connect_plain_raw(managesieve_cfg["host"], managesieve_cfg.get("port", 4190), timeout=timeout)
    return _connect


@pytest.fixture
def sieve(sieve_connect, primary_account):
    """Authenticated ManageSieve connection (per managesieve.tls), torn down after each test."""
    client = sieve_connect()
    sieve_login(client, primary_account["user"], primary_account["password"])
    yield client
    client.logout()
