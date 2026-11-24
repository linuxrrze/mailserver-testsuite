"""ManageSieve (RFC 5804) connection tests.

`managesieve.tls` selects the transport: "starttls" (RFC 5804 default — a
plaintext greeting, then STARTTLS) or "implicit" (TLS from the first byte,
e.g. behind a TLS-terminating proxy). STARTTLS-only checks skip in implicit
mode and vice versa.
"""

import pytest

from lib.managesieve import ManageSieveError, make_ssl_context
from lib.probe import DIAG_UNCONSUMED_PROXY, looks_like_command_rejection


def test_greeting_received(managesieve_endpoint):
    """The server must send its greeting without the client speaking first.

    This is the one test that FAILS when the port accepts TCP but the
    greeting never arrives (typically a reverse proxy such as Traefik peeking
    for client-first bytes because HTTP routers share the entrypoint); every
    other ManageSieve test skips with a reference to it.
    """
    _ms, result = managesieve_endpoint
    if not result.ok:
        pytest.fail(result.diagnosis)


def test_connects_plain(sieve_connect_plain):
    client = sieve_connect_plain()
    assert client.capabilities, "No capabilities advertised in the greeting"
    client.logout()


def test_starttls_connects(sieve_connect_plain, cfg):
    """STARTTLS must be advertised in the plaintext greeting and succeed."""
    client = sieve_connect_plain()
    try:
        assert "STARTTLS" in client.capabilities, (
            f"STARTTLS not advertised in the plaintext greeting: {sorted(client.capabilities)}"
        )
        try:
            client.starttls(make_ssl_context(cfg.get("no_verify", False)))
        except ManageSieveError as e:
            # STARTTLS is advertised yet rejected as an invalid command: the
            # command stream reaching the backend is corrupted — classically an
            # unconsumed PROXY-protocol header (see tests/proxy/test_command_channel).
            if looks_like_command_rejection(str(e)):
                pytest.fail(f"STARTTLS rejected as an invalid command ({e}). {DIAG_UNCONSUMED_PROXY}")
            raise
        assert client.is_tls
    finally:
        try:
            client.logout()
        except Exception:
            pass


def test_socket_is_encrypted(sieve_connect):
    """Verify the socket reports a TLS version (after STARTTLS, or from the start in implicit mode)."""
    client = sieve_connect()
    try:
        sock = client.socket()
        assert hasattr(sock, "version"), "Socket is not an SSLSocket"
        assert sock.version() is not None
    finally:
        client.logout()


def test_cert_valid(cfg, sieve_connect):
    """Connection with strict cert checking must succeed (catches expired/wrong certs)."""
    if cfg.get("no_verify", False):
        pytest.skip("no_verify is set — skipping strict cert check")
    client = sieve_connect(no_verify=False)
    client.logout()


# ---------------------------------------------------------------------------
# Implicit-TLS mode only
# ---------------------------------------------------------------------------

@pytest.fixture
def implicit_client(sieve_connect, sieve_tls_mode):
    if sieve_tls_mode != "implicit":
        pytest.skip("implicit-TLS check: managesieve.tls is 'starttls'")
    client = sieve_connect()
    yield client
    client.logout()


def test_implicit_tls_greeting_over_tls(implicit_client):
    """The greeting (with capabilities) must arrive over the TLS session itself."""
    assert implicit_client.is_tls, "Socket is not TLS-wrapped in implicit mode"
    assert implicit_client.capabilities, "No capabilities in the greeting received over TLS"


def test_implicit_tls_starttls_not_advertised(implicit_client):
    """Inside an already-encrypted session STARTTLS must not be offered."""
    assert "STARTTLS" not in implicit_client.capabilities, (
        "STARTTLS advertised inside an implicit-TLS session — the server (or the "
        "proxy's backend) apparently thinks the connection is plaintext"
    )


def test_implicit_tls_plain_offered(implicit_client):
    """SASL must list mechanisms (incl. PLAIN) once the session is encrypted.

    An empty SASL list in implicit mode usually means the backend sees a
    plaintext connection (TLS terminated at a proxy) and hides PLAIN —
    clients then cannot log in at all.
    """
    mechs = implicit_client.capabilities.get("SASL", "").upper().split()
    assert mechs, "No SASL mechanisms advertised in the implicit-TLS greeting"
    assert "PLAIN" in mechs, f"PLAIN not offered over implicit TLS; SASL = {mechs}"
