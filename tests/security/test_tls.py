"""TLS security tests for IMAP and SMTP."""

import imaplib
import smtplib
import ssl
import time

import pytest

from lib.imap import connect_ssl, connect_starttls, logout, get_capabilities, make_ssl_context as imap_ssl_ctx
from lib.smtp import connect_submission, connect_smtps, make_ssl_context as smtp_ssl_ctx
from lib.managesieve import ManageSieveError

WEAK_CIPHERS = [
    "RC4", "RC2", "DES", "3DES", "NULL", "EXPORT", "anon",
    "MD5",   # as a key exchange/auth, not hash
]

MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2


def _tls_version_ok(version_str: str) -> bool:
    mapping = {
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    v = mapping.get(version_str)
    if v is None:
        return False
    return v >= MIN_TLS_VERSION


# ---------------------------------------------------------------------------
# IMAP TLS
# ---------------------------------------------------------------------------

def test_imap_tls_version(cfg):
    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    try:
        version = imap.socket().version()
        assert _tls_version_ok(version), (
            f"IMAP TLS version {version!r} is below TLS 1.2"
        )
    finally:
        logout(imap)


def test_imap_starttls_tls_version(cfg):
    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_starttls(cfg["imap"]["host"], cfg["imap"]["port_starttls"], ctx)
    try:
        version = imap.socket().version()
        assert _tls_version_ok(version), (
            f"IMAP STARTTLS version {version!r} is below TLS 1.2"
        )
    finally:
        logout(imap)


def test_imap_cipher_not_weak(cfg):
    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    try:
        cipher_name, _, _ = imap.socket().cipher()
        for weak in WEAK_CIPHERS:
            assert weak.lower() not in cipher_name.lower(), (
                f"Weak cipher in use: {cipher_name!r}"
            )
    finally:
        logout(imap)


def test_imap_cert_not_expired(cfg):
    if cfg.get("no_verify", False):
        pytest.skip("no_verify is set — skipping cert expiry check")
    ctx = imap_ssl_ctx(no_verify=False)
    # If the cert is expired, create_default_context will raise during connect
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    logout(imap)


# ---------------------------------------------------------------------------
# SMTP TLS
# ---------------------------------------------------------------------------

def test_smtp_tls_version(cfg):
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    try:
        version = smtp.sock.version()
        assert _tls_version_ok(version), (
            f"SMTP TLS version {version!r} is below TLS 1.2"
        )
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def test_smtp_cipher_not_weak(cfg):
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    try:
        cipher_name, _, _ = smtp.sock.cipher()
        for weak in WEAK_CIPHERS:
            assert weak.lower() not in cipher_name.lower(), (
                f"Weak cipher in use on SMTP: {cipher_name!r}"
            )
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def test_smtp_plain_auth_not_offered_before_starttls(cfg):
    """AUTH must not be advertised before STARTTLS on port 587."""
    host = cfg["smtp"]["host"]
    port = cfg["smtp"]["port_submission"]

    raw = smtplib.SMTP(host, port)
    raw.ehlo()
    features_before_starttls = dict(raw.esmtp_features)
    raw.quit()

    # AUTH should not be in the EHLO response on a plain connection
    assert "auth" not in features_before_starttls, (
        "AUTH offered before STARTTLS — plain-text credential exposure risk"
    )


def test_smtp_auth_rejected_without_tls(cfg, primary_account):
    """Attempting AUTH over a plain connection (before STARTTLS) must be refused."""
    host = cfg["smtp"]["host"]
    port = cfg["smtp"]["port_submission"]

    smtp = smtplib.SMTP(host, port)
    smtp.ehlo()
    # Do NOT call starttls() — attempt login over the plain connection
    try:
        with pytest.raises(smtplib.SMTPException) as exc_info:
            smtp.login(primary_account["user"], primary_account["password"])
        code = getattr(exc_info.value, "smtp_code", None)
        # 530 = must issue STARTTLS first, 538 = encryption required, 503 = bad sequence
        # None = SMTPNotSupportedError (AUTH simply not offered on plain connection)
        assert code in (530, 538, 503, None), (
            f"Expected STARTTLS-required error (530/538/503) or AUTH not offered, "
            f"got {code}: {exc_info.value}"
        )
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def test_imap_logindisabled_before_starttls(cfg):
    """LOGINDISABLED must be advertised before STARTTLS — prevents plaintext credential exposure.

    Behind a reverse proxy this matters more: Dovecot treats connections
    from loopback / login_trusted_networks as secured, so if the proxy
    forwards from such an address the backend may allow plaintext LOGIN
    for every client.
    """
    imap = imaplib.IMAP4(cfg["imap"]["host"], cfg["imap"]["port_starttls"])
    try:
        caps = get_capabilities(imap)
        assert "LOGINDISABLED" in caps, (
            f"LOGINDISABLED not in pre-STARTTLS CAPABILITY: {caps} — "
            "server may allow credentials over an unencrypted connection"
        )
    finally:
        logout(imap)


def test_imap_starttls_not_advertised_after_starttls(cfg):
    """STARTTLS must not appear in CAPABILITY after it has already been issued."""
    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_starttls(cfg["imap"]["host"], cfg["imap"]["port_starttls"], ctx)
    try:
        caps = get_capabilities(imap)
        assert "STARTTLS" not in caps, (
            "STARTTLS still advertised after STARTTLS was issued — server should remove it"
        )
    finally:
        logout(imap)


def test_imap_logindisabled_removed_after_starttls(cfg):
    """LOGINDISABLED must disappear from CAPABILITY once TLS is established."""
    imap = imaplib.IMAP4(cfg["imap"]["host"], cfg["imap"]["port_starttls"])
    caps_before = get_capabilities(imap)

    if "LOGINDISABLED" not in caps_before:
        logout(imap)
        pytest.skip("LOGINDISABLED not present before STARTTLS — skipping post-STARTTLS check")

    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    typ, _ = imap.starttls(ctx)
    assert typ == "OK", f"STARTTLS failed: {typ}"

    caps_after = get_capabilities(imap)
    logout(imap)

    assert "LOGINDISABLED" not in caps_after, (
        "LOGINDISABLED still present after STARTTLS — LOGIN blocked even over TLS"
    )


def test_imap_login_rejected_without_tls(cfg, primary_account):
    """Attempting LOGIN over a plain IMAP connection (no STARTTLS) must be refused.

    Behind a reverse proxy this matters more: Dovecot treats connections
    from loopback / login_trusted_networks as secured, so if the proxy
    forwards from such an address the backend may allow plaintext LOGIN
    for every client.
    """
    host = cfg["imap"]["host"]
    port = cfg["imap"]["port_starttls"]

    imap = imaplib.IMAP4(host, port)
    # Do NOT issue STARTTLS — attempt login over the plain connection
    try:
        typ, data = imap.login(primary_account["user"], primary_account["password"])
        # If the server answered OK it accepted plaintext credentials — that is the failure
        pytest.fail(
            f"Server accepted LOGIN over unencrypted connection: {typ} {data}"
        )
    except imaplib.IMAP4.error as e:
        # Expected: server rejected the login (e.g. [PRIVACYREQUIRED])
        msg = str(e).lower()
        assert any(kw in msg for kw in ("privacy", "encrypt", "starttls", "tls", "secure")), (
            f"LOGIN was rejected but not with a privacy/TLS error: {e}"
        )
    finally:
        try:
            imap.logout()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# ManageSieve TLS — all connections go through the `sieve_connect` /
# `sieve_connect_plain` fixtures, which honour managesieve.tls
# (starttls | implicit); plaintext-phase checks skip in implicit mode.
# ---------------------------------------------------------------------------

# Warn when the ManageSieve certificate expires sooner than this. Basic
# validity (expired / wrong host) is covered by
# tests/managesieve/test_connect.py::test_cert_valid.
DEFAULT_CERT_MIN_DAYS = 14


def test_managesieve_tls_version(sieve_connect):
    client = sieve_connect()
    try:
        version = client.socket().version()
        assert _tls_version_ok(version), (
            f"ManageSieve TLS version {version!r} is below TLS 1.2"
        )
    finally:
        client.logout()


def test_managesieve_cipher_not_weak(sieve_connect):
    client = sieve_connect()
    try:
        cipher_name, _, _ = client.socket().cipher()
        for weak in WEAK_CIPHERS:
            assert weak.lower() not in cipher_name.lower(), (
                f"Weak cipher in use on ManageSieve: {cipher_name!r}"
            )
    finally:
        client.logout()


def test_managesieve_cert_expiry_margin(cfg, sieve_connect):
    """The ManageSieve certificate must stay valid for a safety margin.

    Catches a renewal job that stopped deploying to this service (common
    when the cert is copied to a proxy or a separate port by hand). The
    margin is security.cert_min_days_remaining (default 14).
    """
    if cfg.get("no_verify", False):
        pytest.skip("no_verify is set — certificate details are not available")
    min_days = (cfg.get("security") or {}).get("cert_min_days_remaining", DEFAULT_CERT_MIN_DAYS)
    client = sieve_connect(no_verify=False)
    try:
        cert = client.socket().getpeercert()
    finally:
        client.logout()
    not_after = cert.get("notAfter") if cert else None
    if not not_after:
        pytest.skip("Peer certificate has no notAfter field")
    days_left = (ssl.cert_time_to_seconds(not_after) - time.time()) / 86400
    assert days_left >= min_days, (
        f"ManageSieve certificate expires in {days_left:.1f} days ({not_after}); "
        f"threshold is {min_days} days — is renewal deployed to this service?"
    )


def test_managesieve_starttls_not_advertised_after_starttls(sieve_connect, sieve_tls_mode):
    """STARTTLS must not appear in CAPABILITY after it has already been issued.

    (Implicit-TLS counterpart: tests/managesieve/test_connect.py::
    test_implicit_tls_starttls_not_advertised.)
    """
    if sieve_tls_mode == "implicit":
        pytest.skip("STARTTLS-specific check: managesieve.tls is 'implicit'")
    client = sieve_connect()
    try:
        assert "STARTTLS" not in client.capabilities, (
            "STARTTLS still advertised after STARTTLS was issued — server should remove it"
        )
    finally:
        client.logout()


def test_managesieve_plaintext_sasl_not_offered_before_starttls(sieve_connect_plain):
    """PLAIN/LOGIN must not be offered pre-STARTTLS — prevents plaintext credential exposure.

    This matters even more behind a reverse proxy: the backend sees every
    connection coming from the proxy's address, and Dovecot treats
    connections from loopback or login_trusted_networks as "secured" — so
    plaintext auth (disable_plaintext_auth / auth_allow_cleartext) can end
    up silently enabled for *every* client that comes in via the proxy path.
    Skipped in implicit-TLS mode (no plaintext phase).
    """
    client = sieve_connect_plain()
    try:
        mechs = {m.upper() for m in client.capabilities.get("SASL", "").split()}
        plaintext = mechs & {"PLAIN", "LOGIN"}
        assert not plaintext, (
            f"Plaintext SASL mechanisms offered before STARTTLS: {plaintext} — "
            "credentials could be sent unencrypted (behind a proxy: is the proxy's "
            "address in login_trusted_networks, or is it connecting via loopback?)"
        )
    finally:
        client.logout()


def test_managesieve_auth_rejected_without_tls(sieve_connect_plain, primary_account):
    """AUTHENTICATE over a plain connection (before STARTTLS) must be refused.

    Behind a reverse proxy Dovecot may consider the proxied connection
    secured (loopback / login_trusted_networks) and accept cleartext
    credentials that actually crossed the network unencrypted — this is
    the end-to-end check for that. Skipped in implicit-TLS mode.
    """
    client = sieve_connect_plain()
    try:
        try:
            client.authenticate_plain(primary_account["user"], primary_account["password"])
        except ManageSieveError:
            return  # expected — server refused plaintext auth
        pytest.fail("Server accepted AUTHENTICATE over an unencrypted ManageSieve connection")
    finally:
        client.logout()
