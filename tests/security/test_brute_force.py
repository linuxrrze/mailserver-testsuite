"""Brute force protection tests for IMAP, SMTP and ManageSieve authentication.

What a ban looks like depends on where it is enforced. Directly on the mail
host, a fail2ban firewall rule usually turns into a refused or timed-out
TCP connect. Behind a reverse proxy the TCP connect to the *proxy* still
succeeds, and the ban surfaces one step later: the proxy closes the
connection, never forwards a greeting (timeout), or answers with something
that is not the protocol at all (e.g. an HTTP error page). All of those —
any failure while connecting or reading the greeting, *after* at least one
earlier attempt connected fine — count as "protection triggered" here.

A failure on the very first attempt is not evidence of a ban (the endpoint
is simply unusable — see tests/proxy/test_greeting.py) and skips instead.
"""

import imaplib
import smtplib

import pytest

from lib.imap import connect_ssl, logout, make_ssl_context as imap_ssl_ctx
from lib.smtp import connect_submission, make_ssl_context as smtp_ssl_ctx
from lib.managesieve import ManageSieveError

# Per-attempt connect/greeting timeout: long enough for a slow server, short
# enough that a ban which manifests as silence doesn't stall the run.
CONNECT_TIMEOUT = 15

# Anything that can go wrong while opening a connection and reading the
# greeting. imaplib raises IMAP4.abort/IMAP4.error for a closed connection or
# a non-IMAP greeting; smtplib raises SMTPConnectError/SMTPServerDisconnected;
# socket timeouts, resets and TLS failures are OSErrors.
IMAP_CONNECT_ERRORS = (OSError, EOFError, imaplib.IMAP4.error)
SMTP_CONNECT_ERRORS = (OSError, smtplib.SMTPException)
SIEVE_CONNECT_ERRORS = (OSError, ManageSieveError)

PROXY_NOTE = (
    " Note: behind a reverse proxy without PROXY protocol, fail2ban on the "
    "backend only sees the proxy's IP (which is usually whitelisted, or would "
    "lock out everyone if banned) — enable PROXY protocol to the backend, or "
    "run fail2ban/rate limiting at the proxy."
)


def _first_attempt_failed(proto, e):
    pytest.skip(
        f"{proto}: could not connect even on the first attempt ({type(e).__name__}: {e}) — "
        "that is an unusable endpoint, not evidence of a ban; see tests/proxy/test_greeting.py"
    )


@pytest.mark.full
def test_imap_wrong_password_always_rejected(cfg, primary_account):
    """The server must never accept a wrong password regardless of attempt count."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 10)
    host = cfg["imap"]["host"]
    port = cfg["imap"]["port_ssl"]

    for i in range(attempts):
        try:
            imap = connect_ssl(host, port, imap_ssl_ctx(cfg.get("no_verify", False)), timeout=CONNECT_TIMEOUT)
        except IMAP_CONNECT_ERRORS as e:
            if i == 0:
                _first_attempt_failed("IMAP", e)
            return  # blocked at connect/greeting — protection is working
        try:
            typ, data = imap.login(primary_account["user"], f"wrong-brute-{i}")
            # If we get here without exception the server accepted a bad password
            pytest.fail(f"Server accepted wrong password on attempt {i}: {typ} {data}")
        except (imaplib.IMAP4.error, OSError):
            pass  # expected auth failure (or connection dropped mid-login)
        finally:
            logout(imap)


@pytest.mark.full
def test_imap_repeated_failures_trigger_protection(cfg, primary_account):
    """Repeated IMAP login failures must eventually trigger rate limiting or a block."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 10)
    host = cfg["imap"]["host"]
    port = cfg["imap"]["port_ssl"]

    got_blocked = False
    for i in range(attempts):
        try:
            imap = connect_ssl(host, port, imap_ssl_ctx(cfg.get("no_verify", False)), timeout=CONNECT_TIMEOUT)
        except IMAP_CONNECT_ERRORS as e:
            if i == 0:
                _first_attempt_failed("IMAP", e)
            got_blocked = True
            break
        try:
            imap.login(primary_account["user"], f"wrong-brute-{i}")
        except (imaplib.IMAP4.error, OSError):
            pass
        finally:
            logout(imap)

    if not got_blocked:
        pytest.xfail(
            f"No IP-level block after {attempts} failed IMAP logins — "
            "verify that fail2ban or equivalent is active." + PROXY_NOTE
        )


@pytest.mark.full
def test_smtp_wrong_password_always_rejected(cfg, primary_account):
    """SMTP AUTH must never accept a wrong password regardless of attempt count."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 5)
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    try:
        smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx, timeout=CONNECT_TIMEOUT)
    except SMTP_CONNECT_ERRORS as e:
        _first_attempt_failed("SMTP", e)

    for i in range(attempts):
        try:
            smtp.login(primary_account["user"], f"wrong-brute-{i}")
            pytest.fail(f"SMTP accepted wrong password on attempt {i}")
        except smtplib.SMTPAuthenticationError:
            pass  # correct rejection
        except smtplib.SMTPServerDisconnected:
            # Server closed connection after failures — protection working
            return
        except Exception:
            return

    try:
        smtp.quit()
    except Exception:
        pass


@pytest.mark.full
def test_smtp_repeated_failures_trigger_protection(cfg, primary_account):
    """Multiple failed SMTP AUTH attempts must cause disconnect, 454, or a block on reconnect."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 5)
    host = cfg["smtp"]["host"]
    port = cfg["smtp"]["port_submission"]
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    try:
        smtp = connect_submission(host, port, ctx, timeout=CONNECT_TIMEOUT)
    except SMTP_CONNECT_ERRORS as e:
        _first_attempt_failed("SMTP", e)

    got_protection = False
    for i in range(attempts):
        try:
            smtp.login(primary_account["user"], f"wrong-brute-{i}")
        except smtplib.SMTPAuthenticationError as e:
            if e.smtp_code == 454:   # temporary auth failure — rate limiting
                got_protection = True
                break
        except smtplib.SMTPServerDisconnected:
            got_protection = True
            break
        except Exception:
            break

    try:
        smtp.quit()
    except Exception:
        pass

    if not got_protection:
        # A ban (fail2ban, proxy rate limit) shows up on the *next* connection.
        try:
            fresh = connect_submission(host, port, ctx, timeout=CONNECT_TIMEOUT)
        except SMTP_CONNECT_ERRORS:
            got_protection = True
        else:
            try:
                fresh.quit()
            except Exception:
                pass

    if not got_protection:
        pytest.xfail(
            f"No 454/disconnect/reconnect block after {attempts} failed SMTP AUTH attempts — "
            "verify that auth failure handling / fail2ban is configured." + PROXY_NOTE
        )


@pytest.mark.full
def test_managesieve_wrong_password_always_rejected(cfg, sieve_connect, primary_account):
    """The server must never accept a wrong password regardless of attempt count."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 10)

    for i in range(attempts):
        try:
            client = sieve_connect(timeout=CONNECT_TIMEOUT)
        except SIEVE_CONNECT_ERRORS as e:
            if i == 0:
                _first_attempt_failed("ManageSieve", e)
            return  # blocked at connect/greeting — protection is working
        try:
            client.authenticate_plain(primary_account["user"], f"wrong-brute-{i}")
            pytest.fail(f"Server accepted wrong password on attempt {i}")
        except (ManageSieveError, OSError):
            pass  # expected auth failure (or connection dropped mid-auth)
        finally:
            client.logout()


@pytest.mark.full
def test_managesieve_repeated_failures_trigger_protection(cfg, sieve_connect, primary_account):
    """Repeated ManageSieve AUTHENTICATE failures must eventually trigger rate limiting or a block."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 10)

    got_blocked = False
    for i in range(attempts):
        try:
            client = sieve_connect(timeout=CONNECT_TIMEOUT)
        except SIEVE_CONNECT_ERRORS as e:
            if i == 0:
                _first_attempt_failed("ManageSieve", e)
            got_blocked = True
            break
        try:
            client.authenticate_plain(primary_account["user"], f"wrong-brute-{i}")
        except (ManageSieveError, OSError):
            pass
        finally:
            client.logout()

    if not got_blocked:
        pytest.xfail(
            f"No IP-level block after {attempts} failed ManageSieve auth attempts — "
            "verify that fail2ban or equivalent is active." + PROXY_NOTE
        )
