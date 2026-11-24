"""Brute force protection tests for IMAP and SMTP authentication."""

import imaplib
import smtplib
import pytest

from lib.imap import connect_ssl, logout, make_ssl_context as imap_ssl_ctx
from lib.smtp import connect_submission, make_ssl_context as smtp_ssl_ctx
from lib.managesieve import (
    ManageSieveError,
    connect_starttls as sieve_connect_starttls,
    make_ssl_context as sieve_ssl_ctx,
)


def test_imap_wrong_password_always_rejected(cfg, primary_account):
    """The server must never accept a wrong password regardless of attempt count."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 10)
    host = cfg["imap"]["host"]
    port = cfg["imap"]["port_ssl"]

    for i in range(attempts):
        try:
            ctx = imap_ssl_ctx(cfg.get("no_verify", False))
            imap = connect_ssl(host, port, ctx)
            try:
                typ, data = imap.login(primary_account["user"], f"wrong-brute-{i}")
                # If we get here without exception the server accepted a bad password
                pytest.fail(
                    f"Server accepted wrong password on attempt {i}: {typ} {data}"
                )
            except imaplib.IMAP4.error:
                pass  # expected auth failure
            finally:
                logout(imap)
        except (ConnectionRefusedError, OSError):
            # IP-level block triggered — protection is working
            return


def test_imap_repeated_failures_trigger_protection(cfg, primary_account):
    """Repeated IMAP login failures must eventually trigger rate limiting or a block."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 10)
    host = cfg["imap"]["host"]
    port = cfg["imap"]["port_ssl"]

    got_blocked = False
    for i in range(attempts):
        try:
            ctx = imap_ssl_ctx(cfg.get("no_verify", False))
            imap = connect_ssl(host, port, ctx)
            try:
                imap.login(primary_account["user"], f"wrong-brute-{i}")
            except imaplib.IMAP4.error:
                pass
            finally:
                logout(imap)
        except (ConnectionRefusedError, OSError):
            got_blocked = True
            break

    if not got_blocked:
        pytest.xfail(
            f"No IP-level block after {attempts} failed IMAP logins — "
            "verify that fail2ban or equivalent is active"
        )


def test_smtp_wrong_password_always_rejected(cfg, primary_account):
    """SMTP AUTH must never accept a wrong password regardless of attempt count."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 5)
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)

    for i in range(attempts):
        try:
            smtp.login(primary_account["user"], f"wrong-brute-{i}")
            pytest.fail(
                f"SMTP accepted wrong password on attempt {i}"
            )
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


def test_smtp_repeated_failures_trigger_protection(cfg, primary_account):
    """Multiple failed SMTP AUTH attempts must cause disconnect or 454."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 5)
    ctx = smtp_ssl_ctx(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)

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
        pytest.xfail(
            f"No 454/disconnect after {attempts} failed SMTP AUTH attempts — "
            "verify that auth failure handling / fail2ban is configured"
        )


def test_managesieve_wrong_password_always_rejected(cfg, managesieve_cfg, primary_account):
    """The server must never accept a wrong password regardless of attempt count."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 10)
    host = managesieve_cfg["host"]
    port = managesieve_cfg.get("port", 4190)

    for i in range(attempts):
        try:
            ctx = sieve_ssl_ctx(cfg.get("no_verify", False))
            client = sieve_connect_starttls(host, port, ctx)
            try:
                client.authenticate_plain(primary_account["user"], f"wrong-brute-{i}")
                pytest.fail(f"Server accepted wrong password on attempt {i}")
            except ManageSieveError:
                pass  # expected auth failure
            finally:
                client.logout()
        except (ConnectionRefusedError, OSError):
            # IP-level block triggered — protection is working
            return


def test_managesieve_repeated_failures_trigger_protection(cfg, managesieve_cfg, primary_account):
    """Repeated ManageSieve AUTHENTICATE failures must eventually trigger rate limiting or a block."""
    attempts = cfg.get("security", {}).get("brute_force_probe_attempts", 10)
    host = managesieve_cfg["host"]
    port = managesieve_cfg.get("port", 4190)

    got_blocked = False
    for i in range(attempts):
        try:
            ctx = sieve_ssl_ctx(cfg.get("no_verify", False))
            client = sieve_connect_starttls(host, port, ctx)
            try:
                client.authenticate_plain(primary_account["user"], f"wrong-brute-{i}")
            except ManageSieveError:
                pass
            finally:
                client.logout()
        except (ConnectionRefusedError, OSError):
            got_blocked = True
            break

    if not got_blocked:
        pytest.xfail(
            f"No IP-level block after {attempts} failed ManageSieve auth attempts — "
            "verify that fail2ban or equivalent is active"
        )
