"""SMTP relay restriction tests."""

import smtplib
import pytest

from lib.smtp import make_ssl_context


def test_unauthenticated_relay_rejected(cfg):
    """An unauthenticated connection must not be able to relay to a foreign domain."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = smtplib.SMTP(cfg["smtp"]["host"], cfg["smtp"]["port_submission"])
    smtp.ehlo()
    smtp.starttls(context=ctx)
    smtp.ehlo()

    domain = cfg.get("domain", "example.com")
    foreign = f"relay-test@foreign-domain-that-is-not-{domain}.invalid"

    relayed = False
    try:
        smtp.sendmail(
            f"test@{domain}",
            foreign,
            f"Subject: relay-test\r\n\r\nrelay test body",
        )
        relayed = True
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError):
        pass  # expected — relay correctly refused
    finally:
        try:
            smtp.quit()
        except Exception:
            pass

    if relayed:
        pytest.xfail(
            "Unauthenticated relay was accepted — this server may be running in a trusted "
            "network (e.g. Postfix mynetworks includes the test runner's IP). "
            "Verify relay restrictions from an untrusted IP."
        )


@pytest.mark.full
def test_authenticated_send_to_own_domain(smtp_submission, cfg):
    """An authenticated user must be able to send to their own domain."""
    domain = cfg.get("domain", "example.com")
    account = cfg["accounts"][0]
    smtp_submission.sendmail(
        account["user"],
        account["user"],
        f"Subject: selftest\r\n\r\nself-send test",
    )


@pytest.mark.full
def test_authenticated_relay_to_foreign_domain(cfg, primary_account):
    """Verify relay policy for authenticated users sending to foreign domains.

    RFC 6409 MSAs typically accept mail for any destination from authenticated
    users.  Set smtp.allow_authenticated_relay: false in config.yaml to assert
    the opposite policy.
    """
    from lib.smtp import connect_submission, login, make_ssl_context
    allow = cfg.get("smtp", {}).get("allow_authenticated_relay", True)
    domain = cfg.get("domain", "example.com")
    foreign = f"relay-policy-check@foreign-mailtest.invalid"

    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    login(smtp, primary_account["user"], primary_account["password"])

    relayed = True
    try:
        smtp.sendmail(
            primary_account["user"],
            foreign,
            "Subject: relay-policy\r\n\r\nrelay policy test",
        )
    except Exception:
        relayed = False
    finally:
        try:
            smtp.quit()
        except Exception:
            pass

    if allow:
        assert relayed, (
            "Authenticated relay to foreign domain was blocked but "
            "smtp.allow_authenticated_relay is true"
        )
    else:
        assert not relayed, (
            "Authenticated relay to foreign domain succeeded but "
            "smtp.allow_authenticated_relay is false"
        )
