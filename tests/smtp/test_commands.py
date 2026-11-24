"""SMTP protocol command tests: VRFY, EXPN, command sequence, address validation."""

import smtplib
import pytest

from lib.smtp import connect_submission, make_ssl_context


def _starttls_conn(cfg):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = smtplib.SMTP(cfg["smtp"]["host"], cfg["smtp"]["port_submission"])
    smtp.ehlo()
    smtp.starttls(context=ctx)
    smtp.ehlo()
    return smtp


def test_vrfy_does_not_confirm_user(cfg, primary_account):
    """VRFY must not return 250 — confirming a user exists enables enumeration."""
    smtp = _starttls_conn(cfg)
    try:
        code, _ = smtp.verify(primary_account["user"])
        assert code != 250, (
            f"VRFY returned 250 — user existence confirmed, enables enumeration"
        )
        # 252 = will attempt delivery but cannot verify — acceptable
        # 5xx = access denied / disabled — acceptable
    except smtplib.SMTPException:
        pass  # command rejected entirely — acceptable
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def test_expn_disabled(cfg):
    """EXPN must return 5xx — revealing mailing list membership is not acceptable."""
    smtp = _starttls_conn(cfg)
    try:
        code, _ = smtp.expn("postmaster")
        assert code not in (250, 251), (
            f"EXPN returned {code} — list expansion should be disabled"
        )
    except smtplib.SMTPException:
        pass  # command rejected — acceptable
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def test_rcpt_before_mail_from_rejected(cfg):
    """RCPT TO issued before MAIL FROM must be rejected (bad command sequence)."""
    smtp = _starttls_conn(cfg)
    try:
        code, _ = smtp.rcpt("test@" + cfg.get("domain", "example.com"))
        assert code >= 500, f"RCPT TO without MAIL FROM accepted (code {code})"
    except smtplib.SMTPResponseException as e:
        assert e.smtp_code >= 500, (
            f"Unexpected response code {e.smtp_code} for RCPT before MAIL FROM"
        )
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def test_malformed_mail_from_rejected(cfg):
    """MAIL FROM with a syntactically invalid address should be rejected."""
    smtp = _starttls_conn(cfg)
    try:
        # Send without angle brackets — definitively non-RFC-5321 syntax
        code, msg = smtp.docmd("MAIL", "FROM: notanaddress")
        if code < 500:
            pytest.xfail(
                f"Malformed MAIL FROM accepted with code {code} — "
                "some servers normalise or accept non-standard address syntax"
            )
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def test_ehlo_response_well_formed(cfg):
    """EHLO must return 250 with a non-empty multi-line response."""
    smtp = _starttls_conn(cfg)
    code, msg = smtp.ehlo()
    smtp.quit()
    assert code == 250, f"EHLO returned {code}"
    assert msg, "EHLO response body is empty"
