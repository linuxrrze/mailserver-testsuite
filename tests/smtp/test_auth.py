"""SMTP authentication tests."""

import smtplib
import pytest

from lib.smtp import connect_submission, connect_smtps, make_ssl_context


def test_auth_succeeds(cfg, primary_account):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    smtp.login(primary_account["user"], primary_account["password"])
    smtp.quit()


def test_auth_wrong_password_rejected(cfg, primary_account):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    with pytest.raises(smtplib.SMTPAuthenticationError) as exc_info:
        smtp.login(primary_account["user"], "wrong-password-xyz")
    assert exc_info.value.smtp_code in (535, 534, 530), (
        f"Expected auth failure code, got {exc_info.value.smtp_code}"
    )
    try:
        smtp.quit()
    except Exception:
        pass


def test_auth_mechanisms_advertised(cfg):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    # After EHLO, smtplib stores ESMTP features
    esmtp = smtp.esmtp_features
    assert "auth" in esmtp, f"AUTH not in ESMTP features: {esmtp}"
    smtp.quit()
