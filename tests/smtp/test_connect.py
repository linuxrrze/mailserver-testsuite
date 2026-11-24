"""SMTP connection tests."""

import smtplib
import pytest

from lib.smtp import connect_submission, connect_smtps, make_ssl_context


def test_submission_starttls_connects(cfg):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    assert smtp is not None
    smtp.quit()


def test_smtps_connects(cfg):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_smtps(cfg["smtp"]["host"], cfg["smtp"]["port_smtps"], ctx)
    assert smtp is not None
    smtp.quit()


def test_ehlo_accepted(cfg):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    code, msg = smtp.ehlo()
    assert code == 250, f"EHLO returned {code}: {msg}"
    smtp.quit()


def test_submission_socket_is_encrypted(cfg):
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    sock = smtp.sock
    assert hasattr(sock, "version"), "Socket is not an SSLSocket after STARTTLS"
    assert sock.version() is not None
    smtp.quit()


def test_cert_valid_smtp(cfg):
    if cfg.get("no_verify", False):
        pytest.skip("no_verify is set — skipping strict cert check")
    ctx = make_ssl_context(no_verify=False)
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    smtp.quit()
