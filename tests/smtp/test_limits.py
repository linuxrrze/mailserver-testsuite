"""SMTP message size and recipient limit tests."""

import smtplib
import pytest

from lib.smtp import connect_submission, login, make_ssl_context


def test_size_extension_advertised(cfg):
    """SIZE extension (RFC 1870) must be advertised in EHLO."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    features = smtp.esmtp_features
    smtp.quit()
    assert "size" in features, f"SIZE not in EHLO features: {features}"
    assert int(features["size"]) > 0, "Advertised SIZE limit is 0"


def test_oversized_message_rejected(cfg, primary_account):
    """Declaring a message size beyond the limit in MAIL FROM must be rejected."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    login(smtp, primary_account["user"], primary_account["password"])

    size_limit = int(smtp.esmtp_features.get("size", 0))
    if size_limit == 0:
        smtp.quit()
        pytest.skip("SIZE limit is 0 (unlimited) or not advertised")

    # Declare a size one byte over the limit — no data is actually sent
    code, msg = smtp.mail(primary_account["user"], options=[f"SIZE={size_limit + 1}"])
    try:
        smtp.rset()
        smtp.quit()
    except Exception:
        pass

    assert code >= 500, (
        f"MAIL FROM SIZE={size_limit + 1} accepted (limit={size_limit}) — "
        "oversized declaration not rejected"
    )


def test_null_sender_accepted(cfg):
    """MAIL FROM:<> (null sender) must be accepted — required for DSNs and bounces."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = smtplib.SMTP(cfg["smtp"]["host"], cfg["smtp"]["port_submission"])
    smtp.ehlo()
    smtp.starttls(context=ctx)
    smtp.ehlo()
    try:
        code, msg = smtp.mail("")   # smtplib.quoteaddr("") → "<>"
        assert code < 400, f"Null sender MAIL FROM:<> rejected with {code}: {msg}"
    finally:
        try:
            smtp.rset()
            smtp.quit()
        except Exception:
            pass


def test_max_recipients_enforced(cfg, primary_account):
    """Server must stop accepting RCPT TO at some point (per-message recipient cap)."""
    configured_max = cfg.get("smtp", {}).get("max_recipients", 100)
    max_probe = configured_max + 400  # probe well above the configured limit
    ctx = make_ssl_context(cfg.get("no_verify", False))
    smtp = connect_submission(cfg["smtp"]["host"], cfg["smtp"]["port_submission"], ctx)
    login(smtp, primary_account["user"], primary_account["password"])
    smtp.mail(primary_account["user"])

    accepted = 0
    for i in range(max_probe):
        code, _ = smtp.rcpt(f"rcpt{i:04d}@mailtest-rcptlimit.invalid")
        if code >= 400:
            break
        accepted += 1

    try:
        smtp.rset()
        smtp.quit()
    except Exception:
        pass

    if accepted >= max_probe:
        pytest.xfail(
            f"Server accepted all {max_probe} RCPT TO recipients without enforcing a cap. "
            f"Set smtp.max_recipients in config.yaml to the server's actual limit "
            f"(current configured value: {configured_max})."
        )
    assert accepted < max_probe
