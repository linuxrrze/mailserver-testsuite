"""SMTP connection helpers."""

import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional

from lib.tls import make_context


def make_ssl_context(no_verify: bool = False) -> ssl.SSLContext:
    """Client TLS context; honours `smtp.tls_servername` (see lib/tls.py)."""
    return make_context(no_verify, protocol="smtp")


# Socket timeout for every connection opened through these helpers. Without
# one, a port that accepts TCP but never greets (e.g. a reverse proxy
# peeking for client-first bytes) blocks the test run forever.
DEFAULT_TIMEOUT = 30.0


def connect_smtps(
    host: str, port: int, ssl_ctx: ssl.SSLContext, timeout: float = DEFAULT_TIMEOUT
) -> smtplib.SMTP_SSL:
    return smtplib.SMTP_SSL(host, port, context=ssl_ctx, timeout=timeout)


def connect_submission(
    host: str, port: int, ssl_ctx: ssl.SSLContext, timeout: float = DEFAULT_TIMEOUT
) -> smtplib.SMTP:
    smtp = smtplib.SMTP(host, port, timeout=timeout)
    smtp.ehlo()
    smtp.starttls(context=ssl_ctx)
    smtp.ehlo()
    return smtp


def login(smtp: smtplib.SMTP, user: str, password: str) -> None:
    smtp.login(user, password)


def quit(smtp: smtplib.SMTP) -> None:
    try:
        smtp.quit()
    except Exception:
        pass


def build_message(
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    message_id: Optional[str] = None,
) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    if message_id:
        msg["Message-ID"] = message_id
    msg.set_content(body)
    return msg
