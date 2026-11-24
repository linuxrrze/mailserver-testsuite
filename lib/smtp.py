"""SMTP connection helpers."""

import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional


def make_ssl_context(no_verify: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if no_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def connect_smtps(host: str, port: int, ssl_ctx: ssl.SSLContext) -> smtplib.SMTP_SSL:
    return smtplib.SMTP_SSL(host, port, context=ssl_ctx)


def connect_submission(host: str, port: int, ssl_ctx: ssl.SSLContext) -> smtplib.SMTP:
    smtp = smtplib.SMTP(host, port)
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
