"""End-to-end outgoing header checks: Message-ID, DKIM-Signature, Received."""

import time
import uuid
import pytest

from lib.imap import connect_ssl, login as imap_login, logout, make_ssl_context as imap_ssl_ctx
from lib.smtp import build_message

POLL_INTERVAL = 2
MAX_WAIT = 30


def _send_and_fetch_header(cfg, primary_account, smtp_submission):
    uid = uuid.uuid4().hex
    subject = f"header-check-{uid}"
    msg = build_message(
        from_addr=primary_account["user"],
        to_addr=primary_account["user"],
        subject=subject,
        body=f"Header check {uid}",
        message_id=f"<{uid}@mailtest>",
    )
    smtp_submission.send_message(msg)

    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    imap_login(imap, primary_account["user"], primary_account["password"])

    deadline = time.monotonic() + MAX_WAIT
    ids = []
    while time.monotonic() < deadline:
        imap.select("INBOX")
        typ, data = imap.search(None, f'SUBJECT "{subject}"')
        if typ == "OK" and data[0]:
            ids = data[0].split()
            break
        time.sleep(POLL_INTERVAL)

    header = ""
    if ids:
        typ, fetch_data = imap.fetch(ids[0], "(RFC822.HEADER)")
        if typ == "OK":
            header = fetch_data[0][1].decode("utf-8", errors="replace")
        for mid in ids:
            imap.store(mid, "+FLAGS", "\\Deleted")
        imap.expunge()

    logout(imap)
    return header, uid


def test_message_id_present(cfg, primary_account, smtp_submission):
    """Delivered message must carry a Message-ID header."""
    header, uid = _send_and_fetch_header(cfg, primary_account, smtp_submission)
    assert header, f"Message never arrived (uid={uid})"
    assert "Message-ID:" in header, "Message-ID header missing from delivered message"


def test_dkim_signature_present(cfg, primary_account, smtp_submission):
    """Outgoing messages must be DKIM-signed (DKIM-Signature header present)."""
    header, uid = _send_and_fetch_header(cfg, primary_account, smtp_submission)
    assert header, f"Message never arrived (uid={uid})"
    assert "DKIM-Signature:" in header, (
        "DKIM-Signature header absent — outgoing mail is not DKIM-signed"
    )


def test_received_header_present(cfg, primary_account, smtp_submission):
    """Delivered message must have at least one Received header."""
    header, uid = _send_and_fetch_header(cfg, primary_account, smtp_submission)
    assert header, f"Message never arrived (uid={uid})"
    assert "Received:" in header, "Received header missing from delivered message"
