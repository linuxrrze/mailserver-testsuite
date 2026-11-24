"""End-to-end: send via SMTP, verify arrival via IMAP."""

import imaplib
import time
import uuid
import pytest

from lib.imap import connect_ssl, login as imap_login, logout, make_ssl_context as imap_ssl_ctx
from lib.smtp import build_message


POLL_INTERVAL = 2   # seconds between IMAP polls
MAX_WAIT = 30       # seconds before giving up


def _wait_for_message(imap, subject, timeout=MAX_WAIT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        imap.select("INBOX")
        typ, data = imap.search(None, f'SUBJECT "{subject}"')
        if typ == "OK" and data[0]:
            return data[0].split()
        time.sleep(POLL_INTERVAL)
    return []


def test_send_and_receive(cfg, primary_account, smtp_submission):
    uid = uuid.uuid4().hex
    subject = f"e2e-test-{uid}"
    msg = build_message(
        from_addr=primary_account["user"],
        to_addr=primary_account["user"],
        subject=subject,
        body=f"End-to-end test message {uid}",
        message_id=f"<{uid}@mailtest>",
    )
    smtp_submission.send_message(msg)

    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    imap_login(imap, primary_account["user"], primary_account["password"])
    try:
        ids = _wait_for_message(imap, subject)
        assert ids, f"Message with subject {subject!r} never arrived in INBOX within {MAX_WAIT}s"

        typ, data = imap.fetch(ids[0], "(RFC822.HEADER)")
        assert typ == "OK"
        header = data[0][1].decode("utf-8", errors="replace")
        assert subject in header
        assert primary_account["user"] in header

        # Clean up
        imap.store(ids[0], "+FLAGS", "\\Deleted")
        imap.expunge()
    finally:
        logout(imap)


def test_send_and_receive_roundtrip_latency(cfg, primary_account, smtp_submission):
    """Assert that delivery completes within MAX_WAIT seconds."""
    uid = uuid.uuid4().hex
    subject = f"e2e-latency-{uid}"
    msg = build_message(
        from_addr=primary_account["user"],
        to_addr=primary_account["user"],
        subject=subject,
        body="latency test",
        message_id=f"<{uid}@mailtest>",
    )

    start = time.monotonic()
    smtp_submission.send_message(msg)

    ctx = imap_ssl_ctx(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    imap_login(imap, primary_account["user"], primary_account["password"])
    try:
        ids = _wait_for_message(imap, subject)
        elapsed = time.monotonic() - start
        assert ids, f"Message never arrived (subject={subject!r})"
        assert elapsed < MAX_WAIT, f"Delivery took {elapsed:.1f}s, threshold is {MAX_WAIT}s"

        imap.store(ids[0], "+FLAGS", "\\Deleted")
        imap.expunge()
    finally:
        logout(imap)
