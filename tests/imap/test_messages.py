"""IMAP message operation tests (APPEND / FETCH / STORE / SEARCH / COPY / EXPUNGE)."""

import uuid
import pytest

TEST_BODY = "Hello from the mailserver test suite.\r\nThis is a test message.\r\n"


def _append_message(imap, mailbox, subject, unique_id):
    raw = (
        f"From: tester@example.com\r\n"
        f"To: tester@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: <{unique_id}@mailtest>\r\n"
        f"MIME-Version: 1.0\r\n"
        f"\r\n"
        f"{TEST_BODY}"
    ).encode()
    typ, data = imap.append(mailbox, "", None, raw)
    assert typ == "OK", f"APPEND failed: {typ} {data}"
    return unique_id


def _select(imap, mailbox="INBOX"):
    typ, data = imap.select(mailbox)
    assert typ == "OK", f"SELECT {mailbox!r} failed: {typ} {data}"
    return int(data[0])  # message count


def _search_by_subject(imap, subject):
    typ, data = imap.search(None, f'SUBJECT "{subject}"')
    assert typ == "OK"
    ids = data[0].split()
    return ids


def _cleanup(imap, msg_ids):
    for mid in msg_ids:
        imap.store(mid, "+FLAGS", "\\Deleted")
    imap.expunge()


def test_append_and_fetch(imap):
    uid = uuid.uuid4().hex
    subject = f"mailtest-append-{uid}"
    _append_message(imap, "INBOX", subject, uid)
    _select(imap)

    ids = _search_by_subject(imap, subject)
    assert ids, f"Appended message with subject {subject!r} not found via SEARCH"

    typ, data = imap.fetch(ids[0], "(RFC822.HEADER)")
    assert typ == "OK"
    header = data[0][1].decode("utf-8", errors="replace")
    assert subject in header

    _cleanup(imap, ids)


def test_store_seen_flag(imap):
    uid = uuid.uuid4().hex
    subject = f"mailtest-flags-{uid}"
    _append_message(imap, "INBOX", subject, uid)
    _select(imap)

    ids = _search_by_subject(imap, subject)
    assert ids

    typ, _ = imap.store(ids[0], "+FLAGS", "\\Seen")
    assert typ == "OK"

    typ, data = imap.fetch(ids[0], "(FLAGS)")
    assert typ == "OK"
    flags_str = data[0].decode("utf-8", errors="replace") if isinstance(data[0], bytes) else str(data[0])
    assert "\\Seen" in flags_str

    _cleanup(imap, ids)


def test_copy_message(imap):
    folder = f"TestCopy-{uuid.uuid4().hex[:8]}"
    imap.create(folder)
    uid = uuid.uuid4().hex
    subject = f"mailtest-copy-{uid}"

    try:
        _append_message(imap, "INBOX", subject, uid)
        _select(imap)
        src_ids = _search_by_subject(imap, subject)
        assert src_ids

        typ, _ = imap.copy(src_ids[0], folder)
        assert typ == "OK", "COPY failed"

        _select(imap, folder)
        dst_ids = _search_by_subject(imap, subject)
        assert dst_ids, "Message not found in destination folder after COPY"

        _cleanup(imap, dst_ids)
        _select(imap)  # back to INBOX before cleaning source
        _cleanup(imap, src_ids)
    finally:
        imap.select("INBOX")
        imap.delete(folder)


def test_expunge_removes_deleted(imap):
    uid = uuid.uuid4().hex
    subject = f"mailtest-expunge-{uid}"
    _append_message(imap, "INBOX", subject, uid)
    _select(imap)

    ids = _search_by_subject(imap, subject)
    assert ids

    imap.store(ids[0], "+FLAGS", "\\Deleted")
    imap.expunge()

    ids_after = _search_by_subject(imap, subject)
    assert not ids_after, "Message still present after EXPUNGE"


def test_large_message_roundtrip(imap):
    """A 1 MB message must survive APPEND + FETCH with correct size reported."""
    import re as _re
    uid = uuid.uuid4().hex
    subject = f"mailtest-large-{uid}"
    body = "X" * (1024 * 1024)
    raw = (
        f"Subject: {subject}\r\n"
        f"Message-ID: <{uid}@mailtest>\r\n"
        f"\r\n"
        f"{body}\r\n"
    ).encode("ascii")

    typ, _ = imap.append("INBOX", "", None, raw)
    assert typ == "OK", "APPEND of 1 MB message failed"

    _select(imap)
    ids = _search_by_subject(imap, subject)
    assert ids, "1 MB message not found after APPEND"

    typ2, data = imap.fetch(ids[0], "(RFC822.SIZE)")
    assert typ2 == "OK"
    size_line = data[0].decode("utf-8", errors="replace") if isinstance(data[0], bytes) else str(data[0])
    m = _re.search(r"RFC822\.SIZE\s+(\d+)", size_line)
    assert m, f"RFC822.SIZE not in fetch response: {size_line!r}"
    assert int(m.group(1)) >= 1024 * 1024, (
        f"Reported size {m.group(1)} is less than 1 MB"
    )

    _cleanup(imap, ids)


def test_utf8_subject_roundtrip(imap):
    """Message with a UTF-8 encoded subject must round-trip through APPEND + FETCH."""
    import email.header as _hdr
    uid = uuid.uuid4().hex
    subject_text = f"Ünïcödé tëst {uid}"
    encoded_subject = _hdr.Header(subject_text, "utf-8").encode()

    raw = (
        f"Subject: {encoded_subject}\r\n"
        f"Message-ID: <{uid}@mailtest>\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"body\r\n"
    ).encode("utf-8")

    typ, _ = imap.append("INBOX", "", None, raw)
    assert typ == "OK", "APPEND of UTF-8 subject message failed"

    _select(imap)
    # Search by the unique hex ID embedded in the subject (plain ASCII, reliable)
    ids = _search_by_subject(imap, uid)
    assert ids, f"UTF-8 subject message not found after APPEND (uid={uid!r})"

    typ2, data = imap.fetch(ids[0], "(RFC822.HEADER)")
    assert typ2 == "OK"
    header = data[0][1].decode("utf-8", errors="replace")
    assert uid in header, (
        f"Unique ID {uid!r} not found in fetched header — subject may have been corrupted"
    )

    _cleanup(imap, ids)


def test_search_by_date(imap):
    uid = uuid.uuid4().hex
    subject = f"mailtest-search-{uid}"
    _append_message(imap, "INBOX", subject, uid)
    _select(imap)

    typ, data = imap.search(None, "SINCE 01-Jan-2000")
    assert typ == "OK"
    assert data[0], "SEARCH SINCE returned no results"

    ids = _search_by_subject(imap, subject)
    _cleanup(imap, ids)
