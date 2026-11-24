"""IMAP UID command tests (UID SEARCH, UID FETCH, UID STORE, UID COPY)."""

import uuid
import pytest

# Every test here APPENDs a message first (and EXPUNGEs it) -> mutates -> full.
pytestmark = pytest.mark.full


def _append(imap, subject, uid):
    raw = (
        f"Subject: {subject}\r\n"
        f"Message-ID: <{uid}@mailtest>\r\n"
        f"\r\n"
        f"UID test body\r\n"
    ).encode()
    typ, data = imap.append("INBOX", "", None, raw)
    assert typ == "OK", f"APPEND failed: {typ} {data}"


def _uid_search(imap, subject):
    typ, data = imap.uid("SEARCH", None, f'SUBJECT "{subject}"')
    assert typ == "OK"
    return data[0].split()


def _cleanup_uids(imap, uid_list):
    for uid in uid_list:
        imap.uid("STORE", uid, "+FLAGS", "\\Deleted")
    imap.expunge()


def test_uid_search(imap):
    """UID SEARCH must return UIDs, not sequence numbers."""
    uid = uuid.uuid4().hex
    subject = f"mailtest-uid-search-{uid}"
    _append(imap, subject, uid)
    imap.select("INBOX")

    uids = _uid_search(imap, subject)
    assert uids, f"UID SEARCH found no message for subject {subject!r}"
    # UIDs are numeric strings
    assert all(u.isdigit() for u in uids), f"Non-numeric UIDs returned: {uids}"

    _cleanup_uids(imap, uids)


def test_uid_fetch(imap):
    """UID FETCH must return the correct message headers."""
    uid = uuid.uuid4().hex
    subject = f"mailtest-uid-fetch-{uid}"
    _append(imap, subject, uid)
    imap.select("INBOX")

    uids = _uid_search(imap, subject)
    assert uids

    typ, data = imap.uid("FETCH", uids[0], "(RFC822.HEADER)")
    assert typ == "OK", f"UID FETCH failed: {typ} {data}"
    header = data[0][1].decode("utf-8", errors="replace")
    assert subject in header, f"Subject not found in fetched header: {header[:300]!r}"

    _cleanup_uids(imap, uids)


def test_uid_store_flags(imap):
    """UID STORE must set flags and UID FETCH must reflect the change."""
    uid = uuid.uuid4().hex
    subject = f"mailtest-uid-store-{uid}"
    _append(imap, subject, uid)
    imap.select("INBOX")

    uids = _uid_search(imap, subject)
    assert uids

    typ, _ = imap.uid("STORE", uids[0], "+FLAGS", "\\Flagged")
    assert typ == "OK", "UID STORE +FLAGS failed"

    typ, data = imap.uid("FETCH", uids[0], "(FLAGS)")
    assert typ == "OK"
    flags_line = data[0].decode("utf-8", errors="replace") if isinstance(data[0], bytes) else str(data[0])
    assert "\\Flagged" in flags_line, f"\\Flagged not set after UID STORE: {flags_line!r}"

    _cleanup_uids(imap, uids)


def test_uid_copy(imap):
    """UID COPY must place a copy in the destination folder."""
    folder = f"TestUIDCopy-{uuid.uuid4().hex[:8]}"
    imap.create(folder)
    uid = uuid.uuid4().hex
    subject = f"mailtest-uid-copy-{uid}"

    try:
        _append(imap, subject, uid)
        imap.select("INBOX")
        src_uids = _uid_search(imap, subject)
        assert src_uids

        typ, _ = imap.uid("COPY", src_uids[0], folder)
        assert typ == "OK", f"UID COPY to {folder!r} failed"

        imap.select(folder)
        dst_uids = _uid_search(imap, subject)
        assert dst_uids, f"Message not found in {folder!r} after UID COPY"

        _cleanup_uids(imap, src_uids)
        imap.select(folder)
        _cleanup_uids(imap, dst_uids)
    finally:
        imap.select("INBOX")
        imap.delete(folder)
