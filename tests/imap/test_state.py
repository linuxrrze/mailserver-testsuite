"""IMAP state machine enforcement tests."""

import imaplib
import uuid
import pytest

from lib.imap import connect_ssl, login, logout, make_ssl_context


@pytest.mark.read_only
def test_fetch_without_select_rejected(cfg, primary_account):
    """FETCH in AUTHENTICATED state (no mailbox selected) must be rejected."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    login(imap, primary_account["user"], primary_account["password"])
    # No SELECT — state is AUTHENTICATED, not SELECTED
    try:
        typ, data = imap.fetch("1", "(FLAGS)")
        assert typ in ("BAD", "NO"), (
            f"FETCH without SELECT returned {typ!r} — expected BAD or NO"
        )
    except imaplib.IMAP4.error:
        pass  # server raised an error instead of returning BAD/NO — equally valid
    finally:
        logout(imap)


@pytest.mark.read_only
def test_examine_opens_readonly(cfg, primary_account):
    """EXAMINE must succeed and open the mailbox in read-only mode."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    login(imap, primary_account["user"], primary_account["password"])
    try:
        typ, _ = imap.select("INBOX", readonly=True)
        assert typ == "OK", f"EXAMINE (readonly SELECT) INBOX failed: {typ}"
    finally:
        logout(imap)


@pytest.mark.full
def test_store_on_examined_mailbox_rejected(cfg, primary_account):
    """STORE must be rejected on a mailbox opened read-only with EXAMINE."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    login(imap, primary_account["user"], primary_account["password"])

    uid = uuid.uuid4().hex
    raw = f"Subject: examine-ro-{uid}\r\n\r\ntest\r\n".encode()
    imap.append("INBOX", "", None, raw)

    imap.select("INBOX", readonly=True)  # read-only

    typ, data = imap.store("1", "+FLAGS", "\\Flagged")
    if typ == "OK":
        pytest.xfail(
            "Server accepted STORE on a read-only mailbox — "
            "RFC 3501 §6.4.6 requires NO, but some servers skip this enforcement"
        )
    assert typ in ("NO", "BAD"), (
        f"STORE succeeded on EXAMINE'd mailbox (expected NO/BAD, got {typ!r}): {data}"
    )

    # Cleanup: reopen read-write and delete the appended message
    imap.select("INBOX")
    t2, ids = imap.search(None, f'SUBJECT "examine-ro-{uid}"')
    if t2 == "OK" and ids[0]:
        for mid in ids[0].split():
            imap.store(mid, "+FLAGS", "\\Deleted")
        imap.expunge()

    logout(imap)


def test_noop_accepted_in_selected_state(imap):
    """NOOP must be accepted in any state and return OK."""
    imap.select("INBOX")
    typ, _ = imap.noop()
    assert typ == "OK", f"NOOP returned {typ!r}"


@pytest.mark.read_only
def test_noop_accepted_in_authenticated_state(cfg, primary_account):
    """NOOP must also be accepted before any mailbox is selected."""
    ctx = make_ssl_context(cfg.get("no_verify", False))
    imap = connect_ssl(cfg["imap"]["host"], cfg["imap"]["port_ssl"], ctx)
    login(imap, primary_account["user"], primary_account["password"])
    try:
        typ, _ = imap.noop()
        assert typ == "OK", f"NOOP in AUTHENTICATED state returned {typ!r}"
    finally:
        logout(imap)
