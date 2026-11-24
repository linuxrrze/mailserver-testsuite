"""IMAP IDLE tests (push notification support)."""

import pytest

from lib.imap import get_capabilities


def test_idle_capability_advertised(imap):
    """IDLE must appear in the CAPABILITY response."""
    caps = get_capabilities(imap)
    assert "IDLE" in caps, f"IDLE not in CAPABILITY: {caps}"


def test_idle_command_accepted(imap):
    """IDLE must return a continuation response and DONE must close it cleanly."""
    caps = get_capabilities(imap)
    if "IDLE" not in caps:
        pytest.skip("IDLE not in capabilities")

    imap.select("INBOX")

    tag = b"IDLETEST1"
    imap.send(tag + b" IDLE\r\n")

    line = imap.readline()
    assert line.startswith(b"+"), (
        f"Expected '+ idling' continuation after IDLE, got: {line!r}"
    )

    imap.send(b"DONE\r\n")

    # Read responses until we get the tagged OK (skip any untagged lines)
    for _ in range(20):
        line = imap.readline()
        if tag in line:
            assert b"OK" in line, f"IDLE/DONE did not complete with OK: {line!r}"
            return

    pytest.fail("Never received tagged OK response after IDLE DONE")
