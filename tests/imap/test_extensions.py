"""IMAP extension tests: NAMESPACE and QUOTA."""

import pytest

from lib.imap import get_capabilities


def test_namespace_command_accepted(imap):
    """NAMESPACE command must return OK when the capability is advertised."""
    caps = get_capabilities(imap)
    if "NAMESPACE" not in caps:
        pytest.skip("NAMESPACE not in capabilities")

    # imaplib has no built-in namespace() method; use xatom for extension commands
    typ, data = imap.xatom("NAMESPACE")
    assert typ == "OK", f"NAMESPACE command failed: {typ} {data}"
    # The server must have sent at least one untagged NAMESPACE response
    ns_responses = imap.untagged_responses.get("NAMESPACE", [])
    assert ns_responses, "NAMESPACE returned OK but no untagged NAMESPACE response received"


def test_namespace_personal_namespace_present(imap):
    """NAMESPACE response must include a personal namespace (first field non-NIL)."""
    caps = get_capabilities(imap)
    if "NAMESPACE" not in caps:
        pytest.skip("NAMESPACE not in capabilities")

    imap.xatom("NAMESPACE")
    ns_responses = imap.untagged_responses.get("NAMESPACE", [])
    assert ns_responses, "No NAMESPACE response"

    raw = ns_responses[0]
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    # A personal namespace looks like: (("" "/")) NIL NIL
    # NIL for the first field means no personal namespace — unusual but valid
    assert not raw.strip().upper().startswith("NIL"), (
        f"NAMESPACE has no personal namespace: {raw!r}"
    )


def test_quota_getquotaroot(imap):
    """GETQUOTAROOT INBOX must succeed when QUOTA is in capabilities."""
    caps = get_capabilities(imap)
    if "QUOTA" not in caps:
        pytest.skip("QUOTA not in capabilities")

    typ, data = imap.getquotaroot("INBOX")
    assert typ == "OK", f"GETQUOTAROOT INBOX failed: {typ} {data}"


def test_quota_has_storage_resource(imap):
    """QUOTA response must include a STORAGE resource limit."""
    caps = get_capabilities(imap)
    if "QUOTA" not in caps:
        pytest.skip("QUOTA not in capabilities")

    # imaplib's getquotaroot() pops the QUOTAROOT/QUOTA untagged responses out
    # of imap.untagged_responses and returns them directly — they must be read
    # from the return value, not looked up in untagged_responses afterwards.
    typ, (quotaroot_responses, quota_responses) = imap.getquotaroot("INBOX")
    if not quota_responses or quota_responses == [None]:
        pytest.skip("No QUOTA untagged responses — mailbox may have no quota set")

    # Each QUOTA response looks like: "" (STORAGE used limit)
    found_storage = any(
        b"STORAGE" in r if isinstance(r, bytes) else "STORAGE" in r
        for r in quota_responses
    )
    assert found_storage, (
        f"STORAGE resource not found in QUOTA responses: {quota_responses}"
    )
