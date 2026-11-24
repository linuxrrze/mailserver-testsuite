"""IMAP folder structure tests."""

import imaplib
import uuid
import pytest

from lib.imap import list_mailboxes, list_mailboxes_with_flags, list_subscribed


def test_inbox_exists(imap, cfg):
    folders = list_mailboxes(imap)
    assert any(f.upper() == "INBOX" or f.upper().endswith(".INBOX") for f in folders), (
        f"INBOX not found in {folders}"
    )


@pytest.mark.parametrize("folder", [
    pytest.param("Sent", id="Sent"),
    pytest.param("Drafts", id="Drafts"),
    pytest.param("Trash", id="Trash"),
    pytest.param("Junk", id="Junk"),
])
def test_standard_folder_exists(imap, cfg, folder):
    expected = cfg.get("expected_folders", [])
    if folder not in expected:
        pytest.skip(f"{folder!r} not listed in config expected_folders")
    folders = list_mailboxes(imap)
    # Accept bare name or namespace-prefixed variants (e.g. INBOX.Sent)
    names_upper = {f.upper() for f in folders}
    assert (
        folder.upper() in names_upper
        or f"INBOX.{folder}".upper() in names_upper
    ), f"{folder!r} not found in {folders}"


def test_no_stale_subscriptions(imap):
    all_folders = set(list_mailboxes(imap))
    subscribed = list_subscribed(imap)
    stale = subscribed - all_folders
    assert not stale, f"Stale subscriptions (in LSUB but not LIST): {stale}"


def test_subscribed_is_subset_of_all(imap):
    all_folders = set(list_mailboxes(imap))
    subscribed = list_subscribed(imap)
    assert subscribed <= all_folders, (
        f"Subscribed folders not a subset of all folders: extra={subscribed - all_folders}"
    )


def test_inbox_is_subscribed(imap):
    subscribed = {s.upper() for s in list_subscribed(imap)}
    assert "INBOX" in subscribed, "INBOX is not in the subscribed list"


def test_create_and_delete_folder(imap):
    name = f"TestFolder-{uuid.uuid4().hex[:8]}"
    try:
        typ, _ = imap.create(name)
        assert typ == "OK", f"CREATE {name!r} failed"
        folders = list_mailboxes(imap)
        assert any(name in f for f in folders), f"Folder {name!r} not found after CREATE"
    finally:
        imap.delete(name)
        folders_after = list_mailboxes(imap)
        assert not any(name in f for f in folders_after), f"Folder {name!r} still present after DELETE"


def test_rename_folder(imap):
    name = f"TestRename-{uuid.uuid4().hex[:8]}"
    new_name = f"{name}-renamed"
    imap.create(name)
    try:
        typ, _ = imap.rename(name, new_name)
        assert typ == "OK", f"RENAME to {new_name!r} failed"
        folders = list_mailboxes(imap)
        assert any(new_name in f for f in folders), f"Renamed folder {new_name!r} not found"
    finally:
        imap.delete(new_name)


@pytest.mark.parametrize("special_use,folder_hint", [
    (r"\Sent",   "Sent"),
    (r"\Drafts", "Drafts"),
    (r"\Trash",  "Trash"),
    (r"\Junk",   "Junk"),
])
def test_rfc6154_special_use_flag(imap, cfg, special_use, folder_hint):
    """RFC 6154: each standard folder must carry its special-use attribute in LIST."""
    if folder_hint not in cfg.get("expected_folders", []):
        pytest.skip(f"{folder_hint!r} not in expected_folders")
    folders = list_mailboxes_with_flags(imap)
    matching = [
        name for flags, name in folders
        if special_use.lower() in flags.lower()
    ]
    assert matching, (
        f"No folder carries {special_use!r} special-use flag. "
        f"All (flags, name) pairs: {folders}"
    )


def test_subscribe_unsubscribe(imap):
    name = f"TestSub-{uuid.uuid4().hex[:8]}"
    imap.create(name)
    try:
        imap.subscribe(name)
        subscribed = list_subscribed(imap)
        assert name in subscribed, f"{name!r} not in subscribed list after SUBSCRIBE"

        imap.unsubscribe(name)
        subscribed_after = list_subscribed(imap)
        assert name not in subscribed_after, f"{name!r} still subscribed after UNSUBSCRIBE"
    finally:
        imap.delete(name)
