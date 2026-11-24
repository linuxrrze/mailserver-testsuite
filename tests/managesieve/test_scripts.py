"""ManageSieve script management: PUTSCRIPT/LISTSCRIPTS/GETSCRIPT/SETACTIVE/
DELETESCRIPT/RENAMESCRIPT/CHECKSCRIPT/HAVESPACE (RFC 5804 §2.6-2.13).

Tests that touch the active script save whatever was active beforehand and
restore it in `finally` — this account may have a real, in-use filter script
active, and these tests must not leave it permanently deactivated.
"""

import uuid
import warnings

import pytest

from lib.managesieve import ManageSieveError

VALID_SCRIPT = 'require "fileinto";\nif true {\n  fileinto "INBOX";\n}\n'
INVALID_SCRIPT = "this is not valid sieve syntax {{{"


def _script_name(cfg, suffix):
    prefix = cfg.get("managesieve", {}).get("script_prefix", "mailtest-suite")
    return f"{prefix}-{suffix}-{uuid.uuid4().hex[:8]}"


def _active_script(sieve):
    return next((name for name, is_active in sieve.list_scripts() if is_active), None)


def test_putscript_and_listscripts_roundtrip(sieve, cfg):
    name = _script_name(cfg, "roundtrip")
    sieve.put_script(name, VALID_SCRIPT)
    try:
        names = {n for n, _active in sieve.list_scripts()}
        assert name in names, f"Uploaded script {name!r} not in LISTSCRIPTS: {names}"
    finally:
        sieve.delete_script(name)


def test_getscript_returns_uploaded_content(sieve, cfg):
    name = _script_name(cfg, "getscript")
    sieve.put_script(name, VALID_SCRIPT)
    try:
        content = sieve.get_script(name)
        assert content.strip() == VALID_SCRIPT.strip(), (
            f"GETSCRIPT content does not match what was uploaded: {content!r}"
        )
    finally:
        sieve.delete_script(name)


def test_checkscript_accepts_valid_syntax(sieve):
    sieve.check_script(VALID_SCRIPT)  # must not raise


def test_checkscript_rejects_invalid_syntax(sieve):
    with pytest.raises(ManageSieveError):
        sieve.check_script(INVALID_SCRIPT)


def test_putscript_rejects_invalid_syntax(sieve, cfg):
    name = _script_name(cfg, "invalid")
    with pytest.raises(ManageSieveError):
        sieve.put_script(name, INVALID_SCRIPT)
    names = {n for n, _active in sieve.list_scripts()}
    assert name not in names, "Syntactically invalid script was stored anyway"


def test_setactive_and_deactivate(sieve, cfg):
    name = _script_name(cfg, "active")
    previously_active = _active_script(sieve)

    sieve.put_script(name, VALID_SCRIPT)
    try:
        sieve.set_active(name)
        active = {n for n, is_active in sieve.list_scripts() if is_active}
        assert name in active, f"SETACTIVE did not mark {name!r} active: {active}"

        sieve.set_active("")  # RFC 5804 §2.8: empty name deactivates all scripts
        active = {n for n, is_active in sieve.list_scripts() if is_active}
        assert name not in active, f'Script still active after SETACTIVE "": {active}'
    finally:
        sieve.delete_script(name)
        if previously_active:
            sieve.set_active(previously_active)


def test_active_script_cannot_be_deleted(sieve, cfg):
    """RFC 5804 §2.10: DELETESCRIPT on the currently active script must be rejected."""
    name = _script_name(cfg, "protected")
    previously_active = _active_script(sieve)

    sieve.put_script(name, VALID_SCRIPT)
    try:
        sieve.set_active(name)
        with pytest.raises(ManageSieveError):
            sieve.delete_script(name)
    finally:
        # Cleanup must not mask the real failure: if the server wrongly
        # deleted the active script above, restoring/deleting it raises too.
        cleanup_errors = []
        try:
            sieve.set_active(previously_active if previously_active else "")
        except Exception as e:  # noqa: BLE001 — report, don't mask
            cleanup_errors.append(f"restore active script {previously_active!r}: {e}")
        try:
            if name in {n for n, _active in sieve.list_scripts()}:
                sieve.delete_script(name)
        except Exception as e:  # noqa: BLE001
            cleanup_errors.append(f"delete {name!r}: {e}")
        if cleanup_errors:
            warnings.warn("test_active_script_cannot_be_deleted cleanup: " + "; ".join(cleanup_errors))


def test_deletescript_removes_script(sieve, cfg):
    name = _script_name(cfg, "delete")
    sieve.put_script(name, VALID_SCRIPT)
    sieve.delete_script(name)
    names = {n for n, _active in sieve.list_scripts()}
    assert name not in names, f"Script {name!r} still listed after DELETESCRIPT"


def test_deletescript_unknown_script_rejected(sieve):
    with pytest.raises(ManageSieveError):
        sieve.delete_script(f"nonexistent-{uuid.uuid4().hex}")


def test_renamescript(sieve, cfg):
    old_name = _script_name(cfg, "rename-old")
    new_name = _script_name(cfg, "rename-new")
    sieve.put_script(old_name, VALID_SCRIPT)
    try:
        sieve.rename_script(old_name, new_name)
        names = {n for n, _active in sieve.list_scripts()}
        assert old_name not in names, f"Old name {old_name!r} still present after rename"
        assert new_name in names, f"New name {new_name!r} not present after rename"
    except ManageSieveError as e:
        pytest.xfail(f"RENAMESCRIPT not supported by this server: {e}")
    finally:
        for n in (old_name, new_name):
            try:
                sieve.delete_script(n)
            except ManageSieveError:
                pass


def test_havespace_reports_ok_for_small_script(sieve):
    name = f"havespace-check-{uuid.uuid4().hex[:8]}"
    sieve.have_space(name, len(VALID_SCRIPT))  # must not raise
