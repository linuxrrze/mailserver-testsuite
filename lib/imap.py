"""IMAP connection helpers (extracted from testimap4.py)."""

import imaplib
import re
import ssl
from typing import List, Optional, Set, Tuple

from lib.tls import make_context


LIST_RE = re.compile(
    r"""^\((?P<flags>[^\)]*)\)      # flags inside parentheses
        \s+"(?P<delim>[^"]+)"\s+    # delimiter in quotes
        (?P<name>.+)                # mailbox name (quoted or atom)
    $""",
    re.VERBOSE,
)


def make_ssl_context(no_verify: bool = False) -> ssl.SSLContext:
    """Client TLS context; honours `imap.tls_servername` (see lib/tls.py)."""
    return make_context(no_verify, protocol="imap")


# Socket timeout for every connection opened through these helpers. Without
# one, a port that accepts TCP but never greets (e.g. a reverse proxy
# peeking for client-first bytes) blocks the test run forever.
DEFAULT_TIMEOUT = 30.0


def connect_ssl(
    host: str, port: int, ssl_ctx: ssl.SSLContext, timeout: Optional[float] = DEFAULT_TIMEOUT
) -> imaplib.IMAP4_SSL:
    return imaplib.IMAP4_SSL(host, port, ssl_context=ssl_ctx, timeout=timeout)


def connect_plain(host: str, port: int, timeout: Optional[float] = DEFAULT_TIMEOUT) -> imaplib.IMAP4:
    """Unencrypted connection (for pre-STARTTLS checks)."""
    return imaplib.IMAP4(host, port, timeout=timeout)


def connect_starttls(
    host: str, port: int, ssl_ctx: ssl.SSLContext, timeout: Optional[float] = DEFAULT_TIMEOUT
) -> imaplib.IMAP4:
    imap = imaplib.IMAP4(host, port, timeout=timeout)
    typ, data = imap.starttls(ssl_ctx)
    if typ != "OK":
        raise RuntimeError(f"STARTTLS failed: {typ} {data}")
    return imap


def login(imap: imaplib.IMAP4, user: str, password: str) -> None:
    typ, data = imap.login(user, password)
    if typ != "OK":
        raise RuntimeError(f"Login failed: {typ} {data}")


def logout(imap: imaplib.IMAP4) -> None:
    try:
        imap.logout()
    except Exception:
        pass


def _parse_list_response(raw: List[bytes]) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    for entry in raw:
        line = entry.decode("utf-8", errors="replace")
        m = LIST_RE.match(line)
        if not m:
            continue
        flags = m.group("flags").strip()
        name = m.group("name").strip()
        if name.startswith('"') and name.endswith('"'):
            name = name[1:-1]
            name = name.replace(r'\"', '"')
            name = name.replace(r'\\', "\\")
        results.append((flags, name))
    return results


def list_mailboxes(imap: imaplib.IMAP4) -> List[str]:
    typ, data = imap.list()
    if typ != "OK":
        raise RuntimeError(f"LIST failed: {typ} {data}")
    return [name for _flags, name in _parse_list_response(data)]


def list_mailboxes_with_flags(imap: imaplib.IMAP4) -> List[Tuple[str, str]]:
    """Return [(flags_str, name), ...] for all mailboxes."""
    typ, data = imap.list()
    if typ != "OK":
        raise RuntimeError(f"LIST failed: {typ} {data}")
    return _parse_list_response(data)


def list_subscribed(imap: imaplib.IMAP4) -> Set[str]:
    typ, data = imap.lsub()
    if typ != "OK":
        raise RuntimeError(f"LSUB failed: {typ} {data}")
    return {name for _flags, name in _parse_list_response(data)}


def get_capabilities(imap: imaplib.IMAP4) -> Set[str]:
    typ, data = imap.capability()
    if typ != "OK":
        raise RuntimeError(f"CAPABILITY failed: {typ} {data}")
    raw = data[0].decode("utf-8", errors="replace") if data else ""
    parts = raw.split()
    # Some Python versions include "CAPABILITY" as the first token; strip it if present
    if parts and parts[0].upper() == "CAPABILITY":
        parts = parts[1:]
    return set(parts)
