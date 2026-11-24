"""End-to-end outgoing header checks: Message-ID, DKIM-Signature, Received,
and the client IP recorded for the submission hop.

All checks share ONE delivered message (module-scoped fixture) instead of
sending a mail per test.
"""

import ipaddress
import re
import socket
import time
import uuid
from email.parser import HeaderParser

import pytest

from lib.imap import connect_ssl, login as imap_login, logout, make_ssl_context as imap_ssl_ctx
from lib.smtp import (
    build_message,
    connect_submission,
    login as smtp_login,
    make_ssl_context as smtp_ssl_ctx,
    quit as smtp_quit,
)

# The module-scoped delivered_header fixture sends a real message via submission
# (connect_submission directly, not a login fixture), so every test here depends
# on an actual delivery -> full tier. An explicit marker is required because the
# tests use `delivered_header`, not one of the named login fixtures, and would
# otherwise misinfer as anonymous.
pytestmark = pytest.mark.full

POLL_INTERVAL = 2
MAX_WAIT = 30


@pytest.fixture(scope="module")
def delivered_header(cfg, primary_account, greeting_probe):
    """Send one message via submission (587) to ourselves; return (header_text, uid)."""
    for ep in ("smtp-submission", "imap-ssl"):
        result = greeting_probe(ep)
        if not result.ok:
            pytest.skip(f"{ep}: no usable greeting ({result.status}) — diagnosis in "
                        f"tests/proxy/test_greeting.py::test_server_greeting[{ep}]")

    uid = uuid.uuid4().hex
    subject = f"header-check-{uid}"
    msg = build_message(
        from_addr=primary_account["user"],
        to_addr=primary_account["user"],
        subject=subject,
        body=f"Header check {uid}",
        message_id=f"<{uid}@mailtest>",
    )
    smtp = connect_submission(
        cfg["smtp"]["host"], cfg["smtp"]["port_submission"], smtp_ssl_ctx(cfg.get("no_verify", False))
    )
    try:
        smtp_login(smtp, primary_account["user"], primary_account["password"])
        smtp.send_message(msg)
    finally:
        smtp_quit(smtp)

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


def test_message_id_present(delivered_header):
    """Delivered message must carry a Message-ID header."""
    header, uid = delivered_header
    assert header, f"Message never arrived (uid={uid})"
    assert "Message-ID:" in header, "Message-ID header missing from delivered message"


def test_dkim_signature_present(delivered_header):
    """Outgoing messages must be DKIM-signed (DKIM-Signature header present)."""
    header, uid = delivered_header
    assert header, f"Message never arrived (uid={uid})"
    assert "DKIM-Signature:" in header, (
        "DKIM-Signature header absent — outgoing mail is not DKIM-signed"
    )


def test_received_header_present(delivered_header):
    """Delivered message must have at least one Received header."""
    header, uid = delivered_header
    assert header, f"Message never arrived (uid={uid})"
    assert "Received:" in header, "Received header missing from delivered message"


# ---------------------------------------------------------------------------
# Real client IP on the submission hop
# ---------------------------------------------------------------------------

# RFC 3848 "with" types for authenticated submission (ESMTPA, ESMTPSA) —
# the hop where the server accepted our SMTP AUTH session.
_AUTH_WITH_RE = re.compile(r"\bwith\s+E?SMTPS?A\b", re.IGNORECASE)
_IP_LITERAL_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")


def _submission_client_ip(header_text):
    """Return (ip, received_header) for the authenticated-submission hop, or (None, None).

    Received headers are prepended, so the list runs newest (delivery) to
    oldest; the submission hop is the topmost one whose `with` clause is an
    authenticated SMTP type. The client address is the last IP literal in
    the `from` clause (Postfix: `from helo (rdns [ip])`, Exim:
    `from rdns ([ip] helo=...)`).
    """
    msg = HeaderParser().parsestr(header_text, headersonly=True)
    for raw in msg.get_all("Received") or []:
        value = " ".join(str(raw).split())
        if not _AUTH_WITH_RE.search(value):
            continue
        from_clause = re.split(r"\s+by\s+", value, maxsplit=1)[0]
        ips = []
        for cand in _IP_LITERAL_RE.findall(from_clause):
            try:
                ips.append(ipaddress.ip_address(cand))
            except ValueError:
                pass
        if ips:
            return ips[-1], value
        return None, value
    return None, None


def _runner_source_ip(host, port):
    """Our own source address as used to reach the submission server."""
    with socket.create_connection((host, port), timeout=10) as s:
        return ipaddress.ip_address(s.getsockname()[0]), ipaddress.ip_address(s.getpeername()[0])


def test_submission_hop_records_real_client_ip(cfg, delivered_header):
    """Confirms the server sees the real client IP (PROXY protocol working).

    Behind a reverse proxy the backend only learns the client's address if
    the proxy passes it on (PROXY protocol). The Received header the server
    wrote for our authenticated submission must show this runner's address
    (or `proxy.expected_client_ip` when NAT sits in between). A loopback
    address or one of `proxy.addresses` means the server is logging — and
    fail2ban/rate limits are acting on — the proxy, not the client.
    """
    header, uid = delivered_header
    if not header:
        pytest.skip(f"Message never arrived (uid={uid}) — see the other header tests")
    observed, received = _submission_client_ip(header)
    if received is None:
        pytest.skip("No authenticated-submission (ESMTPA/ESMTPSA) Received header — "
                    "the server may strip it for privacy; client IP not determinable")
    if observed is None:
        pytest.skip(f"No client IP literal in the submission Received header: {received[:200]!r}")

    proxy = cfg.get("proxy") or {}
    proxy_addrs = {ipaddress.ip_address(a) for a in (proxy.get("addresses") or [])}
    expected = proxy.get("expected_client_ip")
    hint = ("the server sees the proxy's IP, not the client's — enable/fix PROXY protocol "
            "between the proxy and the mail server")

    if observed in proxy_addrs:
        pytest.fail(f"Submission hop recorded {observed}, a configured proxy address: {hint}. "
                    f"Header: {received[:200]!r}")
    if expected:
        assert observed == ipaddress.ip_address(expected), (
            f"Submission hop recorded {observed}, expected this client's {expected}: {hint}. "
            f"Header: {received[:200]!r}"
        )
        return

    local_ip, server_ip = _runner_source_ip(cfg["smtp"]["host"], cfg["smtp"]["port_submission"])
    if observed == local_ip:
        return  # the server sees exactly the address we connect from
    if observed.is_loopback and not server_ip.is_loopback:
        pytest.fail(f"Submission hop recorded loopback {observed} although this runner "
                    f"connected from {local_ip}: {hint}. Header: {received[:200]!r}")
    if observed.is_private or observed.is_loopback or observed.is_link_local:
        pytest.fail(
            f"Submission hop recorded {observed}, but this runner connected from {local_ip} — "
            f"a private address that is not ours is most likely the proxy/container network: "
            f"{hint}. (If NAT legitimately sits in between, set proxy.expected_client_ip.) "
            f"Header: {received[:200]!r}"
        )
    pytest.skip(
        f"Submission hop recorded public address {observed} while this runner's local address "
        f"is {local_ip} (NAT?) — set proxy.expected_client_ip to make this check definitive"
    )
