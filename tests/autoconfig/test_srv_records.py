"""RFC 6186 / RFC 8314 DNS SRV record tests for mail client auto-configuration.

SRV records let mail clients discover server hostnames and ports without
hard-coded defaults.  The relevant record names are:

  _imaps._tcp.<domain>        — IMAP over TLS (port 993)
  _imap._tcp.<domain>         — IMAP with STARTTLS (port 143)
  _submission._tcp.<domain>   — SMTP submission with STARTTLS (port 587)
  _submissions._tcp.<domain>  — SMTP submission over TLS (port 465, RFC 8314)
"""

import pytest

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

pytestmark = pytest.mark.skipif(
    not HAS_DNSPYTHON,
    reason="dnspython not installed — run: pip install dnspython",
)


def _srv(name):
    """Return answer list, or empty list when the name / record type doesn't exist."""
    try:
        return list(dns.resolver.resolve(name, "SRV"))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


# ---------------------------------------------------------------------------
# _imaps._tcp  (IMAP over TLS, RFC 6186 §3.2)
# ---------------------------------------------------------------------------

def test_srv_imaps_exists(cfg):
    """_imaps._tcp SRV record must exist."""
    name = f"_imaps._tcp.{cfg['domain']}"
    assert _srv(name), f"No SRV record at {name!r}"


def test_srv_imaps_target_matches_imap_host(cfg):
    """_imaps._tcp SRV target must match configured imap.host."""
    name = f"_imaps._tcp.{cfg['domain']}"
    answers = _srv(name)
    if not answers:
        pytest.skip(f"No SRV record at {name!r}")
    targets = [str(r.target).rstrip(".") for r in answers]
    expected = cfg["imap"]["host"]
    assert any(expected in t for t in targets), (
        f"imap.host {expected!r} not in _imaps._tcp targets: {targets}"
    )


def test_srv_imaps_port_matches(cfg):
    """_imaps._tcp SRV port must match configured imap.port_ssl."""
    name = f"_imaps._tcp.{cfg['domain']}"
    answers = _srv(name)
    if not answers:
        pytest.skip(f"No SRV record at {name!r}")
    ports = [r.port for r in answers]
    expected = cfg["imap"]["port_ssl"]
    assert expected in ports, (
        f"Expected port {expected} in _imaps._tcp SRV ports: {ports}"
    )


# ---------------------------------------------------------------------------
# _imap._tcp  (IMAP with STARTTLS, RFC 6186 §3.1)
# ---------------------------------------------------------------------------

def test_srv_imap_starttls_exists(cfg):
    """_imap._tcp SRV record should exist for STARTTLS IMAP discovery."""
    name = f"_imap._tcp.{cfg['domain']}"
    answers = _srv(name)
    if not answers:
        pytest.xfail(
            f"No _imap._tcp SRV record for {cfg['domain']!r} — "
            "STARTTLS IMAP auto-discovery is unavailable"
        )


def test_srv_imap_starttls_port_matches(cfg):
    """_imap._tcp SRV port must match configured imap.port_starttls."""
    name = f"_imap._tcp.{cfg['domain']}"
    answers = _srv(name)
    if not answers:
        pytest.skip(f"No SRV record at {name!r}")
    ports = [r.port for r in answers]
    expected = cfg["imap"]["port_starttls"]
    assert expected in ports, (
        f"Expected port {expected} in _imap._tcp SRV ports: {ports}"
    )


# ---------------------------------------------------------------------------
# _submission._tcp  (SMTP submission + STARTTLS, RFC 6186 §3.3)
# ---------------------------------------------------------------------------

def test_srv_submission_exists(cfg):
    """_submission._tcp SRV record must exist."""
    name = f"_submission._tcp.{cfg['domain']}"
    assert _srv(name), f"No SRV record at {name!r}"


def test_srv_submission_target_matches_smtp_host(cfg):
    """_submission._tcp SRV target must match configured smtp.host."""
    name = f"_submission._tcp.{cfg['domain']}"
    answers = _srv(name)
    if not answers:
        pytest.skip(f"No SRV record at {name!r}")
    targets = [str(r.target).rstrip(".") for r in answers]
    expected = cfg["smtp"]["host"]
    assert any(expected in t for t in targets), (
        f"smtp.host {expected!r} not in _submission._tcp targets: {targets}"
    )


def test_srv_submission_port_matches(cfg):
    """_submission._tcp SRV port must match configured smtp.port_submission."""
    name = f"_submission._tcp.{cfg['domain']}"
    answers = _srv(name)
    if not answers:
        pytest.skip(f"No SRV record at {name!r}")
    ports = [r.port for r in answers]
    expected = cfg["smtp"]["port_submission"]
    assert expected in ports, (
        f"Expected port {expected} in _submission._tcp SRV ports: {ports}"
    )


# ---------------------------------------------------------------------------
# _submissions._tcp  (SMTP over TLS, RFC 8314)
# ---------------------------------------------------------------------------

def test_srv_submissions_exists(cfg):
    """_submissions._tcp SRV record should exist for SMTPS auto-discovery (RFC 8314)."""
    name = f"_submissions._tcp.{cfg['domain']}"
    answers = _srv(name)
    if not answers:
        pytest.xfail(
            f"No _submissions._tcp SRV record for {cfg['domain']!r} — "
            "SMTPS auto-discovery is unavailable"
        )


def test_srv_submissions_port_matches(cfg):
    """_submissions._tcp SRV port must match configured smtp.port_smtps."""
    name = f"_submissions._tcp.{cfg['domain']}"
    answers = _srv(name)
    if not answers:
        pytest.skip(f"No SRV record at {name!r}")
    ports = [r.port for r in answers]
    expected = cfg["smtp"]["port_smtps"]
    assert expected in ports, (
        f"Expected port {expected} in _submissions._tcp SRV ports: {ports}"
    )
