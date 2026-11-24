"""Microsoft Autodiscover endpoint tests (Outlook / Exchange clients).

Two canonical URLs are tried in order:
  1. https://autodiscover.<domain>/autodiscover/autodiscover.xml
  2. https://<domain>/autodiscover/autodiscover.xml
"""

import xml.etree.ElementTree as ET
import pytest

# Fetch/parse logic is shared with tests/autoconfig/test_consistency.py — see
# lib/autoconfig.py. These aliases keep the test bodies below unchanged.
from lib.autoconfig import (
    AUTODISCOVER_TEMPLATES as _AUTODISCOVER_TEMPLATES,
    fetch_autodiscover as _fetch,
    find_all_local as _find_all,
    child_text as _text,
    local_tag,
)


def _root(cfg):
    """Fetch and parse Autodiscover XML; skip if unreachable."""
    _, body = _fetch(cfg["domain"])
    if body is None:
        pytest.skip(
            f"No Autodiscover endpoint reachable for {cfg['domain']!r}. "
            f"Tried: {[t.format(domain=cfg['domain']) for t in _AUTODISCOVER_TEMPLATES]}"
        )
    try:
        return ET.fromstring(body)
    except ET.ParseError as e:
        pytest.fail(f"Autodiscover response is not valid XML: {e}")


def _require_microsoft_format(root):
    """Skip if the endpoint returned Mozilla clientConfig instead of Autodiscover POX."""
    if local_tag(root.tag) == "clientConfig":
        pytest.skip(
            "Autodiscover URL returns Mozilla clientConfig XML, not Microsoft Autodiscover POX — "
            "Protocol-level checks are not applicable"
        )


def test_autodiscover_reachable(cfg):
    """At least one Autodiscover URL must return HTTP 200."""
    url, _ = _fetch(cfg["domain"])
    assert url is not None, (
        f"No Autodiscover endpoint reachable for {cfg['domain']!r}. "
        f"Tried: {[t.format(domain=cfg['domain']) for t in _AUTODISCOVER_TEMPLATES]}"
    )


def test_autodiscover_xml_valid(cfg):
    """Autodiscover response must be well-formed XML."""
    _root(cfg)  # raises/skips on failure


def test_autodiscover_has_imap_protocol(cfg):
    """Autodiscover must contain an IMAP Protocol block."""
    root = _root(cfg)
    _require_microsoft_format(root)
    protocols = _find_all(root, "Protocol")
    imap = [p for p in protocols if _text(p, "Type").upper() == "IMAP"]
    assert imap, "No IMAP Protocol entry found in Autodiscover response"


def test_autodiscover_imap_server_matches(cfg):
    """Autodiscover IMAP Server must match the configured imap.host."""
    root = _root(cfg)
    _require_microsoft_format(root)
    protocols = _find_all(root, "Protocol")
    imap = [p for p in protocols if _text(p, "Type").upper() == "IMAP"]
    if not imap:
        pytest.skip("No IMAP Protocol in Autodiscover")
    servers = [_text(p, "Server") for p in imap]
    expected = cfg["imap"]["host"]
    assert any(expected in s for s in servers), (
        f"imap.host {expected!r} not found in Autodiscover IMAP servers: {servers}"
    )


def test_autodiscover_imap_uses_ssl(cfg):
    """Autodiscover IMAP Protocol must enable SSL."""
    root = _root(cfg)
    _require_microsoft_format(root)
    protocols = _find_all(root, "Protocol")
    imap = [p for p in protocols if _text(p, "Type").upper() == "IMAP"]
    if not imap:
        pytest.skip("No IMAP Protocol in Autodiscover")
    ssl_values = [_text(p, "SSL").lower() for p in imap]
    assert any(v in ("on", "true", "1") for v in ssl_values), (
        f"Autodiscover IMAP Protocol does not enable SSL: {ssl_values}"
    )


def test_autodiscover_has_smtp_protocol(cfg):
    """Autodiscover must contain an SMTP Protocol block."""
    root = _root(cfg)
    _require_microsoft_format(root)
    protocols = _find_all(root, "Protocol")
    smtp = [p for p in protocols if _text(p, "Type").upper() == "SMTP"]
    assert smtp, "No SMTP Protocol entry found in Autodiscover response"


def test_autodiscover_smtp_server_matches(cfg):
    """Autodiscover SMTP Server must match the configured smtp.host."""
    root = _root(cfg)
    _require_microsoft_format(root)
    protocols = _find_all(root, "Protocol")
    smtp = [p for p in protocols if _text(p, "Type").upper() == "SMTP"]
    if not smtp:
        pytest.skip("No SMTP Protocol in Autodiscover")
    servers = [_text(p, "Server") for p in smtp]
    expected = cfg["smtp"]["host"]
    assert any(expected in s for s in servers), (
        f"smtp.host {expected!r} not found in Autodiscover SMTP servers: {servers}"
    )
