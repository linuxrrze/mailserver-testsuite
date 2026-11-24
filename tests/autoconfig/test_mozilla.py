"""Mozilla Autoconfig endpoint tests (Thunderbird / ISPDB).

The autoconfig protocol is described at:
https://wiki.mozilla.org/Thunderbird:Autoconfiguration

Two canonical URLs are tried in order:
  1. https://autoconfig.<domain>/mail/config-v1.1.xml
  2. https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml
"""

import xml.etree.ElementTree as ET
import pytest

# Fetch/parse logic is shared with tests/autoconfig/test_consistency.py — see
# lib/autoconfig.py. These aliases keep the test bodies below unchanged.
from lib.autoconfig import MOZILLA_TEMPLATES as _AUTOCONFIG_TEMPLATES, fetch_mozilla as _fetch


def _root(cfg):
    """Fetch and parse the autoconfig XML; skip the test if unreachable."""
    _, body = _fetch(cfg["domain"])
    if body is None:
        pytest.skip(
            f"No autoconfig endpoint reachable for {cfg['domain']!r}. "
            f"Tried: {[t.format(domain=cfg['domain']) for t in _AUTOCONFIG_TEMPLATES]}"
        )
    try:
        return ET.fromstring(body)
    except ET.ParseError as e:
        pytest.fail(f"Autoconfig response is not valid XML: {e}")


def test_autoconfig_reachable(cfg):
    """At least one autoconfig URL must return HTTP 200."""
    domain = cfg["domain"]
    url, _ = _fetch(domain)
    assert url is not None, (
        f"No autoconfig endpoint reachable for {domain!r}. "
        f"Tried: {[t.format(domain=domain) for t in _AUTOCONFIG_TEMPLATES]}"
    )


def test_autoconfig_xml_has_client_config_root(cfg):
    """Autoconfig XML root element must be <clientConfig>."""
    root = _root(cfg)
    assert root.tag == "clientConfig", (
        f"Expected <clientConfig> root, got <{root.tag}>"
    )


def test_autoconfig_has_incoming_imap_server(cfg):
    """Autoconfig must contain at least one IMAP incomingServer entry."""
    root = _root(cfg)
    servers = root.findall(".//incomingServer[@type='imap']")
    assert servers, "No <incomingServer type='imap'> found in autoconfig"


def test_autoconfig_imap_host_matches(cfg):
    """Autoconfig IMAP hostname must match the configured imap.host."""
    root = _root(cfg)
    servers = root.findall(".//incomingServer[@type='imap']")
    if not servers:
        pytest.skip("No IMAP incomingServer in autoconfig")
    hostnames = [s.findtext("hostname", "") for s in servers]
    expected = cfg["imap"]["host"]
    assert any(expected in h for h in hostnames), (
        f"imap.host {expected!r} not found in autoconfig IMAP hostnames: {hostnames}"
    )


def test_autoconfig_imap_uses_encryption(cfg):
    """Autoconfig IMAP entry must specify SSL or STARTTLS."""
    root = _root(cfg)
    servers = root.findall(".//incomingServer[@type='imap']")
    if not servers:
        pytest.skip("No IMAP incomingServer in autoconfig")
    secure = [
        s for s in servers
        if s.findtext("socketType", "").upper() in ("SSL", "STARTTLS")
    ]
    assert secure, (
        "Autoconfig IMAP entry specifies neither SSL nor STARTTLS — "
        "clients will attempt unencrypted connections"
    )


def test_autoconfig_has_outgoing_smtp_server(cfg):
    """Autoconfig must contain at least one SMTP outgoingServer entry."""
    root = _root(cfg)
    servers = root.findall(".//outgoingServer[@type='smtp']")
    assert servers, "No <outgoingServer type='smtp'> found in autoconfig"


def test_autoconfig_smtp_host_matches(cfg):
    """Autoconfig SMTP hostname must match the configured smtp.host."""
    root = _root(cfg)
    servers = root.findall(".//outgoingServer[@type='smtp']")
    if not servers:
        pytest.skip("No SMTP outgoingServer in autoconfig")
    hostnames = [s.findtext("hostname", "") for s in servers]
    expected = cfg["smtp"]["host"]
    assert any(expected in h for h in hostnames), (
        f"smtp.host {expected!r} not found in autoconfig SMTP hostnames: {hostnames}"
    )


def test_autoconfig_smtp_uses_encryption(cfg):
    """Autoconfig SMTP entry must specify SSL or STARTTLS."""
    root = _root(cfg)
    servers = root.findall(".//outgoingServer[@type='smtp']")
    if not servers:
        pytest.skip("No SMTP outgoingServer in autoconfig")
    secure = [
        s for s in servers
        if s.findtext("socketType", "").upper() in ("SSL", "STARTTLS")
    ]
    assert secure, (
        "Autoconfig SMTP entry specifies neither SSL nor STARTTLS"
    )
