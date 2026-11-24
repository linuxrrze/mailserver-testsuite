"""PROXY-protocol backend ports must not be reachable from untrusted networks.

Behind a PROXY-protocol-speaking reverse proxy (e.g. Traefik with a
proxyProtocol servers transport) the backend listeners are configured to
REQUIRE and TRUST a PROXY header (Postfix `smtpd_upstream_proxy_protocol`,
Dovecot `haproxy = yes`) — that is how the real client IP reaches the mail
server. This is correct only as long as those backend ports are reachable
from the proxy alone: anyone who can connect directly can prepend their own
header, claim any source address, and so bypass fail2ban, rate limits and
IP-based trust.

OPT-IN, and only meaningful from an UNTRUSTED network. On the LAN or on the
server itself the port may legitimately be open (that is where the proxy
connects from), so this test is skipped unless
`proxy.proxy_protocol_backend_ports` lists ports to check — run it from an
outside host. It only connects and reads what the server volunteers (once
without and once with a spoofed PROXY v1 header); it sends no protocol
commands and no mail transaction.
"""

import pytest

from lib.probe import probe_backend_port


def _backend_targets(cfg):
    proxy = cfg.get("proxy") or {}
    ports = proxy.get("proxy_protocol_backend_ports") or []
    default_host = proxy.get("backend_host") or (cfg.get("smtp") or {}).get("host")
    targets = []
    for entry in ports:
        if isinstance(entry, int):
            targets.append((default_host, entry))
        else:
            host, _, port = str(entry).rpartition(":")
            targets.append((host or default_host, int(port)))
    return targets


def test_proxy_protocol_backend_ports_not_reachable(cfg):
    targets = _backend_targets(cfg)
    if not targets:
        pytest.skip(
            "opt-in: set proxy.proxy_protocol_backend_ports (and run from an UNTRUSTED "
            "network) to check that PROXY-trusting backend ports are firewalled"
        )
    timeout = float((cfg.get("proxy") or {}).get("greeting_timeout", 5))
    findings = []
    for host, port in targets:
        r = probe_backend_port(host, port, timeout=timeout)
        if not r.reachable:
            continue
        spoof = (
            "it ACCEPTED a spoofed PROXY header (greeting followed)"
            if r.spoof_greeted else f"with a spoofed PROXY header it {r.spoofed}"
        )
        findings.append(
            f"PROXY-protocol backend port {port} on {host} is reachable from this host "
            f"(without a header it {r.plain}; {spoof}); from an untrusted network this "
            "permits source-IP spoofing and fail2ban bypass. It must be firewalled to the "
            "proxy only. (Only meaningful when this suite runs from an untrusted network — "
            "on the LAN/same host the port may legitimately be open.)"
        )
    if findings:
        pytest.fail("\n".join(findings))
