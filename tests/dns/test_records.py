"""DNS record checks for deliverability."""

import socket
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


def _resolve(qname, rtype):
    return dns.resolver.resolve(qname, rtype)


def test_mx_record_exists(cfg):
    domain = cfg["domain"]
    answers = _resolve(domain, "MX")
    assert answers, f"No MX records found for {domain!r}"


def test_mx_points_to_configured_host(cfg):
    domain = cfg["domain"]
    smtp_host = cfg["smtp"]["host"]
    answers = _resolve(domain, "MX")
    mx_hosts = [str(r.exchange).rstrip(".") for r in answers]
    assert any(smtp_host in h for h in mx_hosts), (
        f"Configured SMTP host {smtp_host!r} not found in MX records: {mx_hosts}"
    )


def test_spf_record_exists(cfg):
    domain = cfg["domain"]
    answers = _resolve(domain, "TXT")
    spf_records = [str(r) for r in answers if "v=spf1" in str(r)]
    assert spf_records, f"No SPF (v=spf1) TXT record found for {domain!r}"


def test_dmarc_record_exists(cfg):
    domain = cfg["domain"]
    dmarc_name = f"_dmarc.{domain}"
    answers = _resolve(dmarc_name, "TXT")
    dmarc_records = [str(r) for r in answers if "v=DMARC1" in str(r)]
    assert dmarc_records, f"No DMARC (v=DMARC1) TXT record found at {dmarc_name!r}"


def test_dkim_record_exists(cfg):
    domain = cfg["domain"]
    selector = cfg.get("dkim_selector", "mail")
    dkim_name = f"{selector}._domainkey.{domain}"
    answers = _resolve(dkim_name, "TXT")
    dkim_records = [str(r) for r in answers if "v=DKIM1" in str(r)]
    assert dkim_records, f"No DKIM TXT record found at {dkim_name!r}"


def test_mta_sts_txt_record_exists(cfg):
    """_mta-sts TXT record must exist for MTA-STS policy enforcement."""
    domain = cfg["domain"]
    mta_sts_name = f"_mta-sts.{domain}"
    answers = _resolve(mta_sts_name, "TXT")
    sts_records = [str(r) for r in answers if "v=STSv1" in str(r)]
    assert sts_records, f"No MTA-STS (v=STSv1) TXT record found at {mta_sts_name!r}"


def test_mta_sts_policy_reachable(cfg):
    """MTA-STS policy file must be reachable via HTTPS."""
    import urllib.request
    import urllib.error
    domain = cfg["domain"]
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        pytest.fail(f"MTA-STS policy URL {url!r} not reachable: {e}")
    assert "version: STSv1" in body, (
        f"MTA-STS policy body does not contain 'version: STSv1': {body[:200]!r}"
    )
    assert "mode:" in body, "MTA-STS policy missing 'mode:' field"
    assert "mx:" in body, "MTA-STS policy missing 'mx:' field"


def test_dane_tlsa_record_exists(cfg):
    """DANE TLSA record must exist for the MX host on port 25."""
    smtp_host = cfg["smtp"]["host"].rstrip(".")
    tlsa_name = f"_25._tcp.{smtp_host}"
    try:
        answers = _resolve(tlsa_name, "TLSA")
        assert answers, f"No TLSA records found at {tlsa_name!r}"
    except dns.resolver.NoAnswer:
        pytest.fail(f"No TLSA record at {tlsa_name!r} — DANE not configured")
    except dns.resolver.NXDOMAIN:
        pytest.fail(f"TLSA name {tlsa_name!r} does not exist — DANE not configured")


def test_ptr_record_matches_forward(cfg):
    """rDNS of the mail server IP should resolve back to the hostname."""
    host = cfg["smtp"]["host"]
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        pytest.skip(f"Cannot resolve {host!r} to an IP")

    # Reverse lookup
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        pytest.fail(f"No PTR record for {ip}")

    assert host in ptr or ptr in host, (
        f"PTR record {ptr!r} does not match forward hostname {host!r}"
    )
