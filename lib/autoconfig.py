"""Shared fetch/parse helpers for the mail auto-configuration sources.

Three independent sources can advertise where a client should connect:

  * Mozilla Autoconfig  — ``<clientConfig>`` XML (Thunderbird / ISPDB)
  * Microsoft Autodiscover — POX XML (Outlook / Exchange)
  * DNS SRV records     — RFC 6186 / RFC 8314 (_imaps, _imap, _submission,
                          _submissions, _sieve)

The per-source tests under ``tests/autoconfig/`` used to carry their own copies
of the fetch/parse code; this module holds the single implementation they and
``tests/autoconfig/test_consistency.py`` share. Nothing here calls pytest — the
tests decide when to skip/fail — and nothing logs in, so every caller is
anonymous-tier.

Each source is normalised to a list of :class:`Endpoint` records so they can be
compared with each other and with ``config.yaml``.
"""

import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Optional, Tuple

try:
    import dns.resolver  # type: ignore
    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover - exercised only where dnspython is absent
    HAS_DNSPYTHON = False


# ---------------------------------------------------------------------------
# URL templates (shared with the per-source test modules)
# ---------------------------------------------------------------------------

MOZILLA_TEMPLATES = [
    "https://autoconfig.{domain}/mail/config-v1.1.xml",
    "https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml",
    # Some servers serve clientConfig XML at the Microsoft Autodiscover path
    "https://autodiscover.{domain}/autodiscover/autodiscover.xml",
]

AUTODISCOVER_TEMPLATES = [
    "https://autodiscover.{domain}/autodiscover/autodiscover.xml",
    "https://{domain}/autodiscover/autodiscover.xml",
]


@dataclass(frozen=True)
class Endpoint:
    """One normalised server endpoint advertised by a source (or config.yaml)."""

    source: str                 # 'mozilla' | 'autodiscover' | 'srv' | 'config'
    direction: str              # 'incoming' | 'outgoing' | 'sieve'
    protocol: str               # 'imap' | 'smtp' | 'sieve'
    socket: Optional[str]       # 'SSL' | 'STARTTLS' | 'plain' | None (unspecified)
    host: Optional[str]
    port: Optional[int]

    @property
    def key(self):
        """(direction, protocol, socket) — the identity used for comparisons."""
        return (self.direction, self.protocol, self.socket)


class MozillaFormatDetected(Exception):
    """Raised when the Autodiscover URL returns Mozilla clientConfig, not POX."""


# ---------------------------------------------------------------------------
# Small shared XML/parse helpers
# ---------------------------------------------------------------------------

def local_tag(tag: str) -> str:
    """The local part of a possibly namespaced element tag."""
    return tag.split("}")[-1]


def find_all_local(root, name: str):
    """All descendants whose local tag name matches, regardless of namespace."""
    return [el for el in root.iter() if local_tag(el.tag) == name]


def child_text(el, name: str) -> str:
    """Text of the first child whose local tag name matches (namespace-agnostic)."""
    for child in el:
        if local_tag(child.tag) == name:
            return child.text or ""
    return ""


def _to_int(value) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def normalize_socket(value: Optional[str]) -> Optional[str]:
    """Map a source's socket/encryption token to SSL | STARTTLS | plain | None."""
    s = (value or "").strip().upper()
    if s in ("SSL", "TLS", "SSL/TLS"):
        return "SSL"
    if s == "STARTTLS":
        return "STARTTLS"
    if s in ("PLAIN", "NONE"):
        return "plain"
    return None


# ---------------------------------------------------------------------------
# HTTP fetch
# ---------------------------------------------------------------------------

def _fetch_from_templates(templates, domain, timeout=10) -> Tuple[Optional[str], Optional[str]]:
    """Return (url, body) for the first template that answers HTTP 200, else (None, None)."""
    for tmpl in templates:
        url = tmpl.format(domain=domain)
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                if resp.status == 200:
                    return url, resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError):
            continue
    return None, None


def fetch_mozilla(domain, timeout=10) -> Tuple[Optional[str], Optional[str]]:
    """Fetch Mozilla autoconfig XML; (url, body) or (None, None) if unreachable."""
    return _fetch_from_templates(MOZILLA_TEMPLATES, domain, timeout)


def fetch_autodiscover(domain, timeout=10) -> Tuple[Optional[str], Optional[str]]:
    """Fetch Microsoft Autodiscover XML; (url, body) or (None, None) if unreachable."""
    return _fetch_from_templates(AUTODISCOVER_TEMPLATES, domain, timeout)


# ---------------------------------------------------------------------------
# Parsers -> normalised endpoints
# ---------------------------------------------------------------------------

def _provider_domains(provider) -> set:
    """The domains a single <emailProvider> claims: its <domain> children + id attr."""
    doms = set()
    pid = (provider.get("id") or "").strip().lower()
    if pid:
        doms.add(pid)
    for child in provider:
        if local_tag(child.tag) == "domain" and (child.text or "").strip():
            doms.add(child.text.strip().lower())
    return doms


def _providers_for(root, domain: Optional[str]):
    """The <emailProvider> blocks relevant to `domain`.

    A Mozilla clientConfig may bundle several <emailProvider> blocks, each for a
    different domain and each with its own servers/ports (e.g. a main domain on
    993/465 and a sub-domain on alternate ports). Flattening them all together
    conflates unrelated endpoints, so when a domain is given we keep only the
    provider(s) that advertise it. We fall back to every provider when none
    matches (unusual layout) or when the file has no <emailProvider> wrapper.
    """
    providers = find_all_local(root, "emailProvider")
    if not providers:
        return [root]
    if domain:
        d = domain.strip().lower()
        matched = [p for p in providers if d in _provider_domains(p)]
        if matched:
            return matched
    return providers


def mozilla_endpoints(body: str, domain: Optional[str] = None) -> List[Endpoint]:
    """Normalise Mozilla clientConfig XML into IMAP incoming + SMTP outgoing endpoints.

    When `domain` is given, only the <emailProvider> block(s) advertising that
    domain are parsed, so a multi-provider file (several domains, each with its
    own ports) is not conflated into one set of endpoints.
    """
    root = ET.fromstring(body)
    eps: List[Endpoint] = []
    for provider in _providers_for(root, domain):
        for s in find_all_local(provider, "incomingServer"):
            if (s.get("type") or "").strip().lower() != "imap":
                continue
            eps.append(Endpoint(
                "mozilla", "incoming", "imap",
                normalize_socket(child_text(s, "socketType")),
                child_text(s, "hostname").strip() or None,
                _to_int(child_text(s, "port")),
            ))
        for s in find_all_local(provider, "outgoingServer"):
            if (s.get("type") or "").strip().lower() != "smtp":
                continue
            eps.append(Endpoint(
                "mozilla", "outgoing", "smtp",
                normalize_socket(child_text(s, "socketType")),
                child_text(s, "hostname").strip() or None,
                _to_int(child_text(s, "port")),
            ))
    return eps


def is_mozilla_clientconfig(root) -> bool:
    """True if this parsed root is a Mozilla <clientConfig>, not Autodiscover POX."""
    return local_tag(root.tag) == "clientConfig"


def autodiscover_endpoints(body: str) -> List[Endpoint]:
    """Normalise Microsoft Autodiscover POX XML into IMAP/SMTP endpoints.

    Raises :class:`MozillaFormatDetected` when the URL actually served Mozilla
    clientConfig XML (several servers do), so the caller can skip cleanly — the
    same detection the per-source Autodiscover tests use.
    """
    root = ET.fromstring(body)
    if is_mozilla_clientconfig(root):
        raise MozillaFormatDetected(
            "Autodiscover URL returns Mozilla clientConfig XML, not Microsoft Autodiscover POX"
        )
    eps: List[Endpoint] = []
    for p in find_all_local(root, "Protocol"):
        typ = child_text(p, "Type").upper()
        if typ == "IMAP":
            direction, protocol = "incoming", "imap"
        elif typ == "SMTP":
            direction, protocol = "outgoing", "smtp"
        else:
            continue
        ssl_on = child_text(p, "SSL").strip().lower() in ("on", "true", "1")
        socket = "SSL" if ssl_on else (normalize_socket(child_text(p, "Encryption")) or "plain")
        eps.append(Endpoint(
            "autodiscover", direction, protocol, socket,
            child_text(p, "Server").strip() or None,
            _to_int(child_text(p, "Port")),
        ))
    return eps


# ---------------------------------------------------------------------------
# DNS SRV
# ---------------------------------------------------------------------------

# (service prefix, direction, protocol, socket implied by the service name).
# _imaps/_submissions imply implicit TLS; _imap/_submission imply STARTTLS.
_SRV_SERVICES = [
    ("_imaps._tcp", "incoming", "imap", "SSL"),
    ("_imap._tcp", "incoming", "imap", "STARTTLS"),
    ("_submissions._tcp", "outgoing", "smtp", "SSL"),
    ("_submission._tcp", "outgoing", "smtp", "STARTTLS"),
    ("_sieve._tcp", "sieve", "sieve", None),
]


def srv_lookup(name: str):
    """Resolve SRV `name`; [] when the name / record type does not exist.

    Raises RuntimeError if dnspython is not installed — callers guard on
    :data:`HAS_DNSPYTHON` and skip first.
    """
    if not HAS_DNSPYTHON:
        raise RuntimeError("dnspython not installed")
    try:
        return list(dns.resolver.resolve(name, "SRV"))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


def srv_endpoints(domain: str) -> List[Endpoint]:
    """Normalise the RFC 6186/8314 mail SRV records for `domain` into endpoints.

    A record with target "." or port 0 means "service explicitly not provided"
    (RFC 6186 §6) and is dropped.
    """
    eps: List[Endpoint] = []
    for prefix, direction, protocol, socket in _SRV_SERVICES:
        name = f"{prefix}.{domain}"
        for r in srv_lookup(name):
            target = str(r.target).rstrip(".")
            if not target or r.port == 0:
                continue  # service explicitly not offered
            eps.append(Endpoint("srv", direction, protocol, socket, target, r.port))
    return eps


# ---------------------------------------------------------------------------
# config.yaml
# ---------------------------------------------------------------------------

def config_endpoints(cfg) -> List[Endpoint]:
    """The endpoints config.yaml itself specifies, in the same normalised form."""
    eps: List[Endpoint] = []
    imap = cfg.get("imap") or {}
    smtp = cfg.get("smtp") or {}
    if imap.get("host"):
        eps.append(Endpoint("config", "incoming", "imap", "SSL", imap["host"], imap.get("port_ssl", 993)))
        eps.append(Endpoint("config", "incoming", "imap", "STARTTLS", imap["host"], imap.get("port_starttls", 143)))
    if smtp.get("host"):
        eps.append(Endpoint("config", "outgoing", "smtp", "SSL", smtp["host"], smtp.get("port_smtps", 465)))
        eps.append(Endpoint("config", "outgoing", "smtp", "STARTTLS", smtp["host"], smtp.get("port_submission", 587)))
    ms = cfg.get("managesieve") or {}
    if ms.get("host"):
        eps.append(Endpoint("config", "sieve", "sieve", None, ms["host"], ms.get("port", 4190)))
    return eps
