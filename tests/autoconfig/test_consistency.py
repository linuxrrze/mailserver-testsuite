"""Cross-source auto-configuration consistency.

The three auto-detection sources (Mozilla Autoconfig, Microsoft Autodiscover,
DNS SRV records) and ``config.yaml`` should all point clients at the same
servers. These tests check that:

  * the available sources agree WITH EACH OTHER on host and port, for each
    incoming (IMAP) and outgoing (SMTP) endpoint type they both advertise; and
  * each available source agrees WITH config.yaml — host agreement is strict,
    and any port/socket difference is reported so the operator learns about it.

A source that is not available skips its own comparison cleanly, exactly like
the per-source tests: dnspython missing (SRV), Autodiscover not served or
serving Mozilla clientConfig, autoconfig not served. All of this is anonymous
tier — no credentials are used.

Normalisation and fetch/parse live in ``lib/autoconfig.py`` and are shared with
the per-source test modules.
"""

import pytest

from lib.autoconfig import (
    Endpoint,
    HAS_DNSPYTHON,
    MozillaFormatDetected,
    autodiscover_endpoints,
    config_endpoints,
    fetch_autodiscover,
    fetch_mozilla,
    mozilla_endpoints,
    srv_endpoints,
)


# The three auto-detection sources compared against each other (config is a
# separate, authoritative reference handled below).
AUTO_SOURCES = ("mozilla", "autodiscover", "srv")

# Endpoint identities to compare across sources. SSL = implicit TLS, STARTTLS =
# upgrade on the plaintext port.
COMPARE_KEYS = [
    ("incoming", "imap", "SSL"),
    ("incoming", "imap", "STARTTLS"),
    ("outgoing", "smtp", "SSL"),
    ("outgoing", "smtp", "STARTTLS"),
]


def _mozilla(domain):
    _, body = fetch_mozilla(domain)
    if body is None:
        return None
    try:
        eps = mozilla_endpoints(body, domain)
    except Exception:
        return None
    return eps or None


def _autodiscover(domain):
    _, body = fetch_autodiscover(domain)
    if body is None:
        return None
    try:
        eps = autodiscover_endpoints(body)
    except MozillaFormatDetected:
        return None
    except Exception:
        return None
    return eps or None


def _srv(domain):
    if not HAS_DNSPYTHON:
        return None
    try:
        eps = srv_endpoints(domain)
    except Exception:
        return None
    return eps or None


@pytest.fixture(scope="module")
def available_sources(cfg):
    """{source_name: [Endpoint, ...]} for every auto-detection source that answered.

    Fetched once per session's module. Sources that are unreachable, unparseable,
    or (for Autodiscover) serving Mozilla format are simply absent from the dict.
    """
    domain = cfg["domain"]
    out = {}
    for name, eps in (
        ("mozilla", _mozilla(domain)),
        ("autodiscover", _autodiscover(domain)),
        ("srv", _srv(domain)),
    ):
        if eps:
            out[name] = eps
    return out


def _endpoint_for(eps, key):
    direction, protocol, socket = key
    for e in eps:
        if e.direction == direction and e.protocol == protocol and e.socket == socket:
            return e
    return None


def _table(rows):
    """rows: iterable of (label, Endpoint) -> a readable multi-line block."""
    return "\n".join(f"    {label:<13} host={e.host!r} port={e.port}" for label, e in rows)


@pytest.mark.parametrize("key", COMPARE_KEYS, ids=lambda k: "-".join(map(str, k)))
def test_sources_agree_with_each_other(available_sources, key):
    """Every source that advertises an endpoint type must give the same host and port."""
    present = {
        name: _endpoint_for(eps, key)
        for name, eps in available_sources.items()
    }
    present = {name: e for name, e in present.items() if e is not None}

    if len(present) < 2:
        pytest.skip(
            f"Fewer than two sources advertise {key}: "
            f"{sorted(present) or 'none'} — nothing to cross-check"
        )

    rows = sorted(present.items())
    hosts = {(e.host or "").lower() for e in present.values()}
    ports = {e.port for e in present.values()}

    assert len(hosts) == 1, (
        f"Sources disagree on the {key} HOST:\n{_table(rows)}"
    )
    assert len(ports) == 1, (
        f"Sources disagree on the {key} PORT:\n{_table(rows)}"
    )


@pytest.mark.parametrize("source_name", AUTO_SOURCES)
def test_source_agrees_with_config(cfg, available_sources, source_name):
    """Each available source must match config.yaml: host strict, port differences reported."""
    if source_name not in available_sources:
        pytest.skip(f"{source_name} auto-config source not available for {cfg['domain']!r}")

    eps = available_sources[source_name]
    cfg_eps = config_endpoints(cfg)
    cfg_by_key = {e.key: e for e in cfg_eps}

    host_mismatches = []
    port_mismatches = []
    compared = 0

    for e in eps:
        cfg_ep = cfg_by_key.get(e.key)
        if cfg_ep is None:
            # Config has no endpoint of this exact (direction, protocol, socket);
            # still check the host against any config endpoint of the same
            # direction/protocol so a wrong host is never silently accepted.
            same = [c for c in cfg_eps if c.direction == e.direction and c.protocol == e.protocol]
            if same and e.host and e.host.lower() != (same[0].host or "").lower():
                host_mismatches.append(
                    f"{e.key}: source host={e.host!r} vs config {same[0].host!r} "
                    f"(no exact socket match in config)"
                )
            continue
        compared += 1
        if e.host and cfg_ep.host and e.host.lower() != cfg_ep.host.lower():
            host_mismatches.append(f"{e.key}: source host={e.host!r} vs config host={cfg_ep.host!r}")
        if e.port and cfg_ep.port and e.port != cfg_ep.port:
            port_mismatches.append(f"{e.key}: source port={e.port} vs config port={cfg_ep.port}")

    if compared == 0 and not host_mismatches:
        pytest.skip(
            f"{source_name} advertises no endpoint that lines up with a config.yaml "
            f"endpoint type ({[e.key for e in eps]})"
        )

    # Host agreement is strict — a different host is a real misconfiguration.
    assert not host_mismatches, (
        f"{source_name} disagrees with config.yaml on HOST:\n    " + "\n    ".join(host_mismatches)
    )
    # Port/socket differences are reported loudly: the operator asked to know
    # whether the sources and config say the same thing or differ.
    assert not port_mismatches, (
        f"{source_name} advertises a port that differs from config.yaml:\n    "
        + "\n    ".join(port_mismatches)
        + "\n    (If this endpoint is intentionally different, update config.yaml "
        "or the published record so they agree.)"
    )


def test_discovered_hosts_within_configured_domain(cfg, available_sources):
    """Report IMAP/SMTP hosts advertised outside the configured mail domain.

    Hosting mail on a different domain is valid, so this is a soft warning
    (xfail) rather than a hard failure — but the operator asked to be told.
    """
    if not available_sources:
        pytest.skip("No auto-config source available to check")
    domain = cfg["domain"].lower()
    outside = []
    for name, eps in sorted(available_sources.items()):
        for e in eps:
            if e.direction not in ("incoming", "outgoing") or not e.host:
                continue
            h = e.host.lower()
            if h != domain and not h.endswith("." + domain):
                outside.append(f"{name} {e.key}: {e.host}")
    if outside:
        pytest.xfail(
            "Auto-config advertises mail hosts outside the configured domain "
            f"{cfg['domain']!r} (valid, but worth confirming):\n    " + "\n    ".join(sorted(set(outside)))
        )
