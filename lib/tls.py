"""TLS context factory with an optional SNI / server-name override.

A TLS-passthrough reverse proxy (e.g. Traefik TCP routers with
`HostSNI(...)` and `tls.passthrough`) picks the backend from the SNI in the
ClientHello. The name a client must send there can differ from the host it
dials (connecting to `imap.example.com` while the proxy only routes
`mail.example.com`), and a mismatch typically falls through to the proxy's
HTTP handler. The suite therefore lets the TLS server name be configured
per protocol section (`tls_servername`) independently of `host`.

Rather than threading a parameter through every test, the override lives
in a small registry keyed by (protocol, dialed host): `register_servername`
is called once from conftest's `cfg` fixture, and every context made by
`make_context(protocol=...)` (which lib/imap, lib/smtp and lib/managesieve
use) swaps in the configured name whenever it wraps a socket for that host.
The certificate is verified against the server name actually sent.
"""

import ssl
from typing import Dict, Optional, Tuple

_SERVERNAMES: Dict[Tuple[str, str], str] = {}


def register_servername(protocol: str, host: str, servername: Optional[str]) -> None:
    """Use `servername` as SNI/verification name for `protocol` connections to `host`."""
    key = (protocol, host.lower())
    if servername and servername.lower() != host.lower():
        _SERVERNAMES[key] = servername
    else:
        _SERVERNAMES.pop(key, None)


def servername_for(protocol: Optional[str], host: Optional[str]) -> Optional[str]:
    if not protocol or not host:
        return host
    return _SERVERNAMES.get((protocol, host.lower()), host)


class _ServerNameContext(ssl.SSLContext):
    """SSLContext that maps the dialed host to the configured TLS server name."""

    mail_protocol: Optional[str] = None

    def wrap_socket(self, sock, *args, server_hostname=None, **kwargs):
        server_hostname = servername_for(self.mail_protocol, server_hostname)
        return super().wrap_socket(sock, *args, server_hostname=server_hostname, **kwargs)


def make_context(no_verify: bool = False, protocol: Optional[str] = None) -> ssl.SSLContext:
    """Equivalent of ssl.create_default_context() plus the server-name override."""
    ctx = _ServerNameContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.mail_protocol = protocol
    ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    if no_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
