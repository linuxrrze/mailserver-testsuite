"""Raw-socket probes for server-first mail protocols behind reverse proxies.

IMAP, SMTP and ManageSieve are *server-first*: the server speaks (greeting)
before the client sends anything. A TCP reverse proxy that has to look at
the client's first bytes before it can pick a route — e.g. a Traefik
entrypoint that also has HTTP routers attached, so it peeks for an HTTP
request or a TLS ClientHello — never forwards the connection until the
client talks. The result is a port that accepts TCP but never greets, which
an ordinary client experiences as a hang.

`probe_greeting` makes that failure mode visible: it waits for a greeting
without sending anything, and only if none arrives does it send a probe line
long enough to end the proxy's peeking (Traefik decides once it has enough
bytes to rule out / match an HTTP request line), then classifies whatever
comes back.

`probe_backend_port` checks whether a backend port that trusts PROXY
protocol headers (meant to be reachable only from the proxy) is reachable
from where the suite runs (see its docstring).

Both helpers are stdlib-only and config-agnostic; `endpoints_from_config`
maps the suite's config.yaml dict onto `Endpoint`s.
"""

import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Dict, Optional


# Long enough (>= 16 bytes) to end Traefik's client-first peeking, which
# waits for enough bytes to decide between HTTP and TCP routing; starts with
# a verb every target protocol treats as harmless.
PROBE_LINE = b"NOOP probe-from-mailserver-testsuite\r\n"

# Documentation address (RFC 5737 TEST-NET-3) used as the spoofed client IP.
SPOOFED_CLIENT_V4 = "203.0.113.7"
SPOOFED_CLIENT_V6 = "2001:db8::7"   # RFC 3849 documentation prefix

PROTOCOLS = ("imap", "smtp", "managesieve")

_GREETING_RE = {
    "imap": re.compile(rb"^\* (OK|PREAUTH|BYE)\b", re.IGNORECASE),
    "smtp": re.compile(rb"^[245]\d\d[ -]"),
    # A ManageSieve greeting is a list of capability lines ("IMPLEMENTATION"
    # ...) or, degenerate but legal, a bare final status line.
    "managesieve": re.compile(rb'^("|\{\d+\+?\}|OK\b|NO\b|BYE\b)', re.IGNORECASE),
}

_LOGOUT = {
    "imap": b"a0 LOGOUT\r\n",
    "smtp": b"QUIT\r\n",
    "managesieve": b"LOGOUT\r\n",
}

DIAG_HTTP = (
    "reverse proxy HTTP handler is answering on this port "
    "(Traefik HTTP routers without an entryPoints restriction?)"
)
DIAG_CLIENT_FIRST = (
    "server only speaks after client sends data (proxy peeking client-first bytes?)"
)
DIAG_SILENT = "connection accepted but silent"

# A greeting arrives even when a proxy prepends a PROXY-protocol header the
# backend does not consume (the server is server-first, so it greets before
# reading the poisoned input buffer). The fault only shows on the *first
# client command*, which the backend parses together with the leftover header
# bytes and rejects.
DIAG_UNCONSUMED_PROXY = (
    "a valid command was rejected right after the greeting — if this port is behind "
    "a reverse proxy that prepends a PROXY-protocol header (e.g. Traefik "
    "serversTransport=proxyprotocolv2), the backend is not consuming it, so the "
    "header bytes are parsed as protocol commands. Enable PROXY protocol on the "
    "backend listener for the proxy's address (Dovecot: haproxy=yes + "
    "haproxy_trusted_networks; Postfix: smtpd_upstream_proxy_protocol=haproxy)."
)


def looks_like_command_rejection(text: str) -> bool:
    """True if a server message reads like 'that command was invalid/unknown'.

    Used to tell an unconsumed-PROXY-header failure (STARTTLS or the first
    command rejected as garbage) apart from an ordinary protocol error.
    """
    low = text.lower()
    return any(
        s in low
        for s in (
            "error in", "invalid command", "too many invalid",
            "unknown command", "syntax error", "unrecognized command",
            "bad command", "command not",
        )
    )


def diag_sni(ep: "Endpoint") -> str:
    section = {"imap": "imap", "smtp": "smtp", "managesieve": "managesieve"}[ep.protocol]
    return (
        "a TLS-passthrough proxy routes by SNI — verify the TLS SNI used to connect "
        f"({ep.sni!r}) matches the proxy's HostSNI rule (the SNI may need to differ "
        f"from the TCP host you dialed; set {section}.tls_servername)"
    )


@dataclass
class Endpoint:
    name: str
    protocol: str            # one of PROTOCOLS
    host: str
    port: int
    implicit_tls: bool = False
    servername: Optional[str] = None   # TLS SNI / verification name; defaults to host

    @property
    def sni(self) -> str:
        return self.servername or self.host

    def __str__(self) -> str:
        tls = ""
        if self.implicit_tls:
            tls = " (implicit TLS" + (f", SNI {self.sni}" if self.sni != self.host else "") + ")"
        return f"{self.protocol} {self.host}:{self.port}{tls}"


@dataclass
class GreetingResult:
    endpoint: Endpoint
    # ok            greeting arrived on its own and looks like the protocol
    # unexpected    data arrived on its own but is not a valid greeting
    # http          an HTTP response arrived (before or after the probe line)
    # client_first  silent until the probe line, then non-HTTP data
    # silent        silent before and after the probe line
    # closed        connection accepted, then closed without any data
    # tls_failed    TCP connected but the implicit-TLS handshake failed
    # dns / refused / unreachable   could not establish TCP at all
    status: str
    greeting: bytes = b""
    reply: bytes = b""
    error: str = ""
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def not_reachable(self) -> bool:
        """True when no TCP connection could be made at all."""
        return self.status in ("dns", "refused", "unreachable")

    @property
    def diagnosis(self) -> str:
        ep = self.endpoint
        if self.status == "ok":
            return f"{ep}: greeting received: {_snippet(self.greeting)}"
        if self.status == "http":
            if self.greeting:
                msg = f"{ep}: {DIAG_HTTP}; got {_snippet(self.greeting)} instead of a greeting"
            else:
                msg = (
                    f"{ep}: no greeting within {self.elapsed:.0f}s; after the probe line: "
                    f"{DIAG_HTTP}; got {_snippet(self.reply)}"
                )
            if ep.implicit_tls:
                msg += "; " + diag_sni(ep)
            return msg
        if self.status == "client_first":
            return (
                f"{ep}: no greeting within {self.elapsed:.0f}s; {DIAG_CLIENT_FIRST}; "
                f"after the probe line got {_snippet(self.reply)}"
            )
        if self.status == "silent":
            return (
                f"{ep}: {DIAG_SILENT} — no greeting, and still no reply after "
                f"sending a probe line ({self.elapsed:.0f}s total)"
            )
        if self.status == "unexpected":
            return f"{ep}: data arrived but is not a {ep.protocol} greeting: {_snippet(self.greeting)}"
        if self.status == "closed":
            return (
                f"{ep}: connection accepted, then closed without a greeting "
                "(IP banned at the proxy/backend, or the backend is down?)"
            )
        if self.status == "tls_failed":
            hint = ""
            low = self.error.lower()
            if any(k in low for k in ("record layer", "wrong version", "unknown protocol", "packet length")):
                hint = " — the server answered with non-TLS bytes; does this port speak plaintext/STARTTLS instead?"
            return f"{ep}: TCP connected but the implicit-TLS handshake failed: {self.error}{hint}"
        if self.status == "dns":
            return f"{ep}: host name does not resolve: {self.error}"
        if self.status == "refused":
            return f"{ep}: connection refused: {self.error}"
        return f"{ep}: unreachable: {self.error}"


def _snippet(data: bytes, limit: int = 120) -> str:
    text = data.decode("utf-8", errors="replace").strip()
    first = text.splitlines()[0] if text else ""
    if len(first) > limit:
        first = first[:limit] + "..."
    return repr(first)


def _connect_tcp(host: str, port: int, timeout: float):
    """Return (socket, None) or (None, (status, error))."""
    try:
        return socket.create_connection((host, port), timeout=timeout), None
    except socket.gaierror as e:
        return None, ("dns", str(e))
    except ConnectionRefusedError as e:
        return None, ("refused", str(e))
    except OSError as e:   # timeout, no route, network unreachable ...
        return None, ("unreachable", str(e) or type(e).__name__)


def _recv_some(sock, timeout: float, settle: float = 0.3) -> Optional[bytes]:
    """Wait up to `timeout` for data, then keep collecting briefly.

    Returns the bytes read, b"" if the peer closed the connection, or None
    if nothing arrived before the timeout.
    """
    sock.settimeout(timeout)
    try:
        data = sock.recv(4096)
    except (socket.timeout, ssl.SSLWantReadError):
        return None
    except (ConnectionResetError, ssl.SSLError, OSError):
        return b""
    if not data:
        return b""
    # A greeting may span several segments (multi-line ManageSieve/SMTP).
    sock.settimeout(settle)
    while True:
        try:
            more = sock.recv(4096)
        except (socket.timeout, ssl.SSLWantReadError, ssl.SSLError, OSError):
            break
        if not more:
            break
        data += more
    return data


def probe_greeting(
    endpoint: Endpoint,
    ssl_ctx: Optional[ssl.SSLContext] = None,
    greeting_timeout: float = 5.0,
    reply_timeout: float = 5.0,
    connect_timeout: float = 10.0,
) -> GreetingResult:
    """Connect to a server-first endpoint and classify how it greets us.

    Never sends anything until `greeting_timeout` has passed without a
    greeting; then sends PROBE_LINE and waits `reply_timeout` for a reply.
    """
    start = time.monotonic()
    sock, err = _connect_tcp(endpoint.host, endpoint.port, connect_timeout)
    if err:
        return GreetingResult(endpoint, err[0], error=err[1], elapsed=time.monotonic() - start)
    try:
        if endpoint.implicit_tls:
            ctx = ssl_ctx or ssl.create_default_context()
            try:
                sock.settimeout(connect_timeout)
                sock = ctx.wrap_socket(sock, server_hostname=endpoint.sni)
            except (ssl.SSLError, OSError) as e:
                return GreetingResult(
                    endpoint, "tls_failed", error=str(e) or type(e).__name__,
                    elapsed=time.monotonic() - start,
                )

        greeting = _recv_some(sock, greeting_timeout)
        if greeting == b"":
            return GreetingResult(endpoint, "closed", elapsed=time.monotonic() - start)
        if greeting is not None:
            elapsed = time.monotonic() - start
            if greeting.startswith(b"HTTP/"):
                return GreetingResult(endpoint, "http", greeting=greeting, elapsed=elapsed)
            if _GREETING_RE[endpoint.protocol].match(greeting):
                try:
                    sock.sendall(_LOGOUT[endpoint.protocol])
                    _recv_some(sock, 1.0, settle=0.1)
                except OSError:
                    pass
                return GreetingResult(endpoint, "ok", greeting=greeting, elapsed=elapsed)
            return GreetingResult(endpoint, "unexpected", greeting=greeting, elapsed=elapsed)

        # Nothing yet — nudge a peeking proxy into making its routing decision.
        try:
            sock.sendall(PROBE_LINE)
        except OSError as e:
            return GreetingResult(endpoint, "closed", error=str(e), elapsed=time.monotonic() - start)
        reply = _recv_some(sock, reply_timeout)
        elapsed = time.monotonic() - start
        if reply is None:
            return GreetingResult(endpoint, "silent", elapsed=elapsed)
        if reply == b"":
            return GreetingResult(endpoint, "closed", elapsed=elapsed)
        if reply.startswith(b"HTTP/"):
            return GreetingResult(endpoint, "http", reply=reply, elapsed=elapsed)
        return GreetingResult(endpoint, "client_first", reply=reply, elapsed=elapsed)
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# PROXY-protocol backend port reachability
# ---------------------------------------------------------------------------

@dataclass
class BackendPortResult:
    host: str
    port: int
    reachable: bool                 # TCP connect succeeded
    plain: str = ""                 # what a connection WITHOUT a PROXY header saw
    spoofed: str = ""               # what a connection WITH a spoofed header saw
    spoof_greeted: bool = False     # spoofed header was followed by a greeting
    error: str = ""


def proxy_v1_header(peer_ip: str, port: int) -> bytes:
    """PROXY v1 line claiming the client is a documentation address."""
    try:
        v6 = ipaddress.ip_address(peer_ip).version == 6
    except ValueError:
        v6 = False
    if v6:
        return f"PROXY TCP6 {SPOOFED_CLIENT_V6} {peer_ip} 40000 {port}\r\n".encode("ascii")
    return f"PROXY TCP4 {SPOOFED_CLIENT_V4} {peer_ip} 40000 {port}\r\n".encode("ascii")


def _describe(data: Optional[bytes]) -> str:
    if data is None:
        return "silent (no data)"
    if data == b"":
        return "closed without data"
    return f"sent {_snippet(data)}"


def probe_backend_port(host: str, port: int, timeout: float = 5.0) -> BackendPortResult:
    """Check whether a PROXY-protocol backend port is reachable from here.

    Opens two connections and does nothing beyond reading what the server
    volunteers — no protocol commands, certainly no mail transaction:
      1. plain: connect, wait `timeout` for data. A backend that requires a
         PROXY header typically stays silent (waiting for it) or drops us.
      2. spoofed: connect, immediately send a PROXY v1 header claiming a
         documentation source address, then wait for data. A greeting here
         means the backend took the forged source address at face value.
    Reachability (a successful TCP connect) is the finding; the two
    transcripts are context for the report.
    """
    sock, err = _connect_tcp(host, port, timeout)
    if err:
        return BackendPortResult(host, port, False, error=f"{err[0]}: {err[1]}")
    try:
        plain = _describe(_recv_some(sock, timeout))
    finally:
        sock.close()

    sock, err = _connect_tcp(host, port, timeout)
    if err:
        return BackendPortResult(host, port, True, plain=plain, spoofed=f"second connect failed: {err[1]}")
    try:
        try:
            sock.sendall(proxy_v1_header(sock.getpeername()[0], port))
            data = _recv_some(sock, timeout)
        except OSError:
            data = b""   # reset/closed in reaction to the header
        greeted = bool(data) and not data.startswith(b"HTTP/")
        return BackendPortResult(host, port, True, plain=plain, spoofed=_describe(data), spoof_greeted=greeted)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Command-channel integrity (unconsumed PROXY-protocol header)
# ---------------------------------------------------------------------------

# One benign, unauthenticated command to send right after the greeting, and
# how to recognise a clean acceptance versus an "invalid command" rejection.
_CMD_PROBE = {
    "imap": b"mt01 CAPABILITY\r\n",
    "smtp": b"EHLO probe.mailserver-testsuite\r\n",
    "managesieve": b"CAPABILITY\r\n",
}
_CMD_ACCEPTED = {
    "imap": re.compile(rb"^mt01 OK\b", re.IGNORECASE | re.MULTILINE),
    "smtp": re.compile(rb"^250[ -]", re.MULTILINE),
    "managesieve": re.compile(rb"^OK\b", re.IGNORECASE | re.MULTILINE),
}


@dataclass
class CommandChannelResult:
    endpoint: Endpoint
    # ok         the first command was accepted cleanly
    # rejected   the server answered, but not with an acceptance (invalid-command
    #            errors / BYE — the unconsumed-PROXY-header signature)
    # silent     greeting was fine but the command drew no reply
    # closed     the connection dropped on sending the command
    # deferred   the greeting itself was not usable (the greeting test owns it)
    status: str
    greeting: bytes = b""
    reply: bytes = b""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def diagnosis(self) -> str:
        ep = self.endpoint
        if self.status == "ok":
            return f"{ep}: first command after the greeting was accepted: {_snippet(self.reply)}"
        if self.status == "rejected":
            return f"{ep}: {DIAG_UNCONSUMED_PROXY} Got {_snippet(self.reply)}."
        if self.status == "silent":
            return (
                f"{ep}: greeting arrived but a valid command drew no reply "
                "(a proxy swallowing the client->server stream?)"
            )
        if self.status == "closed":
            return f"{ep}: connection closed on the first command. {DIAG_UNCONSUMED_PROXY}"
        if self.status == "deferred":
            return f"{ep}: greeting not usable ({self.error}) — see the greeting test"
        return f"{ep}: {self.status}: {self.error}"


def probe_command_channel(
    endpoint: Endpoint,
    ssl_ctx: Optional[ssl.SSLContext] = None,
    greeting_timeout: float = 5.0,
    reply_timeout: float = 5.0,
    connect_timeout: float = 10.0,
) -> CommandChannelResult:
    """Read the greeting, then send one benign command and check it is accepted.

    Catches the reverse-proxy failure the greeting probe cannot: a proxy that
    prepends a PROXY-protocol header the backend does not consume. Because the
    protocols are server-first, the greeting still arrives clean; the leftover
    header bytes then sit in the server's input buffer ahead of the client's
    first command, which the server parses as garbage and rejects. Intended
    for plaintext / STARTTLS endpoints — with implicit TLS the same fault
    instead breaks the handshake, which `probe_greeting` reports as
    `tls_failed`.
    """
    start = time.monotonic()
    sock, err = _connect_tcp(endpoint.host, endpoint.port, connect_timeout)
    if err:
        return CommandChannelResult(endpoint, "deferred", error=f"{err[0]}: {err[1]}")
    try:
        if endpoint.implicit_tls:
            ctx = ssl_ctx or ssl.create_default_context()
            try:
                sock.settimeout(connect_timeout)
                sock = ctx.wrap_socket(sock, server_hostname=endpoint.sni)
            except (ssl.SSLError, OSError) as e:
                return CommandChannelResult(endpoint, "deferred", error=f"tls_failed: {e}")

        greeting = _recv_some(sock, greeting_timeout)
        if not greeting or greeting.startswith(b"HTTP/") or not _GREETING_RE[endpoint.protocol].match(greeting):
            # No usable greeting: this is mode A, owned by the greeting test.
            return CommandChannelResult(endpoint, "deferred", greeting=greeting or b"", error="no usable greeting")

        try:
            sock.sendall(_CMD_PROBE[endpoint.protocol])
        except OSError as e:
            return CommandChannelResult(endpoint, "closed", greeting=greeting, error=str(e))
        reply = _recv_some(sock, reply_timeout)
        try:
            sock.sendall(_LOGOUT[endpoint.protocol])
            _recv_some(sock, 1.0, settle=0.1)
        except OSError:
            pass

        if reply is None:
            return CommandChannelResult(endpoint, "silent", greeting=greeting)
        if reply == b"":
            return CommandChannelResult(endpoint, "closed", greeting=greeting)
        if _CMD_ACCEPTED[endpoint.protocol].search(reply):
            return CommandChannelResult(endpoint, "ok", greeting=greeting, reply=reply)
        return CommandChannelResult(endpoint, "rejected", greeting=greeting, reply=reply)
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Config mapping
# ---------------------------------------------------------------------------

def managesieve_tls_mode(ms_cfg: Optional[dict]) -> str:
    mode = str((ms_cfg or {}).get("tls", "starttls")).strip().lower()
    if mode not in ("starttls", "implicit"):
        raise ValueError(f"managesieve.tls must be 'starttls' or 'implicit', got {mode!r}")
    return mode


def endpoints_from_config(cfg: dict) -> Dict[str, Endpoint]:
    """Map config.yaml onto the suite's server-first endpoints, keyed by name."""
    eps: Dict[str, Endpoint] = {}
    imap = cfg.get("imap") or {}
    if imap.get("host"):
        sni = imap.get("tls_servername")
        eps["imap-ssl"] = Endpoint("imap-ssl", "imap", imap["host"], int(imap.get("port_ssl", 993)), True, sni)
        eps["imap-starttls"] = Endpoint(
            "imap-starttls", "imap", imap["host"], int(imap.get("port_starttls", 143)), False, sni
        )
    smtp = cfg.get("smtp") or {}
    if smtp.get("host"):
        sni = smtp.get("tls_servername")
        eps["smtp-submission"] = Endpoint(
            "smtp-submission", "smtp", smtp["host"], int(smtp.get("port_submission", 587)), False, sni
        )
        eps["smtp-smtps"] = Endpoint(
            "smtp-smtps", "smtp", smtp["host"], int(smtp.get("port_smtps", 465)), True, sni
        )
    ms = cfg.get("managesieve") or {}
    if ms.get("host"):
        eps["managesieve"] = Endpoint(
            "managesieve", "managesieve", ms["host"], int(ms.get("port", 4190)),
            managesieve_tls_mode(ms) == "implicit", ms.get("tls_servername"),
        )
    return eps
