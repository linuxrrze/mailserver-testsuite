"""ManageSieve (RFC 5804) protocol client.

Python's standard library has no ManageSieve support (unlike imaplib/smtplib),
so this module implements just enough of RFC 5804's wire protocol to drive a
real server: greeting/capability parsing, STARTTLS, SASL PLAIN
authentication, and the script-management commands (PUTSCRIPT, LISTSCRIPTS,
SETACTIVE, GETSCRIPT, DELETESCRIPT, RENAMESCRIPT, CHECKSCRIPT, HAVESPACE).

Wire format notes (RFC 5804 §1.3):
  - Every command is a single CRLF-terminated line, optionally followed by a
    literal ("{N+}\\r\\n" plus N raw octets) when it carries a string too
    large or unsafe to quote (script bodies).
  - Every response is zero or more data lines followed by a final
    "OK"/"NO"/"BYE" line, optionally with a bracketed response code and a
    quoted human-readable message.
  - A literal may appear as a value anywhere a quoted string would (e.g. a
    long script name in LISTSCRIPTS), not just as a whole response line, so
    the line reader below splices literal content back into the line it
    occurs on rather than assuming it always fills the entire line.
"""

import base64
import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple


DEFAULT_PORT = 4190

_LITERAL_RE = re.compile(r"(?:^|(?<=\s))\{(\d+)\+?\}$")
_QSTRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
_STATUS_RE = re.compile(r"^(OK|NO|BYE)\b(.*)$", re.IGNORECASE)


class ManageSieveError(Exception):
    """Raised for a NO/BYE response, or a low-level protocol/connection error."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\\\", "\\")


def _quote(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def make_ssl_context(no_verify: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if no_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class ManageSieveClient:
    """A minimal synchronous RFC 5804 client."""

    def __init__(self, host: str, port: int = DEFAULT_PORT, timeout: float = 15.0):
        self.host = host
        self.port = port
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._rfile = self._sock.makefile("rb")
        self.capabilities: Dict[str, str] = {}
        self._read_greeting()

    # -- transport ------------------------------------------------------

    def socket(self):
        return self._sock

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass

    def _wrap_tls(self, ssl_ctx: ssl.SSLContext) -> None:
        self._sock = ssl_ctx.wrap_socket(self._sock, server_hostname=self.host)
        self._rfile = self._sock.makefile("rb")

    # -- line / literal IO ------------------------------------------------

    def _read_logical_line(self) -> str:
        """Read one response line, splicing in any literal it contains.

        A literal ("{N+}" or "{N}") stands in for a quoted-string value. It
        need not fill the whole line — e.g. a long "SIEVE" capability value
        is `"SIEVE" {200+}` with the key as an ordinary quoted string ahead
        of it — so this looks for the marker as the *trailing* whitespace-
        separated token, not just as the entire line. Its N raw octets are
        read verbatim (they may contain embedded CRLFs, e.g. a script body),
        then re-quoted so downstream parsing (which only looks for quoted
        strings) can treat it like any other string value; any prefix
        before the marker and any trailing tokens after the octets (e.g.
        " ACTIVE") are spliced back on around it.
        """
        raw = self._rfile.readline()
        if not raw:
            raise ManageSieveError("Connection closed by server")
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        m = _LITERAL_RE.search(line)
        if not m:
            return line
        prefix = line[: m.start()]
        size = int(m.group(1))
        data = b""
        while len(data) < size:
            chunk = self._rfile.read(size - len(data))
            if not chunk:
                raise ManageSieveError("Connection closed mid-literal")
            data += chunk
        rest_raw = self._rfile.readline()
        rest = rest_raw.decode("utf-8", errors="replace").rstrip("\r\n")
        decoded = data.decode("utf-8", errors="replace")
        return prefix + '"' + _quote(decoded) + '"' + rest

    def send(self, line: str) -> None:
        self._sock.sendall(line.encode("utf-8") + b"\r\n")

    def send_with_literal(self, prefix: str, payload: bytes) -> None:
        """Send `<prefix> {N+}\\r\\n<payload>\\r\\n` — used for script bodies."""
        header = f"{prefix} {{{len(payload)}+}}\r\n".encode("utf-8")
        self._sock.sendall(header + payload + b"\r\n")

    # -- response parsing -------------------------------------------------

    def read_response(self) -> Tuple[str, Optional[str], str, List[str]]:
        """Read lines up to and including the final OK/NO/BYE.

        Returns (status, code, message, data_lines).
        """
        data_lines: List[str] = []
        while True:
            line = self._read_logical_line()
            m = _STATUS_RE.match(line.strip())
            if not m:
                data_lines.append(line)
                continue
            status = m.group(1).upper()
            rest = m.group(2).strip()
            code = None
            if rest.startswith("("):
                end = rest.find(")")
                if end != -1:
                    code = rest[1:end]
                    rest = rest[end + 1:].strip()
            message = ""
            qm = _QSTRING_RE.match(rest)
            if qm:
                message = _unescape(qm.group(1))
            elif rest:
                message = rest
            return status, code, message, data_lines

    def _expect_ok(self) -> Tuple[Optional[str], str, List[str]]:
        status, code, message, data_lines = self.read_response()
        if status != "OK":
            raise ManageSieveError(f"{status}: {message}", code)
        return code, message, data_lines

    # -- greeting / capability ---------------------------------------------

    def _parse_capability_lines(self, lines: List[str]) -> Dict[str, str]:
        caps: Dict[str, str] = {}
        for line in lines:
            names = _QSTRING_RE.findall(line)
            if not names:
                continue
            key = _unescape(names[0]).upper()
            value = _unescape(names[1]) if len(names) > 1 else ""
            caps[key] = value
        return caps

    def _read_greeting(self) -> None:
        status, code, message, lines = self.read_response()
        if status != "OK":
            raise ManageSieveError(f"Greeting failed: {status} {message}", code)
        self.capabilities = self._parse_capability_lines(lines)

    def capability(self) -> Dict[str, str]:
        self.send("CAPABILITY")
        _, _, lines = self._expect_ok()
        self.capabilities = self._parse_capability_lines(lines)
        return self.capabilities

    # -- STARTTLS -----------------------------------------------------------

    def starttls(self, ssl_ctx: ssl.SSLContext) -> None:
        self.send("STARTTLS")
        self._expect_ok()
        self._wrap_tls(ssl_ctx)
        # RFC 5804 §2.2: capabilities advertised before negotiation are
        # discarded; the client MUST issue CAPABILITY again after STARTTLS.
        self.capability()

    # -- AUTHENTICATE (SASL PLAIN) -------------------------------------------

    def authenticate_plain(self, user: str, password: str, authzid: str = "") -> None:
        raw = f"{authzid}\0{user}\0{password}".encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        self.send(f'AUTHENTICATE "PLAIN" "{b64}"')
        self._expect_ok()

    # -- script management ----------------------------------------------------

    def list_scripts(self) -> List[Tuple[str, bool]]:
        """Return [(name, is_active), ...]."""
        self.send("LISTSCRIPTS")
        _, _, lines = self._expect_ok()
        results = []
        for line in lines:
            stripped = line.strip()
            m = _QSTRING_RE.match(stripped)
            if not m:
                continue
            name = _unescape(m.group(1))
            # The ACTIVE marker is a trailing token after the name, not just
            # any occurrence of that text — a script named e.g. "my-active-1"
            # must not be misread as active by a substring match.
            active = stripped[m.end():].strip().upper() == "ACTIVE"
            results.append((name, active))
        return results

    def put_script(self, name: str, content: str) -> None:
        self.send_with_literal(f'PUTSCRIPT "{_quote(name)}"', content.encode("utf-8"))
        self._expect_ok()

    def get_script(self, name: str) -> str:
        self.send(f'GETSCRIPT "{_quote(name)}"')
        _, _, lines = self._expect_ok()
        if not lines:
            return ""
        m = _QSTRING_RE.match(lines[0].strip())
        return _unescape(m.group(1)) if m else lines[0]

    def set_active(self, name: str) -> None:
        """Activate `name`, or pass "" to deactivate whichever script is active."""
        self.send(f'SETACTIVE "{_quote(name)}"')
        self._expect_ok()

    def delete_script(self, name: str) -> None:
        self.send(f'DELETESCRIPT "{_quote(name)}"')
        self._expect_ok()

    def rename_script(self, old_name: str, new_name: str) -> None:
        self.send(f'RENAMESCRIPT "{_quote(old_name)}" "{_quote(new_name)}"')
        self._expect_ok()

    def check_script(self, content: str) -> None:
        """Validate a script's syntax without storing it."""
        self.send_with_literal("CHECKSCRIPT", content.encode("utf-8"))
        self._expect_ok()

    def have_space(self, name: str, size: int) -> None:
        self.send(f'HAVESPACE "{_quote(name)}" {size}')
        self._expect_ok()

    def noop(self, tag: Optional[str] = None) -> None:
        self.send(f'NOOP "{_quote(tag)}"' if tag else "NOOP")
        self._expect_ok()

    def logout(self) -> None:
        try:
            self.send("LOGOUT")
            self.read_response()
        except Exception:
            pass
        finally:
            self.close()


def connect(host: str, port: int = DEFAULT_PORT, timeout: float = 15.0) -> ManageSieveClient:
    """Plain (unencrypted) connection — issue STARTTLS before AUTHENTICATE."""
    return ManageSieveClient(host, port, timeout=timeout)


def connect_starttls(
    host: str, port: int, ssl_ctx: ssl.SSLContext, timeout: float = 15.0
) -> ManageSieveClient:
    client = ManageSieveClient(host, port, timeout=timeout)
    client.starttls(ssl_ctx)
    return client


def login(client: ManageSieveClient, user: str, password: str) -> None:
    client.authenticate_plain(user, password)
