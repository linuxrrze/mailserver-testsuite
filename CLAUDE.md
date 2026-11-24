# CLAUDE.md — mailserver-testsuite

Black-box pytest suite for IMAP/SMTP/ManageSieve mail servers, including
ones behind a reverse proxy (e.g. Traefik in front of Postfix/Dovecot). Connects to a live server
with real credentials and verifies correctness, security, and deliverability.

## Running the tests

```bash
pytest                  # full suite (verbose, short tracebacks via pytest.ini)
pytest tests/imap/      # one area
pytest -x -s            # stop on first failure, live output
pytest -m "not slow"    # skip opt-in slow checks (proxy idle-timeout probe)
MAILTEST_CONFIG=/path/other.yaml pytest   # alternate config file
```

Full run takes ~5 minutes (live network I/O to the mail server).

## Configuration

`config.yaml` holds server details and credentials. It is gitignored.
Copy the template and fill in your values:

```bash
cp config.yaml.example config.yaml
```

Key fields:

```yaml
imap:
  host: mail.example.com
  port_ssl: 993
  port_starttls: 143
  tls_servername: mail.example.com  # optional SNI override (default: host)
smtp:
  host: mail.example.com
  port_submission: 587
  port_smtps: 465
  allow_authenticated_relay: true
  max_recipients: 100
  tls_servername: mail.example.com  # optional SNI override (default: host)
managesieve:              # optional section
  host: mail.example.com
  port: 4190
  tls: starttls           # starttls | implicit
no_verify: false          # set true for self-signed certs
accounts:
  - user: alice@example.com
    password: "secret"
  - user: bob@example.com   # second account, optional
    password: "secret2"
expected_folders: [INBOX, Sent, Drafts, Trash, Junk]
domain: example.com
dkim_selector: mail
security:
  brute_force_probe_attempts: 10
  cert_min_days_remaining: 14
proxy:                    # all optional
  greeting_timeout: 5     # wait before sending a diagnostic probe line
  idle_probe_seconds: 0   # opt-in idle-timeout probe (e.g. 75), marker `slow`
  addresses: []           # proxy IPs as the backend sees them
  expected_client_ip:     # runner IP as the server should see it (NAT)
  proxy_protocol_backend_ports: []  # opt-in reachability check, untrusted net only
  backend_host:           # host for those ports (default smtp.host)
```

## Project layout

```
config.yaml.example   — configuration template (config.yaml is gitignored)
conftest.py           — session-scoped cfg/account fixtures, cached
                        greeting_probe, managesieve_endpoint/managesieve_cfg;
                        function-scoped imap_ssl, imap_starttls, imap,
                        smtp_submission, smtp_smtps, sieve, and the
                        sieve_connect / sieve_connect_plain factories
lib/
  imap.py             — connect_ssl, connect_starttls, login, logout,
                        get_capabilities, list_mailboxes(_with_flags), list_subscribed
  smtp.py             — connect_smtps, connect_submission, login, quit, build_message
  managesieve.py      — from-scratch RFC 5804 client (stdlib has no ManageSieve
                        support): greeting/capability parsing incl. literal
                        splicing, STARTTLS or implicit TLS (connect_secure),
                        SASL PLAIN, script commands
  tls.py              — SSL context factory with per-protocol TLS server-name
                        (SNI) override registry
  probe.py            — raw-socket greeting probe + diagnosis for server-first
                        ports; PROXY-protocol backend-port reachability probe
tests/
  autoconfig/         — Mozilla clientConfig, Microsoft Autodiscover, DNS SRV records
  dns/                — MX, SPF, DMARC, DKIM, PTR, MTA-STS, DANE/TLSA
  e2e/                — SMTP→IMAP round-trip, latency, Message-ID/DKIM/Received
                        headers, real client IP on the submission hop
  imap/               — connectivity, capabilities, folders, messages, UID ops,
                        IDLE, extensions (NAMESPACE/QUOTA), state machine
  managesieve/        — connectivity, capabilities, auth, script management
                        (PUTSCRIPT/LISTSCRIPTS/GETSCRIPT/SETACTIVE/DELETESCRIPT/
                        RENAMESCRIPT/CHECKSCRIPT/HAVESPACE)
  security/           — TLS version/cipher/cert, unencrypted-auth rejection, brute
                        force (IMAP/SMTP/ManageSieve)
  proxy/              — greeting stall/HTTP-answer diagnosis (IMAP/SMTP), PROXY-
                        protocol backend port reachability (opt-in), idle timeout
                        (opt-in, slow)
  smtp/               — connectivity, auth, commands (VRFY/EXPN), limits, relay
```

## Implementation notes

- **IMAP version check uses a pre-login connection**: some servers (e.g.
  Dovecot) drop `IMAP4rev1` from the authenticated-state CAPABILITY
  response, so the version test opens a fresh connection.
- **`get_capabilities` must not unconditionally skip `parts[0]`**: Python's
  imaplib omits the `CAPABILITY` keyword from `data[0]`, so the parser
  strips it only when it is actually present.
- **Autodiscover URLs serving Mozilla format**: if the Autodiscover URL
  returns `<clientConfig>` XML, the Mozilla autoconfig tests use it as a
  fallback and the Microsoft Autodiscover Protocol tests skip.
- **Unauthenticated relay test depends on the runner's IP**: if the runner
  is in Postfix `mynetworks` (e.g. running on the server itself),
  `test_unauthenticated_relay_rejected` xfails — run it from an untrusted IP.
- **Greeting probe instead of blind connects**: IMAP, SMTP and ManageSieve
  are server-first. A reverse proxy that peeks client-first bytes (e.g. a
  Traefik entrypoint that also has HTTP routers) accepts TCP and then never
  greets. `lib/probe.py` waits `proxy.greeting_timeout`, then sends a ≥16-byte
  probe line and classifies the reply (`HTTP/` → proxy HTTP handler; other
  data → client-first; nothing → silent). The result is cached per session
  (`greeting_probe` fixture). `tests/proxy/test_greeting.py` (IMAP/SMTP) and
  `tests/managesieve/test_connect.py::test_greeting_received` FAIL with the
  diagnosis; the connection fixtures for that endpoint skip with a reference
  to it. ManageSieve only skips outright when unconfigured, unresolvable, or
  refused/unreachable. lib/imap and lib/smtp connects also carry a 30 s
  socket timeout so nothing can hang forever.
- **TLS server name is configurable**: TLS mail ports may sit behind an
  SNI-routing TLS-passthrough proxy, where the SNI must match the proxy's
  rule even if it differs from the host dialed (a mismatch typically falls
  through to the proxy's HTTP handler). `<section>.tls_servername` is
  registered in `lib/tls.py` by the `cfg` fixture and applied by every
  context from `make_ssl_context`, so tests need no per-call plumbing.
- **ManageSieve TLS mode**: `managesieve.tls: starttls | implicit`. All
  ManageSieve connections go through the `sieve_connect` factory (encrypted,
  honours the mode) or `sieve_connect_plain` (skips in implicit mode).
  Capability tests check the encrypted session's capabilities.
- **Plaintext-auth checks matter more behind a proxy**: Dovecot treats
  loopback / `login_trusted_networks` connections as secured, so a proxy
  connecting from such an address can silently enable plaintext auth for
  every client.
- **Brute-force tests behind a proxy**: a ban often shows as connect-then-
  close, a stalled greeting, or an HTTP answer rather than a refused connect;
  any connect/greeting failure after at least one successful attempt counts
  as protection. Without PROXY protocol, backend fail2ban only sees the
  proxy's IP.
- **PROXY-protocol backend ports are trusted by design** (they must accept
  headers from the proxy) and must be firewalled to the proxy only. The
  suite can only flag that such a port is reachable, and that is only
  meaningful from an untrusted network — hence opt-in. It never sends a
  mail transaction there.
- **Real client IP**: `test_submission_hop_records_real_client_ip` reuses
  the single e2e header-check message (module fixture) and confirms the
  authenticated-submission Received header shows this runner's address (or
  `proxy.expected_client_ip`), failing on loopback / `proxy.addresses`.
