# CLAUDE.md — mailserver-testsuite

Black-box pytest suite for IMAP/SMTP mail servers. Connects to a live server
with real credentials and verifies correctness, security, and deliverability.

## Running the tests

```bash
pytest                  # full suite (verbose, short tracebacks via pytest.ini)
pytest tests/imap/      # one area
pytest -x -s            # stop on first failure, live output
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
smtp:
  host: mail.example.com
  port_submission: 587
  port_smtps: 465
  allow_authenticated_relay: true
  max_recipients: 100
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
```

## Last known test results (linux-ng.de, 2026-06-27)

```
92 passed, 27 skipped, 7 xfailed — 0 failures
```

### Skipped

- **DNS + SRV records** (19 tests): `dnspython` not installed. Run
  `pip install dnspython` to enable MX, SPF, DMARC, DKIM, PTR, MTA-STS,
  DANE, and RFC 6186 SRV record checks.
- **Autodiscover Protocol tests** (5 tests): the server serves Mozilla
  `clientConfig` XML at the Autodiscover URL — Microsoft POX Protocol
  checks are skipped automatically when that format is detected.
- **QUOTA extension** (2 tests): server does not advertise the QUOTA cap.
- **`test_required_capability`** (1 test): `REQUIRED_CAPS = []` — IMAP
  version is checked by a separate dedicated test.

### XFailed (soft warnings, not failures)

| Test | Reason |
|---|---|
| `test_desirable_capability[QUOTA]` | QUOTA not advertised — optional |
| `test_store_on_examined_mailbox_rejected` | Server allows STORE on read-only mailbox (RFC 3501 §6.4.6 violation) |
| `test_imap_repeated_failures_trigger_protection` | No fail2ban / rate-limit detected on IMAP |
| `test_smtp_repeated_failures_trigger_protection` | No fail2ban / rate-limit detected on SMTP |
| `test_malformed_mail_from_rejected` | Server normalises non-RFC-5321 MAIL FROM syntax |
| `test_max_recipients_enforced` | No per-message recipient cap within 500 probes |
| `test_unauthenticated_relay_rejected` | Test runner IP is in Postfix `mynetworks` — verify from an untrusted IP |

## Project layout

```
config.yaml.example   — configuration template (config.yaml is gitignored)
conftest.py           — session-scoped cfg/account fixtures + function-scoped
                        imap_ssl, imap_starttls, imap, smtp_submission, smtp_smtps
lib/
  imap.py             — connect_ssl, connect_starttls, login, logout,
                        get_capabilities, list_mailboxes(_with_flags), list_subscribed
  smtp.py             — connect_smtps, connect_submission, login, quit, build_message
  managesieve.py      — from-scratch RFC 5804 client (stdlib has no ManageSieve
                        support): greeting/capability parsing incl. literal
                        splicing, STARTTLS, SASL PLAIN, script commands
tests/
  autoconfig/         — Mozilla clientConfig, Microsoft Autodiscover, DNS SRV records
  dns/                — MX, SPF, DMARC, DKIM, PTR, MTA-STS, DANE/TLSA
  e2e/                — SMTP→IMAP round-trip, latency, Message-ID/DKIM/Received headers
  imap/               — connectivity, capabilities, folders, messages, UID ops,
                        IDLE, extensions (NAMESPACE/QUOTA), state machine
  managesieve/        — connectivity, capabilities, auth, script management
                        (PUTSCRIPT/LISTSCRIPTS/GETSCRIPT/SETACTIVE/DELETESCRIPT/
                        RENAMESCRIPT/CHECKSCRIPT/HAVESPACE)
  security/           — TLS version/cipher/cert, unencrypted-auth rejection, brute
                        force (IMAP/SMTP/ManageSieve)
  smtp/               — connectivity, auth, commands (VRFY/EXPN), limits, relay
```

## Known server quirks (linux-ng.de / Dovecot)

- **Post-login CAPABILITY omits IMAP4rev1**: Dovecot drops the version token
  from the authenticated-state CAPABILITY response. The version test uses a
  fresh pre-login connection.
- **`get_capabilities` must not unconditionally skip `parts[0]`**: Python's
  imaplib omits the `CAPABILITY` keyword from `data[0]`, so the parser now
  strips it only when it is actually present.
- **Autodiscover URL serves Mozilla format**: `autodiscover.linux-ng.de`
  returns `<clientConfig>` XML. The Mozilla autoconfig tests include that URL
  as a fallback; Autodiscover Protocol tests skip when they detect this format.
- **Relay from localhost always accepted**: Postfix `mynetworks` includes the
  loopback address, so `test_unauthenticated_relay_rejected` xfails when run
  on the server itself.
- **ManageSieve (port 4190) not currently exposed**: a TCP connect to
  `imap.linux-ng.de:4190` was accepted (no RST) but no RFC 5804 greeting
  ever arrived — something between the client and the host swallows the
  connection rather than refusing it outright. The `managesieve_cfg`
  fixture therefore does a full greeting-read preflight (not just a TCP
  connect) before running any ManageSieve test, so the whole area skips
  cleanly instead of every test hanging on its own read timeout. Once
  Dovecot's Pigeonhole managesieve service is enabled and reachable, the
  `tests/managesieve/` suite and the ManageSieve sections of
  `tests/security/test_tls.py` and `test_brute_force.py` should start
  running instead of skipping — they were validated against a local mock
  RFC 5804 server (not yet against this server's real Dovecot instance).
