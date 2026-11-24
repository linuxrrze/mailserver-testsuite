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
- **ManageSieve preflight**: the `managesieve_cfg` fixture reads the full
  RFC 5804 greeting (not just a TCP connect) before running any ManageSieve
  test, so the area skips cleanly when port 4190 accepts connections but
  never sends a greeting (e.g. a filtering middlebox), instead of every test
  hanging on its own read timeout.
