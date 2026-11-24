# mailserver-testsuite

A pytest-based black-box test suite for IMAP, SMTP and ManageSieve mail servers — including servers behind a reverse proxy (e.g. Traefik in front of Postfix/Dovecot). Connects to a running server with real credentials and verifies correctness, security, and deliverability — no mocking, no fixtures, no internal server access required.

## What it covers

| Area | Tests |
|---|---|
| **IMAP – connectivity** | IMAPS (993), STARTTLS (143), login success/failure, TLS version, cipher strength, cert validity |
| **IMAP – folders** | LIST/LSUB, standard folders present, no stale subscriptions, CREATE/RENAME/DELETE, SUBSCRIBE/UNSUBSCRIBE, RFC 6154 special-use flags |
| **IMAP – messages** | APPEND, FETCH, STORE flags, COPY, EXPUNGE, SEARCH, UID variants of all operations, 1 MB round-trip, UTF-8 subject round-trip |
| **IMAP – extensions** | CAPABILITY, IDLE (push), NAMESPACE, QUOTA, state-machine enforcement |
| **SMTP – connectivity** | Submission (587 + STARTTLS), SMTPS (465), EHLO response, TLS version, cipher, cert |
| **SMTP – auth** | AUTH success/failure, AUTH not offered before STARTTLS, AUTH rejected without TLS |
| **SMTP – protocol** | VRFY/EXPN disabled, command-sequence enforcement, malformed address rejection |
| **SMTP – limits** | SIZE advertised and enforced, null sender (MAIL FROM:\<\>), per-message recipient cap |
| **SMTP – relay** | Unauthenticated relay blocked, authenticated relay policy |
| **ManageSieve** | Greeting, STARTTLS or implicit TLS (4190), CAPABILITY, AUTHENTICATE, script upload/list/get/activate/delete/rename/check |
| **End-to-end** | SMTP → IMAP round-trip, delivery latency, Message-ID / DKIM-Signature / Received headers, real client IP recorded on the submission hop |
| **Security** | LOGINDISABLED before STARTTLS, capability change after STARTTLS, ManageSieve cert expiry margin, brute-force protection (IMAP/SMTP/ManageSieve, proxy-aware) |
| **Reverse proxy** | Greeting stall / HTTP-answer diagnosis on every server-first port, SNI hint for TLS-passthrough routing, PROXY-protocol backend port reachability (opt-in), idle-timeout survival (opt-in, slow) |
| **DNS** | MX, SPF, DMARC, DKIM, PTR, MTA-STS, DANE/TLSA |
| **Auto-configuration** | Mozilla Autoconfig XML (Thunderbird), Microsoft Autodiscover XML (Outlook), RFC 6186/8314 DNS SRV records |

## Requirements

- Python 3.9 or later
- A running mail server reachable from the machine running the tests
- Two test accounts on the server (one is sufficient for most tests)

```
pip install -r requirements.txt
```

The DNS tests also require `dnspython`:

```
pip install dnspython
```

## Setup

**1. Copy the example config and fill in your server details:**

```
cp config.yaml.example config.yaml
```

Edit `config.yaml` — at minimum set `imap.host`, `smtp.host`, `domain`, and at least one account under `accounts`. See [Configuration](#configuration) below for all options.

`config.yaml` is gitignored so credentials are never committed.

**2. Run the suite:**

```
pytest
```

## Running specific subsets

```bash
# One area only
pytest tests/imap/
pytest tests/smtp/
pytest tests/managesieve/
pytest tests/e2e/
pytest tests/security/
pytest tests/dns/

# One file
pytest tests/imap/test_folders.py

# One test by name
pytest tests/imap/test_folders.py::test_no_stale_subscriptions

# Stop on first failure, show full output
pytest -x -s

# Skip slow DNS/e2e tests
pytest --ignore=tests/dns --ignore=tests/e2e

# Skip opt-in slow checks (idle-timeout probe)
pytest -m "not slow"

# Use a different config file
MAILTEST_CONFIG=/path/to/other.yaml pytest
```

## Configuration

All options live in `config.yaml`. Copy `config.yaml.example` to get started.

### `imap`

| Key | Default | Description |
|---|---|---|
| `host` | — | IMAP server hostname |
| `port_ssl` | `993` | Port for IMAPS (TLS from the start) |
| `port_starttls` | `143` | Port for STARTTLS |
| `tls_servername` | `host` | TLS SNI / certificate name, if it differs from `host` (e.g. an SNI-routing TLS-passthrough proxy) |

### `smtp`

| Key | Default | Description |
|---|---|---|
| `host` | — | SMTP server hostname |
| `port_submission` | `587` | Submission port (STARTTLS) |
| `port_smtps` | `465` | SMTPS port (TLS from the start) |
| `allow_authenticated_relay` | `true` | Whether authenticated users may send to foreign domains. Set `false` if your MSA blocks it and the relay policy test should assert that. |
| `max_recipients` | `100` | Expected per-message recipient cap for the limit test |
| `tls_servername` | `host` | TLS SNI / certificate name, if it differs from `host` |

### `managesieve`

Optional. Omit this section entirely (or leave `host` unset) to skip all ManageSieve tests; they also skip if the host doesn't resolve or refuses the connection. If the port accepts TCP but never sends an RFC 5804 greeting (typically a reverse proxy waiting for client-first bytes), `tests/managesieve/test_connect.py::test_greeting_received` fails with a diagnosis and the other ManageSieve tests skip with a reference to it — nothing hangs.

| Key | Default | Description |
|---|---|---|
| `host` | — | ManageSieve server hostname |
| `port` | `4190` | RFC 5804 default |
| `tls` | `starttls` | `starttls` (plaintext greeting, then STARTTLS) or `implicit` (TLS from the first byte, e.g. behind a TLS-terminating proxy). STARTTLS-only checks skip in implicit mode; implicit mode adds checks that the greeting arrives over TLS, STARTTLS is not advertised, and PLAIN is offered. |
| `tls_servername` | `host` | TLS SNI / certificate name, if it differs from `host` |
| `script_prefix` | `mailtest-suite` | Prefix for the throwaway scripts uploaded/deleted during tests |

Tests that exercise `SETACTIVE` save whatever script was already active on the account beforehand and restore it afterwards, so a real, in-use filter won't be left deactivated.

### `accounts`

A list of at least one account. The first is the primary account used for all tests; the second (if present) is used where two accounts are needed.

```yaml
accounts:
  - user: alice@example.com
    password: "secret"
  - user: bob@example.com
    password: "secret2"
```

### `no_verify`

Set to `true` when testing against a server with a self-signed certificate. This disables TLS certificate verification suite-wide and automatically skips the certificate validity tests.

### `expected_folders`

List of standard folder names the server should have. Controls which parametrised folder-existence and RFC 6154 special-use flag tests run.

```yaml
expected_folders:
  - INBOX
  - Sent
  - Drafts
  - Trash
  - Junk
```

### `domain`

The mail domain (e.g. `example.com`). Used for DNS record checks and relay policy tests.

### `dkim_selector`

The DKIM selector to look up in DNS (e.g. `mail` looks up `mail._domainkey.example.com`).

### `security.brute_force_probe_attempts`

How many consecutive failed logins to attempt before asserting that rate limiting or a block triggered. Default: `10` for IMAP, `5` for SMTP. Behind a proxy a ban often shows up as a connection that is accepted and then closed/silent; any connect or greeting failure after a successful first attempt counts as protection.

### `security.cert_min_days_remaining`

Minimum remaining validity (days) of the ManageSieve certificate. Default: `14`.

### `proxy`

Optional reverse-proxy settings.

| Key | Default | Description |
|---|---|---|
| `greeting_timeout` | `5` | Seconds to wait for a greeting before sending a probe line to diagnose a stalled port |
| `idle_probe_seconds` | `0` | Opt-in: idle an authenticated IMAP and ManageSieve session this long, then NOOP (try `75`; Traefik v3's entrypoint read timeout reportedly defaults to 60 s). Marked `slow`. |
| `addresses` | `[]` | The proxy's IPs as the backend sees them; seeing one in the submission `Received` header fails the client-IP check |
| `expected_client_ip` | — | This runner's IP as the server should see it (set when NAT sits in between) |
| `proxy_protocol_backend_ports` | `[]` | Opt-in: backend ports that trust PROXY headers (e.g. `[10465]`). Fails if reachable — only meaningful when run from an **untrusted** network. Connect + greeting only, no mail transaction. |
| `backend_host` | `smtp.host` | Host for the ports above (entries may also be `"host:port"`) |

## Understanding test results

**`PASSED`** — the server behaved correctly.

**`FAILED`** — a concrete assertion failed; the server did something unexpected.

**`SKIPPED`** — the test does not apply to this server's configuration (e.g. a folder not listed in `expected_folders`, or a capability not advertised).

**`XFAIL`** — the test detected a missing best-practice (e.g. no brute-force protection triggered) but treated it as a soft warning rather than a hard failure. Review the reason shown in the output.

## Project layout

```
config.yaml.example   — configuration template
conftest.py           — shared pytest fixtures (connections, accounts)
lib/
  imap.py             — IMAP connection and parsing helpers
  smtp.py             — SMTP connection helpers
  managesieve.py      — ManageSieve (RFC 5804) protocol client (STARTTLS / implicit TLS)
  tls.py              — SSL context factory with TLS server-name (SNI) override
  probe.py            — greeting-stall diagnosis and PROXY backend-port probes
tests/
  imap/               — IMAP connectivity, folders, messages, extensions
  smtp/               — SMTP connectivity, auth, commands, limits, relay
  managesieve/        — connectivity, capabilities, auth, script management
  e2e/                — end-to-end send/receive and header checks
  security/           — TLS, unencrypted auth, brute-force protection
  dns/                — MX, SPF, DMARC, DKIM, PTR, MTA-STS, DANE
  autoconfig/         — Mozilla Autoconfig, Autodiscover, DNS SRV records
  proxy/              — greeting diagnosis, PROXY backend ports, idle timeout
```
