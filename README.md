# mailserver-testsuite

A pytest-based black-box test suite for IMAP and SMTP mail servers. Connects to a running server with real credentials and verifies correctness, security, and deliverability — no mocking, no fixtures, no internal server access required.

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
| **ManageSieve** | STARTTLS (4190), CAPABILITY, AUTHENTICATE, script upload/list/get/activate/delete/rename/check |
| **End-to-end** | SMTP → IMAP round-trip, delivery latency, Message-ID / DKIM-Signature / Received headers |
| **Security** | LOGINDISABLED before STARTTLS, capability change after STARTTLS, brute-force protection (IMAP/SMTP/ManageSieve) |
| **DNS** | MX, SPF, DMARC, DKIM, PTR, MTA-STS, DANE/TLSA |
| **Auto-configuration** | Mozilla Autoconfig XML (Thunderbird), Microsoft Autodiscover XML (Outlook), RFC 6186/8314 DNS SRV records |

## Requirements

- Python 3.8 or later
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
```

## Configuration

All options live in `config.yaml`. Copy `config.yaml.example` to get started.

### `imap`

| Key | Default | Description |
|---|---|---|
| `host` | — | IMAP server hostname |
| `port_ssl` | `993` | Port for IMAPS (TLS from the start) |
| `port_starttls` | `143` | Port for STARTTLS |

### `smtp`

| Key | Default | Description |
|---|---|---|
| `host` | — | SMTP server hostname |
| `port_submission` | `587` | Submission port (STARTTLS) |
| `port_smtps` | `465` | SMTPS port (TLS from the start) |
| `allow_authenticated_relay` | `true` | Whether authenticated users may send to foreign domains. Set `false` if your MSA blocks it and the relay policy test should assert that. |
| `max_recipients` | `100` | Expected per-message recipient cap for the limit test |

### `managesieve`

Optional. Omit this section entirely (or leave `host` unset) to skip all ManageSieve tests; they also skip automatically if the host doesn't respond with a valid RFC 5804 greeting (e.g. the service isn't enabled), so a stale or wrong entry won't hang the suite.

| Key | Default | Description |
|---|---|---|
| `host` | — | ManageSieve server hostname |
| `port` | `4190` | RFC 5804 default (STARTTLS only — there is no implicit-TLS variant) |
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

How many consecutive failed logins to attempt before asserting that rate limiting or a block triggered. Default: `10` for IMAP, `5` for SMTP.

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
  managesieve.py      — ManageSieve (RFC 5804) protocol client
tests/
  imap/               — IMAP connectivity, folders, messages, extensions
  smtp/               — SMTP connectivity, auth, commands, limits, relay
  managesieve/        — connectivity, capabilities, auth, script management
  e2e/                — end-to-end send/receive and header checks
  security/           — TLS, unencrypted auth, brute-force protection
  dns/                — MX, SPF, DMARC, DKIM, PTR, MTA-STS, DANE
  autoconfig/         — Mozilla Autoconfig, Autodiscover, DNS SRV records
```
