"""Command-channel integrity for plaintext server-first endpoints.

This catches the reverse-proxy failure that the greeting test (test_greeting)
cannot see. When a proxy forwards to the backend with a PROXY-protocol header
(Traefik `serversTransport=proxyprotocolv2`) but the backend listener is NOT
configured to consume it (Dovecot without `haproxy = yes`, Postfix without
`smtpd_upstream_proxy_protocol=haproxy`), the backend is server-first and so
still sends a clean greeting — but the leftover header bytes sit in its input
buffer ahead of the client's first command. That command is then parsed as
garbage and rejected ("Error in command" / "Too many invalid commands" → BYE,
or SMTP 5xx / IMAP BAD).

Each endpoint is probed once per session (lib/probe.py, cached by the
`command_channel_probe` fixture): read the greeting, send one benign
unauthenticated command (IMAP CAPABILITY / SMTP EHLO / ManageSieve
CAPABILITY), and require a clean acceptance. Implicit-TLS endpoints are not
listed — there the same misconfiguration breaks the TLS handshake instead,
which test_greeting reports as `tls_failed`. When the greeting itself is
unusable the probe defers (skips) so the greeting test owns that failure.
"""

import pytest

# Plaintext / STARTTLS server-first endpoints only.
ENDPOINTS = ["imap-starttls", "smtp-submission", "managesieve"]


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_command_channel_clean(command_channel_probe, endpoint):
    result = command_channel_probe(endpoint)
    if result.status == "deferred":
        pytest.skip(result.diagnosis)
    if not result.ok:
        pytest.fail(result.diagnosis)
