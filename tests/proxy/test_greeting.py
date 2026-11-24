"""Server greeting checks for the IMAP and SMTP endpoints (reverse-proxy aware).

IMAP and SMTP are server-first protocols: the greeting must arrive without
the client sending anything. A TCP reverse proxy that peeks at client-first
bytes — e.g. a Traefik entrypoint that also carries HTTP routers, or a
TLS-passthrough router that matches on SNI and falls through to the HTTP
handler when the SNI doesn't match — accepts the connection and then sits
silent, which normal clients see as a hang.

Each endpoint is probed once per session (lib/probe.py, cached by the
`greeting_probe` fixture): wait `proxy.greeting_timeout` seconds for a
greeting; if none arrives send a probe line and classify the reply (HTTP
answer / client-first server / silent). These tests FAIL with that
diagnosis; the connection fixtures for the same endpoint skip with a
reference here instead of every test hanging on its own timeout.

The ManageSieve equivalent is tests/managesieve/test_connect.py::
test_greeting_received, so that `pytest tests/managesieve/` reports it too.
"""

import pytest

ENDPOINTS = ["imap-ssl", "imap-starttls", "smtp-submission", "smtp-smtps"]


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_server_greeting(greeting_probe, endpoint):
    result = greeting_probe(endpoint)
    if not result.ok:
        pytest.fail(result.diagnosis)
