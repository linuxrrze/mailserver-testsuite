"""ManageSieve CAPABILITY advertisement tests (RFC 5804 §1.7 / §2.4).

Checked on the encrypted session (after STARTTLS, or the implicit-TLS
greeting) — that is the capability set clients actually use, and SASL in
particular may legitimately be empty before TLS.
"""

import pytest

REQUIRED_CAPS = ["IMPLEMENTATION", "SIEVE", "SASL", "VERSION"]


@pytest.fixture
def secure_client(sieve_connect):
    client = sieve_connect()
    yield client
    client.logout()


@pytest.mark.parametrize("cap", REQUIRED_CAPS)
def test_required_capability_present(secure_client, cap):
    assert cap in secure_client.capabilities, (
        f"Required capability {cap!r} not advertised; got: {sorted(secure_client.capabilities)}"
    )


def test_sieve_extensions_non_empty(secure_client):
    """The SIEVE capability must list the server's supported script extensions."""
    extensions = secure_client.capabilities.get("SIEVE", "").split()
    assert extensions, "SIEVE capability advertised no supported extensions"


def test_version_is_rfc5804(secure_client):
    version = secure_client.capabilities.get("VERSION", "")
    assert version == "1.0", f"Unexpected ManageSieve VERSION: {version!r}"
