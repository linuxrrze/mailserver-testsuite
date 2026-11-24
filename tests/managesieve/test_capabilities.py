"""ManageSieve CAPABILITY advertisement tests (RFC 5804 §1.7 / §2.4)."""

import pytest

from lib.managesieve import connect

REQUIRED_CAPS = ["IMPLEMENTATION", "SIEVE", "SASL", "VERSION"]


@pytest.mark.parametrize("cap", REQUIRED_CAPS)
def test_required_capability_present(managesieve_cfg, cap):
    client = connect(managesieve_cfg["host"], managesieve_cfg.get("port", 4190))
    try:
        assert cap in client.capabilities, (
            f"Required capability {cap!r} not advertised; got: {sorted(client.capabilities)}"
        )
    finally:
        client.logout()


def test_sieve_extensions_non_empty(managesieve_cfg):
    """The SIEVE capability must list the server's supported script extensions."""
    client = connect(managesieve_cfg["host"], managesieve_cfg.get("port", 4190))
    try:
        extensions = client.capabilities.get("SIEVE", "").split()
        assert extensions, "SIEVE capability advertised no supported extensions"
    finally:
        client.logout()


def test_version_is_rfc5804(managesieve_cfg):
    client = connect(managesieve_cfg["host"], managesieve_cfg.get("port", 4190))
    try:
        version = client.capabilities.get("VERSION", "")
        assert version == "1.0", f"Unexpected ManageSieve VERSION: {version!r}"
    finally:
        client.logout()
