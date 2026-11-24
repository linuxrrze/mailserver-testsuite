"""Idle authenticated sessions must survive the proxy's timeouts (opt-in, slow).

Mail clients keep IMAP (IDLE) and ManageSieve sessions open and quiet for
minutes. A reverse proxy with a short idle/read timeout — Traefik v3's
entrypoint `respondingTimeouts.readTimeout` reportedly defaults to 60s
(unverified) — silently cuts such connections; clients then see random
disconnects and reconnect storms.

Opt-in via `proxy.idle_probe_seconds` (0/absent = skip). The test opens an
authenticated IMAP session and (if configured) an authenticated ManageSieve
session, sleeps once for that many seconds, then sends NOOP on both.
"""

import time

import pytest


@pytest.mark.slow
def test_sessions_survive_idle(cfg, request):
    seconds = float((cfg.get("proxy") or {}).get("idle_probe_seconds") or 0)
    if seconds <= 0:
        pytest.skip("opt-in: set proxy.idle_probe_seconds (e.g. 75) to run the idle-timeout probe")

    sessions = {"IMAP": request.getfixturevalue("imap")}
    ms = cfg.get("managesieve") or {}
    if ms.get("host"):
        try:
            sessions["ManageSieve"] = request.getfixturevalue("sieve")
        except pytest.skip.Exception:
            pass  # unusable ManageSieve is reported by its own tests

    time.sleep(seconds)

    dropped = []
    for name, conn in sessions.items():
        try:
            if name == "IMAP":
                typ, data = conn.noop()
                if typ != "OK":
                    dropped.append(f"{name}: NOOP returned {typ} {data}")
            else:
                conn.noop()
        except Exception as e:  # abort / EOF / reset / ManageSieveError
            dropped.append(f"{name}: {type(e).__name__}: {e}")

    if dropped:
        pytest.fail(
            f"Authenticated session(s) dropped after {seconds:.0f}s idle — "
            + "; ".join(dropped)
            + ". Check the reverse proxy's idle/read timeouts (e.g. Traefik entrypoint "
            "transport.respondingTimeouts.readTimeout / idleTimeout) — they must exceed "
            "the clients' IDLE/keepalive interval (IMAP IDLE re-issues every ~29 min)."
        )
