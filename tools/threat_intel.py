#!/usr/bin/env python3
"""Threat Intelligence sync service.

Pulls high-confidence indicator lists from public feeds and pushes the
resulting CIDRs into the WAF's ip_rules table with a 24h expiry. Designed
to run as its own long-lived container — `python threat_intel.py` loops
forever, syncing every SYNC_INTERVAL_S seconds.

Sources:
  * AbuseIPDB blacklist (requires ABUSEIPDB_API_KEY; skipped gracefully if
    the var isn't set or returns 401/429).
  * Emerging Threats Block list (no key required, plain text).

Each entry is upserted with reason="threat_intel:{source}" so a future
sync run can wipe and replace its own rows without touching manually
added or honeypot-added rules.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import asyncpg
import httpx

log = logging.getLogger("threat_intel")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# --- config ----------------------------------------------------------------

POSTGRES_DSN = os.getenv(
    "POSTGRES_DSN",
    "postgresql://{u}:{p}@{h}:{port}/{db}".format(
        u=os.getenv("POSTGRES_USER", "waf"),
        p=os.getenv("POSTGRES_PASSWORD", "waf"),
        h=os.getenv("POSTGRES_HOST", "postgres"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        db=os.getenv("POSTGRES_DB", "waf"),
    ),
)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ABUSEIPDB_URL     = "https://api.abuseipdb.com/api/v2/blacklist"
ABUSEIPDB_LIMIT   = int(os.getenv("ABUSEIPDB_LIMIT", "10000"))
ABUSEIPDB_MIN_CONF = int(os.getenv("ABUSEIPDB_MIN_CONFIDENCE", "90"))

ET_URL = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"

SYNC_INTERVAL_S = int(os.getenv("THREAT_INTEL_INTERVAL_S", str(6 * 3600)))
EXPIRY_HOURS    = int(os.getenv("THREAT_INTEL_EXPIRY_H", "24"))
HTTP_TIMEOUT_S  = 30.0

# --- fetchers --------------------------------------------------------------

async def fetch_abuseipdb(client: httpx.AsyncClient) -> set[str]:
    if not ABUSEIPDB_API_KEY:
        log.info("AbuseIPDB: ABUSEIPDB_API_KEY not set, skipping")
        return set()
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"confidenceMinimum": ABUSEIPDB_MIN_CONF, "limit": ABUSEIPDB_LIMIT}
    try:
        r = await client.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=HTTP_TIMEOUT_S)
        if r.status_code != 200:
            log.warning("AbuseIPDB returned %s: %s", r.status_code, r.text[:200])
            return set()
        body = r.json()
    except Exception as e:
        log.warning("AbuseIPDB fetch failed: %s", e)
        return set()

    out: set[str] = set()
    for entry in body.get("data", []):
        ip = entry.get("ipAddress")
        if ip and _is_valid_ip(ip):
            out.add(_to_cidr(ip))
    log.info("AbuseIPDB: %d indicators", len(out))
    return out


async def fetch_emerging_threats(client: httpx.AsyncClient) -> set[str]:
    try:
        r = await client.get(ET_URL, timeout=HTTP_TIMEOUT_S)
        r.raise_for_status()
        text = r.text
    except Exception as e:
        log.warning("Emerging Threats fetch failed: %s", e)
        return set()

    out: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        # ET ships lines like "1.2.3.4" or "1.2.3.0/24"; "#" comments scattered.
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        cidr = _maybe_cidr(token)
        if cidr:
            out.add(cidr)
    log.info("Emerging Threats: %d indicators", len(out))
    return out


# --- helpers ---------------------------------------------------------------

def _is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _to_cidr(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    return f"{addr}/{32 if addr.version == 4 else 128}"


def _maybe_cidr(token: str) -> str | None:
    try:
        return str(ipaddress.ip_network(token, strict=False))
    except ValueError:
        return None


# --- DB sync ---------------------------------------------------------------

async def upsert_rules(pool: asyncpg.Pool, source: str, cidrs: set[str]) -> int:
    """Replace this source's previous rows in a single transaction. We don't
    rely on a (ip_cidr, reason) unique index because the existing schema
    doesn't have one — DELETE-then-INSERT inside a tx gives us the same
    atomic upsert semantics without a migration."""
    if not cidrs:
        return 0
    reason = f"threat_intel:{source}"
    expires_at = datetime.now(timezone.utc) + timedelta(hours=EXPIRY_HOURS)
    rows = [(c, "BLOCK", reason, expires_at) for c in cidrs]
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("DELETE FROM ip_rules WHERE reason = $1", reason)
            await conn.executemany(
                "INSERT INTO ip_rules (ip_cidr, action, reason, expires_at) "
                "VALUES ($1::cidr, $2, $3, $4)",
                rows,
            )
    return len(rows)


async def sync_once(pool: asyncpg.Pool) -> None:
    async with httpx.AsyncClient() as client:
        abuse, et = await asyncio.gather(
            fetch_abuseipdb(client),
            fetch_emerging_threats(client),
        )

    # Honour ALLOW rules before publishing: if the operator has explicitly
    # whitelisted an IP, the /ip-check lookup will already prefer ALLOW —
    # but we still avoid clutter by dropping clear overlaps here.
    async with pool.acquire() as conn:
        allow_rows = await conn.fetch(
            "SELECT ip_cidr::text AS c FROM ip_rules WHERE action='ALLOW'"
        )
    allow = {r["c"] for r in allow_rows}
    if allow:
        before = len(abuse) + len(et)
        abuse -= allow
        et    -= allow
        after  = len(abuse) + len(et)
        if before != after:
            log.info("Filtered %d indicators against ALLOW rules", before - after)

    n_abuse = await upsert_rules(pool, "abuseipdb", abuse)
    n_et    = await upsert_rules(pool, "emergingthreats", et)
    log.info("sync complete: abuseipdb=%d emergingthreats=%d", n_abuse, n_et)


async def main() -> int:
    log.info("threat_intel starting (interval=%ds, expiry=%dh)", SYNC_INTERVAL_S, EXPIRY_HOURS)
    try:
        pool = await asyncpg.create_pool(dsn=POSTGRES_DSN, min_size=1, max_size=4, command_timeout=30)
    except Exception as e:
        log.error("failed to connect to postgres: %s", e)
        return 1

    try:
        while True:
            try:
                await sync_once(pool)
            except Exception as e:
                log.exception("sync_once crashed: %s", e)
            await asyncio.sleep(SYNC_INTERVAL_S)
    finally:
        await pool.close()


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()) or 0)
    except KeyboardInterrupt:
        sys.exit(0)
