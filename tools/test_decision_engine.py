#!/usr/bin/env python3
"""End-to-end smoke test for the Phase 4 decision engine.

Hits the running WAF on https://localhost (default — the WAF redirects :80
to :443 and ships with a self-signed cert, so TLS verification is disabled
here) and the ml_engine admin API on http://localhost:8000.

Usage (host side, with the stack up):
    pip install requests
    python tools/test_decision_engine.py          # HTTPS, ignores self-signed cert
    python tools/test_decision_engine.py --no-tls # plain HTTP — only useful if you
                                                  # disabled the 80→443 redirect
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

import requests
import urllib3

ML_ADMIN  = os.getenv("ML_ADMIN", "http://localhost:8000")
TIMEOUT_S = 8.0

# Populated in main() once we've parsed --no-tls.
WAF_URL: str = ""
session: requests.Session = requests.Session()


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

@dataclass
class Result:
    name: str
    passed: bool
    detail: str = ""
    elapsed_ms: float = 0.0


@dataclass
class Suite:
    results: list[Result] = field(default_factory=list)

    def run(self, name: str, fn: Callable[[], tuple[bool, str]]) -> None:
        t0 = time.perf_counter()
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"raised: {type(e).__name__}: {e}"
        elapsed = (time.perf_counter() - t0) * 1000
        self.results.append(Result(name, ok, detail, elapsed))
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {name:38s}  {elapsed:6.0f} ms  {detail}")

    def summary(self) -> int:
        passed = sum(1 for r in self.results if r.passed)
        total  = len(self.results)
        print()
        print("=" * 72)
        print(f"{'Test':40s} {'Result':8s} {'Elapsed':>10s}")
        print("-" * 72)
        for r in self.results:
            marker = "PASS" if r.passed else "FAIL"
            print(f"{r.name:40s} {marker:8s} {r.elapsed_ms:>9.0f}ms")
        print("-" * 72)
        print(f"{passed}/{total} passed")
        print("=" * 72)
        return 0 if passed == total else 1


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def test_health() -> tuple[bool, str]:
    r = session.get(f"{WAF_URL}/_waf/health", timeout=TIMEOUT_S)
    return r.status_code == 200, f"status={r.status_code}"


def test_normal_allow() -> tuple[bool, str]:
    # A benign GET should pass through (200 from upstream OR 502/504 if no
    # backend is wired up — but the WAF decision must NOT be BLOCK).
    r = session.get(f"{WAF_URL}/", timeout=TIMEOUT_S, allow_redirects=False)
    if r.status_code == 403:
        return False, f"unexpected 403 body={r.text[:120]}"
    decision = r.headers.get("X-WAF-Decision", "")
    return True, f"status={r.status_code} decision={decision or '(passed upstream)'}"


def test_sqli_blocked() -> tuple[bool, str]:
    # Classic UNION SELECT — should trip CRS heavily and likely the ML model.
    payload = "/search?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
    r = session.get(f"{WAF_URL}{payload}", timeout=TIMEOUT_S, allow_redirects=False)
    if r.status_code != 403:
        return False, f"expected 403, got {r.status_code}"
    try:
        body = r.json()
    except ValueError:
        return False, f"no JSON body; raw={r.text[:120]}"
    has_ref = isinstance(body.get("ref"), str) and len(body["ref"]) == 8
    return has_ref, f"status=403 ref={body.get('ref')} error={body.get('error')}"


def test_blocked_ip_rule() -> tuple[bool, str]:
    """Add an ip_rule blocking a single synthetic IP, then send a request
    spoofing that IP via X-Forwarded-For (Lua's client_ip() honours XFF).
    Using a fresh /32 means the cache invalidator removes the stale entry
    for us — no race against the 60s TTL.

    Cleans up the rule in `finally` even on failure."""
    rule_id = None
    spoofed_ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"  # TEST-NET-2
    try:
        resp = session.post(
            f"{ML_ADMIN}/ip-rules",
            json={
                "ip_cidr": f"{spoofed_ip}/32",
                "action": "BLOCK",
                "reason": f"test_decision_engine:{uuid.uuid4().hex[:8]}",
                "expires_in_hours": 1,
            },
            timeout=TIMEOUT_S,
        )
        if resp.status_code not in (200, 201):
            return False, f"could not create test rule: {resp.status_code} {resp.text[:120]}"
        rule_id = resp.json()["id"]

        time.sleep(0.1)
        r = session.get(
            f"{WAF_URL}/",
            headers={"X-Forwarded-For": spoofed_ip},
            timeout=TIMEOUT_S,
            allow_redirects=False,
        )
        if r.status_code != 403:
            return False, f"expected 403 from blocked IP {spoofed_ip}, got {r.status_code}"
        try:
            body = r.json()
            return body.get("error") == "Request blocked", \
                f"status=403 ref={body.get('ref')} ip={spoofed_ip}"
        except ValueError:
            return False, f"non-JSON 403 body; raw={r.text[:120]}"
    finally:
        if rule_id:
            try:
                session.delete(f"{ML_ADMIN}/ip-rules/{rule_id}", timeout=TIMEOUT_S)
            except Exception:
                pass


def test_honeypot_blocks_ip() -> tuple[bool, str]:
    """Hit /wp-login.php and assert (a) we got the fake 200 page back, and
    (b) a new honeypot rule appeared in ip_rules within a few seconds."""
    pre = session.get(f"{ML_ADMIN}/ip-rules?limit=500", timeout=TIMEOUT_S).json()
    pre_honeypot = sum(1 for r in pre if (r.get("reason") or "") == "honeypot")

    r = session.get(f"{WAF_URL}/wp-login.php", timeout=TIMEOUT_S, allow_redirects=False)
    if r.status_code == 403:
        return False, "honeypot returned 403 (would reveal trap)"
    if r.status_code != 200:
        return False, f"expected 200 fake login, got {r.status_code}"
    if "wp-submit" not in r.text:
        return False, "fake login HTML missing expected marker"

    # ip-rules write is async via ngx.timer; give it a generous window.
    deadline = time.time() + 5.0
    while time.time() < deadline:
        post = session.get(f"{ML_ADMIN}/ip-rules?limit=500", timeout=TIMEOUT_S).json()
        post_honeypot = sum(1 for r in post if (r.get("reason") or "") == "honeypot")
        if post_honeypot > pre_honeypot:
            return True, f"honeypot rules: {pre_honeypot} → {post_honeypot}"
        time.sleep(0.25)
    return False, f"no new honeypot rule appeared (still {pre_honeypot})"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--no-tls",
        action="store_true",
        help="Hit the WAF on plain HTTP (http://localhost) instead of HTTPS. "
             "Only useful if you've disabled the built-in 80→443 redirect.",
    )
    args = parser.parse_args()

    global WAF_URL, session
    default = "http://localhost" if args.no_tls else "https://localhost"
    WAF_URL = os.getenv("WAF_URL", default)

    session = requests.Session()
    if WAF_URL.startswith("https://"):
        # Self-signed cert in dev — silence the per-request warning spam.
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"WAF URL:      {WAF_URL}")
    print(f"ml_engine:    {ML_ADMIN}")
    print()
    print("Running tests ...")
    s = Suite()
    s.run("health probe",                test_health)
    s.run("benign request not blocked",  test_normal_allow)
    s.run("SQLi payload blocked",        test_sqli_blocked)
    s.run("ip_rules BLOCK enforced",     test_blocked_ip_rule)
    s.run("honeypot adds ip_rule",       test_honeypot_blocks_ip)
    return s.summary()


if __name__ == "__main__":
    sys.exit(main())
