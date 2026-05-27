#!/usr/bin/env python3
"""End-to-end smoke test for the Phase 2 Lua request logger.

Sends a mix of benign / SQLi / XSS requests at the WAF (localhost:80) and
then drains the `waf:requests` Redis stream to confirm each one landed.

Run from the host while `docker compose up` is running:

    pip install requests redis
    python tools/test_logger.py
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass

import redis
import requests

WAF_URL    = "https://localhost"
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
STREAM     = "waf:requests"


@dataclass
class Case:
    name: str
    method: str
    path: str
    body: str | None = None
    headers: dict[str, str] | None = None


CASES: list[Case] = [
    Case("benign-root",      "GET",  "/"),
    Case("benign-static",    "GET",  "/index.html"),
    Case("benign-api",       "GET",  "/api/v1/users?page=1"),
    Case("benign-post",      "POST", "/api/v1/items",
         body=json.dumps({"name": "widget", "qty": 3}),
         headers={"Content-Type": "application/json"}),
    Case("sqli-classic",     "GET",  "/search?q=1%27%20OR%20%271%27%3D%271"),
    Case("sqli-union",       "GET",  "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"),
    Case("sqli-comment",     "GET",  "/login?u=admin%27--&p=anything"),
    Case("xss-script-tag",   "GET",  "/q?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    Case("xss-onerror",      "GET",  "/img?src=x%22%20onerror%3Dalert(1)"),
    Case("xss-javascript",   "GET",  "/redirect?url=javascript:alert(document.cookie)"),
]


def send_all() -> int:
    sent = 0
    for c in CASES:
        url = WAF_URL + c.path
        try:
            r = requests.request(
                c.method, url,
                data=c.body,
                headers=c.headers or {},
                timeout=5,
                allow_redirects=True,
                verify=False,
            )
            print(f"  → {c.name:18s} {c.method:5s} {c.path[:60]:60s}  -> {r.status_code}")
            sent += 1
        except requests.RequestException as e:
            print(f"  ! {c.name:18s} request failed: {e}", file=sys.stderr)
    return sent


def drain_stream(expected: int, timeout_s: float = 5.0) -> list[dict]:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    deadline = time.time() + timeout_s
    seen: list[dict] = []
    last_id = "0-0"
    while time.time() < deadline and len(seen) < expected:
        res = r.xread({STREAM: last_id}, count=100, block=500)
        if not res:
            continue
        for _, entries in res:
            for entry_id, fields in entries:
                fields["_id"] = entry_id
                if "features_json" in fields:
                    try:
                        fields["features"] = json.loads(fields["features_json"])
                    except Exception:
                        pass
                if "headers_json" in fields:
                    try:
                        fields["headers"] = json.loads(fields["headers_json"])
                    except Exception:
                        pass
                seen.append(fields)
                last_id = entry_id
    return seen


def pretty(entry: dict) -> str:
    redacted = {k: v for k, v in entry.items() if k not in ("headers_json", "features_json")}
    return json.dumps(redacted, indent=2, sort_keys=True, default=str)


def main() -> int:
    print(f"== sending {len(CASES)} requests to {WAF_URL} ==")
    sent = send_all()
    if sent == 0:
        print("no requests succeeded — is the WAF up on :80?", file=sys.stderr)
        return 2

    print(f"\n== draining {STREAM} (expecting >= {sent} new entries) ==")
    entries = drain_stream(expected=sent, timeout_s=5.0)
    print(f"   got {len(entries)} entries from {STREAM}")

    for e in entries:
        print("-" * 78)
        print(pretty(e))

    assert len(entries) >= sent, (
        f"expected at least {sent} stream entries, got {len(entries)}"
    )
    print(f"\n[PASS] all {sent} requests round-tripped through waf:requests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
