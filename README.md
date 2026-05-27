# ML-WAF

![CI](https://github.com/kalkI-pratap17012002/ml-waf/actions/workflows/ci.yml/badge.svg)

ML-WAF is a machine-learning-augmented Web Application Firewall. An OpenResty/nginx gateway runs two parallel threat-detection layers — ModSecurity v3 with the OWASP Core Rule Set, and a Python ML scoring service (IsolationForest + XGBoost ensemble) — and combines their verdicts into a single `ALLOW` / `LOG` / `BLOCK` decision enforced in real time. The system is fully containerised: eight services wired together via `docker-compose.yml`, with a React admin dashboard, SHAP per-request explanations, an analyst feedback loop that retrains XGBoost on confirmed false positives, honeypot endpoints that auto-ban scanners, and a periodic threat-intel sync (AbuseIPDB + Emerging Threats).

## Architecture

```
Client (HTTP/S)
     │
     ▼
nginx + OpenResty  (:80 → 301 → :443)
  ├── ModSecurity v3 + OWASP CRS   — rule-based anomaly scoring
  ├── Lua: honeypot.lua             — decoy endpoints, IP auto-banning
  ├── Lua: decision_engine.lua      — combined decision + async logging
  ├── Lua: request_logger.lua       — log-phase XADD to waf:requests
  └── proxy_pass → upstream :8080

Redis Streams (waf:requests, waf:ml_decisions, waf:honeypot)
     │
     ▼
ml_engine  (FastAPI, internal :8000)
  ├── /score           — ML inference (IsolationForest + XGBoost ensemble)
  ├── /ip-check        — CIDR rule lookup with 60s Redis cache
  ├── /ip-rules CRUD   — PostgreSQL-backed allow/block rules
  ├── /log-request     — async durable log to Postgres + InfluxDB
  └── /api/*           — dashboard data API (requests, stats, explain, retrain)

PostgreSQL (internal :5432)
  ├── ip_rules         — CIDR allow/block/challenge rules (GiST indexed)
  ├── request_logs     — durable request log with JSONB raw envelope
  ├── false_positives  — analyst labels for feedback-loop retraining
  └── redteam_attacks  — red-team registration and detection tracking

InfluxDB (:8086)   — time-series metrics (waf_requests measurement)
Grafana  (:3001)   — dashboards over InfluxDB
Dashboard (:3000)  — Vite + React admin UI (live feed, stats, IP rules, model perf)
```

## Quickstart

```bash
git clone https://github.com/kalkI-pratap17012002/ml-waf.git
cd ml-waf
cp .env.example .env          # edit secrets if needed
docker compose up --build -d
docker compose ps             # wait for all 8 healthy
python3 tools/test_decision_engine.py
```

The first build will take ~10 minutes because the nginx image compiles
libmodsecurity from source.

Bring everything down and wipe state:

```bash
docker compose down -v
```

## Service URLs

| Service      | URL / address               | Notes                                       |
|--------------|-----------------------------|---------------------------------------------|
| WAF (HTTP)   | http://localhost/           | 301 → HTTPS (except `/_waf/health`)         |
| WAF (HTTPS)  | https://localhost/          | self-signed cert by default                 |
| Dashboard    | http://localhost:3000       | React admin UI                              |
| Grafana      | http://localhost:3001       | Time-series dashboards over InfluxDB        |
| InfluxDB     | http://localhost:8086       | Metrics store                               |
| ml_engine    | `127.0.0.1:8000` (bound)    | FastAPI admin API, localhost-only           |
| Redis        | `127.0.0.1:6379` (bound)    | Streams + IP-rate sorted sets               |
| Postgres     | internal `postgres:5432`    | Rules, logs, labels, red-team records       |

## Benchmark results

Measured on a 2026-05-27 local run of `ml_engine/evaluate.py` against the
synthetic held-out test split.

| Model                      | Precision | Recall |    F1 |   AUC |
|----------------------------|-----------|--------|-------|-------|
| ModSec-like (rules)        |    1.000  |  0.590 | 0.742 | 0.840 |
| IsolationForest            |    0.500  |  0.040 | 0.074 | 0.744 |
| **XGBoost**                |  **1.000**| **0.975** | **0.987** | **1.000** |
| ML Ensemble (0.4 iso + 0.6 xgb) |    1.000  |  0.980 | 0.990 | 0.989 |
| Combined (ML ∪ Rules)      |    1.000  |  0.980 | 0.990 | 0.989 |

Inference latency over n=500: **p50=1.10 ms, p95=1.77 ms, p99=3.20 ms, max=5.62 ms** — well under the 30 ms per-request budget.

## Key features

ML-WAF runs **dual detection** — every inbound request is scored by both ModSecurity (rule-based, OWASP CRS) and a Python ML ensemble (IsolationForest for anomaly + XGBoost for known-attack), and the verdicts are combined by `decision_engine.lua` into a single `ALLOW`/`LOG`/`BLOCK` decision.

Per-request **SHAP explanations** are exposed via `/api/explain/{id}`: feature attributions for the 20-dim feature vector with base value and sigmoid prediction, rendered inline in the dashboard's RequestDetail modal.

An **analyst feedback loop** lets reviewers label requests as `FALSE_POSITIVE` / `TRUE_POSITIVE` / `FALSE_NEGATIVE`; `POST /api/retrain` then re-extracts features from the persisted raw envelopes, retrains XGBoost on the augmented set, and atomically hot-swaps the model file on disk only if F1 improves on a held-out slice.

**Honeypot auto-banning**: paths like `/wp-login.php`, `/.env`, `/.git/config`, `/admin/`, `/phpmyadmin/` are intercepted by `honeypot.lua`, returned with a convincing fake response, and the source IP is added to a 24-hour BLOCK rule via fire-and-forget timer.

A **red-team integration API** (`/api/redteam/*`) lets pentesters register attacks ahead of time and reports back whether the WAF detected each one — feeding detected/missed counts back into the retrain pipeline as labelled feedback.

A long-lived **threat intelligence sync** (`tools/threat_intel.py`) pulls AbuseIPDB (key-gated) and Emerging Threats feeds every 6 hours, upserting each source atomically (delete-then-insert per source) and skipping any IP already in an explicit ALLOW rule.

The **React admin dashboard** (Vite, `dashboard/src/`) has four pages — Stats, LiveFeed, IP Rules, Model Performance — with React Query polling and optimistic invalidation.

## Testing

```bash
# Train models (synthetic dataset, ~30s; --fast cuts to ~5s for CI)
python3 ml_engine/train.py --fast

# Benchmark: precision/recall/F1/AUC + inference latency p50/p95/p99
python3 ml_engine/evaluate.py

# Integration smoke test against the live Docker stack
python3 tools/test_decision_engine.py
```

The CI workflow runs `ruff` lint, the train/evaluate smoke suite, and the
integration suite against a `docker compose up` stack.

## Production TLS

By default the nginx image bakes a **self-signed certificate** at `/etc/ssl/waf.{crt,key}` so `https://localhost/` works the moment the stack comes up. Port 80 redirects all traffic to 443 with one exception: `/_waf/health` stays on plain HTTP so the Docker healthcheck (and any external L4 probe) doesn't need a CA bundle.

To use a real certificate, drop `waf.crt` and `waf.key` into `nginx/ssl/` and rebuild:

```bash
cp /path/to/fullchain.pem nginx/ssl/waf.crt
cp /path/to/privkey.pem   nginx/ssl/waf.key
docker compose up --build -d nginx
```

For Let's Encrypt via Certbot, stop nginx so Certbot can bind :80 for the HTTP-01 challenge, issue the cert, then copy `fullchain.pem`/`privkey.pem` into `nginx/ssl/waf.crt`/`waf.key` and restart nginx.

## Layout

```
ml-waf/
├── nginx/          # OpenResty image + ModSecurity + Lua hooks
├── ml_engine/      # FastAPI scoring service + training + retrain pipeline
├── dashboard/      # Vite + React admin UI
├── postgres/       # init.sql + migrations
├── tools/          # threat_intel, integration tests
├── docker-compose.yml
├── .env.example
└── README.md
```
