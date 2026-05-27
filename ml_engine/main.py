"""ML inference service for the WAF.

Phase 3: loads real IsolationForest + XGBoost artifacts at startup via the
FastAPI lifespan and serves an ensemble score on /score.

Phase 4 additions:
  * /ip-check, /ip-rules CRUD against PostgreSQL via asyncpg
  * /log-request → PostgreSQL request_logs + InfluxDB waf_requests measurement
  * Redis cache (60s TTL) for hot ip-check lookups
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import asyncpg
import joblib
import numpy as np
import redis
import redis.asyncio as aioredis
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from pydantic import BaseModel, Field

from feature_extractor import FEATURE_NAMES, FeatureExtractor
import retrain as retrain_mod
from explainer import Explainer

Decision = Literal["ALLOW", "LOG", "BLOCK"]
RuleAction = Literal["ALLOW", "BLOCK", "CHALLENGE"]

LOG_THRESHOLD: float = float(os.getenv("WAF_LOG_THRESHOLD", "0.4"))
BLOCK_THRESHOLD: float = float(os.getenv("WAF_BLOCK_THRESHOLD", "0.8"))

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
ML_DEC_STREAM = "waf:ml_decisions"
STREAM_MAXLEN = 100_000
IP_CACHE_TTL_S = 60

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

INFLUX_URL    = os.getenv("INFLUX_URL", "http://influxdb:8086")
INFLUX_TOKEN  = os.getenv("INFLUX_TOKEN", "")
INFLUX_ORG    = os.getenv("INFLUX_ORG", "ml-waf")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "waf_metrics")

MODEL_DIR = Path(os.getenv("WAF_MODEL_DIR", str(Path(__file__).parent / "model")))

log = logging.getLogger("ml_engine")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


class _State:
    """Process-wide model + connection state. Populated by the lifespan handler."""
    scaler: Any = None
    iso: Any = None
    xgb: Any = None
    iso_score_min: float = 0.0
    iso_score_max: float = 1.0
    iso_threshold: float = 0.5
    feature_extractor: FeatureExtractor | None = None
    xgb_importances: np.ndarray | None = None
    loaded: bool = False
    load_ms: float = 0.0
    pg_pool: asyncpg.Pool | None = None
    aredis: aioredis.Redis | None = None
    influx_write: Any = None
    influx_client: InfluxDBClient | None = None
    explainer: Explainer | None = None


STATE = _State()

_redis = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    socket_timeout=0.1,
    socket_connect_timeout=0.1,
    decode_responses=False,
)


def _load_models() -> None:
    t0 = time.perf_counter()
    STATE.scaler = joblib.load(MODEL_DIR / "scaler.pkl")
    STATE.iso = joblib.load(MODEL_DIR / "isolation_forest.pkl")
    STATE.xgb = joblib.load(MODEL_DIR / "xgb_classifier.pkl")
    with open(MODEL_DIR / "iso_threshold.json") as f:
        meta = json.load(f)
    STATE.iso_score_min = float(meta["score_min"])
    STATE.iso_score_max = float(meta["score_max"])
    STATE.iso_threshold = float(meta["normalized_threshold"])

    # Cheap reachability probe before wiring FeatureExtractor to redis — a
    # blocking timeout per /score call would blow the latency budget if redis
    # is down at startup. The FeatureExtractor's circuit breaker handles
    # mid-flight outages once we're connected.
    redis_ok = False
    try:
        with socket.create_connection((REDIS_HOST, REDIS_PORT), timeout=0.25):
            redis_ok = True
    except OSError as e:
        log.warning("redis unreachable at startup; behavioral feats disabled: %s", e)
    STATE.feature_extractor = FeatureExtractor(redis_client=_redis if redis_ok else None)
    STATE.xgb_importances = np.asarray(STATE.xgb.feature_importances_, dtype=np.float64)
    try:
        STATE.explainer = Explainer(STATE.xgb, STATE.scaler)
        log.info("SHAP explainer ready")
    except Exception as e:
        log.warning("SHAP explainer init failed (explanations disabled): %s", e)
        STATE.explainer = None
    STATE.loaded = True
    STATE.load_ms = (time.perf_counter() - t0) * 1000.0
    log.info("models loaded in %.1f ms (model_dir=%s)", STATE.load_ms, MODEL_DIR)


async def _init_pg() -> None:
    try:
        STATE.pg_pool = await asyncpg.create_pool(
            dsn=POSTGRES_DSN, min_size=1, max_size=10, command_timeout=5
        )
        log.info("postgres pool ready")
    except Exception as e:
        log.error("postgres pool init failed (admin endpoints disabled): %s", e)
        STATE.pg_pool = None


async def _init_async_redis() -> None:
    try:
        STATE.aredis = aioredis.Redis(
            host=REDIS_HOST, port=REDIS_PORT,
            socket_timeout=0.2, socket_connect_timeout=0.2,
            decode_responses=True,
        )
        await STATE.aredis.ping()
        log.info("async redis ready")
    except Exception as e:
        log.warning("async redis unavailable: %s", e)
        STATE.aredis = None


def _init_influx() -> None:
    if not INFLUX_TOKEN:
        log.warning("INFLUX_TOKEN unset; influx writes disabled")
        return
    try:
        STATE.influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
        STATE.influx_write = STATE.influx_client.write_api(write_options=SYNCHRONOUS)
        log.info("influxdb writer ready (bucket=%s)", INFLUX_BUCKET)
    except Exception as e:
        log.warning("influx writer init failed: %s", e)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        _load_models()
    except FileNotFoundError as e:
        log.error("model artifacts missing — run `python train.py` first: %s", e)
        raise
    await _init_pg()
    await _init_async_redis()
    _init_influx()
    yield
    if STATE.pg_pool:
        await STATE.pg_pool.close()
    if STATE.aredis:
        await STATE.aredis.close()
    if STATE.influx_client:
        STATE.influx_client.close()


app = FastAPI(title="ML-WAF Engine", version="0.5.0", lifespan=lifespan)

# CORS — the dashboard runs on a separate origin in dev (vite on :3000) and
# in prod when served from a different host. Locked to GET/POST/DELETE since
# we don't use PUT/PATCH anywhere.
DASHBOARD_ORIGINS = [
    o.strip() for o in os.getenv(
        "DASHBOARD_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=DASHBOARD_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def _http_exc_to_json(_req: Request, exc: HTTPException) -> JSONResponse:
    # Make sure every error path returns the documented JSON envelope rather
    # than FastAPI's default {"detail": ...} or a stray HTML page from a
    # higher-level middleware.
    detail = exc.detail if isinstance(exc.detail, str) else json.dumps(exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": _http_error_name(exc.status_code), "detail": detail},
    )


@app.exception_handler(Exception)
async def _unhandled_to_json(_req: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "detail": f"{type(exc).__name__}: {exc}"},
    )


def _http_error_name(code: int) -> str:
    return {
        400: "bad_request", 401: "unauthorized", 403: "forbidden",
        404: "not_found", 409: "conflict", 422: "unprocessable",
        503: "unavailable",
    }.get(code, "error")


# ---------------------------------------------------------------------------
# /score (Phase 3, unchanged behaviour)
# ---------------------------------------------------------------------------

class ScoreRequest(BaseModel):
    method: str
    uri: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    client_ip: str


class TopFeature(BaseModel):
    name: str
    value: float
    importance: float


class ScoreResponse(BaseModel):
    score: float
    decision: Decision
    reason: str
    inference_ms: float
    iso_score: float
    xgb_prob: float
    top_features: list[TopFeature]


def _normalize_iso_score(raw: float) -> float:
    lo, hi = STATE.iso_score_min, STATE.iso_score_max
    if hi - lo < 1e-9:
        return 0.0
    return float(np.clip((raw - lo) / (hi - lo), 0.0, 1.0))


def _decide(score: float) -> tuple[Decision, str]:
    if score >= BLOCK_THRESHOLD:
        return "BLOCK", f"score {score:.2f} >= block threshold {BLOCK_THRESHOLD}"
    if score >= LOG_THRESHOLD:
        return "LOG", f"score {score:.2f} >= log threshold {LOG_THRESHOLD}"
    return "ALLOW", "score below thresholds"


def _top_contributing(features: np.ndarray, k: int = 3) -> list[TopFeature]:
    # |scaled| * importance — captures features both unusual and important.
    scaled = STATE.scaler.transform(features)[0]
    contrib = np.abs(scaled) * STATE.xgb_importances
    raw = features[0]
    idx = np.argsort(-contrib)[:k]
    return [
        TopFeature(
            name=FEATURE_NAMES[i],
            value=float(raw[i]),
            importance=float(STATE.xgb_importances[i]),
        )
        for i in idx
    ]


def _publish_decision(req: ScoreRequest, resp: ScoreResponse) -> None:
    try:
        _redis.xadd(
            ML_DEC_STREAM,
            {
                "ts_ms":        str(int(time.time() * 1000)),
                "client_ip":    req.client_ip,
                "method":       req.method,
                "uri":          req.uri,
                "headers_json": json.dumps(req.headers, ensure_ascii=False),
                "body":         req.body or "",
                "score":        f"{resp.score:.6f}",
                "iso_score":    f"{resp.iso_score:.6f}",
                "xgb_prob":     f"{resp.xgb_prob:.6f}",
                "decision":     resp.decision,
                "reason":       resp.reason,
                "inference_ms": f"{resp.inference_ms:.3f}",
            },
            maxlen=STREAM_MAXLEN,
            approximate=True,
        )
    except Exception as e:
        log.warning("redis xadd failed (non-fatal): %s", e)


@app.get("/health")
async def health() -> dict[str, Any]:
    redis_ok = False
    try:
        redis_ok = bool(_redis.ping())
    except Exception:
        redis_ok = False
    pg_ok = False
    if STATE.pg_pool:
        try:
            async with STATE.pg_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            pg_ok = True
        except Exception:
            pg_ok = False
    return {
        "status": "ok",
        "model_loaded": STATE.loaded,
        "load_ms": STATE.load_ms,
        "redis": redis_ok,
        "postgres": pg_ok,
        "influx": bool(STATE.influx_write),
        "version": app.version,
    }


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    if not STATE.loaded:
        raise HTTPException(status_code=503, detail="models not loaded")

    t0 = time.perf_counter()
    features = STATE.feature_extractor.extract(req.model_dump())
    scaled = STATE.scaler.transform(features)

    iso_raw = float(-STATE.iso.score_samples(scaled)[0])
    iso_score = _normalize_iso_score(iso_raw)
    xgb_prob = float(STATE.xgb.predict_proba(scaled)[0, 1])
    final_score = 0.4 * iso_score + 0.6 * xgb_prob

    decision, reason = _decide(final_score)
    inference_ms = (time.perf_counter() - t0) * 1000.0

    resp = ScoreResponse(
        score=final_score,
        decision=decision,
        reason=reason,
        inference_ms=inference_ms,
        iso_score=iso_score,
        xgb_prob=xgb_prob,
        top_features=_top_contributing(features),
    )
    _publish_decision(req, resp)
    return resp


# ---------------------------------------------------------------------------
# /ip-check — hot-path IP rule lookup with Redis cache
# ---------------------------------------------------------------------------

class IpCheckResponse(BaseModel):
    action: Literal["ALLOW", "BLOCK", "NONE"]
    reason: str
    matched_cidr: str | None = None
    cached: bool = False


def _validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid ip: {ip!r}")


async def _lookup_ip_rule(ip: str) -> tuple[str, str, str | None]:
    """Return (action, reason, matched_cidr). action is 'ALLOW'|'BLOCK'|'NONE'."""
    if not STATE.pg_pool:
        return "NONE", "pg_unavailable", None
    # CIDR containment via inet >>= cidr. ALLOW wins over BLOCK if both match
    # (explicit allowlist beats automated blocklist). Ignore expired rules.
    sql = """
        SELECT action, reason, ip_cidr::text
          FROM ip_rules
         WHERE ip_cidr >>= $1::inet
           AND (expires_at IS NULL OR expires_at > now())
         ORDER BY CASE action WHEN 'ALLOW' THEN 0 WHEN 'BLOCK' THEN 1 ELSE 2 END,
                  masklen(ip_cidr) DESC
         LIMIT 1
    """
    async with STATE.pg_pool.acquire() as conn:
        row = await conn.fetchrow(sql, ip)
    if not row:
        return "NONE", "no_match", None
    return row["action"], row["reason"] or "", row["ip_cidr"]


@app.get("/ip-check", response_model=IpCheckResponse)
async def ip_check(ip: str = Query(...)) -> IpCheckResponse:
    ip = _validate_ip(ip)
    cache_key = f"iprule:{ip}"

    if STATE.aredis:
        try:
            cached = await STATE.aredis.get(cache_key)
            if cached:
                data = json.loads(cached)
                return IpCheckResponse(**data, cached=True)
        except Exception as e:
            log.debug("ip-check cache read failed: %s", e)

    action, reason, matched = await _lookup_ip_rule(ip)
    payload = {"action": action, "reason": reason, "matched_cidr": matched}

    if STATE.aredis:
        try:
            await STATE.aredis.set(cache_key, json.dumps(payload), ex=IP_CACHE_TTL_S)
        except Exception as e:
            log.debug("ip-check cache write failed: %s", e)

    return IpCheckResponse(**payload, cached=False)


# ---------------------------------------------------------------------------
# /log-request — durable request_logs + influx metric
# ---------------------------------------------------------------------------

class LogRequestBody(BaseModel):
    client_ip: str
    method: str
    uri: str
    status_code: int | None = None
    modsec_score: float = 0.0
    ml_score: float = 0.0
    decision: Decision
    request_hash: str
    inference_ms: float | None = None
    has_attack_pattern: bool = False
    uri_length: int | None = None
    # Optional raw envelope — when present we persist it as JSONB so the SHAP
    # explainer can re-extract features on demand.
    headers: dict[str, str] | None = None
    body: str | None = None


async def _insert_request_log(body: LogRequestBody) -> None:
    if not STATE.pg_pool:
        return
    raw_env: str | None = None
    if body.headers is not None or body.body is not None:
        raw_env = json.dumps({
            "method":    body.method,
            "uri":       body.uri,
            "client_ip": body.client_ip,
            "headers":   body.headers or {},
            "body":      body.body or "",
        }, ensure_ascii=False)
    sql = """
        INSERT INTO request_logs
            (client_ip, method, uri, status_code, modsec_score, ml_score,
             decision, request_hash, inference_ms, raw_request)
        VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
    """
    try:
        async with STATE.pg_pool.acquire() as conn:
            await conn.execute(
                sql,
                body.client_ip, body.method, body.uri, body.status_code,
                body.modsec_score, body.ml_score, body.decision, body.request_hash,
                body.inference_ms, raw_env,
            )
    except Exception as e:
        log.warning("request_logs insert failed: %s", e)


def _write_influx(body: LogRequestBody) -> None:
    if not STATE.influx_write:
        return
    try:
        p = (
            Point("waf_requests")
            .tag("decision", body.decision)
            .tag("method", body.method)
            .tag("has_attack_pattern", "1" if body.has_attack_pattern else "0")
            .field("ml_score", float(body.ml_score))
            .field("modsec_score", float(body.modsec_score))
            .field("inference_ms", float(body.inference_ms or 0.0))
            .field("uri_length", int(body.uri_length or len(body.uri)))
        )
        STATE.influx_write.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=p)
    except Exception as e:
        log.debug("influx write failed: %s", e)


@app.post("/log-request")
async def log_request(body: LogRequestBody, bg: BackgroundTasks) -> dict[str, str]:
    # Fire-and-forget from the caller's perspective. Background tasks still
    # await the PG insert so connection errors surface in logs rather than
    # disappearing.
    bg.add_task(_insert_request_log, body)
    bg.add_task(_write_influx, body)
    return {"status": "queued"}


# ---------------------------------------------------------------------------
# /ip-rules CRUD
# ---------------------------------------------------------------------------

class IpRuleIn(BaseModel):
    ip_cidr: str
    action: RuleAction
    reason: str | None = None
    expires_in_hours: float | None = None


class IpRuleOut(BaseModel):
    id: str
    ip_cidr: str
    action: RuleAction
    reason: str | None
    created_at: datetime
    expires_at: datetime | None


def _validate_cidr(cidr: str) -> str:
    try:
        return str(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid cidr: {cidr!r}")


async def _invalidate_ip_cache_for_cidr(cidr: str) -> None:
    """Best-effort cache bust. Caches are per-IP and enumerating every IP in
    a /16 would be silly — let those age out via the 60s TTL. We only actively
    invalidate /32 (and /128) rules, which are the common case."""
    if not STATE.aredis:
        return
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.num_addresses == 1:
            await STATE.aredis.delete(f"iprule:{net.network_address}")
    except Exception:
        pass


@app.get("/ip-rules", response_model=list[IpRuleOut])
async def list_ip_rules(
    limit: int = Query(500, ge=1, le=5000),
    include_expired: bool = Query(False),
) -> list[IpRuleOut]:
    if not STATE.pg_pool:
        raise HTTPException(status_code=503, detail="postgres unavailable")
    where = "" if include_expired else "WHERE expires_at IS NULL OR expires_at > now()"
    sql = f"""
        SELECT id, ip_cidr::text AS ip_cidr, action, reason, created_at, expires_at
          FROM ip_rules
          {where}
         ORDER BY created_at DESC
         LIMIT $1
    """
    async with STATE.pg_pool.acquire() as conn:
        rows = await conn.fetch(sql, limit)
    return [IpRuleOut(id=str(r["id"]), **{k: r[k] for k in
            ("ip_cidr", "action", "reason", "created_at", "expires_at")}) for r in rows]


@app.post("/ip-rules", response_model=IpRuleOut, status_code=201)
async def create_ip_rule(rule: IpRuleIn) -> IpRuleOut:
    if not STATE.pg_pool:
        raise HTTPException(status_code=503, detail="postgres unavailable")
    cidr = _validate_cidr(rule.ip_cidr)
    expires_at: datetime | None = None
    if rule.expires_in_hours and rule.expires_in_hours > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=rule.expires_in_hours)
    sql = """
        INSERT INTO ip_rules (ip_cidr, action, reason, expires_at)
        VALUES ($1::cidr, $2, $3, $4)
        RETURNING id, ip_cidr::text AS ip_cidr, action, reason, created_at, expires_at
    """
    async with STATE.pg_pool.acquire() as conn:
        row = await conn.fetchrow(sql, cidr, rule.action, rule.reason, expires_at)
    await _invalidate_ip_cache_for_cidr(cidr)
    return IpRuleOut(id=str(row["id"]), **{k: row[k] for k in
            ("ip_cidr", "action", "reason", "created_at", "expires_at")})


@app.delete("/ip-rules/{rule_id}", status_code=204)
async def delete_ip_rule(rule_id: str) -> None:
    if not STATE.pg_pool:
        raise HTTPException(status_code=503, detail="postgres unavailable")
    try:
        rid = UUID(rule_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid rule id")
    sql = "DELETE FROM ip_rules WHERE id = $1 RETURNING ip_cidr::text AS ip_cidr"
    async with STATE.pg_pool.acquire() as conn:
        row = await conn.fetchrow(sql, rid)
    if not row:
        raise HTTPException(status_code=404, detail="rule not found")
    await _invalidate_ip_cache_for_cidr(row["ip_cidr"])
    return None


# ---------------------------------------------------------------------------
# Dashboard API — read-only views over request_logs and analyst-facing
# write endpoints (false-positives, retrain, redteam feedback).
# All responses use the {"error","detail"} envelope on failure via the
# global exception handlers above.
# ---------------------------------------------------------------------------

def _require_pg() -> asyncpg.Pool:
    if not STATE.pg_pool:
        raise HTTPException(status_code=503, detail="postgres unavailable")
    return STATE.pg_pool


class RequestLogOut(BaseModel):
    id: int
    timestamp: datetime
    client_ip: str
    method: str
    uri: str
    status_code: int | None
    modsec_score: float | None
    ml_score: float | None
    decision: Decision
    request_hash: str
    inference_ms: float | None = None


class RequestListResponse(BaseModel):
    items: list[RequestLogOut]
    limit: int
    offset: int
    total: int


@app.get("/api/requests", response_model=RequestListResponse)
async def api_list_requests(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    decision: Decision | None = Query(None),
    ip: str | None = Query(None),
) -> RequestListResponse:
    pool = _require_pg()
    where: list[str] = []
    args: list[Any] = []
    if decision:
        args.append(decision)
        where.append(f"decision = ${len(args)}")
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"invalid ip: {ip!r}")
        args.append(ip)
        where.append(f"client_ip = ${len(args)}::inet")
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    args_with_paging = args + [limit, offset]
    sql = f"""
        SELECT id, timestamp, client_ip::text AS client_ip, method, uri,
               status_code, modsec_score, ml_score, decision, request_hash,
               inference_ms
          FROM request_logs
          {where_sql}
         ORDER BY timestamp DESC
         LIMIT ${len(args) + 1} OFFSET ${len(args) + 2}
    """
    count_sql = f"SELECT count(*) FROM request_logs {where_sql}"
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, *args_with_paging)
        total = await conn.fetchval(count_sql, *args)
    items = [RequestLogOut(**dict(r)) for r in rows]
    return RequestListResponse(items=items, limit=limit, offset=offset, total=int(total or 0))


class RequestDetailOut(RequestLogOut):
    raw_request: dict | None = None


@app.get("/api/requests/{request_id}", response_model=RequestDetailOut)
async def api_get_request(request_id: int) -> RequestDetailOut:
    pool = _require_pg()
    sql = """
        SELECT id, timestamp, client_ip::text AS client_ip, method, uri,
               status_code, modsec_score, ml_score, decision, request_hash,
               inference_ms, raw_request
          FROM request_logs WHERE id = $1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(sql, request_id)
    if not row:
        raise HTTPException(status_code=404, detail="request not found")
    data = dict(row)
    raw = data.get("raw_request")
    if isinstance(raw, str):
        try:
            data["raw_request"] = json.loads(raw)
        except json.JSONDecodeError:
            data["raw_request"] = None
    return RequestDetailOut(**data)


# ----- Stats -----------------------------------------------------------------

class StatsSummary(BaseModel):
    total_requests_24h: int
    blocked_24h: int
    avg_ml_score_24h: float
    active_ip_rules: int


@app.get("/api/stats/summary", response_model=StatsSummary)
async def api_stats_summary() -> StatsSummary:
    pool = _require_pg()
    sql = """
        SELECT
            count(*)                                         AS total,
            count(*) FILTER (WHERE decision = 'BLOCK')       AS blocked,
            COALESCE(avg(ml_score), 0)                       AS avg_score
          FROM request_logs
         WHERE timestamp > now() - interval '24 hours'
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(sql)
        rules = await conn.fetchval(
            "SELECT count(*) FROM ip_rules WHERE expires_at IS NULL OR expires_at > now()"
        )
    return StatsSummary(
        total_requests_24h=int(row["total"] or 0),
        blocked_24h=int(row["blocked"] or 0),
        avg_ml_score_24h=float(row["avg_score"] or 0.0),
        active_ip_rules=int(rules or 0),
    )


class TimeseriesBucket(BaseModel):
    bucket: datetime
    allow: int
    log: int
    block: int


@app.get("/api/stats/timeseries", response_model=list[TimeseriesBucket])
async def api_stats_timeseries(hours: int = Query(24, ge=1, le=168)) -> list[TimeseriesBucket]:
    pool = _require_pg()
    sql = """
        SELECT date_trunc('hour', timestamp) AS bucket,
               count(*) FILTER (WHERE decision = 'ALLOW') AS allow,
               count(*) FILTER (WHERE decision = 'LOG')   AS log,
               count(*) FILTER (WHERE decision = 'BLOCK') AS block
          FROM request_logs
         WHERE timestamp > now() - ($1 || ' hours')::interval
         GROUP BY 1
         ORDER BY 1
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, str(hours))
    return [TimeseriesBucket(
        bucket=r["bucket"], allow=int(r["allow"]),
        log=int(r["log"]), block=int(r["block"]),
    ) for r in rows]


class TopIpRow(BaseModel):
    client_ip: str
    requests: int
    blocked: int
    avg_ml_score: float


@app.get("/api/stats/top-ips", response_model=list[TopIpRow])
async def api_top_ips(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=100),
) -> list[TopIpRow]:
    pool = _require_pg()
    sql = """
        SELECT client_ip::text AS client_ip,
               count(*)                                   AS requests,
               count(*) FILTER (WHERE decision='BLOCK')   AS blocked,
               COALESCE(avg(ml_score), 0)                 AS avg_score
          FROM request_logs
         WHERE timestamp > now() - ($1 || ' hours')::interval
           AND (decision = 'BLOCK' OR decision = 'LOG')
         GROUP BY client_ip
         ORDER BY blocked DESC, requests DESC
         LIMIT $2
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, str(hours), limit)
    return [TopIpRow(
        client_ip=r["client_ip"], requests=int(r["requests"]),
        blocked=int(r["blocked"]), avg_ml_score=float(r["avg_score"] or 0),
    ) for r in rows]


# Heuristic attack-type classification driven by stored features. This is
# best-effort labelling for the dashboard pie chart — the truth lives in the
# raw payload, which we inspect here.
@app.get("/api/stats/attack-types")
async def api_attack_types(hours: int = Query(24, ge=1, le=168)) -> dict[str, int]:
    pool = _require_pg()
    sql = """
        SELECT uri, raw_request, decision
          FROM request_logs
         WHERE timestamp > now() - ($1 || ' hours')::interval
           AND decision IN ('BLOCK', 'LOG', 'ALLOW')
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, str(hours))

    counts = {"SQLi": 0, "XSS": 0, "Scanner": 0, "Anomaly": 0, "Clean": 0}
    for r in rows:
        decision = r["decision"]
        if decision == "ALLOW":
            counts["Clean"] += 1
            continue
        uri = (r["uri"] or "").lower()
        raw = r["raw_request"]
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = None
        body = ((raw or {}).get("body") or "").lower()
        ua = ""
        for k, v in ((raw or {}).get("headers") or {}).items():
            if k.lower() == "user-agent":
                ua = (v or "").lower()
                break
        hay = uri + " " + body
        if any(s in hay for s in ("union", "select", "' or", "--", "drop ", "xp_")):
            counts["SQLi"] += 1
        elif any(s in hay for s in ("<script", "javascript:", "onerror=", "onload=", "alert(")):
            counts["XSS"] += 1
        elif any(s in ua for s in ("nmap", "nikto", "sqlmap", "nessus", "masscan", "wpscan", "gobuster", "dirbuster", "wfuzz")):
            counts["Scanner"] += 1
        else:
            counts["Anomaly"] += 1
    return counts


# ----- Explainer -------------------------------------------------------------

@app.get("/api/explain/{request_log_id}")
async def api_explain(request_log_id: int) -> dict:
    if not STATE.explainer:
        raise HTTPException(status_code=503, detail="explainer not available")
    pool = _require_pg()
    sql = "SELECT method, uri, client_ip::text AS client_ip, raw_request FROM request_logs WHERE id = $1"
    async with pool.acquire() as conn:
        row = await conn.fetchrow(sql, request_log_id)
    if not row:
        raise HTTPException(status_code=404, detail="request not found")
    raw = row["raw_request"]
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = None
    if not raw:
        # Fall back to a minimal envelope so SHAP still has something to
        # chew on — uri-based features will be accurate, body-based ones zero.
        raw = {
            "method": row["method"], "uri": row["uri"],
            "client_ip": row["client_ip"], "headers": {}, "body": "",
        }

    t0 = time.perf_counter()
    vec = STATE.feature_extractor.extract(raw)
    explanation = STATE.explainer.explain(vec)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "request_log_id": request_log_id,
        "elapsed_ms": elapsed_ms,
        **explanation,
    }


# ----- False positives -------------------------------------------------------

FpLabel = Literal["FALSE_POSITIVE", "TRUE_POSITIVE", "FALSE_NEGATIVE", "UNSURE"]


class FalsePositiveIn(BaseModel):
    request_log_id: int
    label: FpLabel
    labeled_by: str = "dashboard"


class FalsePositiveOut(BaseModel):
    id: int
    request_log_id: int
    label: FpLabel
    labeled_at: datetime
    labeled_by: str


@app.post("/api/false-positives", response_model=FalsePositiveOut, status_code=201)
async def api_create_fp(body: FalsePositiveIn) -> FalsePositiveOut:
    pool = _require_pg()
    sql = """
        INSERT INTO false_positives (request_log_id, label, labeled_by)
        VALUES ($1, $2, $3)
        RETURNING id, request_log_id, label, labeled_at, labeled_by
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(sql, body.request_log_id, body.label, body.labeled_by)
    except asyncpg.ForeignKeyViolationError:
        raise HTTPException(status_code=404, detail="request_log_id not found")
    return FalsePositiveOut(**dict(row))


@app.get("/api/false-positives", response_model=list[FalsePositiveOut])
async def api_list_fp(limit: int = Query(100, ge=1, le=1000)) -> list[FalsePositiveOut]:
    pool = _require_pg()
    sql = """
        SELECT id, request_log_id, label, labeled_at, labeled_by
          FROM false_positives ORDER BY labeled_at DESC LIMIT $1
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql, limit)
    return [FalsePositiveOut(**dict(r)) for r in rows]


# ----- Retrain ---------------------------------------------------------------

class RetrainTrigger(BaseModel):
    job_id: str
    status: str


@app.post("/api/retrain", response_model=RetrainTrigger, status_code=202)
async def api_retrain() -> RetrainTrigger:
    pool = _require_pg()
    job_id = retrain_mod.start_job(pool, STATE)
    return RetrainTrigger(job_id=job_id, status="pending")


@app.get("/api/retrain/{job_id}/status")
async def api_retrain_status(job_id: str) -> dict:
    job = retrain_mod.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return job.to_dict()


@app.get("/api/retrain/history")
async def api_retrain_history() -> list[dict]:
    return retrain_mod.history()


# ----- Model performance / benchmark ----------------------------------------

@app.get("/api/model/benchmark")
async def api_model_benchmark() -> dict:
    path = MODEL_DIR / "benchmark_report.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="benchmark report missing")
    try:
        return json.loads(path.read_text())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to load benchmark: {e}")


@app.get("/api/model/feature-importances")
async def api_model_importances() -> dict:
    path = MODEL_DIR / "feature_importances.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


# ----- Red team integration --------------------------------------------------

class RedteamAttackIn(BaseModel):
    attack_type: str
    payload: str
    target_uri: str
    timestamp: str  # ISO-8601


class RedteamAttackOut(BaseModel):
    id: int
    was_blocked: bool
    detection_latency_ms: int | None
    detected_request_log_id: int | None


# Window around the registered attack time in which we'll consider a
# request_logs row a match. Generous because red-team agents and the WAF
# may have small clock skew.
REDTEAM_MATCH_WINDOW_S = 10


async def _find_attack_match(
    pool: asyncpg.Pool, target_uri: str, attack_ts: datetime
) -> tuple[int | None, str | None, datetime | None]:
    sql = """
        SELECT id, decision, timestamp
          FROM request_logs
         WHERE uri = $1
           AND timestamp BETWEEN $2 - ($3 || ' seconds')::interval
                             AND $2 + ($3 || ' seconds')::interval
         ORDER BY abs(extract(epoch from (timestamp - $2)))
         LIMIT 1
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(sql, target_uri, attack_ts, str(REDTEAM_MATCH_WINDOW_S))
    if not row:
        return None, None, None
    return int(row["id"]), str(row["decision"]), row["timestamp"]


@app.post("/api/redteam/register-attack", response_model=RedteamAttackOut, status_code=201)
async def api_redteam_register(body: RedteamAttackIn) -> RedteamAttackOut:
    pool = _require_pg()
    try:
        attack_ts = datetime.fromisoformat(body.timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid timestamp: {body.timestamp!r}")

    match_id, decision, match_ts = await _find_attack_match(pool, body.target_uri, attack_ts)
    was_blocked = decision == "BLOCK"
    latency_ms: int | None = None
    if match_ts is not None:
        latency_ms = int(abs((match_ts - attack_ts).total_seconds() * 1000))

    insert = """
        INSERT INTO redteam_attacks
            (attack_timestamp, attack_type, payload, target_uri,
             was_blocked, detection_latency_ms, detected_request_log_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
    """
    async with pool.acquire() as conn:
        new_id = await conn.fetchval(
            insert, attack_ts, body.attack_type, body.payload, body.target_uri,
            was_blocked, latency_ms, match_id,
        )

    # If the attack was registered but NOT blocked, that's a false negative:
    # auto-label it (if we have a matching request_log row) and kick off
    # retraining. Done in a background task so the red-team agent doesn't
    # block on training time.
    if match_id is not None and not was_blocked:
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO false_positives (request_log_id, label, labeled_by)
                       VALUES ($1, 'FALSE_NEGATIVE', 'redteam')""",
                    match_id,
                )
        except Exception as e:
            log.warning("auto-label FN failed: %s", e)
        retrain_mod.start_job(pool, STATE)

    return RedteamAttackOut(
        id=int(new_id), was_blocked=was_blocked,
        detection_latency_ms=latency_ms, detected_request_log_id=match_id,
    )


@app.get("/api/redteam/summary")
async def api_redteam_summary() -> dict:
    pool = _require_pg()
    sql = """
        SELECT count(*)                                          AS registered,
               count(*) FILTER (WHERE was_blocked)               AS blocked,
               count(*) FILTER (WHERE NOT was_blocked)           AS missed,
               COALESCE(avg(detection_latency_ms)
                          FILTER (WHERE detection_latency_ms IS NOT NULL), 0) AS avg_latency
          FROM redteam_attacks
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(sql)
    registered = int(row["registered"] or 0)
    blocked    = int(row["blocked"] or 0)
    return {
        "attacks_registered":      registered,
        "attacks_blocked":         blocked,
        "attacks_missed":          int(row["missed"] or 0),
        "detection_rate":          (blocked / registered) if registered else 0.0,
        "avg_detection_latency_ms": float(row["avg_latency"] or 0.0),
    }
