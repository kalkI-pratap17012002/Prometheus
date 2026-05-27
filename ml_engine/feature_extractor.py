"""Feature extraction for HTTP request envelopes.

Phase 3: produces a fixed-shape numpy vector of 20 features used by both the
IsolationForest (anomaly) and XGBoost (classification) models.

Feature order (index → name):
     0  uri_length
     1  uri_entropy
     2  uri_special_char_ratio
     3  uri_depth
     4  uri_extension_encoded
     5  sql_keyword_score
     6  xss_pattern_score
     7  body_entropy
     8  body_length
     9  encoding_anomaly
    10  method_encoded
    11  header_count
    12  has_unusual_method
    13  user_agent_entropy
    14  content_type_encoded
    15  ip_req_rate_1m
    16  ip_req_rate_5m
    17  ip_error_rate_1m
    18  uri_extension_len
    19  body_uri_ratio
"""
from __future__ import annotations

import math
import re
import time
from collections import Counter
from typing import Any, Optional
from urllib.parse import urlparse

import numpy as np

FEATURE_NAMES: list[str] = [
    "uri_length",
    "uri_entropy",
    "uri_special_char_ratio",
    "uri_depth",
    "uri_extension_encoded",
    "sql_keyword_score",
    "xss_pattern_score",
    "body_entropy",
    "body_length",
    "encoding_anomaly",
    "method_encoded",
    "header_count",
    "has_unusual_method",
    "user_agent_entropy",
    "content_type_encoded",
    "ip_req_rate_1m",
    "ip_req_rate_5m",
    "ip_error_rate_1m",
    "uri_extension_len",
    "body_uri_ratio",
]
FEATURE_DIM = len(FEATURE_NAMES)

SQL_KEYWORD_WEIGHTS: dict[str, int] = {
    "union": 3,
    "select": 2,
    "insert": 2,
    "drop": 3,
    "exec": 3,
    "xp_": 3,
    "--": 2,
    "/*": 1,
}

XSS_PATTERN_WEIGHTS: dict[str, int] = {
    "<script": 3,
    "javascript:": 3,
    "onerror=": 2,
    "onload=": 2,
    "alert(": 1,
    "eval(": 2,
}

METHOD_MAP: dict[str, int] = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}
UNUSUAL_METHODS: set[str] = {"TRACE", "CONNECT", "PATCH"}
SENSITIVE_PATH_HINTS: tuple[str, ...] = (
    "/admin", "/api", "/login", "/auth", "/wp-admin", "/config",
    "/manage", "/private", "/internal",
)

# Common extensions — kept short so a single-int encoding stays well behaved.
EXTENSION_MAP: dict[str, int] = {
    "none": 0, "html": 1, "htm": 1, "php": 2, "asp": 3, "aspx": 3,
    "jsp": 4, "js": 5, "css": 6, "json": 7, "xml": 8, "txt": 9,
    "png": 10, "jpg": 10, "jpeg": 10, "gif": 10, "svg": 11,
    "sql": 12, "py": 13, "sh": 13, "exe": 14, "bak": 15, "old": 15,
}

CONTENT_TYPE_MAP: dict[str, int] = {"json": 0, "form": 1, "multipart": 2, "none": 3}

_ENCODING_ANOMALY_RE = re.compile(r"%25[0-9a-fA-F]{2}|%00", re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _classify_content_type(ct: str) -> int:
    if not ct:
        return CONTENT_TYPE_MAP["none"]
    ct = ct.lower()
    if "json" in ct:
        return CONTENT_TYPE_MAP["json"]
    if "x-www-form-urlencoded" in ct:
        return CONTENT_TYPE_MAP["form"]
    if "multipart" in ct:
        return CONTENT_TYPE_MAP["multipart"]
    return 4


def _encode_extension(path: str) -> tuple[int, int]:
    if "." not in path.rsplit("/", 1)[-1]:
        return EXTENSION_MAP["none"], 0
    ext = path.rsplit(".", 1)[-1].lower()
    ext = ext.split("?", 1)[0].split("#", 1)[0]
    if not ext or len(ext) > 8:
        return EXTENSION_MAP["none"], 0
    return EXTENSION_MAP.get(ext, 16), len(ext)


class FeatureExtractor:
    """Extracts a fixed (1, 20) feature vector from a raw request dict.

    If a redis client is provided, behavioral features (ip_req_rate_*,
    ip_error_rate_1m) are computed from per-IP sorted sets. Without a client,
    those features default to 0.0 so the extractor stays usable for training
    on synthetic data.
    """

    IP_REQ_KEY_PREFIX = "waf:ip:req:"
    IP_ERR_KEY_PREFIX = "waf:ip:err:"

    # Circuit-breaker: a single redis blip costs the socket timeout per call.
    # After repeated failures we stop calling redis for COOLDOWN_S so /score
    # latency stays predictable.
    FAILURE_LIMIT = 3
    COOLDOWN_S = 30.0

    def __init__(self, redis_client: Optional[Any] = None) -> None:
        self.redis = redis_client
        self._consecutive_failures = 0
        self._open_until = 0.0

    # ---- URI ----------------------------------------------------------

    def _uri_features(self, uri: str) -> tuple[float, float, float, float, int, int]:
        parsed = urlparse(uri)
        path = parsed.path or uri
        length = len(uri)
        entropy = _shannon_entropy(uri)
        if length:
            special = sum(1 for c in uri if not (c.isalnum() or c == "/"))
            ratio = special / length
        else:
            ratio = 0.0
        depth = path.count("/")
        ext_enc, ext_len = _encode_extension(path)
        return float(length), entropy, ratio, float(depth), ext_enc, ext_len

    # ---- Payload ------------------------------------------------------

    def _payload_features(self, body: str, uri: str) -> tuple[float, float, float, float, int]:
        haystack = (uri + " " + body).lower()
        norm_len = max(len(body), 1)

        sql_score = sum(w * haystack.count(k) for k, w in SQL_KEYWORD_WEIGHTS.items()) / norm_len
        xss_score = sum(w * haystack.count(k) for k, w in XSS_PATTERN_WEIGHTS.items()) / norm_len

        body_entropy = _shannon_entropy(body)
        body_length = float(len(body))

        anomaly = 1 if _ENCODING_ANOMALY_RE.search(uri + body) else 0
        return sql_score, xss_score, body_entropy, body_length, anomaly

    # ---- HTTP ---------------------------------------------------------

    def _http_features(
        self, method: str, uri: str, headers: dict[str, str]
    ) -> tuple[int, int, int, float, int]:
        method_u = (method or "").upper()
        method_enc = METHOD_MAP.get(method_u, 4)
        header_count = len(headers) if headers else 0

        unusual = 0
        if method_u in UNUSUAL_METHODS:
            path = urlparse(uri).path.lower()
            if any(h in path for h in SENSITIVE_PATH_HINTS):
                unusual = 1
            elif method_u == "TRACE":
                # TRACE is unusual regardless of path
                unusual = 1

        ua = ""
        ct = ""
        for k, v in (headers or {}).items():
            lk = k.lower()
            if lk == "user-agent":
                ua = v or ""
            elif lk == "content-type":
                ct = v or ""

        ua_entropy = _shannon_entropy(ua)
        ct_enc = _classify_content_type(ct)
        return method_enc, header_count, unusual, ua_entropy, ct_enc

    # ---- Behavioral ---------------------------------------------------

    def _behavioral_features(self, client_ip: str) -> tuple[float, float, float]:
        if not self.redis or not client_ip:
            return 0.0, 0.0, 0.0
        now = time.time()
        if now < self._open_until:
            return 0.0, 0.0, 0.0
        try:
            now_ms = int(now * 1000)
            min_1m = now_ms - 60_000
            min_5m = now_ms - 300_000
            req_key = self.IP_REQ_KEY_PREFIX + client_ip
            err_key = self.IP_ERR_KEY_PREFIX + client_ip
            pipe = self.redis.pipeline(transaction=False)
            pipe.zcount(req_key, min_1m, now_ms)
            pipe.zcount(req_key, min_5m, now_ms)
            pipe.zcount(err_key, min_1m, now_ms)
            r1, r5, e1 = pipe.execute()
            self._consecutive_failures = 0
            return float(r1 or 0), float(r5 or 0), float(e1 or 0)
        except Exception:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.FAILURE_LIMIT:
                self._open_until = now + self.COOLDOWN_S
            return 0.0, 0.0, 0.0

    # ---- Public API ---------------------------------------------------

    def extract(self, request_dict: dict) -> np.ndarray:
        uri = request_dict.get("uri", "") or ""
        body = request_dict.get("body", "") or ""
        headers = request_dict.get("headers", {}) or {}
        method = request_dict.get("method", "") or ""
        client_ip = request_dict.get("client_ip", "") or ""

        uri_len, uri_ent, uri_ratio, uri_depth, ext_enc, ext_len = self._uri_features(uri)
        sql, xss, body_ent, body_len, enc_anom = self._payload_features(body, uri)
        method_enc, hdr_count, unusual, ua_ent, ct_enc = self._http_features(method, uri, headers)
        r1, r5, e1 = self._behavioral_features(client_ip)

        body_uri_ratio = body_len / max(uri_len, 1.0)

        vec = np.array([[
            uri_len, uri_ent, uri_ratio, uri_depth, ext_enc,
            sql, xss, body_ent, body_len, enc_anom,
            method_enc, hdr_count, unusual, ua_ent, ct_enc,
            r1, r5, e1, ext_len, body_uri_ratio,
        ]], dtype=np.float64)
        return vec


# Back-compat shim — main.py used to import `extract_features` (a function
# returning a dict). The new pipeline uses FeatureExtractor.extract().
def extract_features(request: dict[str, Any]) -> dict[str, float]:
    fe = FeatureExtractor()
    vec = fe.extract(request)[0]
    return {name: float(v) for name, v in zip(FEATURE_NAMES, vec)}
