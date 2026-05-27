-- =============================================================================
-- ML-WAF admin schema
-- Loaded automatically by the postgres image on first boot from
-- /docker-entrypoint-initdb.d/init.sql
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- IP allow/block rules (CIDR-based). `action` is intentionally a CHECK'd text
-- column instead of an enum so we can extend it without a migration dance.
CREATE TABLE IF NOT EXISTS ip_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_cidr     CIDR        NOT NULL,
    action      TEXT        NOT NULL CHECK (action IN ('ALLOW', 'BLOCK', 'CHALLENGE')),
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_ip_rules_cidr        ON ip_rules USING gist (ip_cidr inet_ops);
CREATE INDEX IF NOT EXISTS idx_ip_rules_expires_at  ON ip_rules (expires_at);

-- Materialized request log (the Redis stream is ephemeral; this is the
-- durable record we attach decisions and labels to).
-- raw_request holds the full {method,uri,headers,body,client_ip} envelope so
-- the SHAP explainer can re-extract features for any past request.
CREATE TABLE IF NOT EXISTS request_logs (
    id            BIGSERIAL PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT now(),
    client_ip     INET        NOT NULL,
    method        TEXT        NOT NULL,
    uri           TEXT        NOT NULL,
    status_code   INTEGER,
    modsec_score  REAL,
    ml_score      REAL,
    decision      TEXT        NOT NULL CHECK (decision IN ('ALLOW', 'LOG', 'BLOCK')),
    request_hash  TEXT        NOT NULL,
    raw_request   JSONB,
    inference_ms  REAL
);
CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_client_ip ON request_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_request_logs_hash      ON request_logs (request_hash);
CREATE INDEX IF NOT EXISTS idx_request_logs_decision  ON request_logs (decision);

-- Analyst labels for retraining feedback loop.
-- FALSE_NEGATIVE = attack that slipped past the WAF (auto-labelled by the
-- red-team feedback endpoint).
CREATE TABLE IF NOT EXISTS false_positives (
    id              BIGSERIAL PRIMARY KEY,
    request_log_id  BIGINT      NOT NULL REFERENCES request_logs(id) ON DELETE CASCADE,
    label           TEXT        NOT NULL CHECK (label IN ('FALSE_POSITIVE', 'TRUE_POSITIVE', 'FALSE_NEGATIVE', 'UNSURE')),
    labeled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    labeled_by      TEXT        NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_false_positives_request_log ON false_positives (request_log_id);
CREATE INDEX IF NOT EXISTS idx_false_positives_label       ON false_positives (label);

-- Attacks registered by the Red-Teaming Agent project. attack_type is
-- free-form ("sqli","xss","traversal","scanner","custom",...). The
-- detected_request_log_id link is filled in when we can match the registered
-- attack to a row in request_logs (by uri+timestamp).
CREATE TABLE IF NOT EXISTS redteam_attacks (
    id                       BIGSERIAL PRIMARY KEY,
    registered_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    attack_timestamp         TIMESTAMPTZ NOT NULL,
    attack_type              TEXT        NOT NULL,
    payload                  TEXT        NOT NULL,
    target_uri               TEXT        NOT NULL,
    was_blocked              BOOLEAN     NOT NULL DEFAULT FALSE,
    detection_latency_ms     INTEGER,
    detected_request_log_id  BIGINT      REFERENCES request_logs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_redteam_attacks_registered_at ON redteam_attacks (registered_at DESC);
CREATE INDEX IF NOT EXISTS idx_redteam_attacks_was_blocked   ON redteam_attacks (was_blocked);
CREATE INDEX IF NOT EXISTS idx_redteam_attacks_attack_type   ON redteam_attacks (attack_type);
