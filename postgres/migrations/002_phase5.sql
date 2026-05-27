-- Phase 5 migration. Apply against existing databases that were initialized
-- from the pre-phase-5 init.sql. Idempotent.

ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS raw_request  JSONB;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS inference_ms REAL;

-- Widen false_positives.label to include FALSE_NEGATIVE. Drop+recreate the
-- check constraint (Postgres has no IF EXISTS for ADD CONSTRAINT).
ALTER TABLE false_positives DROP CONSTRAINT IF EXISTS false_positives_label_check;
ALTER TABLE false_positives
    ADD CONSTRAINT false_positives_label_check
    CHECK (label IN ('FALSE_POSITIVE', 'TRUE_POSITIVE', 'FALSE_NEGATIVE', 'UNSURE'));

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
