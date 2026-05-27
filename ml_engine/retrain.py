"""Async XGBoost retraining pipeline driven by analyst feedback.

Pulls labelled rows from `false_positives` joined with `request_logs`,
re-extracts features from the persisted raw request envelope, augments the
original training set, retrains the XGB classifier, and atomically swaps the
model file if the new F1 is better than the previous best.

The IsolationForest is intentionally NOT retrained — the anomaly detector is
trained normal-only and feedback rows are heavily attack-skewed.

Failures are non-fatal: a rejected model leaves the on-disk artifact alone,
and the result (success or reject) is appended to retrain_history.json.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import asyncpg
import joblib
import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score
from xgboost import XGBClassifier

from feature_extractor import FEATURE_NAMES, FeatureExtractor

log = logging.getLogger("ml_engine.retrain")

MODEL_DIR = Path(os.getenv("WAF_MODEL_DIR", str(Path(__file__).parent / "model")))
HISTORY_PATH = MODEL_DIR / "retrain_history.json"


# ---------------------------------------------------------------------------
# Job tracking — kept entirely in-process. Jobs survive a single uvicorn run
# only; that's fine for a feedback-loop trigger that completes in seconds.
# ---------------------------------------------------------------------------

@dataclass
class RetrainJob:
    job_id: str
    status: str = "pending"        # pending | running | completed | rejected | failed
    started_at: float = 0.0
    finished_at: float = 0.0
    n_feedback: int = 0
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "n_feedback": self.n_feedback,
            "result": self.result,
            "error": self.error,
        }


_JOBS: dict[str, RetrainJob] = {}


def get_job(job_id: str) -> RetrainJob | None:
    return _JOBS.get(job_id)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

LABEL_MAP = {
    # FP = WAF blocked but actually benign → label 0
    "FALSE_POSITIVE": 0,
    # TP = analyst confirms the WAF was right → label 1 (positive reinforcement)
    "TRUE_POSITIVE": 1,
    # FN = attack slipped through → label 1
    "FALSE_NEGATIVE": 1,
}


async def _load_feedback(pool: asyncpg.Pool) -> list[tuple[dict, int]]:
    """Return [(raw_request_envelope, label), ...] for all labelled rows.

    Skips UNSURE rows and rows where raw_request is null (older logs from
    before the phase-5 schema bump).
    """
    sql = """
        SELECT r.raw_request, r.method, r.uri, r.client_ip::text AS client_ip,
               fp.label
          FROM false_positives fp
          JOIN request_logs r ON r.id = fp.request_log_id
         WHERE fp.label IN ('FALSE_POSITIVE', 'TRUE_POSITIVE', 'FALSE_NEGATIVE')
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(sql)
    out: list[tuple[dict, int]] = []
    for r in rows:
        label = LABEL_MAP.get(r["label"])
        if label is None:
            continue
        # raw_request is the source of truth (has headers+body); fall back to
        # the flat columns so older labelled rows still contribute features
        # like uri_length / sql_keyword_score (behavioural feats will be 0).
        raw = r["raw_request"]
        if raw is None:
            raw = {
                "method": r["method"],
                "uri": r["uri"],
                "client_ip": r["client_ip"],
                "headers": {},
                "body": "",
            }
        elif isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                continue
        out.append((raw, label))
    return out


def _vectorize_feedback(records: list[tuple[dict, int]]) -> tuple[np.ndarray, np.ndarray]:
    fe = FeatureExtractor()  # no redis → behavioural feats default to 0
    if not records:
        return np.zeros((0, len(FEATURE_NAMES)), dtype=np.float64), np.zeros((0,), dtype=np.int64)
    X = np.vstack([fe.extract(env) for env, _ in records])
    y = np.array([lbl for _, lbl in records], dtype=np.int64)
    return X, y


def _evaluate(model: XGBClassifier, X_scaled: np.ndarray, y: np.ndarray) -> dict[str, float]:
    proba = model.predict_proba(X_scaled)[:, 1]
    pred = (proba >= 0.5).astype(int)
    return {
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall":    float(recall_score(y, pred, zero_division=0)),
        "f1":        float(f1_score(y, pred, zero_division=0)),
    }


def _append_history(entry: dict[str, Any]) -> None:
    hist: list[dict[str, Any]] = []
    if HISTORY_PATH.exists():
        try:
            hist = json.loads(HISTORY_PATH.read_text())
        except Exception:
            hist = []
    hist.append(entry)
    HISTORY_PATH.write_text(json.dumps(hist, indent=2))


async def _run_retrain(job: RetrainJob, pg_pool: asyncpg.Pool, state: Any) -> None:
    job.status = "running"
    job.started_at = time.time()
    try:
        feedback = await _load_feedback(pg_pool)
        job.n_feedback = len(feedback)
        if not feedback:
            job.status = "rejected"
            job.error = "no labelled feedback available"
            job.finished_at = time.time()
            _append_history({
                "job_id": job.job_id, "ts": job.finished_at, "status": "rejected",
                "reason": "no_feedback",
            })
            return

        # Run blocking sklearn/xgboost work in a thread so the FastAPI loop
        # stays responsive.
        result = await asyncio.to_thread(_do_retrain, feedback, state)
        job.result = result
        if result.get("accepted"):
            job.status = "completed"
            # Hot-swap on STATE so /score uses the new model immediately.
            state.xgb = result["_new_model"]
            state.xgb_importances = np.asarray(state.xgb.feature_importances_, dtype=np.float64)
            log.info("retrain %s accepted: new F1 %.4f > old F1 %.4f",
                     job.job_id, result["new_metrics"]["f1"], result["old_metrics"]["f1"])
        else:
            job.status = "rejected"
            log.warning("retrain %s rejected: new F1 %.4f <= old F1 %.4f",
                        job.job_id, result["new_metrics"]["f1"], result["old_metrics"]["f1"])

        # Strip the in-memory model object before serialising history.
        history_result = {k: v for k, v in result.items() if not k.startswith("_")}
        _append_history({
            "job_id": job.job_id, "ts": time.time(), "status": job.status,
            "n_feedback": job.n_feedback, **history_result,
        })
    except Exception as e:
        job.status = "failed"
        job.error = f"{type(e).__name__}: {e}"
        log.exception("retrain job %s failed", job.job_id)
        _append_history({
            "job_id": job.job_id, "ts": time.time(), "status": "failed",
            "error": job.error,
        })
    finally:
        job.finished_at = time.time()


def _do_retrain(feedback: list[tuple[dict, int]], state: Any) -> dict[str, Any]:
    """Blocking portion of the retrain. Returns a result dict; if accepted the
    fitted model is included under `_new_model` (caller strips before history)."""
    # Load original training set (test_set.npz also stashes the test split's
    # unscaled X). The train.py script doesn't persist the *training* X, so we
    # synthesise a stand-in: regenerate from the random seed.
    from train import DataGenerator, _vectorize  # local import — heavy module

    gen = DataGenerator()
    base_samples = gen.generate()
    X_base, y_base, _ = _vectorize(base_samples)

    X_fb, y_fb = _vectorize_feedback(feedback)

    # Keep a held-out slice of the originals for fair before/after comparison.
    # We don't shuffle — the seeded generator already shuffles.
    n_test = max(int(len(X_base) * 0.2), 200)
    X_test = X_base[-n_test:]
    y_test = y_base[-n_test:]
    X_train = np.vstack([X_base[:-n_test], X_fb]) if X_fb.size else X_base[:-n_test]
    y_train = np.concatenate([y_base[:-n_test], y_fb]) if y_fb.size else y_base[:-n_test]

    scaler = state.scaler
    X_train_s = scaler.transform(X_train)
    X_test_s  = scaler.transform(X_test)

    new_model = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1,
        objective="binary:logistic", eval_metric="logloss",
        random_state=42, n_jobs=-1, tree_method="hist",
    )
    new_model.fit(X_train_s, y_train)

    new_metrics = _evaluate(new_model, X_test_s, y_test)
    old_metrics = _evaluate(state.xgb, X_test_s, y_test)

    accepted = new_metrics["f1"] > old_metrics["f1"]
    result: dict[str, Any] = {
        "accepted": accepted,
        "n_feedback": len(feedback),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "old_metrics": old_metrics,
        "new_metrics": new_metrics,
    }

    if accepted:
        # Atomic-ish replace: write to a temp file, fsync the bytes to disk,
        # then rename. We also keep a backup of the previous model so a bad
        # swap can be rolled back manually.
        target = MODEL_DIR / "xgb_classifier.pkl"
        backup = MODEL_DIR / "xgb_classifier.prev.pkl"
        tmp    = MODEL_DIR / f"xgb_classifier.{uuid.uuid4().hex}.tmp"
        joblib.dump(new_model, tmp)
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
        if target.exists():
            shutil.copy2(target, backup)
        os.replace(tmp, target)
        result["_new_model"] = new_model
        result["model_path"] = str(target)

    return result


# ---------------------------------------------------------------------------
# Public entry points used by main.py
# ---------------------------------------------------------------------------

def start_job(pg_pool: asyncpg.Pool, state: Any) -> str:
    job_id = uuid.uuid4().hex
    job = RetrainJob(job_id=job_id)
    _JOBS[job_id] = job
    asyncio.create_task(_run_retrain(job, pg_pool, state))
    return job_id


def history() -> list[dict[str, Any]]:
    if not HISTORY_PATH.exists():
        return []
    try:
        return json.loads(HISTORY_PATH.read_text())
    except Exception:
        return []


@asynccontextmanager
async def _noop_lifespan():
    yield
