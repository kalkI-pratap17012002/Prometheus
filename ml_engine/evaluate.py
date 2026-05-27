"""Benchmark ModSec-style rules vs. ML alone vs. Combined on the holdout set.

Loads the 20% test split saved by train.py and reports a comparison table.
Also measures /score-equivalent inference latency on the in-process pipeline
and asserts p99 < 30 ms.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix,
)

from feature_extractor import FEATURE_NAMES

MODEL_DIR = Path(__file__).parent / "model"
P99_BUDGET_MS = 30.0

# Indexes into the feature vector — keep in sync with FEATURE_NAMES.
IDX = {name: i for i, name in enumerate(FEATURE_NAMES)}


def modsec_like(X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Approximate a ModSec-CRS-style rules engine using the raw feature vector.

    Returns (predictions 0/1, pseudo-scores in [0,1]) — pseudo-scores are
    monotone in the rule-hit count so we can compute an AUC-comparable number.
    """
    scores = np.zeros(len(X), dtype=np.float64)
    scores += 0.35 * (X[:, IDX["sql_keyword_score"]] > 0.01)
    scores += 0.35 * (X[:, IDX["xss_pattern_score"]] > 0.01)
    scores += 0.25 * (X[:, IDX["encoding_anomaly"]] > 0)
    scores += 0.20 * (X[:, IDX["uri_special_char_ratio"]] > 0.30)
    scores += 0.15 * (X[:, IDX["has_unusual_method"]] > 0)
    scores += 0.15 * (X[:, IDX["uri_length"]] > 256)
    scores = np.clip(scores, 0.0, 1.0)
    preds = (scores >= 0.30).astype(int)
    return preds, scores


def _row(name: str, y: np.ndarray, preds: np.ndarray, scores: np.ndarray | None) -> dict:
    auc = float(roc_auc_score(y, scores)) if scores is not None and len(np.unique(y)) > 1 else None
    return {
        "model": name,
        "precision": float(precision_score(y, preds, zero_division=0)),
        "recall": float(recall_score(y, preds, zero_division=0)),
        "f1": float(f1_score(y, preds, zero_division=0)),
        "auc": auc,
        "confusion": confusion_matrix(y, preds).tolist(),
    }


def _print_table(rows: list[dict]) -> None:
    print(f"\n{'Model':<22}{'Precision':>11}{'Recall':>10}{'F1':>8}{'AUC':>8}")
    print("-" * 59)
    for r in rows:
        auc = f"{r['auc']:.3f}" if r["auc"] is not None else "  n/a"
        print(f"{r['model']:<22}{r['precision']:>11.3f}{r['recall']:>10.3f}"
              f"{r['f1']:>8.3f}{auc:>8}")


def main() -> None:
    print("Loading artifacts…")
    data = np.load(MODEL_DIR / "test_set.npz", allow_pickle=False)
    X_test = data["X_test"]
    X_test_scaled = data["X_test_scaled"]
    y_test = data["y_test"]

    scaler = joblib.load(MODEL_DIR / "scaler.pkl")
    iso = joblib.load(MODEL_DIR / "isolation_forest.pkl")
    xgb = joblib.load(MODEL_DIR / "xgb_classifier.pkl")
    with open(MODEL_DIR / "iso_threshold.json") as f:
        iso_meta = json.load(f)
    iso_lo, iso_hi = iso_meta["score_min"], iso_meta["score_max"]
    iso_thr = iso_meta["normalized_threshold"]

    # ---- ModSec-style baseline ---------------------------------------
    rules_preds, rules_scores = modsec_like(X_test)

    # ---- IsolationForest alone ---------------------------------------
    iso_raw = -iso.score_samples(X_test_scaled)
    iso_norm = np.clip((iso_raw - iso_lo) / max(iso_hi - iso_lo, 1e-9), 0.0, 1.0)
    iso_preds = (iso_norm >= iso_thr).astype(int)

    # ---- XGBoost alone -----------------------------------------------
    xgb_proba = xgb.predict_proba(X_test_scaled)[:, 1]
    xgb_preds = (xgb_proba >= 0.5).astype(int)

    # ---- Combined ensemble -------------------------------------------
    combined = 0.4 * iso_norm + 0.6 * xgb_proba
    combined_preds = (combined >= 0.5).astype(int)

    # ---- ML + ModSec union -------------------------------------------
    union_preds = ((combined >= 0.5) | (rules_preds == 1)).astype(int)
    union_score = np.maximum(combined, rules_scores)

    rows = [
        _row("ModSec-like (rules)", y_test, rules_preds, rules_scores),
        _row("IsolationForest",     y_test, iso_preds, iso_norm),
        _row("XGBoost",              y_test, xgb_preds, xgb_proba),
        _row("ML Ensemble",          y_test, combined_preds, combined),
        _row("Combined (ML∪Rules)",  y_test, union_preds, union_score),
    ]
    _print_table(rows)

    # ---- Latency benchmark -------------------------------------------
    print("\nLatency benchmark (in-process inference path)…")
    latencies = []
    # Use a moderate number of trials to keep the script under a couple seconds.
    sample_indices = np.random.default_rng(0).integers(0, len(X_test), size=500)
    for i in sample_indices:
        x = X_test[i:i + 1]
        t0 = time.perf_counter()
        xs = scaler.transform(x)
        iso_raw_i = float(-iso.score_samples(xs)[0])
        iso_n = float(np.clip((iso_raw_i - iso_lo) / max(iso_hi - iso_lo, 1e-9), 0.0, 1.0))
        xgb_p = float(xgb.predict_proba(xs)[0, 1])
        _ = 0.4 * iso_n + 0.6 * xgb_p
        latencies.append((time.perf_counter() - t0) * 1000.0)
    lat = np.array(latencies)
    p50, p95, p99 = np.percentile(lat, [50, 95, 99])
    print(f"  n={len(lat)}  p50={p50:.2f}ms  p95={p95:.2f}ms  p99={p99:.2f}ms  "
          f"max={lat.max():.2f}ms  mean={lat.mean():.2f}ms")
    latency_ok = bool(p99 < P99_BUDGET_MS)
    if not latency_ok:
        print(f"  WARNING: p99 {p99:.2f}ms exceeds {P99_BUDGET_MS}ms budget")

    report = {
        "rows": rows,
        "latency_ms": {
            "p50": float(p50), "p95": float(p95), "p99": float(p99),
            "max": float(lat.max()), "mean": float(lat.mean()),
            "n": int(len(lat)), "budget_ms": P99_BUDGET_MS,
            "p99_under_budget": latency_ok,
        },
    }
    with open(MODEL_DIR / "benchmark_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport written → {MODEL_DIR / 'benchmark_report.json'}")

    assert latency_ok, f"p99 latency {p99:.2f}ms exceeds {P99_BUDGET_MS}ms budget"


if __name__ == "__main__":
    main()
