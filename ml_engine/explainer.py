"""SHAP-based explainer for the XGBoost classifier.

TreeExplainer is exact (no sampling) and fast for tree models — well within
the 100ms budget for a single 20-feature vector.

The explainer is constructed once at FastAPI startup and held on STATE; each
explain() call is just a single SHAP evaluation on a (1, FEATURE_DIM) array.
"""
from __future__ import annotations

import logging
from typing import Any

import numpy as np
import shap

from feature_extractor import FEATURE_NAMES

log = logging.getLogger("ml_engine.explainer")


class Explainer:
    """Wraps shap.TreeExplainer for the binary-classifier XGB model."""

    def __init__(self, xgb_model: Any, scaler: Any, feature_names: list[str] | None = None) -> None:
        self.xgb = xgb_model
        self.scaler = scaler
        self.feature_names = feature_names or FEATURE_NAMES
        # model_output="raw" returns log-odds, which is what TreeExplainer
        # natively computes for XGB; we sigmoid the prediction for the API.
        self._tree = shap.TreeExplainer(xgb_model)
        # Sanity-probe the explainer once so the first /api/explain call
        # doesn't pay an initialization tax.
        probe = np.zeros((1, len(self.feature_names)), dtype=np.float64)
        try:
            self._tree.shap_values(self.scaler.transform(probe))
        except Exception as e:
            log.warning("SHAP warmup probe failed (non-fatal): %s", e)

    @staticmethod
    def _sigmoid(x: float) -> float:
        if x >= 0:
            z = np.exp(-x)
            return float(1.0 / (1.0 + z))
        z = np.exp(x)
        return float(z / (1.0 + z))

    def explain(self, feature_vector: np.ndarray) -> dict:
        """Run SHAP on a single feature vector (raw, pre-scaling).

        Returns a dict with the base value, the predicted probability, and a
        list of {name, value, shap_value, impact} sorted by |shap_value|.
        """
        if feature_vector.ndim == 1:
            feature_vector = feature_vector.reshape(1, -1)
        if feature_vector.shape[1] != len(self.feature_names):
            raise ValueError(
                f"feature_vector has {feature_vector.shape[1]} features, "
                f"expected {len(self.feature_names)}"
            )

        scaled = self.scaler.transform(feature_vector)
        shap_values = self._tree.shap_values(scaled)
        # For binary XGB, shap_values can be (1, N) or [arr_0, arr_1]; handle both.
        if isinstance(shap_values, list):
            sv = np.asarray(shap_values[-1])
        else:
            sv = np.asarray(shap_values)
        sv = sv.reshape(-1)

        expected = self._tree.expected_value
        if isinstance(expected, (list, np.ndarray)):
            expected = np.asarray(expected).reshape(-1)[-1]
        base_value = float(expected)
        log_odds = base_value + float(sv.sum())
        prediction = self._sigmoid(log_odds)

        raw = feature_vector.reshape(-1)
        order = np.argsort(-np.abs(sv))
        features = [
            {
                "name": self.feature_names[i],
                "value": float(raw[i]),
                "shap_value": float(sv[i]),
                "impact": "positive" if sv[i] >= 0 else "negative",
            }
            for i in order
        ]

        return {
            "base_value": base_value,
            "prediction": prediction,
            "features": features,
        }
