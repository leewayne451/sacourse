"""Unsupervised anomaly detectors over the `features` table.

Models:
  iforest      Isolation Forest (baseline)
  ocsvm        One-Class SVM (baseline; trained on a subsample, it is O(n^2))
  autoencoder  small sklearn MLP autoencoder -- PLACEHOLDER. Replace with the team's
               PyTorch autoencoder / Transformer; just return one score per session.

Split is by time (train on the earlier part, score the later part) so nothing from the
future leaks into training. Labels are only used for evaluation, never for training,
unless --train-benign-only is set (then it is semi-supervised; say so in the report).

Writes: scores(session_id, model, score, rank), alerts(top-k of the primary model),
        work/detector_metrics.json
"""
from __future__ import annotations

import json
import warnings
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from . import config
from .features import COUNT_FEATURES, MODEL_FEATURES


@dataclass
class DetectConfig:
    train_frac: float = 0.5
    models: tuple[str, ...] = ("iforest", "ocsvm", "autoencoder")
    primary: str = "iforest"
    top_k: int = 200
    train_benign_only: bool = False
    max_train_ocsvm: int = 20_000
    max_train_ae: int = 100_000
    seed: int = 42


def _matrix(df: pd.DataFrame) -> np.ndarray:
    X = df[MODEL_FEATURES].astype(float).copy()
    n_nan = int(X.isna().sum().sum())
    if n_nan:
        print(f"  [warn] {n_nan} missing feature values filled with 0 -- check features.py")
        X = X.fillna(0.0)
    for c in COUNT_FEATURES:
        X[c] = np.log1p(X[c].clip(lower=0))
    return X.to_numpy()


def _fit_score(name: str, Xtr: np.ndarray, Xte: np.ndarray, cfg: DetectConfig) -> np.ndarray:
    rng = np.random.default_rng(cfg.seed)
    if name == "iforest":
        m = IsolationForest(n_estimators=300, random_state=cfg.seed, n_jobs=-1).fit(Xtr)
        return -m.score_samples(Xte)
    if name == "ocsvm":
        idx = rng.choice(len(Xtr), min(len(Xtr), cfg.max_train_ocsvm), replace=False)
        m = OneClassSVM(nu=0.01, gamma="scale").fit(Xtr[idx])
        return -m.decision_function(Xte)
    if name == "autoencoder":
        idx = rng.choice(len(Xtr), min(len(Xtr), cfg.max_train_ae), replace=False)
        d = Xtr.shape[1]
        warnings.filterwarnings("ignore", message=".*Maximum iterations.*")
        m = MLPRegressor(hidden_layer_sizes=(d, max(d // 2, 4), max(d // 4, 2), max(d // 2, 4), d),
                         max_iter=200, early_stopping=True, random_state=cfg.seed).fit(Xtr[idx], Xtr[idx])
        return ((m.predict(Xte) - Xte) ** 2).mean(axis=1)
    raise ValueError(f"unknown model {name}")


def _metrics(test: pd.DataFrame, score: np.ndarray, ks: list[int]) -> dict:
    y = test["label"].to_numpy()
    out: dict = {"n_test": int(len(y)), "n_pos": int(y.sum())}
    if y.sum() == 0 or y.sum() == len(y):
        return out
    out["roc_auc"] = float(roc_auc_score(y, score))
    out["pr_auc"] = float(average_precision_score(y, score))
    order = np.argsort(-score)
    insider_users = set(test.loc[test.label == 1, "user"])
    for k in ks:
        top = order[:k]
        hits = int(y[top].sum())
        out[f"precision@{k}"] = hits / k
        out[f"recall@{k}"] = hits / int(y.sum())
        out[f"insiders_caught@{k}"] = (
            f"{len(insider_users & set(test.iloc[top]['user']))}/{len(insider_users)}")
    return out


def run(con, cfg: DetectConfig = DetectConfig()) -> dict:
    df = con.execute("SELECT * FROM features ORDER BY start_ts").df()
    cut = df["start_ts"].quantile(cfg.train_frac)
    train, test = df[df.start_ts < cut].copy(), df[df.start_ts >= cut].copy()
    has_labels = df["label"].notna().all()
    if cfg.train_benign_only and has_labels:
        train = train[train.label == 0]
    scaler = StandardScaler().fit(_matrix(train))
    Xtr, Xte = scaler.transform(_matrix(train)), scaler.transform(_matrix(test))
    print(f"  train {len(train):,} sessions (< {cut}), test {len(test):,} sessions")

    ks = sorted({k for k in (10, 50, 100, cfg.top_k) if k <= len(test)})
    all_scores, metrics = [], {"split_time": str(cut), "features": MODEL_FEATURES, "models": {}}
    for name in cfg.models:
        s = _fit_score(name, Xtr, Xte, cfg)
        frame = pd.DataFrame({"session_id": test.session_id.values, "model": name, "score": s})
        frame["rank"] = frame.score.rank(ascending=False, method="first").astype(int)
        all_scores.append(frame)
        if has_labels:
            metrics["models"][name] = _metrics(test.reset_index(drop=True), s, ks)
            m = metrics["models"][name]
            print(f"  {name:<12} ROC-AUC {m.get('roc_auc', float('nan')):.3f}  "
                  f"PR-AUC {m.get('pr_auc', float('nan')):.3f}  "
                  f"P@{ks[-1]} {m.get(f'precision@{ks[-1]}', float('nan')):.3f}  "
                  f"insiders@{ks[-1]} {m.get(f'insiders_caught@{ks[-1]}', '-')}")
        else:
            print(f"  {name:<12} scored (no labels loaded, skipping metrics)")

    scores = pd.concat(all_scores, ignore_index=True)
    con.register("scores_df", scores)
    con.execute("CREATE OR REPLACE TABLE scores AS SELECT * FROM scores_df")
    con.unregister("scores_df")
    con.execute(f"""
        CREATE OR REPLACE TABLE alerts AS
        SELECT s.session_id, s.model, s.score, s.rank, f."user", f.pc, f.start_ts, f.end_ts, f.label, f.scenario
        FROM scores s JOIN features f USING (session_id)
        WHERE s.model = '{cfg.primary}' AND s.rank <= {int(cfg.top_k)}
        ORDER BY s.rank
    """)
    config.ensure_dirs()
    (config.WORK_DIR / "detector_metrics.json").write_text(json.dumps(metrics, indent=2, default=str))
    return metrics
