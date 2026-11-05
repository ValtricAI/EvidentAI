"""Detector metrics."""

from __future__ import annotations

import math
from typing import Sequence

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def classification_at_threshold(labels: Sequence[int], scores: Sequence[float], threshold: float) -> dict:
    y = np.asarray(labels, dtype=int)
    s = np.asarray(scores, dtype=float)
    pred = (s >= threshold).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return {
        "threshold": threshold,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": _safe_div(fp, fp + tn),
        "accuracy": _safe_div(tp + tn, len(y)),
    }


def ranking_metrics(labels: Sequence[int], scores: Sequence[float]) -> dict:
    y = np.asarray(labels, dtype=int)
    s = np.asarray(scores, dtype=float)
    out: dict = {"auroc": None, "average_precision": None, "fpr_at_95_recall": None}
    if len(set(y.tolist())) < 2:
        return out
    out["auroc"] = float(roc_auc_score(y, s))
    out["average_precision"] = float(average_precision_score(y, s))
    fpr, tpr, _ = roc_curve(y, s)
    idx = np.where(tpr >= 0.95)[0]
    if len(idx):
        out["fpr_at_95_recall"] = float(fpr[idx[0]])
    return out


def latency_summary(latencies_ms: Sequence[float]) -> dict:
    if not latencies_ms:
        return {"mean_ms": None, "p95_ms": None}
    arr = np.asarray(latencies_ms, dtype=float)
    return {"mean_ms": float(arr.mean()), "p95_ms": float(np.percentile(arr, 95))}


def evaluate(labels: Sequence[int], scores: Sequence[float], threshold: float, latencies_ms: Sequence[float] | None = None) -> dict:
    result = {"n": len(labels), "attacks": int(sum(labels)), "benign": int(len(labels) - sum(labels))}
    result.update(classification_at_threshold(labels, scores, threshold))
    result.update(ranking_metrics(labels, scores))
    result["latency"] = latency_summary(latencies_ms or [])
    return result


def fmt(value, digits: int = 3) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "-"
    return f"{value:.{digits}f}"
