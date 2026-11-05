"""The boring baseline: character n-gram TF-IDF + logistic regression."""

from __future__ import annotations

import time

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .base import Detector, ScoreResult


class NgramLRDetector(Detector):
    name = "ngram_lr"
    kind = "classifier"
    threshold = 0.5
    notes = "char_wb 2-5 grams, C=4, class_weight balanced; trained on the train split"

    def __init__(self, train_rows: list[dict]):
        if not train_rows:
            self.available = False
            self.unavailable_reason = "no training rows"
            return
        self.model = Pipeline([
            ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True, max_features=300_000)),
            ("lr", LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced")),
        ])
        t0 = time.perf_counter()
        self.model.fit([r["text"] for r in train_rows], [int(r["label"]) for r in train_rows])
        self.train_seconds = time.perf_counter() - t0

    def score(self, texts: list[str]) -> ScoreResult:
        scores: list[float] = []
        latencies: list[float] = []
        batch = 256
        for i in range(0, len(texts), batch):
            chunk = texts[i : i + batch]
            t0 = time.perf_counter()
            probs = self.model.predict_proba(chunk)[:, 1]
            dt = (time.perf_counter() - t0) * 1000 / len(chunk)
            scores.extend(float(p) for p in probs)
            latencies.extend([dt] * len(chunk))
        return ScoreResult(scores, latencies)
