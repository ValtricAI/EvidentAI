"""Length-only confound baseline.

Attack and benign rows in public datasets often differ in length. A detector
that only beats this baseline by a little is mostly reading length, not
content. Features: log(1 + characters), log(1 + words).
"""

from __future__ import annotations

import math
import time

import numpy as np
from sklearn.linear_model import LogisticRegression

from .base import Detector, ScoreResult


def length_features(texts: list[str]) -> np.ndarray:
    return np.array([[math.log1p(len(t)), math.log1p(len(t.split()))] for t in texts], dtype=float)


class LengthOnlyDetector(Detector):
    name = "length_only"
    kind = "confound"
    threshold = 0.5
    notes = "logistic regression on log character and word counts only; a detector near this line is reading length, not content"

    def __init__(self, train_rows: list[dict]):
        if not train_rows:
            self.available = False
            self.unavailable_reason = "no training rows"
            return
        self.model = LogisticRegression(class_weight="balanced", max_iter=1000)
        self.model.fit(length_features([r["text"] for r in train_rows]), [int(r["label"]) for r in train_rows])

    def score(self, texts: list[str]) -> ScoreResult:
        t0 = time.perf_counter()
        probs = self.model.predict_proba(length_features(texts))[:, 1]
        dt = (time.perf_counter() - t0) * 1000 / max(1, len(texts))
        return ScoreResult([float(p) for p in probs], [dt] * len(texts))
