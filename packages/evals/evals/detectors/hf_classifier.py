"""Off-the-shelf Hugging Face sequence classifiers (ProtectAI, Prompt Guard 2)."""

from __future__ import annotations

import os
import time

from .base import Detector, ScoreResult

BATCH = 16
MAX_LENGTH = 512


class HFClassifierDetector(Detector):
    kind = "classifier"
    threshold = 0.5

    def __init__(self, name: str, model_id: str, positive_labels: tuple[str, ...], gated: bool = False):
        self.name = name
        self.model_id = model_id
        self.positive_labels = {p.upper() for p in positive_labels}
        self.notes = f"{model_id}; P(positive label), max_length {MAX_LENGTH}"
        self._pipe = None
        if gated and not (os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")):
            self.available = False
            self.unavailable_reason = "gated model; set HF_TOKEN after accepting the licence"

    def _load(self):
        if self._pipe is not None:
            return self._pipe
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        torch.set_num_threads(max(1, os.cpu_count() or 1))
        self._tok = AutoTokenizer.from_pretrained(self.model_id)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.model_id).eval()
        id2label = {int(k): str(v).upper() for k, v in self._model.config.id2label.items()}
        self._pos_idx = [i for i, lab in id2label.items() if lab in self.positive_labels]
        if not self._pos_idx:
            # Fall back to the last label, the usual "positive" slot.
            self._pos_idx = [max(id2label)]
        self._pipe = True
        return self._pipe

    def score(self, texts: list[str]) -> ScoreResult:
        import torch

        self._load()
        scores: list[float] = []
        latencies: list[float] = []
        with torch.inference_mode():
            for i in range(0, len(texts), BATCH):
                chunk = texts[i : i + BATCH]
                t0 = time.perf_counter()
                enc = self._tok(chunk, truncation=True, max_length=MAX_LENGTH, padding=True, return_tensors="pt")
                logits = self._model(**enc).logits
                probs = torch.softmax(logits, dim=-1)
                pos = probs[:, self._pos_idx].sum(dim=-1)
                dt = (time.perf_counter() - t0) * 1000 / len(chunk)
                scores.extend(float(p) for p in pos.tolist())
                latencies.extend([dt] * len(chunk))
        return ScoreResult(scores, latencies)
