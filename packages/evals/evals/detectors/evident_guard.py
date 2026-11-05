"""Our own calibrated classifier, loaded from the ONNX export.

Directory layout (``models/evident-guard-v0/``)::

    model.onnx            sequence classification graph (optimum export)
    config.json           id2label {"0": "BENIGN", "1": "INJECTION"}
    tokenizer.json, tokenizer_config.json, special_tokens_map.json, spm.model
    calibration.json      {"temperature": T, "threshold": t, "max_length": L, ...}
    model_card.md

Calibrated probability: ``softmax(logits / temperature)[INJECTION]``.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import numpy as np

from .. import MODELS_DIR
from .base import Detector, ScoreResult

DEFAULT_DIR = MODELS_DIR / "evident-guard-v0"
BATCH = 16


def softmax(x: np.ndarray) -> np.ndarray:
    x = x - x.max(axis=-1, keepdims=True)
    e = np.exp(x)
    return e / e.sum(axis=-1, keepdims=True)


class EvidentGuardDetector(Detector):
    name = "evident_guard_v0"
    kind = "classifier"

    def __init__(self, model_dir: Path = DEFAULT_DIR):
        self.model_dir = Path(model_dir)
        self._session = None
        cal_path = self.model_dir / "calibration.json"
        if not (self.model_dir / "model.onnx").exists() or not cal_path.exists():
            self.available = False
            self.unavailable_reason = f"no trained model at {self.model_dir} (run python -m evals.train)"
            return
        self.calibration = json.loads(cal_path.read_text())
        self.temperature = float(self.calibration.get("temperature", 1.0))
        self.threshold = float(self.calibration.get("threshold", 0.5))
        self.max_length = int(self.calibration.get("max_length", 256))
        self.notes = f"deberta-v3-xsmall fine-tune, ONNX, temperature {self.temperature:.3f}, threshold {self.threshold:.3f}"

    def _load(self):
        if self._session is not None:
            return
        import onnxruntime as ort
        from transformers import AutoTokenizer

        opts = ort.SessionOptions()
        opts.intra_op_num_threads = max(1, os.cpu_count() or 1)
        self._session = ort.InferenceSession(str(self.model_dir / "model.onnx"), opts, providers=["CPUExecutionProvider"])
        self._inputs = {i.name for i in self._session.get_inputs()}
        self._tok = AutoTokenizer.from_pretrained(str(self.model_dir))
        config = json.loads((self.model_dir / "config.json").read_text())
        id2label = {int(k): str(v).upper() for k, v in config.get("id2label", {"0": "BENIGN", "1": "INJECTION"}).items()}
        self._pos = next((i for i, l in id2label.items() if l == "INJECTION"), 1)

    def score(self, texts: list[str]) -> ScoreResult:
        self._load()
        scores: list[float] = []
        latencies: list[float] = []
        for i in range(0, len(texts), BATCH):
            chunk = texts[i : i + BATCH]
            t0 = time.perf_counter()
            enc = self._tok(chunk, truncation=True, max_length=self.max_length, padding=True, return_tensors="np")
            feed = {k: v.astype(np.int64) for k, v in enc.items() if k in self._inputs}
            logits = self._session.run(None, feed)[0]
            probs = softmax(logits / self.temperature)[:, self._pos]
            dt = (time.perf_counter() - t0) * 1000 / len(chunk)
            scores.extend(float(p) for p in probs)
            latencies.extend([dt] * len(chunk))
        return ScoreResult(scores, latencies)
