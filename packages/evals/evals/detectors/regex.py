"""The shared regex library, scored through the Node bridge.

The bridge turns the highest matched severity into an ordinal proxy score
(none 0, low 0.25, medium 0.5, high 0.75, critical 0.9, plus 0.01 per extra
match). It is NOT a probability: AUROC for the regex rows ranks severities,
nothing more. The decision threshold is "any match", i.e. score > 0.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from .. import REGEX_BRIDGE, REPO_ROOT
from .base import Detector, ScoreResult

WARMUP_ROWS = 10  # the first rows pay regex JIT warm-up; excluded from latency


class RegexDetector(Detector):
    kind = "rule"
    threshold = 0.01
    notes = "score is an ordinal severity proxy, not a probability"

    def __init__(self, sensitivity: str):
        self.sensitivity = sensitivity
        self.name = f"regex_{sensitivity}"
        if shutil.which("node") is None or not REGEX_BRIDGE.exists():
            self.available = False
            self.unavailable_reason = "node or packages/detectors/bin/score.mjs not found"

    def score(self, texts: list[str]) -> ScoreResult:
        # Prepend warm-up rows so measured latency reflects steady state.
        warm = [{"id": f"__warm{i}", "text": "What is the weather like today?"} for i in range(WARMUP_ROWS)]
        rows = warm + [{"id": str(i), "text": t} for i, t in enumerate(texts)]
        payload = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
        proc = subprocess.run(
            ["node", str(REGEX_BRIDGE), "--sensitivity", self.sensitivity],
            input=payload,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=True,
        )
        scores = [0.0] * len(texts)
        latencies = [0.0] * len(texts)
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            out = json.loads(line)
            if str(out["id"]).startswith("__warm"):
                continue
            i = int(out["id"])
            scores[i] = float(out["score"])
            latencies[i] = float(out["latencyMs"])
        return ScoreResult(scores, latencies)
