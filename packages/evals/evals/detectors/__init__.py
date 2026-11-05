"""Detector adapters.

Every adapter exposes ``name``, ``kind`` (rule | classifier | external),
``threshold`` (its native decision threshold on the score scale) and
``score(texts) -> ScoreResult``. Adapters that cannot run in the current
environment set ``available = False`` with an ``unavailable_reason`` so the
report carries a "not measured" row instead of silently omitting them.
"""

from __future__ import annotations

from .base import Detector, ScoreResult
from .regex import RegexDetector
from .length_only import LengthOnlyDetector
from .ngram_lr import NgramLRDetector
from .hf_classifier import HFClassifierDetector
from .evident_guard import EvidentGuardDetector
from .jev import JevDetector
from .llm_judge import LLMJudgeDetector


def build_detectors(train_rows: list[dict]) -> list[Detector]:
    detectors: list[Detector] = [
        RegexDetector("low"),
        RegexDetector("medium"),
        RegexDetector("high"),
        LengthOnlyDetector(train_rows),
        NgramLRDetector(train_rows),
        HFClassifierDetector(
            name="protectai_deberta_v2",
            model_id="protectai/deberta-v3-base-prompt-injection-v2",
            positive_labels=("INJECTION",),
        ),
        HFClassifierDetector(
            name="promptguard2_22m",
            model_id="meta-llama/Llama-Prompt-Guard-2-22M",
            positive_labels=("LABEL_1", "MALICIOUS"),
            gated=True,
        ),
        HFClassifierDetector(
            name="promptguard2_86m",
            model_id="meta-llama/Llama-Prompt-Guard-2-86M",
            positive_labels=("LABEL_1", "MALICIOUS"),
            gated=True,
        ),
        EvidentGuardDetector(),
        JevDetector(),
        LLMJudgeDetector(),
    ]
    return detectors


__all__ = ["Detector", "ScoreResult", "build_detectors"]
