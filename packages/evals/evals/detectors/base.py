from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScoreResult:
    """Scores in [0, 1] where higher means more likely an attack.

    ``latencies_ms`` has one entry per text. For batched classifiers the batch
    wall time is divided evenly across its texts (amortised latency).
    """

    scores: list[float]
    latencies_ms: list[float] = field(default_factory=list)


class Detector:
    name: str = "detector"
    kind: str = "classifier"  # rule | classifier | external
    threshold: float = 0.5
    available: bool = True
    unavailable_reason: str = ""
    notes: str = ""

    def score(self, texts: list[str]) -> ScoreResult:  # pragma: no cover - interface
        raise NotImplementedError

    def describe(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "threshold": self.threshold,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "notes": self.notes,
        }
