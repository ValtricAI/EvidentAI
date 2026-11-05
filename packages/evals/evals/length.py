"""Length-confound utilities: character-length buckets and length-matched subsets."""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Sequence

import numpy as np

BUCKET_LABELS = ("q1_short", "q2", "q3", "q4_long")


def length_buckets(texts: Sequence[str]) -> tuple[list[str], list[float]]:
    """Assign each text to a character-length quartile computed on this set."""
    lengths = np.array([len(t) for t in texts], dtype=float)
    if len(lengths) == 0:
        return [], []
    edges = np.quantile(lengths, [0.25, 0.5, 0.75]).tolist()
    labels = []
    for n in lengths:
        if n <= edges[0]:
            labels.append(BUCKET_LABELS[0])
        elif n <= edges[1]:
            labels.append(BUCKET_LABELS[1])
        elif n <= edges[2]:
            labels.append(BUCKET_LABELS[2])
        else:
            labels.append(BUCKET_LABELS[3])
    return labels, edges


def length_matched_indices(labels: Sequence[int], buckets: Sequence[str], seed: int = 0) -> list[int]:
    """Within each length bucket keep an equal number of attacks and benign rows.

    Reservoir-style: for every bucket, sample min(#attack, #benign) rows from
    each class, so the two classes end up with the same length distribution.
    """
    rng = random.Random(seed)
    by_bucket: dict[str, dict[int, list[int]]] = defaultdict(lambda: {0: [], 1: []})
    for i, (y, b) in enumerate(zip(labels, buckets)):
        by_bucket[b][int(y)].append(i)
    chosen: list[int] = []
    for groups in by_bucket.values():
        k = min(len(groups[0]), len(groups[1]))
        if k == 0:
            continue
        chosen.extend(rng.sample(groups[0], k))
        chosen.extend(rng.sample(groups[1], k))
    return sorted(chosen)
