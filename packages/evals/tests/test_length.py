from collections import Counter

from evals.detectors.length_only import LengthOnlyDetector
from evals.length import length_buckets, length_matched_indices


def test_buckets_are_quartiles():
    texts = ["a" * n for n in range(1, 101)]
    buckets, edges = length_buckets(texts)
    counts = Counter(buckets)
    assert len(edges) == 3
    assert all(20 <= c <= 30 for c in counts.values())


def test_length_matched_balances_classes_per_bucket():
    texts = ["a" * n for n in range(1, 101)]
    labels = [1 if n > 50 else 0 for n in range(1, 101)]  # attacks are the long ones
    buckets, _ = length_buckets(texts)
    idx = length_matched_indices(labels, buckets, seed=1)
    for b in set(buckets):
        sel = [i for i in idx if buckets[i] == b]
        assert sum(labels[i] for i in sel) * 2 == len(sel)


def test_length_only_detector_scores_in_unit_interval():
    rows = [{"text": "short attack", "label": 1}, {"text": "a much longer benign sentence about the weather today", "label": 0}] * 10
    det = LengthOnlyDetector(rows)
    res = det.score(["hi", "a very long benign message indeed about nothing in particular"])
    assert len(res.scores) == 2 and all(0 <= s <= 1 for s in res.scores)
