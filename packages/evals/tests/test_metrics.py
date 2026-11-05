import math

from evals.metrics import classification_at_threshold, evaluate, latency_summary, ranking_metrics


def test_classification_counts():
    labels = [1, 1, 0, 0, 1]
    scores = [0.9, 0.4, 0.6, 0.1, 0.8]
    m = classification_at_threshold(labels, scores, 0.5)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 1)
    assert math.isclose(m["precision"], 2 / 3)
    assert math.isclose(m["recall"], 2 / 3)


def test_ranking_perfect_and_degenerate():
    perfect = ranking_metrics([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
    assert perfect["auroc"] == 1.0 and perfect["fpr_at_95_recall"] == 0.0
    single = ranking_metrics([1, 1], [0.3, 0.4])
    assert single["auroc"] is None


def test_evaluate_shape():
    m = evaluate([1, 0], [0.7, 0.2], 0.5, [1.0, 3.0])
    assert m["n"] == 2 and m["f1"] == 1.0
    assert m["latency"]["mean_ms"] == 2.0


def test_latency_empty():
    assert latency_summary([]) == {"mean_ms": None, "p95_ms": None}
