from evals.detectors.jev import extract_score


def test_extracts_nested_score():
    assert extract_score({"answers": [{"type": "score", "score": 0.83}]}) == 0.83
    assert extract_score({"result": {"probability": 0.2}}) == 0.2
    assert extract_score({"answers": [{"value": 7}]}) is None  # out of range
    assert extract_score({"nothing": "here"}) is None
