import random

from taintline.anomaly import Baseline, BigramModel, IsolationForest
from taintline.schema import group_sessions
from taintline.simulate.scenarios import get_scenario
from taintline.simulate.synth import benign_session
from taintline.taint import TaintEngine
from taintline.toolclass import ToolClassifier
import numpy as np


def _benign_analyses(n=40, seed=3):
    rng = random.Random(seed)
    events = []
    for i in range(n):
        events.extend(benign_session(f"b-{i}", rng=rng))
    return TaintEngine(ToolClassifier()).analyze_sessions(group_sessions(events))


def test_bigram_roundtrip():
    m = BigramModel().fit([["<s>", "a", "b", "</s>"], ["<s>", "a", "c", "</s>"]])
    d = m.to_dict()
    m2 = BigramModel.from_dict(d)
    seq = ["<s>", "a", "b", "</s>"]
    assert abs(m.nll(seq) - m2.nll(seq)) < 1e-9


def test_isolation_forest_json_roundtrip():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(100, 5))
    f = IsolationForest(n_trees=20, sample_size=32).fit(X)
    s1 = f.score(X[:5])
    f2 = IsolationForest.from_dict(f.to_dict())
    s2 = f2.score(X[:5])
    assert np.allclose(s1, s2)


def test_baseline_fit_and_save(tmp_path):
    analyses = _benign_analyses()
    b = Baseline().fit(analyses)
    p = tmp_path / "baseline.json"
    b.save(str(p))
    b2 = Baseline.load(str(p))
    a = analyses[0]
    assert abs(b.score(a).score - b2.score(a).score) < 1e-9


def test_attack_scores_higher_than_benign():
    analyses = _benign_analyses(n=50)
    b = Baseline().fit(analyses)
    benign_score = np.mean([b.score(a).score for a in analyses])
    atk = TaintEngine(ToolClassifier()).analyze_sessions(group_sessions(get_scenario("cloud_privesc").build()))[0]
    atk_score = b.score(atk).score
    assert atk_score > benign_score


def test_baseline_needs_enough_sessions():
    import pytest

    with pytest.raises(ValueError):
        Baseline().fit(_benign_analyses(n=3)[:3])
