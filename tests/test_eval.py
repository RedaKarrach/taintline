from taintline.evaluate import run_eval


def test_rule_pack_recall_is_perfect_on_labelled_attacks():
    rep = run_eval(baseline_benign=50, seed=7)
    # every attack scenario's primary expected rules must fire (the rule+taint
    # engine is the primary detector and is held to 100% recall on the suite)
    missed = {s.name: s.missed for s in rep.scenarios if s.category == "attack" and s.missed}
    assert not missed, f"missed expected rules: {missed}"
    assert rep.rule_recall == 1.0


def test_no_benign_false_positives():
    rep = run_eval(baseline_benign=50, seed=7)
    # the hard-negative benign sessions must not raise high/critical findings
    assert rep.benign_false_positive_rate == 0.0


def test_anomaly_model_beats_random_on_average():
    # The anomaly model is a COMPLEMENTARY signal for novel / structurally
    # unusual sessions. Several labelled attacks are deliberately stealthy and
    # structurally benign (they are caught by the rule+taint engine, not here),
    # so the honest expectation is "clearly better than random", not precise.
    # Measured mean over 20 seeds is ~0.64; we assert a safe lower bound.
    aucs = [run_eval(baseline_benign=60, seed=s).anomaly_auc for s in range(8)]
    mean_auc = sum(aucs) / len(aucs)
    assert mean_auc >= 0.58, (mean_auc, aucs)
