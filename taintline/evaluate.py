"""Evaluation harness: measure the rule pack and anomaly model against the
labelled synthetic scenarios.

Two things are scored:

* **Rule detection** - for each attack scenario, did the expected rule ids
  fire? Across all scenarios, how many benign sessions produced a high/critical
  finding (false positives)?
* **Anomaly separation** - does the baseline model rank attack sessions above
  benign ones? Reported as ROC-AUC plus the alert rate at the chosen threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from taintline.anomaly import Baseline
from taintline.rules.engine import SEVERITY_RANK, RuleEngine, load_rules
from taintline.schema import group_sessions
from taintline.simulate.scenarios import SCENARIOS, Scenario
from taintline.simulate.synth import benign_session
from taintline.taint import TaintEngine
from taintline.toolclass import ToolClassifier


@dataclass
class ScenarioResult:
    name: str
    category: str
    expected: list[str]
    fired: list[str]
    missed: list[str]
    unexpected_high: list[str]
    anomaly_score: float
    flagged_anomalous: bool

    @property
    def detected(self) -> bool:
        if self.category == "attack":
            return not self.missed
        return True


@dataclass
class EvalReport:
    scenarios: list[ScenarioResult]
    rule_precision: float
    rule_recall: float
    rule_f1: float
    benign_false_positive_rate: float
    anomaly_auc: float
    confusion: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_precision": round(self.rule_precision, 4),
            "rule_recall": round(self.rule_recall, 4),
            "rule_f1": round(self.rule_f1, 4),
            "benign_false_positive_rate": round(self.benign_false_positive_rate, 4),
            "anomaly_auc": round(self.anomaly_auc, 4),
            "confusion": self.confusion,
            "scenarios": [
                {
                    "name": s.name,
                    "category": s.category,
                    "expected": s.expected,
                    "fired": s.fired,
                    "missed": s.missed,
                    "unexpected_high": s.unexpected_high,
                    "anomaly_score": round(s.anomaly_score, 4),
                    "flagged_anomalous": s.flagged_anomalous,
                    "detected": s.detected,
                }
                for s in self.scenarios
            ],
        }


def _roc_auc(labels: list[int], scores: list[float]) -> float:
    """Mann-Whitney U formulation of ROC-AUC (handles ties)."""
    pos = [s for s, y in zip(scores, labels, strict=False) if y == 1]
    neg = [s for s, y in zip(scores, labels, strict=False) if y == 0]
    if not pos or not neg:
        return float("nan")
    ranked = sorted((s, i) for i, s in enumerate(scores))
    ranks: dict[int, float] = {}
    i = 0
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[ranked[k][1]] = avg
        i = j
    rank_pos = sum(ranks[i] for i, y in enumerate(labels) if y == 1)
    n_pos, n_neg = len(pos), len(neg)
    u = rank_pos - n_pos * (n_pos + 1) / 2.0
    return u / (n_pos * n_neg)


def run_eval(baseline_benign: int = 60, seed: int = 101, rule_paths: list[str] | None = None) -> EvalReport:
    import random

    rng = random.Random(seed)

    # 1) build & fit an anomaly baseline on fresh benign sessions
    benign_events = []
    for i in range(baseline_benign):
        benign_events.extend(benign_session(f"base-{i:03d}", rng=rng))
    base_sessions = group_sessions(benign_events)
    base_engine = TaintEngine(ToolClassifier())
    base_analyses = base_engine.analyze_sessions(base_sessions)
    baseline = Baseline().fit(base_analyses)

    # 2) rules
    engine = RuleEngine(load_rules(rule_paths))

    results: list[ScenarioResult] = []
    tp = fp = fn = 0
    benign_sessions = 0
    benign_fp_sessions = 0
    auc_labels: list[int] = []
    auc_scores: list[float] = []

    # memory scenarios share state across two sessions, so analyze them together
    def analyze_scenario(sc: Scenario) -> None:
        nonlocal tp, fp, fn, benign_sessions, benign_fp_sessions
        extra_events: list = []
        if sc.name == "memory_poison_trigger":
            extra_events = SCENARIOS[2].build()  # the matching write session
        te = TaintEngine(ToolClassifier())
        sessions = group_sessions(extra_events + sc.build())
        analyses = te.analyze_sessions(sessions)
        target = analyses[-1]
        findings = engine.evaluate(target)
        fired = sorted({f.rule_id for f in findings})
        high = sorted({f.rule_id for f in findings if f.rank >= SEVERITY_RANK["high"]})
        expected = set(sc.expected_rules)
        missed = sorted(expected - set(fired))
        a_res = baseline.score(target)
        if sc.category == "attack":
            tp += len(expected & set(fired))
            fn += len(missed)
            # unexpected high/critical findings in an attack are still true-ish; count
            # as precision-neutral. precision is driven by benign false positives.
            unexpected = []
        else:
            benign_sessions += 1
            unexpected = high
            if high:
                benign_fp_sessions += 1
                fp += len(high)
        results.append(
            ScenarioResult(
                name=sc.name,
                category=sc.category,
                expected=sc.expected_rules,
                fired=fired,
                missed=missed,
                unexpected_high=unexpected,
                anomaly_score=a_res.score,
                flagged_anomalous=a_res.is_anomalous,
            )
        )
        auc_labels.append(1 if sc.category == "attack" else 0)
        auc_scores.append(a_res.score)

    for sc in SCENARIOS:
        analyze_scenario(sc)

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = benign_fp_sessions / benign_sessions if benign_sessions else 0.0
    auc = _roc_auc(auc_labels, auc_scores)

    return EvalReport(
        scenarios=results,
        rule_precision=precision,
        rule_recall=recall,
        rule_f1=f1,
        benign_false_positive_rate=fpr,
        anomaly_auc=auc if auc == auc else 0.0,  # nan guard
        confusion={"expected_rule_hits": tp, "missed_rule_hits": fn, "benign_high_findings": fp, "benign_sessions": benign_sessions},
    )
