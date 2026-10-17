# Evaluation

taintline ships its own evaluation harness so detection quality is a measured
number, not a claim. Run it yourself:

```bash
taintline evaluate            # table
taintline evaluate --json     # machine-readable
```

## Method

The harness (`taintline/evaluate.py`) does three things:

1. Fits a fresh anomaly **baseline** on newly generated benign-only sessions.
2. Runs the full rule pack against **13 labelled scenarios** (10 attacks, 3 hard
   negatives) defined in `taintline/simulate/scenarios.py`. Each attack is
   labelled with the rule ids that *should* fire.
3. Computes rule-pack precision/recall/F1, the benign false-positive rate, and
   the anomaly model's ROC-AUC (attack vs benign).

The three **hard negatives** are benign sessions engineered to look suspicious —
a doc emailed to an address the user explicitly gave, a page *about* API-key
hygiene and prompt injection, and an authorized multi-file deletion. A naive
keyword or frequency detector trips on all three; taintline must not.

## Results (bundled synthetic suite)

Rule + taint engine (the primary detector):

| Metric | Value |
|---|---:|
| Recall (expected rules fired) | **1.00** |
| Precision | **1.00** |
| F1 | **1.00** |
| Benign false-positive rate | **0.00** |

Every attack scenario is detected; no hard-negative benign session raises a
high/critical finding.

Anomaly model (complementary signal), ROC-AUC over 20 seeds:

| mean | median | min | max |
|---:|---:|---:|---:|
| 0.637 | 0.633 | 0.467 | 0.833 |

Clearly better than random (0.50), but intentionally not relied on as the primary
detector: three labelled attacks (PII exfiltration, output-beacon, stealthy
memory-poison write) are *structurally identical to benign sessions* and are
caught by the rule/taint engine instead. That is the point of having both layers.

## Per-scenario detection

| Scenario | Type | Rules fired |
|---|---|---|
| indirect_exfil | attack | TL-EXF-001, TL-INJ-001, TL-SEQ-001 |
| tool_poisoning | attack | TL-SCH-001/002/003, TL-EXF-001, TL-SEQ-001 |
| memory_poison_write | attack | TL-MEM-001, TL-MEM-002 |
| memory_poison_trigger | attack | TL-MEM-003, TL-INJ-001 |
| chunked_exfil | attack | TL-EXF-002, TL-INJ-001, TL-SEQ-001 |
| cloud_privesc | attack | TL-INJ-002, TL-SEQ-002 |
| destructive_runaway | attack | TL-AGY-001, TL-SEQ-003 |
| jailbreak_then_action | attack | TL-JBK-001, TL-JBK-002 |
| output_beacon | attack | TL-EXF-006 |
| pii_exfil | attack | TL-EXF-003 |
| benign_authorized_send | benign | *(none)* |
| benign_security_article | benign | *(none)* |
| benign_authorized_cleanup | benign | *(none)* |

## Caveats

- These numbers are on a **synthetic** suite the project also authors. They
  demonstrate the engine behaves as designed and guard against regressions; they
  are **not** a claim of real-world precision on your traffic. Point taintline at
  your own traces, tune the tool-class config and rules, and re-measure.
- Real traffic has far more benign variety than three hard negatives. Expect to
  add tool-class overrides and `unless_principal_regex` guards as you triage.
- The anomaly baseline here is fit on synthetic benign chores; a production
  baseline should be fit on a representative sample of *your* benign sessions
  (`taintline baseline <your-benign-traces>`).
