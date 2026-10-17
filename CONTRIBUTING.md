# Contributing

Thanks for looking. taintline is meant to grow mostly through its **rule pack**
and **tool classifications** — the detection content — which don't require
touching the engine.

## Dev setup

```bash
pip install -e ".[dev]"
pytest
ruff check taintline/ tests/
taintline evaluate      # detection quality gate
```

## Adding a detection rule

1. Write the rule in a YAML file (see [docs/rule-authoring.md](docs/rule-authoring.md)).
   Built-ins live in `taintline/rules/builtin/`.
2. Add (or reuse) a **labelled scenario** in `taintline/simulate/scenarios.py`
   with the rule ids it should fire, plus a hard-negative benign case if your rule
   risks false positives.
3. Run `taintline evaluate`. Your rule must fire on its scenario **and** keep the
   benign false-positive rate at 0.

Every rule needs: a stable `id`, a `severity`, a one-line analyst `description`,
and framework `mappings` where applicable.

## Adding a tool classification

Extend the pattern tables in `taintline/toolclass.py`, or — better for your own
environment — ship a YAML override and load it with `--tool-config`. Add a test
in `tests/test_toolclass.py`.

## Engine changes

Changes to `taint.py`, `rules/engine.py` or `anomaly.py` need tests and must not
regress `taintline evaluate` (recall 1.0, benign FP 0.0 on the bundled suite).
Keep the core dependency-light and **never introduce pickling** of models or
rules — JSON only.

## Style

- Python 3.10+, type hints, `ruff` clean.
- Transparent heuristics over opaque ones: a reviewer should be able to read a
  regex and understand why a finding fired.
- All attack/test data must be synthetic: fake secrets, `.test`/`example.com`
  destinations, no real systems.
