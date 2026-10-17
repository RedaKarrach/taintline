# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-17

Initial release.

### Added
- **Taint engine** (`taint.py`): control / data / stored taint propagation over
  agent sessions, per-call data-flow decisions, cross-session memory taint, and
  character-coverage payload tracking with chunked-exfiltration accumulation.
- **Tool classifier** (`toolclass.py`): source / sink / sensitive-read
  classification by name, file path and MCP transport, with YAML overrides.
- **Content heuristics** (`injection.py`): transparent injection scoring and
  secret detection.
- **YAML rule engine** (`rules/`) with eight matcher types and a 23-rule built-in
  pack mapped to MITRE ATLAS, MITRE ATT&CK, OWASP LLM Top 10 and NIST AI RMF.
- **Anomaly model** (`anomaly.py`): JSON-serialised isolation forest + bigram
  Markov model; no pickling.
- **Attack-graph export** (`graph.py`): Graphviz DOT and node-link JSON.
- **Chain of custody** (`custody.py`): evidence manifest with file hash and
  per-event hash chain, plus tamper verification.
- **Reports** (`report.py`): Markdown, JSON, SARIF 2.1.0, CSV timeline, HTML.
- **Adapters** (`adapters.py`): OpenAI chat logs and OpenTelemetry GenAI spans.
- **Simulator** (`simulate/`): benign generators and 10 labelled attack scenarios
  + 3 hard negatives.
- **Evaluation harness** (`evaluate.py`) and CLI (`cli.py`): `analyze`,
  `baseline`, `graph`, `custody`, `simulate`, `evaluate`, `rules`.
- Test suite (48 tests) and multi-version CI.
