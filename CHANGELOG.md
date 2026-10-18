# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-18

Major expansion: runtime prevention, deep forensics, and adversarial hardening.

### Added
- **Streaming taint engine** (`SessionState.feed` / `preview`): incremental,
  side-effect-free what-if evaluation; batch `analyze` is now a loop over it, with
  a streaming==batch invariant test.
- **Anchored rule evaluation**: `RuleEngine.evaluate(analysis, anchor=event_id)`
  reports only findings a specific event completes.
- **Runtime guard** (`taintline.guard`): pre-execution allow/log/approve/block on
  every tool call, a declarative YAML policy engine, model-output screening
  (beacon neutralization, secret redaction), a write-ahead audit trail, and
  incident replay. New rules can block memory poisoning at write time.
- **MCP stdio proxy** (`taintline guard mcp-proxy`): zero-code enforcement in
  front of any MCP server — strips poisoned tools, blocks dangerous calls,
  tracks results as taint.
- **Adversarial normalization** (`taintline.normalize`): de-obfuscates Unicode
  tags, homoglyphs, zero-width chars, base64/hex, entities, spacing, leetspeak
  before scoring; encoded secrets are still tracked in data-flow.
- **Evasion fuzzer** (`taintline.fuzz`): per-layer recall under 11 obfuscations ×
  6 exfil encodings, with hardening on/off.
- **Deep forensics** (`taintline.forensics`): IOC extraction, STIX 2.1 export,
  blast-radius assessment with remediation, Ed25519-signed evidence packs, and
  AWS CloudTrail correlation.
- **Interactive dashboard** (`taintline.dashboard`): single-file HTML
  investigation UI (timeline, SVG attack graph, IOCs, guard verdicts).
- New CLI: `guard` and `forensics` command groups; `analyze --dashboard
  --evidence-pack --guard-replay`.
- `cryptography` dependency (Ed25519 signing). Test suite grows to 113 tests.

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
