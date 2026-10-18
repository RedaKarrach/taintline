# Architecture

taintline is a pipeline. Each stage is a small, testable module. The engine is
**incremental**: `TaintEngine.new_session(id)` returns a `SessionState` you
`feed(event)` one event at a time, and `preview(event)` answers "what would this
event create?" with no side effects. Batch `analyze()` is a thin loop over
`feed`, so the forensic analyzer and the runtime guard share identical logic (a
`tests/test_streaming.py` invariant checks streaming == batch on every scenario).

```
 trace (JSONL / OpenAI / OTel)
        │  schema.py / adapters.py
        ▼
   [ Event ] ──grouped──► [ Session ]           schema.group_sessions
        │
        │  toolclass.py          classify each tool: source / sink / sensitive-read / transport
        ▼
   TaintEngine.analyze            taint.py
     ├─ seed taint at untrusted sources       (injection.py: injection score)
     ├─ propagate through model turns & calls  (textsim.py: provenance / containment)
     ├─ persist taint through memory           (cross-session)
     ├─ build payloads from secret/PII reads   (injection.py: secret detection)
     └─ record Flows into sinks                (data-flow coverage, chunked accumulation)
        │
        ▼
   SessionAnalysis ──► RuleEngine.evaluate     rules/engine.py + rules/builtin/*.yaml
        │                 │                     → Findings (mapped to ATLAS/ATT&CK/OWASP/NIST)
        │                 │
        │                 ├─► graph.py          provenance / attack graph (DOT, node-link JSON)
        │                 └─► anomaly.py         isolation forest + bigram  → AnomalyResult
        ▼
   report.py   →  Markdown · JSON · SARIF 2.1 · CSV timeline · HTML
   custody.py  →  evidence manifest (file hash + per-event hash chain)

 Built on the same SessionAnalysis / SessionState:
   guard/        preview each call -> policy -> allow/log/approve/block; MCP proxy
   normalize.py  de-obfuscate (NFKC, tags, homoglyphs, base64…) before scoring
   fuzz.py       evasion matrix: measures each layer's recall under obfuscation
   forensics/    ioc · stix (2.1) · blast (impact+remediation) · pack (Ed25519) · cloudtrail
   dashboard.py  single-file interactive HTML investigation UI
```

## Guard (runtime prevention)

`guard/` reuses the engine's `preview` + anchored rule evaluation to decide on a
tool call before it runs. A declarative YAML **policy** maps flows/findings to
allow/log/require_approval/block; the `MCPProxy` enforces it on live MCP stdio
traffic with no change to the agent. Blocked calls are recorded as attempts but
never advance leak state. See [guard.md](guard.md).

## Hardening & robustness

`normalize.py` produces de-obfuscated *views* of text (Unicode NFKC, zero-width
and tag stripping, homoglyph folding, base64/hex/entity/percent decoding,
de-spacing); injection scoring unions signals across all views and treats the
obfuscation itself as a signal, with benign-use guards. `fuzz.py` is an evasion
harness that measures per-layer recall with hardening on and off. See
[robustness.md](robustness.md).

## Forensics

`forensics/` builds on the analysis: `ioc` (indicators), `stix` (STIX 2.1
bundle), `blast` (impact + remediation checklist), `pack` (Ed25519-signed
evidence bundle), `cloudtrail` (was an exfiltrated key actually used?). See
[forensics.md](forensics.md).

## The taint model

An agent turn is modelled as everything the model has seen so far sitting in its
**context**. Three kinds of taint ride that context:

| Kind | Meaning | Confidence floor |
|---|---|---|
| **control** | untrusted content is in context and may have *influenced* a decision | driven by injection score |
| **data** | untrusted content literally *flows into* a specific call's arguments | 0.4 |
| **stored** | taint that entered (or was revived from) the agent's memory | 0.9 × origin |

Key design decisions, and why:

- **Data-ness is per-call, not global.** When the model restates a benign source
  (e.g. repeating a weather forecast), that does **not** promote the context to
  data taint. Whether real content flows is decided at each sink from *that
  call's own arguments* (`provenance`/`containment` in `textsim.py`). This is the
  single most important false-positive control: without it, any session that
  reads something and later calls a tool lights up.

- **Injection score gates "injection" findings.** A source becomes control taint
  with a confidence derived from `injection.score_injection` (a transparent
  noisy-OR over regex signals: override phrases, concealment, exfil imperatives,
  zero-width characters, markdown beacons, …). The `TL-INJ-*` rules additionally
  require `min_source_injection`, so "indirect prompt injection reached a sink"
  means the source actually carried injection signals — not merely that it was
  untrusted.

- **Payloads are tracked by character coverage, not shingles.** A credential or
  PII read becomes a `Payload`. For each outbound call we compute
  `covered_positions(secret, args)` — which characters of the secret appear in
  the call. This **tiles across calls**, so a key split into ten-character GET
  beacons accumulates to full coverage and trips the chunked-exfiltration rule,
  which fixed-window or n-gram methods miss when a chunk is shorter than the
  shingle.

- **Destination authorization lowers confidence — except for jailbreaks.** If an
  outbound destination was named by the human principal, influence confidence is
  cut (they asked for it). But when the taint's source *is* the principal (a
  jailbroken/compromised account naming its own drop point), the downgrade does
  not apply.

- **Memory is a cross-session channel.** `memory_write` stores taint/payloads
  under a key; a later `memory_read` of that key — in any later session, since
  the engine carries memory state across the whole corpus — revives them. This is
  how `TL-MEM-003` catches an attack planted on Monday and triggered on Tuesday.

## Tool classification (`toolclass.py`)

Tools are matched by `fnmatch` on their name into source/sink/sensitive classes,
with three refinements:

1. **File paths** promote a generic `read_file` to a credential read (`*.env`,
   `id_rsa`, `.aws/*`, …) or to an untrusted source (`downloads/`, `attachments/`).
2. **MCP transport** (`meta.transport: remote`, learned from `tool_registered`
   events) makes an otherwise-unknown remote tool both a source and an egress
   sink — remote tools are an exfiltration channel.
3. **Fetch/GET tools are dual-classed** as source *and* `network_egress` sink,
   because the request target and query string leave the trust boundary (this is
   how pixel/markdown-beacon exfiltration works).

Everything is overridable with a YAML config (`ToolClassifier.from_yaml`) or
per-event `meta.trust`.

## Rule engine (`rules/engine.py`)

Declarative YAML, one matcher per `match.type`:

`taint_path`, `data_flow`, `sequence`, `frequency`, `loop`, `content`,
`schema_injection`, `unprompted_sink`. See
[rule-authoring.md](rule-authoring.md). Findings from the same flow campaign
(one source beaconing to many sinks) are collapsed into a single report entry.

## Anomaly model (`anomaly.py`)

A **complementary** unsupervised signal for sessions the rules don't encode:

- A **bigram Markov model** over the sequence of tool *classes* gives a
  per-session negative log-likelihood (unusual tool grammar → high NLL).
- An **isolation forest** over 18 session features (counts, ratios, entropy,
  secret hits, taint density, max flow confidence, the Markov NLL …). Features
  are standardized and security-salient ones up-weighted so they aren't swamped
  by high-variance structural columns.

Both serialize to **plain JSON** — taintline never pickles a model, because a
security tool that unpickles is a deserialization RCE waiting to happen.

## Chain of custody (`custody.py`)

A manifest records the SHA-256 of the raw trace plus a hash chain
`h_i = sha256(h_{i-1} || canonical(event_i))`. Any edit, reorder or deletion of
an event changes the chain head and is pinpointed to the first divergent event,
so a report can be bound to exactly the evidence that produced it.
