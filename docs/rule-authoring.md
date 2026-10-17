# Writing detection rules

Rules are YAML documents (one or many per file, separated by `---`). Drop a
`.yaml` file anywhere and load it with `taintline analyze --rules my-rules/`.
Validate the whole pack with `taintline rules --rules my-rules/`.

## Anatomy

```yaml
id: TL-INJ-001                 # unique id (required)
title: Short human title       # (required)
severity: critical             # info|low|medium|high|critical (required)
description: >                 # shown in reports as "why it matters"
  One or two sentences of analyst context.
match:                         # exactly one matcher (required)
  type: taint_path
  source_class: [web, email]
  sink_class: [any_exfil]
  min_confidence: 0.35
mappings:                      # optional framework references (triage labels)
  mitre_atlas: [AML.T0051.001]
  owasp_llm: [LLM01, LLM02]
tags: [injection, exfiltration]
references: [https://...]
enabled: true                  # optional, default true
```

> **YAML footgun:** never use a bare `on:` key — YAML 1.1 parses it as the
> boolean `True`. Use `on_kind:`. taintline rejects `on:` with a clear error.

## Tool classes you can reference

**Source classes:** `web`, `search`, `email`, `chat_external`, `document`,
`ticket`, `repo_external`, `file_external`, `mcp_remote`, `tool_schema`,
`untrusted_tool`, `trusted_tool`, `user`, `memory`.

**Sink classes:** `network_egress`, `email_send`, `messaging_send`,
`code_execution`, `file_write`, `destructive`, `cloud_control`, `data_write`,
`financial`, `identity`, `mcp_remote`.

**Sensitive-read classes:** `credential`, `pii`.

**Pseudo-classes:** `any_sink`, `any_source`, `any_exfil` (= network_egress +
email_send + messaging_send + mcp_remote), `file_read`, `memory_read`,
`memory_write`, and `*` (any).

## Matchers

### `taint_path` — untrusted influence reaches a sink
```yaml
match:
  type: taint_path
  source_class: [web, email]      # origin classes (or "*")
  sink_class: [any_exfil]         # destination classes (or "*")
  min_confidence: 0.35
  min_source_injection: 0.3       # require injection signals at the source
  taint_kind: [control, data]     # optional filter
  require_unauthorized_destination: true   # only if the dest wasn't named by the user
  cross_session: true             # only flows whose origin is an earlier session
```

### `data_flow` — a sensitive payload leaks into a sink
```yaml
match:
  type: data_flow
  data_class: [credential, secret_pattern, pii]
  sink_class: [any_exfil]
  min_coverage: 0.3               # fraction of the secret present in the call
  chunked: true                   # true=only accumulated, false=only single-call
  require_unauthorized_destination: true
```

### `sequence` — ordered steps within a window
```yaml
match:
  type: sequence
  within: 8                       # max events between consecutive steps
  unless_principal_regex: '\b(delete|remove|purge)\b'   # stand down if the user asked
  steps:
    - tool_class: [credential]
    - tool_class: [any_exfil]
      args_regex: 'https?://'
      min_taint: 0.0
      tool: ["http_*"]            # fnmatch on tool name
      kind: [tool_call]
```

### `frequency` — N calls of a class in a window
```yaml
match:
  type: frequency
  tool_class: [destructive]
  min_count: 5
  window: 15
  unless_principal_regex: '\b(delete|clean ?up)\b'
```

### `loop` — identical call repeated
```yaml
match:
  type: loop
  tool_class: ["*"]
  min_repeats: 4
```

### `content` — regex / injection / secret checks on event text
```yaml
match:
  type: content
  on_kind: [model_output]         # which event kinds to scan
  regex: '!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]{8,}\)'
  min_injection_score: 0.5
  secret_present: true
  tool_class: [network_egress]
  min_taint: 0.4
```

### `schema_injection` — poisoned tool description
```yaml
match:
  type: schema_injection
  min_injection_score: 0.3
```

### `unprompted_sink` — high-impact action the user never asked for
```yaml
match:
  type: unprompted_sink
  sink_class: [destructive, financial, identity]
  principal_regex: '\b(delete|pay|invite|grant)\b'   # if present in user text, suppress
```

## Testing a rule

```bash
# fire it against a built-in attack scenario
taintline simulate --scenario cloud_privesc --out /tmp/s.jsonl
taintline analyze /tmp/s.jsonl --rules my-rules/ --no-builtin

# or add a labelled scenario in taintline/simulate/scenarios.py and run:
taintline evaluate --rules my-rules/
```

Aim for: the rule fires on its target scenario, and **no benign scenario**
(`benign_*`) produces a high/critical finding. `taintline evaluate` reports the
benign false-positive rate directly.
