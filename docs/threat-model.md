# Threat model

## What taintline is

A **post-hoc forensic and detection engine** for AI-agent tool-use traces. It
assumes the agent has already run and you have a log of what it did. Its job is to
reconstruct how untrusted input influenced sensitive actions, produce
evidence-grade findings, and flag anomalous sessions.

## Assets it protects

- **Secrets** the agent can read (API keys, private keys, tokens, `.env`, cloud
  credentials) and **PII** it can access (customer/employee records).
- **Privileged capabilities** the agent holds (shell, cloud control plane,
  identity/IAM, financial actions, destructive operations).
- The **integrity of the agent's memory** across sessions.

## Adversaries and techniques modelled

| Adversary | Technique | Detection |
|---|---|---|
| Web/content author | **Indirect prompt injection** in a page/email/doc/ticket | `TL-INJ-001/002/003`, taint_path |
| Tool/plugin supplier | **Tool poisoning** — instructions in a tool description; secret to a remote MCP tool | `TL-SCH-001/002/003` |
| Patient attacker | **Memory poisoning** — plant in session 1, trigger in session 2 | `TL-MEM-001/002/003`, cross-session taint |
| Data thief | **Credential/PII exfiltration**, incl. **chunked low-and-slow** | `TL-EXF-001..006`, data-flow coverage |
| Post-compromise operator | **Cloud privilege escalation** via the agent | `TL-SEQ-002` |
| Compromised/insider account | **Jailbreak → sensitive action** | `TL-JBK-001/002` |
| Runaway or abused agent | **Excessive agency** — destructive bursts, loops, unprompted actions | `TL-AGY-001/002/003` |
| Output-channel abuse | **Markdown/pixel beacons** in model output | `TL-EXF-006` |

Mapped to **MITRE ATLAS**, **MITRE ATT&CK**, **OWASP Top 10 for LLM Apps
(2025)** and **NIST AI RMF** on every finding.

## Trust boundaries

- **Trusted:** the system prompt and the tool-calling harness itself.
- **Semi-trusted:** the human principal's messages (trusted for *authorization*,
  but a jailbreak message flips an account into an adversary — handled explicitly).
- **Untrusted:** everything returned by a source tool (web, email, documents,
  tickets, external files, remote MCP tools) and every tool *description*.

## What taintline does NOT do

- **It is not a runtime guardrail.** It does not sit in the request path or block
  a call before it happens. Pair it with input/output filters; taintline is the
  detection and forensics layer behind them.
- **It does not execute or sandbox anything.** It reads logs. No network, no code
  execution, no model inference, no pickled models.
- **It cannot see what isn't logged.** Influence that never produced a tool call
  or a logged output is invisible. Garbage or partial traces yield partial
  results; use `custody verify` to confirm you're analyzing complete evidence.

## Known limitations and evasion

- **Heuristic injection scoring.** Injection signals are transparent regexes. An
  attacker who avoids known phrasing lowers the injection score and can suppress
  the `TL-INJ-*` findings — but the **data-flow** (`TL-EXF-*`) and **sequence**
  (`TL-SEQ-*`) rules key off *actions and data movement*, not phrasing, and still
  fire. Defense in depth across matcher types is deliberate.
- **Lexical data-flow.** Payload leakage is measured by character coverage. A
  secret that is transformed before exfiltration (encrypted, hashed, re-encoded
  in a way that breaks 6-char runs) will evade the `data_flow` rules; the
  **sequence** rule (credential read → outbound call) is the backstop, since it
  does not require the secret to be recognizable in the output.
- **Classification by name/path.** Unusual tool names may be misclassified;
  override with a YAML tool-class config or `meta.trust`.
- **Anomaly model is complementary.** It flags structural outliers (mean ROC-AUC
  ≈ 0.64 on the synthetic suite); stealthy attacks that look structurally normal
  are the rules' job, not the model's. Expect benign structural outliers to be
  flagged — triage them with the findings table, which is the precise signal.
- **Framework mappings are triage labels**, verified against the frameworks as of
  the release date, not a compliance attestation.

## Responsible use

The bundled attack scenarios are **synthetic**: fake secrets, `.test`
destinations, no real systems. Use taintline on traces you are authorized to
analyze. It is built for defenders, incident responders, red/blue teams and
auditors.
