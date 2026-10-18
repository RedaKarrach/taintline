# Deep forensics

Beyond "was there an attack?", taintline answers the questions an incident
responder and an auditor actually ask.

## Indicators of compromise

`taintline forensics ioc trace.jsonl` extracts atoms you can pivot on and block
elsewhere: exfiltration domains/IPs/emails, the secrets that left (by kind, never
the value), injected source events, poisoned tools, and corrupted memory keys.
Every IOC traces back to the events that evidence it.

## STIX 2.1 export

`taintline forensics stix trace.jsonl --out bundle.json` emits a standard STIX
bundle: one `attack-pattern` per rule that fired (carrying its MITRE ATLAS /
ATT&CK / OWASP references), an `indicator` + observable per IOC, and a `report`
tying them together. IDs are deterministic, so re-exporting the same evidence
de-duplicates cleanly in a TIP/SIEM.

## Blast radius

`taintline forensics blast-radius trace.jsonl` turns findings into an impact
picture and an ordered remediation checklist: which secrets to rotate, which
destinations to block, whether persistence was established (poisoned
memory/tools), which capabilities were abused (cloud control, code exec,
identity), whether it spans sessions, and a severity tier. `analyze` prints it
automatically and writes `*.blast-radius.json`.

## Signed evidence packs

A pack bundles the evidence manifest, findings, IOCs, blast radius and STIX into
one JSON document, hashes it, and seals it with an **Ed25519 signature**:

```bash
taintline forensics pack keygen --out ir-key
taintline forensics pack build trace.jsonl --sign-key ir-key.key --case-id CASE-42 --out pack.json
taintline forensics pack verify pack.json --public-key ir-key.pub
```

Verification recomputes the digest and checks the signature, proving both
**integrity** (nothing altered) and **authenticity** (produced by the key
holder) — the chain-of-custody properties a court or auditor needs. The private
key never enters the pack; nothing is ever pickled.

## CloudTrail correlation

taintline says a credential was *exfiltrated*. CloudTrail correlation says
whether it was *used*:

```bash
taintline forensics cloudtrail trace.jsonl cloudtrail.json
```

It pulls the AWS access keys that left the boundary (with the time they left),
then scans CloudTrail for post-exposure use, flagging sensitive calls (IAM
changes, `GetSecretValue`, …), brand-new origins (IP/user-agent not seen before
exposure), and logging tampering (`StopLogging`/`DeleteTrail`). Output is a
per-key verdict: used / confirmed-abuse / not-seen.

## Investigation dashboard

`taintline forensics dashboard trace.jsonl --guard-replay --out dash.html` (or
`analyze --dashboard`) builds a single self-contained HTML file — no external
assets, opens offline — with tabs for Overview (blast radius + remediation),
Timeline (every event, taint level, injection score, triggered rules, filterable),
Findings, an inline-SVG attack graph, IOCs (CSV-exportable), and the Guard
verdicts. It's the artifact you hand to another responder or attach to the ticket.
