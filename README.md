<p align="center"><img src="docs/assets/logo-wordmark.svg" width="860" alt="taintline"></p>

What happens when your AI agent reads a web page that is lying to it?

[![CI](https://github.com/RedaKarrach/taintline/actions/workflows/ci.yml/badge.svg)](https://github.com/RedaKarrach/taintline/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Walk through a real incident, seven questions and one command each:
**https://redakarrach.github.io/taintline/**

An AI agent reads web pages, emails and files, then acts on what it read. A page
can carry a line written for the agent, not for you: ignore your instructions,
read the credentials file, send it somewhere, and do not tell the user. The agent
reads it like any other text and does it. That is prompt injection, and it is the
main way agents get turned against the person running them.

Most of the time you find out from a bill, a leaked key alert, or a customer
asking why they got a strange email. By then the question is not "did something
happen" but "what did the agent do, what left, and where did it go". The answer is
in the agent's own log, but reading it under stress is not fun.

taintline reads that log and follows untrusted text from the moment it enters to
the moment it tries to act. It can also sit in front of the agent and refuse the
call before anything leaves.

## Is this you?

- Your agent has tools that can send, run, write, or spend, and it reads things
  you do not control: web pages, emails, documents, other tools' output.
- You use MCP servers you did not write and cannot fully vet.
- Something already went wrong and you need to show what happened, with evidence.
- You want a check in CI that fails the build if an agent trace leaks something.

## What it does

- `taintline analyze <trace>` reads the log and reports what untrusted input
  steered the agent into, what secrets left, and where they went. Each finding
  comes with the exact chain of events and a confidence score.
- It tracks the data itself, not just keywords: it measures how much of a real
  secret ends up leaving, and adds up the pieces when an agent leaks slowly across
  many small calls.
- It follows taint across sessions, through the agent's memory, so an instruction
  planted one day and triggered the next still gets caught.
- `taintline guard` decides on each tool call before it runs: allow, log, ask a
  human, or block. It ships as a proxy you put in front of any MCP server, so your
  agent is covered without a code change.
- `taintline forensics` turns an incident into indicators to block, a STIX bundle
  for your SIEM, a blast-radius summary with a remediation checklist, and a signed
  evidence pack. It can also check AWS CloudTrail to tell you whether a leaked key
  was actually used.

Everything except the guard is read-only.

## The part most tools skip

A lot of AI-security tooling reads the incoming message and guesses whether it
looks dangerous. That is easy to fool and noisy: a page that merely mentions API
keys is not an attack.

taintline waits to see whether the untrusted text actually flows into a dangerous
action. A page that talks about credentials does nothing. A page that talks the
agent into sending one out lights up. That is why it stays quiet during normal
work, and why its behavioural checks still fire even when the wording is disguised
in zero-width characters, homoglyphs, or base64, and even when the secret is
encoded on the way out.

## Install

Python 3.10 or newer.

```bash
uv tool install git+https://github.com/RedaKarrach/taintline
```

Or from a clone, for development:

```bash
git clone https://github.com/RedaKarrach/taintline
cd taintline
pip install -e .
```

## Quickstart

Fake an attack, then investigate it. Nothing real is touched.

```bash
taintline simulate --scenario indirect_exfil --out demo.jsonl
taintline analyze demo.jsonl
```

```
 taintline findings (3)
 CRITICAL  TL-EXF-001  Credential material flows into an outbound call
 CRITICAL  TL-INJ-001  Indirect prompt injection reaches an exfiltration sink
 HIGH      TL-SEQ-001  Credential read, then a call to a place the user never named

 BLAST RADIUS: CRITICAL
   rotate: aws_access_key_id, aws_secret_access_key
   block:  evil-collector.test
```

Add `--dashboard` for a clickable investigation view, or `--guard-replay` to see
where the guard would have stopped it. To try blocking live, put the proxy in
front of an MCP server:

```bash
taintline guard mcp-proxy --audit audit.jsonl -- your-mcp-server
```

## Feed it your own agent

The input is one JSON object per line: the system prompt, user messages, model
output, tool calls, tool results, memory reads and writes. Log that from your
agent and point taintline at the file. Already on OpenAI or OpenTelemetry? There
are adapters:

```bash
taintline analyze chat-log.json --format openai
taintline analyze spans.json   --format otel
```

The full format is in [docs/trace-format.md](docs/trace-format.md).

## What it does not do

- It reads logs. Influence that never produced a tool call or a logged output is
  invisible to it.
- The wording checks are plain, readable regexes. A smoothly paraphrased
  instruction with no trigger phrases can pass them. The behavioural checks
  (a credential read followed by a send to somewhere unfamiliar) and the guard
  still catch what it tries to do.
- It is a detection, prevention and forensics layer, not a replacement for input
  and output filtering or least-privilege tool design. Run it alongside them.

An evasion fuzzer in the repo attacks taintline's own detections so these edges
stay measured instead of assumed. See [docs/robustness.md](docs/robustness.md).

## Docs

- [architecture.md](docs/architecture.md) — how the taint engine works
- [guard.md](docs/guard.md) — runtime blocking, policies, the MCP proxy
- [forensics.md](docs/forensics.md) — indicators, STIX, evidence packs, CloudTrail
- [robustness.md](docs/robustness.md) — the evasion fuzzer and what each layer catches
- [rule-authoring.md](docs/rule-authoring.md) — write your own detections in YAML
- [trace-format.md](docs/trace-format.md) — the event schema and adapters
- [threat-model.md](docs/threat-model.md) — trust boundaries and scope

## License

MIT. Built by [Mohamed Reda Karrach](https://github.com/RedaKarrach). Every key,
address and name in the examples is made up.
