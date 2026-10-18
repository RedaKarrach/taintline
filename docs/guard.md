# Runtime guard

The guard turns taintline from a post-hoc analyzer into a **preventive control**:
it decides on every agent tool call *before* it executes, using the same taint
engine and rule pack, and can allow, log, hold for approval, or block.

## How a decision is made

1. The pending call becomes a `tool_call` event.
2. `SessionState.preview` runs it through the taint engine as a **what-if** (no
   side effects, including no change to cross-session memory), yielding the flows
   the call *would* create.
3. The rule engine evaluates the hypothetical session **anchored** on the call,
   so only findings this specific call completes are considered.
4. The policy turns flows + findings + poisoned-tool and secret-fragment checks
   into `allow` / `log` / `require_approval` / `block`.
5. Allowed calls are committed to the taint state. Blocked calls are recorded as
   attempts (`meta.blocked`) — an attempted exfiltration is evidence — but never
   counted as data that actually left, so they don't advance chunked-leak state.

Authorization is **causal**: only principal messages that arrived *before* a call
can authorize its destination. A jailbroken user naming their own drop point does
not authorize it.

## Policy

A policy is ordered YAML rules; the strongest matching action wins
(block > require_approval > log > allow); allowlists override everything. The
built-in policy (`taintline/guard/default_policy.yaml`) blocks poisoned tools,
memory poisoning, secret-fragment egress to unauthorized destinations, and any
critical finding; holds high-severity findings for approval; and screens model
output (neutralizes markdown beacons, redacts secrets). See it with:

```bash
taintline guard policy
```

Run in **monitor mode** first (`mode: monitor`, or `--monitor`): it never
interferes, only records what it *would* have done — the safe way to roll out.

## Using it

**SDK, in your agent loop:**

```python
from taintline.guard import Guard, ToolBlocked

guard = Guard()                      # one shared taint engine across sessions
s = guard.session("user-42")
s.system("You are a helpful assistant.")
s.user("Summarize https://example.com/x")

# option A: check, then run yourself
d = s.check("web_fetch", {"url": "https://example.com/x"})
if d.allowed:
    s.tool_result("web_fetch", fetch(...))

# option B: let the guard wrap the call (raises ToolBlocked if refused)
post = s.wrap("http_post", real_http_post)
post(url=..., body=...)

# screen model output before showing it to the user
shown = s.screen_output(model_reply).text
```

**MCP proxy, no code changes to the agent:** front any MCP stdio server. In your
MCP client config:

```json
{
  "command": "taintline",
  "args": ["guard", "mcp-proxy", "--audit", "audit.jsonl", "--",
           "npx", "-y", "@modelcontextprotocol/server-fetch"]
}
```

The proxy strips poisoned tools from `tools/list`, blocks dangerous
`tools/call`s (returning a tool-level error the model can recover from), tracks
results as taint, and writes an audit trail you can feed back into
`taintline analyze`.

**Incident replay** — where would the guard have stopped a past incident?

```bash
taintline guard replay incident.jsonl
```

It prints the event-by-event verdict and the first call it would have blocked.
On the bundled scenarios the guard stops every attack (chunked exfil at the
*first* chunk) and touches none of the benign sessions.

## Latency

The preview + anchored evaluation runs in single-digit milliseconds per call on
the synthetic scenarios, so the guard is viable inline. It is CPU-only and
deterministic.
