"""Runtime guard: decide on every tool call *before* it executes.

How a decision is made
----------------------
1. The pending call is built as a ``tool_call`` event.
2. ``SessionState.preview`` runs it through the taint engine as a what-if, with
   no side effects, yielding the flows the call would create.
3. The rule engine evaluates the hypothetical session *anchored* on the call,
   so only findings this call completes are considered.
4. The policy turns flows + findings (+ poisoned-tool and secret-fragment
   checks) into allow / log / require_approval / block.
5. Allowed calls are committed to the taint state. Blocked calls are recorded
   too (as attempts, marked ``meta.blocked``) because an attempted exfiltration
   is evidence, but they never count as data that left the boundary.

Every event the guard sees is appended to an audit trail as JSONL, flushed as
it is written (write-ahead), so the trail survives a crash and can be fed
straight back into ``taintline analyze`` for the forensic report.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import IO, Any
from urllib.parse import urlparse

from taintline.guard.policy import CallContext, Policy
from taintline.injection import find_secrets, score_injection
from taintline.rules.engine import RuleEngine, load_rules
from taintline.schema import Event, group_sessions
from taintline.taint import Flow, SessionState, TaintEngine
from taintline.textsim import destination_authorized, destinations
from taintline.toolclass import ToolClassifier

Approver = Callable[["Decision"], bool]


class ToolBlocked(RuntimeError):
    """Raised by ``GuardSession.call`` when the guard refuses a tool call."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"taintline guard blocked {decision.tool}: {decision.summary()}")


@dataclass
class Decision:
    event_id: str
    tool: str
    args: dict[str, Any]
    action: str  # what the policy decided: allow | log | require_approval | block
    enforced: str  # what actually happened: allow | log | block
    mode: str
    matched: list[tuple[str, str, str]] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    approved: bool | None = None
    allowlisted: str | None = None
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.enforced in ("allow", "log")

    def summary(self) -> str:
        """The deciding rule(s) and their reasons, deduplicated."""
        if self.allowlisted:
            return self.allowlisted
        if not self.matched:
            return "no policy rule matched"
        deciding = [m for m in self.matched if m[1] == self.action] or self.matched
        parts: list[str] = []
        seen: set[str] = set()
        for name, _, reason in deciding:
            fresh = [r for r in reason.split("; ") if r not in seen]
            seen.update(fresh)
            parts.append(f"[{name}] {'; '.join(fresh)}" if fresh else f"[{name}]")
        return " | ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tool": self.tool,
            "action": self.action,
            "enforced": self.enforced,
            "mode": self.mode,
            "approved": self.approved,
            "allowlisted": self.allowlisted,
            "matched": [{"rule": n, "action": a, "reason": r} for n, a, r in self.matched],
            "findings": [f.rule_id for f in self.findings],
            "flows": [f.to_dict() for f in self.flows],
            "latency_ms": round(self.latency_ms, 3),
        }


_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\((https?://[^)\s]+)\)", re.I)


@dataclass
class OutputScreen:
    """Result of screening model output before the user's client renders it."""

    event_id: str
    original: str
    text: str
    neutralized: list[str] = field(default_factory=list)  # beacon URLs removed
    redacted: list[str] = field(default_factory=list)  # secret kinds redacted

    @property
    def changed(self) -> bool:
        return bool(self.neutralized or self.redacted)

    def to_dict(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "neutralized": self.neutralized, "redacted": self.redacted}


class GuardSession:
    """One agent session under guard. Feed it what the agent sees, ask it before
    every tool call."""

    def __init__(self, guard: Guard, session_id: str, audit: IO[str] | None = None):
        self.guard = guard
        self.session_id = session_id
        self.state: SessionState = guard.engine.new_session(session_id)
        self.audit: list[Event] = []
        self.decisions: list[Decision] = []
        self.poisoned_tools: set[str] = set()
        self._audit_fh = audit
        self._seq = 0

    # ---------------------------------------------------------------- events
    def _event(self, kind: str, **kw: Any) -> Event:
        ev = Event(
            id=f"{self.session_id}:{self._seq:05d}",
            session_id=self.session_id,
            seq=self._seq,
            ts=datetime.now(timezone.utc).isoformat(),
            kind=kind,
            **kw,
        )
        self._seq += 1
        return ev

    def _record(self, ev: Event) -> None:
        self.audit.append(ev)
        if self._audit_fh is not None:
            self._audit_fh.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
            self._audit_fh.flush()

    def observe(self, kind: str, content: str = "", **kw: Any) -> Event:
        ev = self._event(kind, content=content, **kw)
        self.state.feed(ev)
        self._record(ev)
        if kind == "tool_registered" and ev.tool:
            inj = self.state.injection.get(ev.id)
            if inj and inj.score >= self.guard.policy.poisoned_tool_threshold:
                self.poisoned_tools.add(ev.tool.lower())
        return ev

    def system(self, text: str) -> Event:
        return self.observe("system_prompt", text)

    def user(self, text: str) -> Event:
        return self.observe("user_message", text)

    def model(self, text: str) -> Event:
        return self.observe("model_output", text)

    def register_tool(self, name: str, description: str, transport: str = "local") -> bool:
        """Record a tool advertisement. Returns True if the tool looks poisoned."""
        self.observe("tool_registered", description, tool=name, meta={"description": description, "transport": transport})
        return name.lower() in self.poisoned_tools

    def tool_result(self, tool: str, content: Any, call_id: str | None = None, meta: dict[str, Any] | None = None) -> Event:
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False, default=str)
        return self.observe("tool_result", text, tool=tool, call_id=call_id, meta=dict(meta or {}))

    # -------------------------------------------------------------- decisions
    def _secret_fragment(self, args_text: str) -> tuple[int, list[str]]:
        """Longest run of characters from a *matched* secret carried by the call."""
        best, kinds = 0, set()
        for p in self.state.payloads:
            if not p.secret_kinds:
                continue  # only payloads where an actual secret value was recognized
            _, positions = p.coverage(args_text)
            n = max((len(v) for v in positions.values()), default=0)
            if n:
                kinds.update(p.secret_kinds)
            best = max(best, n)
        return best, sorted(kinds)

    def check(self, tool: str, args: dict[str, Any] | None = None, call_id: str | None = None, meta: dict[str, Any] | None = None) -> Decision:
        """Decide on a pending tool call. Allowed calls are committed to the
        taint state; refused ones are recorded as blocked attempts."""
        t0 = time.perf_counter()
        args = dict(args or {})
        call_id = call_id or uuid.uuid4().hex[:12]
        ev = self._event("tool_call", tool=tool, args=args, call_id=call_id, meta=dict(meta or {}))
        flows, analysis = self.state.preview(ev)
        findings = self.guard.rules.evaluate(analysis, anchor=ev.id)
        info = analysis.infos.get(ev.id) or self.guard.engine.classifier.classify(ev)
        dests = destinations(ev.args_text)
        authorized, _ = destination_authorized(dests, self.state.principal_text)
        frag, frag_kinds = self._secret_fragment(ev.args_text)
        mem_score, mem_signals = 0.0, []
        if info.is_memory_write:
            value = args.get("value") or args.get("content") or args.get("text") or ""
            sc = score_injection(value if isinstance(value, str) else json.dumps(value, default=str))
            mem_score, mem_signals = sc.score, list(sc.signals)
        ctx = CallContext(
            tool=tool,
            info=info,
            destinations=dests,
            destination_authorized=authorized,
            flows=flows,
            findings=findings,
            poisoned_tool=tool.lower() in self.poisoned_tools,
            secret_fragment_chars=frag,
            secret_fragment_kinds=frag_kinds,
            memory_write_score=mem_score,
            memory_write_signals=mem_signals,
        )
        policy = self.guard.policy
        verdict = policy.decide(ctx)
        decision = Decision(
            event_id=ev.id,
            tool=tool,
            args=args,
            action=verdict.action,
            enforced=verdict.action if verdict.action != "require_approval" else "block",
            mode=policy.mode,
            matched=verdict.matched,
            findings=findings,
            flows=flows,
            allowlisted=verdict.allowlisted,
        )
        if verdict.action == "require_approval":
            if self.guard.approver is not None:
                decision.approved = bool(self.guard.approver(decision))
                decision.enforced = "allow" if decision.approved else "block"
            else:
                decision.enforced = "allow" if policy.on_approval_unavailable == "allow" else "block"
        if policy.mode == "monitor":
            decision.enforced = "allow" if verdict.action == "allow" else "log"

        ev.meta["guard"] = decision.to_dict()
        if decision.allowed:
            self.state.feed(ev)
            self._record(ev)
        else:
            ev.meta["blocked"] = True
            self.state.feed(ev)
            self._record(ev)
            note = self._event(
                "tool_result",
                tool=tool,
                call_id=call_id,
                content=f"BLOCKED by taintline guard: {decision.summary()}",
                meta={"blocked": True},
            )
            self.state.feed(note)
            self._record(note)
        decision.latency_ms = (time.perf_counter() - t0) * 1000.0
        ev.meta["guard"]["latency_ms"] = round(decision.latency_ms, 3)
        self.decisions.append(decision)
        return decision

    def screen_output(self, text: str) -> OutputScreen:
        """Screen model output before it is shown to the user.

        * Markdown images whose URL carries a query string to a host that is not
          allowlisted are neutralized: a client that renders the image would
          fetch it and leak the query string (the markdown-beacon exfiltration
          channel).
        * Recognized secrets are redacted.

        The original text is what gets recorded (it is what the model produced);
        ``OutputScreen.text`` is what the caller should display.
        """
        policy = self.guard.policy
        neutralized: list[str] = []
        redacted: list[str] = []
        clean = text

        if policy.neutralize_beacons:

            def _img(m: re.Match[str]) -> str:
                url = m.group(2)
                parsed = urlparse(url)
                host = parsed.hostname or ""
                if parsed.query and not policy.host_allowlisted(host):
                    neutralized.append(url)
                    return f"[image removed by taintline guard: {host}]"
                return m.group(0)

            clean = _MD_IMAGE.sub(_img, clean)

        if policy.redact_secrets:
            for hit in find_secrets(clean):
                clean = clean.replace(hit.value, f"[REDACTED {hit.kind}]")
                redacted.append(hit.kind)

        meta: dict[str, Any] = {}
        if neutralized or redacted:
            meta["guard_output"] = {"neutralized": neutralized, "redacted": redacted, "mode": policy.mode}
        ev = self.observe("model_output", text, meta=meta)
        shown = clean if policy.mode == "enforce" else text
        return OutputScreen(ev.id, text, shown, neutralized, redacted)

    def call(self, tool: str, args: dict[str, Any], fn: Callable[..., Any]) -> Any:
        """Check, execute ``fn(**args)`` if allowed, and record the result."""
        decision = self.check(tool, args)
        if not decision.allowed:
            raise ToolBlocked(decision)
        result = fn(**args)
        self.tool_result(tool, result, call_id=self.audit[-1].call_id)
        return result

    def wrap(self, tool: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Return a guarded version of ``fn`` for use in an agent's toolbox."""

        def guarded(**kwargs: Any) -> Any:
            return self.call(tool, kwargs, fn)

        guarded.__name__ = getattr(fn, "__name__", tool)
        guarded.__doc__ = getattr(fn, "__doc__", None)
        return guarded

    def analysis(self):
        return self.state.analysis()


class Guard:
    """Shared guard: one policy, one rule pack, one taint engine.

    Sessions created from the same Guard share the engine, so taint planted in
    agent memory in one session is still tracked when a later session reads it.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        rule_paths: list[str] | None = None,
        classifier: ToolClassifier | None = None,
        approver: Approver | None = None,
    ):
        self.policy = policy or Policy.default()
        self.engine = TaintEngine(classifier or ToolClassifier())
        self.rules = RuleEngine(load_rules(rule_paths))
        self.approver = approver

    def session(self, session_id: str | None = None, audit: IO[str] | None = None) -> GuardSession:
        return GuardSession(self, session_id or f"guard-{uuid.uuid4().hex[:8]}", audit=audit)


# ---------------------------------------------------------------------------
# Replay: "where would the guard have stopped this incident?"
# ---------------------------------------------------------------------------


@dataclass
class ReplayStep:
    event: Event
    decision: Decision | None = None  # tool calls and memory writes
    screen: OutputScreen | None = None  # model output

    @property
    def stopped(self) -> bool:
        if self.decision is not None:
            return not self.decision.allowed
        return bool(self.screen and self.screen.text != self.screen.original)


@dataclass
class ReplayResult:
    session_id: str
    steps: list[ReplayStep]
    first_block: int | None  # index into steps of the first stopped call

    @property
    def stopped(self) -> bool:
        return self.first_block is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "stopped": self.stopped,
            "first_block_event": self.steps[self.first_block].event.id if self.stopped else None,
            "decisions": [s.decision.to_dict() for s in self.steps if s.decision],
            "output_screens": [s.screen.to_dict() for s in self.steps if s.screen and s.screen.changed],
        }


def replay(events: list[Event], guard: Guard | None = None) -> list[ReplayResult]:
    """Replay recorded sessions through a guard as if it had been deployed.

    Tool calls are decided live. After the first enforced block the recorded
    history diverges from what would really have happened (the agent would have
    received a refusal), so the replay keeps evaluating later calls only to show
    what *else* the guard would have caught, flagged as post-divergence.
    """
    guard = guard or Guard()
    out: list[ReplayResult] = []
    for session in group_sessions(events):
        gs = guard.session(session.id)
        steps: list[ReplayStep] = []
        first_block: int | None = None
        skip_results: set[str] = set()
        for ev in session.events:
            if ev.kind == "tool_call":
                step = ReplayStep(ev, gs.check(ev.tool or "", ev.args, call_id=ev.call_id, meta={"replayed_from": ev.id}))
                if step.stopped and ev.call_id:
                    skip_results.add(ev.call_id)
            elif ev.kind == "memory_write":
                # a memory write is an action the guard can refuse
                value = ev.content or str(ev.args.get("value", ""))
                key = ev.args.get("key") or ev.meta.get("key") or "default"
                step = ReplayStep(
                    ev, gs.check(ev.tool or "memory_write", {"key": key, "value": value}, meta={"replayed_from": ev.id})
                )
            elif ev.kind == "model_output":
                step = ReplayStep(ev, screen=gs.screen_output(ev.content))
            elif ev.kind == "tool_result" and ev.call_id in skip_results:
                step = ReplayStep(ev)  # the call never ran, so its result never came back
            else:
                _replay_observe(gs, ev)
                step = ReplayStep(ev)
            if step.stopped and first_block is None:
                first_block = len(steps)
            steps.append(step)
        out.append(ReplayResult(session.id, steps, first_block))
    return out


def _replay_observe(gs: GuardSession, ev: Event) -> None:
    if ev.kind == "tool_registered":
        gs.register_tool(ev.tool or "", ev.meta.get("description") or ev.content, ev.meta.get("transport", "local"))
    elif ev.kind == "tool_result":
        gs.tool_result(ev.tool or "", ev.content, call_id=ev.call_id, meta=ev.meta)
    elif ev.kind == "memory_read":
        gs.observe(ev.kind, ev.content, tool=ev.tool, args=ev.args, meta=ev.meta)
    else:
        gs.observe(ev.kind, ev.content)

