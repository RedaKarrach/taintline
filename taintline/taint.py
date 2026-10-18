"""The taint engine: tracks untrusted influence and sensitive data through an
agent session and records flows into sensitive sinks.

Model of an agent turn
----------------------
Everything the model has seen so far is in its context. When an untrusted tool
result enters the context, every later model decision is *control-tainted* by
it (the attacker may have influenced the decision). When the arguments of a
later tool call lexically overlap the untrusted content, the call is
*data-tainted* (attacker text is literally flowing outward). Taint written to
memory becomes *stored* taint and re-enters the context in any later session
that reads that memory key.

Separately, the engine tracks *payloads*: results of credential/PII reads or
any content matching secret patterns. When a sink call contains a meaningful
fraction of a payload, that is a *data flow* (exfiltration). Partial overlaps
to the same sink class are accumulated so chunked exfiltration is caught.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from typing import Any

from taintline.injection import InjectionScore, SecretHit, find_secrets, score_injection
from taintline.normalize import payload_views
from taintline.schema import Event, Session
from taintline.textsim import (
    containment,
    covered_positions,
    destination_authorized,
    destinations,
    normalize,
    provenance,
)
from taintline.toolclass import EXFIL_SINKS, SINK_SEVERITY, ToolClassifier, ToolInfo

KIND_MULTIPLIER = {"data": 1.0, "control": 0.75, "stored": 0.9}


@dataclass(frozen=True)
class Taint:
    origin: str
    source_class: str
    score: float
    kind: str  # control | data | stored
    hops: int
    path: tuple[str, ...]
    signals: tuple[str, ...] = ()

    def confidence(self) -> float:
        base = max(self.score, 0.4 if self.kind == "data" else 0.0)
        mult = KIND_MULTIPLIER.get(self.kind, 0.75)
        return round(min(1.0, base * mult * (0.95 ** max(0, self.hops - 1))), 4)


@dataclass
class Payload:
    origin: str
    data_class: str  # credential | pii | secret_pattern
    text: str
    secret_kinds: tuple[str, ...]
    units: tuple[str, ...] = ()  # the sensitive strings whose leakage we track

    @classmethod
    def build(cls, origin: str, data_class: str, text: str, secrets: list[SecretHit]) -> Payload:
        if secrets:
            units = tuple(s.value for s in secrets)
        elif data_class:
            # no specific secret matched (e.g. a PII table); track the whole body
            units = (text,)
        else:
            units = ()
        return cls(
            origin=origin,
            data_class=data_class,
            text=text,
            secret_kinds=tuple(sorted({s.kind for s in secrets})),
            units=units,
        )

    def coverage(self, dst_text: str) -> tuple[float, dict[int, set[int]]]:
        """Best single-unit coverage fraction, plus per-unit covered positions.

        The destination is searched in its raw form and in the decodings an
        exfiltrating agent might apply (base64, hex, percent-encoding,
        reversal), so encoding a secret does not hide it."""
        best = 0.0
        positions: dict[int, set[int]] = {}
        views = payload_views(dst_text)
        for i, u in enumerate(self.units):
            norm_len = len(normalize(u))
            if norm_len == 0:
                continue
            pos: set[int] = set()
            for v in views:
                pos |= covered_positions(u, v)
            positions[i] = pos
            best = max(best, len(pos) / norm_len)
        return best, positions

    def unit_lengths(self) -> dict[int, int]:
        return {i: len(normalize(u)) for i, u in enumerate(self.units) if normalize(u)}


@dataclass
class Flow:
    kind: str  # taint_path | data_flow | chunked_data_flow
    source: str
    sink: str
    source_class: str
    sink_class: str
    sink_tool: str
    confidence: float
    path: tuple[str, ...]
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_weight(self) -> float:
        return SINK_SEVERITY.get(self.sink_class, 0.5)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source": self.source,
            "sink": self.sink,
            "source_class": self.source_class,
            "sink_class": self.sink_class,
            "sink_tool": self.sink_tool,
            "confidence": self.confidence,
            "path": list(self.path),
            "details": self.details,
        }


@dataclass
class SessionAnalysis:
    session: Session
    infos: dict[str, ToolInfo]
    taints: dict[str, list[Taint]]
    payloads: list[Payload]
    flows: list[Flow]
    injection: dict[str, InjectionScore]
    secrets: dict[str, list[SecretHit]]
    principal_text: str
    user_text: str = ""  # user_message content only (the live human request)
    memory_links: list[tuple[str, str]] = field(default_factory=list)  # (write_event, read_event)

    @property
    def events(self) -> list[Event]:
        return self.session.events

    def event(self, event_id: str) -> Event | None:
        return self.session.by_id(event_id)

    def info(self, event: Event) -> ToolInfo:
        return self.infos.get(event.id, ToolInfo(name=event.tool or ""))

    def max_taint_confidence(self, event_id: str) -> float:
        return max((t.confidence() for t in self.taints.get(event_id, [])), default=0.0)

    def sinks(self) -> list[Event]:
        return [e for e in self.events if e.kind == "tool_call" and self.info(e).is_sink]

    def sources(self) -> list[Event]:
        return [e for e in self.events if e.kind == "tool_result" and self.info(e).is_source]




@dataclass
class _ChunkState:
    covered: dict[int, set[int]] = field(default_factory=dict)  # unit index -> covered char positions
    sinks: list[str] = field(default_factory=list)
    single_hit: bool = False


class SessionState:
    """Incremental taint state for one session.

    ``feed(event)`` commits one event and returns the flows it created.
    ``preview(event)`` answers "what flows *would* this event create?" without
    changing any state (including the engine's cross-session memory). That
    what-if is what lets the runtime guard decide on a tool call *before* it
    executes.

    Authorization is causal: only principal messages that arrived *before* an
    action can authorize it.
    """

    def __init__(self, engine: TaintEngine, session_id: str):
        self.engine = engine
        self.session_id = session_id
        self.events: list[Event] = []
        self.infos: dict[str, ToolInfo] = {}
        self.taints: dict[str, list[Taint]] = {}
        self.payloads: list[Payload] = []
        self.flows: list[Flow] = []
        self.injection: dict[str, InjectionScore] = {}
        self.secrets: dict[str, list[SecretHit]] = {}
        self.memory_links: list[tuple[str, str]] = []
        self.chunks: dict[tuple[str, str], _ChunkState] = {}
        self.context: list[Taint] = []
        self.origin_text: dict[str, str] = {}
        self.principal_parts: list[str] = []
        self.user_parts: list[str] = []

    # ------------------------------------------------------------------ helpers
    @property
    def principal_text(self) -> str:
        return "\n".join(self.principal_parts)

    @property
    def user_text(self) -> str:
        return "\n".join(self.user_parts)

    def _origin_content(self, t: Taint) -> str:
        if t.origin in self.origin_text:
            return self.origin_text[t.origin]
        ev = self.engine.all_events.get(t.origin)
        return ev.text if ev else ""

    def _add_taint(self, ev: Event, t: Taint, text: str) -> None:
        self.origin_text[t.origin] = text
        self.context.append(t)
        self.taints.setdefault(ev.id, []).append(t)

    def _add_source(self, ev: Event, source_class: str, text: str, floor: float = 0.0) -> None:
        sc = score_injection(text)
        self.injection[ev.id] = sc
        score = max(sc.score, floor)
        if score <= 0.0:
            return
        self._add_taint(ev, Taint(ev.id, source_class, score, "control", 0, (ev.id,), sc.signals), text)

    def _add_payload(self, ev: Event, data_class: str, text: str) -> None:
        hits = find_secrets(text)
        self.secrets[ev.id] = hits
        if data_class or hits:
            self.payloads.append(Payload.build(ev.id, data_class or "secret_pattern", text, hits))

    @staticmethod
    def _memory_key(ev: Event) -> str:
        return str(ev.args.get("key") or ev.meta.get("key") or ev.args.get("name") or "default")

    def _memory_write(self, ev: Event, text: str) -> None:
        eng = self.engine
        key = self._memory_key(ev)
        sc = score_injection(text)
        self.injection[ev.id] = sc
        stored: list[Taint] = []
        for t in self.context:
            data = provenance(self._origin_content(t), text) >= eng.data_overlap_threshold
            if data or sc.score >= eng.min_source_score:
                stored.append(replace(t, kind="stored", path=t.path + (ev.id,)))
        if sc.score >= eng.min_source_score and not stored:
            stored.append(Taint(ev.id, "memory", sc.score, "stored", 0, (ev.id,), sc.signals))
            self.origin_text[ev.id] = text
        if stored:
            eng.memory_taints.setdefault(key, []).extend(stored)
            self.taints.setdefault(ev.id, []).extend(stored)
        hits = find_secrets(text)
        if hits:
            eng.memory_payloads.setdefault(key, []).append(Payload.build(ev.id, "secret_pattern", text, hits))
            self.secrets[ev.id] = hits
        eng.memory_writers[key] = ev.id

    def _memory_read(self, ev: Event, text: str) -> None:
        eng = self.engine
        key = self._memory_key(ev)
        for t in eng.memory_taints.get(key, []):
            revived = replace(t, kind="stored", hops=0, path=t.path + (ev.id,))
            self.context.append(revived)
            self.taints.setdefault(ev.id, []).append(revived)
        self.payloads.extend(eng.memory_payloads.get(key, []))
        if key in eng.memory_writers:
            self.memory_links.append((eng.memory_writers[key], ev.id))
        sc = score_injection(text)
        self.injection[ev.id] = sc
        if sc.score >= eng.min_source_score and not eng.memory_taints.get(key):
            self._add_taint(ev, Taint(ev.id, "memory", sc.score, "stored", 0, (ev.id,), sc.signals), text)

    def _cross(self, origin: str, ev: Event) -> bool:
        src = self.engine.all_events.get(origin)
        return bool(src and src.session_id != ev.session_id)

    def _sink(self, ev: Event, info: ToolInfo, call_taints: list[Taint]) -> None:
        eng = self.engine
        args_text = ev.args_text
        dests = destinations(args_text)
        authorized, auth_hits = destination_authorized(dests, self.principal_text)
        blocked = bool(ev.meta.get("blocked"))
        # 1) influence flows: untrusted content -> sink decision
        best: dict[str, Taint] = {}
        for t in call_taints:
            cur = best.get(t.origin)
            if cur is None or t.confidence() > cur.confidence():
                best[t.origin] = t
        for t in best.values():
            # A destination the principal named normally exonerates the call,
            # but not when the principal themselves is the taint source.
            auth_mult = 0.3 if (authorized and t.source_class != "user") else 1.0
            conf = round(t.confidence() * auth_mult, 4)
            if conf < eng.min_flow_confidence:
                continue
            self.flows.append(
                Flow(
                    kind="taint_path",
                    source=t.origin,
                    sink=ev.id,
                    source_class=t.source_class,
                    sink_class=info.sink_class or "",
                    sink_tool=info.name,
                    confidence=conf,
                    path=t.path + (ev.id,),
                    details={
                        "taint_kind": t.kind,
                        "hops": t.hops,
                        "injection_score": t.score,
                        "signals": list(t.signals),
                        "destinations": sorted(dests),
                        "destination_authorized": authorized,
                        "authorized_by": auth_hits,
                        "cross_session": self._cross(t.origin, ev),
                        "blocked": blocked,
                    },
                )
            )
        # 2) data flows: sensitive payload -> sink arguments
        for p in self.payloads:
            cov, positions = p.coverage(args_text)
            any_covered = any(pos for pos in positions.values())
            key = (p.origin, info.sink_class or "")
            state = self.chunks.setdefault(key, _ChunkState())
            if cov >= eng.payload_coverage_threshold:
                if not blocked:
                    state.single_hit = True
                conf = round(min(1.0, 0.5 + 0.5 * cov) * (0.5 if authorized else 1.0), 4)
                self.flows.append(
                    Flow(
                        kind="data_flow",
                        source=p.origin,
                        sink=ev.id,
                        source_class=p.data_class,
                        sink_class=info.sink_class or "",
                        sink_tool=info.name,
                        confidence=conf,
                        path=(p.origin, ev.id),
                        details={
                            "coverage": round(cov, 3),
                            "secret_kinds": list(p.secret_kinds),
                            "destinations": sorted(dests),
                            "destination_authorized": authorized,
                            "authorized_by": auth_hits,
                            "cross_session": self._cross(p.origin, ev),
                            "blocked": blocked,
                        },
                    )
                )
            elif any_covered and (info.sink_class in EXFIL_SINKS) and not blocked:
                # A blocked call never left the boundary, so it does not count
                # towards cumulative (chunked) leakage.
                for i, pos in positions.items():
                    if pos:
                        state.covered.setdefault(i, set()).update(pos)
                state.sinks.append(ev.id)
                lengths = p.unit_lengths()
                total = max((len(state.covered.get(i, set())) / lengths[i] for i in lengths), default=0.0)
                if not state.single_hit and len(state.sinks) >= eng.chunk_min_calls and total >= eng.chunk_coverage_threshold:
                    self.flows[:] = [
                        f
                        for f in self.flows
                        if not (f.kind == "chunked_data_flow" and f.source == p.origin and f.sink_class == key[1])
                    ]
                    self.flows.append(
                        Flow(
                            kind="chunked_data_flow",
                            source=p.origin,
                            sink=ev.id,
                            source_class=p.data_class,
                            sink_class=info.sink_class or "",
                            sink_tool=info.name,
                            confidence=round(min(1.0, 0.5 + 0.5 * total), 4),
                            path=(p.origin, *state.sinks),
                            details={
                                "cumulative_coverage": round(total, 3),
                                "calls": len(state.sinks),
                                "sink_events": list(state.sinks),
                                "secret_kinds": list(p.secret_kinds),
                                "destinations": sorted(dests),
                                "destination_authorized": authorized,
                                "blocked": False,
                            },
                        )
                    )

    # --------------------------------------------------------------- public API
    def feed(self, ev: Event) -> list[Flow]:
        """Commit one event. Returns the flows newly created by it."""
        eng = self.engine
        before = {id(f) for f in self.flows}
        eng.all_events[ev.id] = ev
        self.events.append(ev)
        info = eng.classifier.classify(ev) if ev.tool else ToolInfo(name="")
        self.infos[ev.id] = info

        if ev.kind == "system_prompt":
            self.principal_parts.append(ev.content)

        elif ev.kind == "tool_registered":
            eng.classifier.note_registration(ev)
            self._add_source(ev, "tool_schema", ev.text)

        elif ev.kind == "user_message":
            self.principal_parts.append(ev.content)
            self.user_parts.append(ev.content)
            sc = score_injection(ev.content)
            self.injection[ev.id] = sc
            if sc.score >= 0.5:  # direct jailbreak attempt by the principal
                self._add_taint(ev, Taint(ev.id, "user", sc.score, "control", 0, (ev.id,), sc.signals), ev.content)

        elif ev.kind == "tool_result":
            if ev.meta.get("blocked"):
                pass  # synthetic "blocked" result: carries no external content
            elif info.is_memory_read:
                self._memory_read(ev, ev.content)
            elif info.is_source or info.trust == "untrusted":
                self._add_source(ev, info.source_class or "untrusted_tool", ev.content, floor=0.1)
            else:
                self.injection[ev.id] = score_injection(ev.content)
                if self.injection[ev.id].score >= 0.5:
                    # a trusted tool returning instruction-like content is still worth tracking
                    self._add_source(ev, "trusted_tool", ev.content)
            if not ev.meta.get("blocked"):
                self._add_payload(ev, info.sensitive_class or "", ev.content)

        elif ev.kind == "memory_read":
            self._memory_read(ev, ev.content)

        elif ev.kind == "memory_write":
            self._memory_write(ev, ev.content or str(ev.args.get("value", "")))

        elif ev.kind == "model_output":
            # A model turn advances the hop count. Data-ness is NOT promoted
            # globally here: whether untrusted *content* actually flows is decided
            # per sink call from that call's own arguments.
            self.context = [replace(t, hops=t.hops + 1, path=t.path + (ev.id,)) for t in self.context]
            if self.context:
                self.taints[ev.id] = list(self.context)
            self.injection[ev.id] = score_injection(ev.content)
            hits = find_secrets(ev.content)
            if hits:
                self.secrets[ev.id] = hits

        elif ev.kind == "tool_call":
            args_text = ev.args_text
            call_taints: list[Taint] = []
            for t in self.context:
                kind = t.kind
                if kind != "data" and args_text:
                    src = self._origin_content(t)
                    if provenance(src, args_text) >= eng.data_overlap_threshold or containment(args_text, src) >= 0.6:
                        kind = "data"
                call_taints.append(replace(t, kind=kind))
            if call_taints:
                self.taints[ev.id] = call_taints
            if info.is_memory_write and not ev.meta.get("blocked"):
                self._memory_write(ev, str(ev.args.get("value") or ev.args.get("content") or ev.content))
            if info.is_sink:
                self._sink(ev, info, call_taints)

        return [f for f in self.flows if id(f) not in before]

    def preview(self, ev: Event) -> tuple[list[Flow], SessionAnalysis]:
        """What-if: the flows ``ev`` would create and the resulting analysis.
        All session and engine state is restored afterwards."""
        snap = self._snapshot()
        try:
            new_flows = self.feed(ev)
            return new_flows, self.analysis()
        finally:
            self._restore(snap)

    def analysis(self) -> SessionAnalysis:
        return SessionAnalysis(
            session=Session(id=self.session_id, events=list(self.events)),
            infos=dict(self.infos),
            taints={k: list(v) for k, v in self.taints.items()},
            payloads=list(self.payloads),
            flows=list(self.flows),
            injection=dict(self.injection),
            secrets=dict(self.secrets),
            principal_text=self.principal_text,
            user_text=self.user_text,
            memory_links=list(self.memory_links),
        )

    # --------------------------------------------------------- snapshot/restore
    def _snapshot(self) -> dict[str, Any]:
        eng = self.engine
        session_part = {k: copy.deepcopy(v) for k, v in self.__dict__.items() if k != "engine"}
        return {
            "session": session_part,
            "memory_taints": copy.deepcopy(eng.memory_taints),
            "memory_payloads": copy.deepcopy(eng.memory_payloads),
            "memory_writers": dict(eng.memory_writers),
            "all_events": dict(eng.all_events),
            "registered_remote": set(eng.classifier.registered_remote),
        }

    def _restore(self, snap: dict[str, Any]) -> None:
        eng = self.engine
        self.__dict__.update(snap["session"])
        eng.memory_taints = snap["memory_taints"]
        eng.memory_payloads = snap["memory_payloads"]
        eng.memory_writers = snap["memory_writers"]
        eng.all_events = snap["all_events"]
        eng.classifier.registered_remote = snap["registered_remote"]


class TaintEngine:
    def __init__(
        self,
        classifier: ToolClassifier | None = None,
        min_source_score: float = 0.3,
        min_flow_confidence: float = 0.2,
        data_overlap_threshold: float = 0.15,
        payload_coverage_threshold: float = 0.3,
        chunk_coverage_threshold: float = 0.5,
        chunk_min_calls: int = 3,
    ):
        self.classifier = classifier or ToolClassifier()
        self.min_source_score = min_source_score
        self.min_flow_confidence = min_flow_confidence
        self.data_overlap_threshold = data_overlap_threshold
        self.payload_coverage_threshold = payload_coverage_threshold
        self.chunk_coverage_threshold = chunk_coverage_threshold
        self.chunk_min_calls = chunk_min_calls
        # state that persists across sessions (memory is the agent's long-term store)
        self.memory_taints: dict[str, list[Taint]] = {}
        self.memory_payloads: dict[str, list[Payload]] = {}
        self.memory_writers: dict[str, str] = {}
        self.all_events: dict[str, Event] = {}

    def new_session(self, session_id: str) -> SessionState:
        """Start incremental (streaming) analysis of a session."""
        return SessionState(self, session_id)

    def analyze(self, session: Session) -> SessionAnalysis:
        state = self.new_session(session.id)
        for ev in session.events:
            state.feed(ev)
        return state.analysis()

    def analyze_sessions(self, sessions: list[Session]) -> list[SessionAnalysis]:
        return [self.analyze(s) for s in sessions]
