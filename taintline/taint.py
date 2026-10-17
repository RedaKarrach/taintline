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

from dataclasses import dataclass, field, replace
from typing import Any

from taintline.injection import InjectionScore, SecretHit, find_secrets, score_injection
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
        """Best single-unit coverage fraction, plus per-unit covered positions."""
        best = 0.0
        positions: dict[int, set[int]] = {}
        for i, u in enumerate(self.units):
            norm_len = len(normalize(u))
            if norm_len == 0:
                continue
            pos = covered_positions(u, dst_text)
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

    # ------------------------------------------------------------------
    def analyze_sessions(self, sessions: list[Session]) -> list[SessionAnalysis]:
        return [self.analyze(s) for s in sessions]

    def analyze(self, session: Session) -> SessionAnalysis:
        for e in session.events:
            self.all_events[e.id] = e

        infos: dict[str, ToolInfo] = {}
        taints: dict[str, list[Taint]] = {}
        payloads: list[Payload] = []
        flows: list[Flow] = []
        injection: dict[str, InjectionScore] = {}
        secrets: dict[str, list[SecretHit]] = {}
        memory_links: list[tuple[str, str]] = []
        chunks: dict[tuple[str, str], _ChunkState] = {}
        context: list[Taint] = []
        principal_parts = [e.content for e in session.events if e.kind in ("user_message", "system_prompt")]
        principal_text = "\n".join(principal_parts)
        user_text = "\n".join(e.content for e in session.events if e.kind == "user_message")
        origin_text: dict[str, str] = {}

        def origin_content(t: Taint) -> str:
            if t.origin in origin_text:
                return origin_text[t.origin]
            ev = self.all_events.get(t.origin)
            return ev.text if ev else ""

        def add_source(ev: Event, source_class: str, text: str, floor: float = 0.0) -> None:
            sc = score_injection(text)
            injection[ev.id] = sc
            score = max(sc.score, floor)
            if score <= 0.0:
                return
            t = Taint(ev.id, source_class, score, "control", 0, (ev.id,), sc.signals)
            origin_text[ev.id] = text
            context.append(t)
            taints.setdefault(ev.id, []).append(t)

        def add_payload(ev: Event, data_class: str, text: str) -> None:
            hits = find_secrets(text)
            secrets[ev.id] = hits
            if data_class or hits:
                payloads.append(Payload.build(ev.id, data_class or "secret_pattern", text, hits))

        def memory_key(ev: Event) -> str:
            return str(ev.args.get("key") or ev.meta.get("key") or ev.args.get("name") or "default")

        def handle_memory_write(ev: Event, text: str) -> None:
            key = memory_key(ev)
            sc = score_injection(text)
            injection[ev.id] = sc
            stored: list[Taint] = []
            for t in context:
                data = provenance(origin_content(t), text) >= self.data_overlap_threshold
                if data or sc.score >= self.min_source_score:
                    stored.append(replace(t, kind="stored", path=t.path + (ev.id,)))
            if sc.score >= self.min_source_score and not stored:
                stored.append(Taint(ev.id, "memory", sc.score, "stored", 0, (ev.id,), sc.signals))
                origin_text[ev.id] = text
            if stored:
                self.memory_taints.setdefault(key, []).extend(stored)
                taints.setdefault(ev.id, []).extend(stored)
            hits = find_secrets(text)
            if hits:
                self.memory_payloads.setdefault(key, []).append(Payload.build(ev.id, "secret_pattern", text, hits))
                secrets[ev.id] = hits
            self.memory_writers[key] = ev.id

        def handle_memory_read(ev: Event, text: str) -> None:
            key = memory_key(ev)
            for t in self.memory_taints.get(key, []):
                revived = replace(t, kind="stored", hops=0, path=t.path + (ev.id,))
                context.append(revived)
                taints.setdefault(ev.id, []).append(revived)
            for p in self.memory_payloads.get(key, []):
                payloads.append(p)
            if key in self.memory_writers:
                memory_links.append((self.memory_writers[key], ev.id))
            # Freshly read memory may itself contain instructions not seen before.
            sc = score_injection(text)
            injection[ev.id] = sc
            if sc.score >= self.min_source_score and not self.memory_taints.get(key):
                t = Taint(ev.id, "memory", sc.score, "stored", 0, (ev.id,), sc.signals)
                origin_text[ev.id] = text
                context.append(t)
                taints.setdefault(ev.id, []).append(t)

        def handle_sink(ev: Event, info: ToolInfo, call_taints: list[Taint]) -> None:
            args_text = ev.args_text
            dests = destinations(args_text)
            authorized, auth_hits = destination_authorized(dests, principal_text)
            # 1) influence flows: untrusted content -> sink decision
            best: dict[str, Taint] = {}
            for t in call_taints:
                cur = best.get(t.origin)
                if cur is None or t.confidence() > cur.confidence():
                    best[t.origin] = t
            for t in best.values():
                # A destination the principal named normally exonerates the call,
                # but not when the principal themselves is the taint source
                # (a jailbroken / compromised account naming its own drop point).
                auth_mult = 0.3 if (authorized and t.source_class != "user") else 1.0
                conf = round(t.confidence() * auth_mult, 4)
                if conf < self.min_flow_confidence:
                    continue
                flows.append(
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
                            "cross_session": self.all_events.get(t.origin, ev).session_id != ev.session_id,
                        },
                    )
                )
            # 2) data flows: sensitive payload -> sink arguments
            for p in payloads:
                cov, positions = p.coverage(args_text)
                any_covered = any(pos for pos in positions.values())
                key = (p.origin, info.sink_class or "")
                state = chunks.setdefault(key, _ChunkState())
                if cov >= self.payload_coverage_threshold:
                    state.single_hit = True
                    conf = round(min(1.0, 0.5 + 0.5 * cov) * (0.5 if authorized else 1.0), 4)
                    flows.append(
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
                                "cross_session": self.all_events.get(p.origin, ev).session_id != ev.session_id,
                            },
                        )
                    )
                elif any_covered and (info.sink_class in EXFIL_SINKS):
                    for i, pos in positions.items():
                        if pos:
                            state.covered.setdefault(i, set()).update(pos)
                    state.sinks.append(ev.id)
                    lengths = p.unit_lengths()
                    total = max((len(state.covered.get(i, set())) / lengths[i] for i in lengths), default=0.0)
                    if (
                        not state.single_hit
                        and len(state.sinks) >= self.chunk_min_calls
                        and total >= self.chunk_coverage_threshold
                    ):
                        # replace any earlier chunked flow for this key with the updated one
                        flows[:] = [
                            f
                            for f in flows
                            if not (f.kind == "chunked_data_flow" and f.source == p.origin and f.sink_class == key[1])
                        ]
                        flows.append(
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
                                },
                            )
                        )

        # ------------------------------------------------------------------
        for ev in session.events:
            info = self.classifier.classify(ev) if ev.tool else ToolInfo(name="")
            infos[ev.id] = info

            if ev.kind == "tool_registered":
                self.classifier.note_registration(ev)
                add_source(ev, "tool_schema", ev.text)

            elif ev.kind == "user_message":
                sc = score_injection(ev.content)
                injection[ev.id] = sc
                if sc.score >= 0.5:  # direct jailbreak attempt by the principal
                    t = Taint(ev.id, "user", sc.score, "control", 0, (ev.id,), sc.signals)
                    origin_text[ev.id] = ev.content
                    context.append(t)
                    taints.setdefault(ev.id, []).append(t)

            elif ev.kind == "tool_result":
                if info.is_memory_read:
                    handle_memory_read(ev, ev.content)
                elif info.is_source or info.trust == "untrusted":
                    add_source(ev, info.source_class or "untrusted_tool", ev.content, floor=0.1)
                else:
                    injection[ev.id] = score_injection(ev.content)
                    if injection[ev.id].score >= 0.5:
                        # a trusted tool returning instruction-like content is still worth tracking
                        add_source(ev, "trusted_tool", ev.content)
                add_payload(ev, info.sensitive_class or "", ev.content)

            elif ev.kind == "memory_read":
                handle_memory_read(ev, ev.content)

            elif ev.kind == "memory_write":
                handle_memory_write(ev, ev.content or str(ev.args.get("value", "")))

            elif ev.kind == "model_output":
                # A model turn advances the hop count (the attacker's influence is
                # now one reasoning step further from its origin). Data-ness is NOT
                # promoted globally here: whether untrusted *content* actually flows
                # is decided per sink call from that call's own arguments, so a
                # model merely restating a benign source does not taint later,
                # unrelated calls.
                context = [replace(t, hops=t.hops + 1, path=t.path + (ev.id,)) for t in context]
                if context:
                    taints[ev.id] = list(context)
                sc = score_injection(ev.content)
                injection[ev.id] = sc
                hits = find_secrets(ev.content)
                if hits:
                    secrets[ev.id] = hits

            elif ev.kind == "tool_call":
                args_text = ev.args_text
                call_taints: list[Taint] = []
                for t in context:
                    kind = t.kind
                    if kind != "data" and args_text:
                        src = origin_content(t)
                        if provenance(src, args_text) >= self.data_overlap_threshold or containment(args_text, src) >= 0.6:
                            kind = "data"
                    call_taints.append(replace(t, kind=kind))
                if call_taints:
                    taints[ev.id] = call_taints
                if info.is_memory_write:
                    handle_memory_write(ev, str(ev.args.get("value") or ev.args.get("content") or ev.content))
                if info.is_sink:
                    handle_sink(ev, info, call_taints)

        return SessionAnalysis(
            session=session,
            infos=infos,
            taints=taints,
            payloads=payloads,
            flows=flows,
            injection=injection,
            secrets=secrets,
            principal_text=principal_text,
            user_text=user_text,
            memory_links=memory_links,
        )
