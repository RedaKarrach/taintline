"""YAML rule engine evaluated over a :class:`SessionAnalysis`.

Rules are declarative, Sigma-like documents. The ``match`` block selects one
condition type:

taint_path        an influence flow from an untrusted source class to a sink class
data_flow         a sensitive payload leaking into a sink's arguments
sequence          ordered tool-class steps within a window of events
frequency         a tool class invoked at least N times inside a sliding window
loop              the same tool invoked with identical arguments N times in a row
content           regex / injection-score / secret checks on event text
schema_injection  a registered tool description that carries injection signals
unprompted_sink   a sink class used although the principal never asked for it

See ``docs/rule-authoring.md`` for the full grammar.
"""

from __future__ import annotations

import fnmatch
import glob
import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from taintline.schema import Event
from taintline.taint import Flow, SessionAnalysis
from taintline.toolclass import EXFIL_SINKS, ToolInfo

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
BUILTIN_DIR = os.path.join(os.path.dirname(__file__), "builtin")


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    match: dict[str, Any]
    description: str = ""
    mappings: dict[str, list[str]] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    enabled: bool = True
    source_file: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any], source_file: str = "") -> Rule:
        for key in ("id", "title", "severity", "match"):
            if key not in d:
                raise RuleError(f"{source_file or '<rule>'}: missing required key {key!r}")
        if d["severity"] not in SEVERITY_RANK:
            raise RuleError(f"{d['id']}: invalid severity {d['severity']!r}")
        if not isinstance(d["match"], dict) or "type" not in d["match"]:
            raise RuleError(f"{d['id']}: match must be a mapping with a 'type'")
        if d["match"]["type"] not in _MATCHERS:
            raise RuleError(f"{d['id']}: unknown match type {d['match']['type']!r}")
        # YAML 1.1 parses a bare `on:` key as boolean True; require the quoted
        # or renamed form so content rules do not silently target the wrong kind.
        if True in d["match"] or "on" in d["match"]:
            raise RuleError(f"{d['id']}: use 'on_kind' (a bare 'on:' is parsed as boolean True by YAML)")
        return cls(
            id=str(d["id"]),
            title=str(d["title"]),
            severity=str(d["severity"]),
            match=dict(d["match"]),
            description=str(d.get("description", "")).strip(),
            mappings={k: list(v) for k, v in (d.get("mappings") or {}).items()},
            tags=list(d.get("tags") or []),
            references=list(d.get("references") or []),
            enabled=bool(d.get("enabled", True)),
            source_file=source_file,
        )


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    session_id: str
    events: list[str]
    confidence: float
    evidence: dict[str, Any]
    mappings: dict[str, list[str]]
    description: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "session_id": self.session_id,
            "events": self.events,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "mappings": self.mappings,
            "description": self.description,
            "tags": self.tags,
        }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return [str(x) for x in v]


def _class_matches(wanted: list[str], info: ToolInfo, event: Event) -> bool:
    if not wanted or "*" in wanted:
        return True
    have = {info.source_class, info.sink_class, info.sensitive_class}
    if info.is_file_read:
        have.add("file_read")
    if info.is_memory_write or event.kind == "memory_write":
        have.add("memory_write")
    if info.is_memory_read or event.kind == "memory_read":
        have.add("memory_read")
    if info.is_sink:
        have.add("any_sink")
    if info.is_source:
        have.add("any_source")
    if info.sink_class in EXFIL_SINKS:
        have.add("any_exfil")
    return any(w in have for w in wanted)


def _tool_matches(patterns: list[str], event: Event) -> bool:
    if not patterns:
        return True
    name = (event.tool or "").lower()
    return any(fnmatch.fnmatchcase(name, p.lower()) for p in patterns)


def _step_matches(step: dict[str, Any], event: Event, a: SessionAnalysis) -> bool:
    if event.kind not in _as_list(step.get("kind") or ["tool_call"]):
        return False
    info = a.info(event)
    if not _class_matches(_as_list(step.get("tool_class")), info, event):
        return False
    if not _tool_matches(_as_list(step.get("tool")), event):
        return False
    rx = step.get("args_regex")
    if rx and not re.search(rx, event.args_text, re.I | re.S):
        return False
    min_taint = float(step.get("min_taint", 0.0))
    if min_taint and a.max_taint_confidence(event.id) < min_taint:
        return False
    return True


def _principal_authorizes(match: dict[str, Any], a: SessionAnalysis) -> bool:
    """True when the principal's own messages explicitly authorize this action
    class (via ``unless_principal_regex``), so the rule should stand down."""
    rx = match.get("unless_principal_regex")
    return bool(rx and re.search(rx, a.user_text, re.I))


def _flow_evidence(f: Flow, a: SessionAnalysis) -> dict[str, Any]:
    src = a.event(f.source)
    sink = a.event(f.sink)
    return {
        "flow": f.to_dict(),
        "source_excerpt": src.short(200) if src else "(earlier session)",
        "sink_excerpt": sink.short(200) if sink else "",
    }


# ---------------------------------------------------------------------------
# matchers: each returns a list of Finding
# ---------------------------------------------------------------------------


def _flow_touches(f: Flow, anchor: str | None) -> bool:
    """Anchored evaluation: a flow counts when the anchor is its sink or part of
    its sink chain (chunked flows list every contributing call)."""
    if anchor is None:
        return True
    return f.sink == anchor or anchor in f.details.get("sink_events", ())


def _m_taint_path(rule: Rule, a: SessionAnalysis, anchor: str | None = None) -> list[Finding]:
    m = rule.match
    sources = _as_list(m.get("source_class"))
    sinks = _as_list(m.get("sink_class"))
    min_conf = float(m.get("min_confidence", 0.3))
    min_src_inj = float(m.get("min_source_injection", 0.0))
    kinds = _as_list(m.get("taint_kind"))
    out = []
    for f in a.flows:
        if f.kind != "taint_path" or not _flow_touches(f, anchor):
            continue
        if min_src_inj and float(f.details.get("injection_score", 0.0)) < min_src_inj:
            continue
        if sources and "*" not in sources and f.source_class not in sources:
            continue
        if sinks and "*" not in sinks:
            if "any_exfil" in sinks and f.sink_class in EXFIL_SINKS:
                pass
            elif f.sink_class not in sinks:
                continue
        if f.confidence < min_conf:
            continue
        if kinds and f.details.get("taint_kind") not in kinds:
            continue
        if m.get("require_unauthorized_destination") and f.details.get("destination_authorized"):
            continue
        if "cross_session" in m and bool(m["cross_session"]) != bool(f.details.get("cross_session")):
            continue
        out.append(_finding(rule, a, list(f.path), f.confidence, _flow_evidence(f, a)))
    return out


def _m_data_flow(rule: Rule, a: SessionAnalysis, anchor: str | None = None) -> list[Finding]:
    m = rule.match
    classes = _as_list(m.get("data_class"))
    sinks = _as_list(m.get("sink_class"))
    min_cov = float(m.get("min_coverage", 0.0))
    chunked = m.get("chunked")
    out = []
    for f in a.flows:
        if f.kind not in ("data_flow", "chunked_data_flow") or not _flow_touches(f, anchor):
            continue
        if chunked is True and f.kind != "chunked_data_flow":
            continue
        if chunked is False and f.kind != "data_flow":
            continue
        if classes and "*" not in classes and f.source_class not in classes:
            continue
        if sinks and "*" not in sinks:
            if "any_exfil" in sinks and f.sink_class in EXFIL_SINKS:
                pass
            elif f.sink_class not in sinks:
                continue
        cov = f.details.get("coverage", f.details.get("cumulative_coverage", 0.0))
        if cov < min_cov:
            continue
        if m.get("require_unauthorized_destination") and f.details.get("destination_authorized"):
            continue
        out.append(_finding(rule, a, list(f.path), f.confidence, _flow_evidence(f, a)))
    return out


def _last_step_unauthorized(m: dict[str, Any], a: SessionAnalysis, last: Event) -> bool:
    if not m.get("require_unauthorized_destination"):
        return True
    from taintline.textsim import destination_authorized, destinations

    if any(f.details.get("destination_authorized") for f in a.flows if f.sink == last.id):
        return False
    auth, _ = destination_authorized(destinations(last.args_text), a.principal_text)
    return not auth


def _sequence_finding(rule: Rule, a: SessionAnalysis, matched: list[str]) -> Finding:
    last = a.event(matched[-1])
    conf = max(0.5, a.max_taint_confidence(last.id)) if last else 0.5
    return _finding(
        rule,
        a,
        matched,
        round(conf, 3),
        {"steps": [{"event": eid, "excerpt": (a.event(eid).short(160) if a.event(eid) else "")} for eid in matched]},
    )


def _m_sequence(rule: Rule, a: SessionAnalysis, anchor: str | None = None) -> list[Finding]:
    m = rule.match
    if _principal_authorizes(m, a):
        return []
    steps = m.get("steps") or []
    if len(steps) < 2:
        raise RuleError(f"{rule.id}: sequence needs at least two steps")
    within = int(m.get("within", 10))
    events = a.events

    if anchor is not None:
        # The anchor must be the final step; find the tightest chain ending there.
        idx = next((k for k, e in enumerate(events) if e.id == anchor), None)
        if idx is None or not _step_matches(steps[-1], events[idx], a):
            return []
        if not _last_step_unauthorized(m, a, events[idx]):
            return []
        for i in range(idx - 1, max(-1, idx - within - 1), -1):
            if not _step_matches(steps[0], events[i], a):
                continue
            matched = [events[i].id]
            pos = i
            ok = True
            for step in steps[1:-1]:
                found = next((j for j in range(pos + 1, idx) if _step_matches(step, events[j], a)), None)
                if found is None:
                    ok = False
                    break
                matched.append(events[found].id)
                pos = found
            if ok:
                return [_sequence_finding(rule, a, matched + [anchor])]
        return []

    for i, first in enumerate(events):
        if not _step_matches(steps[0], first, a):
            continue
        matched = [first.id]
        pos = i
        ok = True
        for step in steps[1:]:
            found = None
            for j in range(pos + 1, min(len(events), i + within + 1)):
                if _step_matches(step, events[j], a):
                    found = j
                    break
            if found is None:
                ok = False
                break
            matched.append(events[found].id)
            pos = found
        if not ok or not _last_step_unauthorized(m, a, events[pos]):
            continue
        # report one chain per session; anchored mode handles later chains
        return [_sequence_finding(rule, a, matched)]
    return []


def _m_frequency(rule: Rule, a: SessionAnalysis, anchor: str | None = None) -> list[Finding]:
    m = rule.match
    if _principal_authorizes(m, a):
        return []
    classes = _as_list(m.get("tool_class"))
    tools = _as_list(m.get("tool"))
    kinds = _as_list(m.get("kind") or ["tool_call"])
    min_count = int(m.get("min_count", 5))
    window = int(m.get("window", 20))
    hits = [
        e for e in a.events if e.kind in kinds and _class_matches(classes, a.info(e), e) and _tool_matches(tools, e)
    ]
    if len(hits) < min_count:
        return []

    def burst_finding(burst: list[Event]) -> Finding:
        return _finding(
            rule,
            a,
            [h.id for h in burst],
            0.8,
            {"count": len(burst), "window": window, "tools": sorted({h.tool or "" for h in burst})},
        )

    if anchor is not None:
        last = next((h for h in hits if h.id == anchor), None)
        if last is None:
            return []
        burst = [h for h in hits if last.seq - window <= h.seq <= last.seq]
        return [burst_finding(burst)] if len(burst) >= min_count else []

    for i in range(len(hits) - min_count + 1):
        span = hits[i + min_count - 1].seq - hits[i].seq
        if span <= window:
            return [burst_finding([h for h in hits if hits[i].seq <= h.seq <= hits[i].seq + window])]
    return []


def _m_loop(rule: Rule, a: SessionAnalysis, anchor: str | None = None) -> list[Finding]:
    m = rule.match
    min_repeats = int(m.get("min_repeats", 4))
    classes = _as_list(m.get("tool_class"))
    calls = [e for e in a.events if e.kind == "tool_call" and _class_matches(classes, a.info(e), e)]
    run: list[Event] = []
    best: list[Event] = []
    for e in calls:
        if run and (e.tool, e.args_text) == (run[-1].tool, run[-1].args_text):
            run.append(e)
        else:
            run = [e]
        if anchor is not None:
            if e.id == anchor:
                best = list(run)
                break
        elif len(run) > len(best):
            best = list(run)
    if len(best) >= min_repeats:
        return [_finding(rule, a, [e.id for e in best], 0.7, {"repeats": len(best), "tool": best[0].tool, "args": best[0].args})]
    return []


def _m_content(rule: Rule, a: SessionAnalysis, anchor: str | None = None) -> list[Finding]:
    m = rule.match
    kinds = _as_list(m.get("on_kind") or ["model_output"])
    rx = re.compile(m["regex"], re.I | re.S) if m.get("regex") else None
    min_inj = float(m.get("min_injection_score", 0.0))
    want_secret = bool(m.get("secret_present", False))
    classes = _as_list(m.get("tool_class"))
    min_taint = float(m.get("min_taint", 0.0))
    out = []
    for e in a.events:
        if anchor is not None and e.id != anchor:
            continue
        if e.kind not in kinds:
            continue
        if classes and not _class_matches(classes, a.info(e), e):
            continue
        text = e.text
        if rx and not rx.search(text):
            continue
        inj = a.injection.get(e.id)
        if min_inj and (inj is None or inj.score < min_inj):
            continue
        if want_secret and not a.secrets.get(e.id):
            continue
        if min_taint and a.max_taint_confidence(e.id) < min_taint:
            continue
        conf = max(inj.score if inj else 0.0, a.max_taint_confidence(e.id), 0.5)
        ev: dict[str, Any] = {"excerpt": e.short(200)}
        if inj:
            ev["injection"] = inj.as_dict()
        if a.secrets.get(e.id):
            ev["secrets"] = [{"kind": s.kind, "value": s.redacted()} for s in a.secrets[e.id]]
        out.append(_finding(rule, a, [e.id], round(conf, 3), ev))
    return out


def _m_schema_injection(rule: Rule, a: SessionAnalysis, anchor: str | None = None) -> list[Finding]:
    min_score = float(rule.match.get("min_injection_score", 0.3))
    out = []
    for e in a.events:
        if e.kind != "tool_registered" or (anchor is not None and e.id != anchor):
            continue
        inj = a.injection.get(e.id)
        if inj and inj.score >= min_score:
            out.append(
                _finding(
                    rule,
                    a,
                    [e.id],
                    inj.score,
                    {"tool": e.tool, "transport": e.meta.get("transport", "local"), "injection": inj.as_dict(), "description_excerpt": e.short(240)},
                )
            )
    return out


def _m_unprompted_sink(rule: Rule, a: SessionAnalysis, anchor: str | None = None) -> list[Finding]:
    from taintline.textsim import destination_authorized, destinations

    m = rule.match
    classes = _as_list(m.get("sink_class"))
    principal_rx = re.compile(m["principal_regex"], re.I) if m.get("principal_regex") else None
    if principal_rx and principal_rx.search(a.principal_text):
        return []
    out = []
    for e in a.events:
        if e.kind != "tool_call" or (anchor is not None and e.id != anchor):
            continue
        info = a.info(e)
        if not info.is_sink or not _class_matches(classes, info, e):
            continue
        dests = destinations(e.args_text)
        auth, _ = destination_authorized(dests, a.principal_text)
        if auth:
            continue
        out.append(_finding(rule, a, [e.id], 0.5, {"tool": e.tool, "args": e.args, "destinations": sorted(dests)}))
    return out


_MATCHERS = {
    "taint_path": _m_taint_path,
    "data_flow": _m_data_flow,
    "sequence": _m_sequence,
    "frequency": _m_frequency,
    "loop": _m_loop,
    "content": _m_content,
    "schema_injection": _m_schema_injection,
    "unprompted_sink": _m_unprompted_sink,
}


def _finding(rule: Rule, a: SessionAnalysis, events: list[str], confidence: float, evidence: dict[str, Any]) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        session_id=a.session.id,
        events=events,
        confidence=round(float(confidence), 3),
        evidence=evidence,
        mappings=rule.mappings,
        description=rule.description,
        tags=rule.tags,
    )


# ---------------------------------------------------------------------------
# loading & evaluation
# ---------------------------------------------------------------------------


def load_rules(paths: list[str] | None = None, include_builtin: bool = True) -> list[Rule]:
    files: list[str] = []
    if include_builtin:
        files.extend(sorted(glob.glob(os.path.join(BUILTIN_DIR, "*.yaml"))))
    for p in paths or []:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.yaml"))) + sorted(glob.glob(os.path.join(p, "*.yml"))))
        else:
            files.append(p)
    rules: list[Rule] = []
    seen: set[str] = set()
    for f in files:
        with open(f, encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d]
        for d in docs:
            r = Rule.from_dict(d, source_file=f)
            if r.id in seen:
                raise RuleError(f"duplicate rule id {r.id} in {f}")
            seen.add(r.id)
            rules.append(r)
    return rules


def _collapse_flow_findings(findings: list[Finding]) -> list[Finding]:
    """Merge flow findings from the same rule that share a source and sink class
    (e.g. one injected page beaconing to many GET sinks) into a single finding
    whose events are the union, so one attack campaign is one report entry."""
    out: list[Finding] = []
    groups: dict[tuple, Finding] = {}
    for f in findings:
        flow = f.evidence.get("flow")
        if not flow:
            out.append(f)
            continue
        key = (f.rule_id, f.session_id, flow.get("source"), flow.get("source_class"), flow.get("sink_class"))
        if key not in groups:
            groups[key] = f
        else:
            g = groups[key]
            merged_events = list(dict.fromkeys(g.events + f.events))
            keep = g if g.confidence >= f.confidence else f
            n = int(g.evidence.get("merged_count", 1)) + 1
            new_ev = dict(keep.evidence)
            new_ev["merged_count"] = n
            new_ev["merged_sinks"] = sorted({*new_ev.get("merged_sinks", []), g.evidence.get("flow", {}).get("sink"), f.evidence.get("flow", {}).get("sink")} - {None})
            groups[key] = Finding(
                rule_id=keep.rule_id,
                title=keep.title,
                severity=keep.severity,
                session_id=keep.session_id,
                events=merged_events,
                confidence=max(g.confidence, f.confidence),
                evidence=new_ev,
                mappings=keep.mappings,
                description=keep.description,
                tags=keep.tags,
            )
    out.extend(groups.values())
    return out


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = [r for r in rules if r.enabled]

    def evaluate(self, analysis: SessionAnalysis, anchor: str | None = None) -> list[Finding]:
        """Evaluate every rule over a session.

        With ``anchor`` (an event id), each matcher only reports findings that
        this event *completes* - e.g. the 5th delete in a burst, the outbound
        call that ends a credential-read -> exfil chain. This is how the runtime
        guard asks "is this specific call the attack?".
        """
        findings: list[Finding] = []
        for rule in self.rules:
            matcher = _MATCHERS[rule.match["type"]]
            findings.extend(matcher(rule, analysis, anchor))
        # de-duplicate identical (rule, events) pairs, keep highest confidence
        best: dict[tuple[str, tuple[str, ...]], Finding] = {}
        for f in findings:
            key = (f.rule_id, tuple(f.events))
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f
        collapsed = _collapse_flow_findings(list(best.values()))
        return sorted(collapsed, key=lambda f: (-f.rank, -f.confidence, f.rule_id))

    def evaluate_all(self, analyses: list[SessionAnalysis]) -> list[Finding]:
        out: list[Finding] = []
        for a in analyses:
            out.extend(self.evaluate(a))
        return out
