"""Indicator-of-compromise extraction from a set of analyzed sessions.

An IOC here is an atom a responder can pivot on and block elsewhere: the
exfiltration endpoints the agent was steered toward, the secrets that left (by
kind, never the value), the injected source events, the poisoned tools, and the
memory keys that were corrupted. Each IOC records the events that evidence it so
it can be traced back into the timeline.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from taintline.taint import SessionAnalysis
from taintline.textsim import destinations
from taintline.toolclass import EXFIL_SINKS

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


@dataclass
class IOC:
    type: str  # domain | ipv4 | email | url_path | secret_exposed | poisoned_tool | memory_key | injection_source
    value: str
    role: str  # exfil_endpoint | recipient | exposed | supply_chain | persistence | entry_point
    sessions: set[str] = field(default_factory=set)
    events: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str]:
        return (self.type, self.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "role": self.role,
            "sessions": sorted(self.sessions),
            "events": self.events,
            "context": self.context,
        }


def _classify_dest(dest: str) -> tuple[str, str]:
    if _EMAIL.fullmatch(dest):
        return "email", "recipient"
    if _IPV4.fullmatch(dest):
        return "ipv4", "exfil_endpoint"
    if dest.startswith(("/", "~", "\\")) or ":/" in dest or re.match(r"^[a-z]:/", dest):
        return "url_path", "exfil_endpoint"
    if "." in dest and " " not in dest:
        return "domain", "exfil_endpoint"
    return "url_path", "exfil_endpoint"


def extract_iocs(analyses: list[SessionAnalysis]) -> list[IOC]:
    merged: dict[tuple[str, str], IOC] = {}

    def add(ioc: IOC) -> None:
        cur = merged.get(ioc.key())
        if cur is None:
            merged[ioc.key()] = ioc
        else:
            cur.sessions |= ioc.sessions
            cur.events = list(dict.fromkeys(cur.events + ioc.events))
            for k, v in ioc.context.items():
                cur.context.setdefault(k, v)

    for a in analyses:
        sid = a.session.id
        # destinations of exfil/egress flows, and secrets that left
        for f in a.flows:
            if f.sink_class not in EXFIL_SINKS:
                continue
            sink_ev = a.event(f.sink)
            dests = destinations(sink_ev.args_text) if sink_ev else set()
            for d in dests:
                typ, role = _classify_dest(d)
                add(IOC(typ, d, role, {sid}, [f.sink], {"via_tool": f.sink_tool}))
            for kind in f.details.get("secret_kinds", []):
                add(IOC("secret_exposed", kind, "exposed", {sid}, [f.source, f.sink],
                        {"flow": f.kind, "destinations": sorted(dests)}))
        # injection entry points
        for eid, inj in a.injection.items():
            if inj.score >= 0.5:
                ev = a.event(eid)
                if ev and ev.kind in ("tool_result", "tool_registered", "memory_read"):
                    add(IOC("injection_source", f"{sid}:{ev.tool or ev.kind}", "entry_point", {sid}, [eid],
                            {"signals": list(inj.signals), "score": round(inj.score, 3), "tool": ev.tool}))
        # poisoned tools
        for ev in a.events:
            if ev.kind == "tool_registered":
                inj = a.injection.get(ev.id)
                if inj and inj.score >= 0.3 and ev.tool:
                    add(IOC("poisoned_tool", ev.tool, "supply_chain", {sid}, [ev.id],
                            {"transport": ev.meta.get("transport", "local"), "score": round(inj.score, 3)}))
        # corrupted memory keys: any injection-scored memory write is persistence,
        # whether or not it is read back in the same session
        linked_reads = {w: r for w, r in a.memory_links}
        for ev in a.events:
            is_write = ev.kind == "memory_write" or (ev.kind == "tool_call" and a.info(ev).is_memory_write)
            inj = a.injection.get(ev.id)
            if is_write and inj and inj.score >= 0.3:
                key = str(ev.args.get("key") or ev.meta.get("key") or "default")
                ctx: dict[str, Any] = {"written": ev.id, "signals": list(inj.signals)}
                evs = [ev.id]
                if ev.id in linked_reads:
                    ctx["read"] = linked_reads[ev.id]
                    evs.append(linked_reads[ev.id])
                add(IOC("memory_key", key, "persistence", {sid}, evs, ctx))

    # stable, useful ordering
    order = {"domain": 0, "ipv4": 1, "email": 2, "url_path": 3, "poisoned_tool": 4,
             "memory_key": 5, "secret_exposed": 6, "injection_source": 7}
    return sorted(merged.values(), key=lambda i: (order.get(i.type, 9), i.value))


def group_by_type(iocs: list[IOC]) -> dict[str, list[IOC]]:
    out: dict[str, list[IOC]] = defaultdict(list)
    for i in iocs:
        out[i.type].append(i)
    return dict(out)
