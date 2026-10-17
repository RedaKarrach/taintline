"""Provenance / attack-graph construction and export (DOT, node-link JSON)."""

from __future__ import annotations

import json
from typing import Any

import networkx as nx

from taintline.taint import SessionAnalysis

NODE_COLORS = {
    "source": "#d64545",
    "sink": "#e08a1e",
    "payload": "#7b4fb3",
    "model_output": "#9aa0a6",
    "user_message": "#2f7fd3",
    "system_prompt": "#2f7fd3",
    "memory_write": "#2a9d8f",
    "memory_read": "#2a9d8f",
    "tool_registered": "#c05c9b",
    "default": "#cfd3d7",
}


def build_graph(analyses: list[SessionAnalysis], include_sequence: bool = True) -> nx.DiGraph:
    g = nx.DiGraph()
    for a in analyses:
        prev = None
        payload_ids = {p.origin for p in a.payloads}
        for e in a.events:
            info = a.info(e)
            role = "default"
            if e.kind == "tool_result" and info.is_source:
                role = "source"
            elif e.kind == "tool_call" and info.is_sink:
                role = "sink"
            elif e.id in payload_ids:
                role = "payload"
            elif e.kind in NODE_COLORS:
                role = e.kind
            if e.kind == "tool_registered" and a.taints.get(e.id):
                role = "source"
            g.add_node(
                e.id,
                session=e.session_id,
                seq=e.seq,
                kind=e.kind,
                tool=e.tool or "",
                role=role,
                tainted=bool(a.taints.get(e.id)),
                taint_confidence=a.max_taint_confidence(e.id),
                label=_label(e, info),
            )
            if include_sequence and prev is not None:
                g.add_edge(prev, e.id, kind="seq", weight=0.1)
            prev = e.id
        # tool_call -> tool_result pairing
        pending: dict[str, str] = {}
        last_call: str | None = None
        for e in a.events:
            if e.kind == "tool_call":
                if e.call_id:
                    pending[e.call_id] = e.id
                last_call = e.id
            elif e.kind == "tool_result":
                src = pending.pop(e.call_id, None) if e.call_id else last_call
                if src:
                    g.add_edge(src, e.id, kind="call", weight=0.5)
        for w, r in a.memory_links:
            g.add_edge(w, r, kind="memory", weight=1.0)
        for f in a.flows:
            path = list(f.path)
            for u, v in zip(path, path[1:], strict=False):
                if u in g and v in g:
                    data = g.get_edge_data(u, v) or {}
                    g.add_edge(
                        u,
                        v,
                        kind=f"flow:{f.kind}",
                        weight=max(data.get("weight", 0), f.confidence),
                        confidence=f.confidence,
                    )
            if path and path[0] not in g:
                # cross-session origin: add a stub node so the path is visible
                g.add_node(path[0], session="?", seq=-1, kind="external", tool="", role="source", tainted=True, label=f"{path[0]} (earlier session)")
                if len(path) > 1:
                    g.add_edge(path[0], path[1], kind=f"flow:{f.kind}", weight=f.confidence, confidence=f.confidence)
    return g


def _label(e: Any, info: Any) -> str:
    head = f"{e.seq:03d} {e.kind}"
    if e.tool:
        head += f"\\n{e.tool}"
    snippet = e.short(48).replace('"', "'")
    return f"{head}\\n{snippet}"


def attack_paths(a: SessionAnalysis) -> list[dict[str, Any]]:
    """Flows rendered as readable step lists for reports."""
    out = []
    for f in sorted(a.flows, key=lambda f: -f.confidence):
        steps = []
        for eid in f.path:
            ev = a.event(eid)
            if ev is None:
                steps.append({"event": eid, "kind": "external", "tool": "", "excerpt": "(earlier session)"})
            else:
                steps.append({"event": eid, "kind": ev.kind, "tool": ev.tool or "", "excerpt": ev.short(140)})
        out.append({"flow": f.to_dict(), "steps": steps})
    return out


def to_dot(g: nx.DiGraph, title: str = "taintline attack graph") -> str:
    lines = [
        "digraph taintline {",
        f'  label="{title}"; labelloc=t; fontsize=18; rankdir=LR; node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10];',
    ]
    sessions: dict[str, list[str]] = {}
    for n, d in g.nodes(data=True):
        sessions.setdefault(d.get("session", "?"), []).append(n)
    for sid, nodes in sessions.items():
        lines.append(f'  subgraph "cluster_{sid}" {{ label="session {sid}"; color="#bbbbbb";')
        for n in nodes:
            d = g.nodes[n]
            color = NODE_COLORS.get(d.get("role", "default"), NODE_COLORS["default"])
            pen = "penwidth=2.5, color=\"#b00020\"" if d.get("tainted") else "penwidth=1"
            lines.append(f'    "{n}" [label="{d.get("label", n)}", fillcolor="{color}", {pen}];')
        lines.append("  }")
    for u, v, d in g.edges(data=True):
        kind = d.get("kind", "seq")
        if kind == "seq":
            lines.append(f'  "{u}" -> "{v}" [color="#dddddd", arrowsize=0.5];')
        elif kind == "call":
            lines.append(f'  "{u}" -> "{v}" [color="#888888", style=dashed];')
        elif kind == "memory":
            lines.append(f'  "{u}" -> "{v}" [color="#2a9d8f", penwidth=2, label="memory"];')
        else:
            conf = d.get("confidence", 0.0)
            lines.append(f'  "{u}" -> "{v}" [color="#b00020", penwidth=3, label="{kind.split(":")[1]} {conf:.2f}"];')
    lines.append("}")
    return "\n".join(lines)


def to_json(g: nx.DiGraph) -> str:
    data = nx.node_link_data(g, edges="links")
    return json.dumps(data, indent=2, ensure_ascii=False)
