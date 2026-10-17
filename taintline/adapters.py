"""Adapters that turn other logging formats into native taintline events.

Supported:
* ``openai``  - a JSON file holding ``{"sessions": {id: [messages...]}}`` or a
                bare list of chat-completion style messages (role / content /
                tool_calls / tool_call_id).
* ``otel``    - a JSON array of OpenTelemetry spans following the GenAI
                semantic conventions (``gen_ai.*`` attributes). Best effort.
"""

from __future__ import annotations

import json
from typing import Any

from taintline.schema import Event, _as_text


def _ts(value: Any, fallback_index: int) -> str:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, int | float):
        from datetime import datetime, timezone

        # OTel uses nanoseconds since epoch.
        secs = value / 1e9 if value > 1e12 else value
        return datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
    return f"1970-01-01T00:00:{fallback_index:02d}Z"


def from_openai_messages(session_id: str, messages: list[dict[str, Any]], base_ts: str = "") -> list[Event]:
    events: list[Event] = []
    seq = 0

    def add(kind: str, **kw: Any) -> None:
        nonlocal seq
        events.append(
            Event(
                id=f"{session_id}:{seq:05d}",
                session_id=session_id,
                seq=seq,
                ts=kw.pop("ts", base_ts or _ts(None, seq)),
                kind=kind,
                **kw,
            )
        )
        seq += 1

    for m in messages:
        role = m.get("role")
        ts = m.get("ts") or m.get("timestamp") or base_ts
        if role == "system":
            add("system_prompt", content=_as_text(m.get("content")), ts=ts)
        elif role == "user":
            add("user_message", content=_as_text(m.get("content")), ts=ts)
        elif role == "assistant":
            if m.get("content"):
                add("model_output", content=_as_text(m.get("content")), ts=ts)
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function", {})
                raw_args = fn.get("arguments", "{}")
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                except json.JSONDecodeError:
                    args = {"_raw": raw_args}
                add("tool_call", tool=fn.get("name"), args=args, call_id=tc.get("id"), ts=ts)
        elif role == "tool":
            add(
                "tool_result",
                tool=m.get("name"),
                content=_as_text(m.get("content")),
                call_id=m.get("tool_call_id"),
                meta=dict(m.get("metadata") or {}),
                ts=ts,
            )
    return events


def load_openai(path: str) -> list[Event]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return from_openai_messages("default", data)
    out: list[Event] = []
    for sid, msgs in (data.get("sessions") or {}).items():
        out.extend(from_openai_messages(str(sid), msgs))
    return out


def load_otel(path: str) -> list[Event]:
    """Best-effort mapping of GenAI semantic-convention spans to events."""
    with open(path, encoding="utf-8") as fh:
        spans = json.load(fh)
    if isinstance(spans, dict):
        spans = spans.get("spans") or spans.get("resourceSpans") or []
    events: list[Event] = []
    counters: dict[str, int] = {}
    for s in sorted(spans, key=lambda x: x.get("startTimeUnixNano", x.get("start_time", 0))):
        attrs = s.get("attributes") or {}
        if isinstance(attrs, list):  # OTLP key/value list form
            attrs = {a["key"]: next(iter(a.get("value", {}).values()), None) for a in attrs}
        sid = str(attrs.get("gen_ai.conversation.id") or attrs.get("session.id") or s.get("traceId") or "default")
        seq = counters.get(sid, 0)
        ts = _ts(s.get("startTimeUnixNano", s.get("start_time")), seq)
        op = attrs.get("gen_ai.operation.name", "")

        def add(kind: str, **kw: Any) -> None:
            nonlocal seq
            events.append(Event(id=f"{sid}:{seq:05d}", session_id=sid, seq=seq, ts=ts, kind=kind, **kw))
            seq += 1

        if op == "execute_tool":
            raw_args = attrs.get("gen_ai.tool.call.arguments") or attrs.get("gen_ai.tool.input") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except json.JSONDecodeError:
                args = {"_raw": raw_args}
            name = attrs.get("gen_ai.tool.name") or s.get("name")
            call_id = attrs.get("gen_ai.tool.call.id")
            add("tool_call", tool=name, args=args, call_id=call_id)
            result = attrs.get("gen_ai.tool.call.result") or attrs.get("gen_ai.tool.output")
            if result is not None:
                add("tool_result", tool=name, content=_as_text(result), call_id=call_id)
        elif op in ("chat", "text_completion", "generate_content", "invoke_agent"):
            for ev in s.get("events") or []:
                ea = ev.get("attributes") or {}
                name = ev.get("name", "")
                body = ea.get("gen_ai.event.content") or ea.get("content") or ""
                if name.endswith("user.message"):
                    add("user_message", content=_as_text(body))
                elif name.endswith("system.message"):
                    add("system_prompt", content=_as_text(body))
                elif name.endswith("assistant.message") or name.endswith("choice"):
                    add("model_output", content=_as_text(body))
                elif name.endswith("tool.message"):
                    add("tool_result", tool=ea.get("gen_ai.tool.name"), content=_as_text(body))
        counters[sid] = seq
    return events
