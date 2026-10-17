"""Trace event schema and JSONL loading.

The native trace format is one JSON object per line. Every line is an *event*
in an agent session. The minimum you need is ``session_id``, ``kind`` and a
timestamp; everything else is optional and defaults sensibly.

Event kinds
-----------
system_prompt    the operator's system prompt (trusted)
user_message     a message from the human principal
model_output     text the model produced for the user (or its reasoning summary)
tool_call        the model invoking a tool; ``tool`` + ``args`` (+ ``call_id``)
tool_result      the tool's response; ``content`` holds the returned text/JSON
memory_write     the agent persisting something; ``args.key`` and ``content``
memory_read      the agent recalling something; ``args.key`` and ``content``
tool_registered  a tool/plugin/MCP server advertised to the model; ``meta.description``
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

EVENT_KINDS = {
    "system_prompt",
    "user_message",
    "model_output",
    "tool_call",
    "tool_result",
    "memory_write",
    "memory_read",
    "tool_registered",
}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


@dataclass
class Event:
    id: str
    session_id: str
    seq: int
    ts: str
    kind: str
    tool: str | None = None
    content: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    call_id: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    # ---- derived -------------------------------------------------------
    @property
    def args_text(self) -> str:
        return _as_text(self.args) if self.args else ""

    @property
    def text(self) -> str:
        """All human/model-visible text carried by the event."""
        if self.kind == "tool_call":
            return self.args_text
        if self.kind == "tool_registered":
            return _as_text(self.meta.get("description", "")) + " " + self.content
        if self.kind in ("memory_write", "memory_read"):
            return self.content
        return self.content

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def short(self, n: int = 90) -> str:
        t = self.text.replace("\n", " ").strip()
        return t if len(t) <= n else t[: n - 1] + "…"


@dataclass
class Session:
    id: str
    events: list[Event]

    @property
    def start_ts(self) -> str:
        return self.events[0].ts if self.events else ""

    @property
    def end_ts(self) -> str:
        return self.events[-1].ts if self.events else ""

    def by_id(self, event_id: str) -> Event | None:
        for e in self.events:
            if e.id == event_id:
                return e
        return None


class TraceFormatError(ValueError):
    pass


def parse_event(raw: dict[str, Any], index: int) -> Event:
    if not isinstance(raw, dict):
        raise TraceFormatError(f"line {index}: expected a JSON object")
    session_id = str(raw.get("session_id") or raw.get("session") or "default")
    kind = str(raw.get("kind") or raw.get("type") or "").strip()
    if kind not in EVENT_KINDS:
        raise TraceFormatError(f"line {index}: unknown event kind {kind!r}")
    seq = int(raw.get("seq", index))
    ts = str(raw.get("ts") or raw.get("timestamp") or "")
    event_id = str(raw.get("id") or f"{session_id}:{seq:05d}")
    args = raw.get("args") or raw.get("arguments") or {}
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {"_raw": args}
    content = raw.get("content")
    if content is None:
        content = raw.get("result", raw.get("text", ""))
    meta = raw.get("meta") or raw.get("metadata") or {}
    return Event(
        id=event_id,
        session_id=session_id,
        seq=seq,
        ts=ts,
        kind=kind,
        tool=raw.get("tool") or raw.get("name"),
        content=_as_text(content),
        args=dict(args) if isinstance(args, dict) else {"_raw": args},
        call_id=raw.get("call_id"),
        meta=dict(meta) if isinstance(meta, dict) else {},
    )


def load_jsonl(path: str) -> list[Event]:
    events: list[Event] = []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TraceFormatError(f"line {i + 1}: invalid JSON ({exc.msg})") from exc
            events.append(parse_event(raw, i))
    return events


def dump_jsonl(events: list[Event], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")


def group_sessions(events: list[Event]) -> list[Session]:
    """Group events by session and order sessions chronologically.

    Chronological ordering matters: taint persisted to memory in an earlier
    session must be visible to later sessions.
    """
    buckets: dict[str, list[Event]] = {}
    for e in events:
        buckets.setdefault(e.session_id, []).append(e)
    sessions = []
    for sid, evs in buckets.items():
        evs.sort(key=lambda e: (e.seq, e.ts))
        sessions.append(Session(id=sid, events=evs))
    sessions.sort(key=lambda s: (s.start_ts, s.id))
    return sessions
