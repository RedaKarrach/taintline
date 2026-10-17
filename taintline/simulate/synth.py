"""Low-level builder for synthetic agent traces."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

from taintline.schema import Event


class TraceBuilder:
    """Append-only builder that assigns seq numbers and ISO timestamps."""

    def __init__(self, session_id: str, start: datetime | None = None, step_seconds: int = 3):
        self.session_id = session_id
        self.seq = 0
        self.t = start or datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
        self.step = timedelta(seconds=step_seconds)
        self.events: list[Event] = []

    def _add(self, kind: str, **kw: Any) -> Event:
        e = Event(
            id=f"{self.session_id}:{self.seq:05d}",
            session_id=self.session_id,
            seq=self.seq,
            ts=self.t.isoformat(),
            kind=kind,
            **kw,
        )
        self.events.append(e)
        self.seq += 1
        self.t += self.step
        return e

    def system(self, text: str) -> Event:
        return self._add("system_prompt", content=text)

    def user(self, text: str) -> Event:
        return self._add("user_message", content=text)

    def model(self, text: str) -> Event:
        return self._add("model_output", content=text)

    def register_tool(self, name: str, description: str, transport: str = "local") -> Event:
        return self._add("tool_registered", tool=name, content=description, meta={"description": description, "transport": transport})

    def call(self, tool: str, args: dict[str, Any], call_id: str | None = None, meta: dict[str, Any] | None = None) -> Event:
        cid = call_id or f"c{self.seq}"
        return self._add("tool_call", tool=tool, args=args, call_id=cid, meta=meta or {})

    def result(self, tool: str, content: str, call_id: str | None = None, meta: dict[str, Any] | None = None) -> Event:
        cid = call_id or (self.events[-1].call_id if self.events and self.events[-1].kind == "tool_call" else None)
        return self._add("tool_result", tool=tool, content=content, call_id=cid, meta=meta or {})

    def call_result(self, tool: str, args: dict[str, Any], result: str, meta: dict[str, Any] | None = None) -> tuple[Event, Event]:
        c = self.call(tool, args, meta=meta)
        r = self.result(tool, result, call_id=c.call_id, meta=meta)
        return c, r

    def memory_write(self, key: str, value: str) -> Event:
        return self._add("memory_write", tool="memory_write", args={"key": key, "value": value}, content=value)

    def memory_read(self, key: str, value: str) -> Event:
        return self._add("memory_read", tool="memory_read", args={"key": key}, content=value)


def make_builder(session_id: str, **kw: Any) -> TraceBuilder:
    return TraceBuilder(session_id, **kw)


# ---------------------------------------------------------------------------
# benign activity: a library of harmless agent chores
# ---------------------------------------------------------------------------

_BENIGN_CHORES = [
    ("weather", lambda b: _chore_weather(b)),
    ("summarize_doc", lambda b: _chore_summarize(b)),
    ("search_answer", lambda b: _chore_search(b)),
    ("code_help", lambda b: _chore_code(b)),
    ("calendar", lambda b: _chore_calendar(b)),
    ("notes", lambda b: _chore_notes(b)),
    ("read_pr", lambda b: _chore_pr(b)),
]


def _chore_weather(b: TraceBuilder) -> None:
    b.user("What's the weather in Seattle tomorrow?")
    b.model("Let me check the forecast.")
    b.call_result("web_search", {"query": "Seattle weather tomorrow"}, "Partly cloudy, high 54F, low 41F, 20% rain.")
    b.model("Tomorrow in Seattle: partly cloudy, high 54F, low 41F, 20% chance of rain.")


def _chore_summarize(b: TraceBuilder) -> None:
    b.user("Summarize the attached quarterly notes.")
    b.call_result("read_file", {"path": "/home/u/docs/q3-notes.txt"}, "Q3 revenue up 12%. Churn down. Hiring two engineers. Launch delayed to Q4.")
    b.model("Q3: revenue +12%, churn down, two eng hires planned, launch moved to Q4.")


def _chore_search(b: TraceBuilder) -> None:
    b.user("Who wrote the Raft consensus paper?")
    b.model("Searching.")
    b.call_result("web_search", {"query": "Raft consensus paper authors"}, "Diego Ongaro and John Ousterhout, 'In Search of an Understandable Consensus Algorithm', 2014.")
    b.model("Raft was introduced by Diego Ongaro and John Ousterhout in 2014.")


def _chore_code(b: TraceBuilder) -> None:
    b.user("Run the unit tests in the repo.")
    b.call_result("read_file", {"path": "/repo/pytest.ini"}, "[pytest]\ntestpaths = tests")
    b.call_result("shell", {"cmd": "pytest -q"}, "24 passed in 3.10s")
    b.model("All 24 tests pass.")


def _chore_calendar(b: TraceBuilder) -> None:
    b.user("Do I have anything this afternoon?")
    b.call_result("get_calendar", {"range": "today"}, "2pm standup, 4pm 1:1 with Dana.")
    b.model("You have standup at 2pm and a 1:1 with Dana at 4pm.")


def _chore_notes(b: TraceBuilder) -> None:
    b.user("Remember that I prefer metric units.")
    b.memory_write("preferences", "User prefers metric units for all answers.")
    b.model("Noted - I'll use metric units.")


def _chore_pr(b: TraceBuilder) -> None:
    b.user("What does PR 412 change?")
    b.call_result("github_get_issue", {"number": 412}, "PR 412: refactor the cache layer, add TTL config, update docs. No behavior change for callers.")
    b.model("PR 412 refactors the cache layer and adds a configurable TTL, with doc updates. No caller-facing behavior change.")


def benign_session(session_id: str, rng: random.Random | None = None, chores: int | None = None) -> list[Event]:
    rng = rng or random.Random(hash(session_id) & 0xFFFF)
    b = make_builder(session_id)
    b.system("You are a helpful assistant with access to tools. Follow the user's instructions.")
    n = chores if chores is not None else rng.randint(1, 3)
    for name, fn in rng.sample(_BENIGN_CHORES, k=min(n, len(_BENIGN_CHORES))):
        _ = name
        fn(b)
    return b.events
