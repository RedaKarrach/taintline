"""MCP stdio proxy: enforce the taintline guard on live Model Context Protocol
traffic.

The proxy sits between an MCP client (an IDE, a desktop assistant, an agent
framework) and a real MCP server launched as a subprocess::

    client  <--stdio-->  taintline guard mcp-proxy  <--stdio-->  real server

It relays newline-delimited JSON-RPC in both directions and intervenes on:

* ``tools/list`` responses - every advertised tool (description *and* input
  schema, since poisoning payloads hide in parameter descriptions too) is
  scanned; poisoned tools are stripped before the client/model ever sees them.
* ``tools/call`` requests - previewed against the live taint state and the
  policy *before* being forwarded. Refused calls never reach the server; the
  client receives a tool-level error (``isError: true``) explaining why, which
  the model can read and recover from.
* ``tools/call`` responses - fed into the taint state as tool results, so
  content and secrets they carry are tracked for later calls.

Everything else (initialize, notifications, prompts, resources, server-to-client
requests) passes through untouched. Every event is appended to an audit trail
(JSONL, flushed per line) that ``taintline analyze`` can turn into a forensic
report afterwards.

Scope note: one proxy instance tracks taint across the tools of the server it
fronts. For taint that crosses several servers, run the agent through the
Python SDK (``Guard`` / ``GuardSession``) in the agent loop instead.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import uuid
from typing import IO, Any

from taintline.guard.guard import Decision, Guard

PREFIX = "[taintline-guard]"


def _content_text(result: Any) -> str:
    """Flatten an MCP CallToolResult into text for taint tracking."""
    if not isinstance(result, dict):
        return json.dumps(result, ensure_ascii=False, default=str)
    parts: list[str] = []
    for item in result.get("content") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text":
            parts.append(str(item.get("text", "")))
        elif item.get("type") == "resource":
            res = item.get("resource") or {}
            parts.append(str(res.get("text") or res.get("uri") or ""))
        else:
            parts.append(json.dumps(item, ensure_ascii=False, default=str))
    if "structuredContent" in result:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False, default=str))
    return "\n".join(p for p in parts if p)


class MCPProxy:
    def __init__(
        self,
        server_cmd: list[str],
        guard: Guard | None = None,
        audit_path: str | None = None,
        transport: str = "local",
        strip_poisoned: bool = True,
        untrusted_results: bool = False,
        principal: str | None = None,
        session_id: str | None = None,
        client_in: IO[bytes] | None = None,
        client_out: IO[bytes] | None = None,
        log: IO[str] | None = None,
    ):
        if not server_cmd:
            raise ValueError("server command is required")
        self.server_cmd = server_cmd
        self.guard = guard or Guard()
        self.transport = transport
        self.strip_poisoned = strip_poisoned
        self.untrusted_results = untrusted_results
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self.log = log or sys.stderr
        self._audit_fh = open(audit_path, "a", encoding="utf-8") if audit_path else None  # noqa: SIM115
        self.session = self.guard.session(session_id or f"mcp-{uuid.uuid4().hex[:8]}", audit=self._audit_fh)
        if principal:
            self.session.user(principal)
        self._state_lock = threading.Lock()
        self._out_lock = threading.Lock()
        self._pending_calls: dict[Any, str] = {}
        self._pending_lists: set[Any] = set()
        self.stats = {"calls": 0, "blocked": 0, "held": 0, "poisoned_stripped": 0}
        self.child: subprocess.Popen[bytes] | None = None

    # ------------------------------------------------------------------ io
    def _say(self, text: str) -> None:
        print(f"{PREFIX} {text}", file=self.log, flush=True)

    def _send_client(self, payload: bytes | dict[str, Any]) -> None:
        data = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        with self._out_lock:
            self.client_out.write(data + b"\n")
            self.client_out.flush()

    def _send_server(self, data: bytes) -> None:
        assert self.child and self.child.stdin
        try:
            self.child.stdin.write(data + b"\n")
            self.child.stdin.flush()
        except (BrokenPipeError, OSError):
            self._say("server stdin closed; dropping message")

    # ------------------------------------------------------- client -> server
    def _handle_client_msg(self, msg: Any) -> Any | None:
        """Return the message to forward, or None if it was answered locally."""
        if not isinstance(msg, dict):
            return msg
        method = msg.get("method")
        if method == "tools/list" and "id" in msg:
            self._pending_lists.add(msg["id"])
        elif method == "tools/call" and "id" in msg:
            params = msg.get("params") or {}
            name = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            with self._state_lock:
                decision = self.session.check(name, arguments, call_id=str(msg["id"]), meta={"transport": self.transport})
            self.stats["calls"] += 1
            self._log_decision(decision)
            if not decision.allowed:
                self.stats["held" if decision.action == "require_approval" else "blocked"] += 1
                self._send_client(
                    {
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"Blocked by taintline guard ({decision.action}): {decision.summary()}",
                                }
                            ],
                            "isError": True,
                        },
                    }
                )
                return None
            self._pending_calls[msg["id"]] = name
        return msg

    def _from_client(self, raw: bytes) -> None:
        line = raw.rstrip(b"\r\n")
        if not line.strip():
            return
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            self._send_server(line)
            return
        if isinstance(msg, list):
            # JSON-RPC batch: every element is inspected, so a batch cannot be
            # used to smuggle a tools/call past the guard.
            kept = [m for m in (self._handle_client_msg(x) for x in msg) if m is not None]
            if kept:
                self._send_server(json.dumps(kept, ensure_ascii=False).encode("utf-8"))
            return
        if self._handle_client_msg(msg) is not None:
            self._send_server(line)

    # ------------------------------------------------------- server -> client
    def _handle_server_msg(self, msg: Any) -> tuple[Any, bool]:
        """Return (message, modified)."""
        if not isinstance(msg, dict) or "id" not in msg or "method" in msg:
            return msg, False
        mid = msg["id"]
        if mid in self._pending_lists:
            self._pending_lists.discard(mid)
            result = msg.get("result") or {}
            tools = result.get("tools") or []
            kept = []
            for t in tools:
                name = str(t.get("name", ""))
                scanned = f"{t.get('description', '')}\n{json.dumps(t.get('inputSchema', {}), ensure_ascii=False)}"
                with self._state_lock:
                    poisoned = self.session.register_tool(name, scanned, transport=self.transport)
                if poisoned and self.strip_poisoned:
                    self.stats["poisoned_stripped"] += 1
                    self._say(f"STRIP tool '{name}': description carries injection payload")
                    continue
                kept.append(t)
            if len(kept) != len(tools):
                msg = dict(msg)
                msg["result"] = dict(result, tools=kept)
                return msg, True
        elif mid in self._pending_calls:
            name = self._pending_calls.pop(mid)
            text = _content_text(msg["result"]) if "result" in msg else json.dumps(msg.get("error"), ensure_ascii=False)
            meta = {"transport": self.transport}
            if self.untrusted_results:
                meta["trust"] = "untrusted"
            with self._state_lock:
                self.session.tool_result(name, text, call_id=str(mid), meta=meta)
        return msg, False

    def _from_server(self, raw: bytes) -> None:
        line = raw.rstrip(b"\r\n")
        if not line.strip():
            return
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            self._send_client(line)
            return
        if isinstance(msg, list):
            out, changed = [], False
            for x in msg:
                m, c = self._handle_server_msg(x)
                out.append(m)
                changed = changed or c
            self._send_client(json.dumps(out, ensure_ascii=False).encode("utf-8") if changed else line)
            return
        out_msg, changed = self._handle_server_msg(msg)
        self._send_client(json.dumps(out_msg, ensure_ascii=False).encode("utf-8") if changed else line)

    # --------------------------------------------------------------- logging
    def _log_decision(self, d: Decision) -> None:
        tag = {"allow": "ALLOW", "log": "LOG  ", "block": "BLOCK"}.get(d.enforced, d.enforced.upper())
        if d.action == "require_approval":
            tag = "HOLD " if not d.allowed else "APPROVED"
        line = f"{tag} {d.tool} ({d.latency_ms:.1f} ms)"
        if d.matched:
            line += f" :: {d.summary()}"
        if d.mode == "monitor" and d.action not in ("allow",):
            line += f" [monitor: would {d.action}]"
        self._say(line)

    # ------------------------------------------------------------------- run
    def _pump_server(self) -> None:
        assert self.child and self.child.stdout
        for raw in iter(self.child.stdout.readline, b""):
            try:
                self._from_server(raw)
            except Exception as exc:  # never let one bad message kill the relay
                self._say(f"error relaying server message: {exc!r}")

    def run(self) -> int:
        self._say(f"starting server: {' '.join(self.server_cmd)} (policy mode: {self.guard.policy.mode})")
        self.child = subprocess.Popen(self.server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        pump = threading.Thread(target=self._pump_server, name="mcp-server-pump", daemon=True)
        pump.start()
        try:
            for raw in iter(self.client_in.readline, b""):
                try:
                    self._from_client(raw)
                except Exception as exc:
                    self._say(f"error relaying client message: {exc!r}")
        except KeyboardInterrupt:
            pass
        finally:
            if self.child.stdin:
                try:
                    self.child.stdin.close()
                except OSError:
                    pass
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.terminate()
                self.child.wait(timeout=5)
            pump.join(timeout=5)
            s = self.stats
            self._say(
                f"session {self.session.session_id} closed: {s['calls']} calls, {s['blocked']} blocked, "
                f"{s['held']} held, {s['poisoned_stripped']} poisoned tools stripped"
            )
            if self._audit_fh:
                self._audit_fh.close()
        return self.child.returncode or 0
