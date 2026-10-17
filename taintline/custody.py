"""Chain of custody for trace evidence.

An evidence manifest records the SHA-256 of the raw trace file and a hash
chain over the parsed events (``h_i = sha256(h_{i-1} || canonical(event_i))``).
Any later edit, re-ordering or deletion of an event changes the chain head, so
a report can be tied to exactly the evidence it was produced from.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
from datetime import datetime, timezone
from typing import Any

from taintline import __version__
from taintline.schema import Event


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_chain(events: list[Event], seed: str) -> tuple[str, list[str]]:
    prev = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    links: list[str] = []
    for e in events:
        prev = hashlib.sha256((prev + e.canonical()).encode("utf-8")).hexdigest()
        links.append(prev)
    return prev, links


def build_manifest(trace_path: str, events: list[Event], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    file_hash = sha256_file(trace_path)
    head, links = hash_chain(events, file_hash)
    sessions = sorted({e.session_id for e in events})
    return {
        "schema": "taintline-evidence-manifest/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": {"name": "taintline", "version": __version__},
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "source": {
            "path": os.path.abspath(trace_path),
            "size_bytes": os.path.getsize(trace_path),
            "sha256": file_hash,
        },
        "events": {
            "count": len(events),
            "sessions": sessions,
            "first_ts": events[0].ts if events else None,
            "last_ts": events[-1].ts if events else None,
            "chain_head": head,
            "chain_links": links,
        },
        **(extra or {}),
    }


def verify_manifest(manifest_path: str, trace_path: str | None = None) -> dict[str, Any]:
    """Re-derive hashes and report which checks pass."""
    from taintline.schema import load_jsonl

    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    trace_path = trace_path or manifest["source"]["path"]
    result: dict[str, Any] = {"trace": trace_path, "file_hash_ok": False, "chain_ok": False, "first_divergence": None}
    if not os.path.exists(trace_path):
        result["error"] = "trace file not found"
        return result
    file_hash = sha256_file(trace_path)
    result["file_hash_ok"] = file_hash == manifest["source"]["sha256"]
    events = load_jsonl(trace_path)
    head, links = hash_chain(events, manifest["source"]["sha256"])
    result["chain_ok"] = head == manifest["events"]["chain_head"] and len(links) == manifest["events"]["count"]
    if not result["chain_ok"]:
        recorded = manifest["events"].get("chain_links", [])
        for i, (a, b) in enumerate(zip(links, recorded, strict=False)):
            if a != b:
                result["first_divergence"] = {"index": i, "event_id": events[i].id}
                break
        else:
            if len(links) != len(recorded):
                result["first_divergence"] = {"index": min(len(links), len(recorded)), "event_id": None, "reason": "event count differs"}
    result["ok"] = result["file_hash_ok"] and result["chain_ok"]
    return result
