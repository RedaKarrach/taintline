"""Correlate an agent incident with AWS CloudTrail activity.

taintline tells you an agent *was steered into* reading and exfiltrating a
credential. The next forensic question is: **was that credential then used?**
This module joins the incident against CloudTrail events to answer it.

Given the incident window and the access-key IDs the agent touched, it finds:

* **confirmed abuse** - CloudTrail events using one of the exposed access keys
  after it was exfiltrated, especially from a new IP / user-agent, and
  especially sensitive calls (IAM changes, ``GetSecretValue``, data access,
  ``CreateAccessKey`` ...);
* **suspicious context** - the same key used right after exposure even if the
  call looks ordinary;
* a **verdict** per key (used / not-seen) and a merged timeline.

Input is standard CloudTrail JSON (a ``{"Records": [...]}`` export, a list of
records, or JSONL). Everything is read-only and offline. Synthetic fixtures live
in ``tests``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# CloudTrail events that are high-impact if made with a stolen key
_SENSITIVE_EVENTS = {
    "CreateAccessKey", "CreateUser", "CreateLoginProfile", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion", "UpdateAssumeRolePolicy", "AssumeRole",
    "GetSecretValue", "BatchGetSecretValue", "Decrypt", "GetParameter", "GetParameters",
    "CreateKeyPair", "ImportKeyPair", "RunInstances", "ModifySnapshotAttribute", "SharedSnapshot",
    "PutObject", "GetObject", "DeleteObject", "CopyObject", "CreateBucket", "PutBucketPolicy",
    "DeleteTrail", "StopLogging", "UpdateTrail", "DeleteDBInstance", "ModifyDBInstance",
    "ConsoleLogin", "GetFederationToken", "DeleteUser",
}
_DISABLE_LOGGING = {"StopLogging", "DeleteTrail", "UpdateTrail"}


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, int | float):
        from datetime import timezone

        secs = value / 1000 if value > 1e12 else value
        return datetime.fromtimestamp(secs, tz=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def load_cloudtrail(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    records: list[dict[str, Any]] = []
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            doc = json.loads(text)
            records = doc.get("Records", []) if isinstance(doc, dict) else []
        except json.JSONDecodeError:
            records = []
    if not records and stripped.startswith("["):
        records = json.loads(text)
    if not records:  # JSONL fallback
        for line in text.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


@dataclass
class TrailHit:
    event_time: str
    event_name: str
    event_source: str
    access_key_id: str
    source_ip: str
    user_agent: str
    sensitive: bool
    new_origin: bool  # IP/user-agent not seen for this key before exposure
    disables_logging: bool
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "raw"}
        return d


@dataclass
class KeyVerdict:
    access_key_id: str
    exposed_at: str | None
    used_after_exposure: bool
    confirmed_abuse: bool
    hits: list[TrailHit] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_key_id": self.access_key_id,
            "exposed_at": self.exposed_at,
            "used_after_exposure": self.used_after_exposure,
            "confirmed_abuse": self.confirmed_abuse,
            "hit_count": len(self.hits),
            "hits": [h.to_dict() for h in self.hits],
        }


@dataclass
class CorrelationResult:
    verdicts: list[KeyVerdict]
    summary: dict[str, Any]

    @property
    def any_abuse(self) -> bool:
        return any(v.confirmed_abuse for v in self.verdicts)

    def to_dict(self) -> dict[str, Any]:
        return {"any_abuse": self.any_abuse, "summary": self.summary, "verdicts": [v.to_dict() for v in self.verdicts]}


def _field(rec: dict[str, Any], *path: str) -> Any:
    cur: Any = rec
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _key_of(rec: dict[str, Any]) -> str | None:
    return (
        _field(rec, "userIdentity", "accessKeyId")
        or _field(rec, "userIdentity", "sessionContext", "attributes", "accessKeyId")
        or rec.get("accessKeyId")
    )


def correlate(
    records: list[dict[str, Any]],
    exposed_keys: dict[str, str | None],
    window_hours: float = 72.0,
) -> CorrelationResult:
    """Correlate exposed keys (``{access_key_id: exposed_iso_ts | None}``) with
    CloudTrail ``records``. A hit is a post-exposure use of an exposed key."""
    # baseline: origins seen for each key *before* exposure are "known"
    known_origins: dict[str, set[tuple[str, str]]] = {k: set() for k in exposed_keys}
    for rec in records:
        k = _key_of(rec)
        if k in exposed_keys:
            exposed = _parse_ts(exposed_keys[k])
            t = _parse_ts(rec.get("eventTime"))
            if exposed and t and t < exposed:
                known_origins[k].add((rec.get("sourceIPAddress", ""), rec.get("userAgent", "")))

    verdicts: dict[str, KeyVerdict] = {
        k: KeyVerdict(k, exposed_keys[k], used_after_exposure=False, confirmed_abuse=False) for k in exposed_keys
    }
    for rec in sorted(records, key=lambda r: str(r.get("eventTime", ""))):
        k = _key_of(rec)
        if k not in exposed_keys:
            continue
        exposed = _parse_ts(exposed_keys[k])
        t = _parse_ts(rec.get("eventTime"))
        if exposed and t:
            if t < exposed:
                continue
            if (t - exposed).total_seconds() > window_hours * 3600:
                continue
        name = rec.get("eventName", "")
        origin = (rec.get("sourceIPAddress", ""), rec.get("userAgent", ""))
        hit = TrailHit(
            event_time=str(rec.get("eventTime", "")),
            event_name=name,
            event_source=rec.get("eventSource", ""),
            access_key_id=k,
            source_ip=origin[0],
            user_agent=origin[1],
            sensitive=name in _SENSITIVE_EVENTS,
            new_origin=origin not in known_origins.get(k, set()),
            disables_logging=name in _DISABLE_LOGGING,
            raw=rec,
        )
        v = verdicts[k]
        v.hits.append(hit)
        v.used_after_exposure = True
        if hit.sensitive or hit.new_origin or hit.disables_logging:
            v.confirmed_abuse = True

    vlist = list(verdicts.values())
    summary = {
        "keys_checked": len(exposed_keys),
        "keys_used_after_exposure": sum(1 for v in vlist if v.used_after_exposure),
        "keys_with_confirmed_abuse": sum(1 for v in vlist if v.confirmed_abuse),
        "sensitive_calls": sum(1 for v in vlist for h in v.hits if h.sensitive),
        "logging_tamper_detected": any(h.disables_logging for v in vlist for h in v.hits),
        "window_hours": window_hours,
    }
    return CorrelationResult(vlist, summary)


def exposed_keys_from_analyses(analyses, events) -> dict[str, str | None]:
    """Pull AWS access-key IDs the agent exfiltrated, with the time they left,
    from analyzed sessions. ``events`` provides timestamps by event id."""
    import re

    from taintline.toolclass import EXFIL_SINKS

    ts_by_id = {e.id: e.ts for e in events}
    akia = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
    out: dict[str, str | None] = {}
    for a in analyses:
        for f in a.flows:
            if f.sink_class not in EXFIL_SINKS:
                continue
            sink = a.event(f.sink)
            src = a.event(f.source)
            text = f"{sink.args_text if sink else ''}\n{src.text if src else ''}"
            for key in akia.findall(text):
                out.setdefault(key, ts_by_id.get(f.sink))
    return out
