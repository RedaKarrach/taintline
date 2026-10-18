"""Blast-radius assessment: given the findings, what is actually exposed and
what must the responder do now?

This turns detections into an impact picture a human can triage:

* which **secrets** left the boundary (by kind) and therefore must be rotated;
* which **destinations** received data and should be blocked / investigated;
* whether **persistence** was established (poisoned memory / files) that will
  re-fire until cleaned;
* which **capabilities** were abused (cloud control, code exec, identity);
* a coarse **severity tier** and an ordered, deduplicated remediation checklist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from taintline.forensics.ioc import IOC
from taintline.rules.engine import SEVERITY_RANK, Finding
from taintline.taint import SessionAnalysis
from taintline.toolclass import EXFIL_SINKS

# sink classes that establish persistence or grant standing capability
_PERSIST_SINKS = {"file_write", "data_write"}
_CAPABILITY_SINKS = {"cloud_control", "identity", "code_execution", "financial", "destructive"}


@dataclass
class BlastRadius:
    tier: str  # none | low | elevated | severe | critical
    secrets_to_rotate: list[str] = field(default_factory=list)
    destinations_to_block: list[str] = field(default_factory=list)
    persistence: list[dict[str, Any]] = field(default_factory=list)
    capabilities_abused: list[str] = field(default_factory=list)
    affected_sessions: list[str] = field(default_factory=list)
    cross_session: bool = False
    remediation: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "secrets_to_rotate": self.secrets_to_rotate,
            "destinations_to_block": self.destinations_to_block,
            "persistence": self.persistence,
            "capabilities_abused": self.capabilities_abused,
            "affected_sessions": self.affected_sessions,
            "cross_session": self.cross_session,
            "remediation": self.remediation,
            "stats": self.stats,
        }


def assess_blast_radius(analyses: list[SessionAnalysis], findings: list[Finding], iocs: list[IOC]) -> BlastRadius:
    secrets: set[str] = set()
    destinations: set[str] = set()
    persistence: list[dict[str, Any]] = []
    capabilities: set[str] = set()
    affected: set[str] = set()
    cross_session = False
    confirmed_egress = False

    for i in iocs:
        if i.type == "secret_exposed":
            secrets.add(i.value)
        elif i.role in ("exfil_endpoint", "recipient"):
            destinations.add(i.value)

    for a in analyses:
        for f in a.flows:
            if f.details.get("cross_session"):
                cross_session = True
            if f.kind in ("data_flow", "chunked_data_flow") and f.sink_class in EXFIL_SINKS:
                # only count egress that was NOT blocked by a guard
                if not f.details.get("blocked"):
                    confirmed_egress = True
            if f.sink_class in _CAPABILITY_SINKS and f.confidence >= 0.3:
                capabilities.add(f.sink_class)
            if f.sink_class in _PERSIST_SINKS and f.confidence >= 0.4:
                persistence.append({"kind": f"tainted_{f.sink_class}", "session": a.session.id, "event": f.sink})

    for f in findings:
        affected.add(f.session_id)
        if "memory" in f.tags or f.rule_id.startswith("TL-MEM"):
            persistence.append({"kind": "poisoned_memory", "session": f.session_id, "events": f.events})
        if f.rule_id.startswith("TL-SCH"):
            persistence.append({"kind": "poisoned_tool", "session": f.session_id, "events": f.events})

    max_rank = max((f.rank for f in findings), default=-1)
    # tier: start from the worst finding severity, escalate on real impact
    tier = ["none", "low", "elevated", "severe", "critical"][max(0, min(4, max_rank))] if findings else "none"
    if confirmed_egress and secrets:
        tier = "critical"
    elif persistence and tier in ("none", "low", "elevated"):
        tier = "severe"
    elif capabilities and tier in ("none", "low"):
        tier = "severe"

    remediation = _remediation(secrets, destinations, persistence, capabilities, confirmed_egress, cross_session)
    return BlastRadius(
        tier=tier,
        secrets_to_rotate=sorted(secrets),
        destinations_to_block=sorted(destinations),
        persistence=_dedupe_persistence(persistence),
        capabilities_abused=sorted(capabilities),
        affected_sessions=sorted(affected),
        cross_session=cross_session,
        remediation=remediation,
        stats={
            "findings": len(findings),
            "critical_or_high": sum(1 for f in findings if f.rank >= SEVERITY_RANK["high"]),
            "confirmed_egress": confirmed_egress,
        },
    )


def _dedupe_persistence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen, out = set(), []
    for it in items:
        k = (it["kind"], it.get("session"), str(it.get("event") or it.get("events")))
        if k not in seen:
            seen.add(k)
            out.append(it)
    return out


def _remediation(secrets, destinations, persistence, capabilities, egress, cross_session) -> list[str]:
    steps: list[str] = []
    if secrets:
        steps.append(f"Rotate immediately: {', '.join(sorted(secrets))}. Assume every exposed credential is compromised.")
    if destinations:
        steps.append(f"Block and investigate destinations: {', '.join(sorted(destinations))}.")
    if any(p["kind"] == "poisoned_memory" for p in persistence):
        steps.append("Purge the agent's long-term memory of the poisoned keys; a wipe-and-reseed is safest.")
    if any(p["kind"] == "poisoned_tool" for p in persistence):
        steps.append("Remove or pin the poisoned tool/MCP server; audit the tool's supply chain and its publisher.")
    if any(p["kind"].startswith("tainted_file") or p["kind"].startswith("tainted_data") for p in persistence):
        steps.append("Review files/records the agent wrote under influence; they may re-inject on re-read.")
    if "cloud_control" in capabilities or "identity" in capabilities:
        steps.append("Audit cloud IAM for access keys, policy attachments or new principals created in the window.")
    if "code_execution" in capabilities:
        steps.append("Treat hosts where the agent ran code as potentially compromised; review command history.")
    if cross_session:
        steps.append("This is a multi-session attack; scope the investigation across the agent's full history, not one session.")
    if egress:
        steps.append("Confirm what left via network/DLP logs and notify per your data-breach policy if PII/regulated data is involved.")
    steps.append("Preserve the trace and its evidence pack (hash-chained) before remediating, for the incident record.")
    return steps
