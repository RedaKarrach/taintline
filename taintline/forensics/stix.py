"""Export findings and IOCs as a STIX 2.1 bundle.

STIX is the lingua franca for sharing threat intel with a TIP / SIEM / ISAC.
taintline maps its world onto standard SDOs/SCOs:

* each distinct rule that fired -> an ``attack-pattern`` (carrying its ATLAS /
  ATT&CK / OWASP references as ``external_references``);
* each IOC -> the appropriate Cyber-observable (``domain-name``, ``ipv4-addr``,
  ``email-addr``, ``url``) plus an ``indicator`` with a STIX pattern;
* the incident as a whole -> a ``report`` SDO tying everything together.

IDs are deterministic (UUIDv5 over stable content) so re-exporting the same
evidence yields the same bundle - important for de-duplication in a TIP.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from taintline.forensics.ioc import IOC
from taintline.mappings import FRAMEWORKS, describe
from taintline.rules.engine import Finding

_NS = uuid.UUID("b6f1e2a4-0c3d-5e6f-8a9b-0c1d2e3f4a5b")  # taintline namespace
_NOW = None


def _ts() -> str:
    return (_NOW or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")


def _id(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + '|' + '|'.join(parts))}"


_STIX_SOURCE = {"mitre_attack": "mitre-attack", "mitre_atlas": "mitre-atlas", "owasp_llm": "OWASP", "nist_ai_rmf": "NIST"}


def _external_refs(mappings: dict[str, list[str]]) -> list[dict[str, Any]]:
    refs = []
    for fw, ids in mappings.items():
        src = _STIX_SOURCE.get(fw, fw)
        name = FRAMEWORKS.get(fw, (fw, {}))[0]
        for ident in ids:
            refs.append({"source_name": src, "external_id": ident, "description": describe(fw, ident) + f" [{name}]"})
    return refs


def _observable(ioc: IOC) -> dict[str, Any] | None:
    t = ioc.type
    if t == "domain":
        return {"type": "domain-name", "id": _id("domain-name", ioc.value), "spec_version": "2.1", "value": ioc.value}
    if t == "ipv4":
        return {"type": "ipv4-addr", "id": _id("ipv4-addr", ioc.value), "spec_version": "2.1", "value": ioc.value}
    if t == "email":
        return {"type": "email-addr", "id": _id("email-addr", ioc.value), "spec_version": "2.1", "value": ioc.value}
    if t == "url_path" and "://" in ioc.value:
        return {"type": "url", "id": _id("url", ioc.value), "spec_version": "2.1", "value": ioc.value}
    return None


_PATTERN = {
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "ipv4": lambda v: f"[ipv4-addr:value = '{v}']",
    "email": lambda v: f"[email-addr:value = '{v}']",
    "url_path": lambda v: f"[url:value = '{v}']",
}


def to_stix_bundle(findings: list[Finding], iocs: list[IOC], incident_name: str = "taintline agent incident") -> dict[str, Any]:
    objects: list[dict[str, Any]] = []
    created = _ts()
    ref_ids: list[str] = []

    # attack-patterns, one per distinct rule
    by_rule: dict[str, Finding] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, f)
    for rid, f in sorted(by_rule.items()):
        ap_id = _id("attack-pattern", rid)
        objects.append(
            {
                "type": "attack-pattern",
                "id": ap_id,
                "spec_version": "2.1",
                "created": created,
                "modified": created,
                "name": f"{rid}: {f.title}",
                "description": f.description or f.title,
                "external_references": _external_refs(f.mappings),
                "labels": f.tags or ["taintline"],
            }
        )
        ref_ids.append(ap_id)

    # indicators + observables
    for ioc in iocs:
        pat = _PATTERN.get(ioc.type)
        if not pat:
            continue
        ind_id = _id("indicator", ioc.type, ioc.value)
        objects.append(
            {
                "type": "indicator",
                "id": ind_id,
                "spec_version": "2.1",
                "created": created,
                "modified": created,
                "name": f"{ioc.role}: {ioc.value}",
                "pattern": pat(ioc.value),
                "pattern_type": "stix",
                "valid_from": created,
                "labels": ["malicious-activity"],
                "description": f"taintline IOC ({ioc.type}/{ioc.role}) seen in sessions {sorted(ioc.sessions)}",
            }
        )
        ref_ids.append(ind_id)
        obs = _observable(ioc)
        if obs:
            objects.append(obs)
            ref_ids.append(obs["id"])

    report = {
        "type": "report",
        "id": _id("report", incident_name, created),
        "spec_version": "2.1",
        "created": created,
        "modified": created,
        "name": incident_name,
        "report_types": ["threat-report", "attack-pattern"],
        "published": created,
        "object_refs": ref_ids or [_id("report", "empty")],
        "description": f"{len(by_rule)} distinct detections, {len(iocs)} indicators, produced by taintline.",
    }
    objects.insert(0, report)

    return {"type": "bundle", "id": f"bundle--{uuid.uuid5(_NS, created + incident_name)}", "objects": objects}
