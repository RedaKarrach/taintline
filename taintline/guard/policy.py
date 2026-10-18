"""Guard policy: declarative YAML deciding what happens to a tool call.

A policy is an ordered list of rules. Each rule has an ``action`` and a ``when``
block whose conditions are ANDed. Every matching rule contributes its action;
the strongest one wins (block > require_approval > log > allow). Allowlists
override everything. See ``default_policy.yaml`` for a commented example.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from taintline.rules.engine import SEVERITY_RANK, Finding
from taintline.taint import Flow
from taintline.toolclass import EXFIL_SINKS, ToolInfo

ACTION_RANK = {"allow": 0, "log": 1, "require_approval": 2, "block": 3}
DEFAULT_POLICY_PATH = os.path.join(os.path.dirname(__file__), "default_policy.yaml")

_CONDITION_KEYS = {
    "min_severity",
    "rule_ids",
    "tags",
    "flow_kind",
    "data_class",
    "sink_class",
    "unauthorized_destination",
    "min_confidence",
    "tool",
    "poisoned_tool",
    "secret_fragment",
    "memory_injection",
}


class PolicyError(ValueError):
    pass


@dataclass
class CallContext:
    """Everything the policy may look at for one pending tool call."""

    tool: str
    info: ToolInfo
    destinations: set[str]
    destination_authorized: bool
    flows: list[Flow]
    findings: list[Finding]
    poisoned_tool: bool
    secret_fragment_chars: int  # longest secret fragment carried by the call (characters)
    secret_fragment_kinds: list[str]
    memory_write_score: float = 0.0  # injection score of the value, if this call writes agent memory
    memory_write_signals: list[str] = field(default_factory=list)


@dataclass
class PolicyRule:
    name: str
    action: str
    when: dict[str, Any]
    description: str = ""

    def matches(self, ctx: CallContext) -> tuple[bool, str]:
        w = self.when
        reasons: list[str] = []

        if "tool" in w:
            pats = _as_list(w["tool"])
            if not any(fnmatch.fnmatchcase(ctx.tool.lower(), p.lower()) for p in pats):
                return False, ""
        if w.get("poisoned_tool") and not ctx.poisoned_tool:
            return False, ""
        if w.get("poisoned_tool"):
            reasons.append("tool description carries injection payload")

        if "sink_class" in w:
            wanted = _as_list(w["sink_class"])
            sc = ctx.info.sink_class
            ok = sc is not None and (sc in wanted or "*" in wanted or ("any_exfil" in wanted and sc in EXFIL_SINKS))
            if not ok:
                return False, ""
        if w.get("unauthorized_destination") and (ctx.destination_authorized or not ctx.destinations):
            return False, ""

        if "memory_injection" in w:
            need = float((w["memory_injection"] or {}).get("min_score", 0.3))
            if not ctx.info.is_memory_write or ctx.memory_write_score < need:
                return False, ""
            reasons.append(
                f"memory write carries injection signals ({', '.join(ctx.memory_write_signals)}; score {ctx.memory_write_score:.2f})"
            )

        if "secret_fragment" in w:
            need = int((w["secret_fragment"] or {}).get("min_chars", 8))
            if ctx.secret_fragment_chars < need:
                return False, ""
            reasons.append(
                f"carries {ctx.secret_fragment_chars} chars of a known secret ({', '.join(ctx.secret_fragment_kinds) or 'secret'})"
            )

        finding_keys = {"min_severity", "rule_ids", "tags"} & w.keys()
        if finding_keys:
            hits = [f for f in ctx.findings if _finding_ok(f, w)]
            if not hits:
                return False, ""
            reasons.extend(f"{f.rule_id} ({f.severity}, conf {f.confidence:.2f}): {f.title}" for f in hits)

        flow_keys = {"flow_kind", "data_class", "min_confidence"} & w.keys()
        if flow_keys:
            hits = [f for f in ctx.flows if _flow_ok(f, w)]
            if not hits:
                return False, ""
            reasons.extend(f"{f.kind} {f.source_class}->{f.sink_class} conf {f.confidence:.2f}" for f in hits)

        return True, "; ".join(reasons) or self.description or self.name


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    return [v] if isinstance(v, str) else [str(x) for x in v]


def _finding_ok(f: Finding, w: dict[str, Any]) -> bool:
    if "min_severity" in w and SEVERITY_RANK[f.severity] < SEVERITY_RANK[w["min_severity"]]:
        return False
    if "rule_ids" in w and f.rule_id not in _as_list(w["rule_ids"]):
        return False
    if "tags" in w and not set(_as_list(w["tags"])) & set(f.tags):
        return False
    return True


def _flow_ok(f: Flow, w: dict[str, Any]) -> bool:
    if "flow_kind" in w and f.kind not in _as_list(w["flow_kind"]):
        return False
    if "data_class" in w and f.source_class not in _as_list(w["data_class"]):
        return False
    if "min_confidence" in w and f.confidence < float(w["min_confidence"]):
        return False
    return True


@dataclass
class PolicyVerdict:
    action: str
    matched: list[tuple[str, str, str]] = field(default_factory=list)  # (rule name, action, reason)
    allowlisted: str | None = None


@dataclass
class Policy:
    rules: list[PolicyRule]
    mode: str = "enforce"
    default_action: str = "allow"
    on_approval_unavailable: str = "block"
    poisoned_tool_threshold: float = 0.3
    allow_tools: list[str] = field(default_factory=list)
    allow_destinations: list[str] = field(default_factory=list)
    neutralize_beacons: bool = True
    redact_secrets: bool = True
    source: str = "<inline>"

    @classmethod
    def from_dict(cls, d: dict[str, Any], source: str = "<inline>") -> Policy:
        mode = d.get("mode", "enforce")
        if mode not in ("enforce", "monitor"):
            raise PolicyError(f"{source}: mode must be enforce|monitor, got {mode!r}")
        rules = []
        for i, r in enumerate(d.get("rules") or []):
            name = r.get("name") or f"rule-{i}"
            action = r.get("action")
            if action not in ACTION_RANK:
                raise PolicyError(f"{source}: rule {name!r} has invalid action {action!r}")
            when = dict(r.get("when") or {})
            unknown = set(when) - _CONDITION_KEYS
            if unknown:
                raise PolicyError(f"{source}: rule {name!r} has unknown conditions {sorted(unknown)}")
            if "min_severity" in when and when["min_severity"] not in SEVERITY_RANK:
                raise PolicyError(f"{source}: rule {name!r} has invalid min_severity")
            rules.append(PolicyRule(name=name, action=action, when=when, description=str(r.get("description", "")).strip()))
        allow = d.get("allow") or {}
        default_action = d.get("default_action", "allow")
        if default_action not in ACTION_RANK:
            raise PolicyError(f"{source}: invalid default_action {default_action!r}")
        unavailable = d.get("on_approval_unavailable", "block")
        if unavailable not in ("block", "allow"):
            raise PolicyError(f"{source}: on_approval_unavailable must be block|allow")
        return cls(
            rules=rules,
            mode=mode,
            default_action=default_action,
            on_approval_unavailable=unavailable,
            poisoned_tool_threshold=float(d.get("poisoned_tool_threshold", 0.3)),
            allow_tools=list(allow.get("tools") or []),
            allow_destinations=list(allow.get("destinations") or []),
            neutralize_beacons=bool((d.get("output") or {}).get("neutralize_beacons", True)),
            redact_secrets=bool((d.get("output") or {}).get("redact_secrets", True)),
            source=source,
        )

    def host_allowlisted(self, host: str) -> bool:
        return any(fnmatch.fnmatchcase(host.lower(), p.lower()) for p in self.allow_destinations)

    @classmethod
    def from_yaml(cls, path: str) -> Policy:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {}, source=path)

    @classmethod
    def default(cls) -> Policy:
        return cls.from_yaml(DEFAULT_POLICY_PATH)

    def _allowlisted(self, ctx: CallContext) -> str | None:
        tool = ctx.tool.lower()
        if any(fnmatch.fnmatchcase(tool, p.lower()) for p in self.allow_tools):
            return f"tool {ctx.tool} is allowlisted"
        if ctx.destinations and self.allow_destinations:
            if all(any(fnmatch.fnmatchcase(d, p.lower()) for p in self.allow_destinations) for d in ctx.destinations):
                return "all destinations are allowlisted"
        return None

    def decide(self, ctx: CallContext) -> PolicyVerdict:
        listed = self._allowlisted(ctx)
        if listed:
            return PolicyVerdict(action="allow", allowlisted=listed)
        verdict = PolicyVerdict(action=self.default_action)
        for rule in self.rules:
            ok, reason = rule.matches(ctx)
            if not ok:
                continue
            verdict.matched.append((rule.name, rule.action, reason))
            if ACTION_RANK[rule.action] > ACTION_RANK[verdict.action]:
                verdict.action = rule.action
        return verdict
