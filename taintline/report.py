"""Report writers: Markdown, JSON, SARIF 2.1.0, CSV timeline and a
self-contained HTML page."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from taintline import __version__
from taintline.anomaly import AnomalyResult
from taintline.graph import attack_paths
from taintline.mappings import describe, framework_title
from taintline.rules.engine import SEVERITY_RANK, Finding
from taintline.taint import SessionAnalysis

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def findings_json(
    analyses: list[SessionAnalysis],
    findings: list[Finding],
    anomalies: list[AnomalyResult],
    manifest: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema": "taintline-findings/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": {"name": "taintline", "version": __version__},
        "evidence": {k: v for k, v in (manifest or {}).items() if k != "events"}
        | ({"events": {k: v for k, v in manifest["events"].items() if k != "chain_links"}} if manifest else {}),
        "summary": summary(findings, anomalies),
        "sessions": [
            {
                "session_id": a.session.id,
                "events": len(a.events),
                "start_ts": a.session.start_ts,
                "end_ts": a.session.end_ts,
                "sources": [e.id for e in a.sources()],
                "sinks": [e.id for e in a.sinks()],
                "payloads": [{"origin": p.origin, "class": p.data_class, "secret_kinds": list(p.secret_kinds)} for p in a.payloads],
                "flows": [f.to_dict() for f in a.flows],
                "attack_paths": attack_paths(a),
            }
            for a in analyses
        ],
        "findings": [f.to_dict() for f in findings],
        "anomaly": [r.to_dict() for r in anomalies],
    }


def summary(findings: list[Finding], anomalies: list[AnomalyResult]) -> dict[str, Any]:
    by_sev = Counter(f.severity for f in findings)
    by_rule = Counter(f.rule_id for f in findings)
    sessions_hit = sorted({f.session_id for f in findings if f.rank >= SEVERITY_RANK["high"]})
    return {
        "findings_total": len(findings),
        "by_severity": {s: by_sev.get(s, 0) for s in SEV_ORDER},
        "by_rule": dict(sorted(by_rule.items())),
        "sessions_with_high_or_critical": sessions_hit,
        "anomalous_sessions": [r.session_id for r in anomalies if r.is_anomalous],
    }


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(findings: list[Finding], trace_path: str) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {"severity": f.severity, "tags": f.tags, "mappings": f.mappings},
            },
        )
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title} (session {f.session_id}, confidence {f.confidence:.2f})"},
                "locations": [
                    {
                        "physicalLocation": {"artifactLocation": {"uri": trace_path.replace("\\", "/")}},
                        "logicalLocations": [{"name": eid, "kind": "event"} for eid in f.events],
                    }
                ],
                "properties": {"session_id": f.session_id, "confidence": f.confidence, "evidence": f.evidence},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "taintline", "version": __version__, "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


# ---------------------------------------------------------------------------
# CSV timeline
# ---------------------------------------------------------------------------


def write_timeline_csv(analyses: list[SessionAnalysis], findings: list[Finding], path: str) -> None:
    hits: dict[str, list[str]] = {}
    for f in findings:
        for eid in f.events:
            hits.setdefault(eid, []).append(f.rule_id)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "session_id", "seq", "event_id", "kind", "tool", "role", "max_taint", "injection_score", "secrets", "rules", "excerpt"])
        for a in analyses:
            for e in a.events:
                info = a.info(e)
                role = "source" if (e.kind == "tool_result" and info.is_source) else "sink" if (e.kind == "tool_call" and info.is_sink) else ""
                inj = a.injection.get(e.id)
                w.writerow(
                    [
                        e.ts,
                        e.session_id,
                        e.seq,
                        e.id,
                        e.kind,
                        e.tool or "",
                        role,
                        f"{a.max_taint_confidence(e.id):.2f}",
                        f"{inj.score:.2f}" if inj else "",
                        ";".join(s.kind for s in a.secrets.get(e.id, [])),
                        ";".join(hits.get(e.id, [])),
                        e.short(120),
                    ]
                )


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _sev_badge(sev: str) -> str:
    return {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}[sev]


def to_markdown(
    analyses: list[SessionAnalysis],
    findings: list[Finding],
    anomalies: list[AnomalyResult],
    manifest: dict[str, Any] | None,
    trace_path: str,
) -> str:
    s = summary(findings, anomalies)
    by_session: dict[str, SessionAnalysis] = {a.session.id: a for a in analyses}
    lines: list[str] = []
    lines.append("# taintline forensic report")
    lines.append("")
    lines.append(f"- **Trace:** `{trace_path}`")
    if manifest:
        lines.append(f"- **Evidence SHA-256:** `{manifest['source']['sha256']}`")
        lines.append(f"- **Hash-chain head:** `{manifest['events']['chain_head']}`")
    lines.append(f"- **Sessions:** {len(analyses)} · **Events:** {sum(len(a.events) for a in analyses)}")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).isoformat(timespec='seconds')} by taintline {__version__}")
    lines.append("")
    lines.append("## Executive summary")
    lines.append("")
    lines.append("| Severity | Findings |")
    lines.append("|---|---:|")
    for sev in SEV_ORDER:
        lines.append(f"| {_sev_badge(sev)} | {s['by_severity'][sev]} |")
    lines.append("")
    if s["sessions_with_high_or_critical"]:
        lines.append(f"**Sessions needing immediate review:** {', '.join(f'`{x}`' for x in s['sessions_with_high_or_critical'])}")
    else:
        lines.append("No high or critical findings.")
    if s["anomalous_sessions"]:
        lines.append(f"**Behaviourally anomalous sessions (baseline model):** {', '.join(f'`{x}`' for x in s['anomalous_sessions'])}")
    lines.append("")

    # ---- findings
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_None._")
    for i, f in enumerate(findings, 1):
        a = by_session.get(f.session_id)
        lines.append(f"### {i}. {_sev_badge(f.severity)} · {f.rule_id} · {f.title}")
        lines.append("")
        lines.append(f"- **Session:** `{f.session_id}` · **Confidence:** {f.confidence:.2f}")
        if f.mappings:
            refs = "; ".join(f"{framework_title(k)}: " + ", ".join(describe(k, v) for v in vals) for k, vals in f.mappings.items())
            lines.append(f"- **Mappings:** {refs}")
        if f.description:
            lines.append(f"- **Why it matters:** {f.description}")
        lines.append("")
        lines.append("**Evidence chain**")
        lines.append("")
        lines.append("| # | Event | Kind | Tool | Excerpt |")
        lines.append("|---|---|---|---|---|")
        for j, eid in enumerate(f.events, 1):
            ev = a.event(eid) if a else None
            if ev is None:
                lines.append(f"| {j} | `{eid}` | external | | _(earlier session)_ |")
            else:
                lines.append(f"| {j} | `{eid}` | {ev.kind} | {ev.tool or ''} | {_md_cell(ev.short(110))} |")
        lines.append("")
        flow = f.evidence.get("flow")
        if flow:
            d = flow.get("details", {})
            bits = []
            if "taint_kind" in d:
                bits.append(f"taint kind **{d['taint_kind']}** over {d.get('hops', '?')} model turn(s)")
            if "coverage" in d:
                bits.append(f"**{d['coverage'] * 100:.0f}%** of the secret present in the call")
            if "cumulative_coverage" in d:
                bits.append(f"**{d['cumulative_coverage'] * 100:.0f}%** of the secret leaked across {d['calls']} calls")
            if d.get("destinations"):
                auth = "named by the principal" if d.get("destination_authorized") else "**never named by the principal**"
                bits.append(f"destination(s) {', '.join(f'`{x}`' for x in d['destinations'])} {auth}")
            if d.get("signals"):
                bits.append(f"injection signals: {', '.join(d['signals'])}")
            if d.get("cross_session"):
                bits.append("**cross-session** (origin in an earlier session)")
            if bits:
                lines.append("- " + "\n- ".join(bits))
                lines.append("")
        for key in ("injection", "secrets", "count", "repeats", "steps", "tool", "destinations"):
            if key in f.evidence and key not in ("steps",):
                lines.append(f"- **{key}:** `{json.dumps(f.evidence[key], ensure_ascii=False)[:300]}`")
        lines.append("")

    # ---- anomaly
    if anomalies:
        lines.append("## Behavioural anomaly scores")
        lines.append("")
        lines.append("| Session | Score | Anomalous | Markov NLL | Top deviating features |")
        lines.append("|---|---:|:---:|---:|---|")
        for r in sorted(anomalies, key=lambda r: -r.score):
            feats = ", ".join(f"{t['feature']}={t['value']} (z={t['z']:+.1f})" for t in r.top_features) or "—"
            lines.append(f"| `{r.session_id}` | {r.score:.3f} | {'yes' if r.is_anomalous else 'no'} | {r.markov_nll:.2f} | {feats} |")
        lines.append("")

    # ---- sessions
    lines.append("## Session inventory")
    lines.append("")
    lines.append("| Session | Events | Untrusted sources | Sinks | Payloads | Flows | Findings |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    fcount = Counter(f.session_id for f in findings)
    for a in analyses:
        lines.append(
            f"| `{a.session.id}` | {len(a.events)} | {len(a.sources())} | {len(a.sinks())} | {len(a.payloads)} | {len(a.flows)} | {fcount.get(a.session.id, 0)} |"
        )
    lines.append("")

    # ---- compliance view
    lines.append("## Framework coverage of findings")
    lines.append("")
    cov: dict[str, Counter] = {}
    for f in findings:
        for fw, ids in f.mappings.items():
            cov.setdefault(fw, Counter()).update(ids)
    if not cov:
        lines.append("_No mapped findings._")
    for fw, counter in cov.items():
        lines.append(f"**{framework_title(fw)}**")
        lines.append("")
        for ident, n in counter.most_common():
            lines.append(f"- {describe(fw, ident)} — {n} finding(s)")
        lines.append("")
    lines.append("---")
    lines.append("_Framework identifiers are best-effort labels for triage, not a compliance attestation._")
    return "\n".join(lines) + "\n"


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


# ---------------------------------------------------------------------------
# HTML (self-contained, no external assets)
# ---------------------------------------------------------------------------

_CSS = """
:root{--bg:#0f1117;--fg:#e6e6e6;--muted:#9aa0a6;--card:#171a23;--crit:#d64545;--high:#e08a1e;--med:#d4b11f;--low:#2f7fd3;--info:#6c757d;--line:#262a36}
@media (prefers-color-scheme: light){:root{--bg:#fafafa;--fg:#1b1f27;--muted:#5f6368;--card:#fff;--line:#e3e5ea}}
body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1100px;margin:auto}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.meta{color:var(--muted);font-size:13px}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:var(--card);padding:1px 5px;border-radius:4px}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:110px}
.tile b{display:block;font-size:26px}.tile span{font-size:12px;color:var(--muted);text-transform:uppercase}
.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:8px;padding:14px 16px;margin:12px 0}
.finding.critical{border-left-color:var(--crit)}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--med)}.finding.low{border-left-color:var(--low)}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;color:#fff;background:var(--info);margin-right:8px}
.badge.critical{background:var(--crit)}.badge.high{background:var(--high)}.badge.medium{background:var(--med);color:#111}.badge.low{background:var(--low)}
table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.chain td:first-child{color:var(--muted);width:30px}.why{color:var(--muted);font-size:13px;margin:6px 0}
"""


def to_html(
    analyses: list[SessionAnalysis],
    findings: list[Finding],
    anomalies: list[AnomalyResult],
    manifest: dict[str, Any] | None,
    trace_path: str,
) -> str:
    s = summary(findings, anomalies)
    by_session = {a.session.id: a for a in analyses}
    h = html.escape
    out = [f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>taintline report</title><style>{_CSS}</style></head><body>"]
    out.append("<h1>taintline forensic report</h1>")
    out.append(f"<div class='meta'>Trace <code>{h(trace_path)}</code>")
    if manifest:
        out.append(f" · evidence SHA-256 <code>{manifest['source']['sha256'][:16]}…</code> · chain head <code>{manifest['events']['chain_head'][:16]}…</code>")
    out.append(f" · {len(analyses)} sessions · {sum(len(a.events) for a in analyses)} events · taintline {__version__}</div>")
    out.append("<div class='tiles'>")
    for sev in SEV_ORDER:
        out.append(f"<div class='tile'><b>{s['by_severity'][sev]}</b><span>{sev}</span></div>")
    out.append(f"<div class='tile'><b>{len(s['anomalous_sessions'])}</b><span>anomalous sessions</span></div>")
    out.append("</div>")
    out.append("<h2>Findings</h2>")
    if not findings:
        out.append("<p class='meta'>None.</p>")
    for f in findings:
        a = by_session.get(f.session_id)
        out.append(f"<div class='finding {f.severity}'><span class='badge {f.severity}'>{f.severity}</span><b>{h(f.rule_id)}</b> · {h(f.title)}")
        out.append(f"<div class='meta'>session <code>{h(f.session_id)}</code> · confidence {f.confidence:.2f}")
        if f.mappings:
            refs = " · ".join(f"{h(framework_title(k))}: {h(', '.join(describe(k, v) for v in vals))}" for k, vals in f.mappings.items())
            out.append(f" · {refs}")
        out.append("</div>")
        if f.description:
            out.append(f"<div class='why'>{h(f.description)}</div>")
        out.append("<table class='chain'><tr><th>#</th><th>Event</th><th>Kind</th><th>Tool</th><th>Excerpt</th></tr>")
        for j, eid in enumerate(f.events, 1):
            ev = a.event(eid) if a else None
            if ev is None:
                out.append(f"<tr><td>{j}</td><td><code>{h(eid)}</code></td><td>external</td><td></td><td><i>earlier session</i></td></tr>")
            else:
                out.append(f"<tr><td>{j}</td><td><code>{h(eid)}</code></td><td>{h(ev.kind)}</td><td>{h(ev.tool or '')}</td><td>{h(ev.short(140))}</td></tr>")
        out.append("</table>")
        flow = f.evidence.get("flow")
        if flow:
            d = flow.get("details", {})
            bits = []
            if "coverage" in d:
                bits.append(f"{d['coverage'] * 100:.0f}% of the secret present in the call")
            if "cumulative_coverage" in d:
                bits.append(f"{d['cumulative_coverage'] * 100:.0f}% of the secret leaked across {d['calls']} calls")
            if d.get("destinations"):
                auth = "named by the principal" if d.get("destination_authorized") else "<b>never named by the principal</b>"
                bits.append("destination(s) " + ", ".join(f"<code>{h(x)}</code>" for x in d["destinations"]) + f" {auth}")
            if d.get("signals"):
                bits.append("injection signals: " + h(", ".join(d["signals"])))
            if d.get("cross_session"):
                bits.append("<b>cross-session</b> origin")
            if bits:
                out.append("<div class='why'>" + " · ".join(bits) + "</div>")
        out.append("</div>")
    if anomalies:
        out.append("<h2>Behavioural anomaly scores</h2><table><tr><th>Session</th><th>Score</th><th>Anomalous</th><th>Markov NLL</th><th>Top deviating features</th></tr>")
        for r in sorted(anomalies, key=lambda r: -r.score):
            feats = ", ".join(f"{t['feature']}={t['value']} (z={t['z']:+.1f})" for t in r.top_features) or "—"
            out.append(f"<tr><td><code>{h(r.session_id)}</code></td><td>{r.score:.3f}</td><td>{'yes' if r.is_anomalous else 'no'}</td><td>{r.markov_nll:.2f}</td><td>{h(feats)}</td></tr>")
        out.append("</table>")
    out.append("<h2>Session inventory</h2><table><tr><th>Session</th><th>Events</th><th>Untrusted sources</th><th>Sinks</th><th>Payloads</th><th>Flows</th><th>Findings</th></tr>")
    fcount = Counter(f.session_id for f in findings)
    for a in analyses:
        out.append(
            f"<tr><td><code>{h(a.session.id)}</code></td><td>{len(a.events)}</td><td>{len(a.sources())}</td><td>{len(a.sinks())}</td><td>{len(a.payloads)}</td><td>{len(a.flows)}</td><td>{fcount.get(a.session.id, 0)}</td></tr>"
        )
    out.append("</table><p class='meta'>Framework identifiers are best-effort labels for triage, not a compliance attestation.</p></body></html>")
    return "".join(out)
