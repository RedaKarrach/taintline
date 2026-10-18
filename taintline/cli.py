"""taintline command-line interface.

Commands
--------
analyze     run taint + rules (+ anomaly) over a trace, write reports
baseline    fit a behavioural baseline from benign traces
graph       export the provenance / attack graph (DOT or JSON)
custody     build or verify an evidence manifest
simulate    emit synthetic benign and attack traces
evaluate    score the rule pack + anomaly model on labelled scenarios
rules       list the loaded rule pack
"""

from __future__ import annotations

import json
import os
import sys

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from taintline import __version__
from taintline.adapters import load_openai, load_otel
from taintline.anomaly import Baseline
from taintline.custody import build_manifest, verify_manifest
from taintline.graph import build_graph, to_dot, to_json
from taintline.report import (
    findings_json,
    summary,
    to_html,
    to_markdown,
    to_sarif,
    write_timeline_csv,
)
from taintline.rules.engine import SEVERITY_RANK, RuleEngine, load_rules
from taintline.schema import dump_jsonl, group_sessions, load_jsonl
from taintline.taint import TaintEngine
from taintline.toolclass import ToolClassifier

console = Console()
err = Console(stderr=True)

SEV_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _load_events(path: str, fmt: str) -> list:
    if fmt == "auto":
        if path.endswith(".jsonl") or path.endswith(".ndjson"):
            fmt = "jsonl"
        elif path.endswith(".json"):
            fmt = "openai"
        else:
            fmt = "jsonl"
    if fmt == "jsonl":
        return load_jsonl(path)
    if fmt == "openai":
        return load_openai(path)
    if fmt == "otel":
        return load_otel(path)
    raise click.ClickException(f"unknown format {fmt!r}")


def _build(events, rule_paths, no_builtin, tool_config=None):
    classifier = ToolClassifier.from_yaml(tool_config) if tool_config else ToolClassifier()
    engine = TaintEngine(classifier)
    sessions = group_sessions(events)
    analyses = engine.analyze_sessions(sessions)
    rules = load_rules(list(rule_paths), include_builtin=not no_builtin)
    findings = RuleEngine(rules).evaluate_all(analyses)
    return analyses, findings


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="taintline")
def main() -> None:
    """Forensic taint tracking and detection for AI agent tool-use traces."""


# ---------------------------------------------------------------------------
@main.command()
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True), help="Extra rule file/dir (repeatable).")
@click.option("--no-builtin", is_flag=True, help="Do not load the built-in rule pack.")
@click.option("--tool-config", type=click.Path(exists=True), help="YAML overriding tool source/sink/sensitive classes.")
@click.option("--baseline", "baseline_path", type=click.Path(exists=True), help="Anomaly baseline JSON to score against.")
@click.option("--out", "out_dir", type=click.Path(file_okay=False), help="Write md/json/sarif/csv/html reports here.")
@click.option("--min-severity", type=click.Choice(["info", "low", "medium", "high", "critical"]), default="info")
@click.option("--fail-on", type=click.Choice(["never", "info", "low", "medium", "high", "critical"]), default="never", help="Exit non-zero if a finding at/above this severity exists (CI gate).")
@click.option("--manifest/--no-manifest", default=True, help="Build an evidence manifest alongside reports.")
@click.option("--dashboard", "want_dashboard", is_flag=True, help="Also write an interactive HTML investigation dashboard.")
@click.option("--evidence-pack", "pack_out", type=click.Path(dir_okay=False), help="Write a signed evidence pack (JSON) here.")
@click.option("--sign-key", type=click.Path(exists=True), help="Ed25519 private key PEM to sign the evidence pack.")
@click.option("--guard-replay", is_flag=True, help="Include a guard replay (where would enforcement have stopped it?).")
@click.option("--quiet", is_flag=True)
def analyze(trace, fmt, rule_paths, no_builtin, tool_config, baseline_path, out_dir, min_severity, fail_on, manifest, want_dashboard, pack_out, sign_key, guard_replay, quiet):
    """Analyze a TRACE and report security findings."""
    from taintline.forensics import assess_blast_radius, extract_iocs, to_stix_bundle

    events = _load_events(trace, fmt)
    if not events:
        raise click.ClickException("no events parsed from trace")
    analyses, findings = _build(events, rule_paths, no_builtin, tool_config)
    min_rank = SEVERITY_RANK[min_severity]
    findings = [f for f in findings if f.rank >= min_rank]

    anomalies = []
    if baseline_path:
        base = Baseline.load(baseline_path)
        anomalies = [base.score(a) for a in analyses]

    man = build_manifest(trace, events) if manifest else None
    iocs = extract_iocs(analyses)
    blast = assess_blast_radius(analyses, findings, iocs)
    replay_results = None
    if guard_replay:
        from taintline.guard import replay as _replay

        replay_results = _replay(events)

    if not quiet:
        _print_findings(findings)
        _print_anomalies(anomalies)
        _print_blast(blast)

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(trace))[0]
        with open(os.path.join(out_dir, f"{base_name}.report.md"), "w", encoding="utf-8") as fh:
            fh.write(to_markdown(analyses, findings, anomalies, man, trace))
        with open(os.path.join(out_dir, f"{base_name}.findings.json"), "w", encoding="utf-8") as fh:
            json.dump(findings_json(analyses, findings, anomalies, man), fh, indent=2, ensure_ascii=False)
        with open(os.path.join(out_dir, f"{base_name}.sarif"), "w", encoding="utf-8") as fh:
            json.dump(to_sarif(findings, trace), fh, indent=2, ensure_ascii=False)
        write_timeline_csv(analyses, findings, os.path.join(out_dir, f"{base_name}.timeline.csv"))
        with open(os.path.join(out_dir, f"{base_name}.report.html"), "w", encoding="utf-8") as fh:
            fh.write(to_html(analyses, findings, anomalies, man, trace))
        with open(os.path.join(out_dir, f"{base_name}.iocs.json"), "w", encoding="utf-8") as fh:
            json.dump([i.to_dict() for i in iocs], fh, indent=2, ensure_ascii=False)
        with open(os.path.join(out_dir, f"{base_name}.stix.json"), "w", encoding="utf-8") as fh:
            json.dump(to_stix_bundle(findings, iocs), fh, indent=2, ensure_ascii=False)
        with open(os.path.join(out_dir, f"{base_name}.blast-radius.json"), "w", encoding="utf-8") as fh:
            json.dump(blast.to_dict(), fh, indent=2, ensure_ascii=False)
        if man:
            with open(os.path.join(out_dir, f"{base_name}.manifest.json"), "w", encoding="utf-8") as fh:
                json.dump(man, fh, indent=2, ensure_ascii=False)
        if want_dashboard:
            _write_dashboard(os.path.join(out_dir, f"{base_name}.dashboard.html"), analyses, findings, iocs, blast, anomalies, man, replay_results, title=f"taintline — {base_name}")
        if not quiet:
            console.print(f"[green]Reports written to[/green] {out_dir}")

    if want_dashboard and not out_dir:
        _write_dashboard(f"{os.path.splitext(trace)[0]}.dashboard.html", analyses, findings, iocs, blast, anomalies, man, replay_results)
        if not quiet:
            console.print(f"[green]Dashboard written[/green] -> {os.path.splitext(trace)[0]}.dashboard.html")

    if pack_out:
        _write_evidence_pack(pack_out, trace, events, analyses, findings, iocs, blast, man, sign_key, quiet)

    s = summary(findings, anomalies)
    if fail_on != "never":
        gate = SEVERITY_RANK[fail_on]
        if any(f.rank >= gate for f in findings):
            err.print(f"[red]CI gate: findings at or above {fail_on}.[/red]")
            sys.exit(2)


def _print_findings(findings) -> None:
    if not findings:
        console.print("[green]No findings.[/green]")
        return
    t = Table(title=f"taintline findings ({len(findings)})", show_lines=False, expand=True)
    t.add_column("Severity", no_wrap=True)
    t.add_column("Rule", no_wrap=True)
    t.add_column("Session", no_wrap=True)
    t.add_column("Conf", justify="right", no_wrap=True)
    t.add_column("Title")
    for f in findings:
        t.add_row(f"[{SEV_STYLE[f.severity]}]{f.severity.upper()}[/]", f.rule_id, f.session_id, f"{f.confidence:.2f}", f.title)
    console.print(t)


def _print_blast(blast) -> None:
    if blast.tier == "none":
        return
    style = {"critical": "bold white on red", "severe": "bold red", "elevated": "yellow", "low": "cyan"}.get(blast.tier, "white")
    console.print(f"\n[{style}] BLAST RADIUS: {blast.tier.upper()} [/]")
    if blast.secrets_to_rotate:
        console.print(f"  [bold]rotate:[/bold] {', '.join(blast.secrets_to_rotate)}")
    if blast.destinations_to_block:
        console.print(f"  [bold]block:[/bold] {', '.join(blast.destinations_to_block)}")
    for step in blast.remediation[:6]:
        console.print(f"  • {step}")


def _write_dashboard(path, analyses, findings, iocs, blast, anomalies, man, replay_results, title="taintline investigation"):
    from taintline.dashboard import build_dashboard, dashboard_payload

    payload = dashboard_payload(analyses, findings, iocs=iocs, blast_radius=blast, anomalies=anomalies, manifest=man, replay_results=replay_results, title=title)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_dashboard(payload))


def _write_evidence_pack(path, trace, events, analyses, findings, iocs, blast, man, sign_key, quiet):
    from taintline.forensics import build_evidence_pack, to_stix_bundle

    priv = pub = None
    if sign_key:
        from taintline.forensics.pack import load_private_key
        from cryptography.hazmat.primitives import serialization

        priv = open(sign_key, encoding="utf-8").read()
        pub = load_private_key(priv).public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    pack = build_evidence_pack(
        man or build_manifest(trace, events),
        [f.to_dict() for f in findings],
        [i.to_dict() for i in iocs],
        blast.to_dict(),
        to_stix_bundle(findings, iocs),
        private_pem=priv,
        public_pem=pub,
    )
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(pack, fh, indent=2, ensure_ascii=False)
    if not quiet:
        signed = "signed" if sign_key else "unsigned"
        console.print(f"[green]Evidence pack ({signed}) written[/green] -> {path}  digest {pack['digest']['value'][:16]}…")


def _print_anomalies(anomalies) -> None:
    flagged = [r for r in anomalies if r.is_anomalous]
    if not flagged:
        return
    t = Table(title="Behavioural anomalies", expand=True)
    t.add_column("Session", no_wrap=True)
    t.add_column("Score", justify="right")
    t.add_column("Markov NLL", justify="right")
    t.add_column("Top deviating features")
    for r in sorted(flagged, key=lambda r: -r.score):
        feats = ", ".join(f"{x['feature']}={x['value']}(z{x['z']:+.1f})" for x in r.top_features) or "-"
        t.add_row(r.session_id, f"{r.score:.3f}", f"{r.markov_nll:.2f}", feats)
    console.print(t)


# ---------------------------------------------------------------------------
@main.command()
@click.argument("traces", nargs=-1, type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--out", "out_path", required=True, type=click.Path(dir_okay=False), help="Where to write baseline JSON.")
@click.option("--generate", type=int, default=0, help="Instead of files, synthesize N benign sessions.")
def baseline(traces, fmt, out_path, generate):
    """Fit a behavioural baseline from benign TRACES (or synthesize them)."""
    events = []
    if generate:
        from taintline.simulate.synth import benign_session

        import random

        rng = random.Random(7)
        for i in range(generate):
            events.extend(benign_session(f"baseline-{i:04d}", rng=rng))
    for p in traces:
        events.extend(_load_events(p, fmt))
    if not events:
        raise click.ClickException("no events; pass trace files or --generate N")
    sessions = group_sessions(events)
    analyses = TaintEngine(ToolClassifier()).analyze_sessions(sessions)
    b = Baseline().fit(analyses)
    b.save(out_path)
    console.print(f"[green]Baseline fitted[/green] on {b.n_sessions} sessions -> {out_path} (threshold {b.threshold:.3f})")


# ---------------------------------------------------------------------------
@main.command()
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--no-builtin", is_flag=True)
@click.option("--as", "out_fmt", type=click.Choice(["dot", "json"]), default="dot")
@click.option("--out", "out_path", type=click.Path(dir_okay=False))
def graph(trace, fmt, rule_paths, no_builtin, out_fmt, out_path):
    """Export the provenance / attack graph as DOT or node-link JSON."""
    events = _load_events(trace, fmt)
    analyses, _ = _build(events, rule_paths, no_builtin)
    g = build_graph(analyses)
    text = to_dot(g) if out_fmt == "dot" else to_json(g)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        console.print(f"[green]Graph written[/green] -> {out_path} ({g.number_of_nodes()} nodes, {g.number_of_edges()} edges)")
    else:
        click.echo(text)


# ---------------------------------------------------------------------------
@main.group()
def custody():
    """Evidence chain-of-custody manifests."""


@custody.command("build")
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--out", "out_path", required=True, type=click.Path(dir_okay=False))
def custody_build(trace, fmt, out_path):
    """Build an evidence manifest (file hash + event hash chain)."""
    events = _load_events(trace, fmt)
    man = build_manifest(trace, events)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(man, fh, indent=2, ensure_ascii=False)
    console.print(f"[green]Manifest written[/green] -> {out_path}")
    console.print(f"  file sha256 : {man['source']['sha256']}")
    console.print(f"  chain head  : {man['events']['chain_head']}")


@custody.command("verify")
@click.argument("manifest", type=click.Path(exists=True, dir_okay=False))
@click.option("--trace", type=click.Path(exists=True, dir_okay=False), help="Trace to check (default: path in manifest).")
def custody_verify(manifest, trace):
    """Verify a trace against its manifest."""
    res = verify_manifest(manifest, trace)
    ok = res.get("ok")
    color = "green" if ok else "red"
    console.print(f"[{color}]file hash: {'OK' if res['file_hash_ok'] else 'MISMATCH'} | chain: {'OK' if res['chain_ok'] else 'BROKEN'}[/{color}]")
    if res.get("first_divergence"):
        console.print(f"[red]first divergence:[/red] {res['first_divergence']}")
    sys.exit(0 if ok else 3)


# ---------------------------------------------------------------------------
@main.command()
@click.option("--scenario", help="One scenario by name (default: full mixed dataset).")
@click.option("--benign", type=int, default=20, help="Benign sessions in the mixed dataset.")
@click.option("--seed", type=int, default=11)
@click.option("--out", "out_path", type=click.Path(dir_okay=False), help="Write JSONL here (default: stdout).")
@click.option("--list", "list_only", is_flag=True, help="List available scenarios and exit.")
def simulate(scenario, benign, seed, out_path, list_only):
    """Emit synthetic benign and attack traces (JSONL)."""
    from taintline.simulate.scenarios import SCENARIOS, build_dataset, get_scenario

    if list_only:
        t = Table(title="scenarios")
        t.add_column("name")
        t.add_column("category")
        t.add_column("expected rules")
        t.add_column("description")
        for s in SCENARIOS:
            t.add_row(s.name, s.category, ", ".join(s.expected_rules) or "-", s.description)
        console.print(t)
        return
    if scenario:
        events = get_scenario(scenario).build()
    else:
        events = build_dataset(n_benign=benign, seed=seed)
    if out_path:
        dump_jsonl(events, out_path)
        console.print(f"[green]Wrote[/green] {len(events)} events -> {out_path}")
    else:
        for e in events:
            click.echo(json.dumps(e.to_dict(), ensure_ascii=False))


# ---------------------------------------------------------------------------
@main.command("evaluate")
@click.option("--benign", type=int, default=60, help="Benign sessions used to fit the baseline.")
@click.option("--seed", type=int, default=101)
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Emit the full report as JSON.")
def evaluate_cmd(benign, seed, rule_paths, as_json):
    """Score the rule pack + anomaly model against labelled scenarios."""
    from taintline.evaluate import run_eval

    rep = run_eval(baseline_benign=benign, seed=seed, rule_paths=list(rule_paths) or None)
    if as_json:
        click.echo(json.dumps(rep.to_dict(), indent=2))
        return
    t = Table(title="scenario detection", expand=True)
    t.add_column("scenario")
    t.add_column("cat")
    t.add_column("detected")
    t.add_column("fired rules")
    t.add_column("missed")
    t.add_column("anomaly")
    for s in rep.scenarios:
        det = "[green]yes[/green]" if s.detected else "[red]NO[/red]"
        an = f"{s.anomaly_score:.2f}{'*' if s.flagged_anomalous else ''}"
        miss = ", ".join(s.missed) or "-"
        bad = ", ".join(s.unexpected_high) if s.unexpected_high else ""
        t.add_row(s.name, s.category, det, ", ".join(s.fired) or "-", f"[red]{miss}[/red]" if s.missed else miss, an + (f" [red]{bad}[/red]" if bad else ""))
    console.print(t)
    console.print(
        f"\n[bold]Rule pack:[/bold] precision {rep.rule_precision:.2f} · recall {rep.rule_recall:.2f} · "
        f"F1 {rep.rule_f1:.2f} · benign FP rate {rep.benign_false_positive_rate:.2f}"
    )
    console.print(f"[bold]Anomaly model:[/bold] ROC-AUC {rep.anomaly_auc:.3f} (attack vs benign)")


# ---------------------------------------------------------------------------
@main.command()
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--no-builtin", is_flag=True)
def rules(rule_paths, no_builtin):
    """List the loaded rule pack."""
    rs = load_rules(list(rule_paths), include_builtin=not no_builtin)
    t = Table(title=f"loaded rules ({len(rs)})", expand=True)
    t.add_column("id", no_wrap=True)
    t.add_column("sev", no_wrap=True)
    t.add_column("type", no_wrap=True)
    t.add_column("title")
    for r in sorted(rs, key=lambda r: (-SEVERITY_RANK[r.severity], r.id)):
        t.add_row(r.id, f"[{SEV_STYLE[r.severity]}]{r.severity}[/]", r.match["type"], r.title)
    console.print(t)


# ---------------------------------------------------------------------------
# guard: runtime enforcement
# ---------------------------------------------------------------------------


def _load_guard(policy_path, rule_paths, tool_config, monitor=False):
    from taintline.guard import Guard, Policy

    policy = Policy.from_yaml(policy_path) if policy_path else Policy.default()
    if monitor:
        policy.mode = "monitor"
    classifier = ToolClassifier.from_yaml(tool_config) if tool_config else ToolClassifier()
    return Guard(policy=policy, rule_paths=list(rule_paths) or None, classifier=classifier)


@main.group()
def guard():
    """Runtime enforcement: decide on tool calls before they execute."""


@guard.command("mcp-proxy", context_settings={"ignore_unknown_options": True, "allow_interspersed_args": False})
@click.option("--policy", "policy_path", type=click.Path(exists=True), help="Guard policy YAML (default: built-in).")
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--tool-config", type=click.Path(exists=True))
@click.option("--audit", "audit_path", type=click.Path(dir_okay=False), help="Append the audit trail (JSONL) here.")
@click.option("--remote", is_flag=True, help="Treat the fronted server as a remote MCP endpoint (egress channel).")
@click.option("--untrusted-results", is_flag=True, help="Treat every tool result from this server as untrusted input.")
@click.option("--keep-poisoned", is_flag=True, help="Do not strip poisoned tools from tools/list (calls are still blocked).")
@click.option("--monitor", is_flag=True, help="Never interfere; log what would have been blocked.")
@click.option("--principal", help="What the user asked for; destinations named here count as authorized.")
@click.option("--session-id", help="Session id to use in the audit trail.")
@click.argument("server_cmd", nargs=-1, required=True, type=click.UNPROCESSED)
def guard_mcp_proxy(policy_path, rule_paths, tool_config, audit_path, remote, untrusted_results, keep_poisoned, monitor, principal, session_id, server_cmd):
    """Front an MCP stdio server and enforce the guard on its traffic.

    \b
    Example (Claude Desktop / any MCP client config):
      "command": "taintline",
      "args": ["guard", "mcp-proxy", "--audit", "audit.jsonl", "--", "npx", "-y", "@modelcontextprotocol/server-fetch"]
    """
    from taintline.guard.mcp_proxy import MCPProxy

    g = _load_guard(policy_path, rule_paths, tool_config, monitor)
    proxy = MCPProxy(
        list(server_cmd),
        guard=g,
        audit_path=audit_path,
        transport="remote" if remote else "local",
        strip_poisoned=not keep_poisoned,
        untrusted_results=untrusted_results,
        principal=principal,
        session_id=session_id,
    )
    sys.exit(proxy.run())


@guard.command("replay")
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--policy", "policy_path", type=click.Path(exists=True))
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--tool-config", type=click.Path(exists=True))
@click.option("--session", "only_session", help="Only replay this session id.")
@click.option("--json", "as_json", is_flag=True)
def guard_replay(trace, fmt, policy_path, rule_paths, tool_config, only_session, as_json):
    """Replay a recorded TRACE as if the guard had been deployed.

    Shows, event by event, which calls the guard would have allowed, held or
    blocked and which outputs it would have sanitized: where would it have
    stopped this incident?
    """
    from taintline.guard import replay as do_replay

    events = _load_events(trace, fmt)
    if only_session:
        events = [e for e in events if e.session_id == only_session]
    g = _load_guard(policy_path, rule_paths, tool_config)
    results = do_replay(events, g)
    if as_json:
        click.echo(json.dumps([r.to_dict() for r in results], indent=2))
        return
    stopped = 0
    for r in results:
        stopped += int(r.stopped)
        acted = [s for s in r.steps if s.decision or (s.screen and s.screen.changed)]
        if not acted:
            continue
        t = Table(title=f"session {r.session_id}", expand=True, show_lines=False)
        t.add_column("#", justify="right", no_wrap=True)
        t.add_column("verdict", no_wrap=True)
        t.add_column("event", no_wrap=True)
        t.add_column("why")
        for i, s in enumerate(r.steps):
            ev = s.event
            post = r.first_block is not None and i > r.first_block
            if s.decision:
                d = s.decision
                style = {"allow": "green", "log": "yellow", "block": "bold red"}.get(d.enforced, "white")
                label = "HOLD" if d.action == "require_approval" and not d.allowed else d.enforced.upper()
                why = d.summary() if d.matched or d.allowlisted else ""
                t.add_row(str(ev.seq), f"[{style}]{label}[/]", escape(f"{ev.tool}{' (post-divergence)' if post else ''}"), escape(why[:240]))
            elif s.screen and s.screen.changed:
                bits = [f"neutralized beacon to {u.split('/')[2]}" for u in s.screen.neutralized] + [f"redacted {k}" for k in s.screen.redacted]
                t.add_row(str(ev.seq), "[bold magenta]SANITIZE[/]", "model_output", escape("; ".join(bits)))
        console.print(t)
        if r.stopped:
            first = r.steps[r.first_block].event
            console.print(f"  [bold]first stop:[/bold] event {first.seq} ({first.tool or first.kind})\n")
        else:
            console.print("  [green]nothing to stop in this session[/green]\n")
    console.print(f"[bold]{stopped}/{len(results)} sessions stopped by the guard.[/bold]")


@main.group()
def forensics():
    """Deep forensics: IOCs, STIX, blast radius, signed evidence packs, correlation."""


def _forensic_build(trace, fmt, rule_paths, no_builtin, tool_config):
    events = _load_events(trace, fmt)
    analyses, findings = _build(events, rule_paths, no_builtin, tool_config)
    return events, analyses, findings


@forensics.command("ioc")
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--tool-config", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True)
def forensics_ioc(trace, fmt, rule_paths, tool_config, as_json):
    """Extract indicators of compromise from a trace."""
    from taintline.forensics import extract_iocs

    _, analyses, _ = _forensic_build(trace, fmt, rule_paths, False, tool_config)
    iocs = extract_iocs(analyses)
    if as_json:
        click.echo(json.dumps([i.to_dict() for i in iocs], indent=2))
        return
    t = Table(title=f"IOCs ({len(iocs)})", expand=True)
    for col in ("type", "value", "role", "sessions"):
        t.add_column(col, no_wrap=(col != "value"))
    for i in iocs:
        t.add_row(i.type, escape(i.value), i.role, ", ".join(sorted(i.sessions)))
    console.print(t)


@forensics.command("stix")
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--tool-config", type=click.Path(exists=True))
@click.option("--out", "out_path", type=click.Path(dir_okay=False))
def forensics_stix(trace, fmt, rule_paths, tool_config, out_path):
    """Export a STIX 2.1 bundle of findings and IOCs."""
    from taintline.forensics import extract_iocs, to_stix_bundle

    _, analyses, findings = _forensic_build(trace, fmt, rule_paths, False, tool_config)
    bundle = to_stix_bundle(findings, extract_iocs(analyses))
    text = json.dumps(bundle, indent=2, ensure_ascii=False)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        console.print(f"[green]STIX bundle written[/green] -> {out_path} ({len(bundle['objects'])} objects)")
    else:
        click.echo(text)


@forensics.command("blast-radius")
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--tool-config", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True)
def forensics_blast(trace, fmt, rule_paths, tool_config, as_json):
    """Assess blast radius and print a remediation checklist."""
    from taintline.forensics import assess_blast_radius, extract_iocs

    _, analyses, findings = _forensic_build(trace, fmt, rule_paths, False, tool_config)
    blast = assess_blast_radius(analyses, findings, extract_iocs(analyses))
    if as_json:
        click.echo(json.dumps(blast.to_dict(), indent=2))
        return
    _print_blast(blast)
    if blast.tier == "none":
        console.print("[green]No blast radius: no high/critical impact detected.[/green]")


@forensics.command("dashboard")
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--tool-config", type=click.Path(exists=True))
@click.option("--baseline", "baseline_path", type=click.Path(exists=True))
@click.option("--guard-replay", is_flag=True)
@click.option("--out", "out_path", required=True, type=click.Path(dir_okay=False))
def forensics_dashboard(trace, fmt, rule_paths, tool_config, baseline_path, guard_replay, out_path):
    """Build the interactive HTML investigation dashboard."""
    from taintline.forensics import assess_blast_radius, extract_iocs

    events, analyses, findings = _forensic_build(trace, fmt, rule_paths, False, tool_config)
    iocs = extract_iocs(analyses)
    blast = assess_blast_radius(analyses, findings, iocs)
    anomalies = [Baseline.load(baseline_path).score(a) for a in analyses] if baseline_path else []
    replay_results = None
    if guard_replay:
        from taintline.guard import replay as _replay

        replay_results = _replay(events)
    man = build_manifest(trace, events)
    _write_dashboard(out_path, analyses, findings, iocs, blast, anomalies, man, replay_results,
                     title=f"taintline — {os.path.basename(trace)}")
    console.print(f"[green]Dashboard written[/green] -> {out_path}")


@forensics.group("pack")
def forensics_pack():
    """Signed evidence packs."""


@forensics_pack.command("keygen")
@click.option("--out", "out_prefix", required=True, help="Writes <prefix>.key and <prefix>.pub (PEM).")
def pack_keygen(out_prefix):
    """Generate an Ed25519 signing keypair."""
    from taintline.forensics.pack import generate_keypair

    priv, pub = generate_keypair()
    with open(out_prefix + ".key", "w", encoding="utf-8") as fh:
        fh.write(priv)
    with open(out_prefix + ".pub", "w", encoding="utf-8") as fh:
        fh.write(pub)
    console.print(f"[green]Keypair written[/green] -> {out_prefix}.key (private), {out_prefix}.pub (public)")


@forensics_pack.command("build")
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--rules", "rule_paths", multiple=True, type=click.Path(exists=True))
@click.option("--tool-config", type=click.Path(exists=True))
@click.option("--sign-key", type=click.Path(exists=True), help="Ed25519 private key PEM.")
@click.option("--case-id")
@click.option("--out", "out_path", required=True, type=click.Path(dir_okay=False))
def pack_build(trace, fmt, rule_paths, tool_config, sign_key, case_id, out_path):
    """Build a (signed) evidence pack from a trace."""
    from taintline.forensics import assess_blast_radius, build_evidence_pack, extract_iocs, to_stix_bundle

    events, analyses, findings = _forensic_build(trace, fmt, rule_paths, False, tool_config)
    iocs = extract_iocs(analyses)
    priv = pub = None
    if sign_key:
        from cryptography.hazmat.primitives import serialization

        from taintline.forensics.pack import load_private_key

        priv = open(sign_key, encoding="utf-8").read()
        pub = load_private_key(priv).public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    pack = build_evidence_pack(
        build_manifest(trace, events), [f.to_dict() for f in findings], [i.to_dict() for i in iocs],
        assess_blast_radius(analyses, findings, iocs).to_dict(), to_stix_bundle(findings, iocs),
        private_pem=priv, public_pem=pub, case_id=case_id,
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(pack, fh, indent=2, ensure_ascii=False)
    console.print(f"[green]Evidence pack ({'signed' if sign_key else 'unsigned'}) written[/green] -> {out_path}")
    console.print(f"  digest: {pack['digest']['value']}")


@forensics_pack.command("verify")
@click.argument("pack_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--public-key", type=click.Path(exists=True), help="Pin this Ed25519 public key PEM.")
def pack_verify(pack_path, public_key):
    """Verify an evidence pack's digest and signature."""
    from taintline.forensics import verify_evidence_pack

    with open(pack_path, encoding="utf-8") as fh:
        pack = json.load(fh)
    expected = open(public_key, encoding="utf-8").read() if public_key else None
    res = verify_evidence_pack(pack, expected_public_pem=expected)
    color = "green" if res["ok"] else "red"
    console.print(f"[{color}]digest: {'OK' if res['digest_ok'] else 'MISMATCH'} | "
                  f"signature: {res['signature_ok']} | key_matches: {res['key_matches_expected']}[/{color}]")
    sys.exit(0 if res["ok"] else 3)


@forensics.command("cloudtrail")
@click.argument("trace", type=click.Path(exists=True, dir_okay=False))
@click.argument("cloudtrail_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", type=click.Choice(["auto", "jsonl", "openai", "otel"]), default="auto")
@click.option("--window-hours", type=float, default=72.0)
@click.option("--json", "as_json", is_flag=True)
def forensics_cloudtrail(trace, cloudtrail_path, fmt, window_hours, as_json):
    """Correlate exfiltrated AWS keys from a TRACE against CLOUDTRAIL activity."""
    from taintline.forensics import correlate, exposed_keys_from_analyses, load_cloudtrail

    events, analyses, _ = _forensic_build(trace, fmt, (), False, None)
    keys = exposed_keys_from_analyses(analyses, events)
    if not keys:
        console.print("[yellow]No AWS access keys were found leaving in this trace.[/yellow]")
        return
    res = correlate(load_cloudtrail(cloudtrail_path), keys, window_hours=window_hours)
    if as_json:
        click.echo(json.dumps(res.to_dict(), indent=2))
        return
    tag = "[bold white on red] CONFIRMED ABUSE [/]" if res.any_abuse else "[green]no confirmed abuse in window[/green]"
    console.print(f"Exposed keys: {', '.join(keys)}  ->  {tag}")
    for v in res.verdicts:
        console.print(f"  [bold]{v.access_key_id}[/bold]: used={v.used_after_exposure} abuse={v.confirmed_abuse} ({len(v.hits)} hits)")
        for h in v.hits[:8]:
            flags = ",".join(f for f, on in [("sensitive", h.sensitive), ("new-origin", h.new_origin), ("logging-tamper", h.disables_logging)] if on)
            console.print(escape(f"    {h.event_time} {h.event_name} from {h.source_ip} [{flags or 'routine'}]"))


@guard.command("policy")
@click.option("--policy", "policy_path", type=click.Path(exists=True))
def guard_policy(policy_path):
    """Validate and display a guard policy (default: the built-in one)."""
    from taintline.guard import Policy

    p = Policy.from_yaml(policy_path) if policy_path else Policy.default()
    console.print(f"[bold]policy[/bold] {p.source}  mode={p.mode}  default={p.default_action}  approval-unavailable={p.on_approval_unavailable}")
    t = Table(expand=True)
    t.add_column("rule", no_wrap=True)
    t.add_column("action", no_wrap=True)
    t.add_column("when")
    for r in p.rules:
        style = {"block": "bold red", "require_approval": "yellow", "log": "cyan"}.get(r.action, "green")
        t.add_row(r.name, f"[{style}]{r.action}[/]", escape(json.dumps(r.when)))
    console.print(t)
    console.print(f"allow.tools={p.allow_tools}  allow.destinations={p.allow_destinations}  "
                  f"output: neutralize_beacons={p.neutralize_beacons} redact_secrets={p.redact_secrets}")


if __name__ == "__main__":
    main()
