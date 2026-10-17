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
@click.option("--quiet", is_flag=True)
def analyze(trace, fmt, rule_paths, no_builtin, tool_config, baseline_path, out_dir, min_severity, fail_on, manifest, quiet):
    """Analyze a TRACE and report security findings."""
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

    if not quiet:
        _print_findings(findings)
        _print_anomalies(anomalies)

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(trace))[0]
        md = os.path.join(out_dir, f"{base_name}.report.md")
        js = os.path.join(out_dir, f"{base_name}.findings.json")
        sarif = os.path.join(out_dir, f"{base_name}.sarif")
        csvp = os.path.join(out_dir, f"{base_name}.timeline.csv")
        htmlp = os.path.join(out_dir, f"{base_name}.report.html")
        with open(md, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(analyses, findings, anomalies, man, trace))
        with open(js, "w", encoding="utf-8") as fh:
            json.dump(findings_json(analyses, findings, anomalies, man), fh, indent=2, ensure_ascii=False)
        with open(sarif, "w", encoding="utf-8") as fh:
            json.dump(to_sarif(findings, trace), fh, indent=2, ensure_ascii=False)
        write_timeline_csv(analyses, findings, csvp)
        with open(htmlp, "w", encoding="utf-8") as fh:
            fh.write(to_html(analyses, findings, anomalies, man, trace))
        if man:
            with open(os.path.join(out_dir, f"{base_name}.manifest.json"), "w", encoding="utf-8") as fh:
                json.dump(man, fh, indent=2, ensure_ascii=False)
        if not quiet:
            console.print(f"[green]Reports written to[/green] {out_dir}")

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


if __name__ == "__main__":
    main()
