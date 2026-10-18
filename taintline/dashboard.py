"""Self-contained interactive investigation dashboard (single HTML file).

One file, no external assets, no network: a responder can open it offline or
email it as the incident artifact. It renders from one JSON payload embedded in
the page and offers:

* an **incident header** with the blast-radius tier and evidence hashes;
* tabs: Overview, Timeline, Findings, Attack graph, IOCs, Guard;
* a **session timeline** with every event, taint level, injection score and the
  rules each event triggered, filterable by session and severity;
* an inline **SVG attack graph** (sources -> model turns -> sinks, taint edges
  in red) drawn from the provenance graph with no JS graph library;
* the **IOC table** (exportable as CSV) and the remediation checklist;
* the **guard verdict** per call when a replay is included.

Light and dark themes both supported.
"""

from __future__ import annotations

import html
import json
from typing import Any

from taintline import __version__

_TIER_COLOR = {
    "critical": "#d64545", "severe": "#e0601e", "elevated": "#d4a11f",
    "low": "#2f7fd3", "none": "#2a9d8f",
}


def build_dashboard(payload: dict[str, Any]) -> str:
    """``payload`` is the JSON produced by ``dashboard_payload`` below."""
    data = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    tier = payload.get("blast_radius", {}).get("tier", "none")
    accent = _TIER_COLOR.get(tier, "#2a9d8f")
    title = html.escape(payload.get("title", "taintline investigation"))
    return _TEMPLATE.replace("__ACCENT__", accent).replace("__TITLE__", title).replace(
        "__VERSION__", __version__
    ).replace("/*__DATA__*/null", data)


def dashboard_payload(
    analyses,
    findings,
    *,
    iocs=None,
    blast_radius=None,
    anomalies=None,
    manifest=None,
    replay_results=None,
    cloudtrail=None,
    graph=None,
    title: str = "taintline investigation",
) -> dict[str, Any]:
    """Assemble everything the dashboard renders into one JSON-able dict."""
    from taintline.graph import attack_paths

    hits: dict[str, list[str]] = {}
    for f in findings:
        for eid in f.events:
            hits.setdefault(eid, []).append(f.rule_id)

    sessions = []
    for a in analyses:
        events = []
        for e in a.events:
            info = a.info(e)
            inj = a.injection.get(e.id)
            role = (
                "source" if (e.kind == "tool_result" and info.is_source)
                else "sink" if (e.kind == "tool_call" and info.is_sink)
                else "payload" if a.secrets.get(e.id)
                else e.kind
            )
            events.append({
                "id": e.id, "seq": e.seq, "ts": e.ts, "kind": e.kind, "tool": e.tool or "",
                "role": role, "taint": round(a.max_taint_confidence(e.id), 3),
                "injection": round(inj.score, 3) if inj else 0.0,
                "secrets": sorted({s.kind for s in a.secrets.get(e.id, [])}),
                "rules": hits.get(e.id, []),
                "excerpt": e.short(220),
                "blocked": bool(e.meta.get("blocked")),
            })
        sessions.append({
            "id": a.session.id, "events": events,
            "flows": [f.to_dict() for f in a.flows],
            "attack_paths": attack_paths(a),
        })

    return {
        "title": title,
        "generated_by": f"taintline {__version__}",
        "manifest": {k: v for k, v in (manifest or {}).items() if k != "events"} | (
            {"events": {k: v for k, v in manifest["events"].items() if k != "chain_links"}} if manifest else {}
        ),
        "blast_radius": blast_radius.to_dict() if hasattr(blast_radius, "to_dict") else (blast_radius or {}),
        "findings": [f.to_dict() for f in findings],
        "iocs": [i.to_dict() for i in (iocs or [])],
        "anomalies": [r.to_dict() for r in (anomalies or [])],
        "sessions": sessions,
        "replay": [r.to_dict() for r in (replay_results or [])],
        "cloudtrail": cloudtrail.to_dict() if hasattr(cloudtrail, "to_dict") else (cloudtrail or None),
        "graph": graph,
    }


_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#0f1117;--fg:#e6e8ec;--muted:#9aa0a6;--card:#171a23;--line:#262a36;--accent:__ACCENT__;
--crit:#d64545;--high:#e0601e;--med:#d4a11f;--low:#2f7fd3;--info:#6c757d;--ok:#2a9d8f}
@media (prefers-color-scheme:light){:root{--bg:#f5f6f8;--fg:#1b1f27;--muted:#5f6368;--card:#fff;--line:#e3e5ea}}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--fg);font-size:14px;line-height:1.5}
header{padding:20px 24px;border-bottom:1px solid var(--line);background:linear-gradient(90deg,color-mix(in srgb,var(--accent) 18%,var(--card)),var(--card))}
h1{margin:0 0 4px;font-size:20px}.sub{color:var(--muted);font-size:12px}
.wrap{max-width:1200px;margin:auto;padding:0 16px}
.tier{display:inline-block;padding:3px 12px;border-radius:999px;font-weight:700;font-size:12px;text-transform:uppercase;background:var(--accent);color:#fff;margin-left:8px}
nav{display:flex;gap:4px;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5}
nav button{background:none;border:1px solid transparent;color:var(--muted);padding:6px 12px;border-radius:7px;cursor:pointer;font-size:13px}
nav button.active{background:var(--card);color:var(--fg);border-color:var(--line)}
section{display:none;padding:18px 0}section.active{display:block}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:120px}
.tile b{display:block;font-size:24px}.tile span{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;position:sticky;top:46px;background:var(--bg)}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:var(--bg);padding:1px 5px;border-radius:4px}
.badge{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:999px;color:#fff;margin:1px}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med);color:#111}.low{background:var(--low)}.info{background:var(--info)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:middle}
.d-source{background:var(--high)}.d-sink{background:var(--crit)}.d-payload{background:#7b4fb3}.d-other{background:var(--muted)}
.bar{height:6px;border-radius:3px;background:var(--line);overflow:hidden;min-width:48px;display:inline-block;vertical-align:middle}
.bar>i{display:block;height:100%;background:var(--accent)}
.blocked{text-decoration:line-through;opacity:.6}.rowblock{outline:2px solid var(--crit);outline-offset:-2px}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
select,input{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:7px;padding:5px 8px;font-size:13px}
.muted{color:var(--muted)}.chk li{margin:4px 0}.right{margin-left:auto}
button.mini{background:var(--card);border:1px solid var(--line);color:var(--fg);border-radius:7px;padding:4px 10px;cursor:pointer;font-size:12px}
svg{max-width:100%;height:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
.verdict-allow{color:var(--ok)}.verdict-block{color:var(--crit);font-weight:700}.verdict-log{color:var(--med)}.verdict-hold{color:var(--high);font-weight:700}
details{margin:6px 0}summary{cursor:pointer}
</style></head>
<body>
<header><div class="wrap"><h1>__TITLE__ <span class="tier" id="tier"></span></h1>
<div class="sub" id="sub"></div></div></header>
<div class="wrap">
<nav id="nav"></nav>
<section id="tab-overview" class="active"></section>
<section id="tab-timeline"></section>
<section id="tab-findings"></section>
<section id="tab-graph"></section>
<section id="tab-iocs"></section>
<section id="tab-guard"></section>
</div>
<script>
const DATA = /*__DATA__*/null;
const E = (t,a={},...k)=>{const e=document.createElement(t);for(const[x,v]of Object.entries(a)){if(x==="class")e.className=v;else if(x==="html")e.innerHTML=v;else e.setAttribute(x,v);}for(const c of k)e.append(c);return e;};
const esc=s=>String(s==null?"":s);
const sevRank={critical:4,high:3,medium:2,low:1,info:0};
function badge(s){return `<span class="badge ${s}">${s}</span>`;}

function tabs(){
  const defs=[["overview","Overview"],["timeline","Timeline"],["findings",`Findings (${DATA.findings.length})`],
    ["graph","Attack graph"],["iocs",`IOCs (${DATA.iocs.length})`],["guard","Guard"]];
  const nav=document.getElementById("nav");
  defs.forEach(([id,label],i)=>{const b=E("button",{},label);if(i===0)b.classList.add("active");
    b.onclick=()=>{document.querySelectorAll("nav button").forEach(x=>x.classList.remove("active"));
      document.querySelectorAll("section").forEach(x=>x.classList.remove("active"));
      b.classList.add("active");document.getElementById("tab-"+id).classList.add("active");};
    nav.append(b);});
}

function header(){
  const br=DATA.blast_radius||{};document.getElementById("tier").textContent=(br.tier||"none");
  const m=DATA.manifest||{};const h=(m.source&&m.source.sha256)?m.source.sha256.slice(0,16)+"…":"n/a";
  const ch=(m.events&&m.events.chain_head)?m.events.chain_head.slice(0,16)+"…":"n/a";
  document.getElementById("sub").innerHTML=`${DATA.generated_by} · ${DATA.sessions.length} sessions · `+
    `evidence sha256 <code>${h}</code> · chain head <code>${ch}</code>`;
}

function overview(){
  const br=DATA.blast_radius||{},s=document.getElementById("tab-overview");
  const bySev={critical:0,high:0,medium:0,low:0,info:0};DATA.findings.forEach(f=>bySev[f.severity]++);
  const tiles=E("div",{class:"tiles"});
  for(const k of["critical","high","medium","low"])tiles.append(E("div",{class:"tile"},E("b",{},""+bySev[k]),E("span",{},k)));
  tiles.append(E("div",{class:"tile"},E("b",{},""+DATA.iocs.length),E("span",{},"IOCs")));
  tiles.append(E("div",{class:"tile"},E("b",{},""+(br.secrets_to_rotate||[]).length),E("span",{},"secrets to rotate")));
  s.append(tiles);
  if(br.remediation&&br.remediation.length){
    const c=E("div",{class:"card"});c.append(E("h3",{},"Remediation checklist"));
    const ul=E("ul",{class:"chk"});br.remediation.forEach(r=>ul.append(E("li",{},r)));c.append(ul);s.append(c);
  }
  const grid=E("div",{class:"card"});
  grid.innerHTML=`<h3>Impact</h3>
    <p><b>Secrets to rotate:</b> ${(br.secrets_to_rotate||[]).map(x=>`<code>${esc(x)}</code>`).join(" ")||"<span class=muted>none</span>"}</p>
    <p><b>Destinations to block:</b> ${(br.destinations_to_block||[]).map(x=>`<code>${esc(x)}</code>`).join(" ")||"<span class=muted>none</span>"}</p>
    <p><b>Capabilities abused:</b> ${(br.capabilities_abused||[]).join(", ")||"<span class=muted>none</span>"}</p>
    <p><b>Cross-session:</b> ${br.cross_session?"yes":"no"} · <b>Persistence:</b> ${(br.persistence||[]).length} mechanism(s)</p>`;
  s.append(grid);
  if(DATA.cloudtrail){const ct=DATA.cloudtrail,c=E("div",{class:"card"});
    c.innerHTML=`<h3>CloudTrail correlation</h3><p>${ct.any_abuse?"<b class=verdict-block>Confirmed abuse of exposed credentials.</b>":"No confirmed abuse in window."} `+
      `Keys used after exposure: ${ct.summary.keys_used_after_exposure}/${ct.summary.keys_checked}; sensitive calls: ${ct.summary.sensitive_calls}.</p>`;s.append(c);}
}

function findings(){
  const s=document.getElementById("tab-findings");
  const sorted=[...DATA.findings].sort((a,b)=>sevRank[b.severity]-sevRank[a.severity]||b.confidence-a.confidence);
  if(!sorted.length){s.append(E("p",{class:"muted"},"No findings."));return;}
  sorted.forEach(f=>{const c=E("div",{class:"card"});
    let maps="";for(const[k,v]of Object.entries(f.mappings||{}))maps+=`<code>${esc(k)}: ${v.join(", ")}</code> `;
    c.innerHTML=`${badge(f.severity)} <b>${esc(f.rule_id)}</b> · ${esc(f.title)} <span class="right muted">conf ${f.confidence}</span>
      <div class="muted" style="margin:4px 0">session <code>${esc(f.session_id)}</code> · ${maps}</div>
      <div>${esc(f.description||"")}</div>
      <div class="muted" style="margin-top:6px">events: ${f.events.map(e=>`<code>${esc(e)}</code>`).join(" ")}</div>`;
    s.append(c);});
}

function timeline(){
  const s=document.getElementById("tab-timeline");
  const ctl=E("div",{class:"controls"});
  const sel=E("select",{});sel.append(E("option",{value:"*"},"all sessions"));
  DATA.sessions.forEach(se=>sel.append(E("option",{value:se.id},se.id)));
  const only=E("label",{},E("input",{type:"checkbox",id:"onlyflagged"})," only flagged/blocked");
  ctl.append(sel,only);s.append(ctl);
  const host=E("div",{});s.append(host);
  function render(){host.innerHTML="";
    DATA.sessions.filter(se=>sel.value==="*"||se.id===sel.value).forEach(se=>{
      const c=E("div",{class:"card"});c.append(E("h3",{},"session "+se.id));
      const t=E("table",{});t.innerHTML="<tr><th>#</th><th>event</th><th>tool</th><th>taint</th><th>inj</th><th>rules</th><th>detail</th></tr>";
      const flagged=document.getElementById("onlyflagged").checked;
      se.events.forEach(ev=>{if(flagged&&!ev.rules.length&&!ev.blocked)return;
        const dot=ev.role==="source"?"d-source":ev.role==="sink"?"d-sink":ev.role==="payload"?"d-payload":"d-other";
        const tr=E("tr",{});if(ev.blocked)tr.className="rowblock";
        tr.innerHTML=`<td>${ev.seq}</td>
          <td><span class="dot ${dot}"></span>${esc(ev.kind)}${ev.blocked?' <span class="badge critical">blocked</span>':''}</td>
          <td><code>${esc(ev.tool)}</code></td>
          <td><span class="bar"><i style="width:${Math.round(ev.taint*100)}%"></i></span></td>
          <td>${ev.injection?ev.injection:""}</td>
          <td>${ev.rules.map(r=>`<span class="badge info">${esc(r)}</span>`).join("")}${ev.secrets.map(x=>`<span class="badge high">${esc(x)}</span>`).join("")}</td>
          <td class="${ev.blocked?'blocked':''}">${esc(ev.excerpt)}</td>`;
        t.append(tr);});
      c.append(t);host.append(c);});
  }
  sel.onchange=render;only.querySelector("input").onchange=render;render();
}

function iocs(){
  const s=document.getElementById("tab-iocs");
  const btn=E("button",{class:"mini"},"Export CSV");
  btn.onclick=()=>{const rows=[["type","value","role","sessions","events"]];
    DATA.iocs.forEach(i=>rows.push([i.type,i.value,i.role,(i.sessions||[]).join(" "),(i.events||[]).join(" ")]));
    const csv=rows.map(r=>r.map(x=>`"${String(x).replace(/"/g,'""')}"`).join(",")).join("\n");
    const a=E("a",{href:URL.createObjectURL(new Blob([csv],{type:"text/csv"})),download:"taintline-iocs.csv"});a.click();};
  s.append(E("div",{class:"controls"},btn));
  if(!DATA.iocs.length){s.append(E("p",{class:"muted"},"No IOCs."));return;}
  const t=E("table",{});t.innerHTML="<tr><th>type</th><th>value</th><th>role</th><th>sessions</th></tr>";
  DATA.iocs.forEach(i=>t.append(E("tr",{},E("td",{},i.type),E("td",{html:`<code>${esc(i.value)}</code>`}),E("td",{},i.role),E("td",{},(i.sessions||[]).join(", ")))));
  const c=E("div",{class:"card"});c.append(t);s.append(c);
}

function guard(){
  const s=document.getElementById("tab-guard");
  if(!DATA.replay||!DATA.replay.length){s.append(E("p",{class:"muted"},"No guard replay included. Run `taintline guard replay` or analyze with --guard."));return;}
  DATA.replay.forEach(r=>{const c=E("div",{class:"card"});
    c.append(E("h3",{},`session ${r.session_id} — ${r.stopped?"stopped":"not stopped"}`));
    const t=E("table",{});t.innerHTML="<tr><th>tool</th><th>verdict</th><th>why</th></tr>";
    (r.decisions||[]).forEach(d=>{const v=d.enforced,cls=v==="block"?"verdict-block":v==="log"?"verdict-log":(d.action==="require_approval"&&v==="block")?"verdict-hold":"verdict-allow";
      const reasons=(d.matched||[]).map(m=>`[${esc(m.rule)}] ${esc(m.reason)}`).join(" | ");
      t.append(E("tr",{},E("td",{html:`<code>${esc(d.tool)}</code>`}),E("td",{html:`<span class="${cls}">${esc(v).toUpperCase()}</span>`}),E("td",{},reasons)));});
    c.append(t);s.append(c);});
}

function graph(){
  const s=document.getElementById("tab-graph");
  s.append(E("p",{class:"muted"},"Untrusted sources (orange) and the taint edges (red) into sensitive sinks (red). One column per session."));
  DATA.sessions.forEach(se=>{
    const nodes=se.events.filter(e=>["tool_result","tool_call","model_output","memory_write","memory_read","tool_registered","user_message"].includes(e.kind));
    if(!nodes.length)return;
    const W=1100,rowH=34,padY=30,colX=40,boxW=250;
    const H=padY*2+nodes.length*rowH;
    const idx={};nodes.forEach((n,i)=>idx[n.id]=i);
    let svg=`<svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">`;
    svg+=`<text x="${colX}" y="18" fill="var(--muted)" font-size="12">session ${esc(se.id)}</text>`;
    (se.flows||[]).forEach(f=>{const a=idx[f.source],b=idx[f.sink];if(a==null||b==null)return;
      const y1=padY+a*rowH+14,y2=padY+b*rowH+14,x=colX+boxW+20;
      const col=f.kind==="taint_path"?"#b00020":"#d64545";
      svg+=`<path d="M ${x} ${y1} C ${x+90} ${y1}, ${x+90} ${y2}, ${x} ${y2}" fill="none" stroke="${col}" stroke-width="2.2" opacity="0.85"/>`;});
    nodes.forEach((n,i)=>{const y=padY+i*rowH;
      const fill=n.role==="source"?"#e0601e":n.role==="sink"?"#d64545":n.role==="payload"?"#7b4fb3":"var(--card)";
      const tc=(n.role==="source"||n.role==="sink"||n.role==="payload")?"#fff":"var(--fg)";
      svg+=`<rect x="${colX}" y="${y}" width="${boxW}" height="26" rx="6" fill="${fill}" stroke="var(--line)" ${n.blocked?'stroke="#b00020" stroke-width="2" stroke-dasharray="4"':''}/>`;
      svg+=`<text x="${colX+8}" y="${y+17}" fill="${tc}" font-size="11">${esc((n.tool||n.kind).slice(0,34))}</text>`;});
    svg+=`</svg>`;
    const c=E("div",{class:"card"});c.innerHTML=svg;s.append(c);});
}

tabs();header();overview();findings();timeline();iocs();guard();graph();
</script></body></html>"""
