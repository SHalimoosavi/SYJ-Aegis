#!/usr/bin/env python3
"""Build the deterministic SYJ-AEGIS v1.0.0 dashboard from real scanner output.

This is a documentation build tool. It never analyzes source by itself; it
invokes the already-installed SYJ-AEGIS scanner and consumes its generated
.aegis artifacts.
"""
from __future__ import annotations
import html, json, shutil, subprocess, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
A = ROOT / ".aegis"
FINDINGS = A / "findings.json"
REPORT_SRC = A / "report"
REPORT_DST = DOCS / "report"
STATUS = DOCS / "status.json"
INDEX = DOCS / "index.html"
BASELINE = ROOT / ".github" / "aegis-baseline.json"
SUPPRESSIONS = ROOT / ".github" / "aegis-suppressions.json"
SARIF = A / "dashboard-results.sarif"

class BuildError(RuntimeError): pass

def run(cmd, allow=(0,)):
    p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=False)
    if p.returncode not in allow:
        raise BuildError(f"{' '.join(map(str, cmd))} failed ({p.returncode}): {(p.stderr or p.stdout).strip()}")
    return p

def load(path, default=None):
    if not path.is_file():
        if default is not None: return default
        raise BuildError(f"Missing required generated file: {path.relative_to(ROOT)}")
    try: return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e: raise BuildError(f"Invalid JSON: {path}: {e}") from e

def phase_module(rule_id, category=""):
    if rule_id.startswith("AEGIS-SECRET-"): return "Phase 1", "Secret Detection"
    if rule_id.startswith("AEGIS-AGENCY-"): return "Phase 2", "AgentGuard"
    if rule_id.startswith("AEGIS-AI-"): return "Phase 3", "AI-Firewall"
    if rule_id.startswith("AEGIS-GOV-"): return "Phase 5", "AIGovern"
    return "Other", category or "Other"

def esc(x): return html.escape(str(x), quote=True)

def _run_scan():
    """Backward-compatible Phase 4 test hook."""
    return run(["aegis", "scan", "."])


def compute_metrics(data):
    """Backward-compatible Phase 4 metrics API.

    Uses the historical findings-only input while delegating to the
    current Phase 5/6 metric structure with empty governance/CI data.
    """
    findings = data.get("findings", []) if isinstance(data, dict) else []
    empty_governance = {
        "ai_system_register": [],
        "data_map": [],
        "risk_register": [],
        "control_mapping": [],
        "governance_findings": [],
    }
    empty_sarif = {"version": "2.1.0", "runs": [{"results": []}]}
    empty_ci = {
        "failed": False,
        "fail_on": "high",
        "actionable_findings": 0,
        "baseline_findings": 0,
        "suppressed_findings": 0,
        "total_findings": len(findings),
    }
    return build_metrics(findings, empty_governance, empty_sarif, empty_ci)


def _render_template(template, status, metrics, scan_summary):
    """Backward-compatible renderer for the legacy Phase 4 test.

    The production dashboard now renders from the current self-contained
    template. This compatibility path preserves the original test API.
    """
    severity = metrics.get("severity", {})
    phase = metrics.get("phase", {})
    total = metrics.get("total", 0)

    rows = []
    for i in range(1, 7):
        rows.append(
            f'<tr><td>Phase {i}</td><td>{phase.get(f"Phase {i}", 0)}</td></tr>'
        )

    return (
        f'<div class="metric">{total}</div><div class="label">Total findings</div>'
        f'<div class="metric">{severity.get("CRITICAL", 0)}</div><div class="label">Critical</div>'
        f'<div class="metric">{severity.get("HIGH", 0)}</div><div class="label">High</div>'
        f'<div class="metric">{severity.get("MEDIUM", 0)}</div><div class="label">Medium</div>'
        f'<div class="metric">{severity.get("LOW", 0)}</div><div class="label">Low</div>'
        + "".join(rows)
        + "".join(
            f'<span>{value}</span>'
            for value in (
                status.get("ai_firewall", "planned"),
                status.get("agentguard", "planned"),
                status.get("aigovern", "planned"),
                status.get("phase_4_dashboard", "planned"),
                status.get("phase_5_aigovern", "planned"),
                status.get("phase_6_production_hardening", "planned"),
            )
        )
    )


def build_metrics(findings, governance, sarif, ci):
    sev=Counter(); phase=Counter(); module=Counter()
    for f in findings:
        s=str(f.get("severity","UNKNOWN")); sev[s]+=1
        p,m=phase_module(str(f.get("rule_id","")), str(f.get("category","")))
        phase[p]+=1; module[m]+=1
    gov_findings=governance.get("governance_findings", [])
    # Governance findings are derived controls and are intentionally reported
    # separately so they are never double-counted in the core finding total.
    gov_sev=Counter(str(x.get("severity","UNKNOWN")) for x in gov_findings if isinstance(x,dict))
    phase["Phase 5"] = len(gov_findings)
    module["AIGovern"] = len(gov_findings)
    results=sarif.get("runs",[{}])[0].get("results",[]) if isinstance(sarif,dict) else []
    return {
        "total": len(findings),
        "severity": dict(sorted(sev.items())),
        "phase": {f"Phase {i}": phase.get(f"Phase {i}",0) for i in range(1,7)},
        "module": dict(sorted(module.items())),
        "governance": {
            "systems": len(governance.get("ai_system_register",[])),
            "data_flows": len(governance.get("data_map",[])),
            "risks": len(governance.get("risk_register",[])),
            "controls": len(governance.get("control_mapping",[])),
            "findings": len(gov_findings),
            "severity": dict(sorted(gov_sev.items())),
        },
        "ci": {
            "failed": bool(ci.get("failed",False)),
            "fail_on": ci.get("fail_on"),
            "actionable_findings": ci.get("actionable_findings",0),
            "baseline_findings": ci.get("baseline_findings",0),
            "suppressed_findings": ci.get("suppressed_findings",0),
            "total_findings": ci.get("total_findings",len(results)),
            "sarif_results": len(results),
            "sarif_version": sarif.get("version","unknown"),
        },
    }

def render(metrics, files_scanned):
    m=metrics; sev=m["severity"]
    phase_rows="".join(f"<tr><td>{esc(k)}</td><td>{v}</td></tr>" for k,v in m["phase"].items())
    mod_rows="".join(f"<tr><td>{esc(k)}</td><td>{v}</td></tr>" for k,v in m["module"].items())
    status = [
        ("Phase 1 — Core Scanner","merged"),
        ("Phase 2 — AgentGuard","merged"),
        ("Phase 3 — AI-Firewall","merged"),
        ("Phase 4 — Dashboard","merged"),
        ("Phase 5 — AIGovern","merged"),
        ("Phase 6 — Production Hardening","released — v1.0.0"),
    ]
    cards="".join(f'<article class="card"><h3>{esc(a)}</h3><span class="status">{esc(b)}</span></article>' for a,b in status)
    rules=["AEGIS-SECRET-*","AEGIS-AGENCY-001","AEGIS-AI-001/002/003/004/017","AEGIS-GOV-*"]
    rule_rows="".join(f"<tr><td><code>{esc(r)}</code></td><td>Static, evidence-backed rule family</td></tr>" for r in rules)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="SYJ-AEGIS v1.0.0 local-first AI security and governance dashboard">
<title>SYJ-AEGIS v1.0.0 — Security Dashboard</title>
<style>
:root{{color-scheme:dark;--bg:#080d18;--panel:#101827;--panel2:#162235;--text:#eef4ff;--muted:#a9b7cc;--accent:#45f0b0;--border:#2a3a52;--warn:#ffd166}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:linear-gradient(180deg,var(--bg),#0d1625);color:var(--text);font:15px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}a{{color:var(--accent)}}code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}.wrap{{width:min(1160px,calc(100% - 28px));margin:auto}}
nav{{position:sticky;top:0;z-index:20;background:#080d18ee;backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}}nav .wrap{{display:flex;gap:16px;overflow:auto;white-space:nowrap;padding:12px 0}}nav a{{text-decoration:none;font-size:.88rem}}
.hero{{padding:70px 0 45px;border-bottom:1px solid var(--border)}}.eyebrow,.status{{color:var(--accent);text-transform:uppercase;letter-spacing:.08em;font-weight:700}}h1{{font-size:clamp(2.5rem,8vw,5.5rem);line-height:.98;margin:10px 0}}h2{{margin-top:0}}.tag{{font-size:1.2rem;color:var(--muted);max-width:800px}}
section{{padding:38px 0}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}.metrics{{grid-template-columns:repeat(5,1fr)}}.card{{background:linear-gradient(145deg,var(--panel),var(--panel2));border:1px solid var(--border);border-radius:16px;padding:20px}}.metric{{font-size:2rem;font-weight:800}}.muted{{color:var(--muted)}}.status{{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:4px 9px;font-size:.72rem}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--border)}}th{{color:var(--muted)}}.demo textarea{{width:100%;min-height:210px;background:#080d18;color:var(--text);border:1px solid var(--border);border-radius:10px;padding:14px;font:14px/1.5 ui-monospace,monospace}}button{{background:var(--accent);border:0;border-radius:9px;padding:10px 16px;font-weight:800;cursor:pointer;margin-top:10px}}.notice{{border:1px solid #715f25;background:#211d0d;padding:15px;border-radius:12px;color:#ffe9a6}}.result{{margin-top:14px}}.finding{{border-left:3px solid var(--warn);padding:8px 12px;margin:8px 0;background:#111827}}footer{{padding:40px 0 65px;color:var(--muted)}}
@media(max-width:760px){{.grid,.metrics{{grid-template-columns:1fr}}nav .wrap{{gap:11px}}}}
</style></head>
<body>
<nav><div class="wrap">
<a href="#overview">Overview</a><a href="#architecture">Architecture</a><a href="#features">Features</a><a href="#demo">Live Demo</a><a href="#rules">Security Rules</a><a href="#reports">Reports</a><a href="#ci">CI/SARIF</a><a href="#docs">Documentation</a><a href="https://github.com/SHalimoosavi/SYJ-Aegis">GitHub</a><a href="https://github.com/SHalimoosavi/SYJ-Aegis/releases/tag/v1.0.0">Release v1.0.0</a>
</div></nav>
<header id="overview" class="hero"><div class="wrap"><div class="eyebrow">SYJ-AEGIS · v1.0.0</div><h1>Scan locally.<br>Understand completely.</h1>
<p class="tag">Evidence-first static security and AI governance analysis for applications and agents.</p>
<p>SYJ-AEGIS provides a local-first, dependency-free way to inspect observable source-code evidence without sending the project elsewhere.</p></div></header>
<main class="wrap">
<section><h2>Release status</h2><div class="grid">{cards}</div></section>
<section id="architecture"><h2>Architecture</h2><div class="grid"><article class="card"><h3>Static analysis</h3><p>Source is parsed and inspected. Scanned application code is not executed, imported, or evaluated.</p></article><article class="card"><h3>Governance</h3><p>Phase 5 derives an AI System Register, Data Map, Risk Register, Control Mapping and governance findings from static evidence.</p></article><article class="card"><h3>Production</h3><p>Phase 6 adds CI policy gates, SARIF 2.1.0, baselines and suppressions.</p></article></div></section>
<section id="features"><h2>Real self-scan</h2><div class="grid metrics"><article class="card"><div class="metric">{m["total"]}</div><div class="muted">Core findings</div></article><article class="card"><div class="metric">{sev.get("CRITICAL",0)}</div><div class="muted">Critical</div></article><article class="card"><div class="metric">{sev.get("HIGH",0)}</div><div class="muted">High</div></article><article class="card"><div class="metric">{m["governance"]["findings"]}</div><div class="muted">Governance findings</div></article><article class="card"><div class="metric">{files_scanned}</div><div class="muted">Files scanned</div></article></div>
<div class="grid"><article class="card"><h3>Findings by phase</h3><table><tr><th>Phase</th><th>Count</th></tr>{phase_rows}</table></article><article class="card"><h3>Findings by module</h3><table><tr><th>Module</th><th>Count</th></tr>{mod_rows}</table></article><article class="card"><h3>Governance register</h3><p>AI systems: <b>{m["governance"]["systems"]}</b></p><p>Data flows: <b>{m["governance"]["data_flows"]}</b></p><p>Risks: <b>{m["governance"]["risks"]}</b></p><p>Controls: <b>{m["governance"]["controls"]}</b></p></article></div></section>
<section id="demo"><h2>Browser demonstration</h2><div class="notice"><b>Browser demonstration only.</b> This is a small subset of rules running as pattern matching in your browser. It is <b>not the real scanner</b> and never uploads your text. Full engine: <code>pip install -e .</code>, then <code>aegis scan .</code> / <code>aegis ci .</code>.</div>
<div class="card demo"><textarea id="source" spellcheck="false">API_KEY = "placeholder-1234567890"
value = input("value: ")
print(value)
</textarea><button id="analyze">Analyze snippet locally</button><div id="demoResult" class="result muted">No analysis run yet.</div></div></section>
<section id="rules"><h2>Security Rules</h2><table><tr><th>Family</th><th>Scope</th></tr>{rule_rows}</table></section>
<section id="reports"><h2>Reports</h2><div class="card"><p><a href="report/index.html">Open the regenerated self-scan report →</a></p><p>The report is copied from the real <code>.aegis/report/</code> output during the dashboard build.</p></div></section>
<section id="ci"><h2>CI / SARIF</h2><div class="grid"><article class="card"><div class="metric">{str(m["ci"]["sarif_results"])}</div><div class="muted">SARIF results</div></article><article class="card"><div class="metric">{esc(m["ci"]["sarif_version"])}</div><div class="muted">SARIF version</div></article><article class="card"><div class="metric">{esc("PASS" if not m["ci"]["failed"] else "FAIL")}</div><div class="muted">CI policy state</div></article></div><p>Actionable: {m["ci"]["actionable_findings"]} · Baseline-covered: {m["ci"]["baseline_findings"]} · Suppressed: {m["ci"]["suppressed_findings"]} · Threshold: {esc(m["ci"]["fail_on"])}</p></section>
<section id="docs"><h2>Documentation</h2><div class="grid"><article class="card"><a href="https://github.com/SHalimoosavi/SYJ-Aegis/blob/main/README.md">README</a></article><article class="card"><a href="https://github.com/SHalimoosavi/SYJ-Aegis/blob/main/docs/production-hardening.md">Production Hardening</a></article><article class="card"><a href="https://github.com/SHalimoosavi/SYJ-Aegis/releases/tag/v1.0.0">v1.0.0 Release</a></article></div></section>
<section><h2>What this does NOT do</h2><div class="notice">No runtime code execution. No external API calls. No source-code upload. The browser demo performs pattern matching only. The browser demo is not the production scanner. The production scanner runs locally through Python and the CLI.</div></section>
</main>
<footer><div class="wrap">SYJ-AEGIS v1.0.0 · Local-first · Static analysis · No external page resources. This dashboard is generated from the current scanner outputs; it does not invent or estimate findings.</div></footer>
<script>
"use strict";
function browserRules(source) {{
  const lines=source.split(/\\r?\\n/), findings=[];
  const key=/\\b(?:api[_-]?key|secret|token)\\b\\s*=\\s*["'][^"']{{12,}}["']/i;
  const sink=/\\b(?:eval|exec)\\s*\\(/;
  lines.forEach((line,i)=>{{
    if(key.test(line)) findings.push({{rule:"BROWSER-SECRET-001",line:i+1,text:"Obvious hardcoded secret-like assignment"}});
    if(sink.test(line)) findings.push({{rule:"BROWSER-SINK-001",line:i+1,text:"Direct eval/exec sink pattern"}});
  }});
  return findings;
}}
document.getElementById("analyze").addEventListener("click",()=>{{
  const r=browserRules(document.getElementById("source").value), box=document.getElementById("demoResult");
  if(!r.length) {{ box.className="result"; box.textContent="No browser-demo patterns detected."; return; }}
  box.className="result"; box.innerHTML="<b>Demo findings:</b>"+r.map(x=>`<div class="finding"><code>${{x.rule}}</code> · line ${{x.line}} · ${{x.text}}</div>`).join("");
}});
window.SYJ_AEGIS_BROWSER_RULES=browserRules;
</script>
</body></html>"""

def main():
    if not FINDINGS.is_file():
        print(
            "Required scan output missing: .aegis/findings.json. "
            "Run 'aegis scan .' first.",
            file=sys.stderr,
        )
        return 1

    # Run both real production commands. CI may return 1 when the project's
    # configured policy finds actionable results; that is still valid input.
    run(["aegis","ci",".","--baseline",str(BASELINE),"--suppressions",str(SUPPRESSIONS),
         "--sarif",str(SARIF),"--fail-on","none"], allow=(0,1))
    findings=load(A/"findings.json",{"findings":[]})
    governance=load(A/"governance.json",{})
    sarif=load(SARIF,{"runs":[{"results":[]}]})
    # Re-run with the configured production threshold to obtain the real gate
    # state for the dashboard.
    p=run(["aegis","ci",".","--baseline",str(BASELINE),"--suppressions",str(SUPPRESSIONS),
           "--sarif",str(SARIF),"--fail-on","high"], allow=(0,1))
    try: ci=json.loads(p.stdout)
    except json.JSONDecodeError as e: raise BuildError(f"CI command did not return JSON: {e}")
    # second command can rewrite SARIF; reload it.
    sarif=load(SARIF,{"runs":[{"results":[]}]})
    discovery=load(A/"findings.json",{"findings":[]})
    # Scanner's stdout contains files_scanned; recover it directly with scan.
    s=run(["aegis","scan","."])
    scan_summary=json.loads(s.stdout)
    metrics=build_metrics(discovery.get("findings",[]),governance,sarif,ci)
    status={
      "version":"v1.0.0",
      "phase_1":"merged","phase_2":"merged","phase_3":"merged",
      "phase_4_dashboard":"merged","phase_5_aigovern":"merged",
      "phase_6_production_hardening":"released",
      "release":"v1.0.0",
      "files_scanned":scan_summary.get("files_scanned",0),
      "metrics":metrics,
    }
    STATUS.write_text(json.dumps(status,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    if REPORT_DST.exists(): shutil.rmtree(REPORT_DST)
    if not REPORT_SRC.is_dir(): raise BuildError("Missing .aegis/report after real scan.")
    shutil.copytree(REPORT_SRC,REPORT_DST)
    INDEX.write_text(render(metrics,scan_summary.get("files_scanned",0)),encoding="utf-8")
    print(json.dumps({"status":"PASS","index":"docs/index.html","report":"docs/report","status_json":"docs/status.json",
                      "files_scanned":scan_summary.get("files_scanned",0),
                      "findings":len(discovery.get("findings",[])),
                      "governance_findings":len(governance.get("governance_findings",[])),
                      "sarif_results":metrics["ci"]["sarif_results"]},sort_keys=True))
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except BuildError as e:
        print(f"SYJ-AEGIS dashboard build error: {e}",file=sys.stderr); raise SystemExit(1)
