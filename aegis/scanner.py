from pathlib import Path
import hashlib,json,html
from . import __version__,RULES_VERSION
from .discovery import discover,iter_project_files
from .secrets import scan_file
def project_hash(project):
    h=hashlib.sha256()
    for p in iter_project_files(project):
        try: data=p.read_bytes()
        except OSError: continue
        h.update(p.relative_to(project).as_posix().encode()+b"\\0"+data)
    return h.hexdigest()
def scan(project):
    project=Path(project).resolve(); d=discover(project); f=[]
    for p in iter_project_files(project): f.extend(scan_file(p,project))
    f.sort(key=lambda x:(x.rule_id,x.evidence.file,x.evidence.line,x.name)); return d,f
def render_html(project,d,findings):
    e=lambda x:html.escape(str(x),quote=True)
    rows="".join(f"<tr><td>{e(x.rule_id)}</td><td>{e(x.name)}</td><td>{e(x.severity)}</td><td>{e(x.confidence)}</td><td>{e(x.evidence.file)}:{x.evidence.line}</td><td>{e(x.description)}</td><td>{e(x.remediation)}</td></tr>" for x in findings)
    if not rows: rows='<tr><td colspan="7">No Phase 1 secret findings detected.</td></tr>'
    langs=", ".join(e(x["name"]) for x in d["languages"]) or "UNKNOWN"; frameworks=", ".join(e(x) for x in d["frameworks"]) or "UNKNOWN"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SYJ-AEGIS Report</title><style>body{{font-family:system-ui,sans-serif;margin:0;background:#f5f7fa;color:#172033}}header{{padding:28px;background:#111827;color:white}}main{{max-width:1200px;margin:24px auto;padding:0 16px}}.card{{background:white;border-radius:12px;padding:20px;margin:16px 0;box-shadow:0 2px 10px #0001}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}.metric{{font-size:28px;font-weight:700}}table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{padding:10px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}}th{{background:#f3f4f6}}</style></head><body><header><h1>SYJ-AEGIS AI SECURITY &amp; GOVERNANCE REPORT</h1><p>Local static Phase 1 report — observable static findings only.</p></header><main><div class="card"><h2>Project</h2><p>{e(project.name)}</p></div><div class="grid"><div class="card"><div class="metric">{len(findings)}</div>Findings</div><div class="card"><div class="metric">{sum(x.severity=="HIGH" for x in findings)}</div>High</div><div class="card"><div class="metric">{d["files_scanned"]}</div>Files scanned</div></div><div class="card"><h2>Project Detection</h2><p>Language: {langs}</p><p>Framework: {frameworks}</p></div><div class="card"><h2>Security Overview</h2><p>Phase 1 detects potential exposed secrets and evidence-based project technologies. It does not claim runtime security.</p></div><div class="card"><h2>Findings</h2><table><thead><tr><th>Rule</th><th>Name</th><th>Severity</th><th>Confidence</th><th>Evidence</th><th>Description</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table></div><div class="card"><h2>Phase Scope</h2><p>Agent capabilities, data-flow, RAG, output security, governance, dependencies, SARIF, baselines and suppressions are outside Phase 1.</p></div></main></body></html>"""
def write_outputs(project,d,findings):
    out=Path(project)/".aegis"; (out/"report").mkdir(parents=True,exist_ok=True)
    data={"tool":"SYJ-AEGIS","tool_version":__version__,"rules_version":RULES_VERSION,"findings":[x.to_dict() for x in findings]}
    (out/"findings.json").write_text(json.dumps(data,indent=2,sort_keys=True,ensure_ascii=False)+"\n",encoding="utf-8")
    cfg={"project":{"path":str(Path(project).resolve())},"scan":{"secrets":True,"discovery":True},"phase":1,"network_access":False}
    (out/"configuration.json").write_text(json.dumps(cfg,indent=2,sort_keys=True,ensure_ascii=False)+"\n",encoding="utf-8")
    (out/"report/index.html").write_text(render_html(Path(project),d,findings),encoding="utf-8")
