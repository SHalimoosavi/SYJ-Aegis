import argparse,json,sys
from pathlib import Path
from . import __version__
from .scanner import scan,write_outputs
from .production import (
    evaluate_ci, load_baseline, load_suppressions, write_baseline, write_sarif,
)

def main(argv=None):
    p=argparse.ArgumentParser(prog="aegis",description="SYJ-AEGIS local-first AI application and agent security scanner.")
    s=p.add_subparsers(dest="command"); sp=s.add_parser("scan",help="Scan a project using local static analysis."); sp.add_argument("path",type=Path)
    cp=s.add_parser("ci",help="Run a CI policy scan with SARIF, baselines, and suppressions."); cp.add_argument("path",type=Path); cp.add_argument("--sarif",type=Path,default=Path(".aegis/results.sarif")); cp.add_argument("--baseline",type=Path); cp.add_argument("--suppressions",type=Path); cp.add_argument("--update-baseline",action="store_true"); cp.add_argument("--fail-on",choices=["none","low","medium","high","critical"],default="high")
    s.add_parser("version",help="Show SYJ-AEGIS version.")
    a=p.parse_args(argv)
    if a.command is None: p.print_help(); return 0
    if a.command=="version": print(f"SYJ-AEGIS {__version__}"); return 0
    if a.command=="scan":
        if not a.path.is_dir(): print(f"ERROR: project directory does not exist: {a.path}",file=sys.stderr); return 2
        try: d,f=scan(a.path); write_outputs(a.path.resolve(),d,f)
        except (OSError,ValueError) as exc: print(f"ERROR: scan failed: {exc}",file=sys.stderr); return 2
        print(json.dumps({"project":a.path.resolve().as_posix(),"files_scanned":d["files_scanned"],"findings":len(f),"agent_tools":len(d.get("agent_tools",[])),"output":(a.path.resolve()/".aegis").as_posix()},sort_keys=True)); return 0
    if a.command=="ci":
        if not a.path.is_dir(): print(f"ERROR: project directory does not exist: {a.path}",file=sys.stderr); return 2
        try:
            project=a.path.resolve()
            d,f=scan(project)
            write_outputs(project,d,f)
            baseline_path=a.baseline.resolve() if a.baseline else None
            suppression_path=a.suppressions.resolve() if a.suppressions else None
            if a.update_baseline:
                if baseline_path is None:
                    print("ERROR: --update-baseline requires --baseline",file=sys.stderr); return 2
                write_baseline(baseline_path,f)
            baseline=load_baseline(baseline_path) if baseline_path else set()
            sf,sl,_=load_suppressions(suppression_path) if suppression_path else (set(),set(),{})
            write_sarif(a.sarif.resolve(),f,baseline=baseline,suppression_fingerprints=sf,suppression_locations=sl)
            summary=evaluate_ci(f,fail_on=a.fail_on,baseline=baseline,suppression_fingerprints=sf,suppression_locations=sl)
        except (OSError,ValueError) as exc:
            print(f"ERROR: CI scan failed: {exc}",file=sys.stderr); return 2
        print(json.dumps(summary,sort_keys=True))
        return 1 if summary["failed"] else 0
    return 0
if __name__=="__main__": raise SystemExit(main())
