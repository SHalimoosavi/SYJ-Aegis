import argparse,json,sys
from pathlib import Path
from . import __version__
from .scanner import scan,write_outputs

def main(argv=None):
    p=argparse.ArgumentParser(prog="aegis",description="SYJ-AEGIS local-first AI application and agent security scanner.")
    s=p.add_subparsers(dest="command"); sp=s.add_parser("scan",help="Scan a project using Phase 1/2 static analysis."); sp.add_argument("path",type=Path)
    s.add_parser("version",help="Show SYJ-AEGIS version.")
    a=p.parse_args(argv)
    if a.command is None: p.print_help(); return 0
    if a.command=="version": print(f"SYJ-AEGIS {__version__}"); return 0
    if a.command=="scan":
        if not a.path.is_dir(): print(f"ERROR: project directory does not exist: {a.path}",file=sys.stderr); return 2
        try: d,f=scan(a.path); write_outputs(a.path.resolve(),d,f)
        except (OSError,ValueError) as exc: print(f"ERROR: scan failed: {exc}",file=sys.stderr); return 2
        print(json.dumps({"project":a.path.resolve().as_posix(),"files_scanned":d["files_scanned"],"findings":len(f),"agent_tools":len(d.get("agent_tools",[])),"output":(a.path.resolve()/".aegis").as_posix()},sort_keys=True)); return 0
    return 0
if __name__=="__main__": raise SystemExit(main())
