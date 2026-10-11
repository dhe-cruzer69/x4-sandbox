"""X4 sandbox CLI."""
import argparse, json, sys
from pathlib import Path
from .core import Policy, Sandbox, SandboxError

def main(argv=None) -> int:
    p=argparse.ArgumentParser(prog="x4-sandbox"); sub=p.add_subparsers(dest="action",required=True)
    for name in ("inspect","run"):
        q=sub.add_parser(name); q.add_argument("--workspace",type=Path,required=True)
        q.add_argument("--allow",nargs="+",required=True,metavar="EXECUTABLE")
        q.add_argument("--timeout",type=float,default=30)
        if name=="run":
            q.add_argument("--acknowledge-unenforced-network",action="store_true",
                           help="unsafe: process backend cannot enforce network denial")
            q.add_argument("argv",nargs=argparse.REMAINDER)
    a=p.parse_args(argv); ws=a.workspace.expanduser().resolve()
    if not ws.is_dir(): print("workspace must already exist",file=sys.stderr); return 2
    policy=Policy(tuple(a.allow),timeout_seconds=a.timeout,
        allow_unenforced_network=getattr(a,"acknowledge_unenforced_network",False))
    if a.action=="inspect":
        print(json.dumps({"workspace":str(ws),"backend":"process","network":"deny",
            "network_isolation_enforced":False,"execution_enabled_by_default":False,
            "allowed_commands":list(policy.allowed_commands)},indent=2)); return 0
    args=list(a.argv)
    if args and args[0]=="--": args.pop(0)
    if not args: print("missing command after --",file=sys.stderr); return 2
    try:
        r=Sandbox(ws,policy).run(args)
        print(json.dumps({"run_id":r.run_id,"returncode":r.returncode,"stdout":r.stdout,
            "stderr":r.stderr,"timed_out":r.timed_out,"output_truncated":r.output_truncated,
            "network_isolation_enforced":False},indent=2))
        return 124 if r.timed_out else int(r.returncode or 0)
    except (SandboxError,ValueError) as e: print(f"denied: {e}",file=sys.stderr); return 3
if __name__=="__main__": raise SystemExit(main())
