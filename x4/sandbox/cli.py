"""X4 sandbox CLI. Docker is default; process mode is explicitly unsafe."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .container import ContainerLimits, DockerBackend
from .core import Policy, Sandbox, SandboxError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="x4-sandbox")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("inspect", "run"):
        p = sub.add_parser(action)
        p.add_argument("--workspace", type=Path, required=True)
        p.add_argument("--allow", nargs="+", required=True, metavar="EXECUTABLE")
        p.add_argument("--timeout", type=float, default=30)
        p.add_argument("--backend", choices=("docker", "process"), default="docker")
        p.add_argument("--image", help="preloaded immutable image: name@sha256:<64 lowercase hex>")
        p.add_argument("--docker-context", default="default")
        p.add_argument("--input", action="append", default=[], metavar="RELATIVE_PATH")
        p.add_argument("--memory-mib", type=int, default=512)
        p.add_argument("--cpus", type=float, default=1.0)
        p.add_argument("--pids-limit", type=int, default=128)
        p.add_argument("--tmpfs-mib", type=int, default=64)
        if action == "run":
            p.add_argument("--acknowledge-unenforced-network", action="store_true",
                           help="unsafe: process backend has no OS isolation")
            p.add_argument("argv", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        parser.error("workspace must already exist")
    command: list[str] = list(getattr(args, "argv", []))
    if command and command[0] == "--":
        command.pop(0)
    if args.action == "run" and not command:
        parser.error("missing command after --")
    try:
        policy = Policy(
            tuple(args.allow), network="deny", timeout_seconds=args.timeout,
            allow_unenforced_network=(
                args.action == "run" and args.backend == "process"
                and args.acknowledge_unenforced_network
            ),
        )
        if args.action == "inspect":
            status: dict[str, object] = {
                "workspace": str(workspace), "backend": args.backend,
                "network_isolation_enforced": False,
                "network_isolation_status": "not_verified_until_container_preflight",
                "allowed_commands": list(policy.allowed_commands),
                "execution_enabled_by_default": args.backend == "docker",
            }
            if args.backend == "docker":
                status.update({
                    "image_digest_pinned": bool(args.image and "@sha256:" in args.image),
                    "planned_controls": [
                        "local daemon endpoint", "network=none", "read-only root filesystem",
                        "drop all Linux capabilities", "no-new-privileges", "seccomp active",
                        "non-root UID/GID", "CPU/memory/PID limits", "read-only explicit inputs",
                        "bounded noexec/nosuid/nodev tmpfs", "ephemeral container cleanup",
                    ],
                })
            else:
                status["warning"] = "process backend is not a security boundary"
                status["execution_enabled_by_default"] = False
            print(json.dumps(status, indent=2))
            return 0
        if args.backend == "docker":
            if not args.image:
                raise ValueError("--image name@sha256:<digest> is required")
            limits = ContainerLimits(
                cpus=args.cpus, memory_bytes=args.memory_mib * 1024 * 1024,
                pids_limit=args.pids_limit, tmpfs_bytes=args.tmpfs_mib * 1024 * 1024,
            )
            runner = DockerBackend(workspace, policy, args.image,
                                   context=args.docker_context, limits=limits)
            result = runner.run(command, input_paths=args.input)
        else:
            if not args.acknowledge_unenforced_network:
                raise SandboxError(
                    "process mode blocked; acknowledge its missing OS isolation only for trusted code"
                )
            result = Sandbox(workspace, policy).run(command)
        print(json.dumps({
            "run_id": result.run_id, "backend": result.backend,
            "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "timed_out": result.timed_out, "output_truncated": result.output_truncated,
            "network_isolation_enforced": result.network_isolation_enforced,
        }, indent=2))
        return 124 if result.timed_out else int(result.returncode or 0)
    except (SandboxError, ValueError) as exc:
        print(f"denied: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
