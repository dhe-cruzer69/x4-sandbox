"""Fail-closed Docker isolation backend; daemon and host kernel remain trusted."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .core import AuditLog, Policy, PolicyDenied, RunResult, SandboxError, SandboxUnavailable

_IMAGE = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}\Z")
_ID = re.compile(r"[0-9a-f]{12,64}\Z")
_SECRET_PARTS = {".git", ".x4", ".ssh", ".aws", ".gnupg"}
_SECRET_FILES = {".env", ".netrc", "credentials", "credentials.json", "secrets.json", "id_rsa", "id_ed25519"}
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")
_INPUT_MAX = 256 * 1024 * 1024

@dataclass(frozen=True)
class ContainerLimits:
    cpus: float = 1.0
    memory_bytes: int = 512 * 1024 * 1024
    pids_limit: int = 128
    tmpfs_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        if not 0.1 <= self.cpus <= 4.0:
            raise ValueError("cpus must be in [0.1, 4]")
        if not 64 * 1024**2 <= self.memory_bytes <= 8 * 1024**3:
            raise ValueError("memory_bytes must be 64 MiB..8 GiB")
        if not 16 <= self.pids_limit <= 2048:
            raise ValueError("pids_limit must be in [16, 2048]")
        if not 4 * 1024**2 <= self.tmpfs_bytes <= 1024**3:
            raise ValueError("tmpfs_bytes must be 4 MiB..1 GiB")

class DockerBackend:
    """Ephemeral container, no network, immutable local image, bounded resources.

    Only explicit copied input is mounted read-only. Output is ephemeral tmpfs.
    Never give an agent the Docker socket or permission to configure this backend.
    """
    backend_name = "docker"

    def __init__(self, workspace: str | Path, policy: Policy, image: str, *,
                 audit_path: str | Path | None = None, context: str = "default",
                 limits: ContainerLimits | None = None, docker_executable: str = "docker",
                 require_rootless: bool = False) -> None:
        self.workspace = Path(workspace).expanduser().resolve(strict=True)
        if not self.workspace.is_dir():
            raise ValueError("workspace must be an existing directory")
        if not _IMAGE.fullmatch(image):
            raise ValueError("image must be name@sha256:<64 lowercase hex>; mutable tags are denied")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", context):
            raise ValueError("invalid Docker context")
        if policy.network != "deny" or policy.allow_unenforced_network:
            raise PolicyDenied("Docker backend accepts network='deny' only; unsafe process override is forbidden")
        self.policy, self.image, self.context = policy, image, context
        self.limits = limits or ContainerLimits()
        self.audit = AuditLog(audit_path or self.workspace / ".x4" / "audit.jsonl")
        self.docker = shutil.which(docker_executable)
        if not self.docker:
            raise SandboxUnavailable("Docker CLI unavailable; process fallback is forbidden")
        self.env = dict(os.environ)
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            self.env.pop(key, None)
        self.require_rootless = require_rootless

    def _docker(self, argv: Sequence[str], timeout: float = 10) -> subprocess.CompletedProcess[str]:
        try:
            p = subprocess.run([self.docker, "--context", self.context, *argv],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", timeout=timeout,
                check=False, shell=False, env=self.env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxUnavailable(f"Docker command unavailable: {type(exc).__name__}") from exc
        if p.returncode:
            raise SandboxUnavailable(f"Docker command failed ({p.returncode})")
        return p

    def _verify_daemon(self) -> bool:
        r = self._docker(["context", "inspect", self.context, "--format", "{{json .Endpoints.docker}}"])
        try:
            host = str(json.loads(r.stdout).get("Host", ""))
        except (json.JSONDecodeError, AttributeError) as exc:
            raise SandboxUnavailable("cannot verify daemon endpoint") from exc
        if not (host.startswith("unix://") or host.startswith("npipe://") or host.startswith("npipe:")):
            raise SandboxUnavailable("only local Unix/named-pipe Docker contexts are allowed")
        r = self._docker(["info", "--format", "{{json .SecurityOptions}}"])
        try:
            options = " ".join(map(str, json.loads(r.stdout))).lower()
        except (json.JSONDecodeError, TypeError) as exc:
            raise SandboxUnavailable("cannot verify Docker security options") from exc
        if "seccomp" not in options or "unconfined" in options:
            raise SandboxUnavailable("Docker seccomp status missing or unconfined")
        rootless = "rootless" in options
        if self.require_rootless and not rootless:
            raise SandboxUnavailable("rootless daemon required by policy")
        return rootless

    def _argv(self, argv: Sequence[str]) -> tuple[str, ...]:
        args = tuple(str(x) for x in argv)
        if not args or not args[0] or any("\0" in x for x in args):
            raise PolicyDenied("invalid argv or NUL byte")
        if args[0] not in self.policy.allowed_commands or "/" in args[0] or "\\" in args[0]:
            raise PolicyDenied("executable must be an exact allow-listed name")
        if any(x.lower() in {"-c", "/c", "-command", "-encodedcommand", "-enc"} for x in args[1:]):
            raise PolicyDenied("shell command-string flags are denied")
        if any(len(x.encode("utf-8")) > 32768 for x in args):
            raise PolicyDenied("argument exceeds 32 KiB")
        return args

    def _stage(self, target: Path, paths: Sequence[str]) -> None:
        selected: set[str] = set()
        total = 0
        for raw in paths:
            if not isinstance(raw, str) or not raw or "\0" in raw:
                raise PolicyDenied("input must be an explicit relative path")
            p = PurePosixPath(raw.replace("\\", "/"))
            if p.is_absolute() or ":" in raw or any(x in {"", ".", ".."} for x in p.parts):
                raise PolicyDenied("input path traversal or absolute path denied")
            name = p.as_posix()
            if name in selected or any(name.startswith(x + "/") or x.startswith(name + "/") for x in selected):
                raise PolicyDenied("duplicate or overlapping inputs denied")
            selected.add(name)
            source = self.workspace.joinpath(*p.parts)
            current = self.workspace
            for part in p.parts:
                current = current / part
                if current.is_symlink():
                    raise PolicyDenied("symlink inputs denied")
            if not source.exists() or not (source.is_file() or source.is_dir()):
                raise PolicyDenied("input must exist and be a regular file or directory")
            candidates = [source] if source.is_file() else sorted(source.rglob("*"))
            for item in candidates:
                if item.is_symlink() or not (item.is_file() or item.is_dir()):
                    raise PolicyDenied("symlink/special input files denied")
                rel = item.relative_to(self.workspace)
                parts = [x.lower() for x in rel.parts]
                leaf = parts[-1]
                if any(x in _SECRET_PARTS for x in parts) or leaf == ".env" or leaf.startswith(".env.") or leaf in _SECRET_FILES or leaf.endswith(_SECRET_SUFFIXES):
                    raise PolicyDenied("credential, environment, or metadata path denied")
                if item.is_dir():
                    (target / rel).mkdir(parents=True, exist_ok=True)
                    continue
                total += item.stat().st_size
                if total > _INPUT_MAX:
                    raise PolicyDenied("input snapshot exceeds 256 MiB")
                (target / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(item, target / rel, follow_symlinks=False)
        target.chmod(0o755)

    def _create(self, name: str, staged: Path, argv: tuple[str, ...],
                env: Mapping[str, str]) -> list[str]:
        l = self.limits
        args = ["create", "--pull=never", "--name", name, "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", str(l.pids_limit), "--memory", str(l.memory_bytes),
            "--memory-swap", str(l.memory_bytes), "--cpus", f"{l.cpus:g}",
            "--user", "65532:65532", "--ipc", "private", "--shm-size", str(l.tmpfs_bytes),
            "--cgroupns", "private",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={l.tmpfs_bytes},mode=1777",
            "--tmpfs", f"/work:rw,noexec,nosuid,nodev,size={l.tmpfs_bytes},mode=1777",
            "--mount", f"type=bind,source={staged},target=/input,readonly", "--workdir", "/work"]
        for k, v in sorted(env.items()):
            if k not in self.policy.allowed_env or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", k):
                raise PolicyDenied("container environment variable is not allow-listed")
            if k.lower() in {"ld_preload", "ld_library_path", "pythonpath", "pythonhome", "node_options", "bash_env", "docker_host", "docker_context"}:
                raise PolicyDenied("dangerous environment variable denied")
            if not isinstance(v, str) or "\0" in v or len(v.encode("utf-8")) > 8192:
                raise PolicyDenied("invalid environment value")
            args.extend(["--env", f"{k}={v}"])
        return [*args, self.image, *argv]

    def _verify_container(self, raw: str, name: str, staged: Path, argv: tuple[str, ...]) -> None:
        try:
            item = json.loads(raw)
            h, c = item["HostConfig"], item["Config"]
            mounts, tmpfs = item.get("Mounts", []), item["HostConfig"].get("Tmpfs") or {}
            checks = [
                item.get("Name", "").lstrip("/") == name, c.get("Image") == self.image,
                tuple(c.get("Cmd") or ()) == argv, c.get("User") == "65532:65532",
                h.get("NetworkMode") == "none", h.get("ReadonlyRootfs") is True,
                h.get("Privileged") is False, "ALL" in [str(x).upper() for x in (h.get("CapDrop") or [])],
                not h.get("CapAdd"), not h.get("Binds"), not h.get("PortBindings"),
                not h.get("Devices"), not h.get("DeviceRequests"), h.get("PidMode") in {None, "", "private"},
                any("no-new-privileges:true" in str(x).lower() for x in (h.get("SecurityOpt") or [])),
                h.get("Memory") == self.limits.memory_bytes, h.get("MemorySwap") == self.limits.memory_bytes,
                h.get("NanoCpus") == int(self.limits.cpus * 1_000_000_000),
                h.get("PidsLimit") == self.limits.pids_limit, h.get("IpcMode") == "private",
                h.get("ShmSize") == self.limits.tmpfs_bytes, h.get("CgroupnsMode") == "private",
                all(x in tmpfs for x in ("/tmp", "/work")),
                sum(m.get("Type") == "bind" for m in mounts) == 1,
                all(m.get("Destination") in {"/input", "/tmp", "/work", "/dev/shm"} for m in mounts),
            ]
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
            raise SandboxUnavailable("container inspect was incomplete") from exc
        if not all(checks):
            raise SandboxUnavailable("container inspect did not verify all mandatory isolation controls")
        for path in ("/tmp", "/work"):
            if not all(flag in str(tmpfs[path]).lower() for flag in ("noexec", "nosuid", "nodev")):
                raise SandboxUnavailable(f"unsafe tmpfs flags for {path}")
        binds = [m for m in mounts if m.get("Type") == "bind"]
        if len(binds) != 1 or binds[0].get("Destination") != "/input" or binds[0].get("RW") is not False:
            raise SandboxUnavailable("input mount must be read-only and mapped only at /input")
        expected = str(staged.resolve()).replace("\\", "/").rstrip("/").casefold()
        observed = str(binds[0].get("Source", "")).replace("\\", "/").rstrip("/").casefold()
        if expected != observed:
            raise SandboxUnavailable("input mount source differs from the staged snapshot")

    @staticmethod
    def _read(stream: Any, cap: int, out: bytearray, trunc: list[bool]) -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            room = cap - len(out)
            if room > 0:
                out.extend(chunk[:room])
            if len(chunk) > room:
                trunc[0] = True

    def run(self, argv: Sequence[str], *, timeout_seconds: float | None = None,
            env: Mapping[str, str] | None = None, input_paths: Sequence[str] = (),
            sensitive: bool = False, approval_token: str | None = None) -> RunResult:
        run_id, start = str(uuid.uuid4()), time.monotonic()
        args: tuple[str, ...] = ()
        container_id: str | None = None
        name = "x4-sb-" + uuid.uuid4().hex[:20]
        try:
            args = self._argv(argv)
            if sensitive:
                raise PolicyDenied("authorize sensitive operations through CapabilityGate before dispatch")
            timeout = self.policy.timeout_seconds if timeout_seconds is None else timeout_seconds
            if not 0 < timeout <= self.policy.timeout_seconds:
                raise PolicyDenied("timeout exceeds policy")
            supplied_env = dict(env or {})
            if any(k not in self.policy.allowed_env for k in supplied_env):
                raise PolicyDenied("environment variable not allow-listed")
            rootless = self._verify_daemon()
            self.audit.append({"event": "container_starting", "timestamp": time.time(), "run_id": run_id,
                "backend": "docker", "image": self.image, "executable": args[0], "input_count": len(input_paths),
                "argv_sha256": hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
                "network_isolation_enforced": True, "rootless": rootless,
                "limits": {"cpus": self.limits.cpus, "memory_bytes": self.limits.memory_bytes,
                           "pids_limit": self.limits.pids_limit, "tmpfs_bytes": self.limits.tmpfs_bytes}})
            with tempfile.TemporaryDirectory(prefix="x4-input-") as tmp:
                staged = Path(tmp).resolve()
                self._stage(staged, input_paths)
                created = self._docker(self._create(name, staged, args, supplied_env), timeout=15)
                container_id = created.stdout.strip()
                if not _ID.fullmatch(container_id):
                    raise SandboxUnavailable("Docker returned invalid container ID")
                inspect = self._docker(["inspect", "--format", "{{json .}}", container_id])
                self._verify_container(inspect.stdout, name, staged, args)
                p = subprocess.Popen([self.docker, "--context", self.context, "start", "--attach", container_id],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    shell=False, close_fds=True, env=self.env)
                stdout, stderr = bytearray(), bytearray()
                out_trunc, err_trunc = [False], [False]
                threads = [
                    threading.Thread(target=self._read, args=(p.stdout, self.policy.max_output_bytes, stdout, out_trunc), daemon=True),
                    threading.Thread(target=self._read, args=(p.stderr, self.policy.max_output_bytes, stderr, err_trunc), daemon=True)]
                for t in threads:
                    t.start()
                timed_out = False
                try:
                    rc = p.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    try:
                        self._docker(["kill", container_id], timeout=5)
                    except SandboxError:
                        pass
                    p.terminate()
                    try:
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=2)
                    rc = None
                for t in threads:
                    t.join(timeout=2)
                result = RunResult(run_id, args, rc, stdout.decode("utf-8", "replace"),
                    stderr.decode("utf-8", "replace"), time.monotonic()-start, timed_out,
                    out_trunc[0] or err_trunc[0], "allow", backend="docker", network_isolation_enforced=True)
            self.audit.append({"event": "container_finished", "timestamp": time.time(), "run_id": run_id,
                "returncode": result.returncode, "timed_out": result.timed_out,
                "duration_seconds": round(result.duration_seconds, 6), "output_truncated": result.output_truncated})
            return result
        except SandboxError as exc:
            self.audit.append({"event": "container_denied", "timestamp": time.time(), "run_id": run_id,
                "executable": args[0] if args else None, "reason_type": type(exc).__name__, "policy_decision": "deny"})
            raise
        except OSError as exc:
            raise SandboxUnavailable(f"container process failed: {type(exc).__name__}") from exc
        finally:
            if container_id and _ID.fullmatch(container_id):
                try:
                    self._docker(["rm", "--force", container_id])
                except SandboxError:
                    try:
                        self.audit.append({"event": "container_cleanup_failed", "timestamp": time.time(),
                            "run_id": run_id, "container_id_prefix": container_id[:12]})
                    except SandboxError:
                        pass
