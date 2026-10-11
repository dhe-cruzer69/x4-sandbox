"""Policy-gated process execution. This is not an OS security boundary."""
from __future__ import annotations
import hashlib, json, os, shutil, signal, subprocess, threading, time, uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

class SandboxError(RuntimeError):
    """Base sandbox exception."""
class PolicyDenied(SandboxError):
    """Operation rejected by policy."""
class SandboxUnavailable(SandboxError):
    """Requested security guarantee is unavailable."""
class ApprovalRequired(PolicyDenied):
    """A sensitive operation lacks a valid one-use approval token."""

@dataclass(frozen=True)
class Policy:
    allowed_commands: tuple[str, ...]
    network: str = "deny"
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1_000_000
    allowed_env: tuple[str, ...] = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL")
    allow_unenforced_network: bool = False
    def __post_init__(self):
        if not self.allowed_commands: raise ValueError("allowed_commands must not be empty")
        if self.network not in {"deny", "allowlist"}: raise ValueError("invalid network policy")
        if not 0 < self.timeout_seconds <= 3600: raise ValueError("timeout must be in (0, 3600]")
        if not 0 < self.max_output_bytes <= 10_000_000: raise ValueError("invalid output limit")
        for c in self.allowed_commands:
            if not c or Path(c).name != c or "/" in c or "\\" in c or "\0" in c:
                raise ValueError(f"invalid executable allow-list entry: {c!r}")

@dataclass(frozen=True)
class RunResult:
    run_id: str
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    output_truncated: bool
    policy_decision: str
    backend: str = "process"
    network_isolation_enforced: bool = False

def _json(obj: Mapping[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def _now() -> str: return datetime.now(timezone.utc).isoformat()
def _text(raw: bytes, cap: int) -> tuple[str, bool]:
    return raw[:cap].decode("utf-8", errors="replace"), len(raw) > cap

class AuditLog:
    """JSONL SHA-256 chain; detects edits but cannot prevent full-log replacement."""
    _path_locks_guard = threading.Lock()
    _path_locks: dict[str, Any] = {}

    def __init__(self, path: str | Path):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        key = str(self.path.resolve())
        with type(self)._path_locks_guard:
            self._lock = type(self)._path_locks.setdefault(key, threading.RLock())
        before = self._file_signature()
        verified_tail = self._verify()
        after = self._file_signature()
        if before != after:
            raise SandboxError("audit log changed while it was being verified")
        self.previous = verified_tail
        self._signature = after

    def _file_signature(self) -> tuple[int, int, int] | None:
        try:
            info = self.path.stat()
        except FileNotFoundError:
            return None
        return (info.st_ino, info.st_size, info.st_mtime_ns)

    def _verify(self) -> str:
        if not self.path.exists() or not self.path.stat().st_size: return "0" * 64
        prev = "0" * 64
        with self.path.open(encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                try: row = json.loads(line)
                except json.JSONDecodeError as e: raise SandboxError(f"invalid audit JSON on line {n}") from e
                digest = row.pop("hash", None)
                if row.get("previous_hash") != prev: raise SandboxError(f"audit chain broken on line {n}")
                if hashlib.sha256(_json(row).encode()).hexdigest() != digest:
                    raise SandboxError(f"audit hash mismatch on line {n}")
                prev = digest
        return prev
    def append(self, event: Mapping[str, Any]) -> str:
        # Lock the log file across threads and processes. The signature check catches
        # out-of-band writes since this instance was initialized or last appended.
        with self._lock:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
            locked = False
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX)
                locked = True
                if self._file_signature() != self._signature:
                    raise SandboxError("audit log changed since this writer's last append")
                row = dict(event)
                row["previous_hash"] = self.previous
                digest = hashlib.sha256(_json(row).encode()).hexdigest()
                row["hash"] = digest
                with os.fdopen(fd, "a", encoding="utf-8", closefd=False) as f:
                    f.write(_json(row) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                self.previous = digest
                self._signature = self._file_signature()
                return digest
            finally:
                if locked:
                    if os.name == "nt":
                        import msvcrt
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

class Sandbox:
    """Run allow-listed programs with shell=False, timeout and bounded output.

    Process mode does not enforce network, filesystem, CPU, memory or disk isolation.
    The default network-deny setting therefore fails closed unless explicitly overridden.
    Never use the override for untrusted code.
    """
    def __init__(self, workspace: str | Path, policy: Policy, audit_path: str | Path | None = None,
                 approval_tokens: Sequence[str] = ()):
        self.workspace = Path(workspace).expanduser().resolve()
        if not self.workspace.is_dir(): raise ValueError("workspace must be an existing directory")
        self.policy = policy
        self.audit = AuditLog(audit_path or self.workspace / ".x4" / "audit.jsonl")
        self._approval_tokens = set(approval_tokens)
    def run(self, argv: Sequence[str], *, timeout_seconds: float | None = None,
            env: Mapping[str, str] | None = None, sensitive: bool = False,
            approval_token: str | None = None) -> RunResult:
        run_id = str(uuid.uuid4())
        start = time.monotonic()
        args = tuple(str(x) for x in argv)
        try:
            self._validate(args)
            if self.policy.network != "deny":
                raise SandboxUnavailable("process backend cannot enforce allow-list networking; execution blocked")
            if not self.policy.allow_unenforced_network:
                raise SandboxUnavailable("process backend cannot enforce network denial; execution blocked")
            if sensitive and (not approval_token or approval_token not in self._approval_tokens):
                raise ApprovalRequired("sensitive operation requires a valid one-use approval token")
            timeout = self.policy.timeout_seconds if timeout_seconds is None else timeout_seconds
            if not 0 < timeout <= self.policy.timeout_seconds:
                raise PolicyDenied("run timeout must be positive and within policy limit")
            child_env = {k: os.environ[k] for k in self.policy.allowed_env if k in os.environ}
            for k, v in (env or {}).items():
                if k not in self.policy.allowed_env:
                    raise PolicyDenied(f"environment variable not allowed: {k}")
                if k.upper() in {
                    "PATH", "SYSTEMROOT", "WINDIR", "LD_PRELOAD", "LD_LIBRARY_PATH",
                    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "NODE_OPTIONS",
                    "BASH_ENV", "ENV", "RUBYOPT", "PERL5OPT",
                }:
                    raise PolicyDenied(f"environment variable override is unsafe: {k}")
                if not isinstance(v, str) or "\0" in v:
                    raise PolicyDenied("invalid environment value")
                child_env[k] = v
            if sensitive:
                self._approval_tokens.remove(approval_token)
            argv_digest = hashlib.sha256(_json({"argv": list(args)}).encode()).hexdigest()
            self.audit.append({
                "event": "execution_started", "timestamp": _now(), "run_id": run_id,
                "executable": Path(args[0]).name, "argument_count": len(args),
                "argv_sha256": argv_digest, "policy_decision": "allow",
                "network_isolation_enforced": False,
            })
            kwargs: dict[str, Any] = {
                "cwd": self.workspace, "env": child_env, "shell": False,
                "stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE, "close_fds": True,
            }
            if os.name == "nt":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            else:
                kwargs["start_new_session"] = True
            try:
                proc = subprocess.Popen(list(args), **kwargs)
            except OSError as e:
                raise SandboxUnavailable(f"process executable failed to start: {type(e).__name__}") from e

            out = bytearray()
            err = bytearray()
            out_truncated = [False]
            err_truncated = [False]
            out_reader = threading.Thread(
                target=self._drain_output,
                args=(proc.stdout, self.policy.max_output_bytes, out, out_truncated),
                daemon=True,
            )
            err_reader = threading.Thread(
                target=self._drain_output,
                args=(proc.stderr, self.policy.max_output_bytes, err, err_truncated),
                daemon=True,
            )
            out_reader.start()
            err_reader.start()
            timed_out = False
            try:
                returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill_process_tree(proc, child_env)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                returncode = None
            out_reader.join(timeout=2)
            err_reader.join(timeout=2)
            result = RunResult(
                run_id, args, returncode,
                bytes(out).decode("utf-8", errors="replace"),
                bytes(err).decode("utf-8", errors="replace"),
                time.monotonic() - start, timed_out,
                out_truncated[0] or err_truncated[0], "allow",
            )
            self.audit.append({
                "event": "execution_finished", "timestamp": _now(), "run_id": run_id,
                "returncode": result.returncode, "timed_out": result.timed_out,
                "duration_seconds": round(result.duration_seconds, 6),
                "output_truncated": result.output_truncated,
            })
            return result
        except SandboxError as e:
            self.audit.append({
                "event": "execution_denied", "timestamp": _now(), "run_id": run_id,
                "executable": Path(args[0]).name if args else None,
                "argument_count": len(args), "reason_type": type(e).__name__,
                "policy_decision": "deny",
            })
            raise

    @staticmethod
    def _drain_output(stream: Any, cap: int, sink: bytearray, truncated: list[bool]) -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            room = cap - len(sink)
            if room > 0:
                sink.extend(chunk[:room])
            if len(chunk) > room:
                truncated[0] = True

    @staticmethod
    def _kill_process_tree(proc: subprocess.Popen[bytes], child_env: Mapping[str, str]) -> None:
        if os.name == "nt":
            system_root = os.environ.get("SystemRoot", os.environ.get("SYSTEMROOT", r"C:\Windows"))
            taskkill = Path(system_root) / "System32" / "taskkill.exe"
            if taskkill.is_file():
                try:
                    killed = subprocess.run(
                        [str(taskkill), "/PID", str(proc.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        env=dict(child_env), timeout=5, check=False, shell=False,
                    )
                    if killed.returncode == 0 or proc.poll() is not None:
                        return
                except (OSError, subprocess.TimeoutExpired):
                    pass
            proc.kill()
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()

    def _validate(self, args: tuple[str, ...]) -> None:
        if not args or not args[0]: raise PolicyDenied("argv must contain executable")
        if any("\0" in x for x in args): raise PolicyDenied("NUL bytes are forbidden")
        if args[0] not in self.policy.allowed_commands: raise PolicyDenied(f"executable not allow-listed: {args[0]!r}")
        if Path(args[0]).name != args[0]: raise PolicyDenied("use allow-listed executable name, not path")
        if any(x.lower() in {"-c", "/c", "-command", "-encodedcommand", "-enc", "-e"} for x in args[1:]):
            raise PolicyDenied("shell command-string flags are blocked")
        if shutil.which(args[0], path=os.environ.get("PATH","")) is None:
            raise PolicyDenied(f"executable not found on PATH: {args[0]!r}")
        if self.workspace.resolve() != self.workspace: raise PolicyDenied("workspace path changed")
