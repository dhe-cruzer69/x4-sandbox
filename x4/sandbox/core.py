"""Policy-gated process execution. This is not an OS security boundary."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


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
            if not c or Path(c).name != c or any(x in c for x in ("/", "\\", "\0")):
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
def _now() -> str: return datetime.now(UTC).isoformat()
def _text(raw: bytes, cap: int) -> tuple[str, bool]:
    return raw[:cap].decode("utf-8", errors="replace"), len(raw) > cap

class AuditLog:
    """JSONL SHA-256 chain; detects edits but cannot prevent full-log replacement."""
    def __init__(self, path: str | Path):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous = self._verify()
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
        row = dict(event); row["previous_hash"] = self.previous
        digest = hashlib.sha256(_json(row).encode()).hexdigest(); row["hash"] = digest
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            with os.fdopen(fd, "a", encoding="utf-8", closefd=False) as f:
                f.write(_json(row) + "\n"); f.flush(); os.fsync(f.fileno())
        finally: os.close(fd)
        self.previous = digest
        return digest

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
        run_id = str(uuid.uuid4()); start = time.monotonic(); args = tuple(str(x) for x in argv)
        try:
            self._validate(args)
            if self.policy.network == "deny" and not self.policy.allow_unenforced_network:
                raise SandboxUnavailable("process backend cannot enforce network denial; execution blocked")
            if sensitive and (not approval_token or approval_token not in self._approval_tokens):
                raise ApprovalRequired("sensitive operation requires a valid approval token")
            timeout = self.policy.timeout_seconds if timeout_seconds is None else timeout_seconds
            if not 0 < timeout <= self.policy.timeout_seconds:
                raise PolicyDenied("run timeout must be positive and within policy limit")
            child_env = {k: os.environ[k] for k in self.policy.allowed_env if k in os.environ}
            for k, v in (env or {}).items():
                if k not in self.policy.allowed_env: raise PolicyDenied(f"environment variable not allowed: {k}")
                if not isinstance(v, str) or "\0" in v: raise PolicyDenied("invalid environment value")
                child_env[k] = v
            if sensitive:
                self._approval_tokens.remove(approval_token)
            self.audit.append({"event":"execution_started","timestamp":_now(),"run_id":run_id,
                               "argv":list(args),"policy_decision":"allow","cwd":str(self.workspace),
                               "network_isolation_enforced":False})
            try:
                p = subprocess.run(list(args), cwd=self.workspace, env=child_env, shell=False,
                    stdin=subprocess.DEVNULL, capture_output=True,
                    timeout=timeout, check=False, close_fds=True)
                out, oc = _text(p.stdout, self.policy.max_output_bytes)
                err, ec = _text(p.stderr, self.policy.max_output_bytes)
                result = RunResult(run_id,args,p.returncode,out,err,time.monotonic()-start,False,oc or ec,"allow")
            except subprocess.TimeoutExpired as e:
                out = e.stdout or b""; err = e.stderr or b""
                if isinstance(out,str): out=out.encode()
                if isinstance(err,str): err=err.encode()
                out,oc=_text(out,self.policy.max_output_bytes); err,ec=_text(err,self.policy.max_output_bytes)
                result=RunResult(run_id,args,None,out,err,time.monotonic()-start,True,oc or ec,"allow")
            self.audit.append({"event":"execution_finished","timestamp":_now(),"run_id":run_id,
                "returncode":result.returncode,"timed_out":result.timed_out,
                "duration_seconds":round(result.duration_seconds,6),"output_truncated":result.output_truncated})
            return result
        except SandboxError as e:
            self.audit.append({"event":"execution_denied","timestamp":_now(),"run_id":run_id,
                               "argv":list(args),"reason":str(e),"policy_decision":"deny"})
            raise
    def _validate(self, args: tuple[str, ...]) -> None:
        if not args or not args[0]: raise PolicyDenied("argv must contain executable")
        if any("\0" in x for x in args): raise PolicyDenied("NUL bytes are forbidden")
        if args[0] not in self.policy.allowed_commands: raise PolicyDenied(f"executable not allow-listed: {args[0]!r}")
        if Path(args[0]).name != args[0]: raise PolicyDenied("use allow-listed executable name, not path")
        if any(x in {"-c","/c","-Command","-EncodedCommand"} for x in args[1:]):
            raise PolicyDenied("shell command-string flags are blocked")
        if shutil.which(args[0], path=os.environ.get("PATH","")) is None:
            raise PolicyDenied(f"executable not found on PATH: {args[0]!r}")
        if self.workspace.resolve() != self.workspace: raise PolicyDenied("workspace path changed")
