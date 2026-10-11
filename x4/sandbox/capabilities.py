"""Deny-by-default capability policy and one-use, scope-bound approvals."""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .core import ApprovalRequired, PolicyDenied


@dataclass(frozen=True)
class ApprovalGrant:
    token: str = field(repr=False)
    capability: str
    resource: str
    expires_at: float


class ApprovalAuthority:
    """Trusted approval issuer. Never expose this object to an agent/model/tool."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[str, tuple[str, str, float]] = {}

    def issue(self, capability: str, resource: str, *, ttl_seconds: float = 60.0) -> ApprovalGrant:
        if (not capability or not resource or "\0" in capability + resource
                or len(capability) > 128 or len(resource) > 512):
            raise ValueError("capability/resource must be non-empty and within size limits")
        if not 1 <= ttl_seconds <= 600:
            raise ValueError("approval TTL must be 1..600 seconds")
        token = secrets.token_urlsafe(32)
        expiry = time.time() + ttl_seconds
        deadline = time.monotonic() + ttl_seconds
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            now = time.monotonic()
            self._grants = {k: v for k, v in self._grants.items() if v[2] > now}
            if len(self._grants) >= 10_000:
                raise PolicyDenied("approval capacity reached; operator review required")
            self._grants[digest] = (capability, resource, deadline)
        return ApprovalGrant(token, capability, resource, expiry)

    def consume(self, token: str | None, capability: str, resource: str) -> None:
        if not token:
            raise ApprovalRequired("one-use approval required")
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            grant = self._grants.pop(digest, None)
        if grant is None:
            raise ApprovalRequired("approval missing, expired, invalid, or already used")
        cap, target, expiry = grant
        if time.monotonic() >= expiry:
            raise ApprovalRequired("approval expired")
        if not secrets.compare_digest(cap, capability) or not secrets.compare_digest(target, resource):
            raise ApprovalRequired("approval does not cover this capability and exact resource")


class CapabilityGate:
    """Only explicitly configured (capability, resource) pairs are permitted."""

    def __init__(self, grants: Iterable[tuple[str, str]] = (), *,
                 approval_required: Iterable[tuple[str, str]] = (),
                 authority: ApprovalAuthority | None = None) -> None:
        self._grants = frozenset((str(c), str(r)) for c, r in grants)
        self._approval_required = frozenset((str(c), str(r)) for c, r in approval_required)
        if any(not c or not r or "\0" in c + r for c, r in self._grants | self._approval_required):
            raise ValueError("capability names and resource scopes must be non-empty")
        if not self._approval_required.issubset(self._grants):
            raise ValueError("approval-required pairs must also be explicitly allow-listed")
        self._authority = authority or ApprovalAuthority()

    def authorize(self, capability: str, resource: str, *, approval_token: str | None = None) -> None:
        pair = (capability, resource)
        if pair not in self._grants:
            raise PolicyDenied("capability/resource pair not allow-listed")
        if pair in self._approval_required:
            self._authority.consume(approval_token, capability, resource)
        elif approval_token is not None:
            raise PolicyDenied("approval token supplied where approval is not configured")


class GuardedLocalModelRouter:
    """Call a wrapped router with provider=local and allow_fallback=False, never retry."""

    _OPTIONS = {"temperature", "top_p", "max_tokens", "stop"}

    def __init__(self, router: Any, gate: CapabilityGate, allowed_models: Iterable[str]) -> None:
        self._router = router
        self._gate = gate
        self._models = frozenset(allowed_models)
        if not self._models or any(not m or "\0" in m or len(m) > 256 for m in self._models):
            raise ValueError("exact local model identifiers are required")

    def generate(self, *, model: str, prompt: str, provider: str = "local",
                 approval_token: str | None = None, **options: Any) -> Any:
        if provider != "local":
            raise PolicyDenied("only local provider is permitted; cloud fallback is disabled")
        if model not in self._models:
            raise PolicyDenied("model is not allow-listed")
        if not isinstance(prompt, str):
            raise PolicyDenied("prompt must be UTF-8 text")
        try:
            prompt_size = len(prompt.encode("utf-8"))
        except UnicodeError as exc:
            raise PolicyDenied("prompt contains invalid Unicode") from exc
        if prompt_size > 1_000_000:
            raise PolicyDenied("prompt must be no larger than 1 MiB")
        if set(options) - self._OPTIONS:
            raise PolicyDenied("unsupported model-router options")
        if "temperature" in options and (isinstance(options["temperature"], bool) or not isinstance(options["temperature"], (int, float)) or not 0 <= options["temperature"] <= 2):
            raise PolicyDenied("temperature must be within [0, 2]")
        if "top_p" in options and (isinstance(options["top_p"], bool) or not isinstance(options["top_p"], (int, float)) or not 0 < options["top_p"] <= 1):
            raise PolicyDenied("top_p must be within (0, 1]")
        if "max_tokens" in options and (isinstance(options["max_tokens"], bool) or not isinstance(options["max_tokens"], int) or not 1 <= options["max_tokens"] <= 32768):
            raise PolicyDenied("max_tokens must be within [1, 32768]")
        if "stop" in options:
            stop = options["stop"]
            if isinstance(stop, str):
                valid_stop = len(stop) <= 128
            elif isinstance(stop, list):
                valid_stop = len(stop) <= 8 and all(isinstance(x, str) and len(x) <= 128 for x in stop)
            else:
                valid_stop = False
            if not valid_stop:
                raise PolicyDenied("stop must be a string or list of at most eight 128-character strings")
        self._gate.authorize("model.invoke", model, approval_token=approval_token)
        return self._router.generate(model=model, prompt=prompt, provider="local",
                                     allow_fallback=False, **options)


class GuardedMCPGateway:
    """Gate exact server/tool invocations; transport and MCP authentication stay external."""

    def __init__(self, gateway: Any, gate: CapabilityGate, *,
                 capabilities: Mapping[tuple[str, str], str] | None = None) -> None:
        self._gateway, self._gate = gateway, gate
        self._capabilities = dict(capabilities or {})
        for (server, tool), capability in self._capabilities.items():
            self._resource(server, tool)
            if not capability or "\0" in capability:
                raise ValueError("tool capability must be a non-empty identifier")

    @staticmethod
    def _resource(server: str, tool: str) -> str:
        for value in (server, tool):
            if not value or len(value) > 128 or "\0" in value or "/" in value or value in {".", ".."}:
                raise PolicyDenied("server/tool identifiers must be exact safe names")
        return f"{server}/{tool}"

    def call_tool(self, *, server: str, tool: str, arguments: Mapping[str, Any],
                  approval_token: str | None = None) -> Any:
        resource = self._resource(server, tool)
        if not isinstance(arguments, Mapping):
            raise PolicyDenied("tool arguments must be a JSON object")
        try:
            encoded = json.dumps(dict(arguments), ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > 1_000_000:
                raise PolicyDenied("tool arguments exceed 1 MiB")
            # Round-trip to an owned JSON snapshot so concurrent caller mutation cannot
            # change data after validation but before dispatch.
            normalized = json.loads(encoded)
        except PolicyDenied:
            raise
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise PolicyDenied("tool arguments must be bounded, valid JSON-safe data") from exc
        # Capability selection comes from trusted adapter configuration, never caller input.
        capability = self._capabilities.get((server, tool), "mcp.tool.invoke")
        self._gate.authorize(capability, resource, approval_token=approval_token)
        # Deliberately do not log payloads; arguments can include secrets or user data.
        return self._gateway.call_tool(server=server, tool=tool, arguments=normalized)
