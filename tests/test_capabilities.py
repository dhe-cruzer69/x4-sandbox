import pytest

from x4.sandbox.capabilities import (
    ApprovalAuthority, CapabilityGate, GuardedLocalModelRouter, GuardedMCPGateway,
)
from x4.sandbox.core import ApprovalRequired, PolicyDenied


class FakeRouter:
    def __init__(self):
        self.calls = []
    def generate(self, **kwargs):
        self.calls.append(kwargs)
        return "local-result"


class FakeGateway:
    def __init__(self):
        self.calls = []
    def call_tool(self, **kwargs):
        self.calls.append(kwargs)
        return {"ok": True}


def test_capabilities_deny_by_default():
    with pytest.raises(PolicyDenied):
        CapabilityGate().authorize("model.invoke", "qwen3:4b")


def test_approval_is_scope_bound_and_one_use():
    authority = ApprovalAuthority()
    pair = ("mcp.tool.invoke", "filesystem/delete_file")
    gate = CapabilityGate([pair], approval_required=[pair], authority=authority)
    wrong = authority.issue(pair[0], "filesystem/read_file")
    with pytest.raises(ApprovalRequired):
        gate.authorize(*pair, approval_token=wrong.token)
    grant = authority.issue(*pair)
    gate.authorize(*pair, approval_token=grant.token)
    with pytest.raises(ApprovalRequired):
        gate.authorize(*pair, approval_token=grant.token)


def test_expired_approval_is_rejected(monkeypatch):
    authority = ApprovalAuthority()
    grant = authority.issue("mcp.tool.invoke", "db/write", ttl_seconds=1)
    gate = CapabilityGate([("mcp.tool.invoke", "db/write")],
        approval_required=[("mcp.tool.invoke", "db/write")], authority=authority)
    monkeypatch.setattr("x4.sandbox.capabilities.time.time", lambda: grant.expires_at + 1)
    with pytest.raises(ApprovalRequired, match="expired"):
        gate.authorize("mcp.tool.invoke", "db/write", approval_token=grant.token)


def test_model_router_is_local_only_no_fallback_and_option_allowlist():
    fake = FakeRouter()
    gate = CapabilityGate([("model.invoke", "qwen3:4b")])
    wrapper = GuardedLocalModelRouter(fake, gate, ["qwen3:4b"])
    assert wrapper.generate(model="qwen3:4b", prompt="hello") == "local-result"
    assert fake.calls[0]["provider"] == "local" and fake.calls[0]["allow_fallback"] is False
    with pytest.raises(PolicyDenied, match="cloud fallback"):
        wrapper.generate(model="qwen3:4b", prompt="hi", provider="cloud")
    with pytest.raises(PolicyDenied, match="not allow-listed"):
        wrapper.generate(model="unknown", prompt="hi")
    with pytest.raises(PolicyDenied, match="options"):
        wrapper.generate(model="qwen3:4b", prompt="hi", endpoint="https://example.com")


def test_mcp_exact_capability_and_safe_arguments():
    real = FakeGateway()
    gate = CapabilityGate([("mcp.tool.invoke", "filesystem/read_file")])
    wrapper = GuardedMCPGateway(real, gate)
    assert wrapper.call_tool(server="filesystem", tool="read_file", arguments={"path": "a.txt"}) == {"ok": True}
    with pytest.raises(PolicyDenied):
        wrapper.call_tool(server="filesystem", tool="delete_file", arguments={"path": "a.txt"})
    with pytest.raises(PolicyDenied, match="JSON-safe"):
        wrapper.call_tool(server="filesystem", tool="read_file", arguments={"x": object()})
    assert len(real.calls) == 1
