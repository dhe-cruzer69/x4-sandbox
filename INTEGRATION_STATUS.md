# X4 Integration Contract Status

Reviewed 2026-10-12 from the default branches of the repositories linked below. This record prevents a tested adapter from being mistaken for a live end-to-end security integration.

## Findings

| Component | Current inspected contract | Missing production contract |
|---|---|---|
| [x4-router](https://github.com/dhe-cruzer69/x4-router) | `Router.add_route(path, target)`, `Router.resolve(path)`, `Router.health()`. Default branch commit [65daecdb](https://github.com/dhe-cruzer69/x4-router/commit/65daecdb84e938628c83c3dee2ffe6f369ea5439) labels this an L0 scaffold. | No model generation API, provider selection contract, local endpoint attestation, fallback policy, request context or authenticated caller interface. Route registry alone cannot guarantee local-only model execution. |
| [x4-mcp](https://github.com/dhe-cruzer69/x4-mcp) | `MCPServer.register_tool(name, handler)`, `list_tools()`, and `health()`. Default branch commit [f85d7e94](https://github.com/dhe-cruzer69/x4-mcp/commit/f85d7e94a6e4c9ba1c2ac0b0ee122a99003eca3a) marks the package/server as L0. | No request dispatch interface, authenticated principal/context, schema/risk policy, approval transport or production MCP protocol handling. A callable registry isn't a secured MCP gateway. |
| [x4-mcp-gateway](https://github.com/dhe-cruzer69/x4-mcp-gateway) | Default branch commit [d7ea9e36](https://github.com/dhe-cruzer69/x4-mcp-gateway/commit/d7ea9e36c625bcdeea9636a5526908055524d540); repository currently contains documentation and repository metadata, not an executable gateway package. | No transport/authentication middleware, concrete registry/policy engine, schema validation pipeline, invocation dispatcher, durable approval service or audit implementation to wrap. |

## What this repository implements

- `GuardedLocalModelRouter` is an adapter contract around a future/local-only router implementation. It allow-lists exact model IDs and asks the wrapped implementation for provider `local` and `allow_fallback=False`. Because the inspected `x4-router` does not implement `generate`, this wrapper is not directly wired to that scaffold and cannot prove the actual inference endpoint is local.
- `GuardedMCPGateway` is an adapter contract around a future gateway implementation. It gates exact server/tool resource pairs and bounded JSON arguments. The inspected `x4-mcp` server has no `call_tool` method and the gateway repository has no executable dispatcher, so this is not registered in or active on the existing server transport.
- `CapabilityGate` denies by default. Approval grants are in-memory, short-lived, one-use and bound to the exact capability/resource. The class does not authenticate a human; only a separately trusted identity/approval control plane may call the issuer in production.
- `DockerBackend` is the executable containment work in this branch. A real Docker Engine/Desktop integration and adversarial isolation run on the intended host/image remain mandatory before production use.

## Integration acceptance criteria

1. Implement reviewed, versioned router and MCP contracts in their own repositories, with request context/principal propagated from an authenticated boundary.
2. Bind model invocation to an allow-listed local transport and model ID; test that every fallback/cloud target is denied and cannot be enabled by untrusted input.
3. Bind each MCP invocation to authenticated principal, exact server/tool, validated schema, canonical resource, risk tier and policy decision. Destructive/external writes require a fresh approval authenticated by a trusted issuer and consumed once at the dispatcher.
4. Store grants/replay state and audit checkpoints in a durable, access-controlled trust domain for multi-worker deployments; sign/export audit checkpoints outside the process.
5. Add contract tests against the actual router and MCP implementations, plus an end-to-end denial suite. Until then keep this integration status “adapter only / not production integrated.”
