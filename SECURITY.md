# Security Policy

## Safe use

- Prefer DockerBackend; keep network mode none. Use only reviewed, immutable digest-pinned images already present locally.
- Never grant model/agent processes Docker daemon socket or API access.
- Do not run untrusted/generated code with the legacy process backend. Its unsafe network flag does not create isolation.
- Only stage explicit non-sensitive input paths. Container output is ephemeral unless a separate reviewed artifact-export protocol is added.
- Keep CapabilityGate and ApprovalAuthority outside all model, MCP, tool, and sandbox processes.
- Only permit exact capability/resource pairs. Require fresh approval for destructive, external-write, credential, or other high-impact operations.
- Never send secrets or private approval tokens into prompts, process arguments, logs, or MCP payload logs.
- Store audit checkpoints outside the runner's filesystem trust domain.

## Security boundary

Docker's configured container controls are verified before execution, but this does not make the shared kernel or daemon untrusted. Host root/administrator, daemon control, a vulnerable kernel/runtime, malicious image content, and races in the caller's own workspace are outside the guarantee. On Windows, Docker Desktop Linux containers add its Linux VM to the trusted computing base. Native Windows AppContainer/Job Object/Windows Sandbox execution is not implemented by this backend.

The MCP/model classes are guarded adapter seams only; they do not implement user authentication, OAuth, a human approval UI, durable multi-host grant storage, or a concrete external service connection. Integrate them only after binding to actual X4 router/gateway contracts and testing authorization in those systems.

## Reporting

Report suspected vulnerabilities privately to repository maintainers. Avoid publishing credentials, approval tokens, personal data, or sensitive audit records. Include the affected commit, reproducible steps, environment details, and impact where safely possible.
