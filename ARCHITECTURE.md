# X4 Sandbox Architecture v0.3

## Trust boundaries

Model / agent (untrusted intent)
  -> CapabilityGate (exact capability + exact resource)
  -> one-use scoped approval for configured sensitive operations
  -> trusted host-side dispatcher
     -> GuardedLocalModelRouter (provider local, cloud fallback disabled)
     -> GuardedMCPGateway (exact server/tool)
     -> DockerBackend for isolated code execution with no network
  -> local Docker daemon / Docker Desktop VM / host kernel (trusted computing base)

The guarded router and MCP classes wrap an already trusted implementation. This repository has no concrete X4 model-router, MCP gateway transport, identity provider, or approval UI to bind to, so these adapters are policy interfaces rather than a deployed end-to-end integration. The gate and approval authority must remain in a trusted host control plane.

## Docker backend guarantees

The backend requires an immutable image reference name@sha256:<digest> and pull=never, rejects remote daemon contexts, refuses network-allowlist/unsafe override policies, verifies daemon seccomp status, then creates and inspects a disposable container before starting it. It checks the actual container config for:

- NetworkMode none; no network allow-list is implemented.
- Read-only root filesystem, all Linux capabilities dropped, no capability additions, no-new-privileges, non-root UID/GID.
- CPU, memory (swap ceiling equals memory ceiling), PID, shared memory, and tmpfs bounds.
- Private IPC/cgroup namespace; no privileged mode, host PID mode, published ports, devices, or GPU/device requests.
- Exactly one read-only bind mount at /input, sourced from an explicit-input snapshot; writable output is ephemeral tmpfs.

If an inspection field is missing or disagrees, the backend fails closed before starting the container. It drains output concurrently and bounds captured output; on timeout it attempts container kill then removes the container. Cleanup failures are audited and require review. Docker daemon/API access is not passed into the workload.

## Limits of container isolation

Docker containers use OS namespaces, cgroups, capabilities and security profiles, but share the kernel. Network mode none removes external networking from the container; loopback remains. Docker Desktop on Windows runs Linux containers inside its managed Linux VM: that VM is part of the trusted base. Containers are not a defence against host-kernel/runtime vulnerabilities, host root/administrator access, malicious images, or a compromised Docker daemon. Rootless mode reduces daemon risk but does not replace these checks. The implementation checks the security options surfaced by docker info; it does not prove the kernel is free of vulnerabilities or independently audit the seccomp profile's full contents.

## Windows-native isolation decision

This branch's execution backend is Docker/OCI, not a Windows-native AppContainer/Job Object implementation. On Windows, use Docker Desktop Linux containers only for workloads compatible with the pinned Linux image. For hostile native Windows executables, use a separately launched Windows Sandbox/VM with networking, clipboard, host sharing, peripherals and vGPU disabled by policy. Avoid mapped host folders; if required, map only a new staging snapshot read-only and use a distinct, ACL-restricted export directory. Windows Job Objects can limit/terminate process trees but are not themselves a filesystem or network sandbox. AppContainer/LPAC can provide capability-based access restrictions, but a production launcher must implement and verify tokens, ACLs, network capabilities, process assignment and cleanup using Windows APIs. None of those Windows-native controls are claimed by this code.

## Capability policy

Resources use exact identities such as model.invoke / qwen3:4b or mcp.tool.invoke / filesystem/read_file. No wildcard grants exist. Model adapter validates model/provider/options, forces provider=local and allow_fallback=False. MCP adapter validates the server/tool target and serializable bounded arguments; it never writes argument contents to the local audit log.

Approval grants are random, short-lived, single-use, and bound to one capability/resource pair. The process that receives the grant is not necessarily the human approval service: ApprovalAuthority is a local in-memory primitive, not an authenticated identity system. A trusted UI/policy service must authenticate the approver, display canonical operation details, issue a grant only after approval, and protect the authority from agents. Persistent/multi-worker deployment requires a transactional shared store with replay control and authenticated audit exports.

## Process backend

Legacy process mode remains outside the OS security boundary. It uses an executable allow-list, shell-free argument vectors, bounded captured output, timeouts, environment allow-lists and an audit chain. It cannot enforce filesystem/network isolation or hard resource quotas and must not execute hostile code. Default network-deny remains fail-closed unless the unsafe acknowledgement is explicitly set.

## Audit limitations

Audit records are JSONL hash-chained. That detects row changes and chain discontinuities, but not wholesale replacement, deletion, replay across restored logs, or privileged filesystem manipulation. Export checkpoints to a separate trust domain; sign them with a key held outside this process before treating them as evidence.
