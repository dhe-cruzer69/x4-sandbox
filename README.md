# x4-sandbox

Policy-gated command execution with a Docker/OCI isolation backend and capability gates for X4 model/tool adapters.

## Security status

Prefer DockerBackend for untrusted-workload experiments only after the host Docker installation, image, and workload are reviewed. A container shares its host kernel (or Docker Desktop's Linux VM kernel); it is not equivalent to a dedicated microVM. A Docker daemon/socket is a high-privilege control surface. Never mount the Docker socket into the workload or expose Docker API access to the model/MCP agent.

The legacy process backend is not a security boundary. It cannot enforce network, filesystem, or hard resource isolation. It refuses execution by default; its unsafe override is only for trusted programs.

## Requirements

- Python 3.11+
- Docker Engine or Docker Desktop with a local named-pipe/Unix-socket context and active seccomp profile.
- A preloaded, reviewed image addressed by immutable repository@sha256:<64 lowercase hex> digest. The runner never pulls an image during execution.
- On Windows, Docker Desktop Linux containers use the Docker Desktop VM as part of the trusted computing base. For Windows-native hostile binaries, use a separately provisioned Windows Sandbox/VM boundary; this Docker backend does not sandbox native Windows processes.

## Install and tests

    python -m pip install -e ".[test]"
    python -m pytest
    python -m ruff check . --select E9,F63,F7,F82,F401

CI runs tests on Linux and Windows. Unit tests validate fail-closed policy and generated container configuration; they do not replace a live container/kernel isolation test.

## Inspect

    x4-sandbox inspect --workspace ./workspace --allow python

Inspect is non-executing. It reports planned controls and does not assert that the daemon, image, or host isolation is verified.

## Run with Docker

Create a workspace and put only non-sensitive workload inputs in it. Choose a reviewed local image and pin its digest:

    x4-sandbox run --backend docker --workspace ./workspace --allow python --image registry.example/x4-runner@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --input task.py -- python /input/task.py

The example digest is illustrative, not a real image reference. Replace it with the actual digest of an image that is already present locally.

Before starting the workload, the backend verifies the local Docker endpoint, checks daemon seccomp status, creates an ephemeral container, and inspects its effective configuration. The runner denies startup unless required controls match: network mode none, read-only root filesystem, dropped Linux capabilities, no-new-privileges, non-root UID/GID, CPU/memory/PID limits, private IPC/cgroup namespace, bounded noexec/nosuid/nodev tmpfs paths, and a single explicit read-only /input mount. The container is removed after execution; cleanup failure is audited and requires operator attention.

Default limits: 1 CPU, 512 MiB memory/no extra swap, 128 PIDs, 64 MiB per tmpfs. Inputs are copied to a fresh temporary snapshot; paths, symlinks, common credential locations, and files above 256 MiB total are rejected. Do not stage untrusted or secret-bearing directories.

Network mode none removes the container's external network interface (loopback remains). This backend has no network allow-list mode. Model access must happen outside the sandbox via a separate guarded local-model adapter; do not provide network to an untrusted process just to reach Ollama.

## Explicitly unsafe process mode

Only for programs you already trust:

    x4-sandbox run --backend process --acknowledge-unenforced-network --workspace ./workspace --allow python -- python --version

The flag is a risk acknowledgement, not a firewall. This command can still access host files and network with the current user's privileges. Do not run downloaded/generated code or untrusted tool output in this mode.

## Capability / approval gates

CapabilityGate denies unconfigured capability/resource pairs. ApprovalAuthority issues short-lived, one-use approvals scoped to the exact operation and resource. GuardedLocalModelRouter allows exact local model IDs only and explicitly disables cloud fallback. GuardedMCPGateway authorizes exact server/tool pairs, bounds JSON-safe arguments, and avoids logging payloads.

These are adapter interfaces, not a live X4 router/MCP deployment. No MCP transport authorization, OAuth flow, user identity provider, approval UI, or integration with a specific X4 service is included. Keep the approval issuer and gate in a trusted host-side control plane, never inside the model or tool process. A trusted caller must authenticate the human/policy authority before it invokes ApprovalAuthority.issue; the class itself is in-memory and is not an identity system or durable distributed approval service.

## Audit and cleanup

JSONL SHA-256 chaining detects record edits and chain breaks. It does not prevent deleting/replacing the entire log or protecting it from a privileged host administrator. Export the final hash to a separate trusted system for stronger tamper evidence. Container cleanup failures are not silently converted into process-mode execution.

## Further hardening before production

Run dedicated integration and adversarial tests against supported Docker Engine/Desktop versions and the exact base image; inspect actual kernel/cgroup/seccomp capability state; run the daemon rootless where practical; use an image built from reviewed source and verify its digest; pin and verify Python dependencies/artifacts; provide an external approval/identity service; export signed audit receipts; and test recovery/cleanup under daemon failure. For stronger isolation from the shared kernel, use a separately managed microVM/VM worker with a narrow authenticated job protocol.
