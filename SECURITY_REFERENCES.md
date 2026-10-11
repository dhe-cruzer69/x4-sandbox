# Security design references

Reviewed on 2026-10-12. These are primary vendor/specification references; the implementation and supported host configurations must still be verified by tests.

## Docker / OCI

- [Docker none network driver](https://docs.docker.com/engine/network/drivers/none/) — removes the container's external network interface; loopback remains. Used for the backend's network-deny mode.
- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/) — CPU, memory and memory/swap controls require kernel/cgroup support. The backend verifies the resulting values via container inspection and fails closed if they differ.
- [Docker rootless mode](https://docs.docker.com/engine/security/rootless/) — runs the daemon and containers without root privileges, reducing the impact of daemon/runtime vulnerabilities. Optional strict rootless check exists, but rootless mode is not a substitute for the remaining controls.
- [Docker security](https://docs.docker.com/engine/security/) — the Docker daemon and host kernel remain part of the trusted computing base. Do not expose the socket/API to untrusted agents.
- [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) — documents capability dropping, no-new-privileges, read-only rootfs, PID, memory, CPU, tmpfs and networking options.

## Windows-native containment design

- [Configure Windows Sandbox with a WSB file](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file) — networking, mapped folders, clipboard, audio/video, vGPU and memory configuration; networking/clipboard defaults must be explicitly disabled for hostile inputs.
- [Windows Sandbox sample configurations](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-sample-configuration) — examples of disabling networking and vGPU.
- [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) and [launching an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer) — OS-enforced capability-based access and token/ACL requirements; not implemented by this branch.
- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) — process groups, termination and resource limits; Job Objects do not independently establish filesystem/network isolation.

## MCP authorization

- [Model Context Protocol authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) — authorization is protocol/transport specific and must be implemented by the actual server/client; the local wrapper in this repository is not an OAuth or identity service.
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) — tool/data trust boundaries and security pitfalls.

## Decision record

Docker/OCI was implemented first because the user requested network and resource restrictions and Docker has explicit, inspectable controls for them. The Windows-native path is documented as the next adapter design, not misrepresented as already implemented. MCP/router integration is currently guarded by exact capability/resource adapters; production service identity, transport authorization, durable approval storage, and human approval UI remain additional work.
