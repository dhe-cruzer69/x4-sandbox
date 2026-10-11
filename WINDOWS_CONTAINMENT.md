# Windows-native containment plan

Status: design only; not implemented or validated by the Docker backend.

## Recommended first implementation

Use Windows Sandbox for disposable native-Windows workloads where the OS edition, optional feature and hardware virtualization support it. Its defaults are not safe for hostile input: networking and clipboard sharing are enabled by default. Generate and validate the .wsb file from a typed policy model; never accept arbitrary user-supplied XML.

Baseline policy:
- Networking disabled.
- vGPU disabled.
- Clipboard redirection disabled.
- Audio input, video input and printer redirection disabled.
- No mapped host folders and no logon command by default.
- Set an explicit MemoryInMB limit.
- Use a unique per-run disposable input/output layout. If input mapping becomes unavoidable, mount only a private staging snapshot read-only. Do not expose the user's home, repositories, credential folders, browser profiles, USB roots, or Docker socket.
- Verify feature availability and generated configuration before launching. If Windows Sandbox is unavailable or configuration cannot be verified, fail closed instead of falling back to ordinary process execution.

Windows Sandbox does not expose a general per-process CPU quota through .wsb; do not claim one. A host watchdog can terminate the sandbox after a deadline but does not replace a Job Object or VM hard resource policy. If output must be copied to the host, use a distinct ACL-restricted export path and treat files as hostile; validate file type/count/size and never automatically execute them.

## AppContainer / LPAC alternative

AppContainer provides capability-based isolation of file, registry, process, device and network access. A robust launcher must create a restricted token/package identity, omit network capabilities unless needed, grant only explicit ACLs to per-run directories, start the process with the restricted token, and audit its actual token/capabilities. Low-privilege AppContainer (LPAC) may be more restrictive but compatibility varies. This is Windows API implementation work, not equivalent to running an ordinary subprocess with a Job Object.

## Job Objects

Create a Job Object before launch, apply extended process limits and CPU-rate limits with SetInformationJobObject, assign the process before it can spawn children (prefer a suspended process plus assignment, then resume), prohibit breakaway, and terminate the entire job on timeout/cancel. Job Objects provide process/resource accounting and termination; they do not independently prevent network or filesystem access. Combine them with AppContainer/ACL controls or Windows Sandbox/VM.

## Test plan

- Windows 10/11 supported editions, virtualization enabled/disabled, Sandbox optional feature absent/present.
- Denied networking verified from inside sandbox by attempted egress and DNS; clipboard and shared folders disabled.
- Host-path traversal, symlink/reparse-point handling, ACL denial, output import, secrets in parent environment, and cleanup after timeout/crash.
- Child process spawn, Job Object assignment failure, breakaway attempt, CPU/memory/PID exhaustion.
- Confirm host files and credentials are inaccessible and unchanged after hostile test corpus.
- Capture OS build, generated .wsb hash, policy, test result, sandbox exit status and independent audit checkpoint.

## Decision

Docker/OCI was implemented first because its none network driver and cgroup controls offer an immediately testable path for Linux-image jobs. For Windows-native jobs, treat Windows Sandbox as the preferred separate isolation worker; use Job Objects as a resource/termination complement, not as the whole sandbox.
