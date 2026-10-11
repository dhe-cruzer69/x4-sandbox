# x4-sandbox Architecture v0.2

The process backend runs an allow-listed executable using argument arrays,
shell=False, a bounded timeout, bounded captured output, an environment allow-list,
a workspace working directory, and JSONL hash-chained audit records.

## Security boundary

This is process-level containment, not a sandbox for hostile code. It does not
enforce network denial, filesystem access controls, CPU quotas, memory quotas,
disk quotas, syscall filtering, or Windows Job Objects. The configured default
network-deny policy therefore fails closed unless the caller explicitly opts into
the unenforced limitation. Do not use that override for untrusted code.

Container and remote-worker adapters must report effective capabilities. Any request
requiring isolation must fail closed unless the backend proves the control is active.
Hash chaining detects log edits but cannot prevent a privileged actor from replacing
the entire log; export the final hash independently for stronger evidence.
