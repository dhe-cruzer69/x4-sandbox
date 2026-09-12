# x4-sandbox Architecture

## Purpose

Provide a clear isolation boundary between agent intent and tool execution.

## Threat model focus

- Filesystem escape
- Command injection
- Resource exhaustion (CPU / memory / disk / time)
- Network leakage
- Audit bypass

## Target capabilities

```
Sandbox
├── filesystem isolation (workspace root)
├── command allow-list
├── network policy (default deny)
├── resource limits (CPU, memory, disk, time)
├── approval gates for elevated actions
├── immutable audit events
└── cleanup on exit
```

## API direction

```python
from x4.sandbox import Sandbox

sb = Sandbox(
    workspace="./workspace",
    allowed_commands=["python", "git"],
    network=False,
    timeout_seconds=30,
)
result = sb.run(["python", "task.py"])
```

## Isolation levels (planned)

1. Process-level (current target for v0.1)
2. Container
3. MicroVM / remote worker (later)

Never claim stronger isolation than the implementation provides.
