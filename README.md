# x4-sandbox

**Secure sandboxed tool execution for AI agents**

Filesystem isolation • Command allow-lists • Resource limits • Approval gates • Immutable audit logs

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-v0.1-orange)](CHANGELOG.md)

Part of **[ARIEX4Ops / X4](https://github.com/dhe-cruzer69)**.

---

## Principle

No tool execution without policy evaluation.

## 60-second example

```python
from x4.sandbox import Sandbox

sandbox = Sandbox(
    workspace="./workspace",
    allowed_commands=["python", "git", "ls"],
    network=False,
    timeout_seconds=30,
)
result = sandbox.run(["python", "script.py"])
print(result.stdout)
```

## Architecture & threat model

See [ARCHITECTURE.md](ARCHITECTURE.md).

Isolation levels (planned):
1. Process-level (v0.1 target)
2. Container
3. MicroVM / remote worker

Never claim stronger isolation than the implementation provides.

## Related

- [x4-agents](https://github.com/dhe-cruzer69/x4-agents) — primary consumer
- [x4-core](https://github.com/dhe-cruzer69/x4-core) — shared primitives
- [x4-mcp-gateway](https://github.com/dhe-cruzer69/x4-mcp-gateway) — controlled external tools

## License

Apache-2.0

## Security

See [SECURITY.md](SECURITY.md).

## Support

**[GitHub Sponsors](https://github.com/sponsors/dhe-cruzer69)**
