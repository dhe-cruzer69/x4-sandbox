# x4-sandbox

**Secure sandboxed tool execution runtime for AI agents**

Filesystem isolation • Command allow-lists • Resource limits • Approval gates • Immutable audit logs

Part of [ARIEX4Ops / X4](https://github.com/dhe-cruzer69).

## Principle

No tool execution without policy evaluation.

```python
from x4.sandbox import Sandbox

sandbox = Sandbox(
    workspace="./workspace",
    allowed_commands=["python", "git", "ls"],
    network=False,
    timeout_seconds=30,
)
result = sandbox.run(["python", "script.py"])
```

## Status

v0.1 foundation. Evolving concepts from ariexus sandbox tools.

## License

Apache-2.0

## Support

[GitHub Sponsors](https://github.com/sponsors/dhe-cruzer69)
