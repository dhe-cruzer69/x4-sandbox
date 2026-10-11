import json, sys
from pathlib import Path
import pytest
from x4.sandbox import AuditLog, Policy, PolicyDenied, Sandbox, SandboxUnavailable

def py(): return Path(sys.executable).name
def make(tmp_path, **kw): return Sandbox(tmp_path, Policy((py(),), **kw))
def script(sb, text):
    p=sb.workspace/"task.py"; p.write_text(text,encoding="utf-8")
    return sb.run([py(),p.name])

def test_empty_allowlist_rejected():
    with pytest.raises(ValueError): Policy(())
def test_default_network_deny_fails_closed(tmp_path):
    with pytest.raises(SandboxUnavailable): make(tmp_path).run([py(),"--version"])
def test_allowed_script_runs(tmp_path):
    r=script(make(tmp_path,allow_unenforced_network=True),"print('x4-ok')")
    assert r.returncode==0 and r.stdout.strip()=="x4-ok"
    assert not r.network_isolation_enforced
def test_unlisted_command_rejected(tmp_path):
    with pytest.raises(PolicyDenied,match="not allow-listed"): make(tmp_path).run(["git","--version"])
def test_shell_string_flag_rejected(tmp_path):
    with pytest.raises(PolicyDenied,match="shell command"): make(tmp_path,allow_unenforced_network=True).run([py(),"-c","print(1)"])
def test_timeout_is_bounded(tmp_path):
    sb=make(tmp_path,timeout_seconds=1,allow_unenforced_network=True)
    r=script(sb,"import time; time.sleep(2)")
    assert r.timed_out and r.returncode is None
def test_timeout_cannot_exceed_policy(tmp_path):
    with pytest.raises(PolicyDenied,match="timeout"): make(tmp_path,allow_unenforced_network=True).run([py(),"--version"],timeout_seconds=99)
def test_nul_argument_rejected(tmp_path):
    with pytest.raises(PolicyDenied,match="NUL"): make(tmp_path,allow_unenforced_network=True).run([py(),"bad\0arg"])
def test_environment_is_allowlisted(tmp_path):
    with pytest.raises(PolicyDenied,match="not allowed"): make(tmp_path,allow_unenforced_network=True).run([py(),"--version"],env={"UNSAFE":"1"})
def test_audit_tampering_detected(tmp_path):
    p=tmp_path/"audit.jsonl"; a=AuditLog(p); a.append({"event":"one","n":1}); a.append({"event":"two","n":2})
    lines=p.read_text().splitlines(); row=json.loads(lines[0]); row["n"]=99; lines[0]=json.dumps(row); p.write_text("\n".join(lines)+"\n")
    with pytest.raises(Exception,match="audit (chain broken|hash mismatch)"): AuditLog(p)

def test_sensitive_operation_requires_approval_token(tmp_path):
    sb=Sandbox(tmp_path, Policy((py(),),allow_unenforced_network=True))
    with pytest.raises(Exception,match="approval token"):
        sb.run([py(),"--version"],sensitive=True)
def test_sensitive_approval_token_is_one_use(tmp_path):
    sb=Sandbox(tmp_path, Policy((py(),),allow_unenforced_network=True),approval_tokens=("approval-token-123456",))
    result=sb.run([py(),"--version"],sensitive=True,approval_token="approval-token-123456")
    assert result.returncode==0
    with pytest.raises(Exception,match="approval token"):
        sb.run([py(),"--version"],sensitive=True,approval_token="approval-token-123456")


def test_output_capture_is_bounded(tmp_path):
    sb = make(tmp_path, allow_unenforced_network=True, max_output_bytes=32)
    result = script(sb, "print('x' * 10000)")
    assert len(result.stdout.encode("utf-8")) <= 32
    assert result.output_truncated


def test_audit_redacts_raw_arguments(tmp_path):
    sb = make(tmp_path, allow_unenforced_network=True)
    sb.run([py(), "--version", "sensitive-argument-not-for-audit"])
    audit = (tmp_path / ".x4" / "audit.jsonl").read_text(encoding="utf-8")
    assert "sensitive-argument-not-for-audit" not in audit
    assert '"argv_sha256"' in audit
    assert '"argument_count":3' in audit


def test_policy_rejects_windows_path_in_executable_allowlist():
    with pytest.raises(ValueError, match="invalid executable"):
        Policy((r"C:\Windows\System32\cmd.exe",))

def test_process_allowlist_network_policy_fails_closed(tmp_path):
    sb = Sandbox(tmp_path, Policy((py(),), network="allowlist", allow_unenforced_network=True))
    with pytest.raises(SandboxUnavailable, match="allow-list networking"):
        sb.run([py(), "--version"])


def test_process_rejects_path_environment_override(tmp_path):
    sb = make(tmp_path, allow_unenforced_network=True)
    with pytest.raises(PolicyDenied, match="environment variable override"):
        sb.run([py(), "--version"], env={"PATH": "custom-value"})


def test_audit_log_detects_external_change_after_init(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.append({"event": "first"})
    with path.open("a", encoding="utf-8") as stream:
        stream.write("{}\n")
    with pytest.raises(Exception, match="audit log changed"):
        audit.append({"event": "second"})


def test_audit_log_instances_append_from_verified_shared_tail(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = AuditLog(path)
    second = AuditLog(path)

    first.append({"event": "first"})
    second.append({"event": "second"})
    first.append({"event": "third"})

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [row["event"] for row in rows] == ["first", "second", "third"]
    assert AuditLog(path).previous == rows[-1]["hash"]
