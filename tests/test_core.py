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
    with pytest.raises(PolicyDenied,match="NUL"): make(tmp_path,allow_unenforced_network=True).run([py(),"bad\\0arg"])
def test_environment_is_allowlisted(tmp_path):
    with pytest.raises(PolicyDenied,match="not allowed"): make(tmp_path,allow_unenforced_network=True).run([py(),"--version"],env={"UNSAFE":"1"})
def test_audit_tampering_detected(tmp_path):
    p=tmp_path/"audit.jsonl"; a=AuditLog(p); a.append({"event":"one","n":1}); a.append({"event":"two","n":2})
    lines=p.read_text().splitlines(); row=json.loads(lines[0]); row["n"]=99; lines[0]=json.dumps(row); p.write_text("\\n".join(lines)+"\\n")
    with pytest.raises(Exception,match="audit (chain broken|hash mismatch)"): AuditLog(p)
