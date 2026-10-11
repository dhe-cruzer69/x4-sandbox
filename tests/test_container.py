import json
import subprocess

import pytest

from x4.sandbox.container import ContainerLimits, DockerBackend
from x4.sandbox.core import Policy, PolicyDenied, SandboxUnavailable

IMAGE = "registry.example/x4-runner@sha256:" + "a" * 64


def make_backend(tmp_path, monkeypatch, **kwargs):
    monkeypatch.setattr("x4.sandbox.container.shutil.which", lambda _: "/usr/bin/docker")
    return DockerBackend(tmp_path, Policy(("python",)), IMAGE, **kwargs)


def test_image_digest_is_mandatory(tmp_path, monkeypatch):
    monkeypatch.setattr("x4.sandbox.container.shutil.which", lambda _: "/usr/bin/docker")
    with pytest.raises(ValueError, match="immutable"):
        DockerBackend(tmp_path, Policy(("python",)), "python:latest")


@pytest.mark.parametrize("argv", [
    ("/usr/bin/python", "task.py"), ("python", "-c", "import os"),
    ("python", "-ENC", "payload"), ("python", "bad\0arg"),
])
def test_unsafe_argv_rejected(tmp_path, monkeypatch, argv):
    backend = make_backend(tmp_path, monkeypatch)
    with pytest.raises(PolicyDenied):
        backend._validate_argv(argv)


def test_limits_are_bounded():
    for kwargs in ({"cpus": 0}, {"memory_bytes": 1}, {"pids_limit": 100000}, {"tmpfs_bytes": 1}):
        with pytest.raises(ValueError):
            ContainerLimits(**kwargs)


def test_process_network_override_cannot_enable_container_network(tmp_path, monkeypatch):
    monkeypatch.setattr("x4.sandbox.container.shutil.which", lambda _: "/usr/bin/docker")
    with pytest.raises(PolicyDenied, match="override"):
        DockerBackend(tmp_path, Policy(("python",), allow_unenforced_network=True), IMAGE)


def test_create_args_set_network_and_resource_controls(tmp_path, monkeypatch):
    b = make_backend(tmp_path, monkeypatch)
    staged = tmp_path / "stage"
    staged.mkdir()
    args = b._create_args("x4-test", staged, ("python", "/input/task.py"), {})
    flags = " ".join(args)
    for fragment in (
        "--network none", "--read-only", "--cap-drop ALL",
        "--security-opt no-new-privileges:true", "--memory 536870912",
        "--memory-swap 536870912", "--cpus 1", "--pids-limit 128",
        "--user 65532:65532", "--ipc private", "--cgroupns private", "--pull=never",
    ):
        assert fragment in flags
    assert "target=/input,readonly" in flags
    assert "--privileged" not in args


def test_only_explicit_inputs_are_staged(tmp_path, monkeypatch):
    b = make_backend(tmp_path, monkeypatch)
    (tmp_path / "allowed.txt").write_text("ok", encoding="utf-8")
    (tmp_path / "other.txt").write_text("no", encoding="utf-8")
    staged = tmp_path / "staged"
    staged.mkdir()
    b._stage_inputs(staged, ["allowed.txt"])
    assert (staged / "allowed.txt").read_text(encoding="utf-8") == "ok"
    assert not (staged / "other.txt").exists()


def test_input_traversal_and_symlinks_rejected(tmp_path, monkeypatch):
    b = make_backend(tmp_path, monkeypatch)
    staged = tmp_path / "staged"
    staged.mkdir()
    with pytest.raises(PolicyDenied, match="relative"):
        b._stage_inputs(staged, ["../escape"])
    (tmp_path / "target.txt").write_text("x", encoding="utf-8")
    try:
        (tmp_path / "link.txt").symlink_to(tmp_path / "target.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(PolicyDenied, match="symlink"):
        b._stage_inputs(staged, ["link.txt"])


def test_total_input_size_limit(tmp_path, monkeypatch):
    b = make_backend(tmp_path, monkeypatch)
    monkeypatch.setattr("x4.sandbox.container._INPUT_MAX", 4)
    (tmp_path / "large.bin").write_bytes(b"12345")
    staged = tmp_path / "staged"
    staged.mkdir()
    with pytest.raises(PolicyDenied, match="256 MiB"):
        b._stage_inputs(staged, ["large.bin"])


def test_credential_inputs_rejected(tmp_path, monkeypatch):
    b = make_backend(tmp_path, monkeypatch)
    (tmp_path / ".env").write_text("TOKEN=secret", encoding="utf-8")
    staged = tmp_path / "staged"
    staged.mkdir()
    with pytest.raises(PolicyDenied, match="environment files"):
        b._stage_inputs(staged, [".env"])


def test_inspection_fails_closed_on_missing_guarantee(tmp_path, monkeypatch):
    b = make_backend(tmp_path, monkeypatch)
    bad = {"Config": {"User": "65532:65532", "Image": IMAGE},
           "HostConfig": {"NetworkMode": "bridge"}}
    with pytest.raises(SandboxUnavailable, match="isolation control"):
        b._verify_container(json.dumps(bad), "x4-test", tmp_path, ("python",))


def test_inspection_accepts_exact_hardened_configuration(tmp_path, monkeypatch):
    b = make_backend(tmp_path, monkeypatch)
    staged = tmp_path / "staged"
    staged.mkdir()
    raw = {
        "Name": "/x4-test",
        "Config": {"User": "65532:65532", "Image": IMAGE, "Cmd": ["python", "/input/task.py"]},
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
            "CapDrop": ["ALL"], "CapAdd": [], "SecurityOpt": ["no-new-privileges:true"],
            "Memory": b.limits.memory_bytes, "MemorySwap": b.limits.memory_bytes,
            "PidsLimit": b.limits.pids_limit, "NanoCpus": 1_000_000_000,
            "IpcMode": "private", "CgroupnsMode": "private", "ShmSize": b.limits.tmpfs_bytes,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=67108864",
                      "/work": "rw,noexec,nosuid,nodev,size=67108864"},
            "Binds": [], "PortBindings": {}, "Devices": [], "DeviceRequests": [], "PidMode": "",
        },
        "Mounts": [{"Type": "bind", "Source": str(staged.resolve()), "Destination": "/input", "RW": False}],
    }
    b._verify_container(json.dumps(raw), "x4-test", staged, ("python", "/input/task.py"))


def test_reader_caps_output_without_stopping_drain():
    import io
    out, truncated = bytearray(), [False]
    DockerBackend._reader(io.BytesIO(b"0123456789"), 4, out, truncated)
    assert out == b"0123" and truncated == [True]


def test_windows_docker_desktop_mount_translation():
    expected = "C:/Users/test/AppData/Local/Temp/x4-input"
    observed = "/run/desktop/mnt/host/c/Users/test/AppData/Local/Temp/x4-input"
    assert DockerBackend._same_mount_source(observed, expected)


def test_remote_daemon_is_rejected(tmp_path, monkeypatch):
    b = make_backend(tmp_path, monkeypatch)
    monkeypatch.setattr(b, "_docker", lambda *a, **k: subprocess.CompletedProcess([], 0, '{"Host":"ssh://host"}', ""))
    with pytest.raises(SandboxUnavailable, match="local"):
        b._verify_daemon()


def test_container_image_entrypoint_is_rejected(tmp_path, monkeypatch):
    b = make_backend(tmp_path, monkeypatch)
    staged = tmp_path / "staged-entry"
    staged.mkdir()
    raw = {
        "Name": "/x4-test",
        "Config": {"User": "65532:65532", "Image": IMAGE, "Cmd": ["python"],
                   "Entrypoint": ["/bin/sh", "-c"]},
        "HostConfig": {},
        "Mounts": [],
    }
    with pytest.raises(SandboxUnavailable):
        b._verify_container(json.dumps(raw), "x4-test", staged, ("python",))


def test_docker_cli_environment_drops_endpoint_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote")
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "untrusted-docker-config"))
    b = make_backend(tmp_path, monkeypatch)
    assert not any(k.upper().startswith("DOCKER_") for k in b.env)
