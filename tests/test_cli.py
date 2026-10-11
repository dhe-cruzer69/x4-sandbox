import json
from pathlib import Path

from x4.sandbox.cli import main


def test_inspect_does_not_claim_execution_is_enabled(tmp_path, capsys):
    result = main(["inspect", "--workspace", str(tmp_path), "--allow", "python"])
    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["execution_enabled_by_default"] is False
    assert payload["network_isolation_enforced"] is False
    assert payload["network_isolation_status"] == "not_verified_until_container_preflight"


def test_inspect_requires_exact_digest_shape_for_pin_claim(tmp_path, capsys):
    main(["inspect", "--workspace", str(tmp_path), "--allow", "python",
          "--image", "image:latest"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["image_digest_pinned"] is False
