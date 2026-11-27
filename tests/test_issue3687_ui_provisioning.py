"""Execute UI workflow provisioning without apt, registry access or a VM (#3687)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ui-tests.yml"
CLIENT_MAC = "02:00:00:00:ab:cd"


def _steps() -> list[dict[str, Any]]:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["ui"]["steps"]


def _step(label: str) -> dict[str, Any]:
    matches = [s for s in _steps() if s.get("id") == label or s.get("name", "").startswith(label)]
    assert len(matches) == 1, f"expected one UI provisioning step {label!r}, got {matches}"
    return matches[0]


def _run(step: dict[str, Any], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=cwd,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result


def _executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
    path.chmod(0o755)


@pytest.mark.parametrize("edition,version", [("ce", "2.8"), ("ce", "2.9"), ("plus", "26.03"), ("plus", "26.07")])
def test_client_identity_is_masked_and_scrubbed_for_every_leg(tmp_path: Path, edition: str, version: str) -> None:
    identity = _step("Resolve VM identity")
    assert identity["env"].get("CLIENT_MAC") == "${{ secrets.SMOKE_CLIENT_MAC_ADDRESS }}"
    env = {
        "IMAGE_REF": f"ghcr.io/example/pfsense-{edition}:{version}",
        "INPUT_IMAGE_NAME": f"pfsense-{edition}",
        "CLIENT_MAC": CLIENT_MAC,
        "PLUS_MAC": "02:00:00:00:12:34",
        "PLUS_UUID": "secret-plus-uuid",
        "PLUS_NDI": "secret-plus-ndi",
        "GITHUB_ENV": str(tmp_path / "env"),
    }
    result = _run(identity, ROOT, env)
    assert result.returncode == 0, result.stderr
    assert f"::add-mask::{CLIENT_MAC}" in result.stdout
    exported = (tmp_path / "env").read_text()
    redactions = exported.split("RESOLVED_REDACT<<__EOF__\n")[1].split("__EOF__")[0].strip()
    assert CLIENT_MAC in redactions.splitlines()
    if edition == "ce":
        assert "RESOLVED_VM_MAC=\n" in exported
        assert redactions == CLIENT_MAC
    else:
        assert all(env[key] in redactions.splitlines() for key in ("PLUS_MAC", "PLUS_UUID", "PLUS_NDI"))
    shutil.copytree(ROOT / "scripts", tmp_path / "scripts")
    (tmp_path / "smoke-diag").mkdir()
    log = tmp_path / "smoke-diag/config.xml"
    log.write_text(redactions.lower())
    shots = tmp_path / "test-results/ui-screenshots"
    shots.mkdir(parents=True)
    (shots / "page.png").write_bytes(b"dom-masked screenshot")
    console = tmp_path / "screen-boot.png"
    console.write_bytes(b"console")
    scrub = _step("Scrub Plus secret identity")
    result = _run(scrub, tmp_path, {**env, "SMOKE_REDACT_VALUES": redactions})
    assert result.returncode == 0, result.stderr
    assert all(secret.lower() not in log.read_text().lower() for secret in redactions.splitlines())
    assert (shots / "page.png").read_bytes() == b"dom-masked screenshot"
    assert console.exists() == (edition == "ce")


@pytest.mark.parametrize("tier,marker", [("render", "ui_render"), ("functional", "ui_e2e"), ("browser", "ui_browser")])
def test_every_tier_passes_prepulled_client_to_harness(tmp_path: Path, tier: str, marker: str) -> None:
    step = _step("Run the UI tier")
    assert step["env"].get("SMOKE_CLIENT_MAC_ADDRESS") == "${{ secrets.SMOKE_CLIENT_MAC_ADDRESS }}"
    assert step["env"]["SMOKE_ADMIN_PASSWORD"] == "${{ secrets.SMOKE_ADMIN_PASSWORD }}"
    assert step["env"]["SMOKE_REDACT_VALUES"] == "${{ env.RESOLVED_REDACT }}"
    mapping = _run(_step("tier"), tmp_path, {"TIER": tier, "GITHUB_OUTPUT": str(tmp_path / "output")})
    assert mapping.returncode == 0, mapping.stderr
    assert f"marker={marker}" in (tmp_path / "output").read_text()
    _executable(tmp_path / "bin/python3", 'case "$*" in *canary.xml*) exit 1;; esac')
    _executable(tmp_path / "scripts/select-box.sh", "echo ui-test")
    _executable(
        tmp_path / "scripts/run-smoke.sh",
        'printf "SMOKE_CLIENT_IMAGE_DIR=%s\\n" "$SMOKE_CLIENT_IMAGE_DIR" > "$GITHUB_WORKSPACE/captured"',
    )
    result = _run(
        step,
        tmp_path,
        {
            "PATH": f"{tmp_path}/bin:{os.environ['PATH']}",
            "GITHUB_WORKSPACE": str(tmp_path),
            "MARKER": marker,
            "SCOPE": "full",
            "SMOKE_CLIENT_MAC_ADDRESS": CLIENT_MAC,
        },
    )
    assert result.returncode == 0, result.stderr
    assert f"SMOKE_CLIENT_IMAGE_DIR={tmp_path}/client-image\n" in (tmp_path / "captured").read_text()


def test_client_resolves_and_pulls_by_digest(tmp_path: Path) -> None:
    _executable(
        tmp_path / "bin/oras",
        """case "$1" in
login) cat >/dev/null;;
resolve) echo sha256:abcdef;;
manifest) echo '{"digest":"sha256:abcdef","annotations":{}}';;
pull) printf '%s' "$2" > pulled-ref; touch client.qcow2;;
*) exit 2;;
esac""",
    )
    shutil.copytree(ROOT / "scripts", tmp_path / "scripts")
    env = {
        "PATH": f"{tmp_path}/bin:{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "SMOKE_IMAGE_REPO": "ghcr.io/example",
        "SMOKE_GHCR_USER": "user",
        "SMOKE_GHCR_TOKEN": "token",
    }
    resolve = _step("civm")
    assert "if" not in resolve, "all UI tiers need client provisioning"
    result = _run(resolve, tmp_path, env)
    assert result.returncode == 0, result.stderr
    assert "ref=ghcr.io/example/civm:v1\n" in (tmp_path / "output").read_text()
    assert "digest=sha256:abcdef\n" in (tmp_path / "output").read_text()
    result = _run(
        _step("Pull civm image"),
        tmp_path,
        {**env, "CIVM_REF": "ghcr.io/example/civm:v1", "DIGEST": "sha256:abcdef"},
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "client-image/pulled-ref").read_text() == "ghcr.io/example/civm:v1@sha256:abcdef"
    assert (tmp_path / "client-image/client.qcow2").is_file()


@pytest.mark.parametrize(
    "cache_id,path",
    [("uvcache", "~/.cache/uv")],
)
def test_caches_restore_and_only_save_successful_trusted_misses(cache_id: str, path: str) -> None:
    restore = _step(cache_id)
    assert "if" not in restore
    assert restore["with"]["path"] == path
    saves = [s for s in _steps() if s.get("uses", "").startswith("actions/cache/save@") and s["with"]["path"] == path]
    assert len(saves) == 1
    save = saves[0]
    condition = save["if"]
    # GitHub implicitly applies success() when no status function is present.
    assert all(func not in condition for func in ("always(", "failure(", "cancelled("))
    assert set(condition.split(" && ")) in (
        {f"steps.{cache_id}.outputs.cache-hit != 'true'", "inputs.checkout_ref == ''"},
        {"success()", f"steps.{cache_id}.outputs.cache-hit != 'true'", "inputs.checkout_ref == ''"},
    )
    assert restore["with"]["key"] == save["with"]["key"]
    assert "hashFiles('uv.lock')" in save["with"]["key"]
