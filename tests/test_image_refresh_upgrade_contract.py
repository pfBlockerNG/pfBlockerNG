"""Contract for image-refresh.yml's image-upgrade invocation (issue #2299)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "image-refresh.yml"


def _upgrade_script() -> str:
    """Extract the ``id: upgrade`` run body, bounded to its own workflow step."""
    source = WORKFLOW.read_text(encoding="utf-8")
    step_id = source.index("        id: upgrade\n")
    step_start = source.rfind("\n      - name:", 0, step_id)
    step_end = source.index("\n      - name:", step_id)
    step = source[step_start:step_end]
    body: list[str] = []
    for line in step.split("        run: |\n", 1)[1].splitlines():
        if not line.strip():
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    return "\n".join(body)


def _run_upgrade(tmp_path: Path, *, from_tag: str, target_tag: str, force_flag: str) -> list[str]:
    """Run the workflow body with a fake ``sh`` and return image-upgrade argv."""
    fake_sh = tmp_path / "sh"
    fake_sh.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$ARGV_OUT"\n', encoding="utf-8")
    fake_sh.chmod(0o755)
    argv_file = tmp_path / "argv"
    script = _upgrade_script()
    script = script.replace("${{ inputs.compression }}", "zstd").replace("${{ inputs.upgrade_timeout }}", "1200")
    env = os.environ | {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "ARGV_OUT": str(argv_file),
        "GITHUB_WORKSPACE": str(tmp_path),
        "FROM_TAG": from_tag,
        "TARGET_TAG": target_tag,
        "VARIANT": "CE",
        "FORCE_FLAG": force_flag,
        "BRANCH": "",
        "SMOKE_IMAGE": "ghcr.io/pfblockerng/pfsense-ce",
    }
    subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, check=True, capture_output=True, text=True)
    return argv_file.read_text(encoding="utf-8").splitlines()


@pytest.mark.parametrize(
    ("from_tag", "target_tag", "force_flag", "upgrade_pkgs", "force"),
    [
        ("2.8", "2.9", "", False, False),
        ("2.8", "2.8", "--force", True, True),
        ("2.8", "2.8", "", True, False),
    ],
)
def test_upgrade_flag_follows_version_transition_not_force(
    tmp_path: Path,
    from_tag: str,
    target_tag: str,
    force_flag: str,
    upgrade_pkgs: bool,
    force: bool,
) -> None:
    argv = _run_upgrade(tmp_path, from_tag=from_tag, target_tag=target_tag, force_flag=force_flag)
    assert ("--upgrade-pkgs" in argv) is upgrade_pkgs
    assert ("--force" in argv) is force
