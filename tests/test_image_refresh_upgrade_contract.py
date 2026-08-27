"""Contract for image-refresh.yml's image-upgrade invocation (issue #2299)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tests._workflow_steps import extract_after

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
    for line in extract_after(step, "        run: |\n").splitlines():
        if not line.strip():
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    return "\n".join(body)


def _run_upgrade(
    tmp_path: Path,
    *,
    from_tag: str,
    target_tag: str,
    force_flag: str,
    freebsd_version: str = "15.0-RELEASE",
) -> list[str]:
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
        "FREEBSD_VERSION": freebsd_version,
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


def test_self_refresh_leg_passes_expect_freebsd_major(tmp_path: Path) -> None:
    """Same-version legs derive --expect-freebsd-major from matrix.freebsd_version
    (issue #2242) — the self-consistency check still applies even though this
    leg's freebsd_version provenance is otherwise out of scope."""
    argv = _run_upgrade(tmp_path, from_tag="2.8", target_tag="2.8", force_flag="", freebsd_version="15.0-RELEASE")
    assert "--expect-freebsd-major" in argv
    assert argv[argv.index("--expect-freebsd-major") + 1] == "15"


def test_cross_version_leg_passes_expect_freebsd_major(tmp_path: Path) -> None:
    """issue #2242: cross-version legs ALSO pass --expect-freebsd-major —
    matrix.freebsd_version is the TARGET row's value in both leg modes (the
    version-tracker's direct-leg builder), so the self-consistency check applies
    on every leg, not only same-version refreshes."""
    argv = _run_upgrade(tmp_path, from_tag="2.8", target_tag="2.9", force_flag="", freebsd_version="16.0-RELEASE")
    assert "--expect-freebsd-major" in argv
    assert argv[argv.index("--expect-freebsd-major") + 1] == "16"


def test_missing_freebsd_version_omits_expect_freebsd_major(tmp_path: Path) -> None:
    """An empty matrix.freebsd_version (unreachable on the live matrix) must not
    derive a garbage major — the flag is simply omitted. Pins the omission only;
    the digits guard itself is proven by the non-digit sibling test."""
    argv = _run_upgrade(tmp_path, from_tag="2.8", target_tag="2.9", force_flag="", freebsd_version="")
    assert "--expect-freebsd-major" not in argv


def test_non_digit_freebsd_major_omits_expect_freebsd_major(tmp_path: Path) -> None:
    """A freebsd_version with no leading digits (no dot to split on) must not
    hand a non-numeric value to --expect-freebsd-major, which rejects it."""
    argv = _run_upgrade(tmp_path, from_tag="2.8", target_tag="2.9", force_flag="", freebsd_version="15-STABLE")
    assert "--expect-freebsd-major" not in argv
