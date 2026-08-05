"""Issue #2143 mutation-resistant workflow contract checks."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
REPUBLISH = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")


def _input_block(name: str) -> str:
    lines = REPUBLISH.splitlines()
    marker = f"      {name}:"
    start = lines.index(marker)
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if line.startswith("      ") and not line.startswith("        "):
            break
        block.append(line)
    return "\n".join(block)


def test_release_build_record_keeps_native_package_identity() -> None:
    assert '"destinations":' not in RELEASE
    assert '--build-record "$GITHUB_WORKSPACE/build-record.json"' in RELEASE
    assert 'RENAMED="${PKG_DIR}/${BASE}-${VARIANT}-${PFSENSE_VERSION}.pkg"' in RELEASE
    assert 'RENAMED_DEP="${DEP_PKG_DIR}/${DEP_BASE}-${VARIANT}-${PFSENSE_VERSION}.pkg"' in RELEASE
    record_step = RELEASE.split("name: Write the destination-bound build record", 1)[1]
    record_step = record_step.split("name: Build the .pkg via build-leg.sh", 1)[0]
    assert '"destinations":' not in record_step


def test_manual_republish_inputs_are_individually_required() -> None:
    assert "required: true" in _input_block("release_id")
    assert "required: true" in _input_block("release_tag")


def test_release_build_leg_step_binds_variant_from_the_matrix_row() -> None:
    """The invocation test supplies VARIANT itself, so pin the step env that defines it."""
    step = RELEASE.split("      - name: Build the .pkg via build-leg.sh", 1)[1].split("        run: |", 1)[0]
    assert "VARIANT:" in step
    assert "${{ matrix.variant }}" in step.split("VARIANT:", 1)[1].split("\n", 1)[0]


def test_release_build_leg_passes_variant_to_builder(tmp_path: Path) -> None:
    marker = '          PKG="$(sh scripts/build-leg.sh \\\n'
    invocation = marker + RELEASE.split(marker, 1)[1].split("          PKG_DIR=", 1)[0]
    fake_builder = tmp_path / "build-leg.sh"
    captured = tmp_path / "args"
    fake_builder.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE\"\nprintf '%s\\n' result.pkg\n",
        encoding="utf-8",
    )
    fake_builder.chmod(0o755)
    env = os.environ | {
        "CAPTURE": str(captured),
        "PKG_CHANNEL": "testing",
        "VARIANT": "Plus",
        "PORTS_SHA": "ports-sha",
        "ABI": "FreeBSD:16:amd64",
        "PY": "py311",
        "PHP": "8.3",
        "PORTVERSION": "4.0.1.a1",
        "GITHUB_WORKSPACE": str(ROOT),
    }
    completed = subprocess.run(
        ["sh", "-c", textwrap.dedent(invocation.replace("sh scripts/build-leg.sh", f"sh {fake_builder}"))],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert captured.read_text(encoding="utf-8").splitlines() == [
        "--channel",
        "testing",
        "--variant",
        "Plus",
        "--ports-ref",
        "ports-sha",
        "--abi",
        "FreeBSD:16:amd64",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--pkgversion",
        "4.0.1.a1",
        "--build-record",
        f"{ROOT}/build-record.json",
    ]
