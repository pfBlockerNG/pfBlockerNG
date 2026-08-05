"""Issue #2143 mutation-resistant workflow contract checks."""

from __future__ import annotations

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
