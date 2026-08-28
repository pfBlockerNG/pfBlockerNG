"""Issue #2143 release artifacts follow one build-role matrix row."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
MATRIX = (ROOT / "scripts/read-version-matrix.sh").read_text(encoding="utf-8")
ACTION = (ROOT / ".github/actions/read-version-matrix/action.yml").read_text(encoding="utf-8")


def test_release_uses_existing_one_row_release_matrix() -> None:
    assert "release_matrix:" in ACTION
    assert "release_matrix<<__EOF_RELEASE_MATRIX__" in MATRIX
    assert "release_matrix: ${{ steps.matrices.outputs.release_matrix }}" in RELEASE
    assert "fromJson(needs.read-matrix.outputs.release_matrix)" in RELEASE


def test_release_asset_names_include_row_identity_without_channel_routing() -> None:
    assert 'RENAMED="${PKG_DIR}/${BASE}-${VARIANT}-${PFSENSE_VERSION}.pkg"' in RELEASE
    assert 'RENAMED_DEP="${DEP_PKG_DIR}/${DEP_BASE}-${VARIANT}-${PFSENSE_VERSION}.pkg"' in RELEASE
    assert "channels_" not in RELEASE
    assert "relpkg-${{ matrix.variant }}-${{ matrix.pfsense_version }}" in RELEASE
