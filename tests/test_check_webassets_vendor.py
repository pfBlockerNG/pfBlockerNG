"""Vendor-tree proof for the CodeMirror 6 regex-list editor bundle (issue #1669).

pfBlockerNG is a NO_BUILD FreeBSD port: the CodeMirror 6 bundle under
``src/usr/local/www/pfblockerng/vendor/codemirror/`` must be a committed static
file matching its pinned ``tools/webassets/`` source -- there is no build step
on the appliance to regenerate it. These tests pin that: the committed files
match their own ``MANIFEST.sha256`` (fails if a vendor file is hand-edited
without regenerating the manifest), the vendor dir carries no stray extra
files, the license doc names the CodeMirror/Lezer projects, and a fresh
``scripts/build-webassets.sh`` run reproduces the committed tree byte-for-byte
(the CI drift guard, ``scripts/check_webassets_vendor.py``, run for real).
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/check_webassets_vendor.py"
VENDOR_DIR = ROOT / "src/usr/local/www/pfblockerng/vendor/codemirror"
MANIFEST = VENDOR_DIR / "MANIFEST.sha256"

EXPECTED_FILES = (
    "cm-regex.min.js",
    "LICENSES.md",
)


def _manifest_entries() -> dict[str, str]:
    assert MANIFEST.is_file(), f"missing manifest: {MANIFEST}"
    entries: dict[str, str] = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        entries[name] = digest
    return entries


def test_manifest_lists_exactly_the_expected_vendor_files() -> None:
    assert set(_manifest_entries()) == set(EXPECTED_FILES)


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_committed_vendor_file_matches_its_manifest_digest(name: str) -> None:
    entries = _manifest_entries()
    path = VENDOR_DIR / name
    assert path.is_file(), f"missing vendor file: {path}"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == entries[name], f"{name} content does not match its MANIFEST.sha256 entry"


def test_vendor_dir_has_no_untracked_extra_files() -> None:
    assert VENDOR_DIR.is_dir(), f"missing vendor dir: {VENDOR_DIR}"
    on_disk = {p.name for p in VENDOR_DIR.iterdir() if p.is_file()}
    assert on_disk == set(EXPECTED_FILES) | {"MANIFEST.sha256"}


def test_no_css_file_is_emitted() -> None:
    """CM6 injects its own styles at runtime (style-mod) -- the editor's theme/sizing
    rides EditorView.theme() inside cm-regex.js itself, so there is no separate
    stylesheet to vendor (unlike the retired Prism/code-input tree, which shipped
    prism.min.css + code-input.min.css)."""
    on_disk = {p.name for p in VENDOR_DIR.iterdir() if p.is_file()}
    assert not any(name.endswith(".css") for name in on_disk)


def test_licenses_md_names_codemirror_and_lezer_and_their_license() -> None:
    text = (VENDOR_DIR / "LICENSES.md").read_text(encoding="utf-8")
    assert "CodeMirror" in text
    assert "Lezer" in text
    assert text.count("MIT") >= 2


def test_build_webassets_reproduces_the_committed_vendor_tree() -> None:
    """The sync guard: a fresh, real `scripts/build-webassets.sh` run from the
    pinned tools/webassets/ source (npm ci + esbuild, network required) must
    leave the committed vendor tree byte-identical -- exactly what CI's drift
    guard checks. A stale/hand-edited vendor tree, or a pin bump that wasn't
    rebuilt, fails this."""
    assert SCRIPT.is_file(), f"missing checker: {SCRIPT}"
    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
