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
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/check_webassets_vendor.py"
BUILD_SCRIPT = ROOT / "scripts/build-webassets.sh"
VENDOR_DIR = ROOT / "src/usr/local/www/pfblockerng/vendor/codemirror"
MANIFEST = VENDOR_DIR / "MANIFEST.sha256"

EXPECTED_FILES = (
    "cm-regex.min.js",
    "cm-hooks.min.js",
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


@pytest.mark.skipif(
    shutil.which("npm") is None,
    reason=(
        "npm not on PATH -- this rebuild proof needs a real `npm ci` + esbuild run "
        "(network required) and is not authoritative here anyway; the "
        "webassets-vendor CI job (.github/workflows/test.yml) is the gate that "
        "actually enforces vendor-tree drift on every PR"
    ),
)
def test_build_webassets_reproduces_the_committed_vendor_tree() -> None:
    """The sync guard: a fresh, real `scripts/build-webassets.sh` run from the
    pinned tools/webassets/ source (npm ci + esbuild, network required) must
    leave the committed vendor tree byte-identical -- exactly what CI's drift
    guard checks. A stale/hand-edited vendor tree, or a pin bump that wasn't
    rebuilt, fails this."""
    assert SCRIPT.is_file(), f"missing checker: {SCRIPT}"
    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def _script_patch_argv(target_dir: Path, patch_file: Path) -> list[str]:
    """The patch(1) command line ``build-webassets.sh`` really uses, bound to a fixture."""
    text = BUILD_SCRIPT.read_text(encoding="utf-8")
    match = re.search(r"^\s*(patch\s+\S.*)$", text, re.MULTILINE)
    assert match, f"{BUILD_SCRIPT.name} no longer invokes patch(1)"
    bindings = {"$TOOLS_DIR": str(target_dir), "$_patch": str(patch_file)}
    return [bindings.get(arg, arg) for arg in shlex.split(match.group(1))]


def test_upstream_patches_are_applied_without_fuzz(tmp_path: Path) -> None:
    """A carried patch must FAIL the build once upstream drifts away from its context.

    ``build-webassets.sh`` promises that "a patch that stops applying after a dependency
    bump fails the build here rather than silently reverting the fix in the shipped
    bundle" -- and it runs under ``set -eu``, so a non-zero patch(1) does abort. But
    patch(1)'s default fuzz factor lets a hunk whose OUTER context has drifted apply
    anyway, at a guessed location and with a zero exit status, which is the one way the
    promise can be broken without anything going red. Only ``-F 0`` makes it strict.
    """
    tools = tmp_path / "tools"
    (tools / "pkg").mkdir(parents=True)
    target = tools / "pkg" / "index.js"
    original = [f"line {i}" for i in range(10)]
    original[5] = "const wanted = 1;"
    target.write_text("\n".join(original) + "\n", encoding="utf-8")

    patch_file = tmp_path / "carried.patch"
    patch_file.write_text(
        "--- a/pkg/index.js\n"
        "+++ b/pkg/index.js\n"
        "@@ -3,7 +3,7 @@\n"
        " line 2\n line 3\n line 4\n"
        "-const wanted = 1;\n"
        "+const wanted = 2;\n"
        " line 6\n line 7\n line 8\n",
        encoding="utf-8",
    )

    argv = _script_patch_argv(tools, patch_file)
    clean = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert clean.returncode == 0, f"the fixture patch must apply to a pristine tree: {clean.stderr}"
    assert "const wanted = 2;" in target.read_text(encoding="utf-8")

    # Upstream renames something three lines above the hunk -- inside the context the
    # patch was cut against, outside the lines it edits. That is exactly the shape a
    # dependency bump produces, and it must be refused rather than guessed at.
    drifted = list(original)
    drifted[2] = "line 4 // renamed upstream"
    target.write_text("\n".join(drifted) + "\n", encoding="utf-8")

    result = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert result.returncode != 0, (
        "patch(1) absorbed drifted context with fuzz and reported success, so a future "
        f"@codemirror/view bump would silently ship an unfixed bundle: {result.stdout}"
    )
    assert "const wanted = 2;" not in target.read_text(encoding="utf-8"), "the drifted hunk was applied anyway"
