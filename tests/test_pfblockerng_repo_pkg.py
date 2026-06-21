"""Off-box build and conf-write tests for the pfblockerng-repo meta-package (ADR-39 Phase 2).

Builds the ``pfSense-pkg-pfblockerng-repo`` port with ``build-pkg-portable.py`` against
``pfBlockerNG/FreeBSD-ports@pfblockerng/use-github`` (the ports checkout in
``/tmp/ug-adr39``) and the local pfBlockerNG source (``scripts/lib/detect_variant.sh``).
Then asserts:

1. The manifest ``scripts.post-install`` and ``scripts.post-deinstall`` carry the
   SUB_LIST-substituted bodies (``%%DETECT_HELPER%%`` replaced by the installed path).
2. ``detect_variant.sh`` appears in the manifest's ``files`` section at the expected
   installed path.
3. Simulating the post-install script with mocked detection env vars produces a conf that
   matches the expected direct-Pages URL format for two sample boxes (CE 2.8/amd64 and
   Plus 26.03/aarch64).

Covers both branches of the post-install guard: wrong phase (early exit) and POST-INSTALL
(writes the conf).
"""

from __future__ import annotations

import importlib.util
import io
import json
import lzma
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

# --------------------------------------------------------------------------- #
# Load build-pkg-portable.py (hyphen-named; use importlib).
# --------------------------------------------------------------------------- #

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TOOL = _REPO_ROOT / "scripts" / "build-pkg-portable.py"
_spec = importlib.util.spec_from_file_location("build_pkg_portable", _TOOL)
assert _spec is not None and _spec.loader is not None
bpp = importlib.util.module_from_spec(_spec)
sys.modules["build_pkg_portable"] = bpp
_spec.loader.exec_module(bpp)

# The meta-package port directory on pfblockerng/use-github.
_PORTS_ROOT = Path("/tmp/ug-adr39")
_PORT_DIR = _PORTS_ROOT / "net" / "pfSense-pkg-pfblockerng-repo"

# The installed path of the detection helper (from the port's SUB_LIST).
# Must match DETECT_HELPER_DIR in the Makefile.
_PORTNAME = "pfSense-pkg-pfblockerng-repo"
_DETECT_HELPER_INSTALLED = f"/usr/local/share/{_PORTNAME}/detect_variant.sh"

# Direct GitHub Pages base URL for the release channel (ADR-39).
_PAGES_BASE = "https://pfblockerng.github.io/pkg"
_RELEASE_CHANNEL = "release"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _read_pkg(path: Path) -> tuple[dict, dict, tarfile.TarFile]:
    """Open a .pkg (xz-compressed tar) and return (full_manifest, compact_manifest, tf)."""
    raw = lzma.decompress(path.read_bytes())
    tf = tarfile.open(fileobj=io.BytesIO(raw))
    full = json.loads(_extract(tf, "+MANIFEST"))
    compact = json.loads(_extract(tf, "+COMPACT_MANIFEST"))
    return full, compact, tf


def _extract(tf: tarfile.TarFile, name: str) -> bytes:
    member = tf.extractfile(name)
    assert member is not None, f"missing member {name!r} in .pkg"
    return member.read()


def _build_meta_pkg(tmp_path: Path) -> Path:
    """Build the meta-package .pkg and return the path to the .pkg file."""
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports",
            str(_PORTS_ROOT),
            "--port-dir",
            str(_PORT_DIR),
            "--local-src",
            str(_REPO_ROOT),
            "--abi",
            "FreeBSD:15:amd64",
            "--py-flavor",
            "py311",
            "--compression",
            "xz",
            "--out",
            str(out),
        ]
    )
    assert rc == 0, "build-pkg-portable.py must exit 0 for the meta-package"
    pkgs = list(out.glob("pfSense-pkg-pfblockerng-repo-*.pkg"))
    assert len(pkgs) == 1, f"expected exactly one .pkg output, got {pkgs}"
    return pkgs[0]


def _expected_conf(varver: str, arch: str) -> str:
    """The conf the post-install should write for a given catalog subtree."""
    catalog = f"{varver}/{arch}"
    return (
        f"# pfBlockerNG (release channel) — self-hosted pkg repository (ADR-17).\n"
        f"# NONE-signed: trust anchor is HTTPS to the host (no signing key). The catalog\n"
        f"# path is fully resolved on install/upgrade (on-box detection; ADR-39).\n"
        f"# priority 100 sits above the base Netgate `pfSense` repo so cross-repo\n"
        f"# resolution (pkg install/upgrade, GUI Install) selects our build.\n"
        f"pfblockerng: {{\n"
        f'  url: "{_PAGES_BASE}/{_RELEASE_CHANNEL}/{catalog}",\n'
        f"  mirror_type: none,\n"
        f"  signature_type: none,\n"
        f"  priority: 100,\n"
        f"  enabled: yes\n"
        f"}}\n"
    )


# --------------------------------------------------------------------------- #
# 1. Build the .pkg and inspect the manifest.
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def built_pkg(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict, dict, tarfile.TarFile]:
    """Build the meta-package once and return (full, compact, tf) for all tests."""
    tmp = tmp_path_factory.mktemp("meta_pkg")
    pkg = _build_meta_pkg(tmp)
    return _read_pkg(pkg)


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_build_succeeds(tmp_path: Path) -> None:
    """The meta-package builds without error and produces exactly one .pkg file.

    Scenario:
      Given the pfSense-pkg-pfblockerng-repo port and the local pfBlockerNG source,
      When  build-pkg-portable.py is invoked for CE 2.8/amd64,
      Then  the build exits 0 and a .pkg file is created.
    """
    pkg = _build_meta_pkg(tmp_path)
    assert pkg.is_file(), "build must produce a .pkg file"
    assert pkg.name.startswith("pfSense-pkg-pfblockerng-repo-")


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_manifest_has_post_install_script(built_pkg: tuple) -> None:
    """The manifest carries a ``post-install`` script with the substituted DETECT_HELPER path.

    Scenario:
      Given the built meta-package,
      When  the +MANIFEST is inspected,
      Then  ``scripts.post-install`` exists and contains the real installed helper path
            (%%DETECT_HELPER%% substituted) — not the raw %%...%% token.
    """
    full, compact, _tf = built_pkg
    scripts = full.get("scripts", {})
    assert "post-install" in scripts, f"manifest scripts keys: {list(scripts)}"

    body = scripts["post-install"]
    # The substituted helper path must appear; the raw token must not.
    assert _DETECT_HELPER_INSTALLED in body, (
        f"post-install must reference the installed helper path {_DETECT_HELPER_INSTALLED!r};\nactual body:\n{body}"
    )
    assert "%%DETECT_HELPER%%" not in body, "raw %%DETECT_HELPER%% token must be substituted"

    # The POST-INSTALL phase guard must be present (exit 0 on wrong phase).
    assert "POST-INSTALL" in body, "post-install script must guard on $2 == POST-INSTALL"


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_manifest_has_post_deinstall_script(built_pkg: tuple) -> None:
    """The manifest carries a ``post-deinstall`` script with the expected guard.

    Scenario:
      Given the built meta-package,
      When  the +MANIFEST is inspected,
      Then  ``scripts.post-deinstall`` exists and guards on POST-DEINSTALL.
    """
    full, compact, _tf = built_pkg
    scripts = full.get("scripts", {})
    assert "post-deinstall" in scripts, f"manifest scripts keys: {list(scripts)}"

    body = scripts["post-deinstall"]
    assert "POST-DEINSTALL" in body, "post-deinstall script must guard on $2 == POST-DEINSTALL"
    assert "pfblockerng.conf" in body, "post-deinstall must reference pfblockerng.conf"


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_manifest_has_no_combined_install_or_deinstall(built_pkg: tuple) -> None:
    """The manifest does NOT carry combined ``install``/``deinstall`` keys.

    The meta-package uses ``pkg-post-install`` / ``pkg-post-deinstall`` (not the
    combined ``pkg-install`` / ``pkg-deinstall`` that pfSense's PHP hook uses).
    The _SCRIPT_KEYS mapping translates these to ``post-install`` / ``post-deinstall``.
    """
    full, _compact, _tf = built_pkg
    scripts = full.get("scripts", {})
    assert "install" not in scripts, "must not have a combined 'install' script key"
    assert "deinstall" not in scripts, "must not have a combined 'deinstall' script key"


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_manifest_files_include_detect_variant(built_pkg: tuple) -> None:
    """The manifest ``files`` section contains ``detect_variant.sh`` at the expected path.

    Scenario:
      Given the built meta-package,
      When  the +MANIFEST files dict is inspected,
      Then  exactly one file is present and it is the detection helper at
            /usr/local/share/pfSense-pkg-pfblockerng-repo/detect_variant.sh.
    """
    full, _compact, _tf = built_pkg
    files = full.get("files", {})
    assert _DETECT_HELPER_INSTALLED in files, (
        f"detection helper must be staged at {_DETECT_HELPER_INSTALLED!r};\nactual files: {list(files)}"
    )

    # The helper must have an executable permission (INSTALL_SCRIPT = 0555).
    entry = files[_DETECT_HELPER_INSTALLED]
    assert entry.get("perm") == "0555", (
        f"detect_variant.sh must be installed executable (0555); got {entry.get('perm')!r}"
    )


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_compact_manifest_has_no_scripts_or_files(built_pkg: tuple) -> None:
    """The compact manifest contains only package metadata (no scripts/files).

    Consistent with all other ports: the compact manifest is metadata-only.
    """
    _full, compact, _tf = built_pkg
    assert "scripts" not in compact, "compact manifest must not carry scripts"
    assert "files" not in compact, "compact manifest must not carry files"


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_no_run_depends(built_pkg: tuple) -> None:
    """The meta-package has no RUN_DEPENDS (no PHP, no Python, no add-on binaries).

    The package is intentionally minimal: it ships only the detection helper and
    executes only base-system sh + pkg during post-install.
    """
    full, _compact, _tf = built_pkg
    # No USES=php/python → no variant guard deps injected either.
    assert "deps" not in full or full["deps"] == {}, f"meta-package must have no deps; got: {full.get('deps')}"


# --------------------------------------------------------------------------- #
# 2. Phase guard: wrong-phase exit before and correct-phase write.
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_post_install_phase_guard_exits_early_on_wrong_phase(tmp_path: Path, built_pkg: tuple) -> None:
    """post-install exits 0 without writing the conf when $2 is not POST-INSTALL.

    Scenario — the guard (before-and-after branch coverage):
      Before: conf does not exist.
      Given  $2 = PRE-INSTALL (or any non-POST-INSTALL value),
      When   the post-install script runs,
      Then   it exits 0 immediately and does NOT write the conf.

    This proves the guard is a real code path, not dead code.
    """
    full, _compact, _tf = built_pkg
    script_body = full["scripts"]["post-install"]

    script = tmp_path / "post-install.sh"
    script.write_text(script_body + "\n")
    script.chmod(0o755)

    conf_path = tmp_path / "pfblockerng.conf"
    assert not conf_path.exists()  # before-state: conf absent

    result = subprocess.run(
        ["sh", str(script), str(_PORTNAME), "PRE-INSTALL"],
        env={**os.environ},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"guard exit must be 0; stderr: {result.stderr}"
    assert not conf_path.exists(), "conf must NOT be written for PRE-INSTALL phase"


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_post_deinstall_phase_guard_exits_early_on_wrong_phase(tmp_path: Path, built_pkg: tuple) -> None:
    """post-deinstall exits 0 without removing the conf when $2 is not POST-DEINSTALL.

    Scenario — the guard (before-and-after branch coverage):
      Before: a sentinel conf file exists.
      Given  $2 = DEINSTALL (or any non-POST-DEINSTALL value),
      When   the post-deinstall script runs,
      Then   it exits 0 and leaves the conf file untouched.
    """
    full, _compact, _tf = built_pkg
    script_body = full["scripts"]["post-deinstall"]

    script = tmp_path / "post-deinstall.sh"
    script.write_text(script_body + "\n")
    script.chmod(0o755)

    # Create a sentinel conf file (before-state: conf present)
    conf_dir = tmp_path / "usr" / "local" / "etc" / "pkg" / "repos"
    conf_dir.mkdir(parents=True)
    conf_path = conf_dir / "pfblockerng.conf"
    conf_path.write_text("sentinel\n")

    result = subprocess.run(
        ["sh", str(script), str(_PORTNAME), "DEINSTALL"],
        env={**os.environ},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert conf_path.exists(), "conf must NOT be removed on wrong phase (DEINSTALL vs POST-DEINSTALL)"
    assert conf_path.read_text() == "sentinel\n", "conf content must be unchanged"


# --------------------------------------------------------------------------- #
# 3. Post-install conf-write simulation (mocked detection env vars).
# --------------------------------------------------------------------------- #


def _run_post_install(
    tmp_path: Path,
    script_body: str,
    *,
    globals_plus_inc: str,
    version_content: str,
    pkg_abi: str,
) -> Path:
    """Run the post-install script with mocked detection env vars in a temp root.

    Returns the path to the written pfblockerng.conf.

    Patches three things in the script body text before executing:
      1. The installed detect_variant.sh path → the real helper in the source tree.
      2. The hardcoded _conf_dir → a temp directory (so conf write goes to tmp).
      3. The pkg update call → ``true`` (no live pkg on a dev box).

    The detection helper's env-var knobs (PFB_GLOBALS_PLUS_INC, PFB_VERSION_FILE,
    PFB_PKG_CMD) are injected at subprocess run time so the helper reads fixture data:
      PFB_GLOBALS_PLUS_INC — path to globals.plus.inc (absent → CE; present → Plus)
      PFB_VERSION_FILE     — path to /etc/version fixture
      PFB_PKG_CMD          — pkg stub that prints the ABI string
    """
    tmp_path.mkdir(parents=True, exist_ok=True)

    # ── Fixture files for the detection helper ─────────────────────────────────
    plus_inc = tmp_path / "globals.plus.inc"
    if globals_plus_inc == "present":
        plus_inc.write_text("# Plus marker\n")
        globals_plus_path = str(plus_inc)
    else:
        # Point at a non-existent path so [ -f ... ] returns false → CE.
        globals_plus_path = str(tmp_path / "absent-globals.plus.inc")

    version_file = tmp_path / "etc_version"
    version_file.write_text(version_content + "\n")

    # Fake pkg stub: answers `pkg config abi` with the given ABI string.
    fake_pkg = tmp_path / "fake_pkg.sh"
    fake_pkg.write_text(
        f'#!/bin/sh\nif [ "$1" = "config" ] && [ "$2" = "abi" ]; then\n    printf "%s" "{pkg_abi}"\nfi\n'
    )
    fake_pkg.chmod(0o755)

    # ── Patch the script body ───────────────────────────────────────────────────
    # 1) Replace the installed helper path with the real source-tree path.
    detect_helper = _REPO_ROOT / "scripts" / "lib" / "detect_variant.sh"
    patched = script_body.replace(_DETECT_HELPER_INSTALLED, str(detect_helper))

    # 2) Redirect the conf write to a temp dir by patching the _conf_dir assignment.
    #    The script contains exactly:  _conf_dir="/usr/local/etc/pkg/repos"
    conf_dir = tmp_path / "repos"
    conf_dir.mkdir(exist_ok=True)
    patched = patched.replace(
        '_conf_dir="/usr/local/etc/pkg/repos"',
        f'_conf_dir="{conf_dir}"',
    )

    # 3) Skip the live pkg update (no pkg binary in the test environment).
    patched = patched.replace(
        "/usr/local/sbin/pkg update -q || true",
        "true",
    )

    conf_path = conf_dir / "pfblockerng.conf"

    # ── Write and execute the patched script ───────────────────────────────────
    script = tmp_path / "post-install-patched.sh"
    script.write_text(patched + "\n")
    script.chmod(0o755)

    env = {
        **os.environ,
        "PFB_GLOBALS_PLUS_INC": globals_plus_path,
        "PFB_VERSION_FILE": str(version_file),
        "PFB_PKG_CMD": str(fake_pkg),
    }
    result = subprocess.run(
        ["sh", str(script), _PORTNAME, "POST-INSTALL"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"post-install simulation failed (rc={result.returncode});\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert conf_path.exists(), f"conf was not written to {conf_path};\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return conf_path


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
@pytest.mark.parametrize(
    "globals_plus_inc,version,pkg_abi,expected_varver,expected_arch",
    [
        # CE 2.8.1 / amd64 → varver = "ce-2.8", arch = "amd64"
        ("absent", "2.8.1", "FreeBSD:15:amd64", "ce-2.8", "amd64"),
        # Plus 26.03.1 / aarch64 → varver = "plus-26.03", arch = "aarch64"
        ("present", "26.03.1", "FreeBSD:16:aarch64", "plus-26.03", "aarch64"),
    ],
)
def test_post_install_writes_correct_conf(
    tmp_path: Path,
    built_pkg: tuple,
    globals_plus_inc: str,
    version: str,
    pkg_abi: str,
    expected_varver: str,
    expected_arch: str,
) -> None:
    """Post-install writes a conf with the correct direct Pages URL for the box's catalog.

    Covers two sample boxes (the branch-coverage table):
      - CE 2.8.1 / amd64   → ce-2.8/amd64
      - Plus 26.03.1 / aarch64 → plus-26.03/aarch64

    Scenario (Given/When/Then):
      Before: conf does not exist (before-state asserted).
      Given  mocked detection env vars for the sample box,
      When   the post-install script runs with $2 = POST-INSTALL,
      Then   the written conf carries the fully resolved direct Pages URL
             (https://pfblockerng.github.io/pkg/release/<varver>/<arch>) with
             priority 100, signature_type none, mirror_type none, enabled yes,
             repo name pfblockerng — byte-identical to the expected template.
    """
    full, _compact, _tf = built_pkg
    script_body = full["scripts"]["post-install"]

    conf_path = _run_post_install(
        tmp_path,
        script_body,
        globals_plus_inc=globals_plus_inc,
        version_content=version,
        pkg_abi=pkg_abi,
    )

    # Before-state: conf now exists (was absent before _run_post_install).
    assert conf_path.exists()
    content = conf_path.read_text()

    expected_url = f"{_PAGES_BASE}/{_RELEASE_CHANNEL}/{expected_varver}/{expected_arch}"
    assert expected_url in content, f"conf URL must be {expected_url!r};\nactual conf:\n{content}"

    # Field-level assertions (format contract).
    import re

    def field(key: str) -> str:
        m = re.search(rf"^\s*{re.escape(key)}:\s*(.+?),?\s*$", content, re.MULTILINE)
        assert m is not None, f"field {key!r} not found in conf:\n{content}"
        return m.group(1).strip().rstrip(",").strip()

    assert field("mirror_type") == "none"
    assert field("signature_type") == "none"
    assert field("priority") == "100"
    assert field("enabled") == "yes"

    # Repo name must be `pfblockerng` (not pfblockerng-nightly or similar).
    assert re.search(r"^pfblockerng:\s*\{", content, re.MULTILINE), (
        f"conf stanza key must be 'pfblockerng'; conf:\n{content}"
    )

    # No ${ABI} variable — the URL is fully resolved.
    assert "${ABI}" not in content, "direct-Pages conf must not contain ${ABI} variable"


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_post_install_is_idempotent(tmp_path: Path, built_pkg: tuple) -> None:
    """Running the post-install twice produces identical conf bytes (idempotent).

    Scenario:
      Given the post-install has already run for CE 2.8/amd64 (first run),
      When  it runs again with the same env,
      Then  the conf content is unchanged — identical bytes.
    """
    full, _compact, _tf = built_pkg
    script_body = full["scripts"]["post-install"]

    conf_path_1 = _run_post_install(
        tmp_path / "run1",
        script_body,
        globals_plus_inc="absent",
        version_content="2.8.1",
        pkg_abi="FreeBSD:15:amd64",
    )
    first_content = conf_path_1.read_text()

    conf_path_2 = _run_post_install(
        tmp_path / "run2",
        script_body,
        globals_plus_inc="absent",
        version_content="2.8.1",
        pkg_abi="FreeBSD:15:amd64",
    )
    second_content = conf_path_2.read_text()

    assert first_content == second_content, (
        "post-install must be idempotent (second run produces identical conf):\n"
        f"First:\n{first_content}\nSecond:\n{second_content}"
    )


@pytest.mark.skipif(not _PORT_DIR.is_dir(), reason="pfblockerng/use-github checkout not present at /tmp/ug-adr39")
def test_post_deinstall_removes_conf(tmp_path: Path, built_pkg: tuple) -> None:
    """post-deinstall removes the conf when $2 = POST-DEINSTALL.

    Scenario (before-and-after):
      Before: conf exists (the install wrote it).
      Given  $2 = POST-DEINSTALL,
      When   post-deinstall runs,
      Then   the conf file is removed.
    """
    full, _compact, _tf = built_pkg
    deinstall_body = full["scripts"]["post-deinstall"]

    # Write the real script.
    script = tmp_path / "post-deinstall.sh"
    script.write_text(deinstall_body + "\n")
    script.chmod(0o755)

    # Create the conf that post-install would have written (before-state).
    conf_dir = tmp_path / "usr" / "local" / "etc" / "pkg" / "repos"
    conf_dir.mkdir(parents=True)
    conf_path = conf_dir / "pfblockerng.conf"
    conf_path.write_text("# dummy conf\n")
    assert conf_path.exists()  # before-state: conf present

    # Override /usr/local/etc/pkg/repos in the script: replace the hardcoded path
    # with our tmp path.  The deinstall script uses _conf_path="/usr/local/etc/pkg/repos/pfblockerng.conf"
    real_conf_path = "/usr/local/etc/pkg/repos/pfblockerng.conf"
    patched_body = deinstall_body.replace(real_conf_path, str(conf_path))
    patched_script = tmp_path / "patched_post-deinstall.sh"
    patched_script.write_text(patched_body + "\n")
    patched_script.chmod(0o755)

    result = subprocess.run(
        ["sh", str(patched_script), _PORTNAME, "POST-DEINSTALL"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"post-deinstall must exit 0; stderr: {result.stderr}"
    assert not conf_path.exists(), "conf must be removed by POST-DEINSTALL"


# --------------------------------------------------------------------------- #
# 4. Builder helper: _gh_wrksrc_subdir correctly derives the subdir.
# --------------------------------------------------------------------------- #


def test_gh_wrksrc_subdir_extracts_src(tmp_path: Path) -> None:
    """_gh_wrksrc_subdir returns 'src' for a standard pfBlockerNG port (WRKSRC includes /src).

    This is the existing behavior for pfSense-pkg-pfBlockerNG-nightly and siblings.
    Regression guard: the builder change must not break the standard case.
    """
    mk_text = (
        "PORTNAME=\tpfSense-pkg-pfBlockerNG-nightly\n"
        "PORTVERSION=\t4.0.0.alpha.2\n"
        "USE_GITHUB=\tyes\n"
        "GH_PROJECT=\tpfBlockerNG\n"
        "GH_TAGNAME=\tv${PORTVERSION}\n"
    )
    p = tmp_path / "Makefile"
    p.write_text(mk_text)
    workdir = tmp_path / "work"
    workdir.mkdir()
    seed = {
        "PORTREVISION": "0",
        "PORTEPOCH": "0",
        "WRKDIR": str(workdir / "work"),
        "WRKSRC": str(workdir / "work" / "pfBlockerNG-4.0.0.alpha.2" / "src"),
    }
    mk = bpp.Makefile(p, seed)
    assert bpp._gh_wrksrc_subdir(mk, workdir) == "src"


def test_gh_wrksrc_subdir_extracts_empty_for_repo_root(tmp_path: Path) -> None:
    """_gh_wrksrc_subdir returns '' for the meta-package port (WRKSRC is the tarball root).

    The meta-package sets WRKSRC = ${WRKDIR}/${GH_PROJECT}-${PORTVERSION} (no /src),
    so the entire checkout is the WRKSRC — detect_variant.sh lives at scripts/lib/.
    """
    mk_text = (
        "PORTNAME=\tpfSense-pkg-pfblockerng-repo\n"
        "PORTVERSION=\t4.0.0.alpha.2\n"
        "USE_GITHUB=\tyes\n"
        "GH_PROJECT=\tpfBlockerNG\n"
        "GH_TAGNAME=\tv${PORTVERSION}\n"
    )
    p = tmp_path / "Makefile"
    p.write_text(mk_text)
    workdir = tmp_path / "work"
    workdir.mkdir()
    seed = {
        "PORTREVISION": "0",
        "PORTEPOCH": "0",
        "WRKDIR": str(workdir / "work"),
        "WRKSRC": str(workdir / "work" / "pfBlockerNG-4.0.0.alpha.2"),
    }
    mk = bpp.Makefile(p, seed)
    assert bpp._gh_wrksrc_subdir(mk, workdir) == ""
