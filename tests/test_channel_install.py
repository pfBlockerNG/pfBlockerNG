"""Hermetic tests for scripts/channel-install/install-{stable,testing,edge,nightly}.sh
(issue #2416) and their shared engine, install-common.sh.

The four install-<channel>.sh files are thin: they set PFB_CHANNEL, source
install-common.sh, and call pfb_channel_install(). install-common.sh is the SOLE
client entry point — repo bootstrap (conf + boot hook) and an installed package's
channel move fold into ONE idempotent state machine — check-then-act at every step,
so a second run on a converged box performs zero pkg mutations.

A fake ``pkg`` binary (see ``_PKG_STUB``) fakes just enough of pkg(8) to drive every
branch: a ``pkgstate/<name>/{version,repo}`` directory pair per installed package, a
``catalog/<repo>`` file listing offered versions in catalogue order, and a shared
invocation log (``pkg-invocations.log``) asserted against directly — a mutation is any
logged line starting with ``install`` or ``delete``.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

import pytest

_ROOT_DIR = Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT_DIR / "scripts" / "channel-install"
_COMMON = _SCRIPTS / "install-common.sh"
_HOOK = _ROOT_DIR / "scripts" / "rc.d" / "pfblockerng_repo_generate.sh"

_CHANNELS = ("stable", "testing", "edge", "nightly")
_CANONICAL = "pfSense-pkg-pfBlockerNG"
_BASE_URL = "file:///pages-catalog-root"
_DEFAULT_PAYLOAD_PATH = "/usr/local/pkg/pfblockerng.inc"
_LEGACY_CONF = "pfblockerng.conf"

# The fake pkg(8): every call appends its argv (minus argv[0]) to pkg-invocations.log
# and captures up to one byte of its own stdin (proving the caller redirected
# </dev/null rather than leaving the piped script text on the fd). State lives under
# PFB_TEST_ROOT/pkgstate/<name>/{version,repo}; catalogues under
# PFB_TEST_ROOT/catalog/<repo>, one offered version per line in catalogue order.
_PKG_STUB = r"""#!/bin/sh
# fake pkg(8) stub for tests/test_channel_install.py — see module docstring.
ROOT="${PFB_TEST_ROOT}"
LOG="${ROOT}/pkg-invocations.log"
printf '%s\n' "$*" >> "${LOG}"
_stub_byte="$(head -c 1 2>/dev/null)"
printf '%s' "${_stub_byte}" >> "${ROOT}/pkg-stdin"

STATE="${ROOT}/pkgstate"
CATALOG="${ROOT}/catalog"

case "$1" in
version)
    if [ -n "${PFB_STUB_VERSION_T_BROKEN:-}" ]; then
        printf '?\n'
        exit 0
    fi
    _a="$3"
    _b="$4"
    if [ "${_a}" = "${_b}" ]; then
        printf '=\n'
        exit 0
    fi
    _first="$(printf '%s\n%s\n' "${_a}" "${_b}" | sort -V | head -n1)"
    if [ "${_first}" = "${_a}" ]; then printf '<\n'; else printf '>\n'; fi
    exit 0
    ;;
rquery)
    _repo="$3"
    [ -f "${CATALOG}/${_repo}" ] && cat "${CATALOG}/${_repo}"
    exit 0
    ;;
update)
    [ -n "${PFB_STUB_UPDATE_FAIL:-}" ] && exit 1
    exit 0
    ;;
query)
    if [ "$2" = "-g" ]; then
        _fmt="$3"
        _glob="$4"
        if [ "${_fmt}" = "%n" ] && [ -d "${STATE}" ]; then
            for _d in "${STATE}"/*/; do
                [ -d "${_d}" ] || continue
                _name="$(basename "${_d}")"
                case "${_name}" in
                    ${_glob}) printf '%s\n' "${_name}" ;;
                esac
            done
        fi
        exit 0
    fi
    _fmt="$2"
    _name="$3"
    case "${_fmt}" in
        %v)
            [ -f "${STATE}/${_name}/version" ] || exit 1
            cat "${STATE}/${_name}/version"
            ;;
        %R)
            [ -f "${STATE}/${_name}/repo" ] || exit 1
            cat "${STATE}/${_name}/repo"
            ;;
    esac
    exit 0
    ;;
delete)
    _name="$3"
    rm -rf "${STATE:?}/${_name}"
    exit 0
    ;;
install)
    _repo=""
    _spec=""
    _prev=""
    for _a in "$@"; do
        [ "${_prev}" = "-r" ] && _repo="${_a}"
        _spec="${_a}"
        _prev="${_a}"
    done
    _name="${_spec}"
    _ver=""
    case "${_spec}" in
        pfSense-pkg-pfBlockerNG-*)
            _ver="${_spec#pfSense-pkg-pfBlockerNG-}"
            _name="pfSense-pkg-pfBlockerNG"
            ;;
    esac
    if [ -z "${_ver}" ] && [ -f "${CATALOG}/${_repo}" ]; then
        while IFS= read -r _cver; do
            [ -n "${_cver}" ] || continue
            if [ -z "${_ver}" ]; then
                _ver="${_cver}"
                continue
            fi
            _first="$(printf '%s\n%s\n' "${_cver}" "${_ver}" | sort -V | head -n1)"
            [ "${_first}" = "${_ver}" ] && _ver="${_cver}"
        done < "${CATALOG}/${_repo}"
    fi
    mkdir -p "${STATE}/${_name}"
    printf '%s' "${_ver}" > "${STATE}/${_name}/version"
    printf '%s' "${_repo}" > "${STATE}/${_name}/repo"
    if [ -n "${PFB_STUB_DELETE_CONFIG_XML:-}" ]; then
        rm -f "${PFB_STUB_DELETE_CONFIG_XML}"
    fi
    exit 0
    ;;
info)
    _name="$3"
    printf '%s-x:\n' "${_name}"
    if [ -n "${PFB_STUB_INFO_MANIFEST:-}" ] && [ -f "${PFB_STUB_INFO_MANIFEST}" ]; then
        while IFS= read -r _p; do
            [ -n "${_p}" ] || continue
            printf '\t%s\n' "${_p}"
        done < "${PFB_STUB_INFO_MANIFEST}"
    fi
    exit 0
    ;;
esac
exit 0
"""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _install_script(channel: str) -> Path:
    return _SCRIPTS / f"install-{channel}.sh"


def _repo_name(channel: str) -> str:
    return f"pfblockerng-{channel}"


def _conf_name(channel: str) -> str:
    return f"pfblockerng-{channel}.conf"


def _repos_dir(root: str) -> Path:
    return Path(root) / "usr" / "local" / "etc" / "pkg" / "repos"


def _conf_file_path(root: str, conf_name: str) -> Path:
    return _repos_dir(root) / conf_name


def _conf_path(root: str, channel: str) -> Path:
    return _conf_file_path(root, _conf_name(channel))


def _hook_path(root: str) -> Path:
    return Path(root) / "usr" / "local" / "etc" / "rc.d" / "pfblockerng_repo_generate.sh"


def _config_xml_path(root: str) -> Path:
    return Path(root) / "cf" / "conf" / "config.xml"


def _pkg_log(root: str) -> Path:
    return Path(root) / "pkg-invocations.log"


def _pkg_stdin_capture(root: str) -> Path:
    return Path(root) / "pkg-stdin"


def _write_pkg_stub(root: str) -> str:
    """Install the fake pkg(8) binary under root/bin/pkg; return its path."""
    bin_dir = os.path.join(root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    stub_path = os.path.join(bin_dir, "pkg")
    with open(stub_path, "w") as fh:
        fh.write(_PKG_STUB)
    os.chmod(stub_path, 0o755)
    # Both files must pre-exist (possibly empty) so a run that makes zero pkg calls
    # (e.g. --help) still leaves assertable files for callers that check them. Only
    # CREATE, never truncate: _run_install re-seeds the stub on every call (including
    # repeated calls on the same root for idempotency/resume tests), and the log must
    # accumulate across those calls for callers that diff before/after content.
    for p in (_pkg_stdin_capture(root), _pkg_log(root)):
        if not p.exists():
            p.write_text("")
    return stub_path


def _seed_box(root: str) -> None:
    """CE 2.8.1 box fixture: /etc/version + /etc/product_label (no 'Plus' -> CE).

    Mirrors _run_hook's fixture in tests/test_repo_conf_generators.py so the hook
    resolves the same ce-2.8 varver here.
    """
    etc_dir = os.path.join(root, "etc")
    os.makedirs(etc_dir, exist_ok=True)
    with open(os.path.join(etc_dir, "version"), "w") as fh:
        fh.write("2.8.1\n")
    with open(os.path.join(etc_dir, "product_label"), "w") as fh:
        fh.write("pfSense\n")


def _seed_catalog(root: str, repo: str, versions: tuple[str, ...]) -> None:
    catalog_dir = os.path.join(root, "catalog")
    os.makedirs(catalog_dir, exist_ok=True)
    with open(os.path.join(catalog_dir, repo), "w") as fh:
        for v in versions:
            fh.write(v + "\n")


def _seed_installed(root: str, name: str, version: str, repo: str) -> None:
    state_dir = os.path.join(root, "pkgstate", name)
    os.makedirs(state_dir, exist_ok=True)
    with open(os.path.join(state_dir, "version"), "w") as fh:
        fh.write(version)
    with open(os.path.join(state_dir, "repo"), "w") as fh:
        fh.write(repo)


def _seed_conf_file(root: str, conf_name: str, content: str = "# stub\n") -> Path:
    p = _conf_file_path(root, conf_name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def _seed_payload(root: str, rel_path: str) -> None:
    p = Path(root + rel_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("payload\n")


def _seed_info_manifest(root: str, paths: tuple[str, ...]) -> str:
    manifest = os.path.join(root, "info-manifest")
    with open(manifest, "w") as fh:
        for p in paths:
            fh.write(p + "\n")
    return manifest


def _run_install(
    root: str,
    channel: str,
    *,
    args: tuple[str, ...] = (),
    catalog: tuple[str, ...] = ("4.0.0",),
    info_paths: tuple[str, ...] = (_DEFAULT_PAYLOAD_PATH,),
    create_info_paths: bool = True,
    update_fails: bool = False,
    version_t_broken: bool = False,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run install-<channel>.sh with PFBLOCKERNG_ROOT=root and the fake pkg stub.

    Re-seeds the box fixture, catalogue, and info manifest on every call (idempotent
    to call twice), but never touches pkgstate/ or repo confs — those persist across
    repeated calls on the same root, which is what the idempotency/resume tests need.
    """
    pkg_bin = _write_pkg_stub(root)
    _seed_box(root)
    _seed_catalog(root, _repo_name(channel), catalog)

    manifest = _seed_info_manifest(root, info_paths) if info_paths else None
    if create_info_paths:
        for p in info_paths:
            _seed_payload(root, p)

    env = {
        **os.environ,
        "PFBLOCKERNG_ROOT": root,
        "PKG_BIN": pkg_bin,
        "PFB_BASE_URL": _BASE_URL,
        "PFB_TEST_ROOT": root,
        **(extra_env or {}),
    }
    if update_fails:
        env["PFB_STUB_UPDATE_FAIL"] = "1"
    if version_t_broken:
        env["PFB_STUB_VERSION_T_BROKEN"] = "1"
    if manifest:
        env["PFB_STUB_INFO_MANIFEST"] = manifest

    argv = ["sh", str(_install_script(channel)), *args]
    return subprocess.run(argv, env=env, capture_output=True, text=True, check=False)


def _mutating_lines(log_text: str) -> list[str]:
    return [ln for ln in log_text.splitlines() if ln.startswith(("install", "delete"))]


def _assert_idempotent_second_run(root: str, channel: str) -> None:
    """Re-run install-<channel>.sh on already-converged state: zero pkg mutations,
    identical conf/hook bytes."""
    conf_before = _conf_path(root, channel).read_text()
    hook_before = _hook_path(root).read_text()
    log_before = _pkg_log(root).read_text()

    proc = _run_install(root, channel)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _conf_path(root, channel).read_text() == conf_before, "second run must not change the conf bytes"
    assert _hook_path(root).read_text() == hook_before, "second run must not change the hook bytes"

    new_lines = _pkg_log(root).read_text()[len(log_before) :].splitlines()
    for line in new_lines:
        verb = line.split(" ", 1)[0]
        assert verb in ("update", "query", "rquery", "version", "info"), (
            f"second run on a converged box must not mutate pkg state, found {line!r} in:\n{new_lines}"
        )


# --------------------------------------------------------------------------- #
# 1. Fresh box, every channel — coverage matrix row 1
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("channel", _CHANNELS)
def test_fresh_box_bootstraps_hook_conf_and_installs(channel: str) -> None:
    """Scenario: given a box with nothing configured, when install-<ch>.sh runs,
    then the hook is installed, the conf resolves with the channel's URL segment,
    exactly one bare install runs, and no delete happens."""
    with tempfile.TemporaryDirectory() as root:
        assert not _hook_path(root).exists()
        assert not _conf_path(root, channel).exists()

        proc = _run_install(root, channel)

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Done" in proc.stdout

        assert _hook_path(root).read_bytes() == _HOOK.read_bytes(), (
            "the installed hook must be byte-identical to the checkout copy"
        )

        conf = _conf_path(root, channel).read_text()
        assert "Generated at boot by pfblockerng_repo_generate" in conf
        assert f'url: "{_BASE_URL}/{channel}/ce-2.8"' in conf

        log = _pkg_log(root).read_text()
        assert re.search(rf"(?m)^update -f -r {re.escape(_repo_name(channel))}$", log), log
        installs = [ln for ln in log.splitlines() if ln.startswith("install")]
        assert installs == [f"install -y -r {_repo_name(channel)} {_CANONICAL}"], installs
        assert _mutating_lines(log) == installs, "a fresh box must delete nothing"


def test_conf_resolved_url_line_prints_to_stdout() -> None:
    """N1: the '==> Conf resolved:' header and the url: line it introduces belong
    on the SAME stream — splitting one logical message across stdout and stderr
    means a caller reading stdout alone sees the header with no url after it."""
    with tempfile.TemporaryDirectory() as root:
        channel = "stable"
        proc = _run_install(root, channel)

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "==> Conf resolved:" in proc.stdout, proc.stdout
        assert f'url: "{_BASE_URL}/{channel}/ce-2.8"' in proc.stdout, (
            f"the url: line must print to stdout beside its header:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


# --------------------------------------------------------------------------- #
# 2. Already up to date — zero mutations
# --------------------------------------------------------------------------- #


def test_already_up_to_date_performs_zero_mutations() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, _CANONICAL, "4.0.0", "pfblockerng-stable")

        proc = _run_install(root, "stable", catalog=("4.0.0",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Already up to date" in proc.stdout
        assert _mutating_lines(_pkg_log(root).read_text()) == []


def test_up_to_date_hook_gets_chmod_755_even_when_bytes_are_identical() -> None:
    """CodeRabbit finding on install-common.sh step 2: "up to date" only means the
    HOOK BYTES match — never that the mode is already correct. A byte-identical hook
    left at 0644 (e.g. a restored config backup, or a tar extraction that dropped
    the exec bit) must still be made executable, or it never runs at boot."""
    with tempfile.TemporaryDirectory() as root:
        channel = "stable"
        hook_path = _hook_path(root)
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_bytes(_HOOK.read_bytes())
        hook_path.chmod(0o644)
        assert oct(hook_path.stat().st_mode & 0o777) == "0o644", "before-state: hook must be mode 644"

        proc = _run_install(root, channel)

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Hook up to date" in proc.stdout, proc.stdout
        assert oct(hook_path.stat().st_mode & 0o777) == "0o755", (
            "AFTER: a byte-identical hook must still be made executable"
        )


# --------------------------------------------------------------------------- #
# 3. Same repo, older version — forced repo-qualified reinstall
# --------------------------------------------------------------------------- #


def test_same_repo_older_version_forces_qualified_reinstall() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, _CANONICAL, "3.9.0", "pfblockerng-stable")

        proc = _run_install(root, "stable", catalog=("4.0.0",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        log = _pkg_log(root).read_text()
        assert _mutating_lines(log) == [f"install -y -f -r pfblockerng-stable {_CANONICAL}-4.0.0"]


# --------------------------------------------------------------------------- #
# 4. Canonical from the Netgate repo — forced version-qualified install
# --------------------------------------------------------------------------- #


def test_canonical_from_netgate_repo_forces_qualified_install() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, _CANONICAL, "3.8.0", "pfSense")

        proc = _run_install(root, "stable", catalog=("4.0.0",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        log = _pkg_log(root).read_text()
        assert _mutating_lines(log) == [f"install -y -f -r pfblockerng-stable {_CANONICAL}-4.0.0"]
        assert Path(root, "pkgstate", _CANONICAL, "repo").read_text() == "pfblockerng-stable"


# --------------------------------------------------------------------------- #
# 5. Canonical from another project channel — that conf retired + forced install
# --------------------------------------------------------------------------- #


def test_canonical_from_another_channel_retires_that_conf_and_reinstalls() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, _CANONICAL, "3.9.0", "pfblockerng-nightly")
        _seed_conf_file(root, _conf_name("nightly"))

        proc = _run_install(root, "stable", catalog=("4.0.0",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Retiring" in proc.stdout
        assert not _conf_path(root, "nightly").exists()
        assert _conf_path(root, "stable").exists()
        log = _pkg_log(root).read_text()
        assert _mutating_lines(log) == [f"install -y -f -r pfblockerng-stable {_CANONICAL}-4.0.0"]


# --------------------------------------------------------------------------- #
# 6. Legacy -devel identity — delete + install, legacy conf retired
# --------------------------------------------------------------------------- #


def test_legacy_devel_identity_deleted_then_canonical_installed() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, f"{_CANONICAL}-devel", "3.2.14_2", "pfblockerng")
        _seed_conf_file(root, _LEGACY_CONF, "# legacy release conf\n")

        proc = _run_install(root, "stable", catalog=("4.0.0",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        log = _pkg_log(root).read_text()
        deletes = [ln for ln in log.splitlines() if ln.startswith("delete")]
        installs = [ln for ln in log.splitlines() if ln.startswith("install")]
        assert deletes == [f"delete -y {_CANONICAL}-devel"]
        assert installs == [f"install -y -r pfblockerng-stable {_CANONICAL}"]
        assert not _conf_file_path(root, _LEGACY_CONF).exists(), "the legacy conf must be retired"
        assert "Retiring" in proc.stdout


# --------------------------------------------------------------------------- #
# 7. Two identities installed — -devel deleted, canonical force-reinstalled
# --------------------------------------------------------------------------- #


def test_two_installed_identities_devel_deleted_canonical_reinstalled() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, _CANONICAL, "3.9.0", "pfSense")
        _seed_installed(root, f"{_CANONICAL}-devel", "3.2.14_2", "pfblockerng")

        proc = _run_install(root, "stable", catalog=("4.0.0",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        log = _pkg_log(root).read_text()
        deletes = [ln for ln in log.splitlines() if ln.startswith("delete")]
        installs = [ln for ln in log.splitlines() if ln.startswith("install")]
        assert deletes == [f"delete -y {_CANONICAL}-devel"]
        assert installs == [f"install -y -f -r pfblockerng-stable {_CANONICAL}-4.0.0"]

        remaining = sorted(os.listdir(os.path.join(root, "pkgstate")))
        assert remaining == [_CANONICAL], f"exactly the canonical identity must remain, found {remaining}"


# --------------------------------------------------------------------------- #
# 8. Downgrade across release families warns; same-family backward move does not
# --------------------------------------------------------------------------- #


def test_downgrade_across_release_families_warns_before_install() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, _CANONICAL, "4.0.0.a1", "pfblockerng-edge")

        proc = _run_install(root, "stable", catalog=("3.3.2",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "WARNING" in proc.stderr, proc.stderr
        log = _pkg_log(root).read_text()
        assert _mutating_lines(log) == [f"install -y -f -r pfblockerng-stable {_CANONICAL}-3.3.2"]


def test_same_family_backward_move_prints_no_warning() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, _CANONICAL, "3.4.1.r2", "pfblockerng-edge")

        proc = _run_install(root, "stable", catalog=("3.4.0",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "WARNING" not in proc.stderr, proc.stderr
        log = _pkg_log(root).read_text()
        assert _mutating_lines(log) == [f"install -y -f -r pfblockerng-stable {_CANONICAL}-3.4.0"]


# --------------------------------------------------------------------------- #
# 9. Idempotency — a second run on converged state mutates nothing
# --------------------------------------------------------------------------- #


def test_idempotent_second_run_after_fresh_install() -> None:
    with tempfile.TemporaryDirectory() as root:
        first = _run_install(root, "stable", catalog=("4.0.0",))
        assert first.returncode == 0, first.stdout + first.stderr
        _assert_idempotent_second_run(root, "stable")


def test_idempotent_second_run_after_netgate_migration() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, _CANONICAL, "3.8.0", "pfSense")
        first = _run_install(root, "stable", catalog=("4.0.0",))
        assert first.returncode == 0, first.stdout + first.stderr
        _assert_idempotent_second_run(root, "stable")


def test_idempotent_second_run_after_legacy_devel_migration() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, f"{_CANONICAL}-devel", "3.2.14_2", "pfblockerng")
        _seed_conf_file(root, _LEGACY_CONF, "# legacy release conf\n")
        first = _run_install(root, "stable", catalog=("4.0.0",))
        assert first.returncode == 0, first.stdout + first.stderr
        _assert_idempotent_second_run(root, "stable")


# --------------------------------------------------------------------------- #
# 10. Partial-run resume: conf already resolved, hook absent
# --------------------------------------------------------------------------- #


def test_resume_with_conf_present_but_hook_absent() -> None:
    """Scenario: given a box whose conf already carries the boot marker (a prior
    run got that far) but whose rc.d hook is absent, when install-stable.sh runs,
    then the hook is installed and the package install still happens."""
    with tempfile.TemporaryDirectory() as root:
        channel = "stable"
        _seed_conf_file(
            root,
            _conf_name(channel),
            "# Generated at boot by pfblockerng_repo_generate (ADR-39)\n"
            f'pfblockerng-{channel}: {{\n  url: "{_BASE_URL}/{channel}/ce-2.8",\n'
            "  mirror_type: none,\n  signature_type: none,\n  priority: 100,\n  enabled: yes\n}\n",
        )
        assert not _hook_path(root).exists(), "before-state: hook must be absent"

        proc = _run_install(root, channel, catalog=("4.0.0",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert _hook_path(root).exists() and _hook_path(root).stat().st_size > 0
        assert "Installed boot-time generator hook" in proc.stdout
        log = _pkg_log(root).read_text()
        assert _mutating_lines(log) == [f"install -y -r pfblockerng-{channel} {_CANONICAL}"]


def test_stale_foreign_conf_rejected_when_detection_fails() -> None:
    """CodeRabbit finding on install-common.sh step 3: the boot MARKER alone is not
    enough — the hook leaves an EXISTING conf UNCHANGED when detection fails, so a
    pre-existing conf carrying the marker but resolving to ANOTHER base's URL (a
    stale conf from a fork, a staged prefix, or a restored config backup) must
    still be rejected — never silently accepted and converged onto."""
    with tempfile.TemporaryDirectory() as root:
        channel = "stable"
        pkg_bin = _write_pkg_stub(root)
        _seed_box(root)
        _seed_catalog(root, _repo_name(channel), ("4.0.0",))
        manifest = _seed_info_manifest(root, (_DEFAULT_PAYLOAD_PATH,))
        _seed_payload(root, _DEFAULT_PAYLOAD_PATH)

        # Detection failure: blank /etc/version (written AFTER _seed_box's real one).
        with open(os.path.join(root, "etc", "version"), "w") as fh:
            fh.write("")

        stale_conf_text = (
            "# Generated at boot by pfblockerng_repo_generate (ADR-39)\n"
            'pfblockerng-stable: {\n  url: "https://other.example/pkg/stable/ce-2.8",\n'
            "  mirror_type: none,\n  signature_type: none,\n  priority: 100,\n  enabled: yes\n}\n"
        )
        conf_path = _seed_conf_file(root, _conf_name(channel), stale_conf_text)
        assert "Generated at boot by pfblockerng_repo_generate" in conf_path.read_text(), (
            "before-state: marker must be present"
        )
        assert "other.example" in conf_path.read_text(), "before-state: url must point at another base"

        env = {
            **os.environ,
            "PFBLOCKERNG_ROOT": root,
            "PKG_BIN": pkg_bin,
            "PFB_BASE_URL": _BASE_URL,
            "PFB_TEST_ROOT": root,
            "PFB_STUB_INFO_MANIFEST": manifest,
        }
        proc = subprocess.run(
            ["sh", str(_install_script(channel))], env=env, capture_output=True, text=True, check=False
        )

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert conf_path.read_text() == stale_conf_text, (
            "a stale foreign conf must be left byte-identical — it is not ours to delete"
        )
        assert _mutating_lines(_pkg_log(root).read_text()) == []


# --------------------------------------------------------------------------- #
# 11. Offered-version pick via pkg version -t (issue #2393 residual)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "catalog",
    [("4.0.0_1", "4.0.0_3", "4.0.0_2"), ("4.0.0_3", "4.0.0_1", "4.0.0_2")],
    ids=["mixed-order", "newest-first"],
)
def test_offered_version_picked_via_pkg_version_t_regardless_of_catalogue_order(
    catalog: tuple[str, ...],
) -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "edge", catalog=catalog)

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert f"==> Target: {_CANONICAL}-4.0.0_3 (repo pfblockerng-edge)" in proc.stdout, proc.stdout
        assert Path(root, "pkgstate", _CANONICAL, "version").read_text() == "4.0.0_3"


def test_version_t_broken_fails_loud_with_no_mutation() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "edge", catalog=("3.3.0", "3.3.2"), version_t_broken=True)

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert _mutating_lines(_pkg_log(root).read_text()) == []
        assert not _conf_path(root, "edge").exists()


# --------------------------------------------------------------------------- #
# 12. Empty catalogue: fails, no mutation, no strand of a peer or a pre-existing conf
# --------------------------------------------------------------------------- #


def test_empty_catalogue_fails_no_mutation_peer_conf_untouched() -> None:
    """A peer conf from an already-successful nightly bootstrap must survive an edge
    bootstrap whose catalogue turns out empty — byte-identical, and with no package
    mutation logged."""
    with tempfile.TemporaryDirectory() as root:
        seed = _run_install(root, "nightly", catalog=("1.0.0",))
        assert seed.returncode == 0, seed.stdout + seed.stderr
        peer_before = _conf_path(root, "nightly").read_text()
        log_before = _pkg_log(root).read_text()

        proc = _run_install(root, "edge", catalog=())

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert not _conf_path(root, "edge").exists(), "the stub conf this run created must be removed"
        assert _conf_path(root, "nightly").read_text() == peer_before, "a pre-existing peer conf must survive"
        new_lines = _pkg_log(root).read_text()[len(log_before) :].splitlines()
        assert not any(ln.startswith(("install", "delete")) for ln in new_lines), new_lines


def test_failed_run_against_another_base_url_never_rewrites_a_peer_conf() -> None:
    """A run pointed at a different catalogue base (a fork or a staged prefix) that
    fails before its target is proven must leave a peer channel's conf byte-identical:
    the generator hook is driven for THIS channel's conf only, never for the peers,
    so a bad base URL cannot re-point a working subscription before retirement."""
    with tempfile.TemporaryDirectory() as root:
        seed = _run_install(root, "stable", catalog=("1.0.0",))
        assert seed.returncode == 0, seed.stdout + seed.stderr
        peer_before = _conf_path(root, "stable").read_text()
        assert _BASE_URL in peer_before

        proc = _run_install(root, "nightly", catalog=(), extra_env={"PFB_BASE_URL": f"{_BASE_URL}-staged"})

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert not _conf_path(root, "nightly").exists(), "the stub conf this run created must be removed"
        peer_after = _conf_path(root, "stable").read_text()
        assert peer_after == peer_before, f"peer conf rewritten:\n--- before\n{peer_before}\n--- after\n{peer_after}"


def test_empty_catalogue_leaves_a_pre_existing_target_conf_in_place() -> None:
    with tempfile.TemporaryDirectory() as root:
        _seed_conf_file(root, _conf_name("edge"), "# placeholder pending\n")

        proc = _run_install(root, "edge", catalog=())

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert _conf_path(root, "edge").exists(), "a conf this run did not create must not be removed"


# --------------------------------------------------------------------------- #
# 13. pkg update failure: fails, no mutation, created stub removed
# --------------------------------------------------------------------------- #


def test_pkg_update_failure_fails_no_mutation_stub_removed() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "testing", update_fails=True)

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert not _conf_path(root, "testing").exists()
        assert _mutating_lines(_pkg_log(root).read_text()) == []


# --------------------------------------------------------------------------- #
# 14. Verify failure: pkg info -l lists a path that does not exist on disk
# --------------------------------------------------------------------------- #


def test_verify_fails_when_pkg_info_l_lists_a_missing_path() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(
            root,
            "stable",
            info_paths=("/usr/local/pkg/pfblockerng.inc",),
            create_info_paths=False,
        )

        assert proc.returncode == 6, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# 15. config.xml section preservation
# --------------------------------------------------------------------------- #


def test_config_section_deleted_during_install_fails_verify() -> None:
    with tempfile.TemporaryDirectory() as root:
        _config_xml_path(root).parent.mkdir(parents=True, exist_ok=True)
        _config_xml_path(root).write_text(
            "<pfsense><installedpackages><pfblockerng>x</pfblockerng></installedpackages></pfsense>\n"
        )

        proc = _run_install(
            root,
            "stable",
            extra_env={"PFB_STUB_DELETE_CONFIG_XML": str(_config_xml_path(root))},
        )

        assert proc.returncode == 6, proc.stdout + proc.stderr


def test_config_section_preserved_across_install_succeeds() -> None:
    with tempfile.TemporaryDirectory() as root:
        _config_xml_path(root).parent.mkdir(parents=True, exist_ok=True)
        _config_xml_path(root).write_text(
            "<pfsense><installedpackages><pfblockerng>x</pfblockerng></installedpackages></pfsense>\n"
        )

        proc = _run_install(root, "stable")

        assert proc.returncode == 0, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# 16. Hostile args: positional / unknown flag -> exit 2; --help -> exit 0
# --------------------------------------------------------------------------- #


def test_positional_argument_rejected() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "stable", args=("stable",))

        assert proc.returncode == 2, proc.stdout + proc.stderr
        assert "usage" in proc.stderr.lower() or "Usage:" in proc.stdout


def test_channel_flag_rejected() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "stable", args=("--channel", "stable"))

        assert proc.returncode == 2, proc.stdout + proc.stderr


def test_help_flag_exits_zero() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "stable", args=("--help",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Usage:" in proc.stdout
        assert _mutating_lines(_pkg_log(root).read_text()) == [], "--help must never touch pkg"


def test_missing_pkg_binary_fails_at_step_1_with_exit_1_no_files_written() -> None:
    """CodeRabbit nitpick: PKG_BIN pointing at a nonexistent binary must fail loudly
    at step 1 — before the hook or the conf is ever written — exit 1, naming the
    missing path in the message."""
    with tempfile.TemporaryDirectory() as root:
        channel = "stable"
        _seed_box(root)
        env = {
            **os.environ,
            "PFBLOCKERNG_ROOT": root,
            "PKG_BIN": "/nonexistent/pkg",
            "PFB_BASE_URL": _BASE_URL,
            "PFB_TEST_ROOT": root,
        }
        proc = subprocess.run(
            ["sh", str(_install_script(channel))], env=env, capture_output=True, text=True, check=False
        )

        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "/nonexistent/pkg" in proc.stderr, proc.stderr
        assert not _hook_path(root).exists(), "AFTER: no hook file must be written"
        assert not _conf_path(root, channel).exists(), "AFTER: no conf file must be written"


# --------------------------------------------------------------------------- #
# 17. Piped invocation: stdin never consumed by the script itself
# --------------------------------------------------------------------------- #


def test_piped_invocation_leaves_pkg_stdin_empty_and_installs_a_real_hook() -> None:
    """Scenario: given install-stable.sh piped into `sh -s` (the published
    `fetch | sh` form, exercised here from a checkout with cwd = the script's own
    directory so sibling-file resolution still finds the real hook), when it runs,
    then it succeeds and installs a real hook. (The stdin-isolation guarantee is
    pinned separately by test_pkg_wrapper_redirects_stdin_from_dev_null — here the
    call is the script's last statement, so sh has already drained the pipe.)"""
    with tempfile.TemporaryDirectory() as root:
        channel = "stable"
        pkg_bin = _write_pkg_stub(root)
        _seed_box(root)
        _seed_catalog(root, _repo_name(channel), ("4.0.0",))
        manifest = _seed_info_manifest(root, (_DEFAULT_PAYLOAD_PATH,))
        _seed_payload(root, _DEFAULT_PAYLOAD_PATH)

        env = {
            **os.environ,
            "PFBLOCKERNG_ROOT": root,
            "PKG_BIN": pkg_bin,
            "PFB_BASE_URL": _BASE_URL,
            "PFB_TEST_ROOT": root,
            "PFB_STUB_INFO_MANIFEST": manifest,
        }
        script_text = _install_script(channel).read_text()

        proc = subprocess.run(
            ["sh", "-s"],
            input=script_text,
            cwd=str(_SCRIPTS),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Done" in proc.stdout

        hook = _hook_path(root)
        assert hook.exists() and hook.stat().st_size > 0
        assert hook.read_text().startswith("#!/bin/sh")


def test_pkg_wrapper_redirects_stdin_from_dev_null() -> None:
    """Scenario: given the sourced install-common.sh and a pkg(8) stub that reads its
    stdin, when `_pkg` runs while the calling shell's stdin still holds unread bytes
    (what a `fetch | sh` pipe looks like mid-script), then the stub reads NOTHING —
    the wrapper hands every pkg call /dev/null, so no child can eat script text."""
    with tempfile.TemporaryDirectory() as root:
        pkg_bin = _write_pkg_stub(root)
        env = {**os.environ, "PKG_BIN": pkg_bin, "PFB_TEST_ROOT": root}
        proc = subprocess.run(
            ["sh", "-c", f'PFB_CHANNEL=stable; . "{_COMMON}"; _pkg query "%v" pfSense-pkg-pfBlockerNG'],
            input="REST-OF-THE-PIPED-SCRIPT\n",
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert "query" in _pkg_log(root).read_text(), proc.stdout + proc.stderr
        seen = _pkg_stdin_capture(root).read_text()
        assert seen == "", f"pkg stub read {seen!r} from stdin — _pkg must redirect stdin from /dev/null"


# --------------------------------------------------------------------------- #
# 18. Structure: markers, PFB_CHANNEL, sh -n on all five files
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("channel", _CHANNELS)
def test_channel_script_parses_and_carries_required_markers(channel: str) -> None:
    f = _install_script(channel)
    proc = subprocess.run(["sh", "-n", str(f)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr

    text = f.read_text()
    assert "# PFB_EMBED_COMMON_BEGIN" in text
    assert "# PFB_EMBED_COMMON_END" in text
    assert f'PFB_CHANNEL="{channel}"' in text


def test_install_common_parses_and_carries_required_hook_markers() -> None:
    proc = subprocess.run(["sh", "-n", str(_COMMON)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr

    text = _COMMON.read_text()
    assert "# PFB_EMBED_HOOK_BEGIN" in text
    assert "# PFB_EMBED_HOOK_END" in text


def test_sourcing_without_pfb_channel_fails_loudly() -> None:
    """install-common.sh is sourced ONLY by install-<ch>.sh, which always sets
    PFB_CHANNEL before the `.`. A source with PFB_CHANNEL unset must fail loudly
    instead of silently baking an empty channel into every message, path, and
    hook the state machine drives."""
    env = {k: v for k, v in os.environ.items() if k != "PFB_CHANNEL"}
    proc = subprocess.run(
        ["sh", "-c", f'. "{_COMMON}"'],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "PFB_CHANNEL" in proc.stderr, proc.stderr
