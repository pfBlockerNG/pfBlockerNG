"""Hermetic tests for scripts/install.sh (issue #2416 follow-up: one script, the four
per-channel install-<channel>.sh wrappers + install-common.sh are gone, replaced by a
single script parameterized by ``--channel``).

install.sh is the SOLE client entry point — repo bootstrap (conf + boot hook) and an
installed package's channel move fold into ONE idempotent state machine — check-then-act
at every step, so a second run on a converged box performs zero pkg mutations.

A fake ``pkg`` binary (see ``_PKG_STUB``) fakes just enough of pkg(8) to drive every
branch: a ``pkgstate/<name>/{version,repo}`` directory pair per installed package, a
``catalog/<repo>`` file listing offered versions in catalogue order, and a shared
invocation log (``pkg-invocations.log``) asserted against directly — a mutation is any
logged line starting with ``install`` or ``delete``.

A fake ``fetch`` binary (see ``_FETCH_STUB``) answers the catalogue probe
(``<catalogue-url>/meta.conf``, issue #2926): it records every attempted URL and
the full argv of every call, and succeeds unless ``PFB_STUB_FETCH_FAIL=1``.
"""

from __future__ import annotations

import contextlib
import os
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

_ROOT_DIR = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = _ROOT_DIR / "scripts"
_SCRIPT = _SCRIPTS_DIR / "install.sh"
_HOOK = _ROOT_DIR / "src" / "usr" / "local" / "etc" / "rc.d" / "pfblockerng_repo_generate.sh"

_CHANNELS = ("stable", "testing", "edge", "nightly")
_CANONICAL = "pfSense-pkg-pfBlockerNG"
_BASE_URL = "file:///pages-catalog-root"
_DEFAULT_PAYLOAD_PATH = "/usr/local/pkg/pfblockerng.inc"
_LEGACY_CONF = "pfblockerng.conf"

# Ambient values for these would decide what the stub records instead of the script's own
# behaviour, so _run_install drops them from the child environment.
_CA_ENV_VARS = (
    "SSL_CA_CERT_PATH",
    "SSL_CA_CERT_FILE",
    "PFB_SSL_CA_CERT_PATH",
    "PFB_SSL_CA_CERT_FILE",
)

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
printf '%s\n' "${SSL_CA_CERT_PATH-<unset>}" >> "${ROOT}/pkg-ca-path.log"
printf '%s\n' "${SSL_CA_CERT_FILE-<unset>}" >> "${ROOT}/pkg-ca-file.log"
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
    if [ -n "${PFB_STUB_MUTATE_RC:-}" ]; then
        printf 'pkg: some transport failure\n' >&2
        exit "${PFB_STUB_MUTATE_RC}"
    fi
    _name="$3"
    rm -rf "${STATE:?}/${_name}"
    if [ -n "${PFB_STUB_DEINSTALL_FAIL:-}" ]; then
        if [ -n "${PFB_STUB_SCRIPT_FAILED_GLUED:-}" ]; then
            printf '  thrown</pre>'
        fi
        printf 'pkg: DEINSTALL script failed\n' >&2
    fi
    if [ -n "${PFB_STUB_SCRIPT_FAILED_NOISE:-}" ]; then
        printf 'the POST-INSTALL script failed to mention foo\n'
    fi
    if [ -n "${PFB_STUB_PKG_DIAG:-}" ]; then
        printf 'pkg: Repository pfblockerng-stable has a missing meta file, using previous version\n'
    fi
    exit 0
    ;;
install)
    if [ -n "${PFB_STUB_MUTATE_RC:-}" ]; then
        printf 'pkg: some transport failure\n' >&2
        exit "${PFB_STUB_MUTATE_RC}"
    fi
    if [ -n "${PFB_STUB_STREAM_BLOCK:-}" ]; then
        # An external echo(1): a builtin's stdio buffer is not guaranteed to reach
        # the caller before this stub's own exit, which is exactly what is under test.
        /bin/echo "pfb-stream-marker-2644"
        _wait_i=0
        while [ ! -f "${PFB_STUB_STREAM_BLOCK}" ] && [ "${_wait_i}" -lt 300 ]; do
            sleep 0.1
            _wait_i=$((_wait_i + 1))
        done
    fi
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
    if [ -n "${PFB_STUB_POSTINSTALL_FAIL:-}" ]; then
        if [ -n "${PFB_STUB_SCRIPT_FAILED_GLUED:-}" ]; then
            printf '  thrown</pre>'
        fi
        printf 'pkg: POST-INSTALL script failed\n' >&2
    fi
    if [ -n "${PFB_STUB_SCRIPT_FAILED_NOISE:-}" ]; then
        printf 'the POST-INSTALL script failed to mention foo\n'
    fi
    if [ -n "${PFB_STUB_PKG_DIAG:-}" ]; then
        printf 'pkg: Repository pfblockerng-stable has a missing meta file, using previous version\n'
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


# The fake fetch(1): one line per call in fetch-invocations.log —
# ``pkg-log-bytes=<size of the pkg log at call time> <last non-flag argument>`` — so a
# test can assert the EXACT probed URL and prove the probe ran before the first pkg
# call (size 0). Succeeds unless ``PFB_STUB_FETCH_FAIL=1``.
_FETCH_STUB = r"""#!/bin/sh
# fake fetch(1) stub for tests/test_channel_install.py — see module docstring.
ROOT="${PFB_TEST_ROOT}"
ARGV_LOG="${ROOT}/fetch-argv.log"
LOG="${ROOT}/fetch-invocations.log"
_pkg_log_bytes=0
if [ -f "${ROOT}/pkg-invocations.log" ]; then
    _pkg_log_bytes=$(( $(wc -c < "${ROOT}/pkg-invocations.log") + 0 ))
fi
_url=""
for _arg in "$@"; do
    case "${_arg}" in
        -*) ;;
        *) _url="${_arg}" ;;
    esac
done
printf '%s\n' "$*" >> "${ARGV_LOG}"
printf 'pkg-log-bytes=%s %s\n' "${_pkg_log_bytes}" "${_url}" >> "${LOG}"
[ -n "${PFB_STUB_FETCH_FAIL:-}" ] && exit 1
exit 0
"""

_TIMEOUT_STUB = r"""#!/bin/sh
# fake timeout(1): record the complete bounded invocation, then run its child.
printf '%s\n' "$*" >> "${PFB_TEST_ROOT}/timeout-invocations.log"
shift 3
exec "$@"
"""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


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


def _pkg_ca_path_capture(root: str) -> Path:
    """One line per pkg call: the SSL_CA_CERT_PATH it saw, or <unset>."""
    return Path(root) / "pkg-ca-path.log"


def _pkg_ca_file_capture(root: str) -> Path:
    """One line per pkg call: the SSL_CA_CERT_FILE it saw, or <unset>."""
    return Path(root) / "pkg-ca-file.log"


def _fetch_log(root: str) -> Path:
    """One line per fetch call: ``pkg-log-bytes=<size> <url>`` — created ONLY by an
    actual fetch call, so a run that dies before the probe leaves nothing behind."""
    return Path(root) / "fetch-invocations.log"


def _fetch_argv_log(root: str) -> Path:
    """One line per fetch call: the complete argv, space-separated — so a test can
    assert the EXACT flags the probe ran with (e.g. the no-redirect flag, -A)."""
    return Path(root) / "fetch-argv.log"


def _timeout_log(root: str) -> Path:
    """One line per timeout call: grace, wall-clock budget, child, and child argv."""
    return Path(root) / "timeout-invocations.log"


def _write_pkg_stub(root: str) -> str:
    """Install the fake pkg(8) binary under root/bin/pkg; return its path."""
    bin_dir = os.path.join(root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    stub_path = os.path.join(bin_dir, "pkg")
    with open(stub_path, "w") as fh:
        fh.write(_PKG_STUB)
    os.chmod(stub_path, 0o755)
    # These capture files must pre-exist (possibly empty) so a run that makes zero pkg calls
    # (e.g. --help) still leaves assertable files for callers that check them. Only
    # CREATE, never truncate: _run_install re-seeds the stub on every call (including
    # repeated calls on the same root for idempotency/resume tests), and the log must
    # accumulate across those calls for callers that diff before/after content.
    for p in (_pkg_stdin_capture(root), _pkg_log(root), _pkg_ca_path_capture(root), _pkg_ca_file_capture(root)):
        if not p.exists():
            p.write_text("")
    return stub_path


def _write_fetch_stub(root: str) -> str:
    """Install the fake fetch(1) binary under root/bin/fetch; return its path."""
    bin_dir = os.path.join(root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    stub_path = os.path.join(bin_dir, "fetch")
    with open(stub_path, "w") as fh:
        fh.write(_FETCH_STUB)
    os.chmod(stub_path, 0o755)
    return stub_path


def _write_timeout_stub(root: str) -> str:
    """Install the fake timeout(1) binary under root/bin/timeout; return its path."""
    bin_dir = os.path.join(root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    stub_path = os.path.join(bin_dir, "timeout")
    with open(stub_path, "w") as fh:
        fh.write(_TIMEOUT_STUB)
    os.chmod(stub_path, 0o755)
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


def _prepare_install(
    root: str,
    channel: str,
    *,
    args: tuple[str, ...] = (),
    channel_style: str = "space",
    catalog: tuple[str, ...] = ("4.0.0",),
    info_paths: tuple[str, ...] = (_DEFAULT_PAYLOAD_PATH,),
    create_info_paths: bool = True,
    update_fails: bool = False,
    version_t_broken: bool = False,
    extra_env: dict[str, str] | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Build the argv + environment that runs install.sh --channel <channel> with
    PFBLOCKERNG_ROOT=root and the fake pkg stub.

    Re-seeds the box fixture, catalogue, and info manifest on every call (idempotent
    to call twice), but never touches pkgstate/ or repo confs — those persist across
    repeated calls on the same root, which is what the idempotency/resume tests need.

    ``channel_style`` selects how ``channel`` is passed: ``"space"`` (default,
    ``--channel <channel>``), ``"equals"`` (``--channel=<channel>``), so the two
    accepted forms can share every other fixture.
    """
    pkg_bin = _write_pkg_stub(root)
    fetch_bin = _write_fetch_stub(root)
    _seed_box(root)
    _seed_catalog(root, _repo_name(channel), catalog)

    manifest = _seed_info_manifest(root, info_paths) if info_paths else None
    if create_info_paths:
        for p in info_paths:
            _seed_payload(root, p)

    # Strip every CA-related variable the developer's shell might carry BEFORE layering
    # extra_env on top: popping afterwards would delete a test's own override, including
    # the empty-string opt-out the tests below rely on.
    env = {k: v for k, v in os.environ.items() if k not in _CA_ENV_VARS}
    env.update(
        {
            "PFBLOCKERNG_ROOT": root,
            "PKG_BIN": pkg_bin,
            "FETCH_BIN": fetch_bin,
            "PFB_BASE_URL": _BASE_URL,
            "PFB_TEST_ROOT": root,
            **(extra_env or {}),
        }
    )
    if update_fails:
        env["PFB_STUB_UPDATE_FAIL"] = "1"
    if version_t_broken:
        env["PFB_STUB_VERSION_T_BROKEN"] = "1"
    if manifest:
        env["PFB_STUB_INFO_MANIFEST"] = manifest

    channel_args = [f"--channel={channel}"] if channel_style == "equals" else ["--channel", channel]
    argv = ["sh", str(_SCRIPT), *channel_args, *args]
    return argv, env


def _run_install(
    root: str,
    channel: str,
    *,
    args: tuple[str, ...] = (),
    channel_style: str = "space",
    catalog: tuple[str, ...] = ("4.0.0",),
    info_paths: tuple[str, ...] = (_DEFAULT_PAYLOAD_PATH,),
    create_info_paths: bool = True,
    update_fails: bool = False,
    version_t_broken: bool = False,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run install.sh to completion with the fixture _prepare_install builds.

    The parameters are spelled out rather than forwarded as ``*args, **kwargs``: every
    call in this module goes through here, and ``Any`` would opt all of them out of the
    ``mypy tests/`` gate.
    """
    argv, env = _prepare_install(
        root,
        channel,
        args=args,
        channel_style=channel_style,
        catalog=catalog,
        info_paths=info_paths,
        create_info_paths=create_info_paths,
        update_fails=update_fails,
        version_t_broken=version_t_broken,
        extra_env=extra_env,
    )
    return subprocess.run(argv, env=env, capture_output=True, text=True, check=False)


def _run_argv(*args: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run install.sh with exactly ``args`` — no pkg stub, no box fixture.

    Every arg-parsing rejection happens BEFORE step 1 (environment) even runs, so
    these hostile-input cases need nothing but the script itself.
    """
    env = {**os.environ, **(env_extra or {})}
    return subprocess.run(["sh", str(_SCRIPT), *args], env=env, capture_output=True, text=True, check=False)


def _mutating_lines(log_text: str) -> list[str]:
    return [ln for ln in log_text.splitlines() if ln.startswith(("install", "delete"))]


def _assert_idempotent_second_run(root: str, channel: str) -> None:
    """Re-run install.sh --channel <channel> on already-converged state: zero pkg
    mutations, identical conf/hook bytes."""
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


def test_project_host_bootstrap_installs_the_fingerprint_and_a_signed_conf() -> None:
    """The whole suite runs against a ``file://`` base, where the flip is a no-op — so
    nothing here exercised the shape a real box gets (issue #2675).

    Three things have to hold together for a bootstrap against the project host: the
    conf requires a signature, the trusted fingerprint exists to satisfy it, and the
    path the conf names is the ON-BOX one even though this run is staged under a root.
    A conf naming the staging directory would find no key once the box booted as /.
    """
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "stable", extra_env={"PFB_BASE_URL": "https://pkg.pfblockerng.com"})
        assert proc.returncode == 0, proc.stdout + proc.stderr

        conf = _conf_path(root, "stable").read_text()
        assert 'url: "http://pkg.pfblockerng.com/stable/' in conf, conf
        assert "signature_type: fingerprints," in conf, conf
        assert 'fingerprints: "/usr/local/etc/pkg/fingerprints/pfblockerng",' in conf, conf

        trusted = Path(root) / "usr/local/etc/pkg/fingerprints/pfblockerng/trusted/pkg.pfblockerng.com"
        assert trusted.is_file(), f"no trusted fingerprint under the staged root:\n{proc.stdout}"
        assert trusted.read_text() == (
            'function: "sha256"\nfingerprint: "081df5476f84d8d20417c400f576c355069a4a9979d170bcaae1c9da32778915"\n'
        )
        assert (Path(root) / "usr/local/etc/pkg/fingerprints/pfblockerng/revoked").is_dir()


@pytest.mark.parametrize("channel", _CHANNELS)
def test_fresh_box_bootstraps_hook_conf_and_installs(channel: str) -> None:
    """Scenario: given a box with nothing configured, when install.sh --channel <ch>
    runs, then the hook is installed, the conf resolves with the channel's URL segment,
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
    """ "Up to date" only means the HOOK BYTES match — never that the mode is already
    correct. A byte-identical hook left at 0644 (e.g. a restored config backup, or a
    tar extraction that dropped the exec bit) must still be made executable, or it
    never runs at boot."""
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
    run got that far) but whose rc.d hook is absent, when install.sh --channel stable
    runs, then the hook is installed and the package install still happens."""
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
    """The boot MARKER alone is not enough — the hook leaves an EXISTING conf UNCHANGED
    when detection fails, so a pre-existing conf carrying the marker but resolving
    to ANOTHER base's URL (a stale conf from a fork, a staged prefix, or a restored
    config backup) must still be rejected — never silently accepted and converged
    onto."""
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
            "FETCH_BIN": _write_fetch_stub(root),
            "PFB_BASE_URL": _BASE_URL,
            "PFB_TEST_ROOT": root,
            "PFB_STUB_INFO_MANIFEST": manifest,
        }
        proc = subprocess.run(
            ["sh", str(_SCRIPT), "--channel", channel], env=env, capture_output=True, text=True, check=False
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
# 13. pkg script-failed with rc 0 is still a failed install (issue #2575)
# --------------------------------------------------------------------------- #


def test_postinstall_script_failed_exits_5_without_done() -> None:
    """pkg(8) can exit 0 after POST-INSTALL fails (files already extracted).
    install.sh must not print Done or return 0 — lifecycle on smoke-1 showed
    ``pkg: POST-INSTALL script failed`` followed by ``==> Done`` (issue #2575)."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(
            root,
            "stable",
            extra_env={"PFB_STUB_POSTINSTALL_FAIL": "1"},
        )

        assert proc.returncode == 5, proc.stdout + proc.stderr
        combined = proc.stdout + proc.stderr
        assert "pkg: POST-INSTALL script failed" in combined, combined
        assert "Done" not in proc.stdout


def test_deinstall_script_failed_on_legacy_delete_exits_5_without_done() -> None:
    """Same pkg(8) contract on delete: DEINSTALL can fail while pkg still
    exits 0 and the identity is already gone. Fail closed (issue #2575)."""
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, f"{_CANONICAL}-devel", "3.2.14_2", "pfblockerng")
        _seed_conf_file(root, _LEGACY_CONF, "# legacy release conf\n")

        proc = _run_install(
            root,
            "stable",
            catalog=("4.0.0",),
            extra_env={"PFB_STUB_DEINSTALL_FAIL": "1"},
        )

        assert proc.returncode == 5, proc.stdout + proc.stderr
        combined = proc.stdout + proc.stderr
        assert "pkg: DEINSTALL script failed" in combined, combined
        assert "Done" not in proc.stdout


def test_script_failed_without_pkg_prefix_is_not_a_hook_failure() -> None:
    """Only ``pkg: <script> script failed`` is the hook-failure signal. A
    coincidental ``script failed`` substring in pkg stdout must not fail the
    run."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(
            root,
            "stable",
            extra_env={"PFB_STUB_SCRIPT_FAILED_NOISE": "1"},
        )

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Done" in proc.stdout
        assert "the POST-INSTALL script failed to mention foo" in proc.stdout


def test_postinstall_script_failed_glued_to_hook_output_exits_5_without_done() -> None:
    """pfSense hook stdout often ends without a newline, so pkg's stderr is
    glued: ``thrown</pre>pkg: POST-INSTALL script failed``. The matcher must
    still fail closed (issue #2575, live legs.log)."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(
            root,
            "stable",
            extra_env={
                "PFB_STUB_POSTINSTALL_FAIL": "1",
                "PFB_STUB_SCRIPT_FAILED_GLUED": "1",
            },
        )

        assert proc.returncode == 5, proc.stdout + proc.stderr
        combined = proc.stdout + proc.stderr
        assert "pkg: POST-INSTALL script failed" in combined, combined
        assert "Done" not in proc.stdout


def test_pkg_capture_log_is_removed_after_success() -> None:
    """mktemp capture files live on a small RAM /tmp on the appliance; they
    must not leak after a successful mutate."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "stable")

        assert proc.returncode == 0, proc.stdout + proc.stderr
        leftovers = sorted(Path(root, "tmp").glob("pfb-install-pkg.*"))
        assert leftovers == [], leftovers


def test_pkg_capture_log_is_removed_after_script_failed() -> None:
    """The die() path must remove the capture file too (same as the hook
    staging mktemp)."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(
            root,
            "stable",
            extra_env={"PFB_STUB_POSTINSTALL_FAIL": "1"},
        )

        assert proc.returncode == 5, proc.stdout + proc.stderr
        leftovers = sorted(Path(root, "tmp").glob("pfb-install-pkg.*"))
        assert leftovers == [], leftovers


def test_benign_pkg_diagnostic_is_not_a_hook_failure() -> None:
    """A ``pkg: ``-prefixed warning that is not ``script failed`` must not
    abort a successful install."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(
            root,
            "stable",
            extra_env={"PFB_STUB_PKG_DIAG": "1"},
        )

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Done" in proc.stdout
        assert "pkg: Repository" in proc.stdout


# --------------------------------------------------------------------------- #
# 13b. pkg update failure: fails, no mutation, created stub removed
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
# 16. --channel=<ch> (the equals form) behaves exactly like --channel <ch>
# --------------------------------------------------------------------------- #


def test_channel_equals_form_installs_the_same_as_space_form() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "edge", channel_style="equals", catalog=("4.0.0",))

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Done" in proc.stdout
        assert Path(root, "pkgstate", _CANONICAL, "repo").read_text() == "pfblockerng-edge"


# --------------------------------------------------------------------------- #
# 17. Arg parsing: --channel required/valid, release rejected, hostile args -> 2,
#     -h/--help -> 0. Every case here fails before step 1 (environment), so no pkg
#     stub or box fixture is needed (issue #2416 follow-up: new --channel surface).
# --------------------------------------------------------------------------- #


def test_missing_channel_rejected_with_no_default_message() -> None:
    proc = _run_argv()

    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "no default" in (proc.stdout + proc.stderr).lower(), proc.stdout + proc.stderr


def test_channel_flag_missing_value_rejected() -> None:
    proc = _run_argv("--channel")

    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "requires a value" in (proc.stdout + proc.stderr).lower(), proc.stdout + proc.stderr


@pytest.mark.parametrize("bogus", ["bogus", "STABLE", "Stable", "release "])
def test_invalid_channel_value_rejected(bogus: str) -> None:
    proc = _run_argv("--channel", bogus)

    assert proc.returncode == 2, proc.stdout + proc.stderr


def test_release_channel_rejected_by_name() -> None:
    """`release` (the legacy shared-repo word) is explicitly named in the error —
    distinct from a merely-unknown value, so a user who tries the old word is told
    what changed rather than getting a generic 'unknown channel'."""
    proc = _run_argv("--channel", "release")

    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "release" in proc.stderr.lower(), proc.stderr


def test_positional_argument_alone_rejected() -> None:
    proc = _run_argv("stable")

    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "usage" in proc.stderr.lower() or "Usage:" in proc.stdout


def test_positional_argument_after_valid_channel_rejected() -> None:
    proc = _run_argv("--channel", "stable", "stable")

    assert proc.returncode == 2, proc.stdout + proc.stderr


def test_unknown_flag_rejected() -> None:
    proc = _run_argv("--bogus-flag")

    assert proc.returncode == 2, proc.stdout + proc.stderr


def test_help_flag_exits_zero_and_never_touches_pkg() -> None:
    proc = _run_argv("--help")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Usage:" in proc.stdout


def test_help_short_flag_exits_zero() -> None:
    proc = _run_argv("-h")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Usage:" in proc.stdout


def test_help_before_channel_short_circuits_without_requiring_one() -> None:
    """--help wins even when it is NOT the first/only argument — a user who typo'd
    the channel value still gets usage text, not a channel-validation error."""
    proc = _run_argv("--channel", "bogus", "--help")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Usage:" in proc.stdout


def test_help_flag_never_touches_pkg() -> None:
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
            ["sh", str(_SCRIPT), "--channel", channel], env=env, capture_output=True, text=True, check=False
        )

        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "/nonexistent/pkg" in proc.stderr, proc.stderr
        assert not _hook_path(root).exists(), "AFTER: no hook file must be written"
        assert not _conf_path(root, channel).exists(), "AFTER: no conf file must be written"


# --------------------------------------------------------------------------- #
# 18. Piped invocation: stdin never consumed by the script itself
# --------------------------------------------------------------------------- #


def test_piped_invocation_leaves_pkg_stdin_empty_and_installs_a_real_hook() -> None:
    """Scenario: given install.sh piped into `sh -s -- --channel stable` (the
    published `fetch | sh -s -- --channel <ch>` form, exercised here from a checkout
    with cwd = scripts/ so sibling-file resolution still finds the real hook), when
    it runs, then it succeeds and installs a real hook. (The stdin-isolation
    guarantee is pinned separately by test_pkg_wrapper_redirects_stdin_from_dev_null
    — here the call is the script's last statement, so sh has already drained the
    pipe.)"""
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
            "FETCH_BIN": _write_fetch_stub(root),
            "PFB_BASE_URL": _BASE_URL,
            "PFB_TEST_ROOT": root,
            "PFB_STUB_INFO_MANIFEST": manifest,
        }
        script_text = _SCRIPT.read_text()

        proc = subprocess.run(
            ["sh", "-s", "--", "--channel", channel],
            input=script_text,
            cwd=str(_SCRIPTS_DIR),
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
    """Scenario: given install.sh sourced (via `--help`, which returns before any
    pkg call, so control comes back to the sourcing shell) and a pkg(8) stub that
    reads its stdin, when `_pkg` runs while the calling shell's stdin still holds
    unread bytes (what a `fetch | sh -s -- --channel <ch>` pipe looks like
    mid-script), then the stub reads NOTHING — the wrapper hands every pkg call
    /dev/null, so no child can eat script text.

    ``. file arguments`` is a bash/ksh extension, not POSIX — dash's dot command
    ignores extra words. ``set -- --help`` first is the portable way to hand the
    sourced script its ``"$@"``: a sourced script with no explicit dot-arguments
    inherits the CALLING shell's current positional parameters (POSIX 2.9.5).
    """
    with tempfile.TemporaryDirectory() as root:
        pkg_bin = _write_pkg_stub(root)
        env = {**os.environ, "PKG_BIN": pkg_bin, "PFB_TEST_ROOT": root}
        proc = subprocess.run(
            ["sh", "-c", f'set -- --help; . "{_SCRIPT}" >/dev/null; _pkg query "%v" pfSense-pkg-pfBlockerNG'],
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
# 19. Structure: markers, sh -n
# --------------------------------------------------------------------------- #


def test_install_script_parses_and_carries_required_hook_markers() -> None:
    proc = subprocess.run(["sh", "-n", str(_SCRIPT)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr

    text = _SCRIPT.read_text()
    assert "# PFB_EMBED_HOOK_BEGIN" in text
    assert "# PFB_EMBED_HOOK_END" in text
    assert text.startswith("#!/bin/sh\n")
    assert os.access(str(_SCRIPT), os.X_OK), "the repository copy must be executable"


# --- SSL_CA_CERT_PATH export (issue #2514) ---------------------------------
#
# pfSense Plus pins pkg's CA bundle to Netgate's private CA via the PKG_ENV block
# pfSense-repo-setup writes into pkg.conf. That bundle carries only Netgate CAs, and
# libpkg applies it with setenv(..., overwrite=1), so libfetch-based pkg (1.x) ends up
# with NO public roots and every fetch from our Pages catalog dies with
# "Certificate verification failed for /C=US/O=ISRG/CN=Root YR".
#
# PKG_ENV never sets SSL_CA_CERT_PATH, and libfetch loads both file and path into one
# store (SSL_CTX_load_verify_locations(ctx, ca_cert_file, ca_cert_path)), so exporting
# the path survives the pin -- which is exactly what libcurl-based pkg (2.x) already
# does by default. Verified red->green live on a Plus box with fetch(1).


def _ca_dir(root: str) -> Path:
    return Path(root) / "etc" / "ssl" / "certs"


def _seed_ca_dir(root: str) -> Path:
    """Create the hash dir WITH an entry.

    install.sh refuses to export an empty hash dir (issue #2524), so any case that is
    about something else — the bundle half, a path with a space, an override — needs a
    populated one or it exercises the emptiness guard by accident.
    """
    ca_dir = _ca_dir(root)
    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / "deadbeef.0").write_text("-----BEGIN CERTIFICATE-----\n")
    return ca_dir


def test_every_pkg_call_exports_the_system_ca_path() -> None:
    """Every pkg(8) invocation carries SSL_CA_CERT_PATH pointing at the box's store."""
    with tempfile.TemporaryDirectory() as root:
        ca_dir = _ca_dir(root)
        ca_dir.mkdir(parents=True)
        (ca_dir / "4042bcee.0").write_text("")  # a hashed store is never empty

        proc = _run_install(root, "stable")
        assert proc.returncode == 0, proc.stderr

        seen = _pkg_ca_path_capture(root).read_text().splitlines()
        assert seen, "no pkg calls were made — the run cannot prove the export"
        assert set(seen) == {str(ca_dir)}, (
            f"expected every pkg call to export SSL_CA_CERT_PATH={ca_dir}, saw {sorted(set(seen))}"
        )


def test_absent_ca_dir_leaves_ssl_ca_cert_path_unset() -> None:
    """No CA directory on the box -> nothing is exported (never point pkg at a missing path)."""
    with tempfile.TemporaryDirectory() as root:
        assert not _ca_dir(root).exists()

        proc = _run_install(root, "stable")
        assert proc.returncode == 0, proc.stderr

        seen = _pkg_ca_path_capture(root).read_text().splitlines()
        assert seen, "no pkg calls were made — the run cannot prove the guard"
        assert set(seen) == {"<unset>"}, f"expected SSL_CA_CERT_PATH unset, saw {sorted(set(seen))}"

        files = _pkg_ca_file_capture(root).read_text().splitlines()
        assert set(files) == {"<unset>"}, f"expected SSL_CA_CERT_FILE unset, saw {sorted(set(files))}"


def test_empty_ca_dir_leaves_ssl_ca_cert_path_unset() -> None:
    """An EMPTY hash dir must not be exported (issue #2524).

    ``-d`` alone passes a directory that exists but holds nothing, and FreeBSD ships
    /etc/ssl/certs empty until ``certctl rehash`` runs — the state of a stock box, not a
    hypothetical. libfetch stops calling ``SSL_CTX_set_default_verify_paths()`` as soon as
    EITHER variable is set, so exporting an empty hash dir with no bundle beside it leaves
    an EMPTY store: strictly worse than exporting nothing at all. Matches the
    populated-directory guard the boot hook and ``pfb_pkg_exec()`` also carry.
    """
    with tempfile.TemporaryDirectory() as root:
        _ca_dir(root).mkdir(parents=True)
        assert _ca_dir(root).is_dir() and not any(_ca_dir(root).iterdir())
        assert not _ca_bundle(root).exists(), "bundle must be absent to isolate the PATH-only branch"

        proc = _run_install(root, "stable")
        assert proc.returncode == 0, proc.stderr

        seen = _pkg_ca_path_capture(root).read_text().splitlines()
        assert seen, "no pkg calls were made — the run cannot prove the guard"
        assert set(seen) == {"<unset>"}, (
            f"an empty hash dir was exported as SSL_CA_CERT_PATH={sorted(set(seen))} — "
            "that empties the trust store instead of widening it"
        )


def test_populated_ca_dir_is_still_exported() -> None:
    """The guard must not cost the working case: one entry is enough to export the path."""
    with tempfile.TemporaryDirectory() as root:
        _ca_dir(root).mkdir(parents=True)
        (_ca_dir(root) / "deadbeef.0").write_text("-----BEGIN CERTIFICATE-----\n")

        proc = _run_install(root, "stable")
        assert proc.returncode == 0, proc.stderr

        seen = _pkg_ca_path_capture(root).read_text().splitlines()
        assert seen, "no pkg calls were made — the run cannot prove the guard"
        assert set(seen) == {str(_ca_dir(root))}, (
            f"expected the populated hash dir to be exported, saw {sorted(set(seen))}"
        )


def test_ca_path_is_overridable() -> None:
    """PFB_SSL_CA_CERT_PATH overrides the default location."""
    with tempfile.TemporaryDirectory() as root:
        override = Path(root) / "custom-store"
        override.mkdir()
        # Populated on purpose: an empty hash dir is refused by design (issue #2524), and
        # this case is about the override being honoured, not about the emptiness guard.
        (override / "deadbeef.0").write_text("-----BEGIN CERTIFICATE-----\n")

        proc = _run_install(root, "stable", extra_env={"PFB_SSL_CA_CERT_PATH": str(override)})
        assert proc.returncode == 0, proc.stderr

        seen = _pkg_ca_path_capture(root).read_text().splitlines()
        assert seen, "no pkg calls were made — the run cannot prove the override"
        assert set(seen) == {str(override)}, f"override ignored, saw {sorted(set(seen))}"


def _ca_bundle(root: str) -> Path:
    return Path(root) / "etc" / "ssl" / "cert.pem"


def test_ca_bundle_is_exported_alongside_the_path() -> None:
    """The default bundle is exported too, so setting the path cannot shrink the store.

    libfetch takes `SSL_CTX_load_verify_locations(file, path)` as soon as EITHER variable
    is set, skipping `SSL_CTX_set_default_verify_paths()`. Exporting only the path would
    therefore drop /etc/ssl/cert.pem from the store on a box that has no PKG_ENV pin (CE),
    turning a working box into the very failure this change exists to fix whenever its
    hashed directory is empty or stale. On Plus, PKG_ENV overwrites this value with
    Netgate's bundle, which is exactly what should happen there.
    """
    with tempfile.TemporaryDirectory() as root:
        ca_dir = _ca_dir(root)
        ca_dir.mkdir(parents=True)
        bundle = _ca_bundle(root)
        bundle.write_text("# CA bundle\n")

        proc = _run_install(root, "stable")
        assert proc.returncode == 0, proc.stderr

        seen = _pkg_ca_file_capture(root).read_text().splitlines()
        assert seen, "no pkg calls were made — the run cannot prove the export"
        assert set(seen) == {str(bundle)}, (
            f"expected every pkg call to export SSL_CA_CERT_FILE={bundle}, saw {sorted(set(seen))}"
        )


def test_absent_ca_bundle_leaves_ssl_ca_cert_file_unset() -> None:
    """No bundle on the box -> nothing is exported (never point pkg at a missing file)."""
    with tempfile.TemporaryDirectory() as root:
        _ca_dir(root).mkdir(parents=True)
        assert not _ca_bundle(root).exists()

        proc = _run_install(root, "stable")
        assert proc.returncode == 0, proc.stderr

        seen = _pkg_ca_file_capture(root).read_text().splitlines()
        assert seen, "no pkg calls were made — the run cannot prove the guard"
        assert set(seen) == {"<unset>"}, f"expected SSL_CA_CERT_FILE unset, saw {sorted(set(seen))}"


def test_ca_locations_survive_a_path_containing_a_space() -> None:
    """Quoting holds: a location with a space reaches pkg intact, not word-split."""
    with tempfile.TemporaryDirectory() as root:
        spaced_dir = Path(root) / "ssl store" / "certs"
        spaced_dir.mkdir(parents=True)
        spaced_file = Path(root) / "ssl store" / "cert bundle.pem"
        spaced_file.write_text("# CA bundle\n")

        proc = _run_install(
            root,
            "stable",
            extra_env={
                "PFB_SSL_CA_CERT_PATH": str(spaced_dir),
                "PFB_SSL_CA_CERT_FILE": str(spaced_file),
            },
        )
        assert proc.returncode == 0, proc.stderr

        paths = _pkg_ca_path_capture(root).read_text().splitlines()
        files = _pkg_ca_file_capture(root).read_text().splitlines()
        assert paths and files, "no pkg calls were made — the run cannot prove the quoting"
        assert set(paths) == {str(spaced_dir)}, f"path mangled, saw {sorted(set(paths))}"
        assert set(files) == {str(spaced_file)}, f"file mangled, saw {sorted(set(files))}"


def test_bundle_without_a_directory_exports_only_the_bundle() -> None:
    """Only the bundle present -> only it is exported (the third guard combination)."""
    with tempfile.TemporaryDirectory() as root:
        bundle = _ca_bundle(root)
        bundle.parent.mkdir(parents=True)
        bundle.write_text("# CA bundle\n")
        assert not _ca_dir(root).exists()

        proc = _run_install(root, "stable")
        assert proc.returncode == 0, proc.stderr

        paths = _pkg_ca_path_capture(root).read_text().splitlines()
        files = _pkg_ca_file_capture(root).read_text().splitlines()
        assert files, "no pkg calls were made — the run cannot prove the branch"
        assert set(paths) == {"<unset>"}, f"expected SSL_CA_CERT_PATH unset, saw {sorted(set(paths))}"
        assert set(files) == {str(bundle)}, f"expected the bundle exported, saw {sorted(set(files))}"


def test_empty_path_override_opts_out_of_the_directory() -> None:
    """PFB_SSL_CA_CERT_PATH="" exports no path — the documented opt-out (`-`, not `:-`)."""
    with tempfile.TemporaryDirectory() as root:
        _ca_dir(root).mkdir(parents=True)
        bundle = _ca_bundle(root)
        bundle.write_text("# CA bundle\n")

        proc = _run_install(root, "stable", extra_env={"PFB_SSL_CA_CERT_PATH": ""})
        assert proc.returncode == 0, proc.stderr

        paths = _pkg_ca_path_capture(root).read_text().splitlines()
        files = _pkg_ca_file_capture(root).read_text().splitlines()
        assert paths, "no pkg calls were made — the run cannot prove the opt-out"
        assert set(paths) == {"<unset>"}, f"opt-out ignored, saw {sorted(set(paths))}"
        assert set(files) == {str(bundle)}, f"the other half must still export, saw {sorted(set(files))}"


def test_empty_bundle_override_opts_out_of_the_file() -> None:
    """PFB_SSL_CA_CERT_FILE="" exports no bundle, and the path is unaffected."""
    with tempfile.TemporaryDirectory() as root:
        ca_dir = _ca_dir(root)
        _seed_ca_dir(root)
        _ca_bundle(root).write_text("# CA bundle\n")

        proc = _run_install(root, "stable", extra_env={"PFB_SSL_CA_CERT_FILE": ""})
        assert proc.returncode == 0, proc.stderr

        paths = _pkg_ca_path_capture(root).read_text().splitlines()
        files = _pkg_ca_file_capture(root).read_text().splitlines()
        assert files, "no pkg calls were made — the run cannot prove the opt-out"
        assert set(files) == {"<unset>"}, f"opt-out ignored, saw {sorted(set(files))}"
        assert set(paths) == {str(ca_dir)}, f"the other half must still export, saw {sorted(set(paths))}"


def test_empty_bundle_file_is_not_exported() -> None:
    """A zero-byte bundle is refused, because loading it would cost the path too.

    X509_STORE_load_locations() reads the file eagerly and abandons the CApath when that
    read fails, so pointing pkg at a truncated /etc/ssl/cert.pem would break a box whose
    hashed directory is perfectly healthy — a state set_default_verify_paths() tolerates.
    """
    with tempfile.TemporaryDirectory() as root:
        ca_dir = _ca_dir(root)
        _seed_ca_dir(root)
        _ca_bundle(root).write_text("")

        proc = _run_install(root, "stable")
        assert proc.returncode == 0, proc.stderr

        files = _pkg_ca_file_capture(root).read_text().splitlines()
        paths = _pkg_ca_path_capture(root).read_text().splitlines()
        assert files, "no pkg calls were made — the run cannot prove the guard"
        assert set(files) == {"<unset>"}, f"empty bundle was exported, saw {sorted(set(files))}"
        assert set(paths) == {str(ca_dir)}, f"the path must still export, saw {sorted(set(paths))}"


def test_directory_as_bundle_is_not_exported() -> None:
    """A directory where the bundle should be is refused: `-s` alone is true for one."""
    with tempfile.TemporaryDirectory() as root:
        ca_dir = _ca_dir(root)
        _seed_ca_dir(root)
        _ca_bundle(root).mkdir(parents=True)  # a directory, not a bundle

        proc = _run_install(root, "stable")
        assert proc.returncode == 0, proc.stderr

        files = _pkg_ca_file_capture(root).read_text().splitlines()
        paths = _pkg_ca_path_capture(root).read_text().splitlines()
        assert files, "no pkg calls were made — the run cannot prove the guard"
        assert set(files) == {"<unset>"}, f"a directory was exported as the bundle, saw {sorted(set(files))}"
        assert set(paths) == {str(ca_dir)}, f"the path must still export, saw {sorted(set(paths))}"


# --------------------------------------------------------------------------- #
# 21. pkg output reaches the terminal while pkg is still running (issue #2644)
# --------------------------------------------------------------------------- #


_STREAM_MARKER = "pfb-stream-marker-2644"


def test_pkg_output_is_streamed_while_pkg_still_runs() -> None:
    """The capture that lets install.sh rescan for ``pkg: <script> script failed``
    (issue #2575) must not withhold pkg's output until pkg exits: on a real box the
    converge step is the last slow step, so a replay-at-the-end lands the whole
    install log — pkg's lines and every package script's lines — in one burst right
    before ``==> Done`` (issue #2644).

    The fake pkg prints a marker and then blocks on a sentinel file; the marker has
    to be readable on install.sh's stdout while pkg is still blocked.
    """
    with tempfile.TemporaryDirectory() as root:
        sentinel = Path(root) / "unblock-pkg"
        argv, env = _prepare_install(
            root,
            "stable",
            extra_env={"PFB_STUB_STREAM_BLOCK": str(sentinel)},
        )

        proc = subprocess.Popen(
            argv,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        seen: list[str] = []
        stream = proc.stdout
        assert stream is not None
        reader = threading.Thread(target=lambda: seen.extend(stream), daemon=True)
        reader.start()
        try:
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not any(_STREAM_MARKER in ln for ln in seen):
                time.sleep(0.05)
            streamed = any(_STREAM_MARKER in ln for ln in seen)
            still_running = proc.poll() is None
        finally:
            sentinel.write_text("")
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)
            reader.join(timeout=10)

        output = "".join(seen)
        assert proc.returncode == 0, output
        assert still_running, (
            "fixture broken: install.sh had already finished, so a replay-at-the-end would "
            "have satisfied the marker check too"
        )
        assert streamed, f"pkg output was withheld until pkg exited; got:\n{output}"
        assert "Done" in output


# --------------------------------------------------------------------------- #
# 22. pkg's own non-zero exit is still fatal (issue #2647 review)
# --------------------------------------------------------------------------- #


def test_nonzero_pkg_install_exit_is_fatal() -> None:
    """A mutating pkg call that exits non-zero must stop the run with the caller's
    message and no ``==> Done``.

    Distinct from the #2575 cases, which are pkg exiting ZERO after a package script
    failed. Nothing else in this suite makes ``pkg install`` itself fail, so without
    this the status hand-off out of the streaming reader could report success for a
    failed install and every test would stay green."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "stable", extra_env={"PFB_STUB_MUTATE_RC": "7"})

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert "Done" not in proc.stdout
        assert "pkg install -r pfblockerng-stable" in proc.stderr, proc.stderr
        # The failing call's own output still reaches the operator.
        assert "pkg: some transport failure" in proc.stdout + proc.stderr


def test_nonzero_pkg_delete_exit_is_fatal() -> None:
    """Same contract on the delete verb, which runs from step 9a when a legacy
    identity has to go before the canonical package can be installed."""
    with tempfile.TemporaryDirectory() as root:
        _seed_installed(root, f"{_CANONICAL}-devel", "3.2.14_2", "pfblockerng")
        _seed_conf_file(root, _LEGACY_CONF, "# legacy release conf\n")

        proc = _run_install(root, "stable", extra_env={"PFB_STUB_MUTATE_RC": "7"})

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert "Done" not in proc.stdout
        assert "pkg delete" in proc.stderr, proc.stderr


# --------------------------------------------------------------------------- #
# 23. the output reader dies with the run (issue #2647 review)
# --------------------------------------------------------------------------- #


def _install_sh_pids(pgid: int) -> list[str]:
    """PIDs in process group ``pgid`` still running install.sh."""
    found = subprocess.run(
        ["pgrep", "-g", str(pgid), "-f", "install.sh"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in found.stdout.split() if line]


def test_output_reader_does_not_outlive_the_run() -> None:
    """install.sh streams pkg's output from a background reader. A background reader is
    an untracked wait, so it has to die with its task -- not reparent to PID 1 and poll
    on. SIGKILL is the case no trap can cover, which is exactly why the reader tests its
    parent itself (AGENTS.md "No orphaned waits")."""
    with tempfile.TemporaryDirectory() as root:
        sentinel = Path(root) / "unblock-pkg"
        argv, env = _prepare_install(
            root,
            "stable",
            extra_env={"PFB_STUB_STREAM_BLOCK": str(sentinel)},
        )
        # Own session, so the group holds this run and nothing else.
        proc = subprocess.Popen(
            argv,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        pgid = os.getpgid(proc.pid)
        try:
            seen: list[str] = []
            stream = proc.stdout
            assert stream is not None
            reader = threading.Thread(target=lambda: seen.extend(stream), daemon=True)
            reader.start()

            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline and not any(_STREAM_MARKER in ln for ln in seen):
                time.sleep(0.05)
            assert any(_STREAM_MARKER in ln for ln in seen), (
                f"fixture broken: the run never reached the streaming pkg call; got {seen!r}"
            )
            # The run is mid-install: install.sh itself plus its reader are both live.
            assert len(_install_sh_pids(pgid)) >= 2, (
                "fixture broken: no background reader was running, so killing the parent proves nothing about orphans"
            )

            os.kill(proc.pid, signal.SIGKILL)

            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline and _install_sh_pids(pgid):
                time.sleep(0.25)
            survivors = _install_sh_pids(pgid)
            assert not survivors, (
                f"the output reader outlived install.sh (pids {survivors}); it must stop when its parent is gone"
            )
        finally:
            sentinel.write_text("")
            for pid in _install_sh_pids(pgid):
                with contextlib.suppress(ProcessLookupError, ValueError):
                    os.kill(int(pid), signal.SIGKILL)
            with contextlib.suppress(ProcessLookupError):
                os.kill(proc.pid, signal.SIGKILL)
            proc.wait(timeout=30)


# --------------------------------------------------------------------------- #
# 22. pkg-setup repair hint (issues #2789, #2803, #2808): a failed pkg step is
#     frequently the box's own repository setup, not our conf. `pfSense-upgrade -u`
#     rebuilds that setup and refreshes the catalogue in one command; the bare form
#     is the escalation behind a retry, because it upgrades the release and reboots.
#     The hint rides the failure output, but only where that setup can be the cause.
# --------------------------------------------------------------------------- #

_REPAIR_COMMAND = "pfSense-upgrade -u"
_BARE_UPGRADE_LIST_ITEM = "install.sh:   pfSense-upgrade\n"


def _repair_hint_on_stderr(proc: subprocess.CompletedProcess[str]) -> bool:
    """The hint rides stderr beside die()'s diagnosis: a user who captures only stderr
    for a bug report still gets the remedy."""
    return _REPAIR_COMMAND in proc.stderr


def _repair_hint_shown(proc: subprocess.CompletedProcess[str]) -> bool:
    """Either stream, and either form of the command — strictly stronger than the stderr
    check, so a negative case cannot pass merely because the hint went to stdout."""
    return "pfSense-upgrade" in proc.stdout + proc.stderr


def test_pkg_update_failure_prints_the_repository_repair_sequence() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "testing", update_fails=True)

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert _repair_hint_on_stderr(proc), proc.stdout + proc.stderr
        assert proc.stderr.index("failed") < proc.stderr.index(_REPAIR_COMMAND), (
            f"the diagnosis must precede the remedy:\n{proc.stderr}"
        )


def test_repair_hint_gates_the_bare_upgrade_behind_a_retry() -> None:
    """issues #2803/#2808: `pfSense-upgrade -u` rebuilds the repository setup and
    refreshes the catalogue, and is safe. The BARE form applies the box's pending
    release upgrade and reboots (upstream sets `: ${action:="upgrade"}` when no action
    flag is given), so it sits behind a retry — never beside `-u` as a second list
    item the user works through in order."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "testing", update_fails=True)

        assert proc.returncode == 4, proc.stdout + proc.stderr
        hint = proc.stderr
        _, _, escalation = hint.partition(_REPAIR_COMMAND)
        assert escalation, f"the one-command repair is missing entirely:\n{hint}"
        # Shape, not just vocabulary: a bare `pfSense-upgrade` on its own indented line is
        # a second list item, the regression this gate exists to catch — every keyword
        # below survives that flattening.
        assert _BARE_UPGRADE_LIST_ITEM not in hint, f"the bare upgrade must not be a list item beside `-u`:\n{hint}"
        assert "re-run" in escalation, f"the retry must sit before the escalation:\n{hint}"
        assert "only if" in escalation, f"the bare upgrade must be conditional:\n{hint}"
        assert "reboot" in escalation, f"the reboot must be stated where it is proposed:\n{hint}"
        assert escalation.index("only if") < escalation.index("reboot"), (
            f"the condition must precede the consequence:\n{hint}"
        )


def test_usage_gates_the_bare_upgrade_behind_a_retry() -> None:
    proc = _run_argv("--help")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    text = proc.stdout
    _, _, escalation = text.partition(_REPAIR_COMMAND)
    assert escalation, text
    assert "\n  pfSense-upgrade\n" not in text, f"the bare upgrade must not be a list item:\n{text}"
    # Help text is prose, so the gate words may open a sentence.
    folded = escalation.casefold()
    assert "re-run" in folded, text
    assert "only if" in folded, text
    assert "reboot" in folded, text
    assert folded.index("only if") < folded.index("reboot"), f"the condition must precede the consequence:\n{text}"


def test_empty_catalogue_failure_prints_the_repository_repair_sequence() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "edge", catalog=())

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert _repair_hint_on_stderr(proc), proc.stdout + proc.stderr


def test_pkg_install_failure_prints_the_repository_repair_sequence() -> None:
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "stable", extra_env={"PFB_STUB_MUTATE_RC": "7"})

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert _repair_hint_on_stderr(proc), proc.stdout + proc.stderr


def test_unresolved_conf_leaves_a_stale_conf_byte_identical_without_repair_hint() -> None:
    """The hook stages a CANDIDATE — never CONF_PATH — so when detection fails, the
    seeded (stale, foreign) conf is not even read: the run dies on the marker-less
    candidate before pkg, leaving the pre-existing conf byte-identical, and must not
    point the user at pkg-repository repair (this is our own bootstrap failing)."""
    with tempfile.TemporaryDirectory() as root:
        channel = "stable"
        argv, env = _prepare_install(root, channel)
        # Detection failure: blank /etc/version, so the hook leaves the candidate alone.
        with open(os.path.join(root, "etc", "version"), "w") as fh:
            fh.write("")
        stale_conf_text = (
            "# Generated at boot by pfblockerng_repo_generate (ADR-39)\n"
            'pfblockerng-stable: {\n  url: "https://other.example/pkg/stable/ce-2.8",\n'
            "  mirror_type: none,\n  signature_type: none,\n  priority: 100,\n  enabled: yes\n}\n"
        )
        conf_path = _seed_conf_file(root, _conf_name(channel), stale_conf_text)

        proc = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert "no marker line" in proc.stderr, proc.stderr
        assert conf_path.read_text() == stale_conf_text, (
            "the stale conf must be left byte-identical — the hook stages a candidate, never CONF_PATH"
        )
        assert not _repair_hint_shown(proc), proc.stdout + proc.stderr


def test_unresolved_conf_does_not_print_the_repository_repair_sequence() -> None:
    """The sibling exit-4 site: a conf with no boot marker at all means the generator
    hook never resolved it, which is again our bootstrap and not the box's pkg setup."""
    with tempfile.TemporaryDirectory() as root:
        channel = "stable"
        argv, env = _prepare_install(root, channel)
        with open(os.path.join(root, "etc", "version"), "w") as fh:
            fh.write("")
        _seed_conf_file(root, _conf_name(channel), "# hand-written, no generator marker\n")

        proc = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert "no marker line" in proc.stderr, proc.stderr
        assert not _repair_hint_shown(proc), proc.stdout + proc.stderr


def test_postinstall_script_failure_does_not_print_the_repository_repair_sequence() -> None:
    """Our POST-INSTALL failing is our package's own script, not the box's repository
    setup — pkg fetched and extracted the package just fine."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "stable", extra_env={"PFB_STUB_POSTINSTALL_FAIL": "1"})

        assert proc.returncode == 5, proc.stdout + proc.stderr
        assert not _repair_hint_shown(proc), proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# 24. Catalogue probe before activation (issue #2926)
# --------------------------------------------------------------------------- #


def test_missing_fetch_binary_fails_at_step_1_with_exit_1() -> None:
    """FETCH_BIN is validated beside PKG_BIN: a missing fetch must fail loudly at
    step 1 — before the hook or any conf candidate is written — exit 1, naming the
    missing path in the message."""
    with tempfile.TemporaryDirectory() as root:
        channel = "stable"
        _seed_box(root)
        env = {
            **os.environ,
            "PFBLOCKERNG_ROOT": root,
            "PKG_BIN": _write_pkg_stub(root),
            "FETCH_BIN": "/nonexistent/fetch",
            "PFB_BASE_URL": _BASE_URL,
            "PFB_TEST_ROOT": root,
        }
        proc = subprocess.run(
            ["sh", str(_SCRIPT), "--channel", channel], env=env, capture_output=True, text=True, check=False
        )

        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "/nonexistent/fetch" in proc.stderr, proc.stderr
        assert not _hook_path(root).exists(), "AFTER: no hook file must be written"
        assert not _conf_path(root, channel).exists(), "AFTER: no conf file must be written"


def test_fresh_install_failed_probe_exits_4_without_conf_or_pkg_call() -> None:
    """Scenario: given a fresh box (plus an already-working peer subscription), when
    the catalogue probe fails, then the run exits 4 with NO conf activated for this
    channel, zero pkg invocations, the peer conf byte-identical, and no candidate
    conf left behind in the repos directory."""
    with tempfile.TemporaryDirectory() as root:
        peer = _seed_conf_file(root, _conf_name("nightly"), "# peer nightly conf\n")

        proc = _run_install(root, "stable", extra_env={"PFB_STUB_FETCH_FAIL": "1"})

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert not _conf_path(root, "stable").exists(), "a failed probe must not activate a conf"
        assert _pkg_log(root).read_text() == "", "a failed probe must invoke no pkg"
        assert peer.read_text() == "# peer nightly conf\n", "the peer conf must be untouched"
        leftovers = [p for p in os.listdir(_repos_dir(root)) if not p.endswith(".conf")]
        assert leftovers == [], f"the candidate conf leaked: {leftovers}"
        assert _fetch_log(root).read_text() == (f"pkg-log-bytes=0 {_BASE_URL}/stable/ce-2.8/meta.conf\n"), (
            "the probe must request the generated catalogue's meta.conf"
        )


def test_failed_probe_keeps_a_pre_existing_conf_byte_identical() -> None:
    """Scenario: given a box whose conf predates this run, when the catalogue probe
    fails, then the run exits 4 and the original conf bytes are retained EXACTLY —
    the hook stages a candidate, never CONF_PATH, so nothing is rewritten before
    the catalogue is proven."""
    with tempfile.TemporaryDirectory() as root:
        original = "# operator's conf — pending boot-time generation\n"
        conf = _seed_conf_file(root, _conf_name("stable"), original)

        proc = _run_install(root, "stable", extra_env={"PFB_STUB_FETCH_FAIL": "1"})

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert conf.read_text() == original, "a failed probe must never rewrite an existing conf — it was never touched"
        assert _pkg_log(root).read_text() == "", "a failed probe must invoke no pkg"
        leftovers = [p for p in os.listdir(_repos_dir(root)) if not p.endswith(".conf")]
        assert leftovers == [], f"the candidate conf leaked: {leftovers}"
        assert _fetch_log(root).read_text() == (f"pkg-log-bytes=0 {_BASE_URL}/stable/ce-2.8/meta.conf\n"), (
            "the probe requested the candidate's meta.conf exactly once, with the pkg log empty"
        )


def test_probe_requests_the_exact_generated_catalog_url_before_any_pkg_call() -> None:
    """fetch receives ``<base>/<channel>/<varver>/meta.conf`` — the catalogue URL the
    hook generated, exactly one canonical URL — and the probe lands BEFORE the first
    pkg call: the stub records the pkg log's size at fetch time, and it must be 0."""
    with tempfile.TemporaryDirectory() as root:
        proc = _run_install(root, "stable")

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert _fetch_log(root).read_text().splitlines() == [f"pkg-log-bytes=0 {_BASE_URL}/stable/ce-2.8/meta.conf"], (
            "exactly one probe of the generated catalogue's meta.conf, before any pkg call"
        )
        assert stat.S_IMODE(_conf_path(root, "stable").stat().st_mode) == 0o644, (
            "the activated repository conf must remain world-readable"
        )


@pytest.mark.parametrize(
    "hostile_id, hostile_tail",
    [
        ("ident-var", "/$ABI"),
        ("brace-var", "/${ABI}"),
        ("backslash", "/back\\slash"),
    ],
)
def test_hostile_url_with_ucl_transforming_syntax_fails_before_probe(hostile_id: str, hostile_tail: str) -> None:
    """UCL — pkg(8)'s conf grammar — expands ``$IDENT``/``${...}`` references and a
    backslash escapes the next character, so a url value carrying either is NOT
    byte-identical to what pkg reads back out of the activated conf: the probe
    would fetch one string while pkg resolves another. Rejected BEFORE the fetch:
    exit 4, no fetch call, no conf activated, no pkg call, no candidate leak, peer
    conf untouched."""
    with tempfile.TemporaryDirectory() as root:
        peer = _seed_conf_file(root, _conf_name("nightly"), "# peer nightly conf\n")

        proc = _run_install(root, "stable", extra_env={"PFB_BASE_URL": _BASE_URL + hostile_tail})

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert not _fetch_log(root).exists(), "a UCL-hostile url must be rejected before any fetch"
        assert not _fetch_argv_log(root).exists(), "a UCL-hostile url must be rejected before any fetch"
        assert _pkg_log(root).read_text() == "", "a rejected candidate must invoke no pkg"
        assert not _conf_path(root, "stable").exists(), "a rejected candidate must not activate a conf"
        assert peer.read_text() == "# peer nightly conf\n", "the peer conf must be untouched"
        assert [p for p in os.listdir(_repos_dir(root)) if not p.endswith(".conf")] == [], "the candidate conf leaked"


def test_probe_argv_carries_the_no_redirect_flag_and_failed_pkg_keeps_inherited_conf() -> None:
    """fetch must be invoked with ``-A``: a redirect must never establish that the
    catalogue resource exists — a redirect-shaped false positive would pass the
    probe and let the run proceed to pkg, which then fails on the dead catalog.
    When that failure lands AFTER activation on a box whose conf predates the run,
    the inherited conf survives (CONF_CREATED=0 — a conf this run did not create is
    never removed); the stub's argv log pins the exact flags."""
    with tempfile.TemporaryDirectory() as root:
        conf = _seed_conf_file(root, _conf_name("stable"), "# inherited stable conf\n")
        timeout_bin = _write_timeout_stub(root)

        proc = _run_install(
            root,
            "stable",
            update_fails=True,
            extra_env={"TIMEOUT_BIN": timeout_bin},
        )

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert _fetch_argv_log(root).read_text().splitlines() == [
            f"-q -A -o /dev/null -T 30 {_BASE_URL}/stable/ce-2.8/meta.conf"
        ], "the probe must carry exactly the no-redirect flag (-A) with its bounded flags"
        assert _timeout_log(root).read_text().splitlines() == [
            f"-k 5 30 {Path(root) / 'bin' / 'fetch'} -q -A -o /dev/null -T 30 {_BASE_URL}/stable/ce-2.8/meta.conf"
        ], "timeout(1) must own a hard 30-second wall-clock budget around fetch"
        assert _fetch_log(root).read_text() == (f"pkg-log-bytes=0 {_BASE_URL}/stable/ce-2.8/meta.conf\n"), (
            "the probe still lands before any pkg call"
        )
        assert conf.exists(), "an inherited conf must not be removed on a post-activation failure"
        assert _pkg_log(root).read_text() != "", "pkg ran (the update failed) after the probe passed"


def test_hostile_base_url_with_embedded_quote_fails_before_probe() -> None:
    """A base URL carrying a double quote makes the hook write a conf whose url
    value terminates at the embedded quote — extraction and validation used to be
    uncoupled, so the grep-anywhere prefix check accepted the line while the probe
    fetched a TRUNCATED URL. The candidate must be rejected before any fetch."""
    with tempfile.TemporaryDirectory() as root:
        peer = _seed_conf_file(root, _conf_name("nightly"), "# peer nightly conf\n")

        proc = _run_install(root, "stable", extra_env={"PFB_BASE_URL": f'{_BASE_URL}"hostile'})

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert not _fetch_log(root).exists(), "a malformed candidate must be rejected before any fetch"
        assert _pkg_log(root).read_text() == "", "a rejected candidate must invoke no pkg"
        assert not _conf_path(root, "stable").exists(), "a rejected candidate must not activate a conf"
        assert peer.read_text() == "# peer nightly conf\n", "the peer conf must be untouched"
        assert [p for p in os.listdir(_repos_dir(root)) if not p.endswith(".conf")] == [], "the candidate conf leaked"


def test_hostile_base_url_forging_prefix_in_extra_url_line_fails_closed() -> None:
    """A newline-bearing base URL makes the hook write a second, well-formed url
    key carrying the expected prefix; a grep-anywhere check accepts it while the
    FIRST url (the one extraction picks up) points elsewhere. Exactly one url key
    is allowed — the candidate must be rejected before any fetch."""
    with tempfile.TemporaryDirectory() as root:
        hostile = f'{_BASE_URL}/one",\nurl: "{_BASE_URL}/stable/evil'
        peer = _seed_conf_file(root, _conf_name("nightly"), "# peer nightly conf\n")

        proc = _run_install(root, "stable", extra_env={"PFB_BASE_URL": hostile})

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert not _fetch_log(root).exists(), "a multi-url candidate must be rejected before any fetch"
        assert _pkg_log(root).read_text() == "", "a rejected candidate must invoke no pkg"
        assert not _conf_path(root, "stable").exists(), "a rejected candidate must not activate a conf"
        assert peer.read_text() == "# peer nightly conf\n", "the peer conf must be untouched"
        assert [p for p in os.listdir(_repos_dir(root)) if not p.endswith(".conf")] == [], "the candidate conf leaked"


def test_hostile_base_url_forging_prefix_in_comment_fails_closed() -> None:
    """A newline-bearing base URL can forge the expected prefix inside a COMMENT
    line, which a grep-anywhere prefix check accepts while the single real url
    points elsewhere. The extracted url VALUE must itself match the expected
    <base>/<channel>/ prefix — the candidate must be rejected before any fetch."""
    with tempfile.TemporaryDirectory() as root:
        hostile = f'{_BASE_URL}/one",\n# url: "{_BASE_URL}/stable/evil'
        peer = _seed_conf_file(root, _conf_name("nightly"), "# peer nightly conf\n")

        proc = _run_install(root, "stable", extra_env={"PFB_BASE_URL": hostile})

        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert not _fetch_log(root).exists(), "a forged-prefix candidate must be rejected before any fetch"
        assert _pkg_log(root).read_text() == "", "a rejected candidate must invoke no pkg"
        assert not _conf_path(root, "stable").exists(), "a rejected candidate must not activate a conf"
        assert peer.read_text() == "# peer nightly conf\n", "the peer conf must be untouched"
        assert [p for p in os.listdir(_repos_dir(root)) if not p.endswith(".conf")] == [], "the candidate conf leaked"


@pytest.mark.parametrize("hostile_kind", ["directory", "symlink-to-directory"])
def test_conf_path_not_a_regular_file_fails_closed(hostile_kind: str) -> None:
    """A directory (or a symlink to one) named like the conf must fail closed:
    `mv candidate CONF_PATH` into a directory SUCCEEDS by moving the candidate
    inside it — activation never established, cleanup disarmed, pkg still run.
    The destination's own identity is snapshotted BEFORE the run and verified
    after (lstat kind/inode; for a symlink, the exact readlink target), and NO
    non-.conf candidate may survive ANYWHERE under REPOS_DIR. Exit 1, zero pkg
    calls, peer conf untouched."""
    with tempfile.TemporaryDirectory() as root:
        peer = _seed_conf_file(root, _conf_name("nightly"), "# peer nightly conf\n")
        conf_path = _conf_path(root, "stable")
        hostile_dir = _repos_dir(root) / "hostile-dir"
        hostile_dir.mkdir()
        if hostile_kind == "directory":
            conf_path.mkdir()
        else:
            os.symlink(hostile_dir, conf_path)
        pre_lstat = os.lstat(conf_path)
        pre_target = os.readlink(conf_path) if hostile_kind == "symlink-to-directory" else None

        proc = _run_install(root, "stable")

        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "not a regular file" in proc.stderr, proc.stderr
        assert _pkg_log(root).read_text() == "", "activation refusal must invoke no pkg"
        post_lstat = os.lstat(conf_path)
        assert (post_lstat.st_dev, post_lstat.st_ino, post_lstat.st_mtime_ns) == (
            pre_lstat.st_dev,
            pre_lstat.st_ino,
            pre_lstat.st_mtime_ns,
        ), "the hostile destination itself must be untouched by the run"
        if hostile_kind == "directory":
            assert stat.S_ISDIR(pre_lstat.st_mode) and stat.S_ISDIR(post_lstat.st_mode)
            assert os.listdir(conf_path) == [], (
                f"the candidate must not be moved inside the hostile directory: {os.listdir(conf_path)}"
            )
        else:
            assert stat.S_ISLNK(pre_lstat.st_mode) and stat.S_ISLNK(post_lstat.st_mode)
            assert os.readlink(conf_path) == pre_target, (
                "the symlink conf must still point at the same target after the run"
            )
            assert hostile_dir.is_symlink() or hostile_dir.is_dir()
            assert os.listdir(hostile_dir) == [], f"the candidate leaked: {os.listdir(hostile_dir)}"
        leftovers = [
            str(p.relative_to(_repos_dir(root)))
            for p in _repos_dir(root).rglob("*")
            if p.is_file() and not p.name.endswith(".conf")
        ]
        assert leftovers == [], f"the candidate conf leaked somewhere under REPOS_DIR: {leftovers}"
        assert peer.read_text() == "# peer nightly conf\n", "the peer conf must be untouched"


def test_usage_documents_the_repository_repair_sequence() -> None:
    proc = _run_argv("--help")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _REPAIR_COMMAND in proc.stdout, proc.stdout
