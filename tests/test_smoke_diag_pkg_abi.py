"""Smoke diag bundle must capture pkg ABI/repos with URL redaction (issue #2754).

A #2242 drift (guest pkg ABI FreeBSD:16 vs expected 15) produced 155 setup
errors. The collector had no pkg config ABI, no pkg -vv, no repo confs, so
the forced-ABI path stayed unproven after the guest was torn down.

pkg -vv and repo confs can carry credentials. Redact userinfo and token-shaped
query parameters at capture time.
"""

from __future__ import annotations

import errno
import inspect
import io
import subprocess
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from tests.smoke import helpers


def _add_text_member(archive: tarfile.TarFile, name: str, text: str) -> None:
    payload = text.encode("utf-8")
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))


def test_collect_host_diagnostics_captures_pkg_abi_and_uname() -> None:
    """Given collect_host_diagnostics
    When it builds the guest snapshot script
    Then it records pkg ABI, ALTABI, and uname -mr.
    """
    src = inspect.getsource(helpers.collect_host_diagnostics)
    assert "pkg config ABI" in src
    assert "pkg config ALTABI" in src
    assert "uname -mr" in src


def test_collect_host_diagnostics_captures_pkg_vv_and_repo_confs() -> None:
    """Given collect_host_diagnostics
    When it snapshots pkg configuration
    Then pkg -vv and /usr/local/etc/pkg/repos are in the bundle.
    """
    src = inspect.getsource(helpers.collect_host_diagnostics)
    assert 'pkg -vv > "$D/pkg/pkg_vv.txt"' in src
    assert "/usr/local/etc/pkg/repos" in src


def test_redact_pkg_urls_strips_userinfo() -> None:
    """Given a repo URL with user:pass@
    When capture-time redaction runs
    Then the userinfo is gone and the rest of the URL remains.
    """
    raw = "url: https://ci-token:s3cret@pkg.example.com/nightly/ce-2.8\n"
    out = helpers.redact_pkg_urls(raw)
    assert "s3cret" not in out
    assert "ci-token" not in out
    assert "pkg.example.com/nightly/ce-2.8" in out
    assert "REDACTED@" in out


def test_redact_pkg_urls_strips_token_query() -> None:
    """Given a URL with a token-shaped query parameter
    When capture-time redaction runs
    Then the parameter value is REDACTED and neighbouring params remain.
    """
    raw = "https://pkg.example.com/repo?token=ghp_abc123&abi=FreeBSD:15:amd64\n"
    out = helpers.redact_pkg_urls(raw)
    assert "ghp_abc123" not in out
    assert "token=REDACTED" in out
    assert "abi=FreeBSD:15:amd64" in out


def test_redact_pkg_urls_strips_uppercase_token_query() -> None:
    """Given ?TOKEN= (all-caps keyword)
    When the Python redactor runs
    Then the secret is gone.
    """
    raw = "url: https://pkg.example.com/repo?TOKEN=SEKRIT&abi=FreeBSD:15:amd64\n"
    out = helpers.redact_pkg_urls(raw)
    assert "SEKRIT" not in out
    assert "TOKEN=REDACTED" in out


def test_guest_sed_redacts_uppercase_token_query() -> None:
    """Given the on-box sed program
    When it sees ?TOKEN= and ?KEY=
    Then those secrets are gone (BSD sed has no I flag; every letter is spelled).
    """
    raw = "?token=seklower\n?Token=sekmixed\n?TOKEN=SEKRIT\n?KEY=KEYSECRET\n?tOkEn=weird\n"
    out = helpers.apply_guest_pkg_url_sed(raw)
    assert "seklower" not in out
    assert "sekmixed" not in out
    assert "SEKRIT" not in out
    assert "KEYSECRET" not in out
    assert "weird" not in out


def test_redact_pkg_urls_leaves_clean_urls_intact() -> None:
    """Given a URL with no userinfo and no token query
    When capture-time redaction runs
    Then the text is unchanged.
    """
    raw = "url: http://pkg.pfblockerng.com/nightly/ce-2.8/\nABI: FreeBSD:15:amd64\n"
    assert helpers.redact_pkg_urls(raw) == raw


def test_redact_pkg_urls_docstring_names_partial_mitigation() -> None:
    """Given redact_pkg_urls
    When its docstring is read
    Then it names a partial mitigation and residual path-segment risk,
    not that the tarball never holds credentials.
    """
    src = inspect.getsource(helpers.redact_pkg_urls)
    assert "never holds" not in src
    assert "partial mitigation" in src
    assert "path-segment" in src


def test_collect_host_diagnostics_redacts_pkg_urls_at_capture() -> None:
    """Given the guest snapshot script
    When it captures pkg -vv and repo confs
    Then the live on-box sed is the tested program, and the host second pass runs.
    """
    src = inspect.getsource(helpers.collect_host_diagnostics)
    assert "_PKG_URL_GUEST_SED_QUERY" in src
    assert "redact_pkg_tarball(" in src


def test_redact_pkg_tarball_drops_absolute_symlink_and_strips_residual_token(tmp_path: Path) -> None:
    """The host pass skips appliance absolute links without losing pkg redaction."""
    outside = tmp_path / "outside.conf"
    outside_text = "url: https://outside.example/repo?TOKEN=OUTSIDE_SECRET\n"
    outside.write_text(outside_text, encoding="utf-8")
    tgz = tmp_path / "pfb_smoke_diag.tgz"
    secret = b"url: https://pkg.example.com/repo?ToKeN=HOST_PASS_SECRET\n"
    with tarfile.open(tgz, "w:gz") as tar:
        member = tarfile.TarInfo("pfb_smoke_diag/pkg/pkg_vv.txt")
        member.size = len(secret)
        tar.addfile(member, io.BytesIO(secret))
        absolute_link = tarfile.TarInfo("pfb_smoke_diag/pkg/repos/pfSense.conf")
        absolute_link.type = tarfile.SYMTYPE
        absolute_link.linkname = str(outside)
        tar.addfile(absolute_link)

    helpers.redact_pkg_tarball(str(tgz))

    with tarfile.open(tgz, "r:gz") as tar:
        assert "pfb_smoke_diag/pkg/repos/pfSense.conf" not in tar.getnames()
        data = tar.extractfile("pfb_smoke_diag/pkg/pkg_vv.txt")
        assert data is not None
        out = data.read().decode("utf-8")
    assert "HOST_PASS_SECRET" not in out
    assert "ToKeN=REDACTED" in out
    assert outside.read_text(encoding="utf-8") == outside_text


def test_redact_pkg_tarball_drops_relative_link_outside_destination(tmp_path: Path) -> None:
    """A relative external link is omitted without aborting the host pass."""
    tgz = tmp_path / "pfb_smoke_diag.tgz"
    with tarfile.open(tgz, "w:gz") as archive:
        _add_text_member(
            archive,
            "pfb_smoke_diag/pkg/repos.conf",
            "url: https://pkg.example/repo?TOKEN=RELATIVE_LINK_SECRET\n",
        )
        link = tarfile.TarInfo("pfb_smoke_diag/pkg/external.conf")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../../outside.conf"
        archive.addfile(link)

    helpers.redact_pkg_tarball(str(tgz))

    with tarfile.open(tgz, "r:gz") as archive:
        assert "pfb_smoke_diag/pkg/external.conf" not in archive.getnames()
        data = archive.extractfile("pfb_smoke_diag/pkg/repos.conf")
        assert data is not None
        redacted = data.read().decode("utf-8")
    assert "RELATIVE_LINK_SECRET" not in redacted
    assert "TOKEN=REDACTED" in redacted


def test_redact_pkg_tarball_rejects_traversal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A traversal member remains fatal and cannot write outside extraction."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    tgz = tmp_path / "pfb_smoke_diag.tgz"
    escaped = tmp_path / "escaped.txt"
    payload = b"must not escape"
    with tarfile.open(tgz, "w:gz") as tar:
        member = tarfile.TarInfo("../escaped.txt")
        member.size = len(payload)
        tar.addfile(member, io.BytesIO(payload))

    with pytest.raises(tarfile.OutsideDestinationError):
        helpers.redact_pkg_tarball(str(tgz))

    assert not escaped.exists()


@pytest.mark.parametrize(
    ("archive_kind", "expected_error"),
    [
        pytest.param("invalid", "ReadError", id="invalid-tar"),
        pytest.param("missing-pkg", "RuntimeError", id="missing-pkg"),
    ],
)
def test_collect_host_diagnostics_reports_host_redaction_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    archive_kind: str,
    expected_error: str,
) -> None:
    """An invalid or incomplete archive cannot be reported as fully redacted."""
    dest = tmp_path / "diag"

    def fake_scp(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        tgz = Path(argv[-1])
        if archive_kind == "invalid":
            tgz.write_bytes(b"not a tar archive")
        else:
            with tarfile.open(tgz, "w:gz") as archive:
                _add_text_member(archive, "pfb_smoke_diag/unrelated.txt", "no package tree")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(helpers.subprocess, "run", fake_scp)
    vm = SimpleNamespace(
        ssh=lambda *_args, **_kwargs: None,
        ssh_key_path="unused",
        ssh_port=22,
        ssh_target="root@unused",
        log_path=None,
    )

    helpers.collect_host_diagnostics(cast(helpers.SmokeVM, vm), str(dest))

    output = capsys.readouterr().out
    success_prefix = "[smoke] collected and redacted full guest diagnostics ->"
    failure_prefix = "[smoke] host-side diagnostics redaction failed;"
    terminal_prefixes = (
        success_prefix,
        failure_prefix,
        "[smoke] guest-diagnostics scp failed",
        "[smoke] collect_host_diagnostics failed",
    )
    terminal_lines = [line for line in output.splitlines() if line.startswith(terminal_prefixes)]
    assert success_prefix not in output
    assert len(terminal_lines) == 1
    assert terminal_lines[0].startswith(failure_prefix)
    assert "archive has guest-side redaction only" in terminal_lines[0]
    assert expected_error in terminal_lines[0]
    assert (dest / "pfb_smoke_diag.tgz").exists()


def test_collect_host_diagnostics_reports_one_success_after_real_redaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A valid archive emits one success terminal only after its secret is scrubbed."""
    dest = tmp_path / "diag"

    def fake_scp(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        tgz = Path(argv[-1])
        with tarfile.open(tgz, "w:gz") as archive:
            _add_text_member(
                archive,
                "pfb_smoke_diag/pkg/repos.conf",
                "url: https://pkg.example/repo?ToKeN=SUCCESS_SECRET\n",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(helpers.subprocess, "run", fake_scp)
    vm = SimpleNamespace(
        ssh=lambda *_args, **_kwargs: None,
        ssh_key_path="unused",
        ssh_port=22,
        ssh_target="root@unused",
        log_path=None,
    )

    helpers.collect_host_diagnostics(cast(helpers.SmokeVM, vm), str(dest))

    output = capsys.readouterr().out
    success_prefix = "[smoke] collected and redacted full guest diagnostics ->"
    terminal_prefixes = (
        success_prefix,
        "[smoke] host-side diagnostics redaction failed;",
        "[smoke] guest-diagnostics scp failed",
        "[smoke] collect_host_diagnostics failed",
    )
    terminal_lines = [line for line in output.splitlines() if line.startswith(terminal_prefixes)]
    assert terminal_lines == [f"{success_prefix} {dest / 'pfb_smoke_diag.tgz'}"]
    with tarfile.open(dest / "pfb_smoke_diag.tgz", "r:gz") as archive:
        data = archive.extractfile("pfb_smoke_diag/pkg/repos.conf")
        assert data is not None
        redacted = data.read().decode("utf-8")
    assert "SUCCESS_SECRET" not in redacted
    assert "ToKeN=REDACTED" in redacted


def test_redact_pkg_tarball_missing_archive_is_failure(tmp_path: Path) -> None:
    """A missing pulled archive cannot be reported as a completed host pass."""
    with pytest.raises(FileNotFoundError):
        helpers.redact_pkg_tarball(str(tmp_path / "missing.tgz"))


def test_redact_pkg_tarball_read_failure_is_terminal_after_all_pkg_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every intended pkg file is attempted, then any read failure rejects the pass."""
    tgz = tmp_path / "pfb_smoke_diag.tgz"
    with tarfile.open(tgz, "w:gz") as archive:
        _add_text_member(archive, "pfb_smoke_diag/pkg/a-fail.conf", "unreadable")
        _add_text_member(
            archive,
            "pfb_smoke_diag/pkg/z-ok.conf",
            "url: https://pkg.example/repo?TOKEN=SECOND_FILE_SECRET\n",
        )

    original_read_text = Path.read_text
    attempted: list[str] = []

    def injected_read_text(path: Path, encoding: str | None = None, errors: str | None = None) -> str:
        attempted.append(path.name)
        if path.name == "a-fail.conf":
            raise OSError("injected regular-file read failure")
        return original_read_text(path, encoding=encoding, errors=errors)

    monkeypatch.setattr(Path, "read_text", injected_read_text)
    with pytest.raises(RuntimeError, match="a-fail.conf"):
        helpers.redact_pkg_tarball(str(tgz))

    assert set(attempted) == {"a-fail.conf", "z-ok.conf"}
    with tarfile.open(tgz, "r:gz") as archive:
        data = archive.extractfile("pfb_smoke_diag/pkg/z-ok.conf")
        assert data is not None
        assert "SECOND_FILE_SECRET" in data.read().decode("utf-8")


def test_redact_pkg_tarball_preserves_preexisting_fixed_sidecar(tmp_path: Path) -> None:
    """The old predictable .redact path is unrelated data, never scratch space."""
    tgz = tmp_path / "pfb_smoke_diag.tgz"
    with tarfile.open(tgz, "w:gz") as archive:
        _add_text_member(archive, "pfb_smoke_diag/pkg/repos.conf", "clean\n")
    fixed_sidecar = Path(f"{tgz}.redact")
    fixed_sidecar.write_bytes(b"preexisting unrelated artifact")

    helpers.redact_pkg_tarball(str(tgz))

    assert fixed_sidecar.read_bytes() == b"preexisting unrelated artifact"


@pytest.mark.parametrize("failure_phase", ["add", "close", "replace"])
def test_redact_pkg_tarball_removes_partial_temp_on_repack_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_phase: str
) -> None:
    """Every repack failure removes its unique temporary archive."""
    tgz = tmp_path / "pfb_smoke_diag.tgz"
    with tarfile.open(tgz, "w:gz") as archive:
        _add_text_member(archive, "pfb_smoke_diag/pkg/repos.conf", "clean\n")
    before = {path.name for path in tmp_path.iterdir()}

    if failure_phase == "add":

        def fail_add(*_args: object, **_kwargs: object) -> None:
            raise OSError("injected tar.add failure")

        monkeypatch.setattr(tarfile.TarFile, "add", fail_add)
    elif failure_phase == "close":
        original_close = tarfile.TarFile.close
        close_failed = False

        def fail_close(archive: tarfile.TarFile) -> None:
            nonlocal close_failed
            fail_now = archive.mode == "w" and not close_failed
            original_close(archive)
            if fail_now:
                close_failed = True
                raise OSError("injected tar.close failure")

        monkeypatch.setattr(tarfile.TarFile, "close", fail_close)
    else:

        def fail_replace(*_args: object, **_kwargs: object) -> None:
            raise OSError("injected os.replace failure")

        monkeypatch.setattr(helpers.os, "replace", fail_replace)

    with pytest.raises(OSError, match=f"injected .*{failure_phase} failure"):
        helpers.redact_pkg_tarball(str(tgz))

    assert {path.name for path in tmp_path.iterdir()} == before


def test_redact_pkg_tarball_removes_temp_when_fd_close_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A close failure after mkstemp cannot strand its partial archive."""
    tgz = tmp_path / "pfb_smoke_diag.tgz"
    with tarfile.open(tgz, "w:gz") as archive:
        _add_text_member(archive, "pfb_smoke_diag/pkg/repos.conf", "clean\n")
    before = {path.name for path in tmp_path.iterdir()}
    original_close = helpers.os.close

    def fail_close(fd: int) -> None:
        original_close(fd)
        raise OSError("injected os.close failure")

    monkeypatch.setattr(helpers.os, "close", fail_close)
    with pytest.raises(OSError, match="injected os.close failure"):
        helpers.redact_pkg_tarball(str(tgz))

    assert {path.name for path in tmp_path.iterdir()} == before


def test_redact_pkg_tarball_closes_fd_when_initial_close_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A pre-close failure still closes the mkstemp descriptor during cleanup."""
    tgz = tmp_path / "pfb_smoke_diag.tgz"
    with tarfile.open(tgz, "w:gz") as archive:
        _add_text_member(archive, "pfb_smoke_diag/pkg/repos.conf", "clean\n")
    before = {path.name for path in tmp_path.iterdir()}
    original_close = helpers.os.close
    close_calls: list[int] = []

    def fail_first_close(fd: int) -> None:
        close_calls.append(fd)
        if len(close_calls) == 1:
            raise OSError("injected pre-close failure")
        original_close(fd)

    monkeypatch.setattr(helpers.os, "close", fail_first_close)
    with pytest.raises(OSError, match="injected pre-close failure"):
        helpers.redact_pkg_tarball(str(tgz))

    assert {path.name for path in tmp_path.iterdir()} == before
    assert close_calls[:2] == [close_calls[0], close_calls[0]]
    try:
        with pytest.raises(OSError) as closed:
            helpers.os.fstat(close_calls[0])
        assert closed.value.errno == errno.EBADF
    finally:
        try:
            original_close(close_calls[0])
        except OSError:
            pass


def test_redact_pkg_tarball_drops_internal_link_aliases_without_rewriting_non_pkg(
    tmp_path: Path,
) -> None:
    """Pkg symlink and hardlink aliases cannot rewrite a non-pkg archive member."""
    tgz = tmp_path / "pfb_smoke_diag.tgz"
    non_pkg_secret = "url: https://outside.example/repo?TOKEN=NON_PKG_SECRET\n"
    pkg_secret = "url: https://pkg.example/repo?TOKEN=PKG_SECRET\n"
    with tarfile.open(tgz, "w:gz") as archive:
        _add_text_member(archive, "pfb_smoke_diag/outside.conf", non_pkg_secret)
        _add_text_member(archive, "pfb_smoke_diag/pkg/repos.conf", pkg_secret)
        symlink = tarfile.TarInfo("pfb_smoke_diag/pkg/symlink.conf")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../outside.conf"
        archive.addfile(symlink)
        hardlink = tarfile.TarInfo("pfb_smoke_diag/pkg/hardlink.conf")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "pfb_smoke_diag/outside.conf"
        archive.addfile(hardlink)

    helpers.redact_pkg_tarball(str(tgz))

    with tarfile.open(tgz, "r:gz") as archive:
        names = archive.getnames()
        outside = archive.extractfile("pfb_smoke_diag/outside.conf")
        pkg = archive.extractfile("pfb_smoke_diag/pkg/repos.conf")
        assert outside is not None
        assert pkg is not None
        outside_text = outside.read().decode("utf-8")
        pkg_text = pkg.read().decode("utf-8")
    assert "pfb_smoke_diag/pkg/symlink.conf" not in names
    assert "pfb_smoke_diag/pkg/hardlink.conf" not in names
    assert outside_text == non_pkg_secret
    assert "PKG_SECRET" not in pkg_text
    assert "TOKEN=REDACTED" in pkg_text
