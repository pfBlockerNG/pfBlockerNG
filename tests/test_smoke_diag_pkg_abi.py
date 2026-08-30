"""Smoke diag bundle must capture pkg ABI/repos with URL redaction (issue #2754).

A #2242 drift (guest pkg ABI FreeBSD:16 vs expected 15) produced 155 setup
errors. The collector had no pkg config ABI, no pkg -vv, no repo confs, so
the forced-ABI path stayed unproven after the guest was torn down.

pkg -vv and repo confs can carry credentials. Redact userinfo and token-shaped
query parameters at capture time.
"""

from __future__ import annotations

import inspect
import io
import subprocess
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.smoke import helpers


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


def test_redact_pkg_tarball_rejects_traversal(tmp_path: Path, monkeypatch) -> None:
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


def test_collect_host_diagnostics_reports_host_redaction_failure(tmp_path: Path, monkeypatch, capsys) -> None:
    """A pulled archive is not reported as fully collected when host redaction fails."""
    dest = tmp_path / "diag"

    def fake_scp(argv, **_kwargs):
        Path(argv[-1]).write_bytes(b"not a tar archive")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(helpers.subprocess, "run", fake_scp)
    vm = SimpleNamespace(
        ssh=lambda *_args, **_kwargs: None,
        ssh_key_path="unused",
        ssh_port=22,
        ssh_target="root@unused",
        log_path=None,
    )

    helpers.collect_host_diagnostics(vm, str(dest))

    output = capsys.readouterr().out
    assert "[smoke] collected full guest diagnostics" not in output
    assert "[smoke] host-side diagnostics redaction failed" in output
    assert "archive has guest-side redaction only" in output
    assert "ReadError" in output
    assert (dest / "pfb_smoke_diag.tgz").exists()
