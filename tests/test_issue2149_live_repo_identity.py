from __future__ import annotations

import subprocess
from pathlib import Path
from typing import cast

import pytest
from pytest import MonkeyPatch

from tests.smoke import test_nightly_install as nightly
from tests.smoke import test_repo_install as repo
from tests.smoke.conftest import SmokeVM


def test_smoke_single_exposes_nightly_provenance_inputs() -> None:
    """Actions callers can supply the provenance required by the live Nightly test."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/smoke-single.yml").read_text()
    for name in ("smoke_nightly_expected_source_sha", "smoke_nightly_expected_version"):
        assert workflow.count(f"      {name}:") == 2
    assert "SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA: ${{ inputs.smoke_nightly_expected_source_sha }}" in workflow
    assert "SMOKE_NIGHTLY_EXPECTED_VERSION: ${{ inputs.smoke_nightly_expected_version }}" in workflow


@pytest.mark.parametrize(
    ("actual_version", "record", "message"),
    [
        ("wrong", {"source_sha": "a" * 40, "channel": "edge"}, "installed 'wrong'"),
        ("4.0.0.a21", {"source_sha": "b" * 40, "channel": "edge"}, "installed source"),
        ("4.0.0.a21", {"source_sha": "a" * 40, "channel": "stable"}, "installed channel"),
    ],
)
def test_live_package_rejects_wrong_provenance(
    monkeypatch: MonkeyPatch,
    actual_version: str,
    record: dict[str, object],
    message: str,
) -> None:
    """Each caller-provided identity field rejects a mismatched installed package."""
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args: actual_version)
    monkeypatch.setattr(repo, "pkg_build_record", lambda *_args: record)

    with pytest.raises(AssertionError, match=message):
        repo.assert_live_package(cast(SmokeVM, object()), repo.CANONICAL_PKG_NAME, "4.0.0.a21", "a" * 40, "edge")


@pytest.mark.parametrize("missing", ["SMOKE_REPO_EXPECTED_SOURCE_SHA", "SMOKE_REPO_EXPECTED_VERSION"])
def test_live_pages_requires_expected_identity(monkeypatch: MonkeyPatch, missing: str) -> None:
    """A live semantic URL without both expected identity fields fails closed."""
    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/edge")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_VERSION", "4.0.0.a21")
    monkeypatch.delenv(missing)

    with pytest.raises(AssertionError, match=missing):
        repo.test_install_from_live_pages_url(cast(SmokeVM, object()))


@pytest.mark.parametrize("missing", ["SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA", "SMOKE_NIGHTLY_EXPECTED_VERSION"])
def test_live_nightly_requires_expected_identity(monkeypatch: MonkeyPatch, missing: str) -> None:
    """A live Nightly URL without both expected identity fields fails closed."""
    monkeypatch.setattr(nightly, "_live_nightly_url", lambda: "https://example.test/pkg/nightly")
    monkeypatch.setenv("SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA", "b" * 40)
    monkeypatch.setenv("SMOKE_NIGHTLY_EXPECTED_VERSION", "20260810_2")
    monkeypatch.delenv(missing)

    with pytest.raises(AssertionError, match=missing):
        nightly.test_install_from_live_nightly_url(cast(SmokeVM, object()))


def test_live_pages_install_targets_canonical_package(monkeypatch: MonkeyPatch) -> None:
    """The deployed channel catalog is queried and installed by its canonical package identity."""
    seen: dict[str, list[str] | str] = {"delete": []}
    ssh_calls: list[tuple[str, ...]] = []
    assertions: list[tuple[str, str, str, str]] = []
    expected_source = "a" * 40
    expected_version = "4.0.0.a21"

    class FakeVM:
        def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            ssh_calls.append(args)
            return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/edge")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_SOURCE_SHA", expected_source)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_VERSION", expected_version)
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(repo, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(repo, "restore_pages_hosts", lambda *_args: None)
    monkeypatch.setattr(repo, "repo_priority", lambda *_args: 0)
    monkeypatch.setattr(repo, "write_live_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_update", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_installed_version", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_repo_origin", lambda *_args, **_kwargs: repo.OURS_REPO_NAME)

    def fake_delete(_vm: object, *, pkg_name: str = repo.PKG_NAME, **_kwargs: object) -> None:
        deletes = seen["delete"]
        assert isinstance(deletes, list)
        deletes.append(pkg_name)

    def fake_query(_vm: object, pkg_name: str, **_kwargs: object) -> str | None:
        seen["query"] = pkg_name
        return None

    def fake_install(
        _vm: object, *, pkg_name: str = repo.PKG_NAME, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        seen["install"] = pkg_name
        return subprocess.CompletedProcess([], 0, "", "")

    def fake_origin(_vm: object, pkg_name: str, **_kwargs: object) -> str:
        seen["origin"] = pkg_name
        return "pfblockerng-edge"

    def fake_assert(_vm: object, pkg_name: str, version: str, source_sha: str, channel: str) -> str:
        assertions.append((pkg_name, version, source_sha, channel))
        return version

    monkeypatch.setattr(repo, "pkg_delete", fake_delete)
    monkeypatch.setattr(repo, "pkg_installed_version_of", fake_query)
    monkeypatch.setattr(repo, "pkg_install_from_repo", fake_install)
    monkeypatch.setattr(repo, "pkg_repo_origin_of", fake_origin)
    monkeypatch.setattr(repo, "assert_live_package", fake_assert)

    repo.test_install_from_live_pages_url(cast(SmokeVM, FakeVM()))

    assert seen == {
        "delete": [repo.CANONICAL_PKG_NAME, repo.CANONICAL_PKG_NAME],
        "query": repo.CANONICAL_PKG_NAME,
        "install": repo.CANONICAL_PKG_NAME,
        "origin": repo.CANONICAL_PKG_NAME,
    }
    assert assertions == [(repo.CANONICAL_PKG_NAME, expected_version, expected_source, "edge")]
    assert ("/bin/rm", "-f", repo.REPO_CONF) in ssh_calls


def test_live_nightly_install_targets_canonical_package(monkeypatch: MonkeyPatch) -> None:
    """The deployed Nightly catalog is installed by the shared canonical package identity."""
    seen: dict[str, list[str] | str] = {"delete": []}
    ssh_calls: list[tuple[str, ...]] = []
    assertions: list[tuple[str, str, str, str]] = []
    expected_source = "b" * 40
    expected_version = "20260810_2"

    class FakeVM:
        def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            ssh_calls.append(args)
            return subprocess.CompletedProcess([], 0, "", "")

        def ssh_argv(self, *_args: str) -> list[str]:
            return ["true"]

    monkeypatch.setattr(nightly, "_live_nightly_url", lambda: "https://example.test/pkg/nightly")
    monkeypatch.setenv("SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA", expected_source)
    monkeypatch.setenv("SMOKE_NIGHTLY_EXPECTED_VERSION", expected_version)
    monkeypatch.setattr(nightly, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(nightly, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(nightly, "_ensure_egress_open", lambda: None)
    monkeypatch.setattr(nightly, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(nightly, "restore_pages_hosts", lambda *_args: None)
    monkeypatch.setattr(nightly, "repo_priority", lambda *_args: 0)
    monkeypatch.setattr(
        nightly.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setattr(nightly, "pkg_update", lambda *_args: None)
    monkeypatch.setattr(nightly, "pkg_present", lambda *_args: False)

    def fake_delete(_vm: object, name: str, **_kwargs: object) -> None:
        deletes = seen["delete"]
        assert isinstance(deletes, list)
        deletes.append(name)

    def fake_install(_vm: object, name: str, **_kwargs: object) -> str:
        seen["install"] = name
        return "installed"

    def fake_query(_vm: object, _fmt: str, name: str, **_kwargs: object) -> str:
        seen["query"] = name
        return nightly.NIGHTLY_REPO

    def fake_assert(_vm: object, pkg_name: str, version: str, source_sha: str, channel: str) -> str:
        assertions.append((pkg_name, version, source_sha, channel))
        return version

    monkeypatch.setattr(nightly, "pkg_delete", fake_delete)
    monkeypatch.setattr(nightly, "pkg_install", fake_install)
    monkeypatch.setattr(nightly, "pkg_q", fake_query)
    monkeypatch.setattr(nightly, "assert_live_package", fake_assert)

    nightly.test_install_from_live_nightly_url(cast(SmokeVM, FakeVM()))

    assert seen == {
        "delete": [repo.CANONICAL_PKG_NAME, repo.CANONICAL_PKG_NAME],
        "install": repo.CANONICAL_PKG_NAME,
        "query": repo.CANONICAL_PKG_NAME,
    }
    assert assertions == [(repo.CANONICAL_PKG_NAME, expected_version, expected_source, "nightly")]
    assert ("/bin/rm", "-f", nightly.NIGHTLY_LIVE_CONF) in ssh_calls


def test_live_nightly_downgrade_rejects_failed_ordinary_upgrade(monkeypatch: MonkeyPatch) -> None:
    """A failed ordinary upgrade cannot be accepted as proof that Nightly stayed installed."""

    class FakeVM:
        def ssh(self, *_args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "", "")

    def fail_if_migration_reached(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("migration reached")

    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/stable")
    monkeypatch.setenv(repo.LIVE_NIGHTLY_URL_ENV, "https://example.test/pkg/nightly")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_SOURCE_SHA", "c" * 40)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_VERSION", "89.0.2")
    monkeypatch.setenv("SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA", "b" * 40)
    monkeypatch.setenv("SMOKE_NIGHTLY_EXPECTED_VERSION", "20260810_2")
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(repo, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(repo, "restore_pages_hosts", lambda *_args: None)
    monkeypatch.setattr(repo, "reset_channel_subscription", lambda *_args: None)
    monkeypatch.setattr(repo, "run_add_repo_sh", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_install_qualified", lambda *_args: None)
    monkeypatch.setattr(repo, "assert_live_package", lambda _vm, _name, version, *_args: version)
    monkeypatch.setattr(repo, "pkg_repo_origin_of", lambda *_args: repo.channel_repo_name("nightly"))
    monkeypatch.setattr(
        repo,
        "_pkg_retry",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 17, "", "upgrade failed"),
    )
    monkeypatch.setattr(
        repo,
        "run_migrate_channel_sh",
        fail_if_migration_reached,
    )

    with pytest.raises(AssertionError, match="ordinary pkg upgrade failed"):
        repo.test_live_nightly_downgrade_requires_selected_semantic_repo(cast(SmokeVM, FakeVM()))


def test_live_nightly_downgrade_checks_both_provenances(monkeypatch: MonkeyPatch) -> None:
    """The successful downgrade verifies both the Nightly and semantic identities."""
    assertions: list[tuple[str, str, str]] = []

    class FakeVM:
        def ssh(self, *_args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "", "")

    def fake_assert(_vm: object, _name: str, version: str, source: str, channel: str) -> str:
        assertions.append((version, source, channel))
        return version

    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/stable")
    monkeypatch.setenv(repo.LIVE_NIGHTLY_URL_ENV, "https://example.test/pkg/nightly")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_SOURCE_SHA", "c" * 40)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_VERSION", "89.0.2")
    monkeypatch.setenv("SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA", "b" * 40)
    monkeypatch.setenv("SMOKE_NIGHTLY_EXPECTED_VERSION", "20260810_2")
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(repo, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(repo, "restore_pages_hosts", lambda *_args: None)
    monkeypatch.setattr(repo, "reset_channel_subscription", lambda *_args: None)
    monkeypatch.setattr(repo, "run_add_repo_sh", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_install_qualified", lambda *_args: None)
    monkeypatch.setattr(repo, "assert_live_package", fake_assert)
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args: "20260810_2")
    origins = iter([repo.channel_repo_name("nightly"), repo.channel_repo_name("stable")])
    monkeypatch.setattr(repo, "pkg_repo_origin_of", lambda *_args: next(origins))
    monkeypatch.setattr(
        repo,
        "_pkg_retry",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setattr(
        repo,
        "run_migrate_channel_sh",
        lambda *_args: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setattr(
        repo,
        "_ssh_check",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<\n", ""),
    )
    monkeypatch.setattr(repo, "installed_pfblockerng_names", lambda *_args: [repo.CANONICAL_PKG_NAME])

    repo.test_live_nightly_downgrade_requires_selected_semantic_repo(cast(SmokeVM, FakeVM()))

    assert assertions == [
        ("20260810_2", "b" * 40, "nightly"),
        ("89.0.2", "c" * 40, "stable"),
    ]
