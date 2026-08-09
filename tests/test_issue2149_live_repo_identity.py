from __future__ import annotations

import subprocess
from typing import cast

import pytest
from pytest import MonkeyPatch

from tests.smoke import test_nightly_install as nightly
from tests.smoke import test_repo_install as repo
from tests.smoke.conftest import SmokeVM


def test_live_pages_install_targets_canonical_package(monkeypatch: MonkeyPatch) -> None:
    """The deployed channel catalog is queried and installed by its canonical package identity."""
    seen: dict[str, list[str] | str] = {"delete": []}
    ssh_calls: list[tuple[str, ...]] = []
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

    versions = iter([None, expected_version])

    def fake_query(_vm: object, pkg_name: str, **_kwargs: object) -> str | None:
        seen["query"] = pkg_name
        version = next(versions)
        if version is not None:
            seen["version"] = version
        return version

    def fake_install(
        _vm: object, *, pkg_name: str = repo.PKG_NAME, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        seen["install"] = pkg_name
        return subprocess.CompletedProcess([], 0, "", "")

    def fake_origin(_vm: object, pkg_name: str, **_kwargs: object) -> str:
        seen["origin"] = pkg_name
        return "pfblockerng-edge"

    def fake_record(_vm: object, pkg_name: str, **_kwargs: object) -> dict[str, object]:
        seen["record"] = pkg_name
        return {"channel": "edge", "source_sha": expected_source}

    monkeypatch.setattr(repo, "pkg_delete", fake_delete)
    monkeypatch.setattr(repo, "pkg_installed_version_of", fake_query)
    monkeypatch.setattr(repo, "pkg_install_from_repo", fake_install)
    monkeypatch.setattr(repo, "pkg_repo_origin_of", fake_origin)
    monkeypatch.setattr(repo, "pkg_build_record", fake_record, raising=False)

    repo.test_install_from_live_pages_url(cast(SmokeVM, FakeVM()))

    assert seen == {
        "delete": [repo.CANONICAL_PKG_NAME, repo.CANONICAL_PKG_NAME],
        "query": repo.CANONICAL_PKG_NAME,
        "install": repo.CANONICAL_PKG_NAME,
        "origin": repo.CANONICAL_PKG_NAME,
        "record": repo.CANONICAL_PKG_NAME,
        "version": expected_version,
    }
    assert ("/bin/rm", "-f", repo.REPO_CONF) in ssh_calls


def test_live_nightly_install_targets_canonical_package(monkeypatch: MonkeyPatch) -> None:
    """The deployed Nightly catalog is installed by the shared canonical package identity."""
    seen: dict[str, list[str] | str] = {"delete": []}
    expected_source = "b" * 40
    expected_version = "20260810_2"

    class FakeVM:
        def ssh(self, *_args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
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
        if _fmt == "%v":
            seen["version"] = expected_version
            return expected_version
        return nightly.NIGHTLY_REPO

    def fake_record(_vm: object, pkg_name: str, **_kwargs: object) -> dict[str, object]:
        seen["record"] = pkg_name
        return {"channel": "nightly", "source_sha": expected_source}

    monkeypatch.setattr(nightly, "pkg_delete", fake_delete)
    monkeypatch.setattr(nightly, "pkg_install", fake_install)
    monkeypatch.setattr(nightly, "pkg_q", fake_query)
    monkeypatch.setattr(nightly, "pkg_build_record", fake_record, raising=False)

    nightly.test_install_from_live_nightly_url(cast(SmokeVM, FakeVM()))

    assert seen == {
        "delete": [repo.CANONICAL_PKG_NAME, repo.CANONICAL_PKG_NAME],
        "install": repo.CANONICAL_PKG_NAME,
        "query": repo.CANONICAL_PKG_NAME,
        "record": repo.CANONICAL_PKG_NAME,
        "version": expected_version,
    }


def test_live_nightly_downgrade_rejects_failed_ordinary_upgrade(monkeypatch: MonkeyPatch) -> None:
    """A failed ordinary upgrade cannot be accepted as proof that Nightly stayed installed."""

    class FakeVM:
        def ssh(self, *_args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "", "")

    versions = iter(["20260810_2", "20260810_2"])

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
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args: next(versions))
    monkeypatch.setattr(repo, "pkg_repo_origin_of", lambda *_args: repo.channel_repo_name("nightly"))
    monkeypatch.setattr(
        repo,
        "pkg_build_record",
        lambda *_args: {"channel": "nightly", "source_sha": "b" * 40},
        raising=False,
    )
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
