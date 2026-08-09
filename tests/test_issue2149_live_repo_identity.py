from __future__ import annotations

import subprocess
from typing import cast

from pytest import MonkeyPatch

from tests.smoke import test_nightly_install as nightly
from tests.smoke import test_repo_install as repo
from tests.smoke.conftest import SmokeVM


def test_live_pages_install_targets_canonical_package(monkeypatch: MonkeyPatch) -> None:
    """The deployed channel catalog is queried and installed by its canonical package identity."""
    seen: dict[str, str] = {}

    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/edge")
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
        seen["delete"] = pkg_name

    def fake_query(_vm: object, pkg_name: str, **_kwargs: object) -> None:
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

    monkeypatch.setattr(repo, "pkg_delete", fake_delete)
    monkeypatch.setattr(repo, "pkg_installed_version_of", fake_query)
    monkeypatch.setattr(repo, "pkg_install_from_repo", fake_install)
    monkeypatch.setattr(repo, "pkg_repo_origin_of", fake_origin)

    repo.test_install_from_live_pages_url(object())

    assert seen == {
        "delete": repo.CANONICAL_PKG_NAME,
        "query": repo.CANONICAL_PKG_NAME,
        "install": repo.CANONICAL_PKG_NAME,
        "origin": repo.CANONICAL_PKG_NAME,
    }


def test_live_nightly_install_targets_canonical_package(monkeypatch: MonkeyPatch) -> None:
    """The deployed Nightly catalog is installed by the shared canonical package identity."""
    seen: dict[str, list[str] | str] = {"delete": []}

    class FakeVM:
        def ssh(self, *_args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "", "")

        def ssh_argv(self, *_args: str) -> list[str]:
            return ["true"]

    monkeypatch.setattr(nightly, "_live_nightly_url", lambda: "https://example.test/pkg/nightly")
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

    monkeypatch.setattr(nightly, "pkg_delete", fake_delete)
    monkeypatch.setattr(nightly, "pkg_install", fake_install)
    monkeypatch.setattr(nightly, "pkg_q", fake_query)

    nightly.test_install_from_live_nightly_url(cast(SmokeVM, FakeVM()))

    assert seen == {
        "delete": [repo.CANONICAL_PKG_NAME, repo.CANONICAL_PKG_NAME],
        "install": repo.CANONICAL_PKG_NAME,
        "query": repo.CANONICAL_PKG_NAME,
    }
