from __future__ import annotations

import subprocess

from pytest import MonkeyPatch

from tests.smoke import test_repo_install as repo


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
