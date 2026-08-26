from __future__ import annotations

import subprocess
from pathlib import Path
from typing import cast

import pytest
from pytest import MonkeyPatch

from tests.smoke import test_nightly_install as nightly
from tests.smoke import test_repo_install as repo
from tests.smoke.conftest import SmokeVM


def _live_pages_cleanup_case(
    monkeypatch: MonkeyPatch,
    events: list[str],
    *,
    delete_failure_call: int | None = None,
    install_failure: Exception | None = None,
    same_identity: bool = False,
) -> tuple[SmokeVM, str]:
    canonical_name = repo.CANONICAL_PKG_NAME
    branch_name = canonical_name if same_identity else f"{canonical_name}-edge"
    delete_calls = 0

    class FakeVM:
        def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if args == ("/bin/rm", "-f", repo.REPO_CONF):
                events.append("remove-conf")
            return subprocess.CompletedProcess([], 0, "", "")

    def fake_delete(_vm: object, *, pkg_name: str, **_kwargs: object) -> None:
        nonlocal delete_calls
        delete_calls += 1
        events.append(f"delete:{pkg_name}")
        if delete_calls == delete_failure_call:
            raise RuntimeError(f"delete failed: {pkg_name}")

    def fake_absence(_vm: object, **_kwargs: object) -> list[str]:
        events.append("verify-absent")
        return []

    def fake_install(_vm: object, *, pkg_name: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        events.append(f"install:{pkg_name}")
        if install_failure is not None:
            raise install_failure
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(repo, "PKG_NAME", branch_name)
    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/edge")
    monkeypatch.setenv(repo.LIVE_EXPECTED_SOURCE_SHA_ENV, "a" * 40)
    monkeypatch.setenv(repo.LIVE_EXPECTED_VERSION_ENV, "4.0.0.a21")
    monkeypatch.setenv(repo.LIVE_EXPECTED_CHANNEL_ENV, "edge")
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(repo, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(repo, "restore_pages_hosts", lambda *_args: events.append("restore-hosts"))
    monkeypatch.setattr(repo, "repo_priority", lambda *_args: 0)
    monkeypatch.setattr(repo, "pkg_delete", fake_delete)
    monkeypatch.setattr(repo, "installed_pfblockerng_names", fake_absence)
    monkeypatch.setattr(repo, "write_live_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_update", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_install_from_repo", fake_install)
    monkeypatch.setattr(repo, "pkg_repo_origin_of", lambda *_args: repo.channel_repo_name("edge"))
    monkeypatch.setattr(repo, "assert_live_package", lambda _vm, _name, version, *_args: version)

    return cast(SmokeVM, FakeVM()), branch_name


def test_smoke_single_exposes_nightly_provenance_inputs() -> None:
    """Actions callers can supply the provenance required by the live Nightly test."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/smoke-single.yml").read_text()
    for name in ("smoke_nightly_expected_source_sha", "smoke_nightly_expected_version"):
        assert workflow.count(f"      {name}:") == 2
    assert "SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA: ${{ inputs.smoke_nightly_expected_source_sha }}" in workflow
    assert "SMOKE_NIGHTLY_EXPECTED_VERSION: ${{ inputs.smoke_nightly_expected_version }}" in workflow


def test_smoke_single_exposes_repo_live_inputs() -> None:
    """Actions callers can supply the generic-channel live-install inputs (issue #2389)
    release-published.yml's validate-live-pages-install job feeds."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/smoke-single.yml").read_text()
    for name in (
        "smoke_repo_live_url",
        "smoke_repo_expected_source_sha",
        "smoke_repo_expected_version",
        "smoke_repo_expected_channel",
    ):
        assert workflow.count(f"      {name}:") == 2
    assert "SMOKE_REPO_LIVE_URL: ${{ inputs.smoke_repo_live_url }}" in workflow
    assert "SMOKE_REPO_EXPECTED_SOURCE_SHA: ${{ inputs.smoke_repo_expected_source_sha }}" in workflow
    assert "SMOKE_REPO_EXPECTED_VERSION: ${{ inputs.smoke_repo_expected_version }}" in workflow
    assert "SMOKE_REPO_EXPECTED_CHANNEL: ${{ inputs.smoke_repo_expected_channel }}" in workflow


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


@pytest.mark.parametrize(
    "missing",
    ["SMOKE_REPO_EXPECTED_SOURCE_SHA", "SMOKE_REPO_EXPECTED_VERSION", "SMOKE_REPO_EXPECTED_CHANNEL"],
)
def test_live_pages_requires_expected_identity(monkeypatch: MonkeyPatch, missing: str) -> None:
    """A live semantic URL without every expected identity field fails closed."""
    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/edge")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_VERSION", "4.0.0.a21")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_CHANNEL", "edge")
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


def test_live_nightly_url_boolean_one_uses_default(monkeypatch: MonkeyPatch) -> None:
    """The boolean shorthand selects the deployed Nightly root, never the literal ``1``."""
    monkeypatch.setenv(nightly.LIVE_NIGHTLY_URL_ENV, "1")

    assert nightly._live_nightly_url() == nightly.DEFAULT_LIVE_NIGHTLY_URL


def test_live_nightly_downgrade_expands_boolean_live_urls(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """Both live boolean shorthands reach the downgrade as their current default URLs."""
    polled: list[str] = []

    def stop_after_urls(base_url: str, _catalog_path: str) -> None:
        polled.append(base_url)
        if len(polled) == 2:
            raise RuntimeError("stop after URL expansion")

    monkeypatch.setenv(repo.LIVE_BASE_URL_ENV, "true")
    monkeypatch.setenv(repo.LIVE_NIGHTLY_URL_ENV, "true")
    monkeypatch.setenv(repo.LIVE_EXPECTED_SOURCE_SHA_ENV, "c" * 40)
    monkeypatch.setenv(repo.LIVE_EXPECTED_VERSION_ENV, "4.0.0")
    monkeypatch.setenv(repo.NIGHTLY_EXPECTED_SOURCE_SHA_ENV, "b" * 40)
    monkeypatch.setenv(repo.NIGHTLY_EXPECTED_VERSION_ENV, "20260810_2")
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", stop_after_urls)

    with pytest.raises(RuntimeError, match="stop after URL expansion"):
        repo.test_live_nightly_downgrade_requires_selected_semantic_repo(cast(SmokeVM, object()), tmp_path)

    assert polled == [repo.DEFAULT_LIVE_BASE_URL, nightly.DEFAULT_LIVE_NIGHTLY_URL]


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

    suffixed_name = f"{repo.CANONICAL_PKG_NAME}-edge"
    monkeypatch.setattr(repo, "PKG_NAME", suffixed_name)
    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/edge")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_SOURCE_SHA", expected_source)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_VERSION", expected_version)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_CHANNEL", "edge")
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
        "delete": [
            suffixed_name,
            repo.CANONICAL_PKG_NAME,
            suffixed_name,
            repo.CANONICAL_PKG_NAME,
        ],
        "query": repo.CANONICAL_PKG_NAME,
        "install": repo.CANONICAL_PKG_NAME,
        "origin": repo.CANONICAL_PKG_NAME,
    }
    assert assertions == [(repo.CANONICAL_PKG_NAME, expected_version, expected_source, "edge")]
    assert ("/bin/rm", "-f", repo.REPO_CONF) in ssh_calls


def test_live_pages_cleanup_deletes_both_names_after_install_failure(monkeypatch: MonkeyPatch) -> None:
    """Setup and exceptional cleanup remove both the branch and canonical package identities."""
    deleted: list[str] = []
    ssh_calls: list[tuple[str, ...]] = []
    suffixed_name = f"{repo.CANONICAL_PKG_NAME}-edge"

    class FakeVM:
        def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            ssh_calls.append(args)
            return subprocess.CompletedProcess([], 0, "", "")

    def fail_install(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise RuntimeError("install failed")

    monkeypatch.setattr(repo, "PKG_NAME", suffixed_name)
    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/edge")
    monkeypatch.setenv(repo.LIVE_EXPECTED_SOURCE_SHA_ENV, "a" * 40)
    monkeypatch.setenv(repo.LIVE_EXPECTED_VERSION_ENV, "4.0.0.a21")
    monkeypatch.setenv(repo.LIVE_EXPECTED_CHANNEL_ENV, "edge")
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(repo, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(repo, "restore_pages_hosts", lambda *_args: None)
    monkeypatch.setattr(repo, "repo_priority", lambda *_args: 0)
    monkeypatch.setattr(repo, "pkg_delete", lambda _vm, *, pkg_name, **_kwargs: deleted.append(pkg_name))
    monkeypatch.setattr(repo, "write_live_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_update", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_install_from_repo", fail_install)

    with pytest.raises(RuntimeError, match="install failed"):
        repo.test_install_from_live_pages_url(cast(SmokeVM, FakeVM()))

    assert deleted == [
        suffixed_name,
        repo.CANONICAL_PKG_NAME,
        suffixed_name,
        repo.CANONICAL_PKG_NAME,
    ]
    assert ("/bin/rm", "-f", repo.REPO_CONF) in ssh_calls


@pytest.mark.parametrize("delete_failure_call", [3, 4])
def test_live_pages_teardown_attempts_every_cleanup_after_delete_exception(
    monkeypatch: MonkeyPatch,
    delete_failure_call: int,
) -> None:
    """Either teardown delete may fail without skipping the other cleanup operations."""
    events: list[str] = []
    vm, branch_name = _live_pages_cleanup_case(
        monkeypatch,
        events,
        delete_failure_call=delete_failure_call,
    )
    failed_name = branch_name if delete_failure_call == 3 else repo.CANONICAL_PKG_NAME

    with pytest.raises(RuntimeError) as exc_info:
        repo.test_install_from_live_pages_url(vm)

    assert str(exc_info.value) == (
        "live Pages teardown failed: package cleanup: RuntimeError: "
        f"live Pages package cleanup failed: delete {failed_name}: RuntimeError: delete failed: {failed_name}"
    )
    assert events == [
        f"delete:{branch_name}",
        f"delete:{repo.CANONICAL_PKG_NAME}",
        "verify-absent",
        f"install:{repo.CANONICAL_PKG_NAME}",
        f"delete:{branch_name}",
        f"delete:{repo.CANONICAL_PKG_NAME}",
        "verify-absent",
        "remove-conf",
        "restore-hosts",
    ]


def test_live_pages_body_exception_survives_cleanup_failure(monkeypatch: MonkeyPatch) -> None:
    """A cleanup failure is diagnostic context, never a replacement for the body failure."""
    events: list[str] = []
    vm, branch_name = _live_pages_cleanup_case(
        monkeypatch,
        events,
        delete_failure_call=3,
        install_failure=ValueError("install failed"),
    )

    with pytest.raises(ValueError) as exc_info:
        repo.test_install_from_live_pages_url(vm)
    assert str(exc_info.value) == "install failed"

    assert exc_info.value.__notes__ == [
        "live Pages cleanup also failed: live Pages teardown failed: package cleanup: RuntimeError: "
        f"live Pages package cleanup failed: delete {branch_name}: RuntimeError: delete failed: {branch_name}"
    ]
    assert events == [
        f"delete:{branch_name}",
        f"delete:{repo.CANONICAL_PKG_NAME}",
        "verify-absent",
        f"install:{repo.CANONICAL_PKG_NAME}",
        f"delete:{branch_name}",
        f"delete:{repo.CANONICAL_PKG_NAME}",
        "verify-absent",
        "remove-conf",
        "restore-hosts",
    ]


def test_live_pages_nonzero_deletes_cannot_hide_remaining_packages(monkeypatch: MonkeyPatch) -> None:
    """Ignored nonzero delete exits are rejected by the installed-identity oracle."""
    events: list[str] = []
    canonical_name = repo.CANONICAL_PKG_NAME
    branch_name = f"{canonical_name}-edge"

    class FakeVM:
        def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if args[:5] == ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "delete", "-y"):
                events.append(f"delete:{args[5]}")
                return subprocess.CompletedProcess([], 1, "", "delete failed")
            if args[:4] == ("pkg", "query", "-g", "%n"):
                events.append("verify-absent")
                return subprocess.CompletedProcess([], 0, f"{branch_name}\n{canonical_name}\n", "")
            if args == ("/bin/rm", "-f", repo.REPO_CONF):
                events.append("remove-conf")
            return subprocess.CompletedProcess([], 0, "", "")

    def fail_install(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise RuntimeError("install reached with live package identities still present")

    monkeypatch.setattr(repo, "PKG_NAME", branch_name)
    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/edge")
    monkeypatch.setenv(repo.LIVE_EXPECTED_SOURCE_SHA_ENV, "a" * 40)
    monkeypatch.setenv(repo.LIVE_EXPECTED_VERSION_ENV, "4.0.0.a21")
    monkeypatch.setenv(repo.LIVE_EXPECTED_CHANNEL_ENV, "edge")
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(repo, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(repo, "restore_pages_hosts", lambda *_args: events.append("restore-hosts"))
    monkeypatch.setattr(repo, "repo_priority", lambda *_args: 0)
    monkeypatch.setattr(repo, "write_live_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_update", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_install_from_repo", fail_install)

    with pytest.raises(RuntimeError) as exc_info:
        repo.test_install_from_live_pages_url(cast(SmokeVM, FakeVM()))

    expected_absence_error = (
        "live Pages package cleanup failed: verify package absence: AssertionError: "
        f"live Pages packages still installed: expected absent [{branch_name!r}, {canonical_name!r}]; "
        f"remaining [{branch_name!r}, {canonical_name!r}]; installed [{canonical_name!r}, {branch_name!r}]"
    )
    assert str(exc_info.value) == expected_absence_error
    assert exc_info.value.__notes__ == [
        "live Pages cleanup also failed: live Pages teardown failed: package cleanup: RuntimeError: "
        + expected_absence_error
    ]
    assert events == [
        f"delete:{branch_name}",
        f"delete:{canonical_name}",
        "verify-absent",
        f"delete:{branch_name}",
        f"delete:{canonical_name}",
        "verify-absent",
        "remove-conf",
        "restore-hosts",
    ]


def test_live_pages_identical_package_names_are_deleted_once_per_phase(monkeypatch: MonkeyPatch) -> None:
    """A canonical branch build deduplicates its identical cleanup identity."""
    events: list[str] = []
    vm, branch_name = _live_pages_cleanup_case(monkeypatch, events, same_identity=True)

    repo.test_install_from_live_pages_url(vm)

    assert branch_name == repo.CANONICAL_PKG_NAME
    assert events == [
        f"delete:{repo.CANONICAL_PKG_NAME}",
        "verify-absent",
        f"install:{repo.CANONICAL_PKG_NAME}",
        f"delete:{repo.CANONICAL_PKG_NAME}",
        "verify-absent",
        "remove-conf",
        "restore-hosts",
    ]


@pytest.mark.parametrize(
    ("dest", "primary", "version"),
    [
        ("edge", "testing", "4.0.1.a1"),
        ("testing", "stable", "4.0.0"),
        ("edge", "edge", "4.0.0.a1"),
    ],
)
def test_live_pages_record_channel_is_tag_primary(
    monkeypatch: MonkeyPatch,
    dest: str,
    primary: str,
    version: str,
) -> None:
    """A faster dest still carries the tag primary in pfb_build_record.channel."""
    assertions: list[tuple[str, str, str, str]] = []
    seen_origin: list[str] = []

    class FakeVM:
        def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(repo, "_live_base_url", lambda: f"https://example.test/pkg/{dest}")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_VERSION", version)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_CHANNEL", primary)
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(repo, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(repo, "restore_pages_hosts", lambda *_args: None)
    monkeypatch.setattr(repo, "repo_priority", lambda *_args: 0)
    monkeypatch.setattr(repo, "write_live_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_update", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_delete", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        repo,
        "pkg_install_from_repo",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )

    def fake_origin(_vm: object, _pkg_name: str, **_kwargs: object) -> str:
        origin = repo.channel_repo_name(dest)
        seen_origin.append(origin)
        return origin

    def fake_assert(_vm: object, pkg_name: str, ver: str, source_sha: str, channel: str) -> str:
        assertions.append((pkg_name, ver, source_sha, channel))
        return ver

    monkeypatch.setattr(repo, "pkg_repo_origin_of", fake_origin)
    monkeypatch.setattr(repo, "assert_live_package", fake_assert)

    repo.test_install_from_live_pages_url(cast(SmokeVM, FakeVM()))

    assert seen_origin == [repo.channel_repo_name(dest)]
    assert assertions == [(repo.CANONICAL_PKG_NAME, version, "a" * 40, primary)]


def test_live_pages_rejects_dest_faster_than_primary(monkeypatch: MonkeyPatch) -> None:
    """Containment: dest cannot be slower-or-equal... dest cannot be faster than primary."""

    class FakeVM:
        def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/stable")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_VERSION", "4.0.1.a1")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_CHANNEL", "edge")
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(repo, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(repo, "restore_pages_hosts", lambda *_args: None)
    monkeypatch.setattr(repo, "repo_priority", lambda *_args: 0)
    monkeypatch.setattr(repo, "write_live_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_update", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_delete", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        repo,
        "pkg_install_from_repo",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setattr(repo, "pkg_repo_origin_of", lambda *_a, **_k: repo.channel_repo_name("stable"))
    monkeypatch.setattr(repo, "assert_live_package", lambda *_a, **_k: "4.0.1.a1")

    with pytest.raises(AssertionError, match="slower than primary"):
        repo.test_install_from_live_pages_url(cast(SmokeVM, FakeVM()))


def test_live_pages_rejects_nightly_dest(monkeypatch: MonkeyPatch) -> None:
    """A tagged release never fans into Nightly; dest=nightly is not a live Pages pair."""

    class FakeVM:
        def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(repo, "_live_base_url", lambda: "https://example.test/pkg/nightly")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_VERSION", "4.0.0")
    monkeypatch.setenv("SMOKE_REPO_EXPECTED_CHANNEL", "stable")
    monkeypatch.setattr(repo, "_box_real_varver", lambda _vm: "ce-current")
    monkeypatch.setattr(repo, "poll_catalog_served", lambda *_args: None)
    monkeypatch.setattr(repo, "pin_pages_hosts", lambda *_args: "prior")
    monkeypatch.setattr(repo, "restore_pages_hosts", lambda *_args: None)
    monkeypatch.setattr(repo, "repo_priority", lambda *_args: 0)
    monkeypatch.setattr(repo, "write_live_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_update", lambda *_args: None)
    monkeypatch.setattr(repo, "pkg_delete", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        repo,
        "pkg_install_from_repo",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setattr(repo, "pkg_repo_origin_of", lambda *_a, **_k: repo.channel_repo_name("nightly"))
    monkeypatch.setattr(repo, "assert_live_package", lambda *_a, **_k: "4.0.0")

    with pytest.raises(AssertionError, match="cannot be nightly"):
        repo.test_install_from_live_pages_url(cast(SmokeVM, FakeVM()))


def test_live_package_accepts_primary_on_faster_dest(monkeypatch: MonkeyPatch) -> None:
    """assert_live_package compares record.channel to the tag primary, not the dest folder."""
    monkeypatch.setattr(repo, "pkg_installed_version_of", lambda *_args: "4.0.1.a1")
    monkeypatch.setattr(
        repo,
        "pkg_build_record",
        lambda *_args: {"source_sha": "a" * 40, "channel": "testing"},
    )
    assert (
        repo.assert_live_package(
            cast(SmokeVM, object()),
            repo.CANONICAL_PKG_NAME,
            "4.0.1.a1",
            "a" * 40,
            "testing",
        )
        == "4.0.1.a1"
    )


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


def test_live_nightly_downgrade_rejects_failed_ordinary_upgrade(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """A failed ordinary upgrade cannot be accepted as proof that Nightly stayed installed."""

    class FakeVM:
        def ssh(self, *_args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "", "")

    def fake_run_channel_installer(
        _vm: object, channel: str, *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        # The nightly install (step 1) must succeed to reach the ordinary-upgrade
        # check; the qualified migration (step 2, channel != "nightly") must NEVER
        # be reached once that check fails.
        if channel != "nightly":
            raise RuntimeError("migration reached")
        return subprocess.CompletedProcess([], 0, "", "")

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
    monkeypatch.setattr(repo, "run_channel_installer", fake_run_channel_installer)
    monkeypatch.setattr(repo, "write_live_repo_conf", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repo, "assert_live_package", lambda _vm, _name, version, *_args: version)
    monkeypatch.setattr(repo, "pkg_repo_origin_of", lambda *_args: repo.channel_repo_name("nightly"))
    monkeypatch.setattr(
        repo,
        "_pkg_retry",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 17, "", "upgrade failed"),
    )

    with pytest.raises(AssertionError, match="ordinary pkg upgrade failed"):
        repo.test_live_nightly_downgrade_requires_selected_semantic_repo(cast(SmokeVM, FakeVM()), tmp_path)


def test_live_nightly_downgrade_checks_both_provenances(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """The successful downgrade verifies both the Nightly and semantic identities."""
    assertions: list[tuple[str, str, str]] = []
    installer_calls: list[str] = []

    class FakeVM:
        def ssh(self, *_args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "", "")

    def fake_assert(_vm: object, _name: str, version: str, source: str, channel: str) -> str:
        assertions.append((version, source, channel))
        return version

    def fake_run_channel_installer(
        _vm: object, channel: str, *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        installer_calls.append(channel)
        return subprocess.CompletedProcess([], 0, "", "")

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
    monkeypatch.setattr(repo, "run_channel_installer", fake_run_channel_installer)
    monkeypatch.setattr(repo, "write_live_repo_conf", lambda *_args, **_kwargs: None)
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
        "_ssh_check",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<\n", ""),
    )
    monkeypatch.setattr(repo, "installed_pfblockerng_names", lambda *_args: [repo.CANONICAL_PKG_NAME])

    repo.test_live_nightly_downgrade_requires_selected_semantic_repo(cast(SmokeVM, FakeVM()), tmp_path)

    assert assertions == [
        ("20260810_2", "b" * 40, "nightly"),
        ("89.0.2", "c" * 40, "stable"),
    ]
    assert installer_calls == ["nightly", "stable"]
