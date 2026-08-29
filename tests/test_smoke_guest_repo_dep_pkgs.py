from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.smoke.test_repo_install import build_guest_repo

_REPO_DIR = "/var/tmp/pfb-guest-repo"


class _FakeVM:
    """Records the guest commands ``build_guest_repo`` issues."""

    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        self.commands.append(remote)
        return subprocess.CompletedProcess((), 0, "", "")


@pytest.fixture
def staged(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Path, str]]:
    """Capture every ``local -> remote`` copy instead of running scp."""
    calls: list[tuple[Path, str]] = []

    def _fake_scp(vm: object, local: Path, remote: str, **_kw: object) -> None:
        calls.append((local, remote))

    monkeypatch.setattr("tests.smoke.test_repo_install._scp_to_guest", _fake_scp)
    return calls


def _names(staged: list[tuple[Path, str]]) -> list[str]:
    return [Path(remote).name for _local, remote in staged]


def test_locally_built_run_depends_are_published_into_the_guest_catalog(
    monkeypatch: pytest.MonkeyPatch, staged: list[tuple[Path, str]], tmp_path: Path
) -> None:
    """A RUN_DEPENDS built on the box must reach the catalog ``pkg install`` reads.

    Scenario: issue #1914 — the guest ``file://`` repo served only the package under
    test, so a dependency that exists in no Netgate repository (it is built locally
    by ``smoke-on-box.sh``) was unresolvable and every ``-m repo`` install failed with
    ``has a missing dependency: py311-charset-normalizer``. ``SMOKE_DEP_PKGS`` already
    carries those paths — ``scripts/install-pkg.sh`` consumes it for the direct
    ``pkg add`` path — so the catalog builder must honour it too.
    """
    dep = tmp_path / "py311-charset-normalizer-3.4.4.pkg"
    dep.write_bytes(b"dep")
    pkg = tmp_path / "pfSense-pkg-pfBlockerNG-devel-4.0.0.pkg"
    pkg.write_bytes(b"pkg")
    monkeypatch.setenv("SMOKE_DEP_PKGS", str(dep))
    vm = _FakeVM()

    build_guest_repo(vm, _REPO_DIR, [pkg])  # type: ignore[arg-type]

    assert _names(staged) == [pkg.name, dep.name], (
        f"catalog staged {_names(staged)!r}; the locally built RUN_DEPENDS must be published beside the package"
    )
    assert vm.commands[-1] == ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "repo", _REPO_DIR), (
        "the dep must be staged BEFORE `pkg repo` indexes the directory, or the catalog omits it"
    )


def test_catalog_is_unchanged_when_the_matrix_row_builds_no_dep_pkgs(
    monkeypatch: pytest.MonkeyPatch, staged: list[tuple[Path, str]], tmp_path: Path
) -> None:
    """An empty/unset ``SMOKE_DEP_PKGS`` (the common row) stages exactly what it did before."""
    pkg = tmp_path / "pfSense-pkg-pfBlockerNG-devel-4.0.0.pkg"
    pkg.write_bytes(b"pkg")
    monkeypatch.delenv("SMOKE_DEP_PKGS", raising=False)
    vm = _FakeVM()

    build_guest_repo(vm, _REPO_DIR, [pkg])  # type: ignore[arg-type]

    assert _names(staged) == [pkg.name]

    staged.clear()
    monkeypatch.setenv("SMOKE_DEP_PKGS", "   ")
    build_guest_repo(vm, _REPO_DIR, [pkg])  # type: ignore[arg-type]

    assert _names(staged) == [pkg.name], "whitespace-only SMOKE_DEP_PKGS must not stage a phantom entry"


def test_a_named_dep_pkg_that_does_not_exist_fails_loudly(
    monkeypatch: pytest.MonkeyPatch, staged: list[tuple[Path, str]], tmp_path: Path
) -> None:
    """A missing dep path must raise BEFORE any guest mutation, never yield a short catalog.

    Mirrors ``scripts/install-pkg.sh``'s own ``[ -f "$_dep" ] || exit 1`` guard: a
    catalog missing a dependency fails much later, at ``pkg install``, with an error
    that points at the package rather than at the staging bug.

    Validation runs before the ``rm -rf repo_dir`` that opens the function, so a bad
    ``SMOKE_DEP_PKGS`` leaves any existing guest catalog intact instead of destroying
    it on the way out — failing closed means changing nothing, not changing less.
    """
    pkg = tmp_path / "pfSense-pkg-pfBlockerNG-devel-4.0.0.pkg"
    pkg.write_bytes(b"pkg")
    monkeypatch.setenv("SMOKE_DEP_PKGS", str(tmp_path / "absent-dep.pkg"))
    vm = _FakeVM()

    with pytest.raises(RuntimeError, match="absent-dep.pkg"):
        build_guest_repo(vm, _REPO_DIR, [pkg])  # type: ignore[arg-type]

    assert vm.commands == [], (
        f"guest was mutated before validation failed: {vm.commands!r} — an existing catalog must survive"
    )
    assert staged == [], "nothing may be staged when the dep set does not validate"


def test_a_dep_already_passed_by_the_caller_is_not_staged_twice(
    monkeypatch: pytest.MonkeyPatch, staged: list[tuple[Path, str]], tmp_path: Path
) -> None:
    """Callers that already pass a dep explicitly must not get a duplicate copy."""
    dep = tmp_path / "py311-charset-normalizer-3.4.4.pkg"
    dep.write_bytes(b"dep")
    pkg = tmp_path / "pfSense-pkg-pfBlockerNG-devel-4.0.0.pkg"
    pkg.write_bytes(b"pkg")
    monkeypatch.setenv("SMOKE_DEP_PKGS", str(dep))
    vm = _FakeVM()

    build_guest_repo(vm, _REPO_DIR, [pkg, dep])  # type: ignore[arg-type]

    assert _names(staged) == [pkg.name, dep.name]
