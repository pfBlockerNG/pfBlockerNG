from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/check_composer_vendor.py"


def package(
    name: str = "acme/pkg",
    version: str = "1.0.0",
    *,
    source: str | None = "source-ref",
    dist: str | None = "dist-ref",
) -> dict[str, Any]:
    result: dict[str, Any] = {"name": name, "version": version}
    if source is not None:
        result["source"] = {"reference": source}
    if dist is not None:
        result["dist"] = {"reference": dist}
    return result


def fixture(
    tmp_path: Path,
    locked: list[dict[str, Any]],
    installed: list[dict[str, Any]] | None = None,
    *,
    installed_value: Any = None,
) -> Path:
    (tmp_path / "vendor" / "composer").mkdir(parents=True)
    (tmp_path / "composer.lock").write_text(
        json.dumps({"packages": locked[:1], "packages-dev": locked[1:]}), encoding="utf-8"
    )
    if installed_value is None:
        installed_value = {"packages": installed if installed is not None else locked}
    (tmp_path / "vendor" / "composer" / "installed.json").write_text(json.dumps(installed_value), encoding="utf-8")
    return tmp_path


def run_checker(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), str(root)], capture_output=True, text=True, check=False)


def assert_failure(result: subprocess.CompletedProcess[str], *needles: str) -> None:
    assert result.returncode == 1, result
    assert result.stderr.count("composer install --no-interaction") == 1, result.stderr
    for needle in needles:
        assert needle in result.stderr, result.stderr


def test_matching_packages_and_dev_packages_pass(tmp_path: Path) -> None:
    root = fixture(tmp_path, [package(), package("acme/dev", "2.0.0")])
    result = run_checker(root)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""


def test_absent_source_references_are_normalized_to_null(tmp_path: Path) -> None:
    locked = package(source=None, dist="same")
    installed = package(source=None, dist="same")
    result = run_checker(fixture(tmp_path, [locked], [installed]))
    assert result.returncode == 0, result.stderr


def test_symlinked_vendor_fails_before_metadata(tmp_path: Path) -> None:
    (tmp_path / "composer.lock").write_text("not json", encoding="utf-8")
    target = tmp_path / "shared-vendor"
    target.mkdir()
    (tmp_path / "vendor").symlink_to(target, target_is_directory=True)
    assert_failure(run_checker(tmp_path), "vendor is symlinked")


def test_missing_installed_json_fails(tmp_path: Path) -> None:
    (tmp_path / "vendor").mkdir()
    (tmp_path / "composer.lock").write_text(json.dumps({"packages": [], "packages-dev": []}), encoding="utf-8")
    assert_failure(run_checker(tmp_path), "missing vendor/composer/installed.json")


def test_missing_and_extra_packages_are_named(tmp_path: Path) -> None:
    locked = [package("acme/missing"), package("acme/kept")]
    installed = [package("acme/kept"), package("acme/extra")]
    result = run_checker(fixture(tmp_path, locked, installed))
    assert_failure(result, "missing package: acme/missing", "extra package: acme/extra")


def test_stale_version_source_and_dist_references_are_named(tmp_path: Path) -> None:
    locked = package(version="2.2.5", source="locked-source", dist="locked-dist")
    installed = package(version="2.2.1", source="installed-source", dist="installed-dist")
    result = run_checker(fixture(tmp_path, [locked], [installed]))
    assert_failure(
        result,
        "version mismatch: acme/pkg (locked 2.2.5; installed 2.2.1)",
        "source reference mismatch: acme/pkg (locked locked-source; installed installed-source)",
        "dist reference mismatch: acme/pkg (locked locked-dist; installed installed-dist)",
    )


def test_failed_check_does_not_mutate_fixture(tmp_path: Path) -> None:
    root = fixture(tmp_path, [package(version="2.2.5")], [package(version="2.2.1")])
    paths = [root / "composer.lock", root / "vendor" / "composer" / "installed.json"]
    before = {path: path.read_bytes() for path in paths}
    assert_failure(run_checker(root), "version mismatch")
    assert {path: path.read_bytes() for path in paths} == before


@pytest.mark.parametrize(
    ("value", "needle"),
    [
        ("", "malformed vendor/composer/installed.json"),
        ("null", "top level must be an object"),
        ("{}", "missing packages metadata"),
        ('{"packages": {}}', "packages must be a list"),
        ('{"packages": [1]}', "package 0"),
        ('{"packages": [{"name": 1, "version": "1"}]}', "package 0"),
        ('{"packages": [{"name": "a/b", "version": 1}]}', "package 0"),
        ('{"packages": [{"name": "a/b", "version": "1", "source": []}]}', "package 0"),
        (
            '{"packages": [{"name": "a/b", "version": "1", "source": {"reference": 1}}]}',
            "package 0",
        ),
        ('{"packages": [{"name": "a/b", "version": "1", "dist": []}]}', "package 0"),
        (
            '{"packages": [{"name": "a/b", "version": "1", "dist": {"reference": 1}}]}',
            "package 0",
        ),
        (
            '{"packages": [{"name": "a/b", "version": "1"}, {"name": "a/b", "version": "1"}]}',
            "duplicate package a/b",
        ),
    ],
)
def test_installed_metadata_hostile_inputs_fail_closed(tmp_path: Path, value: str, needle: str) -> None:
    fixture(tmp_path, [package()])
    installed_path = tmp_path / "vendor" / "composer" / "installed.json"
    if value == "":
        installed_path.write_bytes(b"")
    else:
        installed_path.write_text(value, encoding="utf-8")
    assert_failure(run_checker(tmp_path), needle)


def test_invalid_utf8_fails_closed(tmp_path: Path) -> None:
    fixture(tmp_path, [package()])
    (tmp_path / "vendor" / "composer" / "installed.json").write_bytes(b"\xff")
    assert_failure(run_checker(tmp_path), "malformed vendor/composer/installed.json")


def test_malformed_lock_fails_closed(tmp_path: Path) -> None:
    fixture(tmp_path, [package()])
    (tmp_path / "composer.lock").write_text(json.dumps({"packages": "wrong", "packages-dev": []}), encoding="utf-8")
    assert_failure(run_checker(tmp_path), "malformed composer.lock packages: packages must be a list")
