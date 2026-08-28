#!/usr/bin/env python3
"""Verify a worktree's Composer metadata matches its lock file."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REMEDIATION = "remediation: composer install --no-interaction"


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"invalid JSON constant: {value}")


def _load_json(path: Path, label: str) -> tuple[Any | None, list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_json_constant), []
    except FileNotFoundError:
        return None, [f"missing {label}: {path}"]
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        return None, [f"malformed {label}: {exc}"]


def _package_tuple(package: Any) -> tuple[str, tuple[str, str | None, str | None]] | None:
    if not isinstance(package, dict):
        return None
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        return None
    refs: list[str | None] = []
    for field in ("source", "dist"):
        if field not in package:
            refs.append(None)
            continue
        value = package[field]
        if not isinstance(value, dict):
            return None
        reference = value.get("reference")
        if not isinstance(reference, str) or not reference:
            return None
        refs.append(reference)
    return name, (version, refs[0], refs[1])


def _packages(value: Any, label: str) -> tuple[dict[str, tuple[str, str | None, str | None]], list[str]]:
    if not isinstance(value, list):
        return {}, [f"malformed {label}: packages must be a list"]
    packages: dict[str, tuple[str, str | None, str | None]] = {}
    errors: list[str] = []
    for index, package in enumerate(value):
        parsed = _package_tuple(package)
        if parsed is None:
            errors.append(f"malformed {label} package {index}: name, version, source, and dist metadata")
            continue
        name, details = parsed
        if name in packages:
            errors.append(f"malformed {label}: duplicate package {name}")
            continue
        packages[name] = details
    return packages, errors


def _read_lock(path: Path) -> tuple[dict[str, tuple[str, str | None, str | None]], list[str]]:
    value, errors = _load_json(path, "composer.lock")
    if errors:
        return {}, errors
    if not isinstance(value, dict):
        return {}, ["malformed composer.lock: top level must be an object"]
    packages: dict[str, tuple[str, str | None, str | None]] = {}
    for key in ("packages", "packages-dev"):
        current, current_errors = _packages(value.get(key), f"composer.lock {key}")
        errors.extend(current_errors)
        for name, details in current.items():
            if name in packages:
                errors.append(f"malformed composer.lock: duplicate package {name}")
            else:
                packages[name] = details
    return packages, errors


def _read_installed(path: Path) -> tuple[dict[str, tuple[str, str | None, str | None]], list[str]]:
    value, errors = _load_json(path, "vendor/composer/installed.json")
    if errors:
        return {}, errors
    if not isinstance(value, dict):
        return {}, ["malformed vendor/composer/installed.json: top level must be an object"]
    if "packages" not in value:
        return {}, ["malformed vendor/composer/installed.json: missing packages metadata"]
    return _packages(value["packages"], "vendor/composer/installed.json")


def _compare(
    locked: dict[str, tuple[str, str | None, str | None]],
    installed: dict[str, tuple[str, str | None, str | None]],
) -> list[str]:
    def display(reference: str | None) -> str:
        return reference if reference is not None else "null"

    diagnostics: list[str] = []
    for name in sorted(locked.keys() - installed.keys()):
        diagnostics.append(f"missing package: {name} (locked {locked[name][0]})")
    for name in sorted(installed.keys() - locked.keys()):
        diagnostics.append(f"extra package: {name} (installed {installed[name][0]})")
    for name in sorted(locked.keys() & installed.keys()):
        locked_version, locked_source, locked_dist = locked[name]
        installed_version, installed_source, installed_dist = installed[name]
        if locked_version != installed_version:
            diagnostics.append(f"version mismatch: {name} (locked {locked_version}; installed {installed_version})")
        if locked_source != installed_source:
            diagnostics.append(
                f"source reference mismatch: {name} "
                f"(locked {display(locked_source)}; installed {display(installed_source)})"
            )
        if locked_dist != installed_dist:
            diagnostics.append(
                f"dist reference mismatch: {name} (locked {display(locked_dist)}; installed {display(installed_dist)})"
            )
    return diagnostics


def check(root: Path) -> list[str]:
    vendor = root / "vendor"
    if vendor.is_symlink():
        return [f"vendor is symlinked: {vendor}"]
    if not vendor.is_dir():
        return [f"missing vendor directory: {vendor}"]
    installed = vendor / "composer" / "installed.json"
    locked, lock_errors = _read_lock(root / "composer.lock")
    installed_packages, installed_errors = _read_installed(installed)
    errors = lock_errors + installed_errors
    return errors if errors else _compare(locked, installed_packages)


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print("usage: check_composer_vendor.py [worktree]", file=sys.stderr)
        print(REMEDIATION, file=sys.stderr)
        return 2
    root = Path(argv[1] if len(argv) == 2 else ".").resolve()
    diagnostics = sorted(check(root))
    if not diagnostics:
        return 0
    for diagnostic in diagnostics:
        print(diagnostic, file=sys.stderr)
    print(REMEDIATION, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
