"""Tagged release handoff identity and fail-closed validation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/tagged_release_handoff.py"
TAG = "v4.0.0.b1"
SOURCE_SHA = "a" * 40
CI_METADATA_SHA = "b" * 40
PORTS_SHA = "c" * 40
SOURCE_DATE_EPOCH = 1_700_000_000
DEPENDENCY_BUILDER = {
    "python": "3.11.15",
    "pip": "26.2.1",
    "setuptools": "75.6.0",
    "wheel": "0.45.1",
    "zstandard": "0.25.0",
    "uv": "0.12.6",
    "uv_lock_sha256": "d" * 64,
}
ROW = {
    "pfsense_version": "2.8",
    "channel": "CE",
    "freebsd_version": "15.0-RELEASE",
    "freebsd_major": "15",
    "php_version": "8.3",
    "py_flavor": "py311",
    "variant": "CE",
    "status": "active",
    "extra_pkgs": [],
}


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("tagged_release_handoff", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _payload() -> dict[str, object]:
    return _module().build_handoff(
        release_tag=TAG,
        source_sha=SOURCE_SHA,
        ci_metadata_sha=CI_METADATA_SHA,
        ports_sha=PORTS_SHA,
        route_matrix=[ROW],
        source_date_epoch=SOURCE_DATE_EPOCH,
        dependency_builder=DEPENDENCY_BUILDER,
    )


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_cli_creates_canonical_build_time_handoff(tmp_path: Path) -> None:
    route = tmp_path / "route.json"
    output = tmp_path / "handoff.json"
    _write(route, [ROW])
    dependency_builder = tmp_path / "dependency-builder.json"
    _write(dependency_builder, DEPENDENCY_BUILDER)

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--release-tag",
            TAG,
            "--source-sha",
            SOURCE_SHA,
            "--ci-metadata-sha",
            CI_METADATA_SHA,
            "--ports-sha",
            PORTS_SHA,
            "--source-date-epoch",
            str(SOURCE_DATE_EPOCH),
            "--dependency-builder",
            str(dependency_builder),
            "--route-matrix",
            str(route),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert set(payload) == {
        "schema",
        "kind",
        "release_tag",
        "source_sha",
        "ci_metadata_sha",
        "ports_sha",
        "route_matrix",
        "source_date_epoch",
        "dependency_builder",
    }
    assert payload["kind"] == "tagged-release-handoff"
    assert payload["release_tag"] == TAG
    assert payload["source_sha"] == SOURCE_SHA
    assert payload["ci_metadata_sha"] == CI_METADATA_SHA
    assert payload["ports_sha"] == PORTS_SHA
    assert payload["route_matrix"] == [ROW]

    assert payload["source_date_epoch"] == SOURCE_DATE_EPOCH
    assert payload["dependency_builder"] == DEPENDENCY_BUILDER


def test_load_accepts_exact_release_and_source(tmp_path: Path) -> None:
    path = tmp_path / "handoff.json"
    _write(path, _payload())

    handoff = _module().load_handoff(path, expected_release_tag=TAG, expected_source_sha=SOURCE_SHA)

    assert handoff["route_matrix"] == [ROW]
    assert handoff["ports_sha"] == PORTS_SHA


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing", "cannot read"),
        ("malformed", "valid JSON"),
        ("schema-bool", "schema"),
        ("schema-float", "schema"),
        ("wrong-release", "release_tag"),
        ("wrong-source", "source_sha"),
        ("wrong-ci-shape", "ci_metadata_sha"),
        ("extra-field", "unexpected fields"),
    ],
)
def test_load_fails_closed_on_invalid_handoff(tmp_path: Path, case: str, message: str) -> None:
    module = _module()
    path = tmp_path / "handoff.json"
    expected_tag = TAG
    expected_source = SOURCE_SHA
    if case == "missing":
        pass
    elif case == "malformed":
        path.write_text("not json", encoding="utf-8")
    else:
        payload = _payload()
        if case == "schema-bool":
            payload["schema"] = True
        elif case == "schema-float":
            payload["schema"] = 1.0
        elif case == "wrong-release":
            expected_tag = "v4.0.0.b2"
        elif case == "wrong-source":
            expected_source = "d" * 40
        elif case == "wrong-ci-shape":
            payload["ci_metadata_sha"] = "not-a-sha"
        elif case == "extra-field":
            payload["live_route"] = []
        _write(path, payload)

    with pytest.raises(module.HandoffError, match=message):
        module.load_handoff(path, expected_release_tag=expected_tag, expected_source_sha=expected_source)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"source_tag": "v4.0.0.b2"}, "source_tag"),
        ({"source_sha": "d" * 40}, "source_sha"),
        ({"freebsd_ports_sha": "e" * 40}, "freebsd_ports_sha"),
    ],
)
def test_build_records_must_match_handoff_identities(changes: dict[str, str], message: str) -> None:
    module = _module()
    record = {
        "source_tag": TAG,
        "source_sha": SOURCE_SHA,
        "freebsd_ports_sha": PORTS_SHA,
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "dependency_builder": DEPENDENCY_BUILDER,
        **changes,
    }

    with pytest.raises(module.HandoffError, match=message):
        module.validate_build_records(_payload(), [record])


def test_build_records_accept_exact_handoff_identities() -> None:
    module = _module()
    records = [
        {
            "source_tag": TAG,
            "source_sha": SOURCE_SHA,
            "freebsd_ports_sha": PORTS_SHA,
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "dependency_builder": DEPENDENCY_BUILDER,
        },
        {
            "source_tag": TAG,
            "source_sha": SOURCE_SHA,
            "freebsd_ports_sha": PORTS_SHA,
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "dependency_builder": DEPENDENCY_BUILDER,
        },
    ]

    module.validate_build_records(_payload(), records)
