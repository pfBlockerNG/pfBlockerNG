"""issue #2143 review round 2: build-record environment and republish identity."""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from tests._workflow_steps import extract_after, extract_between

ROOT = Path(__file__).resolve().parents[1]
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
REPUBLISH = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")


def _build_record_script() -> str:
    block = extract_after(RELEASE, "      - name: Write the destination-bound build record")
    return textwrap.dedent(extract_between(block, "        run: |\n", "\n      - name:"))


def _republish_validate_script() -> str:
    block = extract_after(REPUBLISH, "      - name: Resolve exact immutable Release")
    script = extract_between(block, "        run: |\n", "\n          git fetch")
    return textwrap.dedent(script) + "\nexit 0\n"


def test_build_record_step_uses_pinned_ports_sha_in_python_child(tmp_path: Path) -> None:
    """The record step reads the pre-fan-out PORTS_SHA pin from its environment."""
    workdir = tmp_path / "work"
    workdir.mkdir()
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    ports_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    completed = subprocess.run(
        ["sh", "-c", _build_record_script()],
        cwd=workdir,
        env=os.environ
        | {
            "PYTHONPATH": str(ROOT),
            "RUNNER_TEMP": str(runner_temp),
            "TAG": "v4.0.0",
            "CHANNEL": "stable",
            "SOURCE": "release/4.0",
            "PORTVERSION": "4.0.0",
            "CLASSIFICATION": "final",
            "COMMIT": "0" * 40,
            "CREATED": "1700000000",
            "MATRIX_ROW": '{"variant":"CE","pfsense_version":"2.8","extra_pkgs":[]}',
            "EXTRA_PKGS": "[]",
            "PORTS_SHA": ports_sha,
            "DEPENDENCY_BUILDER": json.dumps(
                {
                    "python": "3.11.15",
                    "pip": "26.2.1",
                    "setuptools": "75.6.0",
                    "wheel": "0.45.1",
                    "zstandard": "0.25.0",
                    "uv": "0.12.6",
                    "uv_lock_sha256": "d" * 64,
                }
            ),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not (workdir / "build-record.json").exists()
    record = json.loads((runner_temp / "build-record.json").read_text(encoding="utf-8"))
    assert record["freebsd_ports_sha"] == ports_sha


@pytest.mark.parametrize(
    ("tag", "prerelease", "expected_returncode"),
    [
        ("v4.0.0", "false", 0),
        ("v4.0.0", "true", 1),
        ("v4.0.1.a1", "true", 0),
        ("v4.0.1.a1", "false", 1),
    ],
)
def test_manual_republish_requires_the_prerelease_flag_to_match_the_tag(
    tmp_path: Path, tag: str, prerelease: str, expected_returncode: int
) -> None:
    """A manual republish rejects the same flag mismatch the published callback rejects."""
    bin_dir = tmp_path / f"{tag}-{prerelease}"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(
        (
            f'#!/bin/sh\nprintf \'%s\\n\' \'{{"tag_name":"{tag}","draft":false,'
            f'"prerelease":{prerelease},"immutable":true}}\'\n'
        ),
        encoding="utf-8",
    )
    gh.chmod(0o755)
    completed = subprocess.run(
        ["sh", "-c", _republish_validate_script()],
        cwd=ROOT,
        env=os.environ
        | {
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "RELEASE_ID": "12345",
            "RELEASE_TAG": tag,
            "SOURCE_REPOSITORY": "owner/repo",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == expected_returncode, completed.stdout + completed.stderr
