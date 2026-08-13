"""issue #2143 review round 2: build-record environment and republish identity."""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
REPUBLISH = (ROOT / ".github/workflows/pkg-republish.yml").read_text(encoding="utf-8")


def _build_record_script() -> str:
    block = RELEASE.split("      - name: Write the destination-bound build record", 1)[1]
    return textwrap.dedent(block.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0])


def _republish_validate_script() -> str:
    return textwrap.dedent(REPUBLISH.split("        run: |\n", 1)[1].split("      - uses:", 1)[0])


def test_build_record_step_exports_ports_sha_to_the_python_child(tmp_path: Path) -> None:
    """The record step resolves PORTS_SHA in the shell and reads it from a python child."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_git = fake_bin / "git"
    fake_git.write_text(
        "#!/bin/sh\nprintf '%s\\t%s\\n' deadbeefdeadbeefdeadbeefdeadbeefdeadbeef refs/heads/x\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    workdir = tmp_path / "work"
    workdir.mkdir()
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    completed = subprocess.run(
        ["sh", "-c", _build_record_script()],
        cwd=workdir,
        env=os.environ
        | {
            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
            "PYTHONPATH": str(ROOT),
            "GITHUB_ENV": str(tmp_path / "github-env"),
            "RUNNER_TEMP": str(runner_temp),
            "TAG": "v4.0.0",
            "CHANNEL": "stable",
            "SOURCE": "release/4.0",
            "PORTVERSION": "4.0.0",
            "CLASSIFICATION": "final",
            "COMMIT": "0" * 40,
            "CREATED": "1700000000",
            "MATRIX_ROW": '{"variant":"CE","pfsense_version":"2.8"}',
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not (workdir / "build-record.json").exists()
    record = json.loads((runner_temp / "build-record.json").read_text(encoding="utf-8"))
    assert record["freebsd_ports_sha"] == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


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
        f'#!/bin/sh\nprintf \'%s\\n\' \'{{"tag_name":"{tag}","draft":false,"prerelease":{prerelease}}}\'\n',
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
            "REPOSITORY": "owner/repo",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == expected_returncode, completed.stdout + completed.stderr
