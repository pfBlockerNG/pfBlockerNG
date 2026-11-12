"""The CI image tag is a content hash of `.github/docker/` (issue #3852).

A tag that ignored a file the Dockerfile can COPY would serve a stale image for a changed
build input, and nothing would notice until a job ran on the wrong toolchain. The hash step
is run for real, from the workflow's own YAML, over a throwaway git repository.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW: dict[str, Any] = yaml.safe_load((ROOT / ".github/workflows/ci-image.yml").read_text(encoding="utf-8"))
CONTEXT_DIR = WORKFLOW["env"]["CONTEXT_DIR"]
STEPS: list[dict[str, Any]] = WORKFLOW["jobs"]["build"]["steps"]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _tag(repo: Path) -> str:
    """The `ci=` output of the workflow's hash step, run in `repo`."""
    script = next(step["run"] for step in STEPS if step.get("id") == "hash")
    output = repo / "github_output"
    output.write_text("")
    env = {**os.environ, "CONTEXT_DIR": CONTEXT_DIR, "GITHUB_OUTPUT": str(output)}
    subprocess.run(["bash", "-c", script], cwd=repo, env=env, check=True, capture_output=True)
    (line,) = (ln for ln in output.read_text().splitlines() if ln.startswith("ci="))
    return line.removeprefix("ci=")


@pytest.mark.parametrize(
    ("changed", "moves_the_tag"),
    [
        pytest.param("README.md", False, id="file-outside-the-context"),
        pytest.param("src/app.py", False, id="nested-file-outside-the-context"),
        pytest.param(f"{CONTEXT_DIR}/Dockerfile", True, id="dockerfile-edited"),
        pytest.param(f"{CONTEXT_DIR}/helper.py", True, id="new-file-a-copy-could-read"),
        pytest.param(f"{CONTEXT_DIR}/nested/data.txt", True, id="new-nested-file-in-the-context"),
    ],
)
def test_the_tag_moves_exactly_when_the_build_context_changes(
    tmp_path: Path, changed: str, moves_the_tag: bool
) -> None:
    repo = tmp_path / "repo"
    (repo / CONTEXT_DIR).mkdir(parents=True)
    (repo / CONTEXT_DIR / "Dockerfile").write_text("FROM scratch\n")
    (repo / "README.md").write_text("docs\n")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    before = _tag(repo)

    target = repo / changed
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("changed\n")
    _git(repo, "add", "-A")

    assert (_tag(repo) != before) is moves_the_tag, (
        f"changing {changed} must{'' if moves_the_tag else ' not'} move the tag"
    )


def test_buildx_builds_the_directory_the_tag_hashes() -> None:
    hash_run = next(step["run"] for step in STEPS if step.get("id") == "hash")
    build_run = next(step["run"] for step in STEPS if "docker buildx build" in step.get("run", ""))

    assert CONTEXT_DIR == ".github/docker"
    assert '"$CONTEXT_DIR"' in hash_run
    builds = re.findall(r"docker buildx build .*", build_run)
    assert len(builds) == 2
    assert all(build.endswith('"$CONTEXT_DIR"') for build in builds), builds


def test_an_executable_bit_change_moves_the_tag(tmp_path: Path) -> None:
    """Docker's COPY keeps a file's mode, so a mode-only change is a different image."""
    repo = tmp_path / "repo"
    (repo / CONTEXT_DIR).mkdir(parents=True)
    script = repo / CONTEXT_DIR / "check.py"
    script.write_text("print('ok')\n")
    _git(repo, "init", "-q")
    _git(repo, "-c", "core.fileMode=true", "add", "-A")
    before = _tag(repo)

    _git(repo, "update-index", "--chmod=+x", f"{CONTEXT_DIR}/check.py")

    assert _tag(repo) != before, "making a build-context file executable must move the tag"
