"""The CI image tag is a content hash of everything the Dockerfile can COPY (issues #3852, #3884).

That is `.github/docker/` plus the Go gateway's go.mod and go.sum (the `gomod` build context that
pre-downloads its modules). A tag that ignored one of those files would serve a stale image for a
changed build input, and nothing would notice until a job ran on the wrong toolchain. The hash
step is run for real, from the workflow's own YAML, over a throwaway git repository.
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
GO_DIR = "go/pfb_dns_gateway"  # the module the image pre-downloads; pinned here, asserted against the workflow below
DOCKERFILE = (ROOT / CONTEXT_DIR / "Dockerfile").read_text(encoding="utf-8")
STEPS: list[dict[str, Any]] = WORKFLOW["jobs"]["build"]["steps"]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _tag(repo: Path) -> str:
    """The `ci=` output of the workflow's hash step, run in `repo`."""
    script = next(step["run"] for step in STEPS if step.get("id") == "hash")
    output = repo / "github_output"
    output.write_text("")
    env = {**os.environ, **WORKFLOW["env"], "GITHUB_OUTPUT": str(output)}
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
        pytest.param(f"{GO_DIR}/go.mod", True, id="go-mod-edited"),
        pytest.param(f"{GO_DIR}/go.sum", True, id="go-sum-edited"),
        pytest.param(f"{GO_DIR}/main.go", False, id="go-source-outside-the-hash"),
    ],
)
def test_the_tag_moves_exactly_when_the_build_context_changes(
    tmp_path: Path, changed: str, moves_the_tag: bool
) -> None:
    repo = tmp_path / "repo"
    (repo / CONTEXT_DIR).mkdir(parents=True)
    (repo / CONTEXT_DIR / "Dockerfile").write_text("FROM scratch\n")
    (repo / "README.md").write_text("docs\n")
    (repo / GO_DIR).mkdir(parents=True)
    for name in ("go.mod", "go.sum", "main.go"):
        (repo / GO_DIR / name).write_text("original\n")
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


def test_buildx_builds_the_context_the_tag_hashes() -> None:
    hash_run = next(step["run"] for step in STEPS if step.get("id") == "hash")
    build_run = next(step["run"] for step in STEPS if "docker buildx build" in step.get("run", ""))

    assert CONTEXT_DIR == ".github/docker"
    assert WORKFLOW["env"].get("GO_MODULE_DIR") == GO_DIR
    for hashed in ('"$CONTEXT_DIR"', '"$GO_MODULE_DIR/go.mod"', '"$GO_MODULE_DIR/go.sum"'):
        assert hashed in hash_run, f"the hash step must cover {hashed}"
    builds = re.findall(r"docker buildx build .*", build_run)
    assert len(builds) == 4  # ci, ci-vm, unbound, unbound-py
    assert all(build.endswith('"$CONTEXT_DIR"') for build in builds), builds
    assert all('--build-context gomod="$GO_MODULE_DIR"' in build for build in builds), builds


def test_the_dockerfile_copies_exactly_the_go_module_files_the_tag_hashes() -> None:
    """The gomod context holds the whole module, but only go.mod and go.sum are hashed."""
    hash_run = next(step["run"] for step in STEPS if step.get("id") == "hash")
    hashed = re.findall(r'"\$GO_MODULE_DIR/([^"]+)"', hash_run)

    copies = re.findall(r"^COPY --from=gomod (.+) \S+$", DOCKERFILE, re.MULTILINE)

    assert len(copies) == 1, f"expected one COPY --from=gomod, found {copies}"
    assert copies[0].split() == ["go.mod", "go.sum"]
    assert sorted(hashed) == copies[0].split(), f"the hash covers {hashed} but the Dockerfile copies {copies[0]}"


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
