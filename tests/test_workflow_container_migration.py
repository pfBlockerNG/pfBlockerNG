"""Every workflow job runs in the right runner image, at the pinned tag (issue #2215).

The toolchain moved out of the workflows and into two images. That only holds if EVERY
job is actually in one -- a job left behind silently grades against the GitHub-hosted
runner's ambient toolchain, which is the drift the images exist to remove. Checking
test.yml alone is not enough: a stale ``setup-python`` in any other workflow, or a job
pinned to a tag that was never published, is invisible to a per-file guard.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"

# Builds the images, so it cannot run inside one.
EXEMPT = {"ci-images.yml"}

# Jobs that drive a VM need the VM image on the self-hosted fleet; everything else needs
# the base image on GitHub-hosted runners.
VM_JOBS = {
    ("build-image.yml", "publish-image"),
    ("build-image.yml", "verify-image"),
    ("image-refresh.yml", "refresh"),
    ("smoke-single.yml", "smoke"),
    ("ui-tests.yml", "ui"),
    ("version-tracker.yml", "reconcile"),
}

# Provisioning the image makes redundant. A survivor either shadows the baked tool with a
# different build, or fails outright as the non-root job user.
STALE = (
    "actions/setup-python",
    "actions/setup-node",
    "shivammathur/setup-php",
    "oras-project/setup-oras",
    "apt-get install",
    "sudo ",
)


def _pinned_tag() -> str:
    return (ROOT / ".github/docker/VERSION").read_text(encoding="utf-8").strip()


def _workflows() -> list[Path]:
    return sorted(p for p in WORKFLOWS.glob("*.yml") if p.name not in EXEMPT)


def _real_jobs(doc: dict) -> dict:
    """Jobs that execute steps. A `uses:` job delegates to another workflow, which is
    containerised on its own terms, so it has no runner of its own to pin."""
    return {n: j for n, j in (doc.get("jobs") or {}).items() if isinstance(j, dict) and "uses" not in j}


def test_every_job_runs_in_a_runner_image_at_the_pinned_tag() -> None:
    tag = _pinned_tag()
    offenders: list[str] = []

    for path in _workflows():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, job in _real_jobs(doc).items():
            container = job.get("container")
            image = container.get("image", "") if isinstance(container, dict) else str(container or "")
            if not image:
                offenders.append(f"{path.name}::{name} runs on the ambient runner toolchain")
                continue

            want = "ci-runner-vm" if (path.name, name) in VM_JOBS else "ci-runner"
            expected = f"ghcr.io/pfblockerng/{want}:{tag}"
            if image != expected:
                offenders.append(f"{path.name}::{name} uses {image}, expected {expected}")

    assert not offenders, "jobs not pinned to the right image:\n  " + "\n  ".join(offenders)


def test_vm_jobs_target_the_self_hosted_fleet_with_kvm() -> None:
    """A VM job on a GitHub-hosted runner would have no /dev/kvm passthrough, and qemu
    would fall back to TCG -- which does not fail, it times out."""
    offenders: list[str] = []
    for fname, jname in sorted(VM_JOBS):
        doc = yaml.safe_load((WORKFLOWS / fname).read_text(encoding="utf-8"))
        job = doc["jobs"][jname]
        runs_on = job.get("runs-on")
        if not (isinstance(runs_on, list) and "self-hosted" in runs_on):
            offenders.append(f"{fname}::{jname} runs-on={runs_on!r}, expected the self-hosted fleet")
        options = (job.get("container") or {}).get("options", "")
        if "--device /dev/kvm" not in options:
            offenders.append(f"{fname}::{jname} does not pass /dev/kvm into the container")
    assert not offenders, "\n  ".join(offenders)


def test_every_container_runs_an_init_process() -> None:
    """Without an init, PID 1 is the container's sleep command, which never reaps. A test
    that kills a process group then asserts the descendants are gone sees unreaped zombies
    and reports them as still present -- reproduced exactly against GitHub's container
    model (PID 1 = `tail -f /dev/null`, steps via `docker exec`): 2 failed without --init,
    9 passed with it."""
    offenders: list[str] = []
    for path in _workflows():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, job in _real_jobs(doc).items():
            container = job.get("container")
            if not (isinstance(container, dict) and "ci-runner" in str(container.get("image", ""))):
                continue
            if "--init" not in container.get("options", ""):
                offenders.append(f"{path.name}::{name} runs without --init; orphans are never reaped")
    assert not offenders, "\n  ".join(offenders)


def test_no_workflow_still_provisions_a_baked_tool() -> None:
    offenders: list[str] = []
    for path in _workflows():
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), 1):
            code = line.split("#", 1)[0]
            for token in STALE:
                if token in code:
                    offenders.append(f"{path.name}:{line_no}: {token.strip()!r} -- the image provides this")
    assert not offenders, "stale provisioning survived the migration:\n  " + "\n  ".join(offenders)


def test_every_containerised_job_can_actually_pull_the_image() -> None:
    """Job-level `permissions:` REPLACE the workflow's rather than extending them, so a
    job that narrows its token loses the packages:read the pull needs and the daemon
    answers `denied` before a single step runs."""
    offenders: list[str] = []
    for path in _workflows():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        workflow_perms = doc.get("permissions")
        for name, job in _real_jobs(doc).items():
            container = job.get("container")
            if not (isinstance(container, dict) and "ci-runner" in str(container.get("image", ""))):
                continue
            effective = job["permissions"] if isinstance(job.get("permissions"), dict) else workflow_perms
            if not isinstance(effective, dict) or "packages" not in effective:
                offenders.append(f"{path.name}::{name} pulls the image without packages: read")
    assert not offenders, "\n  ".join(offenders)


def test_container_paths_are_not_host_paths() -> None:
    """`${{ github.workspace }}` and `${{ runner.temp }}` expand to the HOST path; inside
    a container the workspace is mounted elsewhere, so a step using them opens nothing.
    The $GITHUB_WORKSPACE / $RUNNER_TEMP env vars ARE translated."""
    offenders: list[str] = []
    targets = list(_workflows()) + sorted((ROOT / ".github/actions").glob("*/action.yml"))
    for path in targets:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\$\{\{\s*(github\.workspace|runner\.temp)\s*\}\}", line):
                offenders.append(f"{path.name}:{line_no}: host path inside a container job")
    assert not offenders, "\n  ".join(offenders)
