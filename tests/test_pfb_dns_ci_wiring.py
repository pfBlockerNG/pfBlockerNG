"""CI provides the Go compiler wherever the pfB-DNS payload is built (issue #3513, dual-arch package).

build-pkg-portable.py cross-compiles the gateway, so every job that runs it needs the pinned Go
toolchain on PATH BEFORE the build step. Every such job, and the job that runs this repository's
own test suite, runs inside the ci / ci-vm image and gets Go from there, whose GO_VERSION ARG
test_ci_tool_pins.py keeps equal to GO_PIN and at least the module's own `go` directive.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from tests.test_ci_tool_pins import GO_PIN

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
SETUP_GO = "actions/setup-go@v7"
TEST_JOB = ("test.yml", "test")
# The build sites known today; the discovery below must still find every one of them. Each runs
# in a ci / ci-vm job container, whose Go comes from the image instead of a setup-go step.
KNOWN_BUILD_SITES = {
    ("build-pkg-linux.yml", "build"),
    ("nightly.yml", "build"),
    ("release.yml", "build-pkgs-portable"),
    ("smoke-single.yml", "smoke"),
}


def _jobs() -> dict[tuple[str, str], dict[str, Any]]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, job in (document.get("jobs") or {}).items():
            found[(path.name, name)] = job
    return found


def _first_step_running(job: dict[str, Any], needle: str) -> int | None:
    for index, step in enumerate(job.get("steps") or []):
        if needle in (step.get("run") or ""):
            return index
    return None


def image_go_problems(job: dict[str, Any]) -> list[str]:
    """Everything wrong with how ``job`` gets the Go baked into the ci / ci-vm image."""
    problems = []
    image = str((job.get("container") or {}).get("image", ""))
    if not re.search(r"needs\.ci-image\.outputs\.ci(_vm)?\b", image):
        problems.append(f"container image is {image!r}, not a ci image that bakes Go")
    if any(str(step.get("uses", "")).startswith("actions/setup-go@") for step in job.get("steps") or []):
        problems.append("a setup-go step would shadow the Go baked into the image")
    return problems


def test_every_job_that_runs_the_package_builder_runs_in_the_image_that_bakes_the_pinned_go() -> None:
    sites = {key: job for key, job in _jobs().items() if _first_step_running(job, "build-leg.sh") is not None}
    assert KNOWN_BUILD_SITES <= set(sites), f"build sites vanished or moved: {sorted(KNOWN_BUILD_SITES - set(sites))}"
    problems = {key: image_go_problems(job) for key, job in sites.items()}
    assert {key: p for key, p in problems.items() if p} == {}


def test_the_test_job_runs_pytest_in_the_ci_image_that_bakes_the_pinned_go() -> None:
    job = _jobs()[TEST_JOB]
    prefix = str((job.get("env") or {}).get("CI_RUN", ""))
    assert re.search(r"needs\.ci-image\.outputs\.ci\b", prefix), f"CI_RUN does not run the ci image: {prefix!r}"
    pytest_steps = [step for step in job["steps"] if "pytest" in (step.get("run") or "")]
    assert pytest_steps, "no step runs pytest"
    for step in pytest_steps:
        code = "\n".join(line for line in step["run"].splitlines() if not line.lstrip().startswith("#"))
        assert "$CI_RUN" in code, f"pytest runs outside the ci image (no Go baked there): {step['run']!r}"


def test_image_go_check_rejects_each_planted_defect() -> None:
    """Vacuity guard: the checker above reports every way the wiring can be wrong."""
    assert image_go_problems({"container": {"image": "${{ needs.ci-image.outputs.ci_vm }}"}, "steps": []}) == []
    assert image_go_problems({"container": {"image": "${{ needs.ci-image.outputs.ci }}"}, "steps": []}) == []
    for label, job, fragment in (
        ("no container", {"steps": []}, "not a ci image"),
        ("foreign image", {"container": {"image": "debian:trixie"}, "steps": []}, "not a ci image"),
        (
            "setup-go shadows the image",
            {"container": {"image": "${{ needs.ci-image.outputs.ci_vm }}"}, "steps": [{"uses": SETUP_GO}]},
            "shadow",
        ),
    ):
        problems = image_go_problems(job)
        assert any(fragment in p for p in problems), f"{label}: not reported, got {problems}"


def test_go_pin_satisfies_the_module_go_directive() -> None:
    go_mod = (ROOT / "go" / "pfb_dns_gateway" / "go.mod").read_text(encoding="utf-8")
    match = re.search(r"^go (\d+)\.(\d+)(?:\.(\d+))?$", go_mod, re.MULTILINE)
    assert match, "go.mod has no `go` directive"
    floor = tuple(int(part or 0) for part in match.groups())
    pinned = tuple(int(part) for part in GO_PIN.split("."))
    assert pinned >= floor, f"CI pins Go {GO_PIN}, below the module's go directive {match.group(0)!r}"
