"""CI provides the Go compiler wherever the pfB-DNS payload is built (issue #3513, dual-arch package).

build-pkg-portable.py cross-compiles the gateway, so every job that runs it needs the pinned Go
toolchain on PATH BEFORE the build step, and the job that runs this repository's own test suite needs
it for the real cross-build cases. The pin is one literal per job, kept equal everywhere by
test_ci_tool_pins.py and at least the module's own `go` directive.
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
# The build sites known today; the discovery below must still find every one of them.
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


def go_wiring_problems(job: dict[str, Any], consumer: str) -> list[str]:
    """Everything wrong with how ``job`` provides Go before its first step that runs ``consumer``."""
    steps = job.get("steps") or []
    consumer_at = _first_step_running(job, consumer)
    if consumer_at is None:
        return [f"no step runs {consumer!r}"]
    setups = [i for i, step in enumerate(steps) if str(step.get("uses", "")) == SETUP_GO]
    if not setups:
        return [f"no {SETUP_GO} step"]
    problems = []
    if setups[0] > consumer_at:
        problems.append(f"{SETUP_GO} comes after the step that runs {consumer!r}")
    inputs = steps[setups[0]].get("with") or {}
    if inputs.get("go-version") != "${{ env.GO_VERSION }}":
        problems.append(f"go-version is {inputs.get('go-version')!r}, not the job's GO_VERSION pin")
    if inputs.get("cache") is not False:
        problems.append(f"cache is {inputs.get('cache')!r}; a package build must not restore a module cache")
    if str((job.get("env") or {}).get("GO_VERSION")) != GO_PIN:
        problems.append(f"job env GO_VERSION is {(job.get('env') or {}).get('GO_VERSION')!r}, expected {GO_PIN!r}")
    return problems


def test_every_job_that_runs_the_package_builder_pins_go_before_building() -> None:
    sites = {key: job for key, job in _jobs().items() if _first_step_running(job, "build-leg.sh") is not None}
    assert KNOWN_BUILD_SITES <= set(sites), f"build sites vanished or moved: {sorted(KNOWN_BUILD_SITES - set(sites))}"
    problems = {key: go_wiring_problems(job, "build-leg.sh") for key, job in sites.items()}
    assert {key: p for key, p in problems.items() if p} == {}


def test_the_test_job_provides_go_for_the_real_cross_build_cases() -> None:
    job = _jobs()[TEST_JOB]
    assert go_wiring_problems(job, "pytest") == []


def test_go_wiring_check_rejects_each_planted_defect() -> None:
    """Vacuity guard: the checker above reports every way the wiring can be wrong."""
    good: dict[str, Any] = {
        "env": {"GO_VERSION": GO_PIN},
        "steps": [
            {"uses": SETUP_GO, "with": {"go-version": "${{ env.GO_VERSION }}", "cache": False}},
            {"run": "sh scripts/build-leg.sh"},
        ],
    }
    assert go_wiring_problems(good, "build-leg.sh") == []

    def mutated(**patch: Any) -> dict[str, Any]:
        job: dict[str, Any] = {"env": dict(good["env"]), "steps": [dict(s) for s in good["steps"]]}
        job["steps"][0]["with"] = dict(good["steps"][0]["with"])
        for key, value in patch.items():
            if key == "env":
                job["env"] = value
            elif key == "uses":
                job["steps"][0]["uses"] = value
            elif key == "order":
                job["steps"].reverse()
            else:
                job["steps"][0]["with"][key] = value
        return job

    for label, job, fragment in (
        ("missing setup-go", mutated(uses="actions/setup-node@v7"), "no actions/setup-go"),
        ("setup after build", mutated(order=True), "comes after"),
        ("literal version", mutated(**{"go-version": "1.27.0"}), "go-version"),
        ("module cache restored", mutated(cache=True), "cache"),
        ("pin missing", mutated(env={}), "GO_VERSION"),
        ("pin drifted", mutated(env={"GO_VERSION": "1.1.0"}), "GO_VERSION"),
    ):
        problems = go_wiring_problems(job, "build-leg.sh")
        assert any(fragment in p for p in problems), f"{label}: not reported, got {problems}"


def test_go_pin_satisfies_the_module_go_directive() -> None:
    go_mod = (ROOT / "go" / "pfb_dns_gateway" / "go.mod").read_text(encoding="utf-8")
    match = re.search(r"^go (\d+)\.(\d+)(?:\.(\d+))?$", go_mod, re.MULTILINE)
    assert match, "go.mod has no `go` directive"
    floor = tuple(int(part or 0) for part in match.groups())
    pinned = tuple(int(part) for part in GO_PIN.split("."))
    assert pinned >= floor, f"CI pins Go {GO_PIN}, below the module's go directive {match.group(0)!r}"
