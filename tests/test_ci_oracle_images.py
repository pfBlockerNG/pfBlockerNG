"""The Unbound oracle images are built once by ci-image.yml and handed to the suites that need them (issue #3884).

The Go ACL oracle (test.yml `go-quality`) and the dns_proxy integration tests (`test`) used to `docker build`
their Unbound image on a cold runner every run. Each now pulls an image that ci-image.yml built from a Dockerfile
target and reads its ref from an env var. The chain has five links, and cutting any one of them falls back to the
slow self-build with every job still green, so each link is asserted here:

1. ci-image.yml builds the target, tags it with the content hash and exposes the ref as a workflow output;
2. the job env maps the variable to that output and CI_RUN passes it into the container;
3. a `docker pull` step runs before the suite (an uninspectable ref makes the test build and tag it locally);
4. the Go gate keeps the variable through `sudo`, whose env_reset would drop it;
5. the suite reads that variable, and the target installs the same Unbound as the suite's own self-build recipe.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CI_IMAGE: dict[Any, Any] = yaml.safe_load((ROOT / ".github/workflows/ci-image.yml").read_text(encoding="utf-8"))
TEST_JOBS: dict[str, Any] = yaml.safe_load((ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8"))["jobs"]
DOCKERFILE = (ROOT / ".github/docker/Dockerfile").read_text(encoding="utf-8")
CALL_OUTPUTS: dict[str, Any] = CI_IMAGE[True]["workflow_call"]["outputs"]  # YAML 1.1 reads the key `on` as True
BUILD_STEPS: list[dict[str, Any]] = CI_IMAGE["jobs"]["build"]["steps"]
SOURCE_LABEL = "LABEL org.opencontainers.image.source=https://github.com/pfBlockerNG/pfBlockerNG"

# `--no-install-recommends` is followed by the packages in the Dockerfile (to a `\` or `&&`) and in both
# self-build recipes (to a quote or `&&`); one pattern reads all three.
PACKAGES = re.compile(r"--no-install-recommends ([\w.+\- ]+)")
BASE_TAG = re.compile(r"(?:FROM |ARG DEBIAN_IMAGE=)(debian:[\w.-]+)")  # the digest pin after `@` is not part of it


def _gate_step(step: dict[str, Any]) -> bool:
    return "GATE" in step.get("env", {})


def _pytest_step(step: dict[str, Any]) -> bool:
    return "uv run pytest" in step.get("run", "")


@dataclass(frozen=True)
class Oracle:
    job: str
    var: str
    output: str  # the ci-image.yml output carrying the ref
    target: str  # the Dockerfile stage that builds it
    repository: str  # where the hash-tagged image is pushed
    runs_suite: Callable[[dict[str, Any]], bool]
    consumer: Path  # the suite file that reads `var`
    getenv: str  # how that file reads it
    recipe: Path  # the file holding the suite's own self-build Dockerfile text
    local_tag: str  # the image name a developer's self-build tags


GO_ORACLE = Oracle(
    job="go-quality",
    var="PFB_UNBOUND_IMAGE",
    output="unbound",
    target="unbound",
    repository="ghcr.io/pfblockerng/pfblockerng-ci-unbound",
    runs_suite=_gate_step,
    consumer=ROOT / "go/pfb_dns_gateway/acl_oracle_test.go",
    getenv='os.Getenv("PFB_UNBOUND_IMAGE")',
    recipe=ROOT / "go/pfb_dns_gateway/acl_oracle_test.go",
    local_tag="pfb-dns-frontend-unbound:trixie",
)
PY_ORACLE = Oracle(
    job="test",
    var="PFB_UNBOUND_PY_IMAGE",
    output="unbound_py",
    target="unbound-py",
    repository="ghcr.io/pfblockerng/pfblockerng-ci-unbound-py",
    runs_suite=_pytest_step,
    consumer=ROOT / "tests/dns_proxy/test_integration_unbound.py",
    getenv='os.environ.get("PFB_UNBOUND_PY_IMAGE")',
    recipe=ROOT / "tests/dns_proxy/test_integration_unbound.py",
    local_tag="pfb-dns-frontend-unbound:trixie-py",
)
ORACLES = [pytest.param(GO_ORACLE, id="go-oracle"), pytest.param(PY_ORACLE, id="dns-proxy-integration")]


def _stage(name: str) -> str:
    """The Dockerfile text from `FROM ... AS <name>` up to the next FROM."""
    for block in re.split(r"^(?=FROM )", DOCKERFILE, flags=re.MULTILINE):
        if re.match(rf"FROM \S+ AS {re.escape(name)}$", block.splitlines()[0]):
            return block
    pytest.fail(f"the Dockerfile has no `{name}` stage")


def _expr(value: object) -> str:
    return re.sub(r"\s+", "", str(value))


@pytest.mark.parametrize("oracle", ORACLES)
def test_ci_image_exposes_the_oracle_ref_built_from_its_dockerfile_target(oracle: Oracle) -> None:
    exposed = CALL_OUTPUTS.get(oracle.output, {}).get("value")
    assert _expr(exposed) == _expr(f"${{{{ jobs.build.outputs.{oracle.output} }}}}"), exposed
    job_output = CI_IMAGE["jobs"]["build"]["outputs"].get(oracle.output)
    assert _expr(job_output) == _expr(f"${{{{ steps.hash.outputs.{oracle.output} }}}}"), job_output

    hash_run = next(step["run"] for step in BUILD_STEPS if step.get("id") == "hash")
    tagged = dict(re.findall(r'"(\w+)=(\S+):\$hash"', hash_run))
    assert tagged.get(oracle.output) == oracle.repository, tagged

    # The build step's env var for this output must be the one that is inspected, built with the right
    # target and tagged: a ref that is checked but never built (or built under another target) skips a build it needs.
    build = next(step for step in BUILD_STEPS if "docker buildx build" in step.get("run", ""))
    ref_vars = [
        k for k, v in build["env"].items() if _expr(v) == _expr(f"${{{{ steps.hash.outputs.{oracle.output} }}}}")
    ]
    assert len(ref_vars) == 1, f"build step env maps {ref_vars} to the {oracle.output} output"
    ref = ref_vars[0]
    assert f'docker manifest inspect "${ref}"' in build["run"], "the skip check must require this image's manifest"
    assert re.search(rf'docker buildx build --target {oracle.target} -t "\${ref}" .*--push', build["run"]), build["run"]


@pytest.mark.parametrize("oracle", ORACLES)
def test_the_job_hands_the_ci_image_output_to_the_suite_through_ci_run(oracle: Oracle) -> None:
    job = TEST_JOBS[oracle.job]
    assert _expr(job["env"].get(oracle.var)) == _expr(f"${{{{ needs.ci-image.outputs.{oracle.output} }}}}")
    assert re.search(rf"-e {oracle.var}\s", job["env"]["CI_RUN"]), (
        f"CI_RUN does not pass {oracle.var}: {job['env']['CI_RUN']}"
    )


@pytest.mark.parametrize("oracle", ORACLES)
def test_the_oracle_image_is_pulled_before_the_suite_runs(oracle: Oracle) -> None:
    steps = TEST_JOBS[oracle.job]["steps"]
    pulls = [i for i, step in enumerate(steps) if step.get("run", "").strip() == f'$CI_RUN docker pull "${oracle.var}"']
    suites = [i for i, step in enumerate(steps) if oracle.runs_suite(step)]

    assert len(pulls) == 1, f"{oracle.job} must have exactly one pull step for ${oracle.var}, found {len(pulls)}"
    assert suites, f"{oracle.job} has no suite step; retarget this test"
    assert pulls[0] < min(suites), f"the pull is step {pulls[0]} but the suite starts at step {min(suites)}"


def test_the_go_gate_keeps_the_oracle_variable_through_sudo() -> None:
    """`sudo` resets the environment, so an unlisted variable is gone and the oracle self-builds."""
    oracle = GO_ORACLE
    gates = [step["env"]["GATE"] for step in TEST_JOBS["go-quality"]["steps"] if _gate_step(step)]
    assert len(gates) == 1
    kept = re.search(r'sudo -n --preserve-env=([\w,]+) "\$\(command -v go\)" test -race', gates[0])
    assert kept, 'the race run must be `sudo -n --preserve-env=<vars> "$(command -v go)" test -race ...`'
    assert oracle.var in kept.group(1).split(","), kept.group(1)


@pytest.mark.parametrize("oracle", ORACLES)
def test_the_suite_reads_the_variable_the_workflow_sets(oracle: Oracle) -> None:
    text = oracle.consumer.read_text(encoding="utf-8")
    assert oracle.getenv in text, f"{oracle.consumer.name} does not read {oracle.var}; CI would self-build"
    assert oracle.local_tag in text, "unset must still self-build under the local tag"


@pytest.mark.parametrize("oracle", ORACLES)
def test_the_dockerfile_target_is_a_labelled_stage_of_the_pinned_base(oracle: Oracle) -> None:
    stage = _stage(oracle.target)
    assert stage.splitlines()[0] == f"FROM ${{DEBIAN_IMAGE}} AS {oracle.target}"
    assert SOURCE_LABEL in stage, "without the source label GHCR does not link the package to this repository"


@pytest.mark.parametrize("oracle", ORACLES)
def test_the_prebuilt_unbound_is_the_one_the_self_build_recipe_installs(oracle: Oracle) -> None:
    """CI and a developer's local run must test the same Unbound: same Debian release, same packages."""
    recipes = PACKAGES.findall(oracle.recipe.read_text(encoding="utf-8"))
    built = PACKAGES.findall(_stage(oracle.target))
    assert len(recipes) == 1 and len(built) == 1, f"self-build recipes {recipes}, Dockerfile installs {built}"
    assert sorted(built[0].split()) == sorted(recipes[0].split())

    base = BASE_TAG.search(DOCKERFILE)
    recipe_base = BASE_TAG.search(oracle.recipe.read_text(encoding="utf-8"))
    assert base and recipe_base
    assert base.group(1) == recipe_base.group(1), (
        "the pinned base and the self-build recipe name different Debian releases"
    )
