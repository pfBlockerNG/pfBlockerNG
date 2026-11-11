import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/test.yml"
DOCKERFILE = ROOT / ".github/docker/Dockerfile"
NODE_JOBS = ("widget-js-tests", "webassets-vendor")
NODE_PIN = "24.19.0"
CI_IMAGE = re.compile(r"^\$\{\{\s*needs\.ci-image\.outputs\.ci\s*\}\}$")


def test_native_junit_jobs_run_on_the_image_that_pins_node() -> None:
    """Native JUnit needs Node 24.19.0. The jobs get it from the ci image, whose build fails on a
    mismatch, instead of a setup-node step that could fall back to an unpinned runtime."""
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert re.search(rf"^ARG NODE_VERSION={re.escape(NODE_PIN)}$", dockerfile, re.MULTILINE), (
        f"the ci image must bake Node {NODE_PIN}: native JUnit requires it"
    )
    assert '[ "$(node --version)" = "v${NODE_VERSION}" ]' in dockerfile, "the image build must fail on a wrong Node"

    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    for job_name in NODE_JOBS:
        image = (jobs[job_name].get("container") or {}).get("image", "")
        assert CI_IMAGE.match(image), f"{job_name}: must run in the ci image that bakes Node {NODE_PIN}, got {image!r}"
