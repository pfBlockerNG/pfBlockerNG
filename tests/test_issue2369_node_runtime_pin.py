from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/test.yml"
NODE_JOBS = ("widget-js-tests", "webassets-vendor")


def test_native_junit_jobs_pin_node_runtime_and_require_setup_success() -> None:
    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]

    for job_name in NODE_JOBS:
        setups = [
            step for step in jobs[job_name]["steps"] if str(step.get("uses", "")).startswith("actions/setup-node@")
        ]
        assert len(setups) == 1, f"{job_name}: expected exactly one setup-node step, got {len(setups)}"
        setup = setups[0]
        assert setup.get("with", {}).get("node-version") == "24.19.0", f"{job_name}: native JUnit requires Node 24.19.0"
        assert setup.get("continue-on-error", False) is False, (
            f"{job_name}: setup-node failure must block instead of falling back to an unpinned runtime"
        )
