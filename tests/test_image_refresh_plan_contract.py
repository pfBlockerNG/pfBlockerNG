"""image-refresh.yml plan-job contract (issue #1820).

Runs the REAL 'Build refresh matrix from ci-metadata' step script (extracted
from the workflow YAML, executed with a fake `git` serving a fixture matrix)
and asserts the emitted strategy matrix:

  - upgrade.available gates a refresh leg REGARDLESS of the entry's `ci` flag
    (the version tracker refreshes the latest image per channel; smoke fan-out
    eligibility is a separate concern);
  - SELF_REFRESH=true emits from==to `--force` legs for the newest amd64 entry
    per channel (patch/GA re-publish under the same floating tag), ignoring
    upgrade.available;
  - route-only and aarch64 entries never produce a leg (no ARM smoke image).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "image-refresh.yml"
STEP_NAME = "Build refresh matrix from ci-metadata"


def _entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "active",
        "ci": True,
        "upgrade": {"available": False},
    }
    base.update(overrides)
    return base


def _run_plan(
    tmp_path: Path,
    versions: list[dict[str, Any]],
    *,
    filter_version: str = "",
    self_refresh: str = "",
    direct_leg: str = "",
) -> dict[str, Any]:
    """Extract the plan step's run script and execute it against a fixture."""
    source = WORKFLOW.read_text(encoding="utf-8")
    step = source.split(f"      - name: {STEP_NAME}\n", 1)[1].split("\n      - name:", 1)[0]
    # The run-block body is every ≥10-space-indented line after `run: |`; the
    # first shallower line ends it (this step is the last of its job, so a
    # step-boundary split alone would leak the next job's YAML into the script).
    body: list[str] = []
    for line in step.split("        run: |\n", 1)[1].splitlines():
        if not line.strip():
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    script = "\n".join(body)

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps({"versions": versions}), encoding="utf-8")
    fake_git = tmp_path / "git"
    fake_git.write_text(
        """#!/bin/sh
case "$1" in
  fetch) exit 0 ;;
  show)  cat "$FAKE_MATRIX" ;;
esac
""",
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    out_file = tmp_path / "gh-output"
    out_file.write_text("", encoding="utf-8")

    env = os.environ | {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "FAKE_MATRIX": str(matrix_file),
        "FILTER_VERSION": filter_version,
        "SELF_REFRESH": self_refresh,
        "DIRECT_LEG": direct_leg,
        "GITHUB_OUTPUT": str(out_file),
    }
    subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, check=True, capture_output=True, text=True)

    outputs: dict[str, str] = {}
    for line in out_file.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        outputs[key] = value
    matrix = json.loads(outputs["matrix"])
    assert json.loads(outputs["count"]) == len(matrix["include"])
    return matrix


class TestBareDispatch:
    """Scenario (issue #1823): the retired upgrade.available matrix mode plans
    NOTHING — legs come only from a direct_leg dispatch (the reconcile loop) or
    an explicit self_refresh run."""

    def test_bare_dispatch_plans_no_legs_even_with_available_flags(self, tmp_path: Path) -> None:
        versions = [
            _entry(upgrade={"available": True}),
            _entry(
                pfsense_version="26.07",
                channel="Plus",
                variant="Plus",
                status="beta",
                ci=False,
                image_name="pfsense-plus",
                upgrade={"available": True, "from": "26.03", "branch": "26.07"},
            ),
        ]
        matrix = _run_plan(tmp_path, versions)
        assert matrix["include"] == []


class TestDirectLeg:
    """Scenario (issue #1823): the reconcile loop dispatches one fully-specified
    leg as JSON; the plan validates and passes it through verbatim."""

    LEG = {
        "variant": "plus",
        "label": "Plus",
        "pfsense_version": "26.07",
        "freebsd_version": "16.0-RELEASE",
        "image_name": "pfsense-plus",
        "branch": "26.07",
        "target": "26.07",
        "from": "26.03",
        "force_flag": "",
    }

    def test_valid_direct_leg_passes_through(self, tmp_path: Path) -> None:
        matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(self.LEG))
        assert matrix["include"] == [self.LEG]

    def test_direct_leg_overrides_self_refresh(self, tmp_path: Path) -> None:
        # A dispatch carrying both inputs is a caller bug; direct wins (explicit
        # beats derived) and exactly one leg runs
        matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(self.LEG), self_refresh="true")
        assert matrix["include"] == [self.LEG]

    def test_garbage_direct_leg_plans_nothing(self, tmp_path: Path) -> None:
        matrix = _run_plan(tmp_path, [_entry()], direct_leg="not json {")
        assert matrix["include"] == []

    def test_incomplete_direct_leg_plans_nothing(self, tmp_path: Path) -> None:
        # Missing required fields (e.g. image_name) must not produce a leg
        leg = {k: v for k, v in self.LEG.items() if k != "image_name"}
        matrix = _run_plan(tmp_path, [_entry()], direct_leg=json.dumps(leg))
        assert matrix["include"] == []


class TestSelfRefreshLegs:
    """Scenario: SELF_REFRESH=true → newest amd64 entry per channel gets a
    from==to --force leg (same floating tag re-publish), upgrade.available ignored."""

    def test_self_refresh_emits_from_equals_to_force_leg(self, tmp_path: Path) -> None:
        versions = [
            _entry(
                pfsense_version="26.03",
                channel="Plus",
                variant="Plus",
                image_name="pfsense-plus",
                upgrade={"available": False},
            )
        ]
        matrix = _run_plan(tmp_path, versions, filter_version="26.03", self_refresh="true")
        assert len(matrix["include"]) == 1
        leg = matrix["include"][0]
        assert leg["pfsense_version"] == "26.03"
        assert leg["from"] == "26.03"
        assert leg["target"] == "26.03"
        assert leg["branch"] == ""
        assert leg["force_flag"] == "--force"
        assert leg["image_name"] == "pfsense-plus"

    def test_self_refresh_without_filter_picks_latest_per_channel(self, tmp_path: Path) -> None:
        versions = [
            _entry(upgrade={"available": False}),  # CE 2.8
            _entry(pfsense_version="2.7", upgrade={"available": False}),
            _entry(
                pfsense_version="26.03",
                channel="Plus",
                variant="Plus",
                image_name="pfsense-plus",
                upgrade={"available": False},
            ),
            _entry(
                pfsense_version="26.07",
                channel="Plus",
                variant="Plus",
                status="beta",
                ci=False,
                image_name="pfsense-plus",
                upgrade={"available": False},
            ),
        ]
        matrix = _run_plan(tmp_path, versions, self_refresh="true")
        legs = {leg["variant"]: leg["pfsense_version"] for leg in matrix["include"]}
        assert legs == {"ce": "2.8", "plus": "26.07"}

    def test_self_refresh_skips_aarch64_duplicate(self, tmp_path: Path) -> None:
        versions = [
            _entry(
                pfsense_version="26.03",
                channel="Plus",
                variant="Plus",
                image_name="pfsense-plus",
                upgrade={"available": False},
            ),
            _entry(
                pfsense_version="26.03",
                channel="Plus",
                variant="Plus",
                ci=False,
                arch="aarch64",
                image_name="pfsense-plus",
                upgrade={"available": False},
            ),
        ]
        matrix = _run_plan(tmp_path, versions, self_refresh="true")
        assert len(matrix["include"]) == 1
        assert matrix["include"][0]["pfsense_version"] == "26.03"
