"""Pin issue #4007: a devel change to a Go module's requirements is checked against the Nightly ports recipe.

The Nightly package is built from devel by the recipe on pfBlockerNG/FreeBSD-ports `pfblockerng/use-github`, whose
`files/modules.txt` must be byte-equal to `go mod vendor`'s for go/pfb_dns_gateway, or the build rejects the source.
#3987 bumped golang.org/x/sys to v0.50.0 while the recipe still listed v0.49.0; only the next nightly noticed, and
FreeBSD-ports#22 followed. `.github/workflows/ports-modules-txt.yml` catches that on the devel PR instead.

These tests run the workflow's REAL check step under sh, with `curl` and `go` replaced by stubs that serve fixture
files: the #3987 pair is the recipe's modules.txt before FreeBSD-ports#22 and `go mod vendor` output at #3987.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

from tests._workflow_steps import extract_job, extract_step

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ports-modules-txt.yml"
FIXTURES = "tests/fixtures/ports_modules_txt/issue3987"
PORTS_BEFORE_22 = ROOT / FIXTURES / "ports-nightly-modules.txt"  # x/sys v0.49.0
VENDOR_AT_3987 = ROOT / FIXTURES / "go-mod-vendor-modules.txt"  # x/sys v0.50.0
PORTS_URL = (
    "https://api.github.com/repos/pfBlockerNG/FreeBSD-ports/contents/"
    "net/pfSense-pkg-pfBlockerNG-nightly/files/modules.txt?ref=pfblockerng/use-github"
)

_FAKE_CURL = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
out=
while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done
cp "$PORTS_SERVED" "$out"
"""
_FAKE_GO = """#!/bin/sh
printf 'go %s in %s\\n' "$*" "$PWD" >> "$STUB_LOG"
[ "$1 $2 $3" = "mod vendor -o" ] || exit 2
mkdir -p "$4"
cp "$VENDOR_SERVED" "$4/modules.txt"
"""


def _check_script() -> str:
    """The `Compare` step's `run: |` body, parsed by YAML so block-scalar rules match what Actions runs."""
    step = extract_step(extract_job(WORKFLOW.read_text(encoding="utf-8"), "nightly-modules-txt"), "Compare")
    return yaml.safe_load("- name: Compare\n" + textwrap.indent(textwrap.dedent(step), "  "))[0]["run"]


def _run_check(
    tmp_path: Path, ports: Path, vendor: Path, fixtures: Path = ROOT / FIXTURES
) -> tuple[subprocess.CompletedProcess[str], str, Path]:
    tree, bin_dir = tmp_path / "tree", tmp_path / "bin"
    shutil.copytree(fixtures, tree / FIXTURES)
    (tree / "go/pfb_dns_gateway").mkdir(parents=True)
    bin_dir.mkdir()
    for name, body in (("curl", _FAKE_CURL), ("go", _FAKE_GO)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    log = tmp_path / "stub.log"
    result = subprocess.run(  # noqa: S603
        ["bash", "-e", "-c", _check_script()],  # noqa: S607 - Actions' default `run:` shell on ubuntu runners
        cwd=tree,
        env={
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "GH_TOKEN": "fixture-token",
            "STUB_LOG": str(log),
            "PORTS_SERVED": str(ports),
            "VENDOR_SERVED": str(vendor),
        },
        capture_output=True,
        text=True,
    )
    return result, (log.read_text() if log.exists() else ""), tree


def test_the_3987_drift_fails_the_devel_pr_naming_the_ports_follow_up(tmp_path: Path) -> None:
    """Scenario: devel vendors x/sys v0.50.0 (#3987) while the Nightly recipe still lists v0.49.0.
    Then the check fails, shows the differing module line, and names the ports change that must follow."""
    result, _log, _tree = _run_check(tmp_path, PORTS_BEFORE_22, VENDOR_AT_3987)
    out = result.stdout + result.stderr
    assert result.returncode != 0, out
    assert "-# golang.org/x/sys v0.49.0" in out, out
    assert "+# golang.org/x/sys v0.50.0" in out, out
    errors = [line for line in out.splitlines() if line.startswith("::error::")]
    assert len(errors) == 1, out
    for named in (
        "pfBlockerNG/FreeBSD-ports",
        "pfblockerng/use-github",
        "net/pfSense-pkg-pfBlockerNG-nightly/files/modules.txt",
        "GH_TUPLE/GL_TUPLE",
    ):
        assert named in errors[0], errors[0]


def test_a_recipe_matching_go_mod_vendor_passes_and_compares_the_live_branch(tmp_path: Path) -> None:
    result, log, tree = _run_check(tmp_path, VENDOR_AT_3987, VENDOR_AT_3987)
    assert result.returncode == 0, result.stdout + result.stderr
    assert PORTS_URL in log, log
    assert "go mod vendor -o " in log and f" in {tree / 'go/pfb_dns_gateway'}\n" in log, log


@pytest.mark.parametrize("fixture", ["ports-nightly-modules.txt", "go-mod-vendor-modules.txt"])
def test_the_red_canary_stops_the_job_when_the_3987_pair_no_longer_differs(tmp_path: Path, fixture: str) -> None:
    """The in-job canary must refuse to grade the tree once the comparison cannot fail on #3987's drift."""
    neutered = tmp_path / "fixtures"
    shutil.copytree(ROOT / FIXTURES, neutered)
    other = "go-mod-vendor-modules.txt" if fixture == "ports-nightly-modules.txt" else "ports-nightly-modules.txt"
    shutil.copy(neutered / other, neutered / fixture)
    result, log, _tree = _run_check(tmp_path, VENDOR_AT_3987, VENDOR_AT_3987, fixtures=neutered)
    out = result.stdout + result.stderr
    assert result.returncode != 0, out
    assert "red canary" in out, out
    assert log == "", log  # nothing fetched or vendored: the canary runs first


def test_the_check_runs_on_devel_prs_that_change_a_go_module_requirement() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    trigger = workflow[True]["pull_request"]  # PyYAML (YAML 1.1) reads the `on:` key as True
    assert trigger["branches"] == ["devel"], trigger
    assert {"go/**/go.mod", "go/**/go.sum"} <= set(trigger["paths"]), trigger
