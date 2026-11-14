"""Pin issue #4007: a devel change to a Go module's requirements is checked against the Nightly ports recipe.

The Nightly package is built from devel by the recipe on pfBlockerNG/FreeBSD-ports `pfblockerng/use-github`. Two
things there must follow devel, or the build rejects the source:

* `files/modules.txt` must be byte-equal to `go mod vendor`'s for go/pfb_dns_gateway. #3987 bumped
  golang.org/x/sys to v0.50.0 while the recipe still listed v0.49.0; FreeBSD-ports#22 followed.
* the GH_TUPLE entries under go/pfb_core/vendor must be the modules go/pfb_core's own go.mod requires beyond the
  gateway's (github.com/pfBlockerNG/xxh3). #3929 made Core require xxh3 before the recipe carried it;
  FreeBSD-ports#20 followed.

`.github/workflows/ports-modules-txt.yml` catches both on the devel PR. These tests run the workflow's REAL check
step under bash, with `curl` and `go` replaced by stubs that serve fixture files (recipe files at the named
FreeBSD-ports commits, `go mod vendor` output and Core's go.mod at the named devel commits).
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
FIXTURES = "tests/fixtures/ports_modules_txt"
I3987 = ROOT / FIXTURES / "issue3987"
I3929 = ROOT / FIXTURES / "issue3929"
PORTS_BEFORE_22 = I3987 / "ports-nightly-modules.txt"  # x/sys v0.49.0
VENDOR_AT_3987 = I3987 / "go-mod-vendor-modules.txt"  # x/sys v0.50.0, == the recipe's modules.txt at #22
MAKEFILE_AT_22 = I3987 / "ports-nightly-Makefile-at-22"  # x/sys v0.50.0 and the xxh3 tuple
MAKEFILE_BEFORE_20 = I3929 / "ports-nightly-Makefile-before-20"  # no xxh3 tuple
MODULES_BEFORE_20 = I3929 / "ports-nightly-modules.txt"  # the recipe's modules.txt then (== #20's)
CORE_GO_MOD_AT_3929 = I3929 / "source/go/pfb_core/go.mod"  # requires xxh3 v1.1.1-pfblockerng.1
_CONTENTS = "https://api.github.com/repos/pfBlockerNG/FreeBSD-ports/contents/net/pfSense-pkg-pfBlockerNG-nightly/"
MODULES_URL = _CONTENTS + "files/modules.txt?ref=pfblockerng/use-github"
MAKEFILE_URL = _CONTENTS + "Makefile?ref=pfblockerng/use-github"

# Serves the recipe's Makefile or modules.txt by the URL asked for, as the contents API would.
_FAKE_CURL = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
out=
src="$MODULES_SERVED"
for a in "$@"; do case "$a" in *"/Makefile?"*) src="$MAKEFILE_SERVED" ;; esac; done
while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done
cp "$src" "$out"
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
    tmp_path: Path,
    *,
    modules: Path,
    vendor: Path,
    makefile: Path = MAKEFILE_AT_22,
    core_go_mod: Path = CORE_GO_MOD_AT_3929,
    fixtures: Path = ROOT / FIXTURES,
) -> tuple[subprocess.CompletedProcess[str], str, Path]:
    tree, bin_dir = tmp_path / "tree", tmp_path / "bin"
    shutil.copytree(fixtures, tree / FIXTURES)
    (tree / "scripts").symlink_to(ROOT / "scripts")
    (tree / "go/pfb_dns_gateway").mkdir(parents=True)
    (tree / "go/pfb_core").mkdir()
    shutil.copy(core_go_mod, tree / "go/pfb_core/go.mod")
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
            "MODULES_SERVED": str(modules),
            "MAKEFILE_SERVED": str(makefile),
            "VENDOR_SERVED": str(vendor),
        },
        capture_output=True,
        text=True,
    )
    return result, (log.read_text() if log.exists() else ""), tree


def _one_error(out: str) -> str:
    errors = [line for line in out.splitlines() if line.startswith("::error::")]
    assert len(errors) == 1, out
    return errors[0]


def test_the_3987_drift_fails_the_devel_pr_naming_the_ports_follow_up(tmp_path: Path) -> None:
    """Scenario: devel vendors x/sys v0.50.0 (#3987) while the Nightly recipe still lists v0.49.0.
    Then the check fails, shows the differing module line, and names the ports change that must follow."""
    result, _log, _tree = _run_check(tmp_path, modules=PORTS_BEFORE_22, vendor=VENDOR_AT_3987)
    out = result.stdout + result.stderr
    assert result.returncode != 0, out
    assert "-# golang.org/x/sys v0.49.0" in out, out
    assert "+# golang.org/x/sys v0.50.0" in out, out
    error = _one_error(out)
    for named in (
        "pfBlockerNG/FreeBSD-ports",
        "pfblockerng/use-github",
        "net/pfSense-pkg-pfBlockerNG-nightly/files/modules.txt",
        "GH_TUPLE/GL_TUPLE",
    ):
        assert named in error, error


def test_the_3929_core_drift_fails_the_devel_pr_naming_the_ports_follow_up(tmp_path: Path) -> None:
    """Scenario: Core requires github.com/pfBlockerNG/xxh3 (#3929) while the recipe has no GH_TUPLE for it yet.
    Given a gateway whose modules.txt matches the recipe (so only Core drifts),
    Then the check fails naming the module and the recipe Makefile change that must follow (FreeBSD-ports#20)."""
    result, log, _tree = _run_check(
        tmp_path, modules=MODULES_BEFORE_20, vendor=MODULES_BEFORE_20, makefile=MAKEFILE_BEFORE_20
    )
    out = result.stdout + result.stderr
    assert result.returncode != 0, out
    assert MAKEFILE_URL in log, log
    error = _one_error(out)
    for named in (
        "github.com/pfBlockerNG/xxh3 v1.1.1-pfblockerng.1",
        "pfBlockerNG/FreeBSD-ports",
        "pfblockerng/use-github",
        "net/pfSense-pkg-pfBlockerNG-nightly/Makefile",
        "go/pfb_core",
    ):
        assert named in error, error


def test_a_pr_moving_cores_own_module_fails_against_the_unchanged_recipe(tmp_path: Path) -> None:
    """Scenario: this PR's go/pfb_core/go.mod bumps xxh3 while the recipe (FreeBSD-ports#22) still names the old tag.
    Then the check reads the PR tree's Core go.mod, not a fixture's, and fails naming both versions."""
    bumped = tmp_path / "go.mod"
    bumped.write_text(CORE_GO_MOD_AT_3929.read_text().replace("xxh3 v1.1.1-pfblockerng.1", "xxh3 v1.2.0-pfblockerng.1"))
    result, _log, _tree = _run_check(tmp_path, modules=VENDOR_AT_3987, vendor=VENDOR_AT_3987, core_go_mod=bumped)
    out = result.stdout + result.stderr
    assert result.returncode != 0, out
    error = _one_error(out)
    assert "go.mod only: github.com/pfBlockerNG/xxh3 v1.2.0-pfblockerng.1" in error, error
    assert "GH_TUPLE only: github.com/pfBlockerNG/xxh3 v1.1.1-pfblockerng.1" in error, error


def test_a_recipe_matching_devel_passes_and_compares_the_live_branch(tmp_path: Path) -> None:
    """The recipe at FreeBSD-ports#22 against devel at #3987: modules.txt and Core's xxh3 tuple both agree."""
    result, log, tree = _run_check(tmp_path, modules=VENDOR_AT_3987, vendor=VENDOR_AT_3987)
    assert result.returncode == 0, result.stdout + result.stderr
    assert MODULES_URL in log, log
    assert MAKEFILE_URL in log, log
    assert "go mod vendor -o " in log and f" in {tree / 'go/pfb_dns_gateway'}\n" in log, log


@pytest.mark.parametrize(
    ("fixture", "replacement"),
    [
        ("issue3987/ports-nightly-modules.txt", "issue3987/go-mod-vendor-modules.txt"),
        ("issue3987/go-mod-vendor-modules.txt", "issue3987/ports-nightly-modules.txt"),
        ("issue3929/ports-nightly-Makefile-before-20", "issue3929/ports-nightly-Makefile-after-20"),
    ],
)
def test_a_red_canary_stops_the_job_when_its_drift_no_longer_fails(
    tmp_path: Path, fixture: str, replacement: str
) -> None:
    """Each in-job canary must refuse to grade the tree once its comparison cannot fail on its recorded drift."""
    neutered = tmp_path / "fixtures"
    shutil.copytree(ROOT / FIXTURES, neutered)
    shutil.copy(neutered / replacement, neutered / fixture)
    result, log, _tree = _run_check(tmp_path, modules=VENDOR_AT_3987, vendor=VENDOR_AT_3987, fixtures=neutered)
    out = result.stdout + result.stderr
    assert result.returncode != 0, out
    assert "red canary" in _one_error(out), out
    assert log == "", log  # nothing fetched or vendored: the canaries run first


def test_the_check_runs_on_devel_prs_that_can_change_what_the_recipe_must_carry() -> None:
    """modules.txt follows go.mod/go.sum and also the gateway's imports: a new import of another package of an
    already-required module adds its line with go.mod and go.sum untouched. Core's own modules follow its go.mod."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    trigger = workflow[True]["pull_request"]  # PyYAML (YAML 1.1) reads the `on:` key as True
    assert trigger["branches"] == ["devel"], trigger
    assert {"go/**/go.mod", "go/**/go.sum", "go/pfb_dns_gateway/**/*.go"} <= set(trigger["paths"]), trigger
