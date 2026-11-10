"""Issue #2166 — the channel a workflow builds, and the package identity that follows it.

`scripts/build-pkg-portable.py` owns the channel vocabulary (`_CHANNEL_PORT_SUB`, which
also drives the port origin `net/pfSense-pkg-pfBlockerNG-<channel>` and therefore the built
package's NAME). When that vocabulary was renamed (`devel` -> `testing`/`edge`/`nightly`),
the workflows that pass `channel:` into build-pkg-linux.yml kept the retired name, and every
repo-install leg died at argparse (`invalid choice: 'devel'`) before a single .pkg was built.

Two consumers hard-code that vocabulary and must not drift from the builder again:

* the workflows, pinned here against the builder's own channel set; and
* the live-install smoke modules, which install the built .pkg BY NAME — so they read the
  name off the artifact (`tests/smoke/pkg_identity.py`) instead of spelling a channel suffix.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"

_spec = importlib.util.spec_from_file_location("build_pkg_portable", ROOT / "scripts/build-pkg-portable.py")
assert _spec and _spec.loader
_builder = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _builder  # the module's dataclasses resolve their own module by name
_spec.loader.exec_module(_builder)

VALID_CHANNELS = frozenset(_builder._CHANNEL_PORT_SUB)


def _pkg_identity() -> ModuleType:
    """Load tests/smoke/pkg_identity.py by path — importing the smoke PACKAGE would drag in
    tests/smoke/conftest.py and its dnspython/requests deps, which the default tier
    (`--ignore=tests/smoke`) deliberately does not install."""
    spec = importlib.util.spec_from_file_location("pfb_pkg_identity", ROOT / "tests/smoke/pkg_identity.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# `channel: testing` (a call site) and the `default: "testing"` of a `channel:` input.
# A `${{ ... }}` value is resolved at run time and carries no literal to check.
_CALL_SITE = re.compile(r'^\s*channel:\s*["\']?([A-Za-z0-9_.-]+)["\']?\s*(?:#.*)?$')
_CHANNEL_KEY = re.compile(r"^(\s*)channel:\s*(?:#.*)?$")
_DEFAULT = re.compile(r'^\s*default:\s*["\']?([A-Za-z0-9_.-]+)["\']?\s*(?:#.*)?$')
# A `run:` step that assembles the channel in shell and dispatches it (version-tracker.yml's
# `PKG_CHANNEL="edge"` -> `gh workflow run build-pkg-linux.yml --field channel=...`). The YAML
# scanners above never see these, and a stale one costs a red workflow run a day.
_SHELL_ASSIGN = re.compile(r'^\s*[A-Z_]*CHANNEL=["\']?([a-z][A-Za-z0-9_.-]*)["\']?\s*(?:#.*)?$')


def _channel_literals() -> list[tuple[str, int, str]]:
    """Every hard-coded channel value in the workflows, as (file, line number, value)."""
    found: list[tuple[str, int, str]] = []
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        lines = workflow.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            call_site = _CALL_SITE.match(line) or _SHELL_ASSIGN.match(line)
            if call_site:
                found.append((workflow.name, index + 1, call_site.group(1)))
                continue
            key = _CHANNEL_KEY.match(line)
            if not key:
                continue
            indent = len(key.group(1))
            for follower in lines[index + 1 :]:
                if follower.strip() and len(follower) - len(follower.lstrip()) <= indent:
                    break  # left the `channel:` input block
                default = _DEFAULT.match(follower)
                if default:
                    found.append((workflow.name, index + 1, default.group(1)))
                    break
    return found


def test_workflows_hard_code_at_least_one_channel() -> None:
    """Guard the scanner itself: a regex that matches nothing would pass every assertion."""
    assert _channel_literals(), "no literal channel value found in .github/workflows — scanner is broken"


def test_smoke_modules_never_hard_code_a_channel_suffixed_package_name() -> None:
    """The live-install constants must follow the artifact, not a channel spelled by hand.

    A `PKG_NAME = "pfSense-pkg-pfBlockerNG-devel"` survives every rename silently and then
    fails on the VM at `pkg install`, one leg at a time, long after the build went green.
    """
    assignment = re.compile(r'^\s*_?[A-Z_]*NAME\s*=\s*["\']pfSense-pkg-pfBlockerNG-([a-z]+)["\']')
    hard_coded = [
        f"{path.name}:{number} pins {match.group(1)!r}"
        for path in sorted((ROOT / "tests/smoke").glob("test_*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if (match := assignment.match(line)) and match.group(1) != "nightly"
    ]
    assert not hard_coded, (
        "smoke modules must take the branch package name from the built .pkg "
        "(pkg_identity.branch_pkg_name), not a hard-coded channel suffix:\n  " + "\n  ".join(hard_coded)
    )


def test_smoke_modules_never_hard_code_the_channel_the_build_reports() -> None:
    """A live case that asserts on the channel must derive it, for the same reason.

    `assert cache.get("channel") == "devel"` outlives the rename exactly as silently as a
    hard-coded package name, and fails on the VM instead of here (issue #2166 review round 3).
    """
    # Both comparison senses, dict/bracket access, and the notice text the box emits.
    channel_literal = re.compile(r"""(?:channel["']?\]?\)?\s*[!=]=\s*|available \()["']?(devel|testing|edge)\b""")
    hard_coded = [
        f"{path.name}:{number}: {line.strip()[:70]}"
        for path in sorted((ROOT / "tests/smoke").glob("test_*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if channel_literal.search(line)
    ]
    assert not hard_coded, (
        "smoke cases must take the channel from the built .pkg (pkg_identity.branch_channel), "
        "not a hard-coded channel name:\n  " + "\n  ".join(hard_coded)
    )


def test_branch_channel_reads_the_channel_off_the_built_artifact() -> None:
    """The channel a build reports is the suffix of the package it installs as."""
    branch_channel = _pkg_identity().branch_channel
    assert branch_channel("/out/pfSense-pkg-pfBlockerNG-edge-4.0.0.a24.pkg") == "edge"
    assert branch_channel("/out/pfSense-pkg-pfBlockerNG-testing-3.2.15.pkg") == "testing"
    assert branch_channel("/out/pfSense-pkg-pfBlockerNG-3.2.15.pkg") == "stable"
    assert branch_channel(None) == _pkg_identity().DEFAULT_CHANNEL


def test_branch_pkg_name_reads_the_name_off_the_built_artifact() -> None:
    """`<name>-<version>.pkg` — the version always starts with a digit, the name never does."""
    branch_pkg_name = _pkg_identity().branch_pkg_name
    assert branch_pkg_name("/out/pfSense-pkg-pfBlockerNG-edge-4.0.0.a24.pkg") == "pfSense-pkg-pfBlockerNG-edge"
    assert branch_pkg_name("/out/pfSense-pkg-pfBlockerNG-3.2.15.pkg") == "pfSense-pkg-pfBlockerNG"
    assert branch_pkg_name("/out/pfSense-pkg-pfBlockerNG-nightly-20260804.pkg") == "pfSense-pkg-pfBlockerNG-nightly"


def test_branch_pkg_name_rejects_an_artifact_it_cannot_read() -> None:
    """A SMOKE_PKG that is not a pfBlockerNG .pkg must fail loudly.

    Falling back to the default channel there would hand the caller a name the artifact does
    not have — the same silent drift this module exists to stop, one level removed.
    """
    branch_pkg_name = _pkg_identity().branch_pkg_name
    for hostile in ("/out/some-other-port-1.2.3.pkg", "/out/pfSense-pkg-pfBlockerNG-edge-4.0.0.a24.txz", "/out/x"):
        try:
            name = branch_pkg_name(hostile)
        except ValueError:
            continue
        raise AssertionError(f"branch_pkg_name({hostile!r}) silently returned {name!r} instead of raising")


def test_branch_pkg_name_falls_back_to_the_channel_ci_actually_builds() -> None:
    """No SMOKE_PKG (collection on a dev box) still has to name the package CI produces."""
    defaults = {value for name, _, value in _channel_literals() if name == "build-pkg-linux.yml"}
    assert len(defaults) == 1, f"build-pkg-linux.yml's dispatch and call defaults disagree: {sorted(defaults)}"
    assert _pkg_identity().branch_pkg_name(None) == f"pfSense-pkg-pfBlockerNG-{defaults.pop()}"


def test_every_workflow_channel_literal_is_a_builder_channel() -> None:
    stale = [
        f"{name}:{line} passes channel {value!r}"
        for name, line, value in _channel_literals()
        if value not in VALID_CHANNELS
    ]
    assert not stale, (
        "workflows pass a channel build-pkg-portable.py rejects "
        f"(valid: {sorted(VALID_CHANNELS)}):\n  " + "\n  ".join(stale)
    )


# Devel pairs with the -nightly port (issue #3791); release lines keep their own channel through
# release*.yml and the prebuilt-artifact path, so none of these entry points may default to edge.
_DEVEL_BUILD_WORKFLOWS = (
    "build-pkg-linux.yml",
    "build-image.yml",
    "smoke.yml",
    "smoke-single.yml",
    "ui-tests.yml",
    "version-tracker.yml",
)


def test_devel_build_and_smoke_workflows_default_to_nightly() -> None:
    channels: dict[str, set[str]] = {name: set() for name in _DEVEL_BUILD_WORKFLOWS}
    for name, _, value in _channel_literals():
        if name in channels:
            channels[name].add(value)
    assert channels == {name: {"nightly"} for name in _DEVEL_BUILD_WORKFLOWS}


def test_smoke_fan_out_ports_checkout_is_overridable_by_dispatch_and_call() -> None:
    """A pre-landing run builds against an unmerged ports commit, as ui-tests.yml already allows."""
    workflow = yaml.safe_load((WORKFLOWS / "smoke.yml").read_text(encoding="utf-8"))
    triggers = workflow[True]  # PyYAML reads the bare `on:` key as the boolean True
    for trigger in ("workflow_dispatch", "workflow_call"):
        assert {"ports_repo", "ports_ref"} <= set(triggers[trigger]["inputs"]), trigger
    build_with = workflow["jobs"]["build-pkg"]["with"]
    assert build_with["ports_repo"] == "${{ inputs.ports_repo || 'pfBlockerNG/FreeBSD-ports' }}"
    assert build_with["ports_ref"] == "${{ inputs.ports_ref || 'pfblockerng/use-github' }}"


def test_version_above_outranks_the_installed_version_on_every_channel() -> None:
    """A seeded "latest" must sit above what is installed, whatever the channel (issue #3791).

    A nightly package version is ``YYYYMMDDHHMMSS.<7-sha>``, which outranks a fixed ``99.0.0``,
    so a fixture seeding that constant offers no update on a nightly build.
    """
    version_above = _pkg_identity().version_above
    assert version_above("20261110120000.abcdef0") == "20261110120001.abcdef0"
    assert version_above("20261110120000") == "20261110120001"
    assert version_above("4.0.0.b1") == "99.0.0"
    assert version_above("") == "99.0.0"


def test_conflict_counterpart_is_never_the_nightly_package() -> None:
    """The nightly conflict cases need a package of ANOTHER channel (issue #3791).

    The branch package is the nightly one now, so installing it "over" the nightly package is
    a no-op and the case can never meet its precondition.
    """
    identity = _pkg_identity()
    for branch in (
        "pfSense-pkg-pfBlockerNG-nightly",
        "pfSense-pkg-pfBlockerNG-edge",
        "pfSense-pkg-pfBlockerNG-testing",
        "pfSense-pkg-pfBlockerNG",
    ):
        assert identity.counterpart_name(branch) != identity.NIGHTLY_NAME, branch
    assert identity.counterpart_name("pfSense-pkg-pfBlockerNG-nightly") == "pfSense-pkg-pfBlockerNG-edge"
    assert identity.counterpart_name("pfSense-pkg-pfBlockerNG-testing") == "pfSense-pkg-pfBlockerNG-testing"
