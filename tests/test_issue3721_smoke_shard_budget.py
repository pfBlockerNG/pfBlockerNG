"""Issue #3721: the smoke shard plan plus the apt step fit the 45-minute job limit.

A stalled mirror ate 24-27 minutes of the job's budget before pytest started, so the apt step
is bounded: every apt-get call retries and times out quickly, and the step itself has a hard
cap. The cap is only meaningful if the longest planned shard still fits behind it, so the
budget is asserted as a sum. The per-module duration rows that keep the plan balanced are
guarded by ``test_every_smoke_module_has_a_duration_row`` in ``test_shard_union.py``.

Issue #3744: the bound alone fails a shard on a stalled mirror, so the download itself leaves the
critical path: apt skips the recommended GUI/audio packages and the downloaded ``.deb`` files
ride an ``actions/cache`` entry keyed on the runner image and the package list.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SHARD_SCRIPT = ROOT / "scripts" / "shard-modules.sh"
SMOKE_DIR = "tests/smoke"
DURATIONS = ROOT / SMOKE_DIR / "module-durations.txt"
WORKFLOW = ROOT / ".github" / "workflows" / "smoke-single.yml"

SHARD_TOTAL = 3  # the smoke.yml fan-out's per-leg shard count
JOB_LIMIT_S = 45 * 60
FIXED_OVERHEAD_S = 120  # VM boot, .pkg install and the two .pkg builds around pytest
APT_STEP_CAP_MINUTES = 5  # a healthy install takes about 17 s
APT_BOUND_PAIRS = (("-o", "Acquire::Retries=3"), ("-o", "Acquire::http::Timeout=20"))


def _weights() -> dict[str, float]:
    rows: dict[str, float] = {}
    for line in DURATIONS.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            key, weight = line.rsplit(None, 1)
            rows[key] = float(weight)
    return rows


def _planned_seconds(shard: int) -> float:
    """Load the splitter plans for one shard: module rows, minus tests deselected off it, plus bare node ids."""
    done = subprocess.run(
        ["sh", str(SHARD_SCRIPT), SMOKE_DIR, str(shard), str(SHARD_TOTAL)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    weights = _weights()
    epsilon = 0.01  # shard-modules.sh's weight for a module or test with no row
    total = 0.0
    deselect_next = False
    for line in done.stdout.splitlines():
        if line == "--deselect":
            deselect_next = True
            continue
        module, _, test = line.partition("::")
        key = f"{module.rsplit('/', 1)[-1]}::{test}" if test else module.rsplit("/", 1)[-1]
        weight = weights.get(key, epsilon)
        total += -weight if deselect_next else weight
        deselect_next = False
    return total


def _is_bounded(command: str) -> bool:
    """True when the apt-get command carries each bound as an exact `-o <option>` token pair."""
    tokens = shlex.split(command, comments=True)
    pairs = set(zip(tokens, tokens[1:], strict=False))
    return all(pair in pairs for pair in APT_BOUND_PAIRS)


def _apt_step() -> dict[str, Any]:
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["smoke"]["steps"]
    matching = [s for s in steps if "apt-get" in str(s.get("run", ""))]
    assert len(matching) == 1, f"steps running apt-get: {[s.get('name') for s in matching]}"
    return matching[0]


def test_every_apt_command_retries_and_times_out() -> None:
    commands = [ln.strip() for ln in str(_apt_step()["run"]).splitlines() if "apt-get" in ln]

    assert commands, "no apt-get command found in the install step"
    unbounded = [c for c in commands if not _is_bounded(c)]
    assert not unbounded, f"apt-get command(s) lacking exact {APT_BOUND_PAIRS}: {unbounded}"


@pytest.mark.parametrize(
    "mutant",
    [
        "sudo apt-get update -o Acquire::Retries=3 -o Acquire::http::Timeout=2000",
        "sudo apt-get update -o Acquire::Retries=3 -o Acquire::http::Timeout=30",
        "sudo apt-get update -o Acquire::Retries=30 -o Acquire::http::Timeout=20",
        "sudo apt-get update -o Acquire::Retries=3",
        "sudo apt-get update Acquire::Retries=3 Acquire::http::Timeout=20",
        "sudo apt-get update  # -o Acquire::Retries=3 -o Acquire::http::Timeout=20",
    ],
)
def test_a_loosened_or_missing_apt_bound_is_not_accepted(mutant: str) -> None:
    assert not _is_bounded(mutant), f"expected {mutant!r} to be rejected as unbounded"


def test_the_apt_step_cap_leaves_room_for_the_longest_planned_shard() -> None:
    minutes = _apt_step().get("timeout-minutes")

    assert minutes == APT_STEP_CAP_MINUTES, (
        f"expected the apt step timeout-minutes {APT_STEP_CAP_MINUTES}, got {minutes!r}"
    )
    planned_max = max(_planned_seconds(shard) for shard in range(SHARD_TOTAL))
    worst_case = planned_max + minutes * 60 + FIXED_OVERHEAD_S
    assert worst_case < JOB_LIMIT_S, (
        f"longest planned shard + apt step cap + fixed overhead must fit the job limit.\n"
        f"  expected: < {JOB_LIMIT_S}s\n"
        f"  actual:   {round(worst_case)}s = {round(planned_max)}s planned"
        f" + {minutes * 60}s apt cap + {FIXED_OVERHEAD_S}s overhead"
    )


def _job() -> dict[str, Any]:
    job: dict[str, Any] = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["smoke"]
    return job


def _skips_recommends(command: str) -> bool:
    """True when the apt-get command carries `--no-install-recommends` as its own token."""
    return "--no-install-recommends" in shlex.split(command, comments=True)


def _install_command() -> str:
    lines = [ln.strip() for ln in str(_apt_step()["run"]).splitlines() if "apt-get install" in ln]
    assert len(lines) == 1, f"apt-get install commands in the install step: {lines}"
    return lines[0]


def _cache_steps() -> tuple[dict[str, Any], dict[str, Any]]:
    """The cache restore step before the apt step and the cache save step after it."""
    steps = _job()["steps"]
    apt_at = steps.index(_apt_step())
    restore = [s for s in steps[:apt_at] if str(s.get("uses", "")).startswith("actions/cache/restore@")]
    assert restore, "no actions/cache/restore step before the apt step"
    archives = _apt_step().get("env", {}).get("APT_ARCHIVES")
    apt_keys = [s for s in restore if s["with"]["path"] == archives]
    assert len(apt_keys) == 1, f"actions/cache/restore steps caching APT_ARCHIVES {archives!r}: {apt_keys}"
    save = [
        s
        for s in steps[apt_at + 1 :]
        if str(s.get("uses", "")).startswith("actions/cache/save@") and s["with"]["key"] == apt_keys[0]["with"]["key"]
    ]
    assert len(save) == 1, f"actions/cache/save steps after the apt step on the apt key: {save}"
    restore = apt_keys
    return restore[0], save[0]


def _resolved_cache_key(image_version: str, workflow_text: str, tmp_path: Path) -> str:
    """Run the key-resolving step the restore step's key points at, as the runner would."""
    restore, _ = _cache_steps()
    match = re.fullmatch(r"\$\{\{ steps\.([\w-]+)\.outputs\.key \}\}", restore["with"]["key"])
    assert match, f"cache key must come from a step output, got {restore['with']['key']!r}"
    step = next(s for s in _job()["steps"] if s.get("id") == match.group(1))
    out = tmp_path / "github_output"
    out.write_text("")
    (tmp_path / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".github" / "workflows" / WORKFLOW.name).write_text(workflow_text, encoding="utf-8")
    env = {
        **_job().get("env", {}),
        **step.get("env", {}),
        "ImageOS": "ubuntu24",
        "ImageVersion": image_version,
        "GITHUB_OUTPUT": str(out),
        "HOME": str(tmp_path),
        "PATH": os.environ["PATH"],
    }
    subprocess.run(["sh", "-c", step["run"]], env=env, cwd=tmp_path, check=True, capture_output=True, text=True)
    return dict(ln.split("=", 1) for ln in out.read_text().splitlines())["key"]


def test_apt_install_skips_recommended_packages() -> None:
    command = _install_command()

    assert _skips_recommends(command), f"expected --no-install-recommends in {command!r}"


@pytest.mark.parametrize(
    "mutant",
    [
        "sudo apt-get install -y qemu-system-x86",
        "sudo apt-get install --install-recommends -y qemu-system-x86",
        "sudo apt-get install -y qemu-system-x86  # --no-install-recommends",
        "sudo apt-get install -y no-install-recommends qemu-system-x86",
    ],
)
def test_an_install_that_keeps_recommends_is_not_accepted(mutant: str) -> None:
    assert not _skips_recommends(mutant), f"expected {mutant!r} to be rejected"


def test_the_downloaded_debs_are_restored_before_and_saved_after_the_install() -> None:
    restore, save = _cache_steps()
    archives = _apt_step()["env"]["APT_ARCHIVES"]

    assert "Dir::Cache::archives=$APT_ARCHIVES" in shlex.split(_install_command(), comments=True), (
        f"expected apt to download into $APT_ARCHIVES: {_install_command()!r}"
    )
    assert restore["with"]["path"] == archives, f"restore path {restore['with']['path']!r} != {archives!r}"
    assert save["with"]["path"] == archives, f"save path {save['with']['path']!r} != {archives!r}"
    assert save["with"]["key"] == restore["with"]["key"], (
        f"save key {save['with']['key']!r} != restore key {restore['with']['key']!r}"
    )


def test_the_cache_key_follows_the_runner_image_and_the_package_list(tmp_path: Path) -> None:
    # The package list lives in the workflow file's install line, so the key hashes that file.
    workflow = WORKFLOW.read_text(encoding="utf-8")

    base = _resolved_cache_key("20261101.1", workflow, tmp_path)

    assert _resolved_cache_key("20261101.1", workflow, tmp_path) == base, "same inputs must reuse the entry"
    assert _resolved_cache_key("20261102.1", workflow, tmp_path) != base, "a new runner image must miss"
    assert _resolved_cache_key("20261101.1", workflow + " tcpdump", tmp_path) != base, "a new package must miss"
