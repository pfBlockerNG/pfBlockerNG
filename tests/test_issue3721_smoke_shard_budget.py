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
    """The apt cache's restore step before the apt step and its save step after it."""
    steps = _job()["steps"]
    apt_at = steps.index(_apt_step())
    archives = _apt_step().get("env", {}).get("APT_ARCHIVES")
    restore = [
        s
        for s in steps[:apt_at]
        if str(s.get("uses", "")).startswith("actions/cache/restore@") and s["with"]["path"] == archives
    ]
    assert len(restore) == 1, f"actions/cache/restore steps caching APT_ARCHIVES {archives!r}: {restore}"
    save = [
        s
        for s in steps[apt_at + 1 :]
        if str(s.get("uses", "")).startswith("actions/cache/save@") and s["with"]["key"] == restore[0]["with"]["key"]
    ]
    assert len(save) == 1, f"actions/cache/save steps after the apt step on the apt key: {save}"
    return restore[0], save[0]


def _key_outputs(*, image_os: str, image_version: str, workflow_text: str, tmp_path: Path) -> dict[str, str]:
    """Run the key-resolving step the restore step's key points at, as the runner would, and return its outputs."""
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
        "ImageOS": image_os,
        "ImageVersion": image_version,
        "GITHUB_OUTPUT": str(out),
        "HOME": str(tmp_path),
        "PATH": os.environ["PATH"],
    }
    subprocess.run(["sh", "-c", step["run"]], env=env, cwd=tmp_path, check=True, capture_output=True, text=True)
    return dict(ln.split("=", 1) for ln in out.read_text().splitlines())


def _chowns_archives_after_install(script: str) -> bool:
    """True when a `chown` of "$APT_ARCHIVES" runs after the apt-get install command."""
    lines = [ln.strip() for ln in script.splitlines()]
    installs = [i for i, ln in enumerate(lines) if "apt-get install" in ln]
    chowns = [i for i, ln in enumerate(lines) if "chown" in shlex.split(ln, comments=True) and '"$APT_ARCHIVES"' in ln]
    return bool(installs and chowns) and max(chowns) > max(installs)


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


def test_a_cold_cache_is_saved_only_after_a_successful_install() -> None:
    restore, save = _cache_steps()
    condition = str(save.get("if", ""))

    hit = f"steps.{restore['id']}.outputs.cache-hit != 'true'"
    assert hit in condition, f"the apt cache save must run only on a miss ({hit!r}), got {condition!r}"
    assert "always()" not in condition, f"the apt cache save must not run after a failed install: {condition!r}"


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ('sudo apt-get install -y x\nsudo chown -R "$(id -u):$(id -g)" "$APT_ARCHIVES"', True),
        ("sudo apt-get install -y x", False),
        ('sudo chown -R "$(id -u):$(id -g)" "$APT_ARCHIVES"\nsudo apt-get install -y x', False),
        ('sudo apt-get install -y x\nsudo chown -R "$(id -u):$(id -g)" /tmp/other', False),
        ('sudo apt-get install -y x\n# sudo chown -R "$(id -u):$(id -g)" "$APT_ARCHIVES"', False),
    ],
)
def test_chown_detector_requires_the_archives_handed_back_after_the_install(script: str, expected: bool) -> None:
    assert _chowns_archives_after_install(script) is expected, f"unexpected verdict for {script!r}"


def test_the_apt_archives_are_handed_to_the_runner_user_after_the_install() -> None:
    script = str(_apt_step()["run"])

    assert _chowns_archives_after_install(script), (
        f"root-owned .deb files must be chowned back after the install or the cache save cannot read them:\n{script}"
    )


def test_the_key_step_writes_the_cache_key_and_the_archive_dir(tmp_path: Path) -> None:
    outputs = _key_outputs(
        image_os="ubuntu24", image_version="20261101.1", workflow_text=WORKFLOW.read_text(), tmp_path=tmp_path
    )

    assert {"key", "dir"} <= outputs.keys(), f"key step outputs: {sorted(outputs)}"
    assert outputs["key"] and outputs["dir"], f"empty key step output: {outputs}"


def test_the_cache_key_follows_the_runner_image_and_the_install_line_only(tmp_path: Path) -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    install = _install_command()

    def key(*, image_os: str = "ubuntu24", image_version: str = "20261101.1", text: str = workflow) -> str:
        return _key_outputs(image_os=image_os, image_version=image_version, workflow_text=text, tmp_path=tmp_path)[
            "key"
        ]

    base = key()

    assert key() == base, "same inputs must reuse the entry"
    assert key(image_version="20261102.1") != base, "a new runner image version must miss"
    assert key(image_os="ubuntu26") != base, "a new runner OS must miss"
    assert key(text=workflow.replace(install, install + " tcpdump")) != base, "a new package must miss"
    assert key(text=workflow + "\n# an unrelated edit\n") == base, "an unrelated workflow edit must stay warm"


def test_a_workflow_without_an_install_line_cannot_resolve_a_key(tmp_path: Path) -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8").replace("apt-get install", "apt-get  install")

    with pytest.raises(subprocess.CalledProcessError):
        _key_outputs(image_os="ubuntu24", image_version="20261101.1", workflow_text=workflow, tmp_path=tmp_path)
