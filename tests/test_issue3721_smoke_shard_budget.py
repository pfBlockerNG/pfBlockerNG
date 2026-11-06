"""Issue #3721: the smoke shard plan plus the apt step fit the 45-minute job limit.

A stalled mirror ate 24-27 minutes of the job's budget before pytest started, so the apt step
is bounded: every apt-get call retries and times out quickly, and the step itself has a hard
cap. The cap is only meaningful if the longest planned shard still fits behind it, so the
budget is asserted as a sum. The per-module duration rows that keep the plan balanced are
guarded by ``test_every_smoke_module_has_a_duration_row`` in ``test_shard_union.py``.
"""

from __future__ import annotations

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
