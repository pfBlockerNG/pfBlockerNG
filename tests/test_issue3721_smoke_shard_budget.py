"""Issue #3721: the smoke shard plan fits the smoke job's time limit.

A stalled mirror once ate 24-27 minutes of the job's budget before pytest started. The apt step
that suffered it is gone (the ``ci-vm`` image bakes the tools, #3852), but the budget it guarded
remains: the longest planned shard plus the fixed per-job overhead must still fit the job's
``timeout-minutes``. The per-module duration rows that keep the plan balanced are guarded by
``test_every_smoke_module_has_a_duration_row`` in ``test_shard_union.py``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SHARD_SCRIPT = ROOT / "scripts" / "shard-modules.sh"
SMOKE_DIR = "tests/smoke"
DURATIONS = ROOT / SMOKE_DIR / "module-durations.txt"
WORKFLOW = ROOT / ".github" / "workflows" / "smoke-single.yml"

SHARD_TOTAL = 3  # the smoke.yml fan-out's per-leg shard count
FIXED_OVERHEAD_S = 120  # VM boot, .pkg install and the two .pkg builds around pytest


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


def test_the_longest_planned_shard_fits_the_smoke_job_timeout() -> None:
    job = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["smoke"]
    job_limit_s = job["timeout-minutes"] * 60

    planned_max = max(_planned_seconds(shard) for shard in range(SHARD_TOTAL))
    worst_case = planned_max + FIXED_OVERHEAD_S
    assert worst_case < job_limit_s, (
        f"longest planned shard + fixed overhead must fit the job limit.\n"
        f"  expected: < {job_limit_s}s\n"
        f"  actual:   {round(worst_case)}s = {round(planned_max)}s planned + {FIXED_OVERHEAD_S}s overhead"
    )
