"""Union oracle for scripts/shard-modules.sh's hybrid test-level split (issue #855,
also implementing #854's core coverage-completeness invariant).

The hybrid splitter (module-level LPT, PLUS test-level LPT for any module whose
table weight exceeds the per-shard target) must never change WHAT runs -- only
HOW it is distributed. This is the end-to-end proof: for a real shard_total, feed
every shard's ``scripts/shard-modules.sh`` output (module paths, bare node IDs,
``--deselect`` pairs) straight into ``pytest --collect-only`` exactly as
``run-smoke.sh`` would, and assert the UNION of every shard's collected node IDs
equals a plain unsharded collection of the same tree -- with NO test collected by
more than one shard (a ``--deselect``ed test double-running would be silently
invisible otherwise).

Runs entirely off-appliance (collection only, no SMOKE_PKG / live VM needed). It
targets `tests/smoke` directly with a SYNTHETIC per-test duration table (via the
`SHARD_DURATIONS_FILE` test-only env override -- see shard-modules.sh's header)
built from a REAL `--collect-only` pass, so it exercises the hybrid path today even
though the checked-in `tests/smoke/module-durations.txt` has no per-test rows yet
(that regeneration is issue #855's Step 2). No module name is hardcoded: the
"oversized" module is whichever one actually collects the most `-m smoke` tests.

Guarded by `pytest.importorskip("dns")`: collecting the whole `tests/smoke` tree
imports every module in it, and `test_stub_shapes.py` needs the optional
`dnspython` dependency (`tests/smoke/requirements.txt`) that the plain
`python -m pytest` unit job does NOT install (pyproject.toml's default addopts
`--ignore=tests/smoke` means this is normally never imported at all). Skips, never
fails, on a checkout without it -- exactly like the ADR-14 browser tier's
`importorskip("playwright...")` precedent.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

dns = pytest.importorskip("dns", reason="tests/smoke/test_stub_shapes.py needs dnspython to import")

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SHARD_SCRIPT = _REPO_ROOT / "scripts" / "shard-modules.sh"
_SMOKE_DIR = _REPO_ROOT / "tests" / "smoke"  # filesystem enumeration only (glob) -- never a subprocess arg
_SMOKE_DIR_REL = "tests/smoke"  # the arg every subprocess call below actually uses (see the note below)
_SYNTHETIC_MODULE_WEIGHT = "100000.00"  # guarantees the chosen module clears any target
_SMALL_WEIGHT = "1.00"  # every other module + every per-test row: never oversized on its own


def _collect(args: list[str]) -> set[str]:
    """Run `pytest --collect-only -q -m smoke <args>` from the repo root and return the
    collected node IDs (only lines shaped `tests/smoke/....py::...`; warnings/summary
    lines never match this shape, so no extra filtering is needed)."""
    cmd = [sys.executable, "-m", "pytest", "--collect-only", "-q", "--override-ini=addopts=", "-m", "smoke", *args]
    proc = subprocess.run(cmd, cwd=_REPO_ROOT, capture_output=True, text=True)
    # rc 0 = tests collected, 1 = collection warnings but items still listed, 5 = no
    # tests matched the marker (a legitimate empty slice, same as run-smoke.sh's own
    # exit-5 tolerance for a sharded run) -- anything else is a genuine failure.
    assert proc.returncode in (0, 1, 5), (
        f"collect-only failed unexpectedly.\n"
        f"  args: {args}\n"
        f"  expected rc: one of (0, 1, 5)\n"
        f"  actual rc:   {proc.returncode}\n"
        f"  stdout tail: {proc.stdout[-2000:]}\n"
        f"  stderr tail: {proc.stderr[-2000:]}"
    )
    return {line for line in proc.stdout.splitlines() if line.startswith("tests/smoke/") and "::" in line}


def _run_shard(shard_index: int, shard_total: int, durations_file: Path) -> list[str]:
    """Invoke scripts/shard-modules.sh for one shard, with the synthetic per-test
    table injected via SHARD_DURATIONS_FILE, and return its stdout lines verbatim --
    exactly the argv words run-smoke.sh splices into its own pytest invocation.

    The test-dir arg MUST be the relative "tests/smoke" (never an absolute path):
    pytest's own node IDs are rootdir-relative, but `--deselect` matches by nodeid
    PREFIX via a plain string comparison (see the header comment above and
    scripts/shard-modules.sh's own prefix-safety note) -- an absolute-path deselect
    target silently never matches a relative nodeid, so deselection would be a
    total no-op and a test would double-run. run-smoke.sh always passes the
    relative `--paths` value it was given, so this mirrors the real caller.
    """
    env = dict(os.environ, SHARD_DURATIONS_FILE=str(durations_file))
    proc = subprocess.run(
        ["sh", str(_SHARD_SCRIPT), _SMOKE_DIR_REL, str(shard_index), str(shard_total)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, (
        f"shard-modules.sh failed for shard {shard_index}/{shard_total}.\n"
        f"  expected rc: 0\n"
        f"  actual rc:   {proc.returncode}\n"
        f"  stderr:      {proc.stderr}"
    )
    return [line for line in proc.stdout.splitlines() if line]


def _build_synthetic_table(tmp_path: Path, oracle_ids: set[str]) -> Path:
    """Synthesize a per-test module-durations.txt table over the REAL tests/smoke
    tree: the module with the most `-m smoke`-collected tests gets a huge module
    weight (always oversized) plus one per-test row (real test ids, equal weight)
    for each of its collected tests; every other enumerated module gets a small,
    never-oversized module row. Forces the hybrid split path today, ahead of the
    real per-test table regeneration (issue #855's Step 2)."""
    counts = Counter(nid.split("::", 1)[0].rsplit("/", 1)[-1] for nid in oracle_ids)
    big_module, big_count = counts.most_common(1)[0]
    assert big_count >= 2, (
        f"need an oversized module with >=2 smoke tests to exercise a real split.\n"
        f"  expected: some module with >= 2 collected -m smoke tests\n"
        f"  actual:   biggest module {big_module!r} has only {big_count}"
    )

    lines = [f"{big_module} {_SYNTHETIC_MODULE_WEIGHT}"]
    for nid in sorted(oracle_ids):
        module_name, testid = nid.split("::", 1)
        if module_name.rsplit("/", 1)[-1] == big_module:
            lines.append(f"{big_module}::{testid} {_SMALL_WEIGHT}")
    for module_path in sorted(_SMOKE_DIR.glob("test_*.py")):
        if module_path.name != big_module:
            lines.append(f"{module_path.name} {_SMALL_WEIGHT}")

    table = tmp_path / "synthetic-module-durations.txt"
    table.write_text("\n".join(lines) + "\n")
    return table


@pytest.fixture(scope="module")
def oracle_ids() -> set[str]:
    """The full, unsharded `-m smoke` collection of tests/smoke -- the ground truth
    every shard_total's union must reproduce exactly."""
    ids = _collect([_SMOKE_DIR_REL])
    assert ids, "the plain unsharded collection found ZERO -m smoke tests -- oracle is empty, test is vacuous"
    return ids


@pytest.fixture(scope="module")
def synthetic_table(tmp_path_factory: pytest.TempPathFactory, oracle_ids: set[str]) -> Path:
    return _build_synthetic_table(tmp_path_factory.mktemp("shard-union"), oracle_ids)


@pytest.mark.parametrize("shard_total", [2, 3, 4])
def test_shard_union_covers_every_test_exactly_once(
    shard_total: int, oracle_ids: set[str], synthetic_table: Path
) -> None:
    """Given the real tests/smoke tree hybrid-split across `shard_total` shards (with a
    synthetic per-test table forcing the split for real today), the UNION of every
    shard's collected node IDs must equal the unsharded oracle, and no test may be
    collected by more than one shard -- a `--deselect`ed test silently double-running
    would otherwise be invisible."""
    shard_sets = [_collect(_run_shard(i, shard_total, synthetic_table)) for i in range(shard_total)]

    union = set().union(*shard_sets)
    total_collected = sum(len(s) for s in shard_sets)

    missing = oracle_ids - union
    extra = union - oracle_ids
    assert union == oracle_ids, (
        f"shard_total={shard_total}: union of all shards must equal the unsharded oracle.\n"
        f"  expected (oracle) count: {len(oracle_ids)}\n"
        f"  actual (union) count:    {len(union)}\n"
        f"  missing from union:      {sorted(missing) or 'none'}\n"
        f"  extra beyond oracle:     {sorted(extra) or 'none'}"
    )
    assert total_collected == len(union), (
        f"shard_total={shard_total}: a test collected by more than one shard would double-run.\n"
        f"  expected (sum of per-shard counts): {total_collected}\n"
        f"  actual (distinct union count):      {len(union)}\n"
        f"  per-shard counts: {[len(s) for s in shard_sets]}"
    )
