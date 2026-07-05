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

Runs entirely off-appliance (collection only, no SMOKE_PKG / live VM needed). The
parametrized ``test_shard_union_covers_every_test_exactly_once`` targets
`tests/smoke` with a SYNTHETIC per-test duration table (via the
`SHARD_DURATIONS_FILE` test-only env override -- see shard-modules.sh's header)
built from a REAL `--collect-only` pass, forcing the hybrid split deterministically
regardless of what the CHECKED-IN table's own targets happen to be (which module is
oversized there depends on measured CI timings, not something a test should
hardcode). No module name is hardcoded: the "oversized" module is whichever one
actually collects the most `-m smoke` tests.

The synthetic table proves the split ALGORITHM never drops/duplicates a test, but
it always synthesizes a row for every collected test, so it structurally cannot see
the one failure mode that comes from the CHECKED-IN `tests/smoke/module-durations.txt`
itself going stale (issue #861): a per-test row surviving a test rename/removal
becomes a bare, nonexistent node-id arg on whichever shard it lands on (pytest exits
4 there); and a NEW test whose nodeid is a strict string EXTENSION of an off-carrier
known row id is silently stripped by that carrier's `--deselect` prefix match and
runs on NO shard. `test_committed_table_rows_exist_in_the_live_collection` and
`test_committed_table_has_no_prefix_blind_spot` below check the COMMITTED table
itself against the live collection to close that gap -- a drift the synthetic-table
tests above can never surface.

Guarded by `pytest.importorskip("dns")`: collecting the whole `tests/smoke` tree
imports every module in it, and `test_stub_shapes.py` needs the optional
`dnspython` dependency (`tests/smoke/requirements.txt`) that a BARE local
`python -m pytest` does not install (pyproject.toml's default addopts
`--ignore=tests/smoke` only skips *collecting* tests/smoke directly -- this file
lives in tests/ and still imports `dns` itself at module scope).
`.github/workflows/test.yml`'s unit job installs `dnspython` precisely so this
module -- the splitter's sole correctness gate -- actually runs in CI instead of
skipping (issue #861). Skips, never fails, on a checkout without it -- exactly like
the ADR-14 browser tier's `importorskip("playwright...")` precedent.
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
_COMMITTED_DURATIONS_FILE = _SMOKE_DIR / "module-durations.txt"


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


# ---------------------------------------------------------------------------
# Committed-table drift gate (issue #861) -- unlike the synthetic-table test
# above, these check tests/smoke/module-durations.txt AS COMMITTED, which the
# synthetic table can never drift-check (it always synthesizes a fresh row for
# every collected test).
# ---------------------------------------------------------------------------


def _parse_duration_table(path: Path) -> dict[str, float]:
    """Parse a module-durations.txt-shaped table into {row_id: weight}, mirroring
    scripts/shard-modules.sh's table reader: comment/blank lines are skipped, and
    the WEIGHT is always the LAST whitespace-delimited field so a parametrized
    test id containing its own space round-trips intact (issue #861's table-parser
    fix -- the key is everything before that last field, rejoined verbatim)."""
    rows: dict[str, float] = {}
    for lineno, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.rsplit(None, 1)
        # A malformed non-comment row must fail the gate, not slip past it — a
        # corrupted committed table evading the drift checks defeats their point
        # (review #861).
        if len(parts) != 2:
            raise AssertionError(f"malformed duration row in {path}:{lineno}: {raw_line!r}")
        key, weight = parts
        try:
            rows[key] = float(weight)
        except ValueError as exc:
            raise AssertionError(f"invalid duration weight in {path}:{lineno}: {raw_line!r}") from exc
    return rows


def _basename_nodeid(nid: str) -> str:
    """Convert a collected `tests/smoke/test_x.py::test_y` node id to the
    `test_x.py::test_y` BASENAME form module-durations.txt rows actually use
    (scripts/module-durations.sh strips the directory prefix when it writes the
    table)."""
    module, rest = nid.split("::", 1)
    return f"{module.rsplit('/', 1)[-1]}::{rest}"


def _per_test_row_ids(table: dict[str, float]) -> set[str]:
    """Row keys that are per-test rows (`module::test`), excluding module-sum rows."""
    return {key for key in table if "::" in key}


def _assert_committed_table_rows_exist(table_path: Path, oracle_ids: set[str]) -> None:
    """Every per-test row nodeid in table_path must exist in the live -m smoke
    collection -- a stale row (a renamed/removed test) becomes a bare, nonexistent
    node-id argument on whichever shard it lands on, and pytest exits 4 there
    (issue #861 blocking findings on shard-modules.sh:46/346: run-smoke.sh maps
    only exit 5 to a benign empty-shard pass, so exit 4 fails the whole leg)."""
    table = _parse_duration_table(table_path)
    live_ids = {_basename_nodeid(nid) for nid in oracle_ids}
    stale = _per_test_row_ids(table) - live_ids
    assert not stale, (
        f"stale per-test row(s) in {table_path} -- no matching live -m smoke test.\n"
        f"  regenerate tests/smoke/module-durations.txt (scripts/module-durations.sh)\n"
        f"  stale row(s): {sorted(stale)}"
    )


def _assert_committed_table_has_no_prefix_blind_spot(table_path: Path, oracle_ids: set[str]) -> None:
    """A collected test in a module that HAS per-test rows, itself lacking a row, is
    a blind spot IFF its nodeid is a strict string PREFIX EXTENSION of some other
    row in that same module: pytest's `--deselect` matches by prefix, so the
    carrier's deselect for the shorter known id also silently strips the longer
    unknown one, and it then runs on NO shard (issue #861 blocking finding on
    shard-modules.sh:49)."""
    table = _parse_duration_table(table_path)
    row_ids = _per_test_row_ids(table)
    modules_with_rows = {row_id.split("::", 1)[0] for row_id in row_ids}
    blind_spots = set()
    for nid in oracle_ids:
        bid = _basename_nodeid(nid)
        module = bid.split("::", 1)[0]
        if module not in modules_with_rows or bid in row_ids:
            continue
        if any(other != bid and bid.startswith(other) for other in row_ids if other.split("::", 1)[0] == module):
            blind_spots.add(bid)
    assert not blind_spots, (
        f"collected test(s) string-extend a known per-test row id with no row of their own -- "
        f"the carrier's --deselect for the shorter id would also strip these.\n"
        f"  regenerate tests/smoke/module-durations.txt (scripts/module-durations.sh)\n"
        f"  blind spot(s): {sorted(blind_spots)}"
    )


def test_committed_table_rows_exist_in_the_live_collection(oracle_ids: set[str]) -> None:
    """The COMMITTED tests/smoke/module-durations.txt must not carry a per-test row
    for a test that no longer collects -- a rename/removal without regenerating the
    table turns that row into a bare, nonexistent pytest node-id argument on some
    shard, failing the leg with pytest exit 4 (issue #861)."""
    _assert_committed_table_rows_exist(_COMMITTED_DURATIONS_FILE, oracle_ids)


def test_committed_table_has_no_prefix_blind_spot(oracle_ids: set[str]) -> None:
    """A NEW test added to a module the COMMITTED table already splits at test
    granularity must get its OWN row before it ships, whenever its nodeid string-
    extends an existing off-carrier row -- otherwise the carrier's `--deselect` for
    the shorter id silently strips it too and it runs on NO shard (issue #861; the
    in-tree test_cron_detects_changed_local_feed / ..._same_second pair is exactly
    this shape)."""
    _assert_committed_table_has_no_prefix_blind_spot(_COMMITTED_DURATIONS_FILE, oracle_ids)
