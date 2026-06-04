"""ADR-10 Phase-1 de-risking spike: the cost of the zero-downtime DNSBL swap.

Question this answers (falsify-first, before ADR-10 builds any swap machinery):
the zero-downtime design rebuilds the matcher structures on a background thread
**while the old structures stay live**, then atomically swaps the new ones in. For
the build window BOTH structure-sets are resident -> the transient peak RAM is
~2x the steady-state DNSBL footprint (~274 B/entry x millions, ADR-05 SS3a). On a
small appliance (e.g. 1 GB) a multi-million-entry ABP feed could OOM mid-swap.
This spike produces that ~2x peak-RAM number and gates it against a min-spec box.

It also measures the second Phase-1 agent-runnable number: the per-block Reports
sqlite write overhead (``pfb_db_enqueue(("cache", ...))`` -> the ``dnsblcache``
table, ``pfb_unbound.py``) versus the ~1 us matcher, to decide whether the async
log path is overkill / droppable / generation-keyable on a swap (ADR-10 Bonus 2,
feeds Phase 3).

What this spike deliberately does NOT do (maintainer-owned, no live Unbound in CI):
* the shared-interpreter / shared-module-globals visibility probe (the load-bearing
  gate) -- documented + cited in RESULTS/01, with a live-box procedure + a result slot;
* the live restart-downtime baseline (dropped/refused queries during today's restart);
* the C-cache delta-flush cost on a real box.

Reuses the ADR-06 spike's pure ``build()`` + the un-pruned raw corpus generator
(``_corpus_raw``): ADR-10 swaps in exactly the structure-set that build produces,
so the same build is the right thing to double. stdlib only; pympler is an
optional dev tool (deep retained sizing), absent -> that line is skipped, gate
falls back to the tracemalloc peak.

Run from the repo root (dev-only; not shipped, not in the default pytest run)::

    python -m pip install pympler          # dev-only, ADR-05 SS3a baseline tool
    SPIKE_N=5 SPIKE_SIZES=2000000 python benchmarks/spike_adr10_swap.py
    SPIKE_SQLITE_ROWS=20000 python benchmarks/spike_adr10_swap.py
"""

from __future__ import annotations

import gc
import os
import resource
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _corpus_raw import generate_raw_corpus  # noqa: E402
from spike_adr06_build import build  # noqa: E402  -- reuse the pure ADR-06 build

try:
    from pympler import asizeof  # type: ignore
except ImportError:  # pragma: no cover - dev tool only
    asizeof = None  # type: ignore[assignment]

# --------------------------------------------------------------------------- #
# Kill-threshold (proposed in Phase 1; tune with the maintainer in the handoff).
# --------------------------------------------------------------------------- #
# The ADR-10 swap holds BOTH the old and the new structure-set resident from the
# start of the background build until the swap + GC -> the transient peak is ~2x
# the steady-state DNSBL footprint. The gate is whether that ~2x peak fits the
# smallest box pfBlockerNG targets WITH headroom for everything else resident
# (Unbound's own C-side message cache, the OS, PHP/cron). We state a conservative
# min-spec appliance and a budget fraction of its RAM the transient peak may use.
MIN_SPEC_BOX_MIB = 1024.0  # smallest realistic appliance pfBlockerNG runs on (1 GB)
# Of that, Unbound's C-cache + OS + base services already claim the bulk; we allow
# the DNSBL transient (steady-state + the during-build duplicate) to use at most
# this fraction before we refuse to swap and fall back to the restart.
SWAP_RAM_BUDGET_FRACTION = 0.35  # transient peak must fit 35% of the min-spec box
THRESH_SWAP_PEAK_MIB = MIN_SPEC_BOX_MIB * SWAP_RAM_BUDGET_FRACTION  # ~358 MiB

BASELINE_BYTES_PER_ENTRY = 274.0  # ADR-05 SS3a steady-state dict baseline

# Reports-sqlite write micro-bench: the per-block async log path must be cheap
# relative to the ~1 us matcher, or it is overkill on the (now no_cache_store)
# block path and a candidate to simplify/drop/generation-key on a swap (Bonus 2).
MATCHER_US_BASELINE = 1.0  # ADR-05 SS3a ~1 us/lookup dict matcher


# --------------------------------------------------------------------------- #
# Part 1 -- ~2x peak RAM of build-while-old-live + swap.
# --------------------------------------------------------------------------- #


def _maxrss_mib() -> float:
    """Process peak RSS high-water mark (ru_maxrss). macOS reports bytes, Linux KiB."""
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / 2**20 if sys.platform == "darwin" else rss / 1024.0


def _measure_swap_peak(lines: list[str], feeds: list[str]) -> tuple[int, int, dict[str, Any], dict[str, Any]]:
    """Model the zero-downtime swap; return (build_peak, both_resident_bytes, old, new).

    The sequence mirrors ``rebuild_and_swap`` (ADR-10 Phase 3/4): the OLD
    structure-set is already resident and serving queries; the background thread
    runs ``build()`` to produce a SECOND, independent set; both are live at once
    (the ~2x high-water mark); the ref is swapped to the new set; the old set is
    dropped and GC'd. ``old`` is held across the build so the both-resident cost
    is real -- the whole point of this spike.

    Two numbers come out:
      * ``build_peak`` -- tracemalloc allocations *during the new build* (the NEW
        set + its transient working memory; ``old`` predates ``start()`` so it is
        NOT in this figure -- this is ~one set's high-water, not the doubled total);
      * ``both_resident`` -- the genuine simultaneous footprint, sized by pympler
        over BOTH sets while both are live (the ~2x number the gate cares about);
        ``None``-equivalent (0) when pympler is absent.
    """
    # Steady state: the old structures are already built and serving.
    old = build(lines, feeds)
    gc.collect()

    tracemalloc.start()
    tracemalloc.reset_peak()
    # Background rebuild: a SECOND full set is constructed while ``old`` stays live.
    new = build(lines, feeds)
    _, build_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Both sets are live RIGHT NOW (pre-swap). Size the genuine 2x footprint.
    both_resident = 0
    if asizeof is not None:
        both_resident = asizeof.asizeof(
            old["dataDB"],
            old["zoneDB"],
            old["feedGroupIndexDB"],
            new["dataDB"],
            new["zoneDB"],
            new["feedGroupIndexDB"],
        )
    # Atomic swap point: ``new`` is now authoritative; ``old`` becomes garbage.
    return build_peak, both_resident, old, new


def _retained_bytes(structures: dict[str, Any]) -> int | None:
    if asizeof is None:
        return None
    return asizeof.asizeof(structures["dataDB"], structures["zoneDB"], structures["feedGroupIndexDB"])


def run_ram(n_domain_lines: int, n_runs: int) -> str:
    if n_runs < 1:
        raise ValueError(f"n_runs must be >= 1, got {n_runs}")
    print("=" * 78)
    print(
        "ADR-10 P1 SPIKE  ~2x peak RAM of build-while-old-live + swap  (CPython {}.{}, {})".format(
            sys.version_info.major, sys.version_info.minor, sys.platform
        )
    )
    print("-" * 78)
    corpus = generate_raw_corpus(n_domain_lines)
    print(
        "raw corpus: total lines={:,}  domain lines={:,}  bare-IP lines={:,}  unique domains={:,}".format(
            corpus.total_lines, corpus.n_domain_lines, corpus.n_ip_lines, corpus.n_unique_domains
        )
    )

    build_peaks: list[int] = []
    both_resident_list: list[int] = []
    last_new: dict[str, Any] = {}
    for r in range(n_runs):
        build_peak, both_resident, old, new = _measure_swap_peak(corpus.lines, corpus.feeds)
        build_peaks.append(build_peak)
        if both_resident:
            both_resident_list.append(both_resident)
        last_new = new
        print(
            "  run {}/{}: new-build peak={:.1f} MiB  both-resident={:.1f} MiB  data={:,} zone={:,}".format(
                r + 1,
                n_runs,
                build_peak / 2**20,
                (both_resident / 2**20) if both_resident else float("nan"),
                new["counts"]["data"],
                new["counts"]["zone"],
            )
        )
        del old, new
        gc.collect()

    counts = last_new["counts"]
    total = counts["total"]
    retained = _retained_bytes(last_new)
    build_peak_max = max(build_peaks)
    maxrss_mib = _maxrss_mib()

    print("-" * 78)
    print(
        "new-set build peak (tracemalloc): median={:.1f} MiB  max={:.1f} MiB  (one set; old predates start)".format(
            statistics.median(build_peaks) / 2**20, build_peak_max / 2**20
        )
    )
    print(
        "loaded entries (one set):{:>10,}  (data={:,} zone={:,} feedgroups={:,})".format(
            total, counts["data"], counts["zone"], counts["feedgroups"]
        )
    )
    steady_per_entry: float
    both_resident_mib: float
    if retained is not None and both_resident_list:
        steady_per_entry = retained / total if total else float("nan")
        both_resident_mib = statistics.median(both_resident_list) / 2**20
        print(
            "steady-state footprint:  {:.1f} MiB one set  ({:.1f} B/entry vs {:.0f} B/entry baseline)".format(
                retained / 2**20, steady_per_entry, BASELINE_BYTES_PER_ENTRY
            )
        )
        print(
            "BOTH-RESIDENT (the 2x):  {:.1f} MiB  (old + new live simultaneously, pympler-sized)".format(
                both_resident_mib
            )
        )
    else:
        steady_per_entry = float("nan")
        both_resident_mib = float("nan")
        print(
            "steady-state footprint:  (pympler absent -- run: python -m pip install pympler;"
            " gate falls back to 2x tracemalloc build peak)"
        )
    print(
        "process peak RSS (ru_maxrss this run): {:.1f} MiB  (whole interpreter, incl. both sets + arenas)".format(
            maxrss_mib
        )
    )

    # ----------------------------------------------------------------------- #
    # GATE -- does the ~2x transient (both-resident) footprint fit a min-spec box?
    # ----------------------------------------------------------------------- #
    print("-" * 78)
    # Prefer the genuine both-resident pympler number; fall back to 2x the
    # tracemalloc build peak when pympler is absent.
    gate_mib = both_resident_mib if both_resident_list else (2 * build_peak_max / 2**20)
    gate_src = "both-resident (pympler)" if both_resident_list else "2x tracemalloc build peak (pympler absent)"
    ram_ok = gate_mib <= THRESH_SWAP_PEAK_MIB
    print(
        "min-spec box: {:.0f} MiB  budget for DNSBL transient: {:.0%} = {:.0f} MiB".format(
            MIN_SPEC_BOX_MIB, SWAP_RAM_BUDGET_FRACTION, THRESH_SWAP_PEAK_MIB
        )
    )
    print("  gate input: {:.1f} MiB [{}] -> {}".format(gate_mib, gate_src, "PASS" if ram_ok else "OVER-BUDGET"))
    print(
        "  NOTE: this is DNSBL-structure bytes only. Real process RSS (above) is higher\n"
        "        (interpreter, arenas, fragmentation) and Unbound's C message cache is\n"
        "        ALSO resident. The maintainer must confirm peak RSS on a real min-spec\n"
        "        box under load (RESULTS/01 slot) -- this number is the floor, not the RSS."
    )
    verdict = "GO" if ram_ok else "RAM-GATED (mitigation required)"
    print("=" * 78)
    print(
        "RAM VERDICT: {}  (~2x transient {:.0f} MiB threshold on a {:.0f} MiB box)".format(
            verdict, THRESH_SWAP_PEAK_MIB, MIN_SPEC_BOX_MIB
        )
    )
    print(
        "  mitigation if over-budget: RAM-gate the swap (fall back to today's restart\n"
        "  on a constrained box) and/or a lower-peak build (drop+free per-feed raw as\n"
        "  consumed; build into the live dicts' shapes once). Restart is the fail-safe."
    )
    print("=" * 78)
    return verdict


# --------------------------------------------------------------------------- #
# Part 2 -- Reports-sqlite per-block write overhead (Bonus 2).
# --------------------------------------------------------------------------- #


def _open_cache_db(path: str) -> sqlite3.Connection:
    """Open the Reports cache db exactly as pfb_unbound.py does (WAL, table shape)."""
    con = sqlite3.connect(path, timeout=100000, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=100000")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute(
        "CREATE TABLE IF NOT EXISTS dnsblcache ( type TEXT, domain TEXT, groupname TEXT, final TEXT, feed TEXT );"
    )
    con.commit()
    return con


def run_sqlite(n_rows: int) -> None:
    print("=" * 78)
    print("ADR-10 P1 SPIKE  Reports-sqlite per-block write overhead vs the ~1 us matcher")
    print("-" * 78)
    rows = [
        ("py", "blocked{:07d}.example-feed.com".format(i), "DNSBL_Group", "0.0.0.0", "feed_03") for i in range(n_rows)
    ]

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "pfb_py_cache.sqlite")
        con = _open_cache_db(path)

        # (a) Per-row INSERT + commit -- the worst case (no batching at all).
        t0 = time.perf_counter()
        for row in rows:
            con.execute("INSERT INTO dnsblcache (type, domain, groupname, final, feed) VALUES (?,?,?,?,?)", row)
            con.commit()
        per_row_commit = (time.perf_counter() - t0) / n_rows

        con.execute("DELETE FROM dnsblcache")
        con.commit()

        # (b) Batched executemany + one commit -- what pfb_db_worker actually does.
        t0 = time.perf_counter()
        con.executemany("INSERT INTO dnsblcache (type, domain, groupname, final, feed) VALUES (?,?,?,?,?)", rows)
        con.commit()
        per_row_batch = (time.perf_counter() - t0) / n_rows
        con.close()

    # (c) The enqueue cost the DNS thread ACTUALLY pays: a queue.put_nowait of a
    # 5-tuple. The disk write happens off-thread in pfb_db_worker -- the response
    # path never waits on it. Measure the put_nowait alone.
    import queue as _queue

    q: _queue.Queue[Any] = _queue.Queue(maxsize=5000)
    t0 = time.perf_counter()
    for i, row in enumerate(rows):
        try:
            q.put_nowait(("cache", row))
        except _queue.Full:
            q.get_nowait()  # drain so the micro-bench keeps measuring put cost
            q.put_nowait(("cache", row))
    per_enqueue = (time.perf_counter() - t0) / n_rows

    print("rows: {:,}".format(n_rows))
    print(
        "  (a) per-row INSERT+commit   : {:>8.2f} us/row  (worst case, unbatched -- NOT what ships)".format(
            per_row_commit * 1e6
        )
    )
    print(
        "  (b) batched executemany+commit: {:>6.2f} us/row  (what pfb_db_worker does off-thread)".format(
            per_row_batch * 1e6
        )
    )
    print(
        "  (c) queue.put_nowait (DNS-thread cost): {:>5.3f} us/row  (the ONLY cost on the response path)".format(
            per_enqueue * 1e6
        )
    )
    print("-" * 78)
    print("  matcher baseline: ~{:.1f} us/lookup (ADR-05 SS3a). On the response path the".format(MATCHER_US_BASELINE))
    print("  block write costs only the enqueue (c); the INSERT (b) is amortised off-thread.")
    ratio = per_enqueue * 1e6 / MATCHER_US_BASELINE
    print(
        "  enqueue / matcher ratio: {:.2f}x  ->  {}".format(
            ratio,
            "negligible (keep async path; clear/generation-key on swap)"
            if ratio < 1.0
            else "non-trivial (consider dropping/generation-keying)",
        )
    )
    print("  NOTE: blocks set qstate.no_cache_store=1 (#43) -> EVERY block traverses operate()")
    print("  and enqueues a row -> the write rate equals the block-query rate, not the")
    print("  unique-blocked-name rate. This is the Bonus-2 input the Phase-3 Reports-log")
    print("  decision (clear / generation-key / drop) is made on.")
    print("=" * 78)


def main() -> None:
    n_runs = int(os.environ.get("SPIKE_N", "3"))
    sizes = [int(s) for s in os.environ.get("SPIKE_SIZES", "2000000").split(",") if s.strip()]
    for n in sizes:
        run_ram(n, n_runs)
    run_sqlite(int(os.environ.get("SPIKE_SQLITE_ROWS", "20000")))


if __name__ == "__main__":
    main()
