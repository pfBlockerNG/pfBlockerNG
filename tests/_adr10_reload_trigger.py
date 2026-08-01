#!/usr/bin/env python3
"""Standalone trigger for ``test_adr10_concurrency`` -- run in a SEPARATE process.

It publishes a new DNSBL manifest AND a new user-regex ini, then bumps the
reload-generation sentinel, exactly the way PHP/shell do on a real box (stage ->
fsync -> atomic ``rename``, then flip the sentinel). Running it as its own process
is the point: it shares NO GIL and NO module state with the query process, so it
genuinely exercises the atomic-publish-vs-concurrent-read path. Pure stdlib -- it
deliberately does NOT import ``pfb_unbound``, so it spawns clean under any start
method (spawn/fork) and never drags the matcher into the trigger process.

It alternates between TWO source pairs (gen1 <-> gen2), flipping ``K`` times so the
query threads see repeated generational swaps -- an extended torn hunt, not a single
edge. The user-regex lane lives in the ini, so
gen1 and gen2 carry DIFFERENT ini text; publishing the ini alongside the manifest is
mandatory (a manifest-only flip would freeze the user-regex stratum across the swap).

argv (positional):
    <flips>                 number of flips to perform (>=1); flip i publishes pair (i%2)
    <live_manifest_path>    where the live manifest is read by the watcher
    <live_ini_path>         where the live user-regex ini is read by the watcher
    <sentinel_path>         the reload-generation sentinel
    <applied_path>          the applied-generation marker the watcher publishes on swap
    <observed_path>         the query-process marker for a completed generation scan
    <manifest_a> <ini_a>    gen1 source pair (published on even flips: 0, 2, ...)
    <manifest_b> <ini_b>    gen2 source pair (published on odd flips: 1, 3, ...)

NOTE: the live manifest starts as gen1 (the test wrote it before spawning us), so the
FIRST flip (i=0) publishes pair B (gen2) -- i.e. we publish pair ``(i + 1) % 2`` so the
sequence the watcher applies is gen2, gen1, gen2, ... and every flip is a real advance.

Each flip WAITS for the watcher to APPLY the resulting generation (the applied marker
reaches ``2 + i``), then for a query to OBSERVE that generation before the next flip.
This serialises the writer against the builder so the builder always reads a CONSISTENT
(manifest, ini) pair -- the snapshot swap under test is atomic, but the build *input*
(two separate files read in sequence) would otherwise race a mid-build overwrite and
yield a self-consistent-but-cross-gen snapshot. The atomic _snapshot rebind is still
exercised ``flips`` times; a query observes every intermediate generation, and every
query thread observes the baseline and final generation without a torn (mixed) view.
"""

from __future__ import annotations

import os
import sys
import time


def _atomic_write(path: str, data: str) -> None:
    # Stage in the SAME dir, fsync, then rename -- a concurrent reader sees the whole
    # old file or the whole new one, never a torn/partial manifest or ini.
    tmp = "{}.tmp.{}".format(path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _read_gen(path: str) -> int | None:
    try:
        with open(path, encoding="utf-8") as fh:
            first = fh.readline().strip()
    except OSError:
        return None
    return int(first) if first.isdigit() else None


def _bump_sentinel(sentinel: str) -> int:
    cur = _read_gen(sentinel) or 0
    nxt = cur + 1
    _atomic_write(sentinel, "{}\n".format(nxt))
    return nxt


def _wait_generation_marker(path: str, target: int, timeout: float) -> None:
    """Wait for a marker, failing loudly when the run is stuck or the environment is broken."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        actual = _read_gen(path)
        if (actual or 0) >= target:
            return
        time.sleep(0.01)
    actual = _read_gen(path)
    if (actual or 0) >= target:
        return
    raise RuntimeError(
        "wait_generation_marker stuck/environment: expected target generation {} at {!r}; actual={!r}".format(
            target, path, actual
        )
    )


def main(argv: list[str]) -> int:
    flips = int(argv[1])
    live_manifest = argv[2]
    live_ini = argv[3]
    sentinel = argv[4]
    applied = argv[5]
    observed = argv[6]
    manifest_a, ini_a = argv[7], argv[8]
    manifest_b, ini_b = argv[9], argv[10]

    pairs = [(manifest_a, ini_a), (manifest_b, ini_b)]

    for i in range(flips):
        # Flip 0 publishes pair B (gen2), flip 1 pair A (gen1), ... -- the live state
        # begins at gen1, so each publish is a genuine generation advance.
        manifest_src, ini_src = pairs[(i + 1) % 2]
        # 1) publish the new manifest + ini atomically (the per-feed raw they reference
        #    is already on disk), THEN 2) bump the sentinel -- the all-or-nothing commit
        #    the watcher acts on. Both files are in place before the sentinel advances,
        #    so the rebuild always reads a consistent (manifest, ini) pair.
        _atomic_write(live_manifest, _read(manifest_src))
        _atomic_write(live_ini, _read(ini_src))
        gen = _bump_sentinel(sentinel)
        # Wait for the watcher to APPLY this generation before flipping again, so the
        # next overwrite cannot race an in-flight build's (manifest, ini) reads.
        _wait_generation_marker(applied, gen, timeout=20.0)
        _wait_generation_marker(observed, gen, timeout=20.0)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
