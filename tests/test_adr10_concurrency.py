"""ADR-10 concurrency/atomicity: a SEPARATE PROCESS triggers a no-restart reload while
many query threads hammer the matcher — proving the swap is ATOMIC (no torn read),
ACTUALLY TAKES EFFECT (the sentinels flip), and never STALLS or crashes a query.

This complements the live-VM smoke (the load test on a real Unbound). Here the trigger
is a real second process (``tests/_adr10_reload_trigger.py``) — no shared GIL with the
query process, like the PHP trigger on a box — so it genuinely exercises the atomic-
publish-vs-concurrent-read path: the trigger atomically publishes a new manifest and
bumps the sentinel while the in-process watcher rebuilds and the query threads read.

Two sentinels flip in OPPOSITE directions across the reload:

  * ``SENT_A``: blocked in gen1, allowed in gen2  (block → allow)
  * ``SENT_B``: allowed in gen1, blocked in gen2  (allow → block)

so a CONSISTENT snapshot has EXACTLY ONE of them blocked. A query that captures the live
snapshot once (as ``operate()`` does) and sees BOTH or NEITHER blocked is a **torn
read** — the exact failure the single-ref GIL-atomic, build-new-then-rebind swap must
make impossible. The trigger sleeps a ``wait_before`` first so the query threads
accumulate a gen1 baseline before the flip (per the repo's before/after rule).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from typing import Any

import pfb_unbound as P

_TRIGGER = os.path.join(os.path.dirname(__file__), "_adr10_reload_trigger.py")

# Exact-match data_db keys (looked up directly in the snapshot, never DNS-queried, so the
# RFC-6761 / HSTS constraints that bind the smoke suite do not apply here).
SENT_A = "asentinel.pfbconctest.com"  # gen1 blocked  -> gen2 allowed
SENT_B = "bsentinel.pfbconctest.com"  # gen1 allowed  -> gen2 blocked


def _write(path: str, data: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


def _manifest_json(raw_path: str) -> str:
    """A minimal one-feed manifest whose raw file lists the blocked domain(s)."""
    return json.dumps(
        {
            "version": 1,
            "config": {
                "tld_master": "",
                "tld_blacklist": [],
                "tld_exclusion": [],
                "user_whitelist": [],
                "top1m_list": [],
                "top1m_enabled": False,
            },
            "feeds": [{"raw": raw_path, "feed": "conc", "group": "conc", "format_hint": "", "log_flag": "1"}],
        }
    )


def _setup_module(tmp_path: Any, monkeypatch: Any) -> dict[str, str]:
    """Wire the module so the REAL background builder (``_build_swap_snapshot``) rebuilds
    from a manifest on disk and the watcher swaps it in — no live Unbound, no sqlite."""
    raw_a = str(tmp_path / "feed_a.txt")
    _write(raw_a, SENT_A + "\n")  # gen1: A blocked
    raw_b = str(tmp_path / "feed_b.txt")
    _write(raw_b, SENT_B + "\n")  # gen2: B blocked
    manifest = str(tmp_path / "pfb_py_sources.json")
    _write(manifest, _manifest_json(raw_a))
    gen2_src = str(tmp_path / "gen2_sources.json")
    _write(gen2_src, _manifest_json(raw_b))  # what the trigger publishes
    sentinel = str(tmp_path / "pfb_py_reload")
    _write(sentinel, "1\n")
    applied = str(tmp_path / "pfb_py_reload.applied")

    P.pfb["pfb_py_sources"] = manifest
    P.pfb["pfb_py_reload"] = sentinel
    P.pfb["pfb_py_reload_applied"] = applied
    P.pfb["pfb_unbound.ini"] = str(tmp_path / "absent.ini")  # no user-regex section
    P.pfb["python_hsts"] = False  # skip the hsts file load
    P.pfb["regex_cap"] = False
    P.pfb["mod_threading"] = True
    P.pfb["pfb_py_count"] = str(tmp_path / "count")
    P.pfb["pfb_py_regex_count"] = str(tmp_path / "rcount")
    monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)  # no UI count file
    monkeypatch.setattr(P, "_db_reset_cache", lambda: True)  # no Reports sqlite
    monkeypatch.setattr(P, "RELOAD_POLL_INTERVAL", 0.05)  # prompt poll + stop observation
    P.decisionDB = P._LruCache(0)
    P.pfb_reload_stop = threading.Event()

    snap = P._build_swap_snapshot()
    assert snap is not None, "gen1 build returned None"
    assert SENT_A in snap.data_db and SENT_B not in snap.data_db, "gen1 sentinels wrong"
    P._snapshot = snap
    return {"manifest": manifest, "gen2_src": gen2_src, "sentinel": sentinel, "applied": applied}


def test_separate_process_trigger_swaps_atomically_under_load(tmp_path: Any, monkeypatch: Any) -> None:
    ctx = _setup_module(tmp_path, monkeypatch)
    wait_before = 0.6
    n_threads = 8

    # The in-process watcher (real builder) — wakes on the sentinel bump and swaps.
    watcher = threading.Thread(target=P.pfb_reload_watcher, name="pfb_reload_watcher_test", daemon=True)
    watcher.start()

    stop = threading.Event()
    errors: list[str] = []
    stats: list[dict[str, int]] = []

    def query_loop() -> None:
        local = {"n": 0, "gen1": 0, "gen2": 0, "torn": 0}
        try:
            while not stop.is_set():
                snap = P._snapshot  # capture ONCE per query, exactly as operate() does
                a = SENT_A in snap.data_db
                b = SENT_B in snap.data_db
                local["n"] += 1
                if a and not b:
                    local["gen1"] += 1
                elif b and not a:
                    local["gen2"] += 1
                else:
                    local["torn"] += 1  # (blocked,blocked) or (allowed,allowed) — a mixed view
        except Exception as e:  # noqa: BLE001 — record, never let a query crash silently
            errors.append(repr(e))
        stats.append(local)

    threads = [threading.Thread(target=query_loop, daemon=True) for _ in range(n_threads)]
    for t in threads:
        t.start()

    # BEFORE: let the loops read gen1 for a moment so there is a real baseline.
    time.sleep(0.1)
    assert P._snapshot.data_db.keys() == {SENT_A}, "expected gen1 (A blocked) before the trigger"

    # Fire the trigger in a SEPARATE PROCESS: it sleeps `wait_before`, then atomically
    # publishes gen2 and bumps the sentinel — racing the query process via the filesystem.
    proc = subprocess.Popen(
        [sys.executable, _TRIGGER, str(wait_before), ctx["gen2_src"], ctx["manifest"], ctx["sentinel"]]
    )
    try:
        assert proc.wait(timeout=30) == 0, "trigger process failed to publish + flip"
        # Wait (bounded) for the watcher to APPLY gen2 under the concurrent query load.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and SENT_A in P._snapshot.data_db:
            time.sleep(0.02)
        time.sleep(0.2)  # let the loops observe gen2 a bit
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=5)
        P.pfb_reload_stop.set()
        watcher.join(timeout=5)

    # --- assertions ---
    assert not watcher.is_alive(), "watcher did not join cleanly"
    assert errors == [], f"query thread(s) raised: {errors}"

    # AFTER: the swap actually took effect (B blocked, A allowed) — live + applied marker.
    assert P._snapshot.data_db.keys() == {SENT_B}, "the gen2 swap did not take effect"
    assert P._reload_read_generation(ctx["applied"]) == 2, "watcher did not record applied gen 2"

    total_n = sum(s["n"] for s in stats)
    total_gen1 = sum(s["gen1"] for s in stats)
    total_gen2 = sum(s["gen2"] for s in stats)
    total_torn = sum(s["torn"] for s in stats)

    # CORE GUARANTEE: not one query observed a torn (mixed-generation) snapshot.
    assert total_torn == 0, f"torn reads under a concurrent swap: {[s for s in stats if s['torn']]}"
    # A gen1 baseline was read BEFORE the flip, and gen2 was read AFTER it (the flip landed).
    assert total_gen1 > 0, "no gen1 baseline observed before the swap"
    assert total_gen2 > 0, "the swapped (gen2) lists were never observed under load"
    # Queries kept flowing throughout (no stall) — every thread did real, repeated work.
    assert total_n > n_threads * 50, f"suspiciously few queries ({total_n}) — a stall?"
    assert all(s["n"] > 0 for s in stats), "a query thread never ran"
