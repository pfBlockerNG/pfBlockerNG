# pfb_unbound.py
# pfBlockerNG - Unbound resolver python integration

# part of pfSense (https://www.pfsense.org)
# Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
# Copyright (c) 2015-2024 BBcan177@gmail.com
# All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import csv
import errno
import itertools
import json
import logging
import logging.handlers
import os
import re
import select
import sys
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

# CPython 3.11+ internal regex AST parser used by the literal-prefilter to extract
# a required substring from a compiled pattern.  The import is best-effort: if the
# private module is absent (non-CPython, future rename) the prefilter degrades
# gracefully to always-run (no correctness impact, only a performance one).
try:
    import re._parser as _sre_parse  # type: ignore[attr-defined]
except Exception:
    _sre_parse = None  # type: ignore[assignment]

if TYPE_CHECKING:
    # Symbols injected by Unbound's embedded Python interpreter (pythonmod) into
    # this script's globals at runtime. They are imported here only so static
    # type checkers can resolve them; the import is never executed at runtime.
    from unboundmodule import (  # noqa: F401
        MODULE_ERROR,
        MODULE_EVENT_MODDONE,
        MODULE_EVENT_NEW,
        MODULE_EVENT_PASS,
        MODULE_FINISHED,
        MODULE_RESTART_NEXT,
        MODULE_WAIT_MODULE,
        MODULE_WAIT_SUBQUERY,
        PKT_QR,
        PKT_RA,
        PKT_RD,
        RCODE_NOERROR,
        RCODE_NXDOMAIN,
        RR_CLASS_IN,
        RR_TYPE_A,
        RR_TYPE_AAAA,
        RR_TYPE_ANY,
        RR_TYPE_CNAME,
        RR_TYPE_DNAME,
        RR_TYPE_MX,
        RR_TYPE_NS,
        RR_TYPE_PTR,
        RR_TYPE_SIG,
        RR_TYPE_SRV,
        RR_TYPE_TXT,
        DNSMessage,
        invalidateQueryInCache,
        log_err,
        log_info,
        log_warn,
        module_env,
        module_qstate,
        query_info,
        register_inplace_cb_query_response,
        register_inplace_cb_reply,
        register_inplace_cb_reply_cache,
        register_inplace_cb_reply_local,
        register_inplace_cb_reply_servfail,
        reply_info,
        sec_status_indeterminate,
        sec_status_insecure,
        storeQueryInCache,
    )

global pfb
pfb: dict[str, Any] = {}

# ADR-08: stdlib unicodedata backs the inlined IDN homoglyph analyzer below (script_of).
import unicodedata
from collections import OrderedDict, defaultdict
from configparser import ConfigParser

# Module-level globals populated by init_standard() at runtime. Declared here
# without assignment (PEP 526) so type checkers can resolve them across the
# functions that reference them via `global`; no runtime object is created.
rcodeDB: dict[int, str]
dataDB: defaultdict[str, Any]
zoneDB: defaultdict[str, Any]
regexDB: defaultdict[str, Any]
allowRegexDB: defaultdict[str, Any]
hstsDB: defaultdict[str, Any]
whiteDB: defaultdict[str, Any]
gpListDB: defaultdict[str, Any]
noAAAADB: defaultdict[str, Any]
decisionDB: _LruCache
_dnsbl_last_event: Any = None
safeSearchDB: defaultdict[str, Any]
feedGroupIndexDB: defaultdict[int, Any]
maxmindReader: Any

# ADR-10: the single module-level reference to the current immutable matcher
# snapshot. init_standard builds it from the loaded strata and assigns it ONCE
# (replacing the per-global query-time read); operate() captures this ONE ref per
# query and reads every matcher field off it. A future zero-downtime reload rebinds
# this ref atomically (GIL-atomic STORE), so a query sees the whole old or the whole
# new snapshot, never a torn mix. Declared without assignment (PEP 526); the runtime
# object is created in init_standard.
_snapshot: Snapshot

# Background I/O worker (file + sqlite writes off the DNS response path)
pfb_task_queue: queue.Queue
pfb_worker_thread: Any
pfb_db_queue: queue.Queue
pfb_db_worker_thread: Any
pfb_log_queue: queue.Queue
pfb_log_listener: Any
pfb_loggers: dict[str, Any] = {}

# ADR-10: the reload-watcher daemon thread + its stop handle (a threading.Event).
# The watcher waits on the reload sentinel's DIRECTORY and runs rebuild_and_swap() off
# the query threads on a generation-id advance. Declared here; created in init_standard
# (gated on pfb["mod_threading"]) and joined in deinit.
pfb_reload_watcher_thread: Any
pfb_reload_stop: Any

# PFBL-03: the DNSBL-control command-channel reader daemon + its stop handle. The
# watcher waits on the control file's DIRECTORY (mirroring the reload watcher) and routes
# a fresh command through pfb_apply_control_command() OFF the query threads. Declared
# here; created in init_standard (gated on pfb["mod_threading"]) and joined in deinit.
pfb_control_watcher_thread: Any
pfb_control_stop: Any

if TYPE_CHECKING:
    # Modules imported defensively in the try/except guards below. Declared here
    # unconditionally so static checkers treat them as always bound (the runtime
    # guards leave them possibly-unbound). This block never executes at runtime.
    import ipaddress
    import queue
    import sqlite3
    import threading

    import maxminddb

# Import additional python modules
try:
    import queue  # noqa: F811
    import threading  # noqa: F811

    pfb["mod_threading"] = True
except Exception as e:
    pfb["mod_threading"] = False
    pfb["mod_threading_e"] = e
    pass

try:
    import ipaddress  # noqa: F811

    pfb["mod_ipaddress"] = True
except Exception as e:
    pfb["mod_ipaddress"] = False
    pfb["mod_ipaddress_e"] = e
    pass

try:
    import maxminddb  # noqa: F811

    pfb["mod_maxminddb"] = True
except Exception as e:
    pfb["mod_maxminddb"] = False
    pfb["mod_maxminddb_e"] = e
    pass

try:
    import sqlite3  # noqa: F811

    pfb["mod_sqlite3"] = True
except Exception as e:
    pfb["mod_sqlite3"] = False
    pfb["mod_sqlite3_e"] = e
    pass


PFB_QUEUE_MAXSIZE = 5000


def pfb_async_worker() -> None:
    # Single background consumer for file/sqlite I/O. FIFO order is preserved so
    # query counters and log lines stay consistent and chronological.
    while True:
        task = pfb_task_queue.get()
        try:
            if task is None:
                break
            func, args = task
            func(*args)
        except Exception as e:
            err = sys.__stderr__
            if err is not None:
                try:
                    err.write("[pfBlockerNG]: async I/O worker error: {}\n".format(e))
                except Exception:
                    pass
        finally:
            pfb_task_queue.task_done()


def pfb_async(func: Callable[..., Any], *args: Any) -> None:
    # Enqueue file/sqlite I/O for the background worker. Falls back to
    # synchronous execution when the worker is not running (during init, in the
    # test suite, or when threading is unavailable). Drops the task if the
    # bounded queue is saturated, so the DNS response path is never blocked.
    if pfb.get("async_worker"):
        try:
            pfb_task_queue.put_nowait((func, args))
            return
        except queue.Full:
            pfb["async_dropped"] = pfb.get("async_dropped", 0) + 1
            return
    func(*args)


# --------------------------------------------------------------------------- #
# ADR-10: zero-downtime reload-watcher daemon (gated on pfb["mod_threading"]).
# Watches a generation-id sentinel PHP/shell advance after an atomic publish;
# on advance, rebuild_and_swap() builds off the query threads and swaps in
# the new snapshot via one GIL-atomic ref rebind (old snapshot serves until
# then; single-flight). Watch is kqueue EVFILT_VNODE on the sentinel's
# directory where available, else a low-frequency mtime poll. RAM-gated:
# declines the swap fail-closed if the OLD+NEW-resident build would not fit.
# Pinned by tests/test_adr10_watcher.py, tests/test_adr10_swap.py.
# --------------------------------------------------------------------------- #

# Steady-state retained bytes per matcher entry (ADR-05 SS3a / ADR-10 spike:
# 274-276 B/entry). Used to PROJECT the both-resident transient of an in-process build.
RELOAD_BYTES_PER_ENTRY = 276
# Headroom kept free above the projected transient so the build does not drive the box
# to the OOM edge (Unbound's own C message cache, the OS, PHP/cron also need RAM).
RELOAD_RAM_HEADROOM_BYTES = 64 * 1024 * 1024
# Low-frequency poll cadence for the mtime fallback (and the kqueue wait timeout, so the
# stop Event is observed promptly). Best-effort -- a small delay is acceptable by design.
RELOAD_POLL_INTERVAL = 2.0


def _reload_total_ram_bytes() -> int | None:
    """Best-effort TOTAL physical RAM in bytes, stdlib only.

    ``os.sysconf('SC_PHYS_PAGES')`` x ``SC_PAGE_SIZE`` (present on FreeBSD and Linux).
    This is the watcher's COARSE OOM-impossibility backstop: it asks only "could the ~2x
    transient build ever fit in this box's RAM at all?", consistent with PHP's primary
    ``hw.usermem`` gate (also total). PHP's gate is the authoritative pre-flip decision;
    the watcher deliberately does NOT second-guess it on free-page tightness -- a healthy
    cache-heavy box runs with little FREE but ample reclaimable RAM, so a free-page gate
    here (the old ``SC_AVPHYS_PAGES``) spuriously DECLINED a PHP-approved swap and forced
    a needless restart. Returns ``None`` when the platform cannot report it (the caller
    then DECLINES -- fail-closed)."""
    try:
        names = os.sysconf_names  # type: ignore[attr-defined]
        if "SC_PHYS_PAGES" in names and "SC_PAGE_SIZE" in names:
            total_pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            if total_pages >= 0 and page_size > 0:
                return total_pages * page_size
    except (ValueError, OSError, AttributeError):
        pass
    return None


def _reload_ram_gate_ok(
    entry_count: int,
    *,
    total_ram: Callable[[], int | None] | None = None,
) -> bool:
    """True iff an in-process rebuild for ``entry_count`` entries could fit in RAM.

    Coarse OOM-impossibility backstop (PHP's gate is the authoritative pre-flip check):
    projects the both-resident transient (~2x: OLD + NEW set) as
    ``2 x entry_count x RELOAD_BYTES_PER_ENTRY`` and requires TOTAL physical RAM to cover
    it plus ``RELOAD_RAM_HEADROOM_BYTES``. Gating on total (not free) keeps it consistent
    with PHP and avoids spuriously declining a PHP-approved swap on a cache-heavy box
    (which would stall PHP to its wait-for-apply timeout and force a needless restart).
    ``total_ram`` is injectable for testing; when omitted it resolves the module probe at
    CALL time. Fail-closed: if total RAM is unknown, the gate DECLINES (returns False)."""
    probe = total_ram if total_ram is not None else _reload_total_ram_bytes
    total = probe()
    if total is None:
        return False
    projected = 2 * max(entry_count, 0) * RELOAD_BYTES_PER_ENTRY
    return total >= projected + RELOAD_RAM_HEADROOM_BYTES


def _reload_read_generation(sentinel_path: str) -> int | None:
    """Read the generation id from the sentinel, or ``None`` if absent/unreadable.

    The generation is a monotonically-advancing base-10 integer on the FIRST line of
    the sentinel file (PHP/shell write it after the atomic manifest publish). A missing
    or unparseable sentinel yields ``None`` (treated as "no advance" -- best-effort)."""
    try:
        with open(sentinel_path, encoding="utf-8") as fh:
            line = fh.readline().strip()
    except OSError:
        return None
    if not line:
        return None
    try:
        return int(line)
    except ValueError:
        return None


def _reload_write_applied(gen: int) -> None:
    """Publish ``gen`` as the APPLIED-generation marker (atomic temp + ``os.replace``).

    Written by the watcher after a successful swap (and once at startup with the
    baseline). PHP polls it to learn the live generation -- the readiness handshake that
    replaces "wait for the Unbound restart" for a no-restart data update. Best-effort: a
    write failure is logged (to py_error.log via the redirected stderr) and the swap
    still stands; PHP's wait then times out and falls back to the restart (fail-safe)."""
    path = pfb.get("pfb_py_reload_applied")
    if not path:
        return
    tmp = "{}.tmp".format(path)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("{}\n".format(int(gen)))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError as e:
        sys.stderr.write("[pfBlockerNG]: failed to write applied-generation marker [ {} ]: {}\n".format(path, e))
        try:
            os.unlink(tmp)
        except OSError:
            pass


# ADR-61: Python's OWN structured status ledger (``pfb_py_status.json``, chroot-relative
# alongside ``pfb_py_reload``) -- Python writes it, PHP only ever reads it (a read-only
# merge helper lives in pfblockerng_extra.inc). Entries are ``{facility, item, stage,
# message, first_seen, last_seen}``, the same shape as PHP's own pfb_sync_status.json for
# display consistency, but a SEPARATE file (the two-file boundary is load-bearing, not
# incidental -- see the ADR's cross-process-boundary section). Every entry here uses
# facility="dnsbl", stage="parse" (Python owns only the DNSBL parse-stage signal; the
# apply-stage entries for the SAME facility are PHP-owned under a different key).


def _pfb_py_status_read_all() -> list[dict[str, Any]]:
    """Read the full ledger. Absent file, unreadable file, or corrupt/wrong-shape
    JSON all degrade to an empty list (fail-open), never raise."""
    path = pfb.get("pfb_py_status")
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def _pfb_py_status_write_all(entries: list[dict[str, Any]]) -> None:
    """Atomically persist the full ledger (temp write + fsync + ``os.replace``),
    mirroring ``_reload_write_applied()``'s idiom. A write failure is a silent
    no-op -- the ledger is a display-only signal, never worth raising over."""
    path = pfb.get("pfb_py_status")
    if not path:
        return
    tmp = "{}.tmp".format(path)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(entries, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# init_standard() runs once per Unbound worker thread (same shared interpreter/globals
# as decisionDB's _LruCache above), so a read-modify-write span here needs the same
# lock-protects-the-whole-span treatment -- two threads' open()/close() calls can
# otherwise interleave their _pfb_py_status_read_all()/_write_all() and silently drop
# one thread's update (the classic lost-update race).
_pfb_py_status_lock: Any = threading.Lock() if pfb.get("mod_threading") else nullcontext()


def pfb_py_status_open(
    facility: str, item: str, stage: str, message: str, clock_fn: Callable[[], int] | None = None
) -> None:
    """Open (or refresh) one ``{facility, item, stage}`` entry.

    Idempotent by key: refreshing an already-open key updates ``message``/
    ``last_seen`` in place and preserves the original ``first_seen`` -- never
    duplicates the entry."""
    now = clock_fn() if clock_fn is not None else int(time.time())
    with _pfb_py_status_lock:
        entries = _pfb_py_status_read_all()
        for entry in entries:
            if entry.get("facility") == facility and entry.get("item") == item and entry.get("stage") == stage:
                entry["message"] = message
                entry["last_seen"] = now
                _pfb_py_status_write_all(entries)
                return
        entries.append(
            {
                "facility": facility,
                "item": item,
                "stage": stage,
                "message": message,
                "first_seen": now,
                "last_seen": now,
            }
        )
        _pfb_py_status_write_all(entries)


def pfb_py_status_close(facility: str, item: str, stage: str) -> None:
    """Clear one ``{facility, item, stage}`` entry. Closing an absent key is a
    safe no-op -- no write."""
    with _pfb_py_status_lock:
        entries = _pfb_py_status_read_all()
        filtered = [
            entry
            for entry in entries
            if not (entry.get("facility") == facility and entry.get("item") == item and entry.get("stage") == stage)
        ]
        if len(filtered) == len(entries):
            return
        _pfb_py_status_write_all(filtered)


def _build_swap_snapshot() -> Snapshot | None:
    """The background reload builder: re-read the manifest, rebuild every matcher
    stratum into FRESH dicts (mutating NO live dict), and return a new Snapshot -- or
    ``None`` to fail-closed (rebuild_and_swap then keeps the live snapshot).

    Reproduces init's DNSBL load off fresh local dicts so the swapped snapshot is the
    exact set the manifest + ini + static cap define (decision-identical to a fresh init
    load):
      * dnsbl_build_from_manifest() -> data/zone/feedGroupIndex/white + FEED block-regex
        + @@/re/ allow-regex + the important_rules fast-path flag + the loaded count.
        ``None`` (absent/unparseable manifest, build error) -> the whole swap is a no-op.
      * USER REGEX-ini patterns merged on top (band PRIO_USER_BLOCK, sovereign over feed
        allows), honouring the opt-in static cap -- so a swap NEVER drops user regex
        (ADR-07).
      * hstsDB reloaded from pfb_py_hsts.txt (watch-out (b): hstsDB is NOT in the
        manifest; omitting it would ship an empty hsts_db and silently flip HSTS NULL-vs-
        VIP behaviour)."""
    build_result = dnsbl_build_from_manifest(pfb["pfb_py_sources"])
    if build_result is None:
        return None

    data_db = build_result.data_db
    zone_db = build_result.zone_db
    feed_group_index_db = build_result.feed_group_index_db
    white_db = build_result.white_db
    regex_db: dict[str, Any] = dict(build_result.regex_db)
    allow_regex_db: dict[str, Any] = dict(build_result.allow_regex_db)

    # USER REGEX-ini patterns (sovereign band) merged on top of the feed block-regex,
    # mirroring init's REGEX-section load (incl. the opt-in static cap).
    if os.path.isfile(pfb["pfb_unbound.ini"]):
        config = ConfigParser()
        try:
            config.read(pfb["pfb_unbound.ini"])
            if config.has_section("REGEX"):
                r_count = 1
                for name, pattern in config.items("REGEX"):
                    if _regex_is_catastrophic_shape(pattern):
                        sys.stderr.write(
                            "[pfBlockerNG]: dropping pathological user regex [ {} ] pattern [ {} ] "
                            "on line #{} (catastrophic shape)".format(name, pattern, r_count)
                        )
                        r_count += 1
                        continue
                    if pfb["regex_cap"] and len(pattern) > REGEX_STATIC_LEN_CAP:
                        sys.stderr.write(
                            "[pfBlockerNG]: dropping over-length user regex [ {} ] pattern [ {} ] "
                            "on line #{} (static length cap)".format(name, pattern, r_count)
                        )
                        r_count += 1
                        continue
                    try:
                        regex_db[name] = {
                            "re": re.compile(pattern),
                            "important": False,
                            "band": PRIO_USER_BLOCK,
                        }
                    except Exception as e:
                        sys.stderr.write(
                            "[pfBlockerNG]: Regex [ {} ] compile error pattern [  {}  ] on line #{}: {}".format(
                                name, pattern, r_count, e
                            )
                        )
                    r_count += 1
        except Exception as e:
            sys.stderr.write("[pfBlockerNG]: reload: failed to load user REGEX ini: {}".format(e))

    # HSTS reloaded from the static file (watch-out b -- not in the manifest).
    hsts_db: dict[str, Any] = {}
    if pfb["python_hsts"] and os.path.isfile(pfb["pfb_py_hsts"]):
        try:
            with open(pfb["pfb_py_hsts"]) as hsts:
                for line in hsts:
                    hsts_db[line.rstrip("\r\n")] = 0
        except Exception as e:
            sys.stderr.write("[pfBlockerNG]: reload: failed to load {}: {}".format(pfb["pfb_py_hsts"], e))

    return Snapshot(
        data_db=data_db,
        zone_db=zone_db,
        white_db=white_db,
        regex_db=regex_db,
        allow_regex_db=allow_regex_db,
        feed_group_index_db=feed_group_index_db,
        hsts_db=hsts_db,
        important_rules=bool(build_result.important_rules),
        counts=len(data_db) + len(zone_db),
        regex_count=len(regex_db) + len(allow_regex_db),
        rejects=build_result.rejects,
    )


def _reload_run_swap(builder: Callable[[], Snapshot | None]) -> bool:
    """Run ONE RAM-gated rebuild_and_swap() for the watcher (off the query threads).

    Projects the build's transient from the LIVE snapshot's entry count and consults the
    RAM gate FIRST; if the box cannot fit the ~2x transient, DECLINE fail-closed -- the
    old snapshot stays live, log that the update needs the restart fallback. Otherwise
    delegate to the fail-closed rebuild_and_swap (default emit_counts=True so the
    UI counts refresh without a restart).

    Returns ``True`` iff the snapshot was actually swapped in (the caller then advances
    the applied-generation marker); ``False`` on a RAM decline OR a failed/empty build
    (the marker is NOT advanced, so PHP's wait times out and falls back to the restart)."""
    snap = _snapshot
    entry_count = snap.counts + snap.regex_count if snap is not None else 0
    if not _reload_ram_gate_ok(entry_count):
        log_info(
            "[pfBlockerNG]: DNSBL reload DECLINED -- RAM-constrained box (projected ~{} MiB "
            "for {} entries would not fit total RAM); keeping current lists, the update "
            "needs the restart fallback".format(
                (2 * entry_count * RELOAD_BYTES_PER_ENTRY) // (1024 * 1024), entry_count
            )
        )
        return False
    if rebuild_and_swap(builder):
        log_info("[pfBlockerNG]: DNSBL lists reloaded with no restart (zero-downtime swap)")
        return True
    return False


def pfb_reload_watcher(builder: Callable[[], Snapshot | None] = _build_swap_snapshot) -> None:
    """Daemon body: wait on the reload sentinel and run a single-flight, RAM-gated swap
    on every generation ADVANCE, until the stop Event is set.

    ``builder`` is injectable (the production default rebuilds from the manifest; tests
    pass a stub). The function reads the sentinel's generation, swaps on an advance, then
    waits for the next change via kqueue EVFILT_VNODE on the sentinel's DIRECTORY (or the
    mtime-poll fallback), re-checking the generation after each wake AND after each build
    (single-flight coalescing: a trigger during a build is folded into one more build iff
    the generation advanced)."""
    sentinel = pfb["pfb_py_reload"]
    watch_dir = os.path.dirname(os.path.abspath(sentinel)) or "."

    # Baseline: adopt the CURRENT generation WITHOUT building (init already loaded the
    # lists synchronously -- the watcher only acts on a FUTURE advance). Publish that
    # baseline as the applied generation so PHP's first wait-for-apply (after a flip)
    # has a floor to compare against and never blocks on a stale/absent marker.
    last_gen = _reload_read_generation(sentinel)
    if last_gen is not None:
        _reload_write_applied(last_gen)

    def drain_and_swap() -> None:
        # Single-flight: build for the latest generation, then re-check; if it advanced
        # again during the build, build once more. Loops until stable or stop is set.
        nonlocal last_gen
        while not pfb_reload_stop.is_set():
            cur = _reload_read_generation(sentinel)
            if cur is None or (last_gen is not None and cur <= last_gen):
                return
            last_gen = cur
            # Advance the applied marker ONLY on a real swap -- a RAM decline / failed
            # build returns False, leaving the marker behind so PHP times out and
            # restarts (the new lists still load, just via the fail-safe path).
            if _reload_run_swap(builder):
                _reload_write_applied(cur)

    waiter = _ReloadKqueueWaiter(watch_dir) if hasattr(select, "kqueue") else None
    if waiter is not None and not waiter.is_active():
        # kqueue setup failed -> its wait() returns immediately, which would hot-spin
        # this loop. Drop to the mtime-poll fallback (the stop-Event wait) instead.
        waiter.close()
        waiter = None
    try:
        while not pfb_reload_stop.is_set():
            # Act on any advance already pending (covers the gap between baseline and the
            # first wait, and the poll-fallback path).
            drain_and_swap()
            if pfb_reload_stop.is_set():
                break
            if waiter is not None:
                waiter.wait(RELOAD_POLL_INTERVAL)
            else:
                # mtime-poll fallback (kqueue unavailable, e.g. Linux/CI): sleep on the
                # stop Event so deinit wakes us immediately; the generation re-check on
                # the next loop is what actually drives the swap.
                pfb_reload_stop.wait(RELOAD_POLL_INTERVAL)
    except Exception as e:
        err = sys.__stderr__
        if err is not None:
            try:
                err.write("[pfBlockerNG]: reload watcher error: {}\n".format(e))
            except Exception:
                pass
    finally:
        if waiter is not None:
            waiter.close()


class _ReloadKqueueWaiter:
    """A select.kqueue EVFILT_VNODE waiter on a DIRECTORY fd (FreeBSD).

    Watching the directory -- not the sentinel file fd -- survives an atomic rename/
    replace of the sentinel (the file inode changes; the dir is notified WRITE/RENAME).
    ``wait(timeout)`` blocks until a vnode event OR the timeout (so the stop Event is
    seen promptly). Best-effort: any kqueue error degrades to a timed wait."""

    def __init__(self, watch_dir: str) -> None:
        self._kq: Any = None
        self._fd: int = -1
        try:
            self._fd = os.open(watch_dir, os.O_RDONLY)
            self._kq = select.kqueue()
            ev = select.kevent(
                self._fd,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=(
                    select.KQ_NOTE_WRITE
                    | select.KQ_NOTE_EXTEND
                    | select.KQ_NOTE_RENAME
                    | select.KQ_NOTE_DELETE
                    | select.KQ_NOTE_ATTRIB
                ),
            )
            self._kq.control([ev], 0, 0)
        except OSError as e:
            sys.stderr.write("[pfBlockerNG]: reload watcher kqueue setup failed, polling instead: {}".format(e))
            self.close()

    def is_active(self) -> bool:
        """True iff kqueue set up successfully; False ⇒ caller should mtime-poll instead."""
        return self._kq is not None

    def wait(self, timeout: float) -> None:
        if self._kq is None:
            return
        try:
            self._kq.control(None, 1, timeout)
        except OSError as e:
            if e.errno != errno.EINTR:
                sys.stderr.write("[pfBlockerNG]: reload watcher kqueue wait error: {}".format(e))

    def close(self) -> None:
        if self._kq is not None:
            try:
                self._kq.close()
            except OSError:
                pass
            self._kq = None
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1


# --------------------------------------------------------------------------- #
# PFBL-03: the local privileged DNSBL-control command channel (reader daemon).
# Mirrors the ADR-10 reload watcher: waits on the control file's directory
# (kqueue EVFILT_VNODE, mtime-poll fallback); on change, reads a JSON record
# carrying a monotonic SEQUENCE and ignores any seq <= last-applied (exactly-
# once + replay safety). A fresh record routes through the shared
# pfb_apply_control_command() handler; runs off the query threads.
# --------------------------------------------------------------------------- #


def _control_read_record(path: str) -> dict[str, Any] | None:
    """Read + parse the control channel's JSON record, or ``None`` if absent/unreadable/
    malformed. Best-effort: any read or JSON error yields ``None`` (treated as "no
    command")."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return None
    if not raw.strip():
        return None
    try:
        record = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(record, dict):
        return None
    return record


def _control_write_applied(seq: int) -> None:
    """Publish ``seq`` as the APPLIED-sequence marker (atomic temp + ``os.replace``).

    Written by the watcher after it consumes a record so the writer can confirm the
    command ran. Best-effort: a write failure is logged and the command still stands."""
    path = pfb.get("pfb_py_control_applied")
    if not path:
        return
    tmp = "{}.tmp".format(path)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("{}\n".format(int(seq)))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError as e:
        sys.stderr.write("[pfBlockerNG]: failed to write control applied marker [ {} ]: {}\n".format(path, e))
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _control_record_to_command(record: dict[str, Any]) -> list[str] | None:
    """Translate a control JSON record into the dot-split token list the shared handler
    consumes (mirroring the DNS-TXT q_name split), or ``None`` when the command is
    unknown / the required fields are absent. The shared handler re-validates the IP and
    duration; this only assembles the tokens.

    Record shape: ``{"seq": int, "cmd": "disable|enable|addbypass|removebypass",
    "ip": "<v4/v6>", "duration": <int>, "ts": <epoch>}`` -- ``ip``/``duration`` present
    only for the commands that take them."""
    cmd = record.get("cmd")
    if cmd not in ("disable", "enable", "addbypass", "removebypass"):
        return None

    command = ["python_control", cmd]
    if cmd in ("addbypass", "removebypass"):
        ip = record.get("ip")
        if not isinstance(ip, str) or ip == "":
            return None
        # The shared handler un-maps '-' to '.' (the DNS-TXT transport encoding); the
        # channel carries the IP verbatim, so a dotted IPv4 passes through unchanged.
        command.append(ip)
    elif cmd == "disable":
        # disable carries an optional duration as the 3rd token (validated downstream).
        if "duration" in record:
            command.append("{}".format(record.get("duration")))
        return command

    # addbypass takes an optional duration as the 4th token.
    if cmd == "addbypass" and "duration" in record:
        command.append("{}".format(record.get("duration")))

    return command


def pfb_control_watcher() -> None:
    """Daemon body: wait on the control channel and apply each FRESH command (seq advance)
    until the stop Event is set.

    Adopts the current seq at startup WITHOUT applying (a record already on disk from a
    prior run is not replayed), publishes it as the applied baseline, then on every change
    reads the record, applies it iff its seq strictly advances, and republishes the
    applied seq. Single-flight by construction (one record at a time, latest seq wins)."""
    channel = pfb["pfb_py_control"]
    watch_dir = os.path.dirname(os.path.abspath(channel)) or "."

    # Baseline: adopt the seq of any record already present WITHOUT applying it -- the
    # watcher only acts on a FUTURE advance (mirrors the reload watcher's baseline).
    last_seq = 0
    record = _control_read_record(channel)
    if record is not None:
        seq = record.get("seq")
        if isinstance(seq, int):
            last_seq = seq
    _control_write_applied(last_seq)

    def drain_and_apply() -> None:
        nonlocal last_seq
        while not pfb_control_stop.is_set():
            rec = _control_read_record(channel)
            if rec is None:
                return
            seq = rec.get("seq")
            if not isinstance(seq, int) or seq <= last_seq:
                return
            last_seq = seq
            command = _control_record_to_command(rec)
            if command is not None:
                applied, msg = pfb_apply_control_command(command)
                if msg:
                    log_info("[pfBlockerNG]: {}".format(msg))
            # Advance the applied marker on every consumed record (advance or rejection),
            # so the writer's wait never blocks on a record the reader already saw.
            _control_write_applied(seq)

    waiter = _ReloadKqueueWaiter(watch_dir) if hasattr(select, "kqueue") else None
    if waiter is not None and not waiter.is_active():
        waiter.close()
        waiter = None
    try:
        while not pfb_control_stop.is_set():
            drain_and_apply()
            if pfb_control_stop.is_set():
                break
            if waiter is not None:
                waiter.wait(RELOAD_POLL_INTERVAL)
            else:
                pfb_control_stop.wait(RELOAD_POLL_INTERVAL)
    except Exception as e:
        err = sys.__stderr__
        if err is not None:
            try:
                err.write("[pfBlockerNG]: control watcher error: {}\n".format(e))
            except Exception:
                pass
    finally:
        if waiter is not None:
            waiter.close()


def parse_python_tlds(raw: str) -> list[str]:
    """Parse the MAIN-ini ``python_tlds`` value into a cleaned TLD-Allow list.

    issue #713: the previous unconditional ``raw.split(",")`` left a degenerate value
    (absent/empty ini key -- "") as ``['']`` -- a non-empty LIST holding one blank
    entry. That fed a buggy ``!= ""`` guard (a list is never equal to a str, so it was
    ALWAYS True) which force-enabled the TLD-Allow blacklist even with no TLDs
    configured -- "empty TLD-Allow blocks all". Splitting, stripping, and dropping
    blank entries here makes an empty/whitespace-only value parse to ``[]`` (falsy),
    so the caller's plain truthiness guard (``if python_tld and python_tlds:``) behaves
    correctly.

    issue #720: entries are lowercased too. The GUI's TLD checkboxes are lowercase,
    but the value also splices in the SYSTEM DOMAIN's TLD (``system/domain`` -- a
    case-preserved free-text field), and the TLD-Allow membership test compares
    against the lowercased qname label (RFC 4343) -- so normalise the config side
    at the same read boundary.
    """
    return [t.strip().lower() for t in raw.split(",") if t.strip()]


def _parse_ini_int(config: ConfigParser, section: str, option: str) -> int | None:
    """Parse an integer MAIN-ini option; ``None`` on a malformed (non-integer) value.

    issue #713: ``ConfigParser.getint()`` raises ``ValueError`` on a non-integer ini
    value. Mirrors the existing ``regex_warn_ms``/``regex_evict_ms`` try/except-ValueError
    guard (a few lines below the callers in ``init_standard``) so a malformed
    ``python_tld_seg``/``decisiondb_max`` value can no longer throw out of module init
    and take the whole Unbound Python module down. The caller keeps its own current
    value on a ``None`` return instead of crashing.
    """
    try:
        return config.getint(section, option)
    except ValueError:
        return None


def warn_if_legacy_control_enabled(enabled: bool) -> None:
    """PFBL-03: log a one-time deprecation warning at module load when the legacy
    DNS-TXT control transport is enabled. Neutral wording -- the path is deprecated
    and less secure than the CLI, and will be removed in a future release."""
    if enabled:
        log_warn(
            "[pfBlockerNG]: DNSBL Control legacy DNS-TXT transport is enabled. It is "
            "deprecated and less secure than the CLI and will be removed in a future "
            "release; migrate CRON/Scheduler tasks to the 'pfblockerng dnsbl-control' CLI."
        )


def _load_zone_db(feed_group_db: defaultdict[str, int], feed_group_index: int) -> int:
    """Parse the legacy zone CSV (``pfb["pfb_py_zone"]``) into ``zoneDB`` -- skipped
    when the ADR-06 manifest already built it. Extracted out of ``init_standard``
    (mirrors ``_load_safesearch_db``) so the load -- and its failure diagnostic --
    are unit-testable without the full Unbound ``env``/``id`` init rig. Returns the
    advanced ``feed_group_index`` (shared with ``_load_data_db`` across both files).
    Behaviour-preserving: same parse rules, same ``pfb["zoneDB"]`` flag."""
    if not os.path.isfile(pfb["pfb_py_zone"]):
        pfb_py_status_close("dnsbl", pfb["pfb_py_zone"], "parse")
        return feed_group_index
    try:
        with open(pfb["pfb_py_zone"]) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=",")
            for row in csv_reader:
                if row and len(row) == 6:
                    # Query Feed/Group/index
                    isInFeedGroupDB = feed_group_db.get(row[4] + row[5])

                    # Add Feed/Group/index
                    if isInFeedGroupDB is None:
                        feed_group_db[row[4] + row[5]] = feed_group_index
                        feedGroupIndexDB[feed_group_index] = {"feed": row[4], "group": row[5]}
                        final_index = feed_group_index
                        feed_group_index += 1

                    # Use existing Feed/Group/index
                    else:
                        final_index = isInFeedGroupDB

                    zoneDB[row[1]] = {"log": row[3], "index": final_index, "important": False}
                else:
                    sys.stderr.write("[pfBlockerNG]: Failed to parse: {}: {}".format(pfb["pfb_py_zone"], row))

            pfb["zoneDB"] = True
            pfb["python_blacklist"] = True
            pfb_py_status_close("dnsbl", pfb["pfb_py_zone"], "parse")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_zone"], e))
        pfb_py_status_open("dnsbl", pfb["pfb_py_zone"], "parse", "Failed to load: {}: {}".format(pfb["pfb_py_zone"], e))
    return feed_group_index


def _load_data_db(feed_group_db: defaultdict[str, int], feed_group_index: int) -> int:
    """Parse the legacy data CSV (``pfb["pfb_py_data"]``) into ``dataDB`` -- skipped
    when the ADR-06 manifest already built it. Same extraction rationale/shape as
    ``_load_zone_db`` (shares ``feed_group_db``/``feed_group_index`` with it)."""
    if not os.path.isfile(pfb["pfb_py_data"]):
        pfb_py_status_close("dnsbl", pfb["pfb_py_data"], "parse")
        return feed_group_index
    try:
        with open(pfb["pfb_py_data"]) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=",")
            for row in csv_reader:
                if row and len(row) == 6:
                    # Query Feed/Group/index
                    isInFeedGroupDB = feed_group_db.get(row[4] + row[5])

                    # Add Feed/Group/index
                    if isInFeedGroupDB is None:
                        feed_group_db[row[4] + row[5]] = feed_group_index
                        feedGroupIndexDB[feed_group_index] = {"feed": row[4], "group": row[5]}
                        final_index = feed_group_index
                        feed_group_index += 1

                    # Use existing Feed/Group/index
                    else:
                        final_index = isInFeedGroupDB

                    dataDB[row[1]] = {"log": row[3], "index": final_index, "important": False}
                else:
                    sys.stderr.write("[pfBlockerNG]: Failed to parse: {}: {}".format(pfb["pfb_py_data"], row))

            pfb["dataDB"] = True
            pfb["python_blacklist"] = True
            pfb_py_status_close("dnsbl", pfb["pfb_py_data"], "parse")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_data"], e))
        pfb_py_status_open("dnsbl", pfb["pfb_py_data"], "parse", "Failed to load: {}: {}".format(pfb["pfb_py_data"], e))
    return feed_group_index


def _load_whitelist_db() -> None:
    """Parse the legacy user whitelist CSV (``pfb["pfb_py_whitelist"]``) into
    ``whiteDB`` -- skipped when the ADR-06 manifest already built it. Same
    extraction rationale as ``_load_zone_db``."""
    if not os.path.isfile(pfb["pfb_py_whitelist"]):
        pfb_py_status_close("dnsbl", pfb["pfb_py_whitelist"], "parse")
        return
    try:
        with open(pfb["pfb_py_whitelist"]) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=",")
            for row in csv_reader:
                if row and len(row) == 2:
                    if row[1] == "1":
                        wildcard = True
                    else:
                        wildcard = False
                    # ADR-07: whiteDB value widens to
                    # {"wildcard", "important"}; the legacy CSV is the
                    # USER whitelist -> important=True (sovereignty).
                    whiteDB[row[0]] = {"wildcard": wildcard, "important": True}
                    pfb["whiteDB"] = True
                else:
                    sys.stderr.write("[pfBlockerNG]: Failed to parse: {}: {}".format(pfb["pfb_py_whitelist"], row))

        pfb_py_status_close("dnsbl", pfb["pfb_py_whitelist"], "parse")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_whitelist"], e))
        pfb_py_status_open(
            "dnsbl", pfb["pfb_py_whitelist"], "parse", "Failed to load: {}: {}".format(pfb["pfb_py_whitelist"], e)
        )


def _load_hsts_db() -> None:
    """Parse the HSTS preload file (``pfb["pfb_py_hsts"]``) into ``hstsDB`` --
    gated on ``pfb["python_hsts"]`` (not on the ADR-06 manifest: hstsDB is NOT
    part of the manifest build). Same extraction rationale as ``_load_zone_db``."""
    if not (pfb["python_hsts"] and os.path.isfile(pfb["pfb_py_hsts"])):
        pfb_py_status_close("dnsbl", pfb["pfb_py_hsts"], "parse")
        return
    try:
        with open(pfb["pfb_py_hsts"]) as hsts:
            for line in hsts:
                hstsDB[line.rstrip("\r\n")] = 0
            pfb["hstsDB"] = True
        pfb_py_status_close("dnsbl", pfb["pfb_py_hsts"], "parse")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_hsts"], e))
        pfb_py_status_open("dnsbl", pfb["pfb_py_hsts"], "parse", "Failed to load: {}: {}".format(pfb["pfb_py_hsts"], e))


def _load_zone_and_data_dbs(dnsbl_built: bool, feed_group_db: defaultdict[str, int], feed_group_index: int) -> int:
    """Run the legacy zone/data CSV loaders when the ADR-06 manifest build did NOT
    already supply them; otherwise close the parse-stage entries they would own --
    a manifest-built init means neither loader ran this pass (issue #1049)."""
    if not dnsbl_built:
        feed_group_index = _load_zone_db(feed_group_db, feed_group_index)
        feed_group_index = _load_data_db(feed_group_db, feed_group_index)
    else:
        pfb_py_status_close("dnsbl", pfb["pfb_py_zone"], "parse")
        pfb_py_status_close("dnsbl", pfb["pfb_py_data"], "parse")
    return feed_group_index


def _load_whitelist_and_hsts_dbs(dnsbl_built: bool) -> None:
    """Run whitelist/HSTS loading when the blacklist gate is on -- whitelist is
    skipped when the manifest already built it (ADR-06); otherwise (blacklist
    OFF) close both parse-stage entries, since neither loader runs this pass
    (issue #1049)."""
    if pfb["python_blacklist"]:
        if not dnsbl_built:
            _load_whitelist_db()
        else:
            pfb_py_status_close("dnsbl", pfb["pfb_py_whitelist"], "parse")
        _load_hsts_db()
    else:
        pfb_py_status_close("dnsbl", pfb["pfb_py_whitelist"], "parse")
        pfb_py_status_close("dnsbl", pfb["pfb_py_hsts"], "parse")


def _close_dnsbl_loader_entries_when_disabled() -> None:
    """python_enable OFF skips every DNSBL loader this pass -- close every
    parse-stage entry a prior init could have left open (issue #1049)."""
    for item in (
        pfb["pfb_py_sources"],
        pfb["pfb_py_zone"],
        pfb["pfb_py_data"],
        pfb["pfb_py_whitelist"],
        pfb["pfb_py_hsts"],
        pfb["pfb_py_ss"],
    ):
        pfb_py_status_close("dnsbl", item, "parse")


def _load_ini_config() -> ConfigParser | None:
    """Parse ``pfb["pfb_unbound.ini"]`` -- extracted out of ``init_standard`` (same
    extraction rationale as ``_load_zone_db``) so the load -- and its failure
    diagnostic -- are unit-testable. Returns ``None`` when the ini file is absent
    (caller's existing "ini file missing" fallback applies unchanged). On a parse
    failure, still returns the (empty) ConfigParser -- behaviour-preserving fall-
    through into the caller's ``has_section()`` checks, exactly as the original
    inline try/except (no early return on the read failure)."""
    if not os.path.isfile(pfb["pfb_unbound.ini"]):
        pfb_py_status_close("dnsbl", pfb["pfb_unbound.ini"], "parse")
        return None
    config = ConfigParser()
    try:
        config.read(pfb["pfb_unbound.ini"])
        pfb_py_status_close("dnsbl", pfb["pfb_unbound.ini"], "parse")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed to load ini configuration: {}".format(e))
        pfb_py_status_open("dnsbl", pfb["pfb_unbound.ini"], "parse", "Failed to load ini configuration: {}".format(e))
    return config


def init_standard(id: int, env: module_env) -> bool:
    global \
        pfb, \
        rcodeDB, \
        dataDB, \
        zoneDB, \
        regexDB, \
        allowRegexDB, \
        hstsDB, \
        whiteDB, \
        decisionDB, \
        _dnsbl_last_event, \
        noAAAADB, \
        gpListDB, \
        safeSearchDB, \
        feedGroupIndexDB, \
        maxmindReader, \
        pfb_task_queue, \
        pfb_worker_thread, \
        pfb_db_queue, \
        pfb_db_worker_thread, \
        pfb_reload_watcher_thread, \
        pfb_reload_stop, \
        pfb_control_watcher_thread, \
        pfb_control_stop

    if not register_inplace_cb_reply(inplace_cb_reply, env, id):
        log_info("[pfBlockerNG]: Failed register_inplace_cb_reply")
        return False

    if not register_inplace_cb_reply_cache(inplace_cb_reply_cache, env, id):
        log_info("[pfBlockerNG]: Failed register_inplace_cb_reply_cache")
        return False

    if not register_inplace_cb_reply_local(inplace_cb_reply_local, env, id):
        log_info("[pfBlockerNG]: Failed register_inplace_cb_reply_local")
        return False

    if not register_inplace_cb_reply_servfail(inplace_cb_reply_servfail, env, id):
        log_info("[pfBlockerNG]: Failed register_inplace_cb_reply_servfail")
        return False

    # Issue #267: register the upstream-facing query_response callback. It fires on the
    # raw server response BEFORE Unbound builds the client reply, preserving the upstream
    # RA/AA bits + EDNS options (including EDE). Registered defensively: a failure (or
    # an Unbound too old to expose this callback) must not break module init.
    try:
        if not register_inplace_cb_query_response(inplace_cb_query_response, env, id):
            log_info("[pfBlockerNG]: Failed register_inplace_cb_query_response")
    except Exception as _e:
        sys.stderr.write("[pfBlockerNG] register_inplace_cb_query_response: {}\n".format(_e))

    # Store previous error message to avoid repeating
    pfb["p_err"] = ""

    # Log stderr to file
    class log_stderr(object):
        def __init__(self, logger: logging.Logger) -> None:
            self.logger = logger
            self.linebuf = ""

        def write(self, msg: str) -> None:
            if msg != pfb["p_err"]:
                pfb_async(self.logger.log, logging.ERROR, msg.rstrip())
            pfb["p_err"] = msg

    # Create python error logfile
    logfile = "/var/log/pfblockerng/py_error.log"

    for i in range(2):
        try:
            logging.basicConfig(format="%(asctime)s|%(levelname)s| %(message)s", filename=logfile, filemode="a")
            break
        except IOError:
            # Remove logfile if ownership is not 'unbound:unbound'
            if os.path.isfile(logfile):
                os.remove(logfile)
    sys.stderr = log_stderr(logging.getLogger("pfb_stderr"))

    # Validate write access to log files
    for l_file in ("dnsbl", "dns_reply", "unified"):
        lfile = "/var/log/pfblockerng/" + l_file + ".log"

        try:
            if os.path.isfile(lfile) and not os.access(lfile, os.W_OK):
                new_file = "/var/log/pfblockerng/" + l_file + str(datetime.now().strftime("_%Y%m%d%H%M%S.log"))
                os.rename(lfile, new_file)
        except Exception as e:
            sys.stderr.write("[pfBlockerNG]: Failed to validate write permission: {}.log: {}".format(l_file, e))
            if os.path.isfile(lfile):
                new_file = "/var/log/pfblockerng/" + l_file + str(datetime.now().strftime("_%Y%m%d%H%M%S.log"))
                os.rename(lfile, new_file)
            pass

    if not pfb["mod_threading"]:
        sys.stderr.write("[pfBlockerNG]: Failed to load python module 'threading': {}".format(pfb["mod_threading_e"]))

    if not pfb["mod_ipaddress"]:
        sys.stderr.write("[pfBlockerNG]: Failed to load python module 'ipaddress': {}".format(pfb["mod_ipaddress_e"]))

    if not pfb["mod_maxminddb"]:
        sys.stderr.write("[pfBlockerNG]: Failed to load python module 'maxminddb': {}".format(pfb["mod_maxminddb_e"]))

    if not pfb["mod_sqlite3"]:
        sys.stderr.write("[pfBlockerNG]: Failed to load python module 'sqlite3': {}".format(pfb["mod_sqlite3_e"]))

    # Initialize default settings
    pfb["dnsbl_ipv4"] = ""
    pfb["dnsbl_ipv6"] = ""
    pfb["dataDB"] = False
    pfb["zoneDB"] = False
    pfb["hstsDB"] = False
    pfb["whiteDB"] = False
    pfb["regexDB"] = False
    # ADR-07: allow-regex container (@@/re/) and the $important/$badfilter fast-path
    # flag. Both are inert today (no ABP rule is parsed yet) -- the matcher keeps its
    # existing early-exit path while important_rules is False (behaviour-preserving).
    pfb["allowRegexDB"] = False
    pfb["important_rules"] = False
    # ADR-07 regex-safety defaults: cap OFF (nothing dropped at load unless the
    # user enables "Limit long/complex regex"); runtime warn/evict ALWAYS on at the
    # measured ceilings. The ini MAIN section overrides these.
    pfb["regex_cap"] = False
    pfb["regex_warn_ms"] = REGEX_WARN_MS_DEFAULT
    pfb["regex_evict_ms"] = REGEX_EVICT_MS_DEFAULT
    pfb["gpListDB"] = False
    pfb["noAAAADB"] = False
    pfb["python_idn"] = False
    # ADR-08: the IDN-feature mode, derived from python_idn (see idn_mode_from_legacy).
    # Default OFF; the ini load below recomputes it from the loaded python_idn.
    pfb["idn_mode"] = IdnMode.Off
    # ADR-08: the two Confusable-mode sub-toggles. block_malicious is DEFAULT-ON
    # (a cross-script confusable homograph blocks unless the operator disables it);
    # escalate_suspicious is OPT-IN (a suspicious/flagged anomaly only alerts unless the
    # operator escalates it to a block). Both only act in IDN_MODE_CONFUSABLE.
    pfb["python_idn_block_malicious"] = True
    pfb["python_idn_escalate_suspicious"] = False
    # TLD-Allow defaults. The PHP ini writer always emits these three MAIN keys, so
    # the config.has_option() loads below normally populate them -- but default them
    # here too so a hand-edited/corrupted ini that drops the keys can't KeyError on
    # the unconditional reads (TLD-Allow check + manifest cfg). ``python_tlds`` is a
    # list (the ini load below populates it via ``parse_python_tlds()``, issue #713);
    # evaluate_domain's TLD-Allow arm requires a non-empty ``cfg["python_tlds"]`` before
    # testing ``tld not in cfg["python_tlds"]``, so the empty-list default here is a
    # no-op rather than a block-everything trap.
    pfb["python_tld"] = False
    pfb["python_tlds"] = []
    pfb["python_tld_seg"] = 0
    # Max entries in the per-domain decision cache (LRU); 0 = unbounded. WebUI-configurable.
    pfb["decisiondb_max"] = 10000
    pfb["python_hsts"] = False
    pfb["python_reply"] = False
    pfb["python_cname"] = False
    pfb["safeSearchDB"] = False
    pfb["group_policy"] = False
    pfb["python_enable"] = False
    pfb["python_nolog"] = False
    pfb["python_control"] = False
    # PFBL-03: the legacy DNS-TXT control transport is OFF by default and gated behind
    # this separate opt-in. DNSBL control is CLI-driven (pfblockerng dnsbl-control ...) via
    # the local privileged command file; the DNS-TXT path is deprecated and less secure,
    # and will be removed in a future release (no fixed version). A startup warning is
    # logged when it is enabled (see the config ingest in init_standard).
    pfb["python_control_legacy"] = False
    pfb["python_maxmind"] = False
    pfb["python_blocking"] = False
    pfb["python_blacklist"] = False
    pfb["sqlite3_dnsbl_con"] = False
    pfb["sqlite3_resolver_con"] = False
    pfb["async_worker"] = False
    pfb["reload_watcher"] = False
    pfb["control_watcher"] = False
    pfb["forwarding"] = False

    # DNSBL Python files
    pfb["pfb_unbound.ini"] = "pfb_unbound.ini"
    pfb["pfb_py_whitelist"] = "pfb_py_whitelist.txt"
    pfb["pfb_py_zone"] = "pfb_py_zone.txt"
    pfb["pfb_py_data"] = "pfb_py_data.txt"
    pfb["pfb_py_hsts"] = "pfb_py_hsts.txt"
    pfb["pfb_py_ss"] = "pfb_py_ss.txt"
    # ADR-06: per-feed manifest (the new shell->Python boundary) and the
    # Python-emitted entry count. When the manifest is present, init builds the
    # DNSBL structures from the raw feeds via the pure build() layer; otherwise
    # it falls back to the legacy data/zone CSV load (shell/PHP still produce
    # those files for that fallback).
    pfb["pfb_py_sources"] = "pfb_py_sources.json"
    # ADR-10: the zero-downtime RELOAD SENTINEL. Path is chroot-relative (Unbound
    # is chrooted at /var/unbound, the module's CWD) -- so the in-chroot absolute path
    # PHP/shell must write is /var/unbound/pfb_py_reload. PHP atomically publishes the
    # new manifest + per-feed raw, then writes a monotonically-advancing GENERATION ID
    # (a base-10 integer, first line) into this file; the reload-watcher thread wakes on
    # the directory change, reads the generation, and on an ADVANCE runs
    # rebuild_and_swap() off the query threads. Correctness rides on the atomic publish
    # + the generation compare, NOT on notify latency (a missed event only delays).
    pfb["pfb_py_reload"] = "pfb_py_reload"
    # ADR-10: the APPLIED-generation marker. After the watcher successfully swaps in the
    # snapshot for generation N it writes N here (atomic temp+rename, first line). PHP's
    # data fast path waits (bounded) for this to reach the generation it just flipped
    # before returning, so the reload call returns only once the new lists are LIVE --
    # restoring the "lists live on return" invariant the restart had (the ADR-12 post
    # hook + the #51 alert page + the smoke suite then observe the new state, not a
    # pending swap). Host path /var/unbound/pfb_py_reload.applied; chroot-relative here.
    pfb["pfb_py_reload_applied"] = "pfb_py_reload.applied"
    # PFBL-03: the local privileged DNSBL-control command channel. PHP/shell (root only)
    # atomically publishes a small JSON record carrying a monotonically-advancing
    # sequence + the command; the control-watcher thread wakes on the directory change,
    # ignores any record whose seq <= the last applied (exactly-once + replay safety),
    # and routes a fresh one through pfb_apply_control_command(). Chroot-relative
    # (Unbound's CWD is /var/unbound) -> host path /var/unbound/pfb_py_control. The
    # writer keeps owner root, group unbound, mode 0640: root WRITES, unbound READS via
    # group -- authorization is "only root may write" (no group/other write).
    pfb["pfb_py_control"] = "pfb_py_control"
    # PFBL-03: the APPLIED-sequence marker (mirrors pfb_py_reload.applied). After the
    # control-watcher applies a record with seq N it writes N here (atomic temp+rename),
    # so the writer can confirm execution. Host path /var/unbound/pfb_py_control.applied.
    pfb["pfb_py_control_applied"] = "pfb_py_control.applied"
    pfb["pfb_py_count"] = "pfb_py_count"
    # ADR-07: the ADMITTED (cap-filtered) feed+user regex total -- the count the
    # DNSBL_Regex UI alias reads (inc:8329). It is the live size of regexDB +
    # allowRegexDB AFTER both the user REGEX-ini load and the feed-regex merge, so
    # patterns the static cap dropped are excluded (value changes by design, ADR §2).
    pfb["pfb_py_regex_count"] = "pfb_py_regex_count"
    # ADR-48 (issue #789): the per-entry reject tally artifact (BuildResult.rejects,
    # a JSON array of nonzero-total {feed, group, shape, wire_cap} rows) -- PHP reads
    # it after a DNSBL run and emits the canonical stage=entries line. Chroot-relative
    # bare name, exactly like pfb_py_count above (the manifest-boundary discipline).
    pfb["pfb_py_reject_stats"] = "pfb_py_reject_stats.json"
    # ADR-61: Python's OWN parse-stage status ledger (chroot-relative, alongside
    # pfb_py_reload) -- written/cleared by pfb_py_status_open()/close(); PHP only reads it.
    pfb["pfb_py_status"] = "pfb_py_status.json"
    pfb["pfb_py_dnsbl"] = "pfb_py_dnsbl.sqlite"
    pfb["pfb_py_cache"] = "pfb_py_cache.sqlite"
    pfb["pfb_py_resolver"] = "pfb_py_resolver.sqlite"
    pfb["maxminddb"] = "/usr/local/share/GeoIP/GeoLite2-Country.mmdb"

    # Remove DNSBL cache file (For Reports tab query)
    if os.path.isfile(pfb["pfb_py_cache"]):
        os.remove(pfb["pfb_py_cache"])

    # DNSBL validation on these RR_TYPES only
    pfb["rr_types"] = (
        RR_TYPE_A,
        RR_TYPE_AAAA,
        RR_TYPE_ANY,
        RR_TYPE_CNAME,
        RR_TYPE_DNAME,
        RR_TYPE_SIG,
        RR_TYPE_MX,
        RR_TYPE_NS,
        RR_TYPE_PTR,
        RR_TYPE_SRV,
        RR_TYPE_TXT,
        64,
        65,
    )

    # List of HSTS preload TLDs
    pfb["hsts_tlds"] = (
        "android",
        "app",
        "bank",
        "chrome",
        "dev",
        "foo",
        "gle",
        "gmail",
        "google",
        "hangout",
        "insurance",
        "meet",
        "new",
        "page",
        "play",
        "search",
        "youtube",
    )

    # Initialize dicts/lists
    dataDB = defaultdict(list)
    zoneDB = defaultdict(list)
    # Built with the preset cap; the configured value (read from the ini below) is
    # applied to .maxsize while the cache is still empty.
    decisionDB = _LruCache(pfb["decisiondb_max"])
    _dnsbl_last_event = None
    safeSearchDB = defaultdict(list)
    feedGroupIndexDB = defaultdict(list)

    regexDB = defaultdict(str)
    allowRegexDB = defaultdict(str)
    # ADR-07: clear the runtime warn rate-limit + perf-fallback strike state on a
    # (re)load so a fresh regex set starts with clean warn/evict bookkeeping.
    _regex_warned.clear()
    _regex_perf_strikes.clear()
    # Drop the literal-prefilter index caches so a fresh build occurs on the next
    # query (the new regex dicts are different objects; the identity check would
    # catch this anyway, but releasing the slot here avoids holding the old DB).
    global _block_regex_index, _allow_regex_index
    _block_regex_index = None
    _allow_regex_index = None
    whiteDB = defaultdict(str)
    hstsDB = defaultdict(str)
    gpListDB = defaultdict(str)
    noAAAADB = defaultdict(str)
    feedGroupDB: defaultdict[str, Any] = defaultdict(str)

    # Read pfb_unbound.ini settings
    config = _load_ini_config()
    if config is not None:
        if config.has_section("MAIN"):
            if config.has_option("MAIN", "python_enable"):
                pfb["python_enable"] = config.getboolean("MAIN", "python_enable")
            if config.has_option("MAIN", "python_reply"):
                pfb["python_reply"] = config.getboolean("MAIN", "python_reply")
            if config.has_option("MAIN", "python_blocking"):
                pfb["python_blocking"] = config.getboolean("MAIN", "python_blocking")
            if config.has_option("MAIN", "python_hsts"):
                pfb["python_hsts"] = config.getboolean("MAIN", "python_hsts")
            if config.has_option("MAIN", "python_idn"):
                pfb["python_idn"] = config.getboolean("MAIN", "python_idn")
            # ADR-08: the IDN mode. The PHP ini writer emits an explicit
            # idn_mode = off|all|confusable key; honour it when present, else fall
            # back to the legacy derivation ('on'->All-IDN, off->Off) for a config
            # written before the key existed.
            if config.has_option("MAIN", "idn_mode"):
                _raw_idn = config.get("MAIN", "idn_mode").strip().lower()
                if _raw_idn in (IDN_MODE_OFF, IDN_MODE_ALL, IDN_MODE_CONFUSABLE):
                    pfb["idn_mode"] = IdnMode(_raw_idn)
                else:
                    pfb["idn_mode"] = idn_mode_from_legacy(pfb["python_idn"])
            else:
                pfb["idn_mode"] = idn_mode_from_legacy(pfb["python_idn"])
            # ADR-08: the two Confusable sub-toggles. Read the MAIN keys when the
            # PHP ini writer emits them, else keep the defaults (block_malicious
            # ON, escalate OFF).
            if config.has_option("MAIN", "python_idn_block_malicious"):
                pfb["python_idn_block_malicious"] = config.getboolean("MAIN", "python_idn_block_malicious")
            if config.has_option("MAIN", "python_idn_escalate_suspicious"):
                pfb["python_idn_escalate_suspicious"] = config.getboolean("MAIN", "python_idn_escalate_suspicious")
            # issue #713: config.getint() raises ValueError on a non-integer ini value.
            # Unlike the regex_warn_ms/regex_evict_ms getfloat reads above (already
            # guarded), these two getint reads were UNGUARDED -- a malformed
            # python_tld_seg/decisiondb_max value threw out of module init and took the
            # whole Unbound Python module down. _parse_ini_int() mirrors the regex_*
            # try/except-ValueError guard; keep the current default on a parse failure,
            # and only touch decisionDB.maxsize when the parse actually succeeded.
            if config.has_option("MAIN", "python_tld_seg"):
                parsed_tld_seg = _parse_ini_int(config, "MAIN", "python_tld_seg")
                if parsed_tld_seg is not None:
                    pfb["python_tld_seg"] = parsed_tld_seg
            if config.has_option("MAIN", "decisiondb_max"):
                parsed_decisiondb_max = _parse_ini_int(config, "MAIN", "decisiondb_max")
                if parsed_decisiondb_max is not None:
                    pfb["decisiondb_max"] = parsed_decisiondb_max
                    decisionDB.maxsize = pfb["decisiondb_max"]
            if config.has_option("MAIN", "python_tld"):
                pfb["python_tld"] = config.getboolean("MAIN", "python_tld")
            if config.has_option("MAIN", "python_tlds"):
                pfb["python_tlds"] = parse_python_tlds(config.get("MAIN", "python_tlds"))
            if config.has_option("MAIN", "dnsbl_ipv4"):
                pfb["dnsbl_ipv4"] = config.get("MAIN", "dnsbl_ipv4")
            if config.has_option("MAIN", "dnsbl_ipv6"):
                pfb["dnsbl_ipv6"] = config.get("MAIN", "dnsbl_ipv6")
            if config.has_option("MAIN", "python_nolog"):
                pfb["python_nolog"] = config.getboolean("MAIN", "python_nolog")
            if config.has_option("MAIN", "python_cname"):
                pfb["python_cname"] = config.getboolean("MAIN", "python_cname")
            if config.has_option("MAIN", "python_control"):
                pfb["python_control"] = config.getboolean("MAIN", "python_control")
            if config.has_option("MAIN", "python_control_legacy"):
                pfb["python_control_legacy"] = config.getboolean("MAIN", "python_control_legacy")
            warn_if_legacy_control_enabled(pfb["python_control_legacy"])

            if config.has_option("MAIN", "forwarding"):
                pfb["forwarding"] = config.getboolean("MAIN", "forwarding")

            # ADR-07: regex-safety knobs. ``regex_cap`` is the opt-in "Limit
            # long/complex regex" static pre-filter (drops over-long/nested-quantifier
            # patterns at load -- feed AND user). ``regex_warn_ms`` / ``regex_evict_ms``
            # are the always-on runtime warn/evict ceilings (per-match thread CPU). All
            # default to OFF / the measured defaults when absent.
            if config.has_option("MAIN", "regex_cap"):
                pfb["regex_cap"] = config.getboolean("MAIN", "regex_cap")
            if config.has_option("MAIN", "regex_warn_ms"):
                try:
                    pfb["regex_warn_ms"] = config.getfloat("MAIN", "regex_warn_ms")
                except ValueError:
                    pass
            if config.has_option("MAIN", "regex_evict_ms"):
                try:
                    pfb["regex_evict_ms"] = config.getfloat("MAIN", "regex_evict_ms")
                except ValueError:
                    pass

            if pfb["dnsbl_ipv6"] == "":
                pfb["dnsbl_ipv6"] = "::"

            # List of DNS R_CODES
            rcodeDB = {
                0: "NoError",
                1: "FormErr",
                2: "ServFail",
                3: "NXDOMAIN",
                4: "NotImp",
                5: "Refused",
                6: "YXDomain",
                7: "YXRRSet",
                8: "NXRRSet",
                9: "NotAuth",
                10: "NotZone",
                11: "DSOTYPENI",
                16: "BADVERS",
                17: "BADKEY",
                18: "BADTIME",
                19: "BADMODE",
                20: "BADNAME",
                21: "BADALG",
                22: "BADTRUNC",
                23: "BADCOOKIE",
            }

        if pfb["python_enable"]:
            # Enable the Blacklist functions (IDN). ADR-08: ANY active IDN mode (All-IDN
            # via the legacy python_idn flag, OR Confusable) needs the blacklist machinery
            # (whitelist load + stats) -- the Confusable matcher feeds is_found like a feed.
            if pfb["python_idn"] or pfb["idn_mode"] is not IdnMode.Off:
                pfb["python_blacklist"] = True

            # Enable the Blacklist functions (TLD Allow). issue #713: python_tlds is a
            # LIST (parse_python_tlds()'s output) -- `!= ""` compares a list to a str,
            # which is ALWAYS True, so an empty/degenerate TLD-Allow value used to force
            # this on regardless of content. Plain truthiness is the correct guard: an
            # empty list (no configured TLDs) must NOT enable the blacklist gate.
            if pfb["python_tld"] and pfb["python_tlds"]:
                pfb["python_blacklist"] = True

            # Collect user-defined Regex patterns
            if config.has_section("REGEX"):
                regex_config = config.items("REGEX")
                if regex_config:
                    r_count = 1
                    for name, pattern in regex_config:
                        # ADR-07: a catastrophic SHAPE in the un-vetted USER regex
                        # list is dropped at load UNCONDITIONALLY (logged, not compiled)
                        # -- the always-on safety gate. The opt-in length ceiling (the
                        # "Limit long/complex regex" setting) is the separate tunable
                        # half: it drops over-length-but-safe user patterns only when on.
                        if _regex_is_catastrophic_shape(pattern):
                            sys.stderr.write(
                                "[pfBlockerNG]: dropping pathological user regex [ {} ] pattern [ {} ] "
                                "on line #{} (catastrophic shape)".format(name, pattern, r_count)
                            )
                            r_count += 1
                            continue
                        if pfb["regex_cap"] and len(pattern) > REGEX_STATIC_LEN_CAP:
                            sys.stderr.write(
                                "[pfBlockerNG]: dropping over-length user regex [ {} ] pattern [ {} ] "
                                "on line #{} (static length cap)".format(name, pattern, r_count)
                            )
                            r_count += 1
                            continue
                        try:
                            # ADR-07: a USER regex is SOVEREIGN -- band 5 (user block),
                            # so it beats ANY feed allow (@@ band 2 / @@$important band 4),
                            # matching the decision oracle's Provenance.USER block. Stored
                            # as the {"re","important","band"} payload the matcher scores
                            # via _block_entry_band; a bare compiled pattern would score the
                            # feed-block band 1 and be overridden by a feed @@. ($badfilter-
                            # immunity is inherent: user regex never enter the feed reconcile
                            # rule list.) A user regex never loses to a feed allow, only to
                            # the user whitelist (band 6) -- preserved by the fast path.
                            regexDB[name] = {
                                "re": re.compile(pattern),
                                "important": False,
                                "band": PRIO_USER_BLOCK,
                            }
                            pfb["regexDB"] = True
                            pfb["python_blacklist"] = True
                        except Exception as e:
                            sys.stderr.write(
                                "[pfBlockerNG]: Regex [ {} ] compile error pattern [  {}  ] on line #{}: {}".format(
                                    name, pattern, r_count, e
                                )
                            )
                            pass
                        r_count += 1

            # Collect user-defined no AAAA domains
            if config.has_section("noAAAA"):
                noaaaa_config = config.items("noAAAA")
                if noaaaa_config:
                    try:
                        for key, line in noaaaa_config:
                            data = line.rstrip("\r\n").split(",")
                            if data and len(data) == 2:
                                if data[1] == "1":
                                    wildcard = True
                                else:
                                    wildcard = False
                                noAAAADB[data[0]] = wildcard
                            else:
                                sys.stderr.write(
                                    "[pfBlockerNG]: Failed to parse: noAAAA: row:{} line:{}".format(key, line)
                                )

                        pfb["noAAAADB"] = True
                    except Exception as e:
                        sys.stderr.write("[pfBlockerNG]: Failed to load no AAAA domain list: {}".format(e))
                        pass

            # Collect user-defined Group Policy Global Bypass List
            if config.has_section("GP_Bypass_List"):
                gp_bypass_list = config.items("GP_Bypass_List")
                if gp_bypass_list:
                    try:
                        for key, line in gp_bypass_list:
                            gpListDB[line.rstrip("\r\n")] = 0

                        pfb["gpListDB"] = True
                    except Exception as e:
                        sys.stderr.write("[pfBlockerNG]: Failed to load GP Bypass List: {}".format(e))
                        pass

            # Collect SafeSearch Redirection list
            _load_safesearch_db()

            # ADR-06: prefer BUILDING the DNSBL structures from the raw feeds via
            # the pure build() layer (the new shell->Python boundary). When the
            # per-feed manifest is present, Python parses -> normalises -> classifies
            # (data/zone) -> builds dataDB/zoneDB/feedGroupIndexDB/whiteDB and emits
            # the entry count -- it is now the source of truth for the built
            # structures. The legacy data/zone/whitelist CSV load below is the
            # FALLBACK (shell/PHP still produce those files for this fallback),
            # used only when no manifest is present. Python ignores
            # stray IP lines and never touches the firewall/IP path (DNSBL-IP stays
            # in PHP). The build call site is the future zero-downtime swap point;
            # no background-thread/restart-free behaviour is added here.
            dnsbl_built = False
            build_result = dnsbl_build_from_manifest(pfb["pfb_py_sources"])
            if build_result is not None:
                # Atomic assign of the freshly-built structures into the module
                # globals (build() mutated nothing global; this is the swap).
                dataDB = build_result.data_db
                zoneDB = build_result.zone_db
                feedGroupIndexDB = build_result.feed_group_index_db
                whiteDB = build_result.white_db

                # ADR-07: MERGE the ABP feed block-regex into regexDB (preserving the
                # user-regex patterns compiled from the REGEX ini section above) and load
                # the @@/re/ allow-regex into allowRegexDB. Feed regex carry an explicit
                # band + $important; user regex are the {re, band: PRIO_USER_BLOCK (5)}
                # payload (sovereign over feed allows -- loaded above).
                regexDB.update(build_result.regex_db)
                allowRegexDB.update(build_result.allow_regex_db)

                pfb["zoneDB"] = bool(zoneDB)
                pfb["dataDB"] = bool(dataDB)
                pfb["whiteDB"] = bool(whiteDB)
                pfb["regexDB"] = bool(regexDB)
                pfb["allowRegexDB"] = bool(allowRegexDB)
                # The fast path stays byte-identical while important_rules is False; it
                # flips True only when an ABP $important / feed @@ / feed regex loaded.
                pfb["important_rules"] = bool(build_result.important_rules)
                if dataDB or zoneDB or regexDB or allowRegexDB:
                    pfb["python_blacklist"] = True

                # Emit pfb_py_count (the LOADED total) for the UI (inc:3149).
                dnsbl_emit_count(pfb["pfb_py_count"], build_result.counts)
                # ADR-48 (issue #789): emit the per-entry reject tally artifact
                # alongside the count -- PHP reads it after this run and emits
                # stage=entries for any feed with a nonzero bucket.
                dnsbl_emit_reject_stats(pfb["pfb_py_reject_stats"], build_result.rejects)
                dnsbl_built = True

            # While reading 'data|zone' CSV files: Replace 'Feed/Group' pairs with an index value (Memory performance)
            feedGroup_index = 0

            # Zone/Data dicts -- or close their entries when the manifest built them.
            feedGroup_index = _load_zone_and_data_dbs(dnsbl_built, feedGroupDB, feedGroup_index)

            # Clear temporary Feed/Group/Index list
            feedGroupDB.clear()

            # Whitelist/HSTS dicts -- or close their entries when the blacklist gate is off.
            _load_whitelist_and_hsts_dbs(dnsbl_built)

            # ADR-07: emit the ADMITTED regex total for the DNSBL_Regex UI alias
            # (inc:8329). regexDB now holds USER regex (REGEX-ini) + FEED block regex
            # (merged from build()); allowRegexDB holds FEED @@/re/ allow regex. Both
            # have already had over-cap patterns dropped at load when the static cap is
            # on, so this live size is the cap-filtered admitted count (value changes by
            # design, ADR §2). Emitted whenever the plugin is enabled so the alias is
            # accurate even with feed regex but no user regex.
            dnsbl_emit_count(pfb["pfb_py_regex_count"], len(regexDB) + len(allowRegexDB))

            # Validate SQLite3 database connections. A False validate (issue #900)
            # is the corrupt/broken-DB case -- _validate_db_with_recovery deletes
            # the file and retries once; still False just leaves the flag off (no
            # crash, no infinite retry) and is logged loudly.
            if pfb["mod_sqlite3"]:
                # Enable Resolver query statistics
                if _validate_db_with_recovery(DB_RESOLVER):
                    pfb["sqlite3_resolver_con"] = True
                else:
                    sys.stderr.write("[pfBlockerNG]: Failed to open pfb_py_resolver.sqlite database\n")

                # Enable DNSBL statistics -- forwarding-gated too, not just
                # blacklist-gated (issue #860; see _dnsbl_stats_wanted).
                if _dnsbl_stats_wanted():
                    if _validate_db_with_recovery(DB_DNSBL):
                        pfb["sqlite3_dnsbl_con"] = True
                    else:
                        sys.stderr.write("[pfBlockerNG]: Failed to open pfb_py_dnsbl.sqlite database\n")

            # Open MaxMind db reader for DNS Reply GeoIP logging
            if pfb["mod_maxminddb"] and pfb["python_reply"] and os.path.isfile(pfb["maxminddb"]):
                try:
                    maxmindReader = maxminddb.open_database(pfb["maxminddb"])
                    pfb["python_maxmind"] = True
                except Exception as e:
                    sys.stderr.write("[pfBlockerNG]: Failed to open MaxMind DB: {}".format(e))
                    pass
        else:
            # issue #1049: python_enable OFF skips every DNSBL loader above --
            # close their parse-stage entries instead of stranding them open.
            _close_dnsbl_loader_entries_when_disabled()
    else:
        log_info("[pfBlockerNG]: Failed to load ini configuration. Ini file missing.")

    # ADR-10: BUNDLE the loaded matcher strata into ONE immutable Snapshot and
    # install it through the shared fail-closed rebuild_and_swap(). Up to here init
    # populated the scratch globals (dataDB/zoneDB/whiteDB/regexDB/allowRegexDB/
    # feedGroupIndexDB/hstsDB) exactly as before -- from the manifest build() OR the
    # legacy CSV fallback, plus the user REGEX ini and the HSTS file; the
    # ``important_rules`` fast-path gate sits in pfb["important_rules"]. The builder
    # closure wraps those SAME dict objects into a fresh Snapshot (no copy, no shape
    # change), and rebuild_and_swap is the SINGLE place the ``_snapshot`` ref is bound
    # (one GIL-atomic store; the zero-downtime reload-watcher reuses this same point). It
    # runs on BOTH the python_enable and the else (empty defaultdicts) paths, so a
    # snapshot is always present for operate(). Decision-identical to the old per-global
    # read -- the same dict objects, just bundled (pinned by the retained ADR-06/07
    # oracles). Net init behaviour is UNCHANGED: this builder never returns None (so the
    # swap always succeeds at init), the decisionDB.clear() is a no-op on the cache init
    # just re-created empty, the Reports-cache reset matches init's earlier os.remove of
    # pfb_py_cache.sqlite (the file was just removed and the table is empty), and
    # ``emit_counts=False`` keeps init's existing path-specific inline count emits (the
    # manifest-path pfb_py_count + the always-on pfb_py_regex_count above) -- the swap
    # must NOT re-emit here or the CSV-fallback/else paths would gain count writes they
    # do not make today. The background reload-watcher caller uses the default emit_counts=True.
    def _init_build_snapshot() -> Snapshot:
        return Snapshot(
            data_db=dataDB,
            zone_db=zoneDB,
            white_db=whiteDB,
            regex_db=regexDB,
            allow_regex_db=allowRegexDB,
            feed_group_index_db=feedGroupIndexDB,
            hsts_db=hstsDB,
            important_rules=bool(pfb["important_rules"]),
            counts=len(dataDB) + len(zoneDB),
            regex_count=len(regexDB) + len(allowRegexDB),
        )

    rebuild_and_swap(_init_build_snapshot, emit_counts=False)

    # Start background DB-write worker (persistent sqlite connection, batched)
    if pfb["mod_threading"] and not pfb.get("db_worker"):
        try:
            pfb_db_queue = queue.Queue(maxsize=PFB_DB_QUEUE_MAXSIZE)
            pfb_db_worker_thread = threading.Thread(name="pfb_db_io", target=pfb_db_worker, daemon=True)
            pfb_db_worker_thread.start()
            pfb["db_worker"] = True
        except Exception as e:
            pfb["db_worker"] = False
            sys.stderr.write("[pfBlockerNG]: Failed to start DB I/O worker: {}".format(e))

    # Start background I/O worker (off-loads file/sqlite writes from the DNS path)
    if pfb["mod_threading"] and not pfb.get("async_worker"):
        try:
            pfb_task_queue = queue.Queue(maxsize=PFB_QUEUE_MAXSIZE)
            pfb_worker_thread = threading.Thread(name="pfb_async_io", target=pfb_async_worker, daemon=True)
            pfb_worker_thread.start()
            pfb["async_worker"] = True
        except Exception as e:
            pfb["async_worker"] = False
            sys.stderr.write("[pfBlockerNG]: Failed to start async I/O worker: {}".format(e))

    # ADR-10: start the zero-downtime reload-watcher (daemon). It waits on the reload
    # sentinel and runs a single-flight, RAM-gated rebuild_and_swap() off the query
    # threads on a generation advance -- no Unbound restart for a DNSBL-data update.
    if pfb["mod_threading"] and not pfb.get("reload_watcher"):
        try:
            pfb_reload_stop = threading.Event()
            pfb_reload_watcher_thread = threading.Thread(
                name="pfb_reload_watcher", target=pfb_reload_watcher, daemon=True
            )
            pfb_reload_watcher_thread.start()
            pfb["reload_watcher"] = True
        except Exception as e:
            pfb["reload_watcher"] = False
            sys.stderr.write("[pfBlockerNG]: Failed to start reload watcher: {}".format(e))

    # PFBL-03: start the DNSBL-control command-channel reader (daemon) when the feature is
    # enabled. It waits on the control channel and routes a fresh command through the
    # shared handler off the query threads -- the local privileged transport that replaces
    # the DNS-TXT path.
    if pfb["mod_threading"] and pfb["python_control"] and not pfb.get("control_watcher"):
        try:
            pfb_control_stop = threading.Event()
            pfb_control_watcher_thread = threading.Thread(
                name="pfb_control_watcher", target=pfb_control_watcher, daemon=True
            )
            pfb_control_watcher_thread.start()
            pfb["control_watcher"] = True
        except Exception as e:
            pfb["control_watcher"] = False
            sys.stderr.write("[pfBlockerNG]: Failed to start control watcher: {}".format(e))

    pfb_setup_logging()

    log_info("[pfBlockerNG]: init_standard script loaded")
    return True


# ADR-08: IDN-feature mode selector (ADR-28 shared vocabulary 'on'/'confusable'/'off'
# across config.xml, py_unbound.ini, and this enum). IDN_MODE_OFF: the IDN feed never
# fires. IDN_MODE_ALL: block every xn-- query as feed="IDN" (prefix match only, no
# punycode decode); token "on" is the legacy value. IDN_MODE_CONFUSABLE: the TR39
# mixed-script analyzer tier. A config predating idn_mode (only python_idn=on|off)
# maps via idn_mode_from_legacy(): on->All, off/absent->Off.
IDN_MODE_OFF = "off"
IDN_MODE_ALL = "on"
IDN_MODE_CONFUSABLE = "confusable"


# ---------------------------------------------------------------------------
# ADR-28 §2.2 — IdnMode enum (the only Python runtime enum; pfb_unbound reads
# all toggles as bools via config.getboolean, so toggle/lenient enums have no
# Python consumer and live in PHP only).
#
# Rule: py_unbound.ini stored values NEVER change.  IdnMode is an INTERNAL
# runtime representation only; conversion at the READ boundary (pfb_global).
# The backing value equals the canonical ini string — byte-identical on write.
# ---------------------------------------------------------------------------


class IdnMode(Enum):
    """IDN-feature mode selector (ADR-08 §2.2, backed by canonical stored string).

    The backing values are the single shared vocabulary used by config.xml, py_unbound.ini,
    and the PHP PfbIdnMode enum: All reuses the legacy 'on' token (block-all-IDN), so a
    pre-4.0.0 install round-trips with no migration.
    """

    All = "on"
    Confusable = "confusable"
    Off = "off"

    @classmethod
    def default(cls) -> IdnMode:
        return cls.Off


def idn_mode_from_legacy(python_idn: bool) -> IdnMode:
    """Map the legacy on/off ``python_idn`` flag to an IDN mode.

    True ('on') -> IdnMode.All (today's block-all-IDN behaviour); False -> IdnMode.Off.
    The Confusable value cannot arise from the legacy flag -- it reaches Python only
    once the PHP UI emits it.
    """
    return IdnMode.All if python_idn else IdnMode.Off


def is_idn_domain(q_name: str) -> bool:
    return q_name.startswith("xn--") or ".xn--" in q_name


def idn_mode_decision(q_name: str, idn_mode: IdnMode) -> bool:
    """Pure IDN feed decision: should this query be blocked by the All-IDN feed?

    Returns True only in IdnMode.All on an xn-- query. IdnMode.Off and
    IdnMode.Confusable return False here -- the Confusable tier is decided by
    ``idn_confusable_action`` instead, not this gate. No punycode decode, no
    script work. Pinned by tests/test_adr08_mode_baseline.py.
    """
    return idn_mode is IdnMode.All and is_idn_domain(q_name)


# --------------------------------------------------------------------------- #
# ADR-08: TR39 cross-script IDN homoglyph analyzer (stdlib only). Each xn-- label
# is punycode-decoded, each code point's script read from unicodedata.name(), and
# a severity assigned PER LABEL (never unioned across the dot). Decode-safe: a
# malformed label is FLAGGED, never raised into operate(). Graded against the
# reference oracle + corpus in tests/test_adr08_*.
# --------------------------------------------------------------------------- #

SEV_LEGIT = "legit"
SEV_SUSPICIOUS = "suspicious"
SEV_MALICIOUS = "malicious"
SEV_FLAGGED = "flagged"

LEVEL_ASCII = "ascii_only"
LEVEL_SINGLE = "single_script"
LEVEL_HIGHLY_RESTRICTIVE = "highly_restrictive"
LEVEL_NON_RESTRICTIVE = "non_restrictive"

# >=2 of the mutually-confusable trio in ONE label -> malicious (incl. Cyrillic+Greek).
# UTS#39 Highly Restrictive allow-set: single script, OR Latin + a CJK companion
# {Han, Hiragana, Katakana, Hangul, Bopomofo}.
CONFUSABLE_SET = frozenset({"Latin", "Cyrillic", "Greek"})
_HIGHLY_RESTRICTIVE_SET = frozenset({"Latin", "Han", "Hiragana", "Katakana", "Hangul", "Bopomofo"})
# ADR-08 Section 2: digits + hyphen are the EURid-exempt, letter-less "Common-only mix"
# -- legitimate and never touched in Confusable mode, even though they resolve to NO
# letter-script (same as an empty/control-char/emoji label, which stays flagged; #720).
_DIGIT_HYPHEN_CHARS = frozenset("0123456789-")
_SEV_ORDER = {SEV_LEGIT: 0, SEV_FLAGGED: 1, SEV_SUSPICIOUS: 2, SEV_MALICIOUS: 3}
_DECODE_ERRORS = (UnicodeDecodeError, UnicodeError, ValueError)
# unicodedata.name() leading token -> script; CJK ideographs name themselves "CJK".
_NAME_PREFIX_TO_SCRIPT = {"CJK": "Han"}
# Common ideographic Lo marks name() would misattribute (Lm marks drop out by category).
_COMMON_LO_MARKS = frozenset({0x3006, 0x303C})


def decode_idn_label(label: str) -> str:
    """Raw stdlib 'punycode' decode of one label (NOT 'idna'); MAY raise on malformed input."""
    if not label.startswith("xn--"):
        return label
    return label[4:].encode("ascii").decode("punycode")


def script_of(codepoint: int) -> tuple[str, ...]:
    """Script of a code point from its unicodedata.name() leading token; () for a transparent
    point (non-letter, Lm modifier mark, Common Lo mark, or unnamed -- contributes no script)."""
    ch = chr(codepoint)
    cat = unicodedata.category(ch)
    if cat[0] != "L" or cat == "Lm" or codepoint in _COMMON_LO_MARKS:
        return ()
    name = unicodedata.name(ch, "")
    if not name:
        return ()
    token = name.split(" ", 1)[0]
    return (_NAME_PREFIX_TO_SCRIPT.get(token, token.capitalize()),)


def resolved_script_set(text: str) -> set[str]:
    """Distinct scripts in ONE decoded label (Common/Inherited transparent; never unions)."""
    out: set[str] = set()
    for ch in text:
        out.update(script_of(ord(ch)))
    return out


def restriction_level(scripts: set[str], *, ascii_only: bool = False) -> str:
    """UTS#39 restriction level for a resolved script set (the documented intermediate)."""
    if ascii_only:
        return LEVEL_ASCII
    if len(scripts) == 1:
        return LEVEL_SINGLE
    if scripts and len(scripts) >= 2 and scripts <= _HIGHLY_RESTRICTIVE_SET:
        return LEVEL_HIGHLY_RESTRICTIVE
    return LEVEL_NON_RESTRICTIVE


def severity_of(text: str) -> str:
    """legit | suspicious | malicious | flagged for ONE decoded label (never unions across the dot)."""
    scripts = resolved_script_set(text)
    if len(scripts & CONFUSABLE_SET) >= 2:
        return SEV_MALICIOUS
    if not scripts:
        # A digits/hyphen-only label is the ADR-08 Section 2 Common-only carve-out --
        # legit, not flagged. Every OTHER scriptless label (empty, control-char, emoji,
        # combining-marks-alone) has no such contract exemption and stays flagged (the
        # decision-table's borderline call: "no letter-script -> flagged, NOT legit").
        return SEV_LEGIT if text and set(text) <= _DIGIT_HYPHEN_CHARS else SEV_FLAGGED
    if restriction_level(scripts) in (LEVEL_SINGLE, LEVEL_HIGHLY_RESTRICTIVE):
        return SEV_LEGIT
    return SEV_SUSPICIOUS


@dataclass(frozen=True)
class LabelVerdict:
    """Decode-safe analysis of ONE label; ``offending`` = the scripts to surface in the log."""

    a_label: str
    decoded: str | None
    scripts: frozenset[str]
    severity: str
    offending: frozenset[str]
    decode_error: str | None


@dataclass(frozen=True)
class NameVerdict:
    """Per-label analysis of a whole name; the most severe label wins."""

    a_name: str
    labels: tuple[LabelVerdict, ...]
    severity: str
    offending: frozenset[str]


def _offending_scripts(scripts: frozenset[str], severity: str) -> frozenset[str]:
    """The script(s) explaining a non-legit verdict (for the dual-form log line)."""
    if severity == SEV_MALICIOUS:
        return frozenset(scripts & CONFUSABLE_SET)
    if severity == SEV_SUSPICIOUS:
        return scripts
    return frozenset()


def classify_label(a_label: str) -> LabelVerdict:
    """Decode + classify ONE label, NEVER raising (a punycode decode error -> FLAGGED)."""
    try:
        decoded = decode_idn_label(a_label)
    except _DECODE_ERRORS as exc:
        return LabelVerdict(a_label, None, frozenset(), SEV_FLAGGED, frozenset(), type(exc).__name__)
    scripts = frozenset(resolved_script_set(decoded))
    sev = severity_of(decoded)
    return LabelVerdict(a_label, decoded, scripts, sev, _offending_scripts(scripts, sev), None)


def classify_idn(q_name: str) -> NameVerdict:
    """Classify a whole name PER LABEL; most-severe label wins, never unions across the dot."""
    verdicts = tuple(classify_label(lbl) for lbl in q_name.split("."))
    worst = verdicts[0]
    for v in verdicts[1:]:
        if _SEV_ORDER[v.severity] > _SEV_ORDER[worst.severity]:
            worst = v
    return NameVerdict(q_name, verdicts, worst.severity, worst.offending)


# ADR-08: the Confusable tier. Distinct feed/group labels so a homoglyph block
# is attributed apart from the blunt All-IDN feed ("IDN"/"DNSBL_IDN") and the alerts
# page / Reports can break it out. Malicious -> the Homoglyph feed; the suspicious/
# flagged (non-malicious anomaly) tier -> the Suspect feed.
IDN_FEED_MALICIOUS = "Homoglyph"
IDN_GROUP_MALICIOUS = "DNSBL_Homoglyph"
IDN_FEED_SUSPECT = "Homoglyph_Suspect"
IDN_GROUP_SUSPECT = "DNSBL_Homoglyph_Suspect"

# The three matcher actions the analyzer's severity maps to (mirrors the reference
# oracle's ACT_NONE/ACT_ALERT/ACT_BLOCK under the two sub-toggles).
IDN_ACT_NONE = "none"
IDN_ACT_ALERT = "alert"
IDN_ACT_BLOCK = "block"

# Issue #267: RFC 8914 Extended DNS Error info-codes that signal an upstream block.
EDE_BLOCKED = 15  # INFO-CODE 15: Blocked
EDE_FILTERED = 17  # INFO-CODE 17: Filtered
# EDNS option code 15 carries RFC 8914 EDE data (distinct from the INFO-codes above).
EDNS_OPT_CODE_EDE = 15


@dataclass(frozen=True)
class UpstreamBlock:
    """Result of classifying a forwarded DNS reply as an upstream/external block.

    Mirrors Pi-hole's external-block detection (NXRA / EDE15 / EDE17 signals).
    """

    signal: str  # "NXRA" | "EDE15" | "EDE17"
    label: str  # human detail, e.g. "NXRA", "EDE15 (Blocked)", "EDE17 (Filtered)"
    provider: str  # EDE EXTRA-TEXT if the response carried one, else "" (generic)


def classify_upstream_block(
    rcode: int,
    ra_available: bool,
    aa_authoritative: bool = False,
    ede: list[tuple[int, str]] | None = None,
) -> UpstreamBlock | None:
    """Decide whether a forwarded DNS reply is an upstream/external block (Pi-hole parity).

    Args:
        rcode: the reply RCODE (compare against RCODE_NXDOMAIN).
        ra_available: True if the reply's RA (Recursion Available) header bit is SET.
        aa_authoritative: True if the reply's AA (Authoritative Answer) bit is SET.
            An authoritative NXDOMAIN (AA=1) is a real NXDOMAIN from the zone owner,
            not a filtering block — excluded from NXRA detection.
        ede: parsed RFC 8914 Extended DNS Error options as (info_code, extra_text) pairs,
             or None/empty if the reply carried none.

    Returns an UpstreamBlock if the reply matches a known upstream-block signal, else None.
    Precedence: a recognised EDE (15 Blocked / 17 Filtered) is the stronger, standardised
    signal and wins (and carries its EXTRA-TEXT as ``provider``); otherwise NXRA
    (rcode == NXDOMAIN AND NOT ra_available AND NOT aa_authoritative). A natural recursive
    NXDOMAIN (RA set), an authoritative NXDOMAIN (AA set), and a non-NXDOMAIN with no
    recognised EDE are NOT blocks (return None).
    """
    if ede:
        ede15_extra: str | None = None
        ede17_extra: str | None = None
        for info_code, extra_text in ede:
            if info_code == EDE_BLOCKED and ede15_extra is None:
                ede15_extra = extra_text
            elif info_code == EDE_FILTERED and ede17_extra is None:
                ede17_extra = extra_text
        if ede15_extra is not None:
            return UpstreamBlock("EDE15", "EDE15 (Blocked)", ede15_extra.strip())
        if ede17_extra is not None:
            return UpstreamBlock("EDE17", "EDE17 (Filtered)", ede17_extra.strip())
    if rcode == RCODE_NXDOMAIN and not ra_available and not aa_authoritative:
        return UpstreamBlock("NXRA", "NXRA", "")
    return None


def _parse_ede_options(opts: Iterable[tuple[int, bytes]]) -> list[tuple[int, str]]:
    """Parse raw EDNS option pairs into RFC 8914 EDE (info_code, extra_text) tuples.

    Pure / unit-testable -- no Unbound API calls.  For each ``(opt_code, opt_data)``
    pair: if ``opt_code == EDNS_OPT_CODE_EDE`` and the data is at least 2 bytes, the
    first 2 bytes are the big-endian INFO-CODE and the remainder (if any) is the
    UTF-8 EXTRA-TEXT.  Pairs whose opt_code is not 15 or whose data is shorter than 2
    bytes are silently skipped (not EDE / malformed).
    """
    result: list[tuple[int, str]] = []
    for opt_code, opt_data in opts:
        if opt_code != EDNS_OPT_CODE_EDE:
            continue
        if len(opt_data) < 2:
            continue
        info_code = int.from_bytes(opt_data[:2], "big")
        extra_text = opt_data[2:].decode("utf-8", "replace")
        result.append((info_code, extra_text))
    return result


def _idn_dual_form(verdict: NameVerdict) -> str:
    """Actionable dual-form description of the offending label, for the log line.

    ``xn--pple-43d [аpple] Cyrillic`` -- the A-label, the decoded Unicode in brackets,
    and the offending script(s) -- mirroring the alerts page's existing ``idn_to_utf8``
    "domain [decoded]" display so a homoglyph block/alert is human-readable. The worst
    label is the first whose severity equals the name verdict's (name severity = most
    severe label); fall back to the whole name if none matches (defensive).
    """
    worst = next((lbl for lbl in verdict.labels if lbl.severity == verdict.severity), None)
    if worst is None:
        return verdict.a_name
    a_label = worst.a_label
    scripts = " ".join(sorted(verdict.offending)) if verdict.offending else ""
    if worst.decoded is None:
        # FLAGGED via a caught decode error -- no decoded form to show; name the failure.
        detail = "decode-error:{}".format(worst.decode_error or "unknown")
        return "{} [{}]".format(a_label, detail)
    decoded = worst.decoded
    if scripts:
        return "{} [{}] {}".format(a_label, decoded, scripts)
    return "{} [{}]".format(a_label, decoded)


def idn_confusable_action(
    q_name: str,
    *,
    block_malicious: bool,
    escalate_suspicious: bool,
) -> tuple[str, NameVerdict | None]:
    """Confusable-mode action for one query name + the verdict that drove it.

    Gated by ``is_idn_domain`` (a non-xn-- query pays NOTHING -- no decode, no script
    work, returns ``(IDN_ACT_NONE, None)``). On an xn-- query it classifies the name
    PER-LABEL via the pure analyzer (``classify_idn`` never raises -- a malformed label
    is FLAGGED, the resolver never crashes) and maps severity -> action exactly like the
    reference oracle's ``action(...)`` under the two sub-toggles:

      * MALICIOUS  -> block  when ``block_malicious`` (default-ON); alert when disabled.
      * SUSPICIOUS / FLAGGED -> alert by default; block when ``escalate_suspicious`` (opt-in).
      * LEGIT      -> none (resolve untouched -- single-script, Latin+CJK, Common-mix).
    """
    if not is_idn_domain(q_name):
        return IDN_ACT_NONE, None
    verdict = classify_idn(q_name)
    sev = verdict.severity
    if sev == SEV_LEGIT:
        return IDN_ACT_NONE, verdict
    if sev == SEV_MALICIOUS:
        return (IDN_ACT_BLOCK if block_malicious else IDN_ACT_ALERT), verdict
    # SUSPICIOUS or FLAGGED: alert by default, escalatable to block via the opt-in.
    return (IDN_ACT_BLOCK if escalate_suspicious else IDN_ACT_ALERT), verdict


def get_q_name_qstate(qstate: module_qstate | None) -> str:
    q_name = ""
    try:
        if qstate and qstate.qinfo and qstate.qinfo.qname_str and qstate.qinfo.qname_str.strip():
            q_name = qstate.qinfo.qname_str.rstrip(".")
        elif qstate and qstate.return_msg and qstate.return_msg.qinfo and qstate.return_msg.qinfo.qname_str.strip():
            q_name = qstate.return_msg.qinfo.qname_str.rstrip(".")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed get_q_name_qstate: {}".format(e))
        pass
    return is_unknown(q_name)


def get_q_name_qinfo(qinfo: query_info | None) -> str:
    q_name = ""
    try:
        if qinfo and qinfo.qname_str and qinfo.qname_str.strip():
            q_name = qinfo.qname_str.rstrip(".")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed get_q_name_qinfo: {}".format(e))
        pass
    return is_unknown(q_name)


def get_q_ip(qstate: module_qstate) -> str:
    q_ip = ""

    try:
        if qstate and qstate.mesh_info.reply_list:
            reply_list = qstate.mesh_info.reply_list
            while reply_list:
                if reply_list.query_reply:
                    q_ip = reply_list.query_reply.addr
                    break
                reply_list = reply_list.next
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed get_q_ip: {}".format(e))
        pass
    return is_unknown(q_ip)


def get_q_ip_comm(kwargs: dict[str, Any] | None) -> str:
    q_ip = ""

    try:
        if kwargs and kwargs is not None and ("pfb_addr" in kwargs):
            q_ip = kwargs["pfb_addr"]
        elif kwargs and kwargs is not None and kwargs["repinfo"] and kwargs["repinfo"].addr:
            q_ip = kwargs["repinfo"].addr
    except Exception as e:
        for a in e.args:
            sys.stderr.write("[pfBlockerNG]: Failed get_q_ip_comm: {}".format(a))
        pass
    return is_unknown(q_ip)


def get_q_type(qstate: module_qstate | None, qinfo: query_info | None) -> str:
    q_type = ""
    if qstate and qstate.qinfo.qtype_str:
        q_type = qstate.qinfo.qtype_str
    elif qinfo and qinfo.qtype_str:
        q_type = qinfo.qtype_str
    return is_unknown(q_type)


def get_o_type(qstate: module_qstate | None, rep: reply_info | None) -> str:
    o_type = ""
    if qstate:
        if (
            qstate.return_msg
            and qstate.return_msg.rep
            and qstate.return_msg.rep.rrsets[0]
            and qstate.return_msg.rep.rrsets[0].rk
        ):
            o_type = qstate.return_msg.rep.rrsets[0].rk.type_str
        elif qstate.qinfo.qtype_str:
            o_type = qstate.qinfo.qtype_str
        elif rep is not None and rep.rrsets[0] is not None and rep.rrsets[0].rk is not None:
            o_type = rep.rrsets[0].rk.type_str
    return is_unknown(o_type)


def get_rep_ttl(rep: reply_info | None) -> str:
    # Presence, not truthiness: TTL 0 is a valid value (RFC 2181 s8 -- deliverable,
    # non-cacheable), only a missing reply/TTL is unknown. Bypasses is_unknown(),
    # whose falsy check would swallow 0 (#723).
    if rep and rep.ttl is not None:
        return str(rep.ttl)
    return "Unk"


def get_tld(qstate: module_qstate) -> str:
    tld = ""
    try:
        if qstate and qstate.qinfo and len(qstate.qinfo.qname_list) > 1:
            # RFC 4343: DNS name comparison is case-insensitive, but production Unbound's
            # qname_list preserves the client's wire case (e.g. dns0x20). python_tlds /
            # hsts_tlds are stored lowercase-only, so lowercase here at the source rather
            # than at every membership-test call site (#720).
            tld = qstate.qinfo.qname_list[-2].lower()
    except Exception as e:
        # A qname carrying invalid UTF-8 bytes makes Unbound's qname_list access raise
        # while decoding the labels; swallow it and fall back to an empty TLD rather than
        # crashing the Python module on that query (mirrors get_q_name_qstate).
        sys.stderr.write("[pfBlockerNG]: Failed get_tld: {}\n".format(e))
    return tld


def get_tld_from_name(q_name: str) -> str:
    # The TLD get_tld() reads from qstate.qinfo.qname_list, but derived from a name
    # STRING -- for a CNAME target evaluated mid-chain, whose TLD differs from the
    # original query's. evaluate_domain() uses it for the TLD-Allow and HSTS checks,
    # so each evaluated name must be checked against its own TLD.
    #
    # This must match get_tld(): production Unbound's qname_list carries the trailing
    # root label "" (pythonmod GetNameAsLabelList counts the zero-length root), so
    # qname_list[-2] is the TLD (e.g. "com" for "sub.example.com."). From a string the
    # equivalent is the LAST label of the dot-split name -- parts[-1], NOT parts[-2]
    # (which is the second-level label / SLD). The prior parts[-2] yielded the SLD, so a
    # CNAME target's TLD-Allow check ran against the wrong label: a target whose real TLD
    # is allowed was falsely blocked, and `tld in hsts_tlds` never fired for a CNAME
    # target (VIP instead of NULL). (#706)
    #
    # Lowercased for the same reason as get_tld() (RFC 4343 case-insensitive compare
    # against the lowercase-only python_tlds/hsts_tlds; #720). The current caller
    # already passes a lowercased q_name, so this is a no-op there -- it keeps the
    # pair's contract (both always return a lowercase TLD) consistent for any future
    # caller that doesn't pre-lowercase.
    parts = q_name.rstrip(".").split(".")
    return parts[-1].lower() if len(parts) > 1 else ""


def convert_ipv4(x: Any) -> str:
    ipv4 = ""
    if x:
        ipv4 = "{}.{}.{}.{}".format(x[2], x[3], x[4], x[5])
    return is_unknown(ipv4)


def convert_ipv6(x: Any) -> str:
    ipv6 = ""
    if x:
        ipv6 = (
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}"
        ).format(x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15], x[16], x[17])
    return is_unknown(ipv6)


def convert_other(x: Any) -> str:
    """Decode an rr_data payload shaped like an uncompressed RFC 1035 SS3.3.1 wire-format
    domain name: a 2-byte RDATA-length prefix (x[0:2], the same convention as
    convert_ipv4()/convert_ipv6()) followed by one or more labels -- each a 1-63 length
    octet plus that many raw content bytes -- terminated by a zero-length root label.

    Consumers: the DNSBL CNAME walk and the SafeSearch CNAME check (_ss_answer_has_cname_to)
    feed CNAME rdata through this to compare the decoded target against feed/target names;
    the reply logger renders other rrtypes (TXT, MX, ...) through it best-effort for logging.

    A malformed length octet -- >63 (e.g. a DNS compression-pointer marker, invalid in an
    uncompressed dname) or one that would overrun the remaining buffer -- fails safe to the
    "Unknown" sentinel rather than decoding junk; callers that guard on `!= "Unknown"` (the
    CNAME walk) skip it instead of DNSBL-evaluating garbage. A bare root label with no
    preceding labels also decodes to "Unknown" (the empty name).

    Lenient case: a length-prefixed character-string (TXT rdata) carries no root
    terminator, since that terminator is a dname-only construct -- when the buffer is
    exhausted mid-walk with no explicit zero octet, the labels parsed so far are still
    returned joined by ".", not "Unknown".

    Accepted logging-only change (#717): MX/SRV-style rdata carries a leading fixed field
    (e.g. MX's 2-byte preference) before its dname, which this decoder has no way to know
    to skip -- that field's leading zero byte reads as a zero-length root label, so the
    decode is the empty name ("Unknown") rather than the old scrape's accidental
    "foo.com". Only the cosmetic reply logger ever feeds MX/SRV rdata through here; the
    DNSBL CNAME walk only ever passes CNAME rdata, which has no such leading field.
    """
    final = ""
    if x:
        labels = []
        buf = x[2:]
        pos = 0
        malformed = False
        rooted = False
        while pos < len(buf):
            length = buf[pos]
            pos += 1
            if length == 0:
                rooted = True
                break
            if length > 63 or pos + length > len(buf):
                malformed = True
                break
            labels.append(buf[pos : pos + length].decode("latin-1"))
            pos += length
        if not malformed and (labels or rooted):
            final = ".".join(labels)
    return is_unknown(final)


def is_unknown(x: Any) -> Any:
    try:
        if not x or x is None:
            return "Unknown"
    except Exception as e:
        for a in e.args:
            sys.stderr.write("[pfBlockerNG]: Failed is_unknown: {}".format(a))
        pass
    return x


# All connection access is serialized by _db_lock; connections are opened with
# check_same_thread=False so the DB worker and the synchronous fallback (init,
# tests) can share them safely under the lock.
_db_lock: Any = threading.Lock() if pfb.get("mod_threading") else nullcontext()
# Issue #900: serializes corrupt-DB recovery -- _validate_db_with_recovery's whole
# validate -> remove -> revalidate sequence must be atomic across its caller threads
# (init, the ADR-10 swap watcher, the control-channel enable / timed re-enable), or a
# losing racer can delete the winner's freshly rebuilt LIVE DB file. Lock ordering:
# _db_recovery_lock -> _db_lock only (_db_lock is a plain lock acquired solely inside
# _db_run, which pfb_db_validate calls under this lock); no path acquires
# _db_recovery_lock while holding _db_lock, so the ordering never inverts -- no deadlock.
_db_recovery_lock: Any = threading.Lock() if pfb.get("mod_threading") else nullcontext()
_db_conns: dict[int, Any] = {}

PFB_DB_QUEUE_MAXSIZE = 5000
PFB_DB_FLUSH_INTERVAL = 1.0
PFB_DB_MAX_BATCH = 2000

DB_RESOLVER = 1
DB_DNSBL = 2
DB_CACHE = 3


def _db_file(db: int) -> str:
    if db == DB_RESOLVER:
        return pfb["pfb_py_resolver"]
    if db == DB_DNSBL:
        return pfb["pfb_py_dnsbl"]
    if db == DB_CACHE:
        return pfb["pfb_py_cache"]
    return ""


def _db_seed_upstream_row(cursor: Any) -> None:
    # Issue #285 / #858: seed the synthetic 'Upstream' group row so the per-block
    # counter UPDATE in _db_flush_dnsbl always has a row to increment -- the upstream
    # block is not a feed, so dnsbl_save_stats() never creates it. The single INSERT
    # ... WHERE NOT EXISTS is atomic (vs a check-then-insert): a no-op once the row is
    # present, so it is idempotent and preserves any accumulated counter. Shared by
    # _db_create (seed at connect) and _db_flush_dnsbl (issue #858: self-heal at
    # write -- a mid-connection TABLE REBUILD, e.g. dnsbl_save_stats()'s empty-stats
    # DROP TABLE or pfb_open_sqlite's corrupt-DB recovery, leaves the row absent and
    # the bare counter UPDATE silently no-ops on it until the next Unbound restart
    # re-runs _db_create. A cleardnsbl/report-clear reset is NOT this case -- it only
    # runs UPDATE dnsbl SET counter = 0 and keeps every row).
    cursor.execute(
        "INSERT INTO dnsbl ( groupname, timestamp, entries, counter ) "
        "SELECT 'Upstream', ?, 0, 0 "
        "WHERE NOT EXISTS (SELECT 1 FROM dnsbl WHERE groupname = 'Upstream')",
        (make_timestamp(),),
    )


def _db_create(db: int, cursor: Any) -> None:
    if db == DB_RESOLVER:
        cursor.execute("CREATE TABLE IF NOT EXISTS resolver (row integer, totalqueries integer, queries integer)")
        # Seed row 0 atomically (no-op once present) -- same singleton-seed shape as
        # _db_seed_upstream_row: INSERT ... WHERE NOT EXISTS avoids a check-then-insert
        # race and is idempotent (preserves accumulated totals across a re-init/reconnect).
        cursor.execute(
            "INSERT INTO resolver ( row, totalqueries, queries ) "
            "SELECT 0, 0, 0 WHERE NOT EXISTS (SELECT 1 FROM resolver)"
        )
    elif db == DB_DNSBL:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER )"
        )
        _db_seed_upstream_row(cursor)
    elif db == DB_CACHE:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS dnsblcache ( type TEXT, domain TEXT, groupname TEXT, final TEXT, feed TEXT );"
        )


def _db_connect(db: int) -> Any:
    con = sqlite3.connect(_db_file(db), timeout=100000, check_same_thread=False)
    # A silently-failed PRAGMA leaves the connection on SQLite defaults -- most
    # importantly rollback-journal instead of WAL, where a writer's commit blocks
    # concurrent readers (issue #771). The connection still works, so don't fail
    # the connect -- but the fallback must be visible in the log.
    try:
        # PRAGMA journal_mode=WAL returns the mode actually in effect; a non-'wal'
        # result is a silent downgrade (no exception), so read it back and warn.
        row = con.execute("PRAGMA journal_mode=WAL").fetchone()
        con.execute("PRAGMA busy_timeout=100000")
        con.execute("PRAGMA synchronous=NORMAL")
        mode = str(row[0]).lower() if row else ""
        if mode != "wal":
            sys.stderr.write(
                "[pfBlockerNG]: sqlite journal_mode is '{}' (wanted 'wal') db {}:"
                " concurrent readers may hit 'database is locked'\n".format(mode, _db_file(db))
            )
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: sqlite PRAGMA setup failed db {}: {}\n".format(_db_file(db), e))
    _db_create(db, con.cursor())
    con.commit()
    return con


def _db_close(db: int) -> None:
    con = _db_conns.pop(db, None)
    if con is not None:
        try:
            con.close()
        except Exception:
            pass


def _db_run(db: int, work: Callable[[Any], None]) -> bool:
    # Run work(con) against the persistent connection and commit. On fault,
    # reconnect (which re-creates the tables) and re-run, bounded retries, so a
    # dequeued write is never silently dropped on a transient error.
    with _db_lock:
        for attempt in range(4):
            try:
                con = _db_conns.get(db)
                if con is None:
                    con = _db_connect(db)
                    _db_conns[db] = con
                work(con)
                con.commit()
                return True
            except Exception as e:
                _db_close(db)
                if attempt == 3:
                    sys.stderr.write("[pfBlockerNG]: sqlite write failed db {}: {}\n".format(_db_file(db), e))
                    # Preserve historical behaviour: clear a corrupt DNSBL cache db.
                    if db == DB_CACHE:
                        try:
                            if os.path.isfile(pfb["pfb_py_cache"]):
                                os.remove(pfb["pfb_py_cache"])
                        except Exception:
                            pass
                    return False
                time.sleep(0.25)
        return False


def _db_flush_resolver(delta: int) -> bool:
    if not delta or not pfb["sqlite3_resolver_con"]:
        return True
    return _db_run(
        DB_RESOLVER,
        lambda con: con.execute("UPDATE resolver SET totalqueries = totalqueries + ? WHERE row = 0", (delta,)),
    )


def _db_flush_dnsbl(deltas: dict[str, int]) -> bool:
    if not deltas or not pfb["sqlite3_dnsbl_con"]:
        return True
    rows = [(d, g) for g, d in deltas.items()]

    def _flush(con: Any) -> None:
        if "Upstream" in deltas:
            # Issue #858: re-seed a mid-connection-cleared 'Upstream' row before the
            # UPDATE below, so the increment is never silently dropped. Gated on an
            # actual Upstream delta so a feed-only flush doesn't pay for it.
            _db_seed_upstream_row(con.cursor())
        con.executemany("UPDATE dnsbl SET counter = counter + ? WHERE groupname = ?", rows)

    return _db_run(DB_DNSBL, _flush)


def _db_flush_cache(rows: list[Any]) -> bool:
    if not rows:
        return True
    return _db_run(
        DB_CACHE,
        lambda con: con.executemany(
            "INSERT INTO dnsblcache (type, domain, groupname, final, feed) VALUES (?,?,?,?,?)", rows
        ),
    )


def _db_reset_cache() -> bool:
    # ADR-10: reset the DNSBL Reports cache (the dnsblcache table the Reports tab
    # reads) on a zero-downtime DNSBL swap, in parity with the init-time os.remove of
    # pfb_py_cache.sqlite. Goes through _db_run -> _db_lock, so it serializes with the
    # off-thread pfb_db_worker (and the synchronous fallback) on the SAME persistent
    # connection -- it never touches the sqlite file directly off-thread (a delete/
    # reconnect would race the worker mid-flush). DELETE FROM (vs DROP/os.remove) keeps
    # the schema + WAL connection live so the very next enqueued block row inserts
    # cleanly post-swap; _db_run re-creates the table on a faulted reconnect. The
    # current PHP Reports reader reads ALL rows (no generation column), so a destructive
    # clear is the correct no-restart equivalent of today's wipe-on-restart; a
    # generation-key alternative is deferred to PHP.
    return _db_run(DB_CACHE, lambda con: con.execute("DELETE FROM dnsblcache"))


def pfb_db_validate(db: int) -> bool:
    # Ensure the database/table exists (used at init to gate statistics).
    return _db_run(db, lambda con: None)


def _validate_db_with_recovery(db: int) -> bool:
    # Issue #900: pfb_db_validate -> _db_run swallows every connect/PRAGMA fault
    # (a corrupt file included) and returns False -- it never raises, so the
    # try/except recovery this replaces was dead code and a corrupt DB was never
    # healed. Treat a False validate as the broken-DB case (usually corruption;
    # disk-full/read-only faults also land here -- acceptable for a stats-only
    # DB): delete the file plus its WAL/SHM sidecars (the DBs run journal_mode=
    # WAL, so a stale -wal/-shm surviving next to a recreated main file must not
    # linger; each remove tolerates a fault, e.g. a read-only dir) and
    # revalidate once -- no infinite retry.
    #
    # The whole validate -> remove -> revalidate sequence holds _db_recovery_lock:
    # without it, two threads recovering the same corrupt DB can both validate
    # False, and the loser's remove then deletes the winner's freshly rebuilt LIVE
    # file while the cached connection in _db_conns keeps writing to the unlinked
    # inode -- counters silently lost again. The first validate inside the lock
    # doubles as the loser's recheck: it succeeds via the winner's cached
    # connection and returns without a second delete. Lock ordering stays
    # _db_recovery_lock -> _db_lock (via pfb_db_validate -> _db_run); see the
    # _db_recovery_lock definition.
    with _db_recovery_lock:
        if pfb_db_validate(db):
            return True
        base = _db_file(db)
        for stale in (base, base + "-wal", base + "-shm"):
            try:
                os.remove(stale)
            except OSError:
                pass  # already gone, or unremovable; the revalidate below reports if still broken
        return pfb_db_validate(db)


def _dnsbl_stats_wanted() -> bool:
    # Issue #860: the Upstream counter (issue #267 forwarding-mode detection) shares
    # the dnsbl stats DB with per-feed blocks. Detection itself is forwarding-gated
    # only (inplace_cb_query_response), so gating the DB open on python_blacklist
    # alone left a forwarding-only install (no DNSBL blacklist loaded) with
    # sqlite3_dnsbl_con permanently False: every upstream block logged its line but
    # the counter enqueue/flush was silently skipped forever. Extracted (rather than
    # inlined) so it's unit-testable -- init_standard itself needs the live Unbound
    # env and can't run off-box.
    return bool(pfb["python_blacklist"] or pfb.get("forwarding"))


def _open_dnsbl_stats_db_if_wanted() -> None:
    # Issue #862 / #870: open the dnsbl stats SQLite DB when stats are newly wanted but
    # init left it closed (a forwarding-off, no-feeds boot skips the open). Shared by
    # every site that flips python_blacklist True AFTER init -- the ADR-10 swap
    # (rebuild_and_swap) and the PFBL-03 control-channel enable / timed re-enable
    # (pfb_apply_control_command, python_control_sleep) -- so all post-init enable paths
    # stay consistent; else _db_flush_dnsbl and _log_upstream_block (both gated on
    # sqlite3_dnsbl_con) silently drop every counter until the next full restart.
    #
    # Idempotent (the not-sqlite3_dnsbl_con guard no-ops when init already opened it).
    # NOT off the DNS fast path under the legacy control transport: pfb_apply_control_command
    # is reachable from operate() (the python_control_legacy branch), so this can run on an
    # Unbound query worker, not just the watcher / control-sleep threads. Issue #900: a
    # corrupt DB is recovered (delete + one revalidate) by _validate_db_with_recovery, shared
    # with init_standard's identical "Enable DNSBL statistics" gate.
    if pfb["mod_sqlite3"] and not pfb["sqlite3_dnsbl_con"] and _dnsbl_stats_wanted():
        if _validate_db_with_recovery(DB_DNSBL):
            pfb["sqlite3_dnsbl_con"] = True
        else:
            sys.stderr.write("[pfBlockerNG]: Failed to open pfb_py_dnsbl.sqlite database after recovery attempt\n")


def _db_apply(task: tuple) -> None:
    # Synchronous fallback when no DB worker is running (init, tests).
    kind = task[0]
    if kind == "resolver":
        _db_flush_resolver(1)
    elif kind == "dnsbl":
        _db_flush_dnsbl({task[1]: 1})
    elif kind == "cache":
        _db_flush_cache([task[1]])


def pfb_db_worker() -> None:
    # Batch DB writes off the DNS path. Counter increments accumulate as per-key
    # deltas (commutative); cache rows keep FIFO order. Flush on a timer, on a
    # size threshold, when idle, and on stop.
    resolver_delta = 0
    dnsbl_deltas: dict[str, int] = {}
    cache_rows: list[Any] = []
    last_flush = time.monotonic()
    stop = False

    def accumulate(t: tuple) -> None:
        nonlocal resolver_delta
        if t[0] == "resolver":
            resolver_delta += 1
        elif t[0] == "dnsbl":
            dnsbl_deltas[t[1]] = dnsbl_deltas.get(t[1], 0) + 1
        elif t[0] == "cache":
            cache_rows.append(t[1])

    def flush() -> None:
        nonlocal resolver_delta, dnsbl_deltas, cache_rows, last_flush
        if resolver_delta and _db_flush_resolver(resolver_delta):
            resolver_delta = 0
        if dnsbl_deltas and _db_flush_dnsbl(dnsbl_deltas):
            dnsbl_deltas = {}
        if cache_rows and _db_flush_cache(cache_rows):
            cache_rows = []
        last_flush = time.monotonic()

    while True:
        try:
            task = pfb_db_queue.get(timeout=PFB_DB_FLUSH_INTERVAL)
        except queue.Empty:
            task = None
        try:
            if task is not None:
                if task[0] == "stop":
                    while True:
                        try:
                            t = pfb_db_queue.get_nowait()
                        except queue.Empty:
                            break
                        try:
                            if t is not None and t[0] != "stop":
                                accumulate(t)
                        finally:
                            pfb_db_queue.task_done()
                    stop = True
                else:
                    accumulate(task)
        finally:
            if task is not None:
                pfb_db_queue.task_done()

        if (
            stop
            or task is None
            or (resolver_delta + len(dnsbl_deltas) + len(cache_rows)) >= PFB_DB_MAX_BATCH
            or (time.monotonic() - last_flush) >= PFB_DB_FLUSH_INTERVAL
        ):
            flush()
        if stop:
            break


def pfb_db_enqueue(task: tuple) -> None:
    # Enqueue a DB op for the worker; drop on a saturated queue so the DNS
    # response path is never blocked. Falls back to synchronous execution when
    # no worker is running (init, tests, threading unavailable).
    if pfb.get("db_worker"):
        try:
            pfb_db_queue.put_nowait(task)
            return
        except queue.Full:
            pfb["db_dropped"] = pfb.get("db_dropped", 0) + 1
            return
    _db_apply(task)


def get_details_dnsbl(
    m_type: str,
    qinfo: query_info | None,
    qstate: module_qstate | None,
    rep: reply_info | None,
    kwargs: dict[str, Any] | None,
) -> bool:
    global pfb, rcodeDB, decisionDB, noAAAADB, maxmindReader, _dnsbl_last_event

    if qstate and qstate is not None:
        q_name = get_q_name_qstate(qstate)
    elif qinfo and qinfo is not None:
        q_name = get_q_name_qinfo(qinfo)
    else:
        return True

    # Increment totalqueries counter
    if pfb["sqlite3_resolver_con"]:
        pfb_db_enqueue(("resolver",))

    # Determine if event is a 'reply' or DNSBL block. decisionDB now also holds allow
    # ("let it resolve"/whitelisted) verdicts, so attribute only an actual block.
    # operate() stores decisionDB keys lowercased, so normalize the lookup -- otherwise
    # a mixed-case query is blocked but its block is not attributed here (the log/counter
    # path silently misses it -> per-feed under-count).
    q_name_key = q_name.lower()
    cached = decisionDB.get(q_name_key)
    # No snap_gen check (issue #1074): this only ATTRIBUTES the block operate() served
    # -- a live-gen gate would drop the log line for a block served just before a swap;
    # worst case is a swap-race mis-attributed feed/group in the log, never the answer.
    dnsbl = cached.dnsbl if cached is not None else UNSET
    if dnsbl is not UNSET and dnsbl.is_found and not dnsbl.in_whitelist:
        # If logging is disabled, do not log blocked DNSBL events (Utilize DNSBL Webserver)
        # except for Python nullblock events
        if pfb["python_nolog"] and not dnsbl.null_blocking:
            return True

        # Increment dnsblgroup counter
        if pfb["sqlite3_dnsbl_con"] and dnsbl.group != "":
            pfb_db_enqueue(("dnsbl", dnsbl.group))

        # The cached DnsblDecision is both name- and qtype-independent for some block
        # kinds -- two subdomains of one blocked zone share an identical payload (same
        # b_eval=zone) -- so fold BOTH the queried name and q_type into the
        # consecutive-dedup signature and the log line. Without the name, two distinct
        # same-zone blocks compare equal -> the second is wrongly marked a duplicate
        # (zone under-count); the old dnsblDB dict carried a "qname" field that str()
        # folded in implicitly, which DnsblDecision does not. Without q_type, a client's
        # back-to-back A+AAAA of one name collapses (dual-stack under-count) and Reports
        # cannot break down by record type. The decision path stays correct and untouched.
        q_type = get_q_type(qstate, qinfo)

        dupEntry = "+"
        event_sig = (q_name_key, q_type, dnsbl)
        if _dnsbl_last_event is not None:
            if str(_dnsbl_last_event) == str(event_sig):
                dupEntry = "-"
            else:
                _dnsbl_last_event = event_sig
        else:
            _dnsbl_last_event = event_sig

        # Skip logging: null-no-log ("2") and NXDOMAIN-no-log ("4"). The per-group
        # counter above still increments (stats parity with the logged variants); only
        # the dnsbl.log line is suppressed.
        if dnsbl.log_type in ("2", "4"):
            return True

        q_ip = get_q_ip_comm(kwargs)
        if q_ip == "Unknown":
            q_ip = "127.0.0.1"

        timestamp = make_timestamp()

        csv_line = ",".join(
            "{}".format(v)
            for v in (
                "DNSBL-python",
                timestamp,
                q_name,
                q_ip,
                dnsbl.p_type,
                dnsbl.b_type,
                dnsbl.group,
                dnsbl.b_eval,
                dnsbl.feed,
                dupEntry,
                q_type,
            )
        )
        pfb_log("/var/log/pfblockerng/dnsbl.log", csv_line)

    return True


def _log_idn_alert(q_name: str, q_ip: str, idn_alert: tuple[Any, Any, str], q_type: str) -> None:
    """Log an ADR-08 Confusable-mode ALERT (the name still resolves) -- same shape as a block.

    A suspicious/flagged homoglyph (or a malicious one with the block sub-toggle disabled)
    is alerted, not blocked: it must be surfaced so an operator can review it, without
    breaking resolution. The line mirrors ``get_details_dnsbl``'s CSV columns so the alerts
    page renders it identically -- with ``b_type`` "Homoglyph_Alert" marking it a non-block
    alert, and ``b_eval`` carrying the dual form (``xn-- [decoded] script``).
    """
    feed, group, b_eval = idn_alert
    if q_ip == "Unknown":
        q_ip = "127.0.0.1"
    csv_line = ",".join(
        "{}".format(v)
        for v in (
            "DNSBL-python",
            make_timestamp(),
            q_name,
            q_ip,
            "Python",  # p_type
            "Homoglyph_Alert",  # b_type -- distinguishes an alert from a block
            group,
            b_eval,
            feed,
            "+",  # dupEntry
            q_type,
        )
    )
    pfb_log("/var/log/pfblockerng/dnsbl.log", csv_line)


def _log_upstream_block(q_name: str, q_ip: str, result: UpstreamBlock, q_type: str) -> None:
    """Log an issue #267 upstream/external DNS block -- same CSV shape as a DNSBL block.

    Mirrors ``_log_idn_alert``'s structure.  ``b_type`` is ``"Upstream_Block"`` so the
    PHP Reports/Alerts page can filter and render it distinctly (a later PR).
    ``b_eval`` is the classifier label (e.g. ``"NXRA"``); ``feed`` is the provider
    name from EDE EXTRA-TEXT, or ``"External"`` when the reply carried none.
    No consecutive-duplicate suppression for now (noted as a follow-up).
    """
    if q_ip == "Unknown":
        q_ip = "127.0.0.1"
    csv_line = ",".join(
        "{}".format(v)
        for v in (
            "DNSBL-python",
            make_timestamp(),
            q_name,
            q_ip,
            "Python",  # p_type
            "Upstream_Block",  # b_type -- greppable prefix, distinct from feed blocks
            "Upstream",  # group
            result.label,  # b_eval, e.g. "NXRA" / "EDE15 (Blocked)"
            result.provider or "External",  # feed -- provider name or generic sentinel
            "+",  # dupEntry (dedup follow-up)
            q_type,
        )
    )
    pfb_log("/var/log/pfblockerng/dnsbl.log", csv_line)
    # Increment the aggregate Upstream group counter (parity with per-feed DNSBL blocks).
    if pfb["sqlite3_dnsbl_con"]:
        pfb_db_enqueue(("dnsbl", "Upstream"))


def make_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _log_entry_direct(line: str, log: str) -> None:
    # Synchronous fallback used when the logging pipeline is not running (during
    # init, in the test suite, or if it failed to start): open/append/close per line.
    for i in range(1, 5):
        try:
            with open(log, "a") as append_log:
                append_log.write(line + "\n")
        except Exception as e:
            if i == 4:
                sys.stderr.write("[pfBlockerNG]: log_entry: {}: {}".format(i, e))
            time.sleep(0.25)
            continue
        break


PFB_LOG_QUEUE_MAXSIZE = 5000

PFB_LOG_FILES = (
    "/var/log/pfblockerng/dnsbl.log",
    "/var/log/pfblockerng/dns_reply.log",
)


class _PfbLogFilter(logging.Filter):
    # Route each record to exactly one file handler, by logger name.
    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name

    def filter(self, record: Any) -> bool:
        return record.name == self._name


class _PfbDropQueueHandler(logging.handlers.QueueHandler):
    # Never block the DNS path: drop the record when the bounded queue is full.
    def enqueue(self, record: Any) -> None:
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            pfb["log_dropped"] = pfb.get("log_dropped", 0) + 1


def pfb_setup_logging() -> None:
    # One persistent-handle file logger per app log, written from a single
    # QueueListener thread off the DNS path. WatchedFileHandler reopens the file
    # when it is rotated/truncated externally (the line-cap trim, the viewer clear).
    global pfb_log_queue, pfb_log_listener
    if pfb.get("log_listener"):
        return
    try:
        pfb_log_queue = queue.Queue(maxsize=PFB_LOG_QUEUE_MAXSIZE)
        handlers = []
        for path in PFB_LOG_FILES:
            name = "pfb.applog." + path
            logger = logging.getLogger(name)
            logger.setLevel(logging.INFO)
            logger.propagate = False
            logger.handlers = [_PfbDropQueueHandler(pfb_log_queue)]
            pfb_loggers[path] = logger

            handler = logging.handlers.WatchedFileHandler(path, mode="a", delay=True)
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler.addFilter(_PfbLogFilter(name))
            handlers.append(handler)

        pfb_log_listener = logging.handlers.QueueListener(pfb_log_queue, *handlers)
        pfb_log_listener.start()
        pfb["log_listener"] = True
    except Exception as e:
        pfb["log_listener"] = False
        pfb_loggers.clear()
        sys.stderr.write("[pfBlockerNG]: Failed to start log listener: {}".format(e))


def pfb_log(log: str, line: str) -> None:
    # Emit a line to an app log via the async logging pipeline; fall back to a
    # synchronous append when the pipeline is not running (init, tests).
    logger = pfb_loggers.get(log)
    if logger is not None:
        logger.info(line)
    else:
        _log_entry_direct(line, log)


def get_details_reply(
    m_type: str,
    qinfo: query_info | None,
    qstate: module_qstate | None,
    rep: reply_info | None,
    kwargs: dict[str, Any] | None,
) -> bool:
    global pfb, rcodeDB, decisionDB, noAAAADB, maxmindReader

    if qstate and qstate is not None:
        q_name = get_q_name_qstate(qstate)
    elif qinfo and qinfo is not None:
        q_name = get_q_name_qinfo(qinfo)
    else:
        return True

    q_ip = get_q_ip_comm(kwargs)
    if q_ip == "Unknown" or q_ip == "127.0.0.1":
        q_ip = "127.0.0.1"
        m_type = "resolver"

    o_type = get_q_type(qstate, qinfo)
    if m_type == "cache" or o_type == "PTR":
        q_type = o_type
    else:
        q_type = get_o_type(qstate, rep)

    # Collect 'python_control' and 'noAAAA' events from inplace_cb_reply
    if m_type == "reply-x":
        is_reply = False
        if q_name.startswith("python_control."):
            is_reply = True
        if not is_reply and q_type == "AAAA" and evaluate_noaaaa(q_name, noAAAADB):
            is_reply = True

        if not is_reply:
            return True
        m_type = "reply"

    # Increment totalqueries counter (Don't include the Resolver DNS requests)
    if pfb["sqlite3_resolver_con"] and q_ip != "127.0.0.1":
        pfb_db_enqueue(("resolver",))

    # Do not log Replies, if disabled
    if not pfb["python_reply"]:
        return True

    r_addr = ""
    if rep and rep is not None:
        if rep.an_numrrsets and rep.an_numrrsets > 0:
            for i in range(0, rep.an_numrrsets):
                if rep.rrsets[i].rk and rep.rrsets[i].entry.data:
                    e = rep.rrsets[i].rk
                    if e.type_str:
                        d = rep.rrsets[i].entry.data
                        if e.type_str == "CNAME" and d.count > 1:
                            continue

                        for j in range(0, d.count):
                            x = d.rr_data[j]
                            if e.type_str == "A":
                                r_addr = convert_ipv4(x)
                                break
                            elif e.type_str == "AAAA":
                                if pfb["mod_ipaddress"]:
                                    r_addr = convert_ipv6(x)
                                    try:
                                        r_addr = ipaddress.ip_address(r_addr).compressed
                                    except Exception as ex:
                                        sys.stderr.write(
                                            "[pfBlockerNG]: Failed to compress IPv6: {}, {}".format(r_addr, ex)
                                        )
                                        pass
                                break
                            elif e.type_str in ("DNSKEY", "DS"):
                                r_addr = "DNSSEC"
                                break
                            else:
                                r_addr = r_addr + "|" + convert_other(x)
                                r_addr = r_addr.strip("|")
                            if not r_addr:
                                r_addr = "NXDOMAIN"

        else:
            # No Answer section found
            r_addr = "NXDOMAIN"

    # Collect RCODE for non-NOError codes
    try:
        if qstate and qstate.return_rcode is not None and qstate.return_rcode != 0:
            isrcode = rcodeDB.get(qstate.return_rcode)
            if isrcode is not None:
                r_addr = isrcode
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: RCODE {}: {}".format(e, q_name))
        pass

    r_addr = is_unknown(r_addr)

    if q_type == "SOA" and r_addr == "NXDOMAIN":
        r_addr = "SOA"

    if q_type == "NSEC3" and r_addr == "NXDOMAIN":
        r_addr = "NSEC3"

    if q_type == "NS" and q_name == "Unknown":
        q_name = "NS"

    # Determine if domain was noAAAA blocked
    if r_addr == "NXDOMAIN" and q_type == "AAAA" and evaluate_noaaaa(q_name, noAAAADB):
        r_addr = "noAAAA"

    if pfb["python_maxmind"] and r_addr not in ("", "Unknown", "NXDOMAIN", "NODATA", "DNSSEC", "SOA", "NS"):
        version: int | str = ""
        try:
            version = ipaddress.ip_address(r_addr).version
        except Exception:
            pass

        if version != "":
            try:
                isPrivate = ipaddress.ip_address(r_addr).is_private
                isLoopback = ipaddress.ip_address(r_addr).is_loopback

                if isPrivate:
                    iso_code = "prv"
                elif isLoopback:
                    iso_code = "l.b."
                else:
                    geoip = maxmindReader.get(r_addr)
                    if geoip:
                        if "country" in geoip:
                            country = geoip["country"]
                            if "iso_code" in country:
                                iso_code = geoip["country"]["iso_code"]
                            else:
                                iso_code = "unk"
                        elif "continent" in geoip:
                            continent = geoip["continent"]
                            if "code" in continent:
                                iso_code = geoip["continent"]["code"]
                            else:
                                iso_code = "unk"
                        else:
                            iso_code = "unk"
                    else:
                        iso_code = "unk"

            except Exception as e:
                sys.stderr.write("[pfBlockerNG]: MaxMind Reader failed: {}: IP: {}".format(e, r_addr))
                iso_code = "unk"
                pass
        else:
            iso_code = "unk"
    else:
        iso_code = "unk"

    ttl = get_rep_ttl(rep)
    # Cached TTLs are in unix timestamp (time remaining)
    if m_type == "cache":
        if ttl.isdigit() and len(ttl) == 10:
            ttl = str(int(ttl) - int(time.time()))
        else:
            ttl = ""

    timestamp = make_timestamp()

    csv_line = ",".join(
        "{}".format(v) for v in ("DNS-reply", timestamp, m_type, o_type, q_type, ttl, q_name, q_ip, r_addr, iso_code)
    )
    pfb_log("/var/log/pfblockerng/dns_reply.log", csv_line)

    return True


# Is sleep duration valid
def python_control_duration(duration: str) -> int | bool:

    try:
        if duration.isnumeric():
            value = int(duration)
            if 0 < value <= 3600:
                return value
        return False
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_duration: {}".format(e))
        pass
    return False


# Is thread still active
def python_control_thread(tname: str) -> bool:
    try:
        for t in threading.enumerate():
            if t.name == tname:
                return True
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_thread: {}".format(e))
        pass
    return False


# Python_control Start Thread
def python_control_start_thread(tname: str, fcall: Callable[..., Any], arg1: Any, arg2: Any) -> bool:
    try:
        t1 = threading.Thread(name=tname, target=fcall, args=(arg1, arg2), daemon=True)
        t1.start()
        return True
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_start_thread: {}".format(e))
        pass
    return False


# Python_control sleep timer
def python_control_sleep(duration: int, arg: Any) -> bool:
    global pfb

    try:
        time.sleep(duration)
        pfb["python_blacklist"] = True
        # Issue #870: the timed re-enable newly wants DNSBL stats too -- open the DB
        # init skipped, same as the control-channel enable and the ADR-10 swap.
        _open_dnsbl_stats_db_if_wanted()
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_sleep: {}".format(e))
        pass
    return True


# Python_control Add Bypass IP for specified duration
def python_control_addbypass(duration: int, b_ip: str) -> bool:
    global pfb, gpListDB

    try:
        time.sleep(duration)
        if gpListDB.get(b_ip) is not None:
            gpListDB.pop(b_ip)
            return True
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] python_control_addbypass: {}".format(e))
        pass
    return False


# PFBL-03: the SINGLE DNSBL-control command handler. Both transports route
# here -- the legacy DNS-TXT branch (operate()) and the local privileged
# command channel (pfb_control_watcher()) -- so the grammar and its side
# effects have exactly one implementation. ``control_command`` is the
# dot-split token list both build identically; validated here (never
# trusting the transport): a bypass IP via ipaddress.ip_address(), a
# duration via python_control_duration() (1-3600). Returns
# ``(applied, message)``; behaviour is byte-for-byte the prior DNS-TXT branch.
def pfb_apply_control_command(control_command: list[str]) -> tuple[bool, str]:
    global pfb, gpListDB

    control_rcd = False
    control_msg = ""

    if len(control_command) >= 2:
        if control_command[1] == "disable":
            control_rcd = True
            control_msg = "Python_control: DNSBL disabled"
            pfb["python_blacklist"] = False

            # If duration specified, disable DNSBL Blocking for specified time in seconds
            if pfb["mod_threading"] and len(control_command) == 3 and control_command[2] != "":
                # Validate Duration argument
                duration = python_control_duration(control_command[2])
                if duration:
                    # Ensure thread is not active
                    if not python_control_thread("sleep"):
                        # Start Thread
                        if not python_control_start_thread("sleep", python_control_sleep, duration, None):
                            control_rcd = False
                            control_msg = "Python_control: DNSBL disabled: Thread failed"
                        else:
                            control_msg = "{} for {} second(s)".format(control_msg, duration)
                    else:
                        control_rcd = False
                        control_msg = "Python_control: DNSBL disabled: Previous call still in progress"
                else:
                    control_rcd = False
                    control_msg = "Python_control: DNSBL disabled: duration [ {} ] out of range (1-3600sec)".format(
                        control_command[2]
                    )

        elif control_command[1] == "enable":
            control_rcd = True
            control_msg = "Python_control: DNSBL enabled"
            pfb["python_blacklist"] = True
            # Issue #870: enabling via the control channel newly satisfies
            # _dnsbl_stats_wanted(); open the stats DB init skipped at boot (sibling of
            # #862's swap-path open) so per-feed/Upstream counters do not silently no-op.
            _open_dnsbl_stats_db_if_wanted()

        elif control_command[1] == "addbypass" or control_command[1] == "removebypass":
            # PFBL-03: reject a malformed bypass command instead of raising
            if len(control_command) < 3 or control_command[2] == "":
                return False, "Python_control: Missing bypass IP"
            b_ip = (control_command[2]).replace("-", ".")
            try:
                isIPValid = ipaddress.ip_address(b_ip)
            except ValueError:
                return False, "Python_control: Invalid IP: [ {} ]".format(b_ip)

            if isIPValid:
                if not pfb["gpListDB"]:
                    pfb["gpListDB"] = True

                control_rcd = True
                if control_command[1] == "addbypass":
                    control_msg = "Python_control: Add bypass for IP: [ {} ]".format(b_ip)

                    # If duration specified, disable DNSBL Blocking for specified time in seconds
                    if pfb["mod_threading"] and len(control_command) == 4 and control_command[3] != "":
                        # Validate Duration argument
                        duration = python_control_duration(control_command[3])
                        if duration:
                            # Ensure thread is not active
                            if not python_control_thread("addbypass" + b_ip):
                                # Start Thread
                                if not python_control_start_thread(
                                    "addbypass" + b_ip, python_control_addbypass, duration, b_ip
                                ):
                                    control_rcd = False
                                    control_msg = "Python_control: Add bypass for IP: [ {} ] thread failed".format(b_ip)
                                else:
                                    gpListDB[b_ip] = 0
                                    control_msg = "{} for {} second(s)".format(control_msg, duration)
                            else:
                                control_rcd = False
                                control_msg = (
                                    "Python_control: Add bypass for IP: [ {} ]: Previous call still in progress"
                                ).format(b_ip)
                        else:
                            control_rcd = False
                            control_msg = (
                                "Python_control: Add bypass for IP: [ {} ]: duration [ {} ] out of range (1-3600sec)"
                            ).format(b_ip, control_command[3])
                    else:
                        # Add bypass called without duration
                        if control_rcd:
                            gpListDB[b_ip] = 0

                elif control_command[1] == "removebypass":
                    if gpListDB.get(b_ip) is not None:
                        control_msg = "Python_control: Remove bypass for IP: [ {} ]".format(b_ip)
                        gpListDB.pop(b_ip)
                    else:
                        control_msg = "Python_control: IP not in Group Policy: [ {} ]".format(b_ip)

    return control_rcd, control_msg


def inplace_cb_reply(
    qinfo: query_info,
    qstate: module_qstate,
    rep: reply_info,
    rcode: int,
    edns: Any,
    opt_list_out: Any,
    region: Any,
    **kwargs: Any,
) -> bool:
    get_details_reply("reply-x", qinfo, qstate, rep, kwargs)
    return True


def inplace_cb_reply_cache(
    qinfo: query_info,
    qstate: module_qstate,
    rep: reply_info,
    rcode: int,
    edns: Any,
    opt_list_out: Any,
    region: Any,
    **kwargs: Any,
) -> bool:
    get_details_reply("cache", qinfo, qstate, rep, kwargs)
    return True


def inplace_cb_reply_local(
    qinfo: query_info,
    qstate: module_qstate,
    rep: reply_info,
    rcode: int,
    edns: Any,
    opt_list_out: Any,
    region: Any,
    **kwargs: Any,
) -> bool:
    get_details_reply("local", qinfo, qstate, rep, kwargs)
    return True


def inplace_cb_reply_servfail(
    qinfo: query_info,
    qstate: module_qstate,
    rep: reply_info,
    rcode: int,
    edns: Any,
    opt_list_out: Any,
    region: Any,
    **kwargs: Any,
) -> bool:
    get_details_reply("servfail", qinfo, qstate, rep, kwargs)
    return True


def _upstream_edns_opts(qstate: Any) -> list[tuple[int, bytes]]:
    """Read the upstream's EDNS options from ``qstate.edns_opts_back_in_iter``.

    Returns ``[(opt_code, opt_data_bytes), ...]`` — empty list on any failure.
    Validated live (issue #267, run #158): no option registration needed for EDE (code 15).
    """
    try:
        return [(int(o.code), bytes(o.data)) for o in qstate.edns_opts_back_in_iter]
    except Exception:  # noqa: BLE001
        return []


def _client_ip_from_qstate(qstate: Any) -> str:
    """Best-effort client IP from ``qstate.mesh_info.reply_list``; fallback ``"127.0.0.1"``."""
    try:
        rl = qstate.mesh_info.reply_list
        if rl is not None:
            qr = getattr(rl, "query_reply", None)
            if qr is not None:
                addr = getattr(qr, "addr", None)
                if addr:
                    return str(addr)
    except Exception:  # noqa: BLE001
        pass
    return "127.0.0.1"


def inplace_cb_query_response(qstate: Any, response: Any, **kwargs: Any) -> bool:
    """Detect an upstream/external DNS block on the RAW upstream response (issue #267).

    Fires per upstream response, before Unbound rebuilds the client reply, so the
    upstream RA/AA bits + EDE survive here (the inplace_cb_reply* hooks do not see them).
    Only active in forwarding mode (pfb["forwarding"]). Observe-and-log only.
    """
    try:
        if not pfb.get("forwarding"):
            return True
        rep = getattr(response, "rep", None)
        flags = getattr(rep, "flags", None) if rep is not None else None
        if not isinstance(flags, int):
            return True
        rcode = flags & 0x000F
        ra = bool(flags & 0x0080)  # wire RA bit (NOT the runtime PKT_RA=0x20)
        aa = bool(flags & 0x0400)  # wire AA bit
        ede = _parse_ede_options(_upstream_edns_opts(qstate))
        result = classify_upstream_block(rcode, ra, aa, ede)
        if result is None:
            return True
        q_name = get_q_name_qstate(qstate)
        q_type = get_q_type(qstate, None)
        q_ip = _client_ip_from_qstate(qstate)
        _log_upstream_block(q_name, q_ip, result, q_type)
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] inplace_cb_query_response: {}\n".format(e))
    return True


def deinit(id: int) -> bool:
    global \
        pfb, \
        maxmindReader, \
        pfb_task_queue, \
        pfb_worker_thread, \
        pfb_db_queue, \
        pfb_db_worker_thread, \
        pfb_reload_watcher_thread, \
        pfb_reload_stop, \
        pfb_control_watcher_thread, \
        pfb_control_stop

    if pfb["python_maxmind"]:
        maxmindReader.close()

    # ADR-10: stop the reload-watcher cleanly -- set the stop Event (which also wakes
    # the kqueue/poll wait via its timeout), then join with a timeout so deinit never
    # hangs on a stuck watcher. The thread is a daemon, so a missed join cannot block
    # interpreter shutdown either.
    if pfb.get("reload_watcher"):
        try:
            pfb_reload_stop.set()
            pfb_reload_watcher_thread.join(timeout=5)
        except Exception:
            pass
        pfb["reload_watcher"] = False

    # PFBL-03: stop the control-channel reader cleanly (same pattern as the reload
    # watcher -- set the stop Event to wake the kqueue/poll wait, then a bounded join).
    if pfb.get("control_watcher"):
        try:
            pfb_control_stop.set()
            pfb_control_watcher_thread.join(timeout=5)
        except Exception:
            pass
        pfb["control_watcher"] = False

    # Drain and stop the background DB-write worker, then close connections
    if pfb.get("db_worker"):
        try:
            pfb_db_queue.put(("stop",))
            pfb_db_worker_thread.join(timeout=5)
        except Exception:
            pass
        pfb["db_worker"] = False
    # Close under the lock: if the worker outlived the join timeout it may still be
    # mid-_db_run (which holds _db_lock), so serialize the close to avoid a race.
    with _db_lock:
        for _db in list(_db_conns.keys()):
            _db_close(_db)

    # Stop the logging pipeline (QueueListener flushes queued records on stop)
    if pfb.get("log_listener"):
        try:
            pfb_log_listener.stop()
        except Exception:
            pass
        pfb["log_listener"] = False

    # Drain and stop the background I/O worker
    if pfb.get("async_worker"):
        try:
            pfb_task_queue.put(None)
            pfb_worker_thread.join(timeout=5)
        except Exception:
            pass
        pfb["async_worker"] = False

    log_info("[pfBlockerNG]: pfb_unbound.py script exiting")
    return True


def inform_super(id: int, qstate: module_qstate, superqstate: module_qstate, qdata: Any) -> bool:
    return True


# --------------------------------------------------------------------------- #
# DNSBL build layer (ADR-06) -- pure, stdlib-only, Unbound-symbol-free. Moves
# list preprocessing (parse -> normalise -> classify data/zone -> build dicts)
# out of shell/PHP: the boundary is "shell/PHP fetch + tag; Python parse ->
# normalise -> classify -> build dicts -> emit counts" (ADR.md SS2), wired
# into init() via dnsbl_build_from_manifest().
#
#   * Build-time OPTIMISATIONS are dropped, not reimplemented -- no dedup/
#     collapse/build-time whitelist removal (the dict load dedups keys for
#     free; whitelisting is QUERY-TIME via whiteDB).
#   * Classification mirrors tld_analysis/tld_search: a registrable parent ->
#     wildcard ZONE; a deeper sub-domain under an unknown public suffix, or a
#     TLD-excluded name -> exact DATA; a blacklisted TLD -> a whole-TLD ZONE.
#   * IP extraction is NOT Python's job -- it stays in PHP; the parser SKIPS
#     non-domain lines and never produces firewall input.
#   * build() is REENTRANT (returns a new structure-set, mutates no module
#     global) so a zero-downtime reload can run it off-thread and swap in.
#
# Pinned by tests/test_adr06_build_module.py.
# --------------------------------------------------------------------------- #

# Entry kinds (ABP-ready seam). The ADR-06 plain/hosts/csv path emits ONLY BLOCK;
# the ADR-07 ABP Stage-A parser (``parse_abp``) emits BLOCK *and* ALLOW. ``REGEX``
# here is an entry kind kept for the legacy ParsedEntry seam; the ABP Rule model
# below uses ``RULE_TARGET_*`` to say whether a rule targets a domain or a regex.
DNSBL_KIND_BLOCK = "block"
DNSBL_KIND_ALLOW = "allow"
DNSBL_KIND_REGEX = "regex"

# Classification outcomes for an entry's key.
DNSBL_CLASS_DATA = "data"  # exact match  (loaded into dataDB)
DNSBL_CLASS_ZONE = "zone"  # wildcard-incl-self match (loaded into zoneDB)

# --------------------------------------------------------------------------- #
# ADR-07: the intermediate ABP Rule model. ``parse_abp(line, ...) -> Rule |
# None`` turns one raw ABP line into a typed Rule (or None to skip), agreeing
# on every corpus line with the reference oracle
# (tests/test_adr07_decision_spec.py::parse_abp_line).
#
# A Rule's ``target``: RULE_TARGET_DOMAIN (an exact-or-wildcard domain
# literal, ``wildcard`` says whether subdomains are covered) or
# RULE_TARGET_REGEX (an irreducible pattern stored raw in ``key``, NOT
# compiled here). ``kind`` is DNSBL_KIND_BLOCK (``||``/hosts/plain/``/re/``)
# or DNSBL_KIND_ALLOW (``@@||``/``@@/re/``). ``provenance`` is RULE_PROV_FEED
# (a downloaded feed line) or RULE_PROV_USER (sovereign, $badfilter-immune).
# --------------------------------------------------------------------------- #
RULE_TARGET_DOMAIN = "domain"
RULE_TARGET_REGEX = "regex"

RULE_PROV_USER = "user"
RULE_PROV_FEED = "feed"

# Lower-cased label alphabet for the domain-shape gate (parity with PFB_FILTER_DOMAIN,
# pfblockerng.inc:1138-1150, whose regex allows [a-zA-Z0-9_.-]). Underscore is deliberate:
# DNS labels carry no protocol charset (RFC 2181 s11), underscored names are standardized
# practice (RFC 8552) and appear on real blocklists -- this gates BLOCKLIST names matched
# against QNAMEs, not hostnames, so strict LDH would be a coverage hole (#723).
_DNSBL_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")


@dataclass(frozen=True)
class Rule:
    """One typed, DNS-only ABP rule (Stage A) -- the output of ``parse_abp``.

    This is the intermediate model the reconcile / precedence stages stand on;
    it carries everything ``$badfilter`` / ``$important`` / provenance
    resolution need, none of which can survive being folded into a domain-keyed
    dict. Mirrors the reference oracle Rule (tests/test_adr07_decision_spec.py).

    Fields:
        kind            DNSBL_KIND_BLOCK (``||`` / hosts / plain / ``/re/``) or
                        DNSBL_KIND_ALLOW (``@@||`` / ``@@/re/``).
        target          RULE_TARGET_DOMAIN (``key_or_pattern`` is a domain literal;
                        ``wildcard`` says whether subdomains are covered) or
                        RULE_TARGET_REGEX (``key_or_pattern`` is the raw inner regex
                        pattern -- NOT compiled here; compile/load is a later phase).
        key_or_pattern  the validated, lower-cased domain (DOMAIN) or the raw regex
                        inner pattern (REGEX).
        wildcard        DOMAIN only: True -> domain + all subdomains (zone); False ->
                        exact (data). Ignored for REGEX.
        important       the rule carried ``$important`` (raises its feed band 1/2 ->
                        3/4). Always meaningless for, but recorded on, USER rules
                        (they are sovereign regardless).
        badfilter       the rule carried ``$badfilter`` (feed-only prune key; the
                        rule itself emits no decision -- reconcile() consumes it).
        provenance      RULE_PROV_USER (sovereign, $badfilter-immune, fact 7) or
                        RULE_PROV_FEED.
        feed/group/log  the per-feed manifest row metadata (attached by the caller;
                        ``parse_abp`` plumbs whatever it is given through unchanged).
        signature       the ``$badfilter`` match key:
                        ``(key_or_pattern, tuple(sorted DNS-options)) MINUS $badfilter``.
                        Two rules with the same signature are the same target+options
                        (a feed ``$badfilter`` prunes a feed rule with a matching
                        signature during reconcile()).
    """

    kind: str
    target: str
    key_or_pattern: str
    important: bool
    badfilter: bool
    provenance: str
    feed: str
    group: str
    log: str
    signature: tuple[str, tuple[str, ...]]
    wildcard: bool = False


@dataclass
class ParsedEntry:
    """One parsed feed line, pre-normalisation.

    ``kind`` is the ABP-ready tag; this phase only ever sets ``DNSBL_KIND_BLOCK``.
    ``value`` is the raw domain token extracted from the line (not yet validated /
    lower-cased). ``feed`` / ``group`` / ``log`` come from the per-feed manifest row.
    """

    kind: str
    value: str
    feed: str
    group: str
    log: str


@dataclass
class BuildResult:
    """The structure-set build() returns -- decision-equivalent to the loader
    contract. All dicts are FRESH (no module global is mutated), so the
    result is safe to atomically swap in later.

    Shapes (ADR-07 widened payloads). For a non-ABP (plain/hosts/csv) build every
    ``important`` is ``False`` and ``band`` is the feed-block band (1); the ABP path
    (format_hint='abp') sets ``important``/``band`` from the reconciled rule:
        data_db[domain]          = {"log": <"0"|"1"|"2">, "index": <int>, "important": bool, "band": int}
        zone_db[registrable]     = {"log": <flag>,        "index": <int>, "important": bool, "band": int}
        feed_group_index_db[idx] = {"feed": <str>, "group": <str>}
        white_db[domain]         = {"wildcard": bool, "important": bool, "band": int}
        regex_db[name]           = {"re": <compiled>, "important": bool, "band": int}   (ABP block-regex)
        allow_regex_db[name]     = {"re": <compiled>, "important": bool, "band": int}   (ABP @@/re/ allow-regex)
    ``important_rules`` is the build-emitted fast-path gate (ADR.md SS2): True iff any
    surviving rule needs the numeric 6-band branch (any $important / feed @@ / feed
    regex). ``counts`` is the LOADED total (len(data_db) + len(zone_db)); init emits
    it as pfb_py_count (its value legitimately rises -- lists are un-pruned).
    ``regex_count`` is the ADMITTED feed-regex total for the DNSBL_Regex alias (UI).
    ``rejects`` is the ADR-48 (issue #789) per-entry reject tally -- (feed, group)
    -> {'shape': n, 'wire_cap': m} -- for every domain target a normalise-fail (or
    the reconcile() wire-cap fold-drop) rejected; a diagnostic count, not consumed
    by any decision.
    """

    data_db: dict[str, dict[str, Any]]
    zone_db: dict[str, dict[str, Any]]
    feed_group_index_db: dict[int, dict[str, str]]
    white_db: dict[str, dict[str, Any]]
    counts: int
    regex_db: dict[str, dict[str, Any]] = field(default_factory=dict)
    allow_regex_db: dict[str, dict[str, Any]] = field(default_factory=dict)
    important_rules: bool = False
    regex_count: int = 0
    rejects: RejectTally = field(default_factory=dict)


# issue #1074: every built Snapshot gets a unique, monotonically-advancing generation
# so a decisionDB memo can be tied to the snapshot that produced it (id() is unusable:
# a freed old snapshot's id can be reused by the new one).
_snapshot_gen = itertools.count(1)


@dataclass(frozen=True)
class Snapshot:
    """ADR-10: the immutable bundle of every matcher stratum a DNS query reads.

    Today the matcher reads several independent module globals per query
    (``dataDB``/``zoneDB``/``whiteDB``/``regexDB`` + ADR-07's ``allowRegexDB`` and the
    ``important_rules`` flag, plus ``hstsDB`` and ``feedGroupIndexDB``), each assigned
    one-by-one at init. A background swap that reassigns them individually would let a
    mid-swap query read e.g. new ``dataDB`` + old ``whiteDB`` -- a torn, inconsistent
    decision. Bundling them here behind ONE module reference makes the future
    zero-downtime swap (ADR.md SS2 "Atomic swap shape") consistent-by-construction: a
    query captures the single ref once and reads every field off it, so it resolves
    entirely against one snapshot even if a swap lands mid-query. The swap itself is a
    single ``STORE_NAME`` (GIL-atomic); no lock is taken on the per-query hot path.

    Scope (deliberate): exactly the strata the per-query ``containers`` assembly feeds
    ``evaluate_domain`` (``operate()``), plus the ``important_rules`` fast-path gate and
    the build counts. The ``operate()``-level axes ``noAAAADB``/``safeSearchDB``/
    ``gpListDB`` are NOT here -- they are not read by ``evaluate_domain``/``containers``,
    are not produced by ``build()``/``dnsbl_build_from_manifest`` (loaded from static
    files), and ``gpListDB`` is MUTATED in place per query (a group-policy bypass cache),
    so it is not an immutable swap target. ``rcodeDB``/``maxmindReader`` shape the reply,
    not the block decision, and are likewise out.

    Immutability note (watch-out): the tuple of fields is frozen, but the
    contained dicts are ordinary dicts. ADR-07's runtime regex eviction still mutates
    ``regex_db`` in place (``_regex_evict_names`` in ``evaluate_domain``); a swap replaces
    the whole snapshot with a freshly-compiled set, so any evicted-pattern state is
    rebuilt from the manifest + the static cap (reconciled + documented in ADR.md SS2).

    The fields mirror the legacy ``containers`` keys + the ``cfg`` fast-path flag so the
    refactor is byte-for-byte decision-identical (pinned by the retained ADR-06/07
    oracles): ``data_db``->dataDB, ``zone_db``->zoneDB, ``white_db``->whiteDB,
    ``regex_db``->regexDB, ``allow_regex_db``->allowRegexDB,
    ``feed_group_index_db``->feedGroupIndexDB, ``hsts_db``->hstsDB.

    ``rejects`` (ADR-48, issue #789) rides alongside ``counts``/``regex_count`` as
    a build-diagnostic passthrough -- NOT a per-query stratum (absent from
    ``containers()``) -- so a no-restart swap can re-emit the reject-stats artifact
    from the fresh ``BuildResult`` exactly as it re-emits the UI counts.
    """

    data_db: dict[str, Any]
    zone_db: dict[str, Any]
    white_db: dict[str, Any]
    regex_db: dict[str, Any]
    allow_regex_db: dict[str, Any]
    feed_group_index_db: dict[int, Any]
    hsts_db: dict[str, Any]
    important_rules: bool = False
    counts: int = 0
    regex_count: int = 0
    rejects: RejectTally = field(default_factory=dict)
    # issue #1074: identity of this snapshot for decisionDB memo stamping; auto-assigned,
    # never passed by builders.
    gen: int = field(default_factory=lambda: next(_snapshot_gen))

    def containers(self) -> dict[str, Any]:
        """The per-query ``containers`` dict ``evaluate_domain`` reads (legacy keys).

        ``operate()`` captures the single live ``Snapshot`` once per query and calls
        this to feed ``evaluate_domain`` -- replacing the old per-query re-assembly from
        separate module globals (the torn-read hazard ADR-10 removes)."""
        return {
            "dataDB": self.data_db,
            "zoneDB": self.zone_db,
            "whiteDB": self.white_db,
            "regexDB": self.regex_db,
            "allowRegexDB": self.allow_regex_db,
            "feedGroupIndexDB": self.feed_group_index_db,
            "hstsDB": self.hsts_db,
        }


def _dnsbl_is_ipv4(token: str) -> bool:
    """Mirror is_ipaddrv4: dotted-quad, each octet 0-255, no leading zeros.

    Used only to RECOGNISE and SKIP bare-IP lines (the firewall path stays in PHP);
    Python never emits IPs.
    """
    parts = token.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        # issue #1071: int() runs only behind an ASCII-decimal test and a length cap —
        # str.isdigit() is True for non-decimal Unicode digits int() rejects, and a >4300
        # digit octet trips CPython's int-conversion limit; either ValueError aborts build().
        if not (p.isascii() and p.isdigit()) or len(p) > 3 or not (0 <= int(p) <= 255) or (len(p) > 1 and p[0] == "0"):
            return False
    return True


def _dnsbl_parse_abp_line(line: str) -> str | None:
    """Current basic-ABP token-strip (pfblockerng.inc:7706-7717).

    Keep ONLY a plain ``||domain^`` network line and strip the ``||`` / ``^`` tokens
    to a bare domain. IGNORE everything else exactly as today: ``@@`` exceptions,
    ``##`` / ``#@#`` element-hiding, ``$options``, ``*`` and ``/`` (path / regex).
    Returns the bare domain or ``None``. (The future ABP ADR replaces this.)
    """
    if not line.startswith("||") or not line.endswith("^"):
        return None
    if "$" in line or "*" in line or "/" in line:
        return None
    return line[2:-1]


# --------------------------------------------------------------------------- #
# ADR-07 Stage-A: DNS-only ABP option / scope classification. A ``$options``
# tail is KEPT only if EVERY option is DNS-relevant ($important / $badfilter).
# Any page-context option ($third-party / $domain= / $script / $image / $csp
# / ...), any non-DNS AdGuard modifier that only rewrites ($dnsrewrite /
# $dnstype / $client / $ctag), or any UNRECOGNISED option puts the whole rule
# out of DNS scope -> skipped (parse_abp returns None).
# --------------------------------------------------------------------------- #
# Options that DO modify a DNS block/allow decision (kept):
_DNSBL_DNS_RELEVANT_OPTS = frozenset({"important", "badfilter"})
# Options that imply a page/element context, never a DNS decision (-> SKIP rule):
_DNSBL_PAGE_CONTEXT_OPTS = frozenset(
    {
        "third-party",
        "~third-party",
        "domain",  # $domain=...
        "script",
        "image",
        "stylesheet",
        "object",
        "subdocument",
        "document",
        "xmlhttprequest",
        "websocket",
        "ping",
        "media",
        "font",
        "popup",
        "csp",
        "elemhide",
        "generichide",
        "genericblock",
        "rewrite",  # $rewrite= (response rewriting, not a DNS decision)
    }
)
# AdGuard DNS modifiers whose ONLY effect is a rewrite, not block/allow (-> SKIP):
_DNSBL_NON_DNS_MODIFIERS = frozenset({"dnsrewrite", "dnstype", "client", "ctag"})


def _dnsbl_opt_name(opt: str) -> str:
    """Bare option name: drop a ``=value`` tail and a leading ``~`` is preserved
    only via the explicit ``~third-party`` membership (we never KEEP a ``~`` opt)."""
    return opt.split("=", 1)[0].strip()


def _dnsbl_classify_options(opts_str: str) -> tuple[tuple[str, ...], bool, bool] | None:
    """Parse the ``$...`` suffix. Return ``(sorted_dns_opts, important, badfilter)``
    if EVERY option is DNS-relevant, else ``None`` (skip the rule).

    ``sorted_dns_opts`` is the sorted tuple of DNS-relevant option NAMES that are
    NOT ``$badfilter`` (i.e. ``("important",)`` or ``()``) -- it feeds the rule's
    $badfilter signature. A page-context option, a non-DNS modifier, or
    an unrecognised option returns None (conservative: never invent a DNS decision
    for a modifier we do not model).
    """
    important = False
    badfilter = False
    kept: list[str] = []
    for raw in opts_str.split(","):
        raw = raw.strip()
        if not raw:
            continue
        name = _dnsbl_opt_name(raw)
        if name in _DNSBL_PAGE_CONTEXT_OPTS or name in _DNSBL_NON_DNS_MODIFIERS:
            return None
        if name == "important":
            important = True
            kept.append(name)
            continue
        if name == "badfilter":
            badfilter = True
            continue  # excluded from the signature by design
        # An unrecognised option -> out of DNS scope (skip the whole rule).
        return None
    return tuple(sorted(kept)), important, badfilter


# Element-hiding / cosmetic marker family (ADR §2 Decision 2) -- shared by
# parse_abp()'s skip check and _dnsbl_is_abp_rule_line()'s capture guard so the
# two never drift apart.
_DNSBL_ELEMENT_HIDING_MARKERS = ("##", "#@#", "#?#", "#%#", "#$#")


def _dnsbl_parse_abp_regex(stripped: str) -> tuple[str, str, str] | None:
    """Recognise a regex rule. Return ``(kind, inner, opts_str)`` for ``/re/`` (block)
    or ``@@/re/`` (allow), with an OPTIONAL ``$options`` suffix after the closing
    slash (``/re/$important``, ``@@/re/$badfilter``); else ``None``. ``inner`` is the
    raw pattern between the slashes (NOT compiled here -- reduction happens in
    reconcile(), compile/load in _dnsbl_compile_regex_rules()); ``opts_str`` is
    the ``$``-suffix (without the ``$``) or "" when absent. The closing slash
    is the last ``/`` of the rule (no options) or
    the ``/`` immediately preceding ``$`` (options) -- so a ``/`` inside the pattern
    body does not end it."""
    if stripped.startswith("@@/"):
        kind, body = DNSBL_KIND_ALLOW, stripped[2:]
    elif stripped.startswith("/"):
        kind, body = DNSBL_KIND_BLOCK, stripped
    else:
        return None
    # body now starts with the opening "/". A regex rule is "/<inner>/" optionally
    # followed by "$<options>". Find the closing slash + options tail.
    if body.endswith("/"):
        inner, opts_str = body[1:-1], ""
    else:
        # options present: the closing slash is the one directly before "/$".
        marker = body.rfind("/$")
        if marker <= 0:
            return None
        inner, opts_str = body[1:marker], body[marker + 2 :]
    if not inner:
        return None
    return kind, inner, opts_str


def _dnsbl_is_abp_rule_line(line: str) -> bool:
    """Capture guard: should ``build()`` route ``line`` to ``parse_abp()``?

    Mirrors PHP's ``pfb_dnsbl_is_abp_rule_line()`` (pfblockerng.inc, ADR-62)
    row for row -- ``||``/``@@`` anchors, the element-hiding marker family,
    and the ``/regex/`` closing-slash shape (mirroring, not calling,
    ``_dnsbl_parse_abp_regex``: PHP's own predicate is a structural
    length/marker check, not a full parse -- e.g. bare ``//`` capture=True
    even though ``_dnsbl_parse_abp_regex('//')`` is None, matching PHP's own
    capture-vs-accept split). NOT a parser: a captured line can still make
    ``parse_abp()`` return ``None`` (e.g. bare ``@@``/``||`` -- structural
    capture, not final accept). A bare domain line is deliberately FALSE
    (ADR-62 delta D1).
    """
    if line.startswith("||") or line.startswith("@@"):
        return True
    if any(marker in line for marker in _DNSBL_ELEMENT_HIDING_MARKERS):
        return True
    if line.startswith("/"):
        if line.endswith("/") and len(line) > 1:
            return True
        marker = line.rfind("/$")
        return marker != -1 and marker > 0
    return False


def parse_abp(
    line: str,
    *,
    provenance: str = RULE_PROV_FEED,
    feed: str = "",
    group: str = "",
    log: str = "",
    tally: RejectTally | None = None,
) -> Rule | None:
    """The full DNS-only ABP Stage-A parser: one raw ABP line -> a typed ``Rule``
    (or ``None`` to skip). PURE -- no Unbound symbol, no side effect. Agrees with
    the reference oracle (tests/test_adr07_decision_spec.py::parse_abp_line) on
    every corpus line.

    KEEP (-> Rule):
        ``||domain^`` (+DNS-options)                 block, domain, wildcard
        ``@@||domain^`` (+DNS-options)               allow, domain, wildcard
        ``<ip> domain`` (hosts)                      block, domain, wildcard
        plain bare ``domain``                        block, domain, wildcard
        ``/re/`` (block) / ``@@/re/`` (allow)        block/allow, regex (raw inner)
    SKIP (-> None):
        comment / control (``!`` / ``[``), plain ``#`` lines, element-hiding
        (``##`` / ``#@#`` / ``#?#`` / ``#%#`` / ``#$#``), path/URL rules (``/`` or
        ``*`` in the anchor), page-context / non-DNS / unrecognised ``$options``,
        and IP-VALUED anchors (``||1.2.3.4^``, hosts ``<ip> <ip>``) -- those are the
        PHP firewall path (no-leak contract, ADR-06 fact 7).

    ``feed`` / ``group`` / ``log`` / ``provenance`` are plumbed through unchanged
    (the caller supplies them from the manifest row). Domain targets pass through
    ``normalise()`` (lower-case + shape gate); an invalid domain -> ``None``.

    ``tally`` (ADR-48, issue #789): optional out-param -- when not ``None``,
    a normalise-fail reject on a domain target (anchor/hosts/bare) is counted into
    it (bucket 'shape' | 'wire_cap', keyed (feed, group)). Left ``None`` (the
    default), this function is BYTE-IDENTICAL to before -- purity is test-pinned.
    """
    s = line.strip()
    if not s:
        return None
    # comment / control headers
    if s.startswith("!") or s.startswith("["):
        return None
    if s.startswith("#"):
        # a plain-feed ``#`` comment (element-hiding needs a ``##`` token, caught next)
        return None
    # element-hiding / cosmetic (``##`` / ``#@#`` / ``#?#`` / ``#%#`` / ``#$#``) -> SKIP
    if any(marker in s for marker in _DNSBL_ELEMENT_HIDING_MARKERS):
        return None

    # ---- regex rules: /re/ (block) or @@/re/ (allow) --------------------- #
    regex_hit = _dnsbl_parse_abp_regex(s)
    if regex_hit is not None:
        kind, inner, opts_str = regex_hit
        if opts_str:
            classified = _dnsbl_classify_options(opts_str)
            if classified is None:
                return None  # page-context / non-DNS / unrecognised -> skip whole rule
            dns_opts, important, badfilter = classified
        else:
            dns_opts, important, badfilter = (), False, False
        return Rule(
            kind=kind,
            target=RULE_TARGET_REGEX,
            key_or_pattern=inner,
            important=important,
            badfilter=badfilter,
            provenance=provenance,
            feed=feed,
            group=group,
            log=log,
            signature=(inner, dns_opts),
            wildcard=False,
        )

    # ---- network rules: @@||domain^ (allow) / ||domain^ (block) ---------- #
    is_allow = s.startswith("@@||")
    is_block = s.startswith("||")
    if is_allow or is_block:
        rest = s[4:] if is_allow else s[2:]
        anchor, _, opts_str = rest.partition("$")
        # split the anchor at the ABP separator ``^``; reject any path token
        host = anchor.split("^", 1)[0]
        tail = anchor.split("^", 1)[1] if "^" in anchor else ""
        if "/" in host or "*" in host or "/" in tail or tail.strip("^"):
            return None
        if _dnsbl_is_ipv4(host):
            return None  # IP-anchored -> PHP firewall path; Python skips (no leak)
        dom, bucket = _normalise_verdict(host)
        if dom is None:
            if tally is not None and bucket is not None:
                _tally_reject(tally, feed, group, bucket)
            return None
        if opts_str:
            classified = _dnsbl_classify_options(opts_str)
            if classified is None:
                return None
            dns_opts, important, badfilter = classified
        else:
            dns_opts, important, badfilter = (), False, False
        return Rule(
            kind=DNSBL_KIND_ALLOW if is_allow else DNSBL_KIND_BLOCK,
            target=RULE_TARGET_DOMAIN,
            key_or_pattern=dom,
            important=important,
            badfilter=badfilter,
            provenance=provenance,
            feed=feed,
            group=group,
            log=log,
            signature=(dom, dns_opts),
            wildcard=True,  # ||domain^ / @@||domain^ cover the domain + subdomains
        )

    # ---- hosts: "<ip> <domain>" ----------------------------------------- #
    # Split on ANY whitespace (space OR tab): tab-delimited hosts lines are valid and
    # must not fall through to the bare-domain path and get dropped. ABP network/regex
    # rules are handled above, so a 2-token line here is a hosts line or junk.
    parts = s.split(None, 1)
    if len(parts) == 2:
        first, target = parts[0], parts[1].strip()
        if not _dnsbl_is_ipv4(first):
            return None  # not a hosts line (a real ABP line never has a bare space)
        if _dnsbl_is_ipv4(target):
            return None  # "<ip> <ip>" -> firewall path
        dom, bucket = _normalise_verdict(target)
        if dom is None:
            if tally is not None and bucket is not None:
                _tally_reject(tally, feed, group, bucket)
            return None
        return Rule(
            kind=DNSBL_KIND_BLOCK,
            target=RULE_TARGET_DOMAIN,
            key_or_pattern=dom,
            important=False,
            badfilter=False,
            provenance=provenance,
            feed=feed,
            group=group,
            log=log,
            signature=(dom, ()),
            wildcard=True,  # plain/hosts cover the domain + subdomains (reference oracle)
        )

    # ---- bare plain domain ---------------------------------------------- #
    if "/" in s or "*" in s:
        return None
    dom, bucket = _normalise_verdict(s)
    if dom is None:
        if tally is not None and bucket is not None:
            _tally_reject(tally, feed, group, bucket)
        return None
    return Rule(
        kind=DNSBL_KIND_BLOCK,
        target=RULE_TARGET_DOMAIN,
        key_or_pattern=dom,
        important=False,
        badfilter=False,
        provenance=provenance,
        feed=feed,
        group=group,
        log=log,
        signature=(dom, ()),
        wildcard=True,
    )


def _dnsbl_strip_hosts_prefix(line: str) -> str:
    """Hosts format: ``<sink-ip> <domain>`` -> take the domain token (inc:7899-7907).

    Handles ``0.0.0.0 domain`` and ``127.0.0.1 domain``; a non-IP first token keeps
    the chars before the space (PHP's behaviour).
    """
    if " " in line:
        first, _, rest = line.partition(" ")
        rest = rest.strip()
        if _dnsbl_is_ipv4(first):
            return rest
        return first
    return line


def parse(format_hint: str, line: str) -> ParsedEntry | None:
    """Parse one raw feed line into a kind-tagged block entry, or ``None`` to skip.

    ``format_hint`` dispatches the per-format handler (the manifest replaces the old
    in-loop CSV-type sniffing). This subsumes the current basic-ABP token-strip and
    reproduces today's per-format behaviour, including which lines are IGNORED.

    Bare-IP lines and the csv:pon col-0 IP are NOT returned here -- IP extraction is
    a PHP/firewall concern; a stray bare IP simply yields ``None`` (and
    would fail domain validation anyway). ``feed`` / ``group`` / ``log`` are attached
    by build() from the manifest row, so parse() only resolves the domain token.

    NOTE: the ABP-ready ``kind`` field is always ``DNSBL_KIND_BLOCK`` in this phase;
    ``@@`` / regex / element / ``$options`` lines are dropped, not emitted as allow /
    regex kinds (that is the future ABP ADR).
    """
    stripped = line.strip()
    if not stripped:
        return None

    if format_hint == "abp":
        # ABP control / comment lines (header, '!', '[') are dropped first.
        if stripped.startswith("!") or stripped.startswith("["):
            return None
        host = _dnsbl_parse_abp_line(stripped)
        if host is None:
            return None
        return ParsedEntry(kind=DNSBL_KIND_BLOCK, value=host, feed="", group="", log="")

    if format_hint == "csv:pon":
        # 9-col CSV: domain = col2 (always kept). col0 is handled by the PHP DNSBL-IP
        # pass; Python ignores it here.
        if stripped.startswith("!") or stripped.lower().startswith("timestamp"):
            return None
        try:
            row = next(csv.reader([stripped]))
        except (csv.Error, StopIteration):
            return None
        if len(row) != 9:
            return None
        domain = row[2]
        if not domain:
            return None
        return ParsedEntry(kind=DNSBL_KIND_BLOCK, value=domain, feed="", group="", log="")

    # hosts / plain
    if stripped.startswith("#") or stripped.startswith("!"):
        return None
    token = _dnsbl_strip_hosts_prefix(stripped)
    token = token.strip().strip(".")
    if not token:
        return None
    # Bare IP -> firewall path (PHP); skipped from the domain build.
    if _dnsbl_is_ipv4(token):
        return None
    return ParsedEntry(kind=DNSBL_KIND_BLOCK, value=token, feed="", group="", log="")


# ADR-48 (issue #789): the per-entry reject tally build()/parse_abp()/
# reconcile() accumulate into, keyed (feed, group) -> {'shape': n, 'wire_cap': m}.
# A plain dict (no class): the shape never grows past the two RESOLVED buckets
# (ADR §2 item 4), so a helper that does the defaulting is all this needs.
RejectTally = dict[tuple[str, str], dict[str, int]]


def _tally_reject(tally: RejectTally, feed: str, group: str, bucket: str) -> None:
    """Increment ``bucket`` ('shape' | 'wire_cap') for (feed, group) in ``tally``,
    defaulting a fresh {'shape': 0, 'wire_cap': 0} row on first hit."""
    counts = tally.setdefault((feed, group), {"shape": 0, "wire_cap": 0})
    counts[bucket] += 1


def _dnsbl_within_wire_caps(host: str) -> bool:
    """True iff ``host`` can be encoded in a DNS query (#753): <= 253 chars total
    (the RFC 1035 presentation cap, undotted) and every label <= 63. The domain
    charset is ASCII-only, so chars == octets. Shared by ``normalise()`` and the
    ``reconcile()`` regex fold so the caps live in one place."""
    return len(host) <= 253 and all(len(label) <= 63 for label in host.split("."))


def _normalise_verdict(value: str) -> tuple[str | None, str | None]:
    """The classified body of ``normalise()``: returns ``(domain, None)`` on
    accept, or ``(None, bucket)`` on reject where ``bucket`` is ``'shape'`` (no
    dot / edge hyphen / empty label / bad char -- a domain-SHAPE defect) or
    ``'wire_cap'`` (the #753 length caps -- a well-shaped but unqueryable name).
    Split out of ``normalise()`` so callers that need the #789 reject tally
    (``build()`` / ``parse_abp()`` / ``reconcile()``) can bucket it; ``normalise()``
    itself stays a pure ``str | None`` wrapper (public contract unchanged).
    """
    host = value.strip().strip(".").lower()
    if "." not in host:
        return None, "shape"
    if not _dnsbl_within_wire_caps(host):
        return None, "wire_cap"
    for label in host.split("."):
        if not label or label[0] == "-" or label[-1] == "-":
            return None, "shape"
        if any(c not in _DNSBL_LABEL_CHARS for c in label):
            return None, "shape"
    return host, None


def normalise(value: str) -> str | None:
    """Lower-case + PFB_FILTER_DOMAIN domain-shape gate (inc:1138-1150).

    Returns the validated, lower-cased domain or ``None`` when the token is not a
    valid domain (which is how stray non-domain entries -- including any IP that
    slipped past parse() -- are dropped without ever reaching the dicts).

    Length caps mirror the PHP gate at the queryable bound (#753): every label
    <= 63 chars, whole name <= 253 chars (``_dnsbl_within_wire_caps``; the RFC
    1035 presentation cap, applied after the trailing dot is stripped -- the
    same names PHP's ``strlen < 255`` accepts in dotted form, #752). PHP also
    tolerates a bare 254-char undotted name (an inert sanity-cap artefact,
    pinned by #752); this gate rejects it as unqueryable. Every entry gated
    here becomes an exact or wildcard match key, and a name that cannot be
    encoded in a DNS query could never match a lookup -- rejecting it keeps
    unreachable dead weight out of the block dicts. The ``reconcile()`` regex
    fold applies the same caps to a domain-literal regex key.

    Thin wrapper over ``_normalise_verdict()`` -- see there for the reject-bucket
    classification (ADR-48, issue #789).
    """
    domain, _ = _normalise_verdict(value)
    return domain


def _dnsbl_load_tld_master(
    suffix_lines: Iterable[str],
    tld_blacklist: Iterable[str],
    tld_exclusion: Iterable[str],
) -> dict[str, dict[str, str]]:
    """Build the public-suffix oracle tlds[tld][full-suffix] (tld_analysis:2630-2642),
    minus any blacklisted or excluded TLD (inc:2749-2751 / 2791-2793)."""
    blacklist = {t.strip(".") for t in tld_blacklist}
    exclusion_keys = {e.strip(".") for e in tld_exclusion}
    tlds: dict[str, dict[str, str]] = {}
    for line in suffix_lines:
        suffix = line.strip()
        if not suffix or suffix.startswith("#"):
            continue
        tld = suffix.rsplit(".", 1)[-1]
        if tld in blacklist or tld in exclusion_keys:
            continue
        tlds.setdefault(tld, {})[suffix] = ""
    return tlds


def _dnsbl_tld_search(tlds: dict[str, dict[str, str]], tld: str, dparts: list[str], j: int, k: int) -> str | None:
    """tld_search (inc:2595-2603): if the j-label suffix is a known public suffix,
    the registrable parent is the k-label slice."""
    tld_query = ".".join(dparts[-j:])
    if tld_query in tlds.get(tld, {}):
        return ".".join(dparts[-k:])
    return None


def classify(domain: str, tlds: dict[str, dict[str, str]], exclusion: set[str]) -> tuple[str, str]:
    """Return ``(DNSBL_CLASS_ZONE, registrable-parent)`` or ``(DNSBL_CLASS_DATA, domain)``.

    Mirrors tld_analysis:2832-2874 exactly: a registrable parent -> wildcard ZONE; a
    deeper sub-domain whose parent is not a known public suffix -> exact DATA; a
    whole-domain TLD exclusion forces exact DATA (transparent, not wildcarded).
    """
    dparts = domain.split(".")
    dcnt = len(dparts)
    tld = dparts[-1]
    dfound = ""

    if dcnt > 5:
        dfound = ""
    elif dcnt == 5:
        dfound = _dnsbl_tld_search(tlds, tld, dparts, 4, 5) or ""
    elif dcnt == 4:
        dfound = _dnsbl_tld_search(tlds, tld, dparts, 3, 4) or ""
    elif dcnt == 3:
        dfound = _dnsbl_tld_search(tlds, tld, dparts, 2, 3) or ""
    elif dcnt == 2:
        dfound = ".".join(dparts[-2:])

    # TLD exclusion: whole domain in the exclusion set -> force exact DATA.
    if domain in exclusion:
        dfound = ""

    if dfound:
        return DNSBL_CLASS_ZONE, dfound
    return DNSBL_CLASS_DATA, domain


# --------------------------------------------------------------------------- #
# ADR-07 Stage-B reconcile: $badfilter prune + regex reduction + classify +
# priority bands. PURE / reentrant -- consumes the typed ``Rule`` stream from
# Stage-A (parse_abp) into the pre-emit rule sets build() folds in; NEVER
# compiles/executes a regex itself. Reference oracle:
# tests/test_adr07_decision_spec.py (reduce_regex/reconcile/priority/decide),
# benchmarks/spike_adr07_regex.reduce_pattern; ADR.md SS2.
# --------------------------------------------------------------------------- #

# Regex-reduction grammar (mirrors the reference oracle reduce_regex + the spike
# reduce_pattern). A reducible ``/re/`` decides IDENTICALLY to a domain/wildcard
# rule, so it folds to a domain Rule at zero per-query cost. ``D`` is a domain
# literal: labels of [a-z0-9-] joined by ESCAPED dots (``\.``), no other metachar.
_DNSBL_RX_DOMAIN_LITERAL = re.compile(r"^[a-z0-9_-]+(?:\\\.[a-z0-9_-]+)+$")  # underscore per #723
# Prefixes that mean "domain + all subdomains" (-> wildcard zone after fold):
_DNSBL_RX_WILDCARD_PREFIXES = (r"^(.+\.)?", r"(^|\.)", r"^(?:.+\.)?")
# Prefix that means "exact domain only" (-> exact data after fold):
_DNSBL_RX_EXACT_PREFIXES = (r"^",)
# A leading ``(www\.)?`` after ``^`` is exact-with-optional-www -> still exact.
_DNSBL_RX_WWW_OPT = r"(www\.)?"


def _dnsbl_reduce_regex(inner: str) -> tuple[bool, str] | None:
    """Return ``(wildcard, domain)`` if a regex inner pattern folds to a
    domain/wildcard rule, else ``None`` (irreducible -- stays a compiled pattern).

    ``wildcard`` True -> domain + subdomains (zone); False -> exact (data). Mirrors
    the reference oracle ``reduce_regex`` + ``spike.reduce_pattern`` exactly (so a
    reducible feed regex == its dict form). Pure; does NOT compile the pattern.
    Per ADR.md SS2 we do NOT expand finite classes (``ad[0-9]\\.x`` stays a regex).
    """
    if not inner.endswith("$"):
        return None
    body = inner[:-1]
    for pre in _DNSBL_RX_WILDCARD_PREFIXES:
        if body.startswith(pre):
            lit = body[len(pre) :]
            if _DNSBL_RX_DOMAIN_LITERAL.match(lit):
                return True, lit.replace("\\.", ".")
            return None
    for pre in _DNSBL_RX_EXACT_PREFIXES:
        if body.startswith(pre):
            lit = body[len(pre) :]
            if lit.startswith(_DNSBL_RX_WWW_OPT):
                lit = lit[len(_DNSBL_RX_WWW_OPT) :]
            if _DNSBL_RX_DOMAIN_LITERAL.match(lit):
                return False, lit.replace("\\.", ".")
            return None
    return None


def _dnsbl_rule_band(rule: Rule) -> int:
    """The numeric priority band (1-6) for a surviving rule (ADR.md SS2 / the
    PRIO_* constants). USER -> band 5/6 (sovereign); FEED -> 1/2, +$important ->
    3/4. ``important`` is meaningless for USER rules (they are always sovereign)."""
    user = rule.provenance == RULE_PROV_USER
    if rule.kind == DNSBL_KIND_ALLOW:
        return _allow_priority(rule.important, user=user)
    return _block_priority(rule.important, user=user)


@dataclass(frozen=True)
class BlockDomainRule:
    """A reconciled domain BLOCK ready to emit into dataDB/zoneDB.

    ``cls`` is DNSBL_CLASS_DATA (exact) or DNSBL_CLASS_ZONE (wildcard); ``key`` is
    the anchor domain itself for a ZONE (ABP ``||host^`` covers subdomains at any
    depth -- no registrable-parent reduction, #718) or the exact domain for DATA
    (an exact fold, or a TLD-exclusion carve-out).
    """

    cls: str
    key: str
    band: int
    important: bool
    provenance: str
    feed: str
    group: str
    log: str


@dataclass(frozen=True)
class AllowDomainRule:
    """A reconciled domain ALLOW ready to emit into whiteDB.

    ``wildcard`` True -> domain + subdomains; False -> exact. ``important`` raises a
    feed allow's band to 4 (and is always effectively sovereign for USER rules)."""

    domain: str
    wildcard: bool
    band: int
    important: bool
    provenance: str


@dataclass(frozen=True)
class RegexRule:
    """A reconciled IRREDUCIBLE regex (block or allow), raw ``pattern`` NOT
    compiled here -- Stage B never executes a regex; ``_dnsbl_compile_regex_rules()``
    compiles it.

    ``kind`` is DNSBL_KIND_BLOCK or DNSBL_KIND_ALLOW. ``band`` is the priority band;
    ``important`` is carried for the 6-band resolution."""

    pattern: str
    kind: str
    band: int
    important: bool
    provenance: str
    feed: str
    group: str
    log: str


@dataclass
class ReconcileResult:
    """The Stage-B pre-emit rule sets (pure return value -- no global is touched).

    build() folds these into the matcher dicts + compiles the irreducible regex:
        block_domains            -> dataDB/zoneDB (+band/important/feed/group/log)
        allow_domains            -> whiteDB ({wildcard, important} + band)
        block_regex_irreducible  -> regexDB     (compiled by _dnsbl_compile_regex_rules())
        allow_regex_irreducible  -> allowRegexDB (compiled by _dnsbl_compile_regex_rules())
    ``important_rules`` is the build-emitted fast-path flag (ADR.md SS2 "Query-time
    matcher"): True iff ANY surviving rule would engage the numeric 6-band branch
    (any $important, any feed allow/@@ or feed regex). False keeps today's matcher.
    ``pruned`` / ``reduced`` / ``skipped_badfilter`` are diagnostic counts."""

    block_domains: list[BlockDomainRule] = field(default_factory=list)
    allow_domains: list[AllowDomainRule] = field(default_factory=list)
    block_regex_irreducible: list[RegexRule] = field(default_factory=list)
    allow_regex_irreducible: list[RegexRule] = field(default_factory=list)
    important_rules: bool = False
    pruned: int = 0
    reduced: int = 0
    skipped_badfilter: int = 0


def reconcile(
    rules: Iterable[Rule],
    tlds: dict[str, dict[str, str]],
    exclusion: set[str],
    tally: RejectTally | None = None,
) -> ReconcileResult:
    """Stage-B: reconcile the typed ``Rule`` stream into the pre-emit rule sets.

    PURE + REENTRANT: builds and returns a FRESH ``ReconcileResult``, mutates no
    argument and no module global, never compiles/executes a regex -- two calls on
    equal inputs yield equal results. Steps (ADR.md SS2):

      1. $BADFILTER PRUNE (feed-only): collect the signatures of FEED rules carrying
         ``$badfilter``; drop every FEED rule with a matching signature; the
         ``$badfilter`` rules themselves emit nothing. USER rules are IMMUNE (never
         collected, never pruned -- sovereignty, fact 7).
      2. REGEX REDUCTION: a reducible regex Rule folds to a domain rule (block ->
         data/zone by its wildcard bit, allow -> whiteDB wildcard); irreducible
         regex passes through into the irreducible set (compiled by build()).
      3. DATA vs ZONE: a wildcard block (``||host^`` / wildcard fold) emits a ZONE
         keyed at the anchor itself -- ABP subdomain coverage at ANY depth (#718);
         a TLD-exclusion domain still forces exact DATA; an exact fold stays DATA.
      4. ASSIGN priority BANDS to every surviving rule (``_dnsbl_rule_band``).

    ``exclusion`` is the TLD-exclusion set (same shape build() uses). ``tlds`` is
    kept for signature stability but no longer consulted: classify's registrable-
    parent rule is a plain/hosts-path concept (ADR-06) that must not demote an ABP
    anchor. Matches the reference oracle ``reconcile`` + ``decide`` precedence.

    ``tally`` (ADR-48, issue #789): optional out-param -- when not ``None``,
    the #753 wire-cap fold-drop (a reducible regex whose folded key is unqueryable)
    is counted into it as 'wire_cap', attributed to the ORIGINATING rule's own
    feed/group (each survivor is reconciled one rule at a time, before any
    same-key merge, so there is no multi-feed key to disambiguate).
    """
    rule_list = list(rules)

    # --- Step 1: feed-only $badfilter prune ------------------------------- #
    bad_sigs = {r.signature for r in rule_list if r.badfilter and r.provenance == RULE_PROV_FEED}
    result = ReconcileResult()
    survivors: list[Rule] = []
    for r in rule_list:
        if r.badfilter:
            result.skipped_badfilter += 1
            continue  # the $badfilter rule itself never emits a decision
        if r.provenance == RULE_PROV_FEED and r.signature in bad_sigs:
            result.pruned += 1
            continue  # pruned by a feed $badfilter (USER rules are never here)
        survivors.append(r)

    # --- Steps 2-4: reduce, classify, band -------------------------------- #
    for r in survivors:
        # A surviving rule engages the numeric 6-band branch (vs today's fast path)
        # whenever it is $important, or a feed ALLOW (@@), or a feed regex -- i.e.
        # anything beyond a band-1 feed block / a user rule the fast path handles.
        if r.important or (r.provenance == RULE_PROV_FEED and r.kind == DNSBL_KIND_ALLOW):
            result.important_rules = True

        if r.target == RULE_TARGET_REGEX:
            reduced = _dnsbl_reduce_regex(r.key_or_pattern)
            if reduced is None:
                # Irreducible -> hand the RAW pattern through as a compile candidate.
                if r.provenance == RULE_PROV_FEED:
                    result.important_rules = True  # any feed regex engages numeric path
                regex_rule = RegexRule(
                    pattern=r.key_or_pattern,
                    kind=r.kind,
                    band=_dnsbl_rule_band(r),
                    important=r.important,
                    provenance=r.provenance,
                    feed=r.feed,
                    group=r.group,
                    log=r.log,
                )
                if r.kind == DNSBL_KIND_ALLOW:
                    result.allow_regex_irreducible.append(regex_rule)
                else:
                    result.block_regex_irreducible.append(regex_rule)
                continue
            # Reducible -> fold to a domain rule (zero per-query cost).
            wildcard, domain = reduced
            # #753: the folded literal is an exact/wildcard match KEY -- apply
            # the same wire caps normalise() applies to its ||host^ twin. An
            # over-cap key can never match a queryable qname, so drop the rule
            # outright (keeping it as a compiled regex would pay per-query cost
            # for a pattern that can never match).
            if not _dnsbl_within_wire_caps(domain):
                if tally is not None:
                    _tally_reject(tally, r.feed, r.group, "wire_cap")
                continue
            result.reduced += 1
        elif r.target == RULE_TARGET_DOMAIN:
            wildcard, domain = r.wildcard, r.key_or_pattern
        else:  # pragma: no cover - defensive; parse_abp only emits domain/regex
            continue

        band = _dnsbl_rule_band(r)
        if r.kind == DNSBL_KIND_ALLOW:
            result.allow_domains.append(
                AllowDomainRule(
                    domain=domain,
                    wildcard=wildcard,
                    band=band,
                    important=r.important,
                    provenance=r.provenance,
                )
            )
        else:
            # BLOCK domain -> data vs zone. ABP wildcard semantics come from the
            # rule itself: ``||host^`` (and a wildcard-shaped regex fold) covers
            # host + ALL subdomains, so it emits a ZONE keyed at the anchor at any
            # depth (#718) -- classify's registrable-parent rule is a plain/hosts
            # path concept and must not demote an ABP anchor. TLD exclusion still
            # opts a domain out of wildcarding (transparent exact DATA), and a
            # wildcard=False fold (exact /^D$/) stays forced to DATA.
            if wildcard and domain not in exclusion:
                cls, key = DNSBL_CLASS_ZONE, domain
            else:
                cls, key = DNSBL_CLASS_DATA, domain
            result.block_domains.append(
                BlockDomainRule(
                    cls=cls,
                    key=key,
                    band=band,
                    important=r.important,
                    provenance=r.provenance,
                    feed=r.feed,
                    group=r.group,
                    log=r.log,
                )
            )
        # NOTE: a user rule alone does NOT force ``important_rules`` -- today's fast
        # path already handles a pure user whitelist (important whiteDB) + user
        # blocks. The flag is about the feed $important/@@/regex the fast
        # path cannot resolve; once that is set, the numeric branch sees the user
        # bands (5/6) too.

    return result


def _dnsbl_normalise_whitelist(
    user_whitelist: Iterable[str],
    top1m_list: Iterable[str],
    top1m_enabled: bool,
) -> dict[str, dict[str, Any]]:
    """User-whitelist normalisation (pfb_unbound_python_whitelist, inc:2259) into the
    query-time whiteDB shape: www-strip; leading-dot -> wildcard True else False.
    TOP1M entries are loaded ONLY when enabled (bare domains -> exact). No build-time
    list pruning -- this only populates whiteDB.

    ADR-07: the whiteDB value widens from a bare ``bool`` (wildcard?) to
    ``{"wildcard": bool, "important": bool}``. User whitelist + TOP1M load as
    ``important=True`` (user-intent sovereignty, ADR.md SS2 / fact 7). Because an
    allow already beats every block today, this changes NO decision now -- the
    ``important`` flag is only consulted by the (currently unreachable) numeric
    6-band branch of ``evaluate_domain``.
    """
    white_db: dict[str, dict[str, Any]] = {}
    for raw in user_whitelist:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("www."):
            line = line[4:]
        if line.startswith("."):
            white_db[line.lstrip(".")] = {"wildcard": True, "important": True, "band": PRIO_USER_ALLOW}
        else:
            white_db[line] = {"wildcard": False, "important": True, "band": PRIO_USER_ALLOW}

    if top1m_enabled:
        for raw in top1m_list:
            dom = raw.strip()
            if dom:
                # TOP1M behaves as a user allow (sovereign, band 6) -- fact 7.
                white_db.setdefault(dom, {"wildcard": False, "important": True, "band": PRIO_USER_ALLOW})

    return white_db


# ============================================================================ #
# ADR-07: regex safety (opt-in static cap + always-on runtime warn/evict)      #
# ============================================================================ #
# `re` does not release the GIL during a match and a Python thread cannot be
# killed, so a query-time timeout CANNOT interrupt a catastrophic match. Bounded
# residual instead: a pathological pattern's FIRST match may block one query,
# then it is EVICTED so it cannot hang again. (1) opt-in static cap drops
# over-long/nested-quantifier patterns at LOAD; (2) always-on runtime timing
# evicts a pattern from the live regexDB/allowRegexDB over an EVICT ceiling
# (snapshot-iterate, evict-after-loop; dict.pop is atomic under the GIL).

# Length ceiling (heuristic): a pattern over this many characters is dropped
# at load ONLY when the opt-in "Limit long/complex regex" setting is enabled.
# Length alone is a tunable convenience cap, NOT a safety gate -- a long
# pattern is not inherently pathological -- so it stays behind the flag.
REGEX_STATIC_LEN_CAP = 200

# A quantified group that itself sits inside a quantifier: (a+)+, (a*)*, (\w+\.)+,
# ([a-z]+)*, (.*a){20}. Measured to catch 1/1 catastrophic patterns in
# the corpus with no false-negatives and no false-positives on the cap-passing set.
_REGEX_NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")

# Alternation-overlap: a quantified group whose body contains an alternation `|`,
# e.g. (a|a)+, (a|ab)*, (foo|foobar)+. Overlapping/ambiguous alternatives under a
# quantifier backtrack catastrophically just like a nested quantifier, yet the
# nested-quantifier shape above does not catch them (no inner quantifier). Kept
# conservative: a single `(...)` (no inner parens) with a `|`, then a quantifier.
_REGEX_ALTERNATION_OVERLAP = re.compile(r"\([^()]*\|[^()]*\)\s*[+*{]")

# Multi-group adjacent quantified groups: (a+)(a+)+, (a+)(b+)*, (...)(...)+ -- two
# back-to-back groups where the SECOND carries a trailing quantifier. The first
# group's unbounded body and the quantified second group share input, so the engine
# explores an exponential partition of the matched span. The single-group
# _REGEX_NESTED_QUANTIFIER above misses this (the outer quantifier sits on a sibling
# group, not the enclosing one). Each group body is paren-free (kept conservative).
_REGEX_ADJACENT_GROUP_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\([^()]*\)\s*[+*]")

# Stacked bounded repeats: a{1000}{1000}, (x){500}{500}, [a-z]{50}{50} -- a `{m}`/`{m,n}`
# repeat immediately followed by another `{...}`. Python's re multiplies the bounds, so a
# pair of large counts is a polynomial/exponential blow-up with a tiny source string. A
# group/atom (optionally already quantified) then two consecutive brace quantifiers.
_REGEX_STACKED_BOUNDED_REPEAT = re.compile(r"(?:\)|\]|\w)\{\d+(?:,\d*)?\}\{\d+(?:,\d*)?\}")

# Complexity-budget backstop: cap the combined count of unbounded quantifiers (`+`/`*`,
# unescaped) and alternations (`|`, unescaped) in one pattern. The structural regexes
# above catch KNOWN bad shapes; this catches novel compositions of many quantifiers /
# alternatives that together create a large backtracking surface even when no single
# pair matches a structural template. The threshold (12) is generous: realistic ABP/DNS
# feed regex carries a handful of anchors + one or two trailing quantifiers (a domain
# pattern like `^(.+\.)?ads?[0-9]*\.example\.(com|net|org)$` counts ~5), so 12 clears
# every benign pattern in the corpus while still bounding adversarial stacking.
_REGEX_BUDGET_MAX = 12
_REGEX_UNBOUNDED_QUANTIFIER = re.compile(r"(?<!\\)[+*]")
_REGEX_ALTERNATION = re.compile(r"(?<!\\)\|")

# Runtime warn/evict ceilings (milliseconds of per-match thread CPU; measured
# defaults, ADR.md SS2). Overridable via the pfb_unbound.ini MAIN section
# (regex_warn_ms / regex_evict_ms) -> cfg, so they are not hardcoded magic.
REGEX_WARN_MS_DEFAULT = 10.0
REGEX_EVICT_MS_DEFAULT = 100.0

# perf_counter fallback needs TWO consecutive over-evict strikes before evicting,
# so a single wall-clock spike (a descheduled thread) cannot false-evict a good
# pattern. thread_time is jitter-robust and evicts on the first crossing.
REGEX_PERF_STRIKES = 2

# `time.thread_time` is present on CPython/FreeBSD (CLOCK_THREAD_CPUTIME_ID); fall
# back to `time.perf_counter` (+ the 2-strike guard) only where it is absent.
_REGEX_HAVE_THREAD_TIME = hasattr(time, "thread_time")

# Rate-limit the WARN log to one line per pattern name (a slow pattern warns once,
# not on every query) and track perf_counter strikes per name. Module-level dicts
# mutated under the GIL; small + bounded by the loaded regex count.
_regex_warned: set[str] = set()
_regex_perf_strikes: dict[str, int] = {}

# Single-slot identity cache for the literal-prefilter index (one per scan
# function).  Each slot is None or (db_ref, buckets, always) where db_ref is the
# exact dict object of the regex DB, buckets maps first-char -> [(name, literal)],
# and always is the list of names whose pattern yielded no required literal.  A
# wholesale snapshot swap changes the dict's identity and triggers a rebuild; an
# in-place eviction (pop) on the SAME dict does not -- a stale bucket entry for an
# evicted name is a safe over-inclusion (the regex_db.get(_k) guard skips it).
_block_regex_index: tuple[dict[str, Any], dict[str, list[tuple[str, str]]], list[str]] | None = None
_allow_regex_index: tuple[dict[str, Any], dict[str, list[tuple[str, str]]], list[str]] | None = None


def _required_literal(pattern: str) -> str | None:
    """Return a lowercased substring that MUST appear in every match of ``pattern``,
    or None if none can be proven.

    Backs the per-query regex-rule prefilter: rules are bucketed by this literal's
    first char and only run when it is present in the query; a rule with no literal
    is always-run.  Necessary-condition only -- it never drops a match.  Rationale,
    benchmarks, and the bucket-vs-Aho-Corasick decision live in ADR-28.

    Walks Python's regex AST to find the longest contiguous run of mandatory literal
    characters.  A run is broken by anything that is not a guaranteed-present literal:
    character classes, alternations, optional/unbounded quantifiers, assertions, and
    backrefs all break or contribute nothing.  MAX_REPEAT with min>=1 and SUBPATTERN
    groups recurse.

    Returns the longest run lowercased when its length is >=2, else None.  On any
    parse error (unknown opcode, private-module absent, non-CPython) returns None so
    the rule becomes always-run -- a safe degradation that changes no decision.
    """
    if _sre_parse is None:
        return None

    def _runs(seq: Any) -> Iterator[str]:
        cur: list[str] = []
        for op, av in seq:
            name: str = op.name if hasattr(op, "name") else str(op)
            if name == "LITERAL":
                cur.append(chr(av))
                continue
            if cur:
                yield "".join(cur)
                cur = []
            if name in ("MAX_REPEAT", "MIN_REPEAT"):
                mn, _mx, item = av
                if mn >= 1:
                    yield from _runs(item)
            elif name == "SUBPATTERN":
                yield from _runs(av[-1])
            # BRANCH, IN, ANY, AT, ASSERT, GROUPREF, etc. -> break the run, yield nothing
        if cur:
            yield "".join(cur)

    try:
        parsed = _sre_parse.parse(pattern)
        best = max(_runs(parsed), key=len, default="")
        return best.lower() if len(best) >= 2 else None
    except Exception:
        return None


def _build_regex_index(
    regex_db: dict[str, Any],
) -> tuple[dict[str, list[tuple[str, str]]], list[str]]:
    """Build (buckets, always) for the literal-prefilter over ``regex_db``.

    ``buckets`` maps first-char-of-literal -> list of (name, literal); ``always``
    collects the names whose pattern yielded no required literal (they are always
    candidate for the full re.search).  Both are built once per distinct db object
    and cached by the caller.
    """
    buckets: dict[str, list[tuple[str, str]]] = {}
    always: list[str] = []
    for name, r in regex_db.items():
        pattern_obj = r.get("re") if isinstance(r, dict) else r
        raw_pattern: str = pattern_obj.pattern if hasattr(pattern_obj, "pattern") else ""
        lit = _required_literal(raw_pattern) if raw_pattern else None
        if lit is None:
            always.append(name)
        else:
            ch = lit[0]
            if ch not in buckets:
                buckets[ch] = []
            buckets[ch].append((name, lit))
    return buckets, always


def _regex_is_catastrophic_shape(pattern: str) -> bool:
    """Pure static analysis (NO execution): True when ``pattern`` carries a structurally
    catastrophic shape -- a nested / adjacent / overlapping unbounded quantifier, a
    stacked bounded repeat, or so many unbounded quantifiers + alternations combined that
    its backtracking surface is unsafe. This is the SAFETY gate: it is applied to FEED and
    user regex UNCONDITIONALLY at load (independent of the opt-in length cap) because these
    shapes drive catastrophic backtracking in the `re` engine. It only inspects the pattern
    STRING -- it never runs the candidate against any input -- so it is itself cheap and
    safe. Length is deliberately NOT part of this gate (a long pattern is not inherently
    catastrophic; the length ceiling is the separate opt-in convenience cap)."""
    if _REGEX_NESTED_QUANTIFIER.search(pattern) is not None:
        return True
    if _REGEX_ALTERNATION_OVERLAP.search(pattern) is not None:
        return True
    if _REGEX_ADJACENT_GROUP_QUANTIFIER.search(pattern) is not None:
        return True
    if _REGEX_STACKED_BOUNDED_REPEAT.search(pattern) is not None:
        return True
    # Budget backstop: total unbounded quantifiers + alternations over the threshold.
    budget = len(_REGEX_UNBOUNDED_QUANTIFIER.findall(pattern)) + len(_REGEX_ALTERNATION.findall(pattern))
    return budget > _REGEX_BUDGET_MAX


def _regex_timed_search(pattern: Any, q_name: str) -> tuple[Any, float]:
    """Run ``pattern.search(q_name)`` and return ``(match, elapsed_ms)`` where
    ``elapsed_ms`` is per-thread CPU time (``time.thread_time``) when available, else
    wall clock (``time.perf_counter``). Thread CPU is jitter-robust: a thread merely
    descheduled under load does not inflate the measurement, so a good pattern is not
    false-evicted. NO timeout is attempted -- a match cannot be interrupted (fact 2);
    this only MEASURES so the caller can warn/evict AFTER the (first) match returns."""
    if _REGEX_HAVE_THREAD_TIME:
        start = time.thread_time()
        match = pattern.search(q_name)
        elapsed_ms = (time.thread_time() - start) * 1000.0
    else:
        start = time.perf_counter()
        match = pattern.search(q_name)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
    return match, elapsed_ms


def _regex_should_evict(name: str, elapsed_ms: float, warn_ms: float, evict_ms: float, group: str, feed: Any) -> bool:
    """Apply the runtime warn/evict policy for ONE match of pattern ``name`` that took
    ``elapsed_ms``. Logs a rate-limited warning over ``warn_ms`` (once per name) and
    returns True when the pattern should be EVICTED (over ``evict_ms``). With
    ``time.thread_time`` an over-evict crossing evicts on the FIRST hit; on the
    perf_counter fallback it requires ``REGEX_PERF_STRIKES`` consecutive crossings so
    a lone wall-clock spike cannot false-evict. The caller collects names to evict and
    pops them AFTER the scan loop (snapshot-iterate; never mutate mid-iteration)."""
    if elapsed_ms <= warn_ms:
        # A fast match clears any accumulated perf-fallback strike streak.
        if not _REGEX_HAVE_THREAD_TIME:
            _regex_perf_strikes.pop(name, None)
        return False

    if elapsed_ms <= evict_ms:
        if name not in _regex_warned:
            _regex_warned.add(name)
            sys.stderr.write(
                "[pfBlockerNG]: slow {} regex [ {} ] feed [ {} ] took {:.1f} ms (warn ceiling {:.1f} ms)".format(
                    group, name, feed, elapsed_ms, warn_ms
                )
            )
        if not _REGEX_HAVE_THREAD_TIME:
            _regex_perf_strikes.pop(name, None)
        return False

    # Over the EVICT ceiling.
    if not _REGEX_HAVE_THREAD_TIME:
        strikes = _regex_perf_strikes.get(name, 0) + 1
        _regex_perf_strikes[name] = strikes
        if strikes < REGEX_PERF_STRIKES:
            return False
        _regex_perf_strikes.pop(name, None)

    sys.stderr.write(
        "[pfBlockerNG]: EVICTING {} regex [ {} ] feed [ {} ] -- match took {:.1f} ms (evict ceiling {:.1f} ms); "
        "it will no longer be evaluated".format(group, name, feed, elapsed_ms, evict_ms)
    )
    _regex_warned.discard(name)
    return True


def _regex_evict_names(db: dict[str, Any], names: Iterable[str]) -> None:
    """Pop evicted pattern keys from a live regex DB AFTER the scan loop. ``dict.pop``
    is atomic under the GIL, so this is safe even though the matcher runs across many
    Unbound query threads; the scan iterates a SNAPSHOT (list(...)) so this never
    mutates a dict mid-iteration (ADR.md fact 3)."""
    for name in names:
        db.pop(name, None)


def _dnsbl_compile_regex_rules(
    regex_rules: Iterable[RegexRule],
    *,
    static_cap: bool = False,
) -> tuple[dict[str, dict[str, Any]], int]:
    """Compile a list of irreducible ``RegexRule`` into the live regex-DB shape.

    Returns ``(db, admitted)`` where ``db[name] = {"re": <compiled>, "important":
    bool, "band": int}`` and ``admitted`` is the count of patterns that compiled.
    A pattern that fails ``re.compile`` is logged and skipped (mirrors the init REGEX
    load) -- it never aborts the build. Names are unique per pattern occurrence so two
    feeds carrying the same pattern both load.

    ADR-07: a pattern carrying a catastrophic SHAPE (nested / adjacent / overlapping
    unbounded quantifier, stacked bounded repeat, or over the complexity budget) is
    DROPPED at load UNCONDITIONALLY -- independent of ``static_cap`` -- because such a
    shape drives catastrophic backtracking in the `re` engine. The opt-in length ceiling
    (the "Limit long/complex regex" setting, ``static_cap``) is the SEPARATE tunable half:
    when True it ALSO drops over-length-but-safe patterns. All checks are pure static
    string analysis (no execution); the always-on runtime warn/evict guard lives in the
    matcher (it is what bounds the residual of anything that slips through).
    """
    db: dict[str, dict[str, Any]] = {}
    admitted = 0
    seq = 0
    for rule in regex_rules:
        if _regex_is_catastrophic_shape(rule.pattern):
            sys.stderr.write(
                "[pfBlockerNG]: dropping pathological {} regex feed [ {} ] pattern [ {} ] (catastrophic shape)".format(
                    rule.kind, rule.feed, rule.pattern
                )
            )
            continue
        if static_cap and len(rule.pattern) > REGEX_STATIC_LEN_CAP:
            sys.stderr.write(
                "[pfBlockerNG]: dropping over-length {} regex feed [ {} ] pattern [ {} ] (static length cap)".format(
                    rule.kind, rule.feed, rule.pattern
                )
            )
            continue
        try:
            compiled = re.compile(rule.pattern)
        except re.error as e:
            sys.stderr.write(
                "[pfBlockerNG]: ABP regex compile error feed [ {} ] pattern [ {} ]: {}".format(
                    rule.feed, rule.pattern, e
                )
            )
            continue
        # Key by feed + a per-build sequence so identical patterns from different feeds
        # (or the same feed) do not collide and each is independently evictable (P7).
        name = "{}#{}".format(rule.feed or "DNSBL", seq)
        seq += 1
        db[name] = {"re": compiled, "important": rule.important, "band": rule.band}
        admitted += 1
    return db, admitted


def build(
    manifest: dict[str, Any],
    config: dict[str, Any],
    *,
    line_reader: Callable[[str], Iterable[str]],
    top1m_enabled: bool = False,
) -> BuildResult:
    """Pure, reentrant DNSBL build: raw feeds + config -> matcher structure-set.

    ``manifest`` is the per-feed boundary: one row per
    raw feed file mapping it to ``{raw, feed, group, format_hint, log_flag}``.
    ``config`` carries the classification + whitelist inputs (``tld_master`` suffix
    lines, ``tld_blacklist``, ``tld_exclusion``, ``user_whitelist``, ``user_unlock``,
    ``top1m_list``).
    ``line_reader`` yields the raw lines for a feed's ``raw`` reference -- injected so
    this stays pure and side-effect-free (no filesystem coupling, unit-testable; the
    init wiring supplies a file-backed reader).

    Returns a FRESH ``BuildResult`` and mutates no module global -- calling it twice
    yields equal structures (reentrant / zero-downtime-ready). It performs NO dedup,
    NO subdomain collapse and NO build-time whitelist/TOP1M removal: duplicate keys
    are simply overwritten last-wins by dict assignment (the documented attribution
    change, ADR.md SS2), and redundant subdomains stay because their parent zone still
    matches them.

    ADR-48 (issue #789): every domain target a normalise-fail rejects (permit path,
    plain path, both parse_abp() call sites) and the reconcile() wire-cap fold-drop
    are tallied into ``BuildResult.rejects`` (bucket 'shape' | 'wire_cap', keyed
    (feed, group)) -- accounting only, no gate DECISION changes.
    """
    suffix_lines = list(config.get("tld_master", []))
    tld_blacklist = list(config.get("tld_blacklist", []))
    tld_exclusion = list(config.get("tld_exclusion", []))
    exclusion = {e.strip(".") for e in tld_exclusion}

    # ADR-07: the opt-in static cap (drop over-long / nested-quantifier feed regex
    # at load). Read from the manifest config; OFF by default so nothing is dropped.
    static_cap = bool(config.get("regex_cap", False))

    tlds = _dnsbl_load_tld_master(suffix_lines, tld_blacklist, tld_exclusion)

    data_db: dict[str, dict[str, Any]] = {}
    zone_db: dict[str, dict[str, Any]] = {}
    feed_group_index_db: dict[int, dict[str, str]] = {}
    feed_group_db: dict[str, int] = {}
    next_index = 0
    # ADR-48 (issue #789): the per-entry reject tally this build accumulates.
    rejects: RejectTally = {}

    def index_for(feed: str, group: str) -> int:
        nonlocal next_index
        key = feed + group
        idx = feed_group_db.get(key)
        if idx is None:
            idx = next_index
            feed_group_db[key] = idx
            feed_group_index_db[idx] = {"feed": feed, "group": group}
            next_index += 1
        return idx

    # Whole-TLD block: a blacklisted TLD becomes a synthetic DNSBL_TLD zone entry
    # (inc:2740 ``,<tld>,,1,DNSBL_TLD,DNSBL_TLD``).
    for raw_tld in tld_blacklist:
        tld = raw_tld.strip(".")
        if not tld:
            continue
        idx = index_for("DNSBL_TLD", "DNSBL_TLD")
        zone_db[tld] = {"log": "1", "index": idx, "important": False, "band": PRIO_FEED_BLOCK}

    # ADR-06 (#51): the temporary per-alert Unlock store (config.user_unlock, fed from
    # the pfb_unlock state by the alerts dnsbl_remove handler) loads into whiteDB
    # exactly like the permanent user whitelist -- both are band-6 sovereign user allows
    # (_dnsbl_normalise_whitelist marks every entry important=True / PRIO_USER_ALLOW), so
    # an unlocked domain resolves (its feed / Custom_List block is overridden). A FULL
    # build emits an empty user_unlock (Force/Cron re-lock); only the incremental
    # dnsbl_remove handler populates it.
    white_db = _dnsbl_normalise_whitelist(
        config.get("user_whitelist", []),
        config.get("top1m_list", []),
        top1m_enabled,
    )
    # Merge the unlock set WITHOUT narrowing an existing permanent allow: a domain may be
    # a wildcard in user_whitelist (".x" -> covers subdomains) yet exact in user_unlock,
    # and a plain last-wins concat would downgrade the wildcard to exact. Widen on
    # collision instead -- the same monotonic merge the feed @@ allows use below (keep
    # the broadest wildcard/important, highest band; both sides are band-6 user allows).
    for domain, unlock_entry in _dnsbl_normalise_whitelist(config.get("user_unlock", []), (), False).items():
        existing = white_db.get(domain)
        if existing is None:
            white_db[domain] = unlock_entry
            continue
        white_db[domain] = {
            "wildcard": _white_entry_wildcard(existing) or _white_entry_wildcard(unlock_entry),
            "important": _white_entry_important(existing) or _white_entry_important(unlock_entry),
            "band": max(_white_entry_band(existing), _white_entry_band(unlock_entry)),
        }

    # ADR-07: ABP feeds (format_hint='abp') are parsed into the typed Rule stream
    # (Stage A, parse_abp) and reconciled (Stage B) into the banded pre-emit rule
    # sets; non-ABP feeds keep the ADR-06 lite parse() -> block-only path unchanged.
    # The reconciled ABP structures (incl. @@/regex/important/badfilter) are emitted
    # below alongside the plain blocks. Each ABP rule carries its manifest-row
    # feed/group/log straight through parse_abp onto the Rule.
    abp_rules: list[Rule] = []
    # ADR-31 §2.2.3: a permit feed that inserts a band-2 allow must engage the numeric
    # band-aware resolution (exactly as any feed @@ allow does via reconcile, line ~4095),
    # so a higher-band block still wins -- a band-5 user/Custom_List block (the headline
    # security case) and equally a band-3 $important feed block. Without it the fast path
    # treats ANY whiteDB hit as an unconditional override -- a fail-open.
    permit_allow_inserted = False

    for feed_row in manifest.get("feeds", []):
        feed = feed_row["feed"]
        group = feed_row["group"]
        fmt = feed_row["format_hint"]
        log_flag = feed_row["log_flag"]
        # ADR-31: permit-mode feeds — every host line is a band-2 wildcard allow.
        # ``mode`` absent or ``'deny'`` falls through to the existing block build path
        # (backward-safe: older manifests without the field build byte-identically).
        # ``mode='permit'`` routes hosts into whiteDB at PRIO_FEED_ALLOW (band 2),
        # wildcard=True (subdomain-covering, matching @@||host^), important=False.
        # ABP directives (@@, ||, [, !, $options) are ignored in v1 ("every host = allow").
        # Provenance is recorded via index_for(feed, group) so reports can attribute
        # the allow to its DNSWL feed (same convention as block-feed entries).
        if feed_row.get("mode") == "permit":
            for raw_line in line_reader(feed_row["raw"]):
                # Skip ABP/comment control lines — in a permit feed every plain host is
                # an allow; ABP directives are ignored (v1). The skip set matches the
                # plain-block loop's broadened capture below (regex/element-hiding, not
                # just '@@'/'||') so a captured-but-non-host line never becomes an
                # accidental allow (ADR-62 delta D4).
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("!") or stripped.startswith("["):
                    continue
                if _dnsbl_is_abp_rule_line(stripped):
                    continue
                entry = parse(fmt, stripped)
                if entry is None:
                    continue
                domain, bucket = _normalise_verdict(entry.value)
                if domain is None:
                    if bucket is not None:
                        _tally_reject(rejects, feed, group, bucket)
                    continue
                # Insert as band-2 wildcard allow (@@||host^ shape) into whiteDB.
                # Monotonic-widen on collision: never downgrade an existing higher band
                # (e.g. a user whitelist entry at band 6 must not be narrowed to band 2).
                idx = index_for(feed, group)
                new_entry: dict[str, Any] = {
                    "wildcard": True,
                    "important": False,
                    "band": PRIO_FEED_ALLOW,
                    "index": idx,
                }
                existing = white_db.get(domain)
                if existing is None:
                    white_db[domain] = new_entry
                    permit_allow_inserted = True
                elif _white_entry_band(existing) < PRIO_FEED_ALLOW:
                    white_db[domain] = new_entry
                    permit_allow_inserted = True
                # Same or higher band: keep existing (monotonic widen — never downgrade).
            continue
        # ADR-07: a DNSBL Group Custom_List (the {alias}_custom synthetic row, PHP
        # provenance='user') is USER-curated -> SOVEREIGN over feeds: the user is the
        # sovereign and a list (automated) can never override an explicit user choice.
        # So its blocks carry the user-block band (5, == user regex), which beats any
        # feed allow (@@ band 2 / @@$important band 4); only the band-6 whitelist wins.
        # A downloaded feed stays band 1. The ABP path threads provenance into
        # parse_abp -> reconcile (_dnsbl_rule_band scores USER at band 5); the non-ABP
        # plain path bands the entry directly here.
        provenance = RULE_PROV_USER if feed_row.get("provenance") == "user" else RULE_PROV_FEED
        block_band = PRIO_USER_BLOCK if provenance == RULE_PROV_USER else PRIO_FEED_BLOCK
        if fmt == "abp":
            for raw_line in line_reader(feed_row["raw"]):
                rule = parse_abp(raw_line, provenance=provenance, feed=feed, group=group, log=log_flag, tally=rejects)
                if rule is not None:
                    abp_rules.append(rule)
            continue
        for raw_line in line_reader(feed_row["raw"]):
            # ADR-62: per-line ABP detection in a non-ABP feed, broadened from ADR-21's
            # '||'/'@@||' to the full Decision-2 capture shape set (regex, element-
            # hiding) via _dnsbl_is_abp_rule_line() -- a self-identifying ABP entry is
            # invalid in every plain dialect, so it would otherwise be dropped by the
            # plain validator. Route it to the full parse_abp() Stage-A parser -> the
            # abp_rules stream (Stage-B reconcile), with the SAME provenance/feed/
            # group/log plumbing as the whole-feed ABP path above. parse_abp() returns
            # None for anything it itself skips (path/wildcard/IP anchors, element-
            # hiding, non-DNS $options, malformed anchors) -> silently skipped here too.
            stripped = raw_line.strip()
            if _dnsbl_is_abp_rule_line(stripped):
                rule = parse_abp(stripped, provenance=provenance, feed=feed, group=group, log=log_flag, tally=rejects)
                if rule is not None:
                    abp_rules.append(rule)
                continue
            entry = parse(fmt, raw_line)
            if entry is None:
                continue
            domain, bucket = _normalise_verdict(entry.value)
            if domain is None:
                if bucket is not None:
                    _tally_reject(rejects, feed, group, bucket)
                continue
            # Only BLOCK is produced by the lite path (ABP-ready seam; module header).
            if entry.kind != DNSBL_KIND_BLOCK:
                continue
            idx = index_for(feed, group)
            cls, key = classify(domain, tlds, exclusion)
            # Non-ABP block: band 1 (downloaded feed) or 5 (USER Custom_List); never
            # $important (the plain path has no $options grammar).
            payload = {"log": log_flag, "index": idx, "important": False, "band": block_band}
            if cls == DNSBL_CLASS_ZONE:
                zone_db[key] = payload  # last-wins (dict; ADR-06 SS2 attribution change)
            else:
                data_db[key] = payload

    # ---- Stage-B reconcile + Stage-C emit for the ABP rule stream -------------- #
    regex_db: dict[str, dict[str, Any]] = {}
    allow_regex_db: dict[str, dict[str, Any]] = {}
    important_rules = permit_allow_inserted
    regex_count = 0
    if abp_rules:
        result = reconcile(abp_rules, tlds, exclusion, tally=rejects)
        important_rules = important_rules or result.important_rules

        # Domain blocks -> dataDB/zoneDB (carry band + $important).
        for b in result.block_domains:
            idx = index_for(b.feed or "DNSBL", b.group or "DNSBL")
            payload = {"log": b.log or "1", "index": idx, "important": b.important, "band": b.band}
            if b.cls == DNSBL_CLASS_ZONE:
                zone_db[b.key] = payload
            else:
                data_db[b.key] = payload

        # Domain allows (@@||domain^ and reduced @@/re/) -> whiteDB. A user whitelist
        # entry (band 6) must never be downgraded by a feed allow on the SAME key, so
        # only widen when the key is absent or the existing band is lower.
        for a in result.allow_domains:
            existing = white_db.get(a.domain)
            if existing is None:
                white_db[a.domain] = {"wildcard": a.wildcard, "important": a.important, "band": a.band}
                continue
            if _white_entry_band(existing) < a.band:
                white_db[a.domain] = {"wildcard": a.wildcard, "important": a.important, "band": a.band}
                continue
            # Same key, SAME band: a key can carry both an exact (reduced @@/^d$/)
            # and a wildcard (@@||d^) allow. The suffix-walk only honours wildcard
            # entries, so first-writer-wins would silently drop subdomain coverage.
            # Merge monotonically (widen) -- keep the strongest of each field.
            if _white_entry_band(existing) == a.band:
                white_db[a.domain] = {
                    "wildcard": _white_entry_wildcard(existing) or a.wildcard,
                    "important": _white_entry_important(existing) or a.important,
                    "band": a.band,
                }

        # Irreducible regex -> regexDB (block) / allowRegexDB (allow). Compile here;
        # a broken pattern is logged + skipped, mirroring the init regex load
        # (pfb_unbound.py REGEX section). The runtime warn/evict guard (ADR-07)
        # applies later, at query time in evaluate_domain, not during this compile.
        # Iterate over a stable list so the emit order is deterministic.
        regex_db, block_admitted = _dnsbl_compile_regex_rules(result.block_regex_irreducible, static_cap=static_cap)
        allow_regex_db, allow_admitted = _dnsbl_compile_regex_rules(
            result.allow_regex_irreducible, static_cap=static_cap
        )
        regex_count = block_admitted + allow_admitted

    return BuildResult(
        data_db=data_db,
        zone_db=zone_db,
        feed_group_index_db=feed_group_index_db,
        white_db=white_db,
        counts=len(data_db) + len(zone_db),
        regex_db=regex_db,
        allow_regex_db=allow_regex_db,
        important_rules=important_rules,
        regex_count=regex_count,
        rejects=rejects,
    )


def _dnsbl_path_within_base(path: str, base_dir: str) -> bool:
    """Containment check: is the resolved real path of ``path`` inside ``base_dir``?

    The manifest is published next to its raw feeds, so every ``raw`` / ``tld_master``
    file a row references must resolve under the manifest's own directory. A row whose
    resolved path escapes that directory (via ``..`` or an absolute path elsewhere) is
    rejected by the caller -- never opened. Symlinks are resolved (``os.path.realpath``)
    so a link inside ``base_dir`` cannot point outside it.
    """
    real_base = os.path.realpath(base_dir)
    real_path = os.path.realpath(path)
    try:
        return os.path.commonpath([real_base, real_path]) == real_base
    except ValueError:
        return False


def _dnsbl_file_line_reader(base_dir: str) -> Callable[[str], Iterable[str]]:
    """A file-backed ``line_reader`` for build(): map a feed_row["raw"] reference to
    its raw lines, streamed lazily so peak RAM stays at the dict floor.

    ``raw`` may be an absolute path or a name relative to ``base_dir`` (the directory
    holding the manifest). Yields stripped-of-newline lines; a missing/unreadable feed
    yields nothing (and is logged by the caller) rather than aborting the whole build.
    """

    def reader(raw: str) -> Iterable[str]:
        path = raw if os.path.isabs(raw) else os.path.join(base_dir, raw)
        if not _dnsbl_path_within_base(path, base_dir):
            # The feed path escapes the manifest directory -- skip it (do not open).
            sys.stderr.write("[pfBlockerNG]: Refusing DNSBL feed outside base dir: '{}'".format(path))
            return
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError as e:
            # A single missing/unreadable feed is logged and skipped -- it must not
            # abort the whole build (the other feeds still load).
            sys.stderr.write("[pfBlockerNG]: Failed to read DNSBL feed '{}': {}".format(path, e))
            return
        with fh:
            for line in fh:
                yield line.rstrip("\r\n")

    return reader


def _dnsbl_config_from_manifest(manifest: dict[str, Any], base_dir: str) -> dict[str, Any]:
    """Shape the manifest's ``config`` block into the build() config blob.

    The on-box manifest carries ``tld_master`` as a FILE PATH (the public-suffix
    oracle); the build takes the suffix LINES directly (pure, filesystem-decoupled),
    so read the file here. ``tld_blacklist`` / ``tld_exclusion`` / ``user_whitelist``
    / ``user_unlock`` / ``top1m_list`` are passed through as lists. Missing keys default
    empty so a partial manifest still builds.
    """
    config = manifest.get("config", {})

    tld_master_lines: list[str] = []
    tld_master = config.get("tld_master")
    if isinstance(tld_master, list):
        tld_master_lines = list(tld_master)
    elif isinstance(tld_master, str) and tld_master:
        path = tld_master if os.path.isabs(tld_master) else os.path.join(base_dir, tld_master)
        if not _dnsbl_path_within_base(path, base_dir):
            # The tld_master path escapes the manifest directory -- skip it (do not open).
            sys.stderr.write("[pfBlockerNG]: Refusing tld_master outside base dir: '{}'".format(path))
        else:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    tld_master_lines = fh.read().splitlines()
            except OSError as e:
                sys.stderr.write("[pfBlockerNG]: Failed to read tld_master '{}': {}".format(path, e))

    # ADR-07: the static-cap flag reaches build() via the ini-derived pfb setting
    # (the cap setting lives in pfb_unbound.ini MAIN, not the manifest); a manifest
    # ``config.regex_cap`` (if present) takes precedence so the build stays a pure
    # function of (manifest+config) in tests that inject it directly.
    regex_cap = bool(config.get("regex_cap", pfb.get("regex_cap", False)))

    return {
        "tld_master": tld_master_lines,
        "tld_blacklist": list(config.get("tld_blacklist", [])),
        "tld_exclusion": list(config.get("tld_exclusion", [])),
        "user_whitelist": list(config.get("user_whitelist", [])),
        # ADR-06 (#51): the temporary per-alert unlock set -> band-6 whiteDB allows.
        "user_unlock": list(config.get("user_unlock", [])),
        "top1m_list": list(config.get("top1m_list", [])),
        "regex_cap": regex_cap,
    }


def dnsbl_build_from_manifest(manifest_path: str) -> BuildResult | None:
    """Read the per-feed manifest JSON and BUILD the DNSBL structure-set from raw.

    This is the ADR-06 init swap point: a pure ``(manifest+raw) -> BuildResult``
    step (build() mutates no global) that a future zero-downtime reload can run on a
    background thread and atomically swap in. This phase only calls it synchronously
    at init and assigns the result into the module globals -- no background/restart-
    free behaviour is added here.

    The manifest carries ``feeds`` (one row per raw feed file) and a ``config`` block.
    ``top1m_enabled`` is taken from ``config["top1m_enabled"]``. Returns ``None`` when
    the manifest is absent or cannot be parsed (init then falls back to the legacy
    CSV load -- shell/PHP still produce those files for that fallback).
    """
    if not os.path.isfile(manifest_path):
        # issue #1049: close an orphaned prior parse-stage entry -- mirrors the
        # 6 CSV-loader sites' absent-file close (af3da0ec).
        pfb_py_status_close("dnsbl", manifest_path, "parse")
        return None

    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as e:
        sys.stderr.write("[pfBlockerNG]: Failed to load DNSBL manifest '{}': {}".format(manifest_path, e))
        pfb_py_status_open(
            "dnsbl", manifest_path, "parse", "Failed to load DNSBL manifest '{}': {}".format(manifest_path, e)
        )
        return None

    base_dir = os.path.dirname(os.path.abspath(manifest_path))
    config = _dnsbl_config_from_manifest(manifest, base_dir)
    top1m_enabled = bool(manifest.get("config", {}).get("top1m_enabled", False))

    try:
        result = build(
            manifest,
            config,
            line_reader=_dnsbl_file_line_reader(base_dir),
            top1m_enabled=top1m_enabled,
        )
    except Exception as e:
        sys.stderr.write("[pfBlockerNG]: Failed to build DNSBL structures from raw: {}".format(e))
        pfb_py_status_open("dnsbl", manifest_path, "parse", "Failed to build DNSBL structures from raw: {}".format(e))
        return None

    pfb_py_status_close("dnsbl", manifest_path, "parse")
    return result


def dnsbl_emit_count(count_path: str, count: int) -> bool:
    """Write the Python-emitted entry total to ``pfb_py_count`` (the UI reads it at
    pfblockerng.inc:3149).

    ADR-06 redefines ``pfb_py_count`` to the LOADED entry total (len(dataDB)+len(
    zoneDB)); its value legitimately RISES vs today because the lists are no longer
    dedup/collapse/whitelist/TOP1M-pruned. The sync-check at inc:3149-3156 still
    subtracts this value -- it must be reconciled once shell/PHP is slimmed to
    match. Returns True on success.
    """
    try:
        with open(count_path, "w", encoding="utf-8") as fh:
            fh.write("{}\n".format(count))
        return True
    except OSError as e:
        sys.stderr.write("[pfBlockerNG]: Failed to write DNSBL count '{}': {}".format(count_path, e))
        return False


def dnsbl_emit_reject_stats(stats_path: str, rejects: RejectTally) -> bool:
    """Write the ADR-48 (issue #789) per-entry reject tally to ``pfb_py_reject_stats``
    as a JSON array of ``{"feed", "group", "shape", "wire_cap"}`` rows, one per
    (feed, group) with a NONZERO bucket -- PHP reads it after a DNSBL run and emits
    the canonical ``stage=entries`` line per nonzero bucket (Python never logs the
    line itself; sinks stay PHP-only). An empty ``rejects`` still writes ``"[]"`` so
    PHP can tell "ran, zero rejects" from "no artifact" (fresh boot / an old python
    module that predates this file). Atomic temp + ``os.replace`` (mirrors
    ``_reload_write_applied``): a partial write can never leave PHP reading a
    truncated/corrupt artifact. Returns True on success.
    """
    entries = [
        {"feed": feed, "group": group, "shape": counts["shape"], "wire_cap": counts["wire_cap"]}
        for (feed, group), counts in sorted(rejects.items())
        if counts["shape"] or counts["wire_cap"]
    ]
    tmp = "{}.tmp".format(stats_path)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(entries, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, stats_path)
        return True
    except OSError as e:
        sys.stderr.write("[pfBlockerNG]: Failed to write DNSBL reject stats '{}': {}".format(stats_path, e))
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


def rebuild_and_swap(build_snapshot: Callable[[], Snapshot | None], *, emit_counts: bool = True) -> bool:
    """ADR-10: the single fail-closed build -> atomic-swap + cache-reset step.

    ``build_snapshot`` is a zero-arg builder that produces a BRAND-NEW ``Snapshot`` off
    the live one (the pure ``build()``/``dnsbl_build_from_manifest()`` layer plus the
    HSTS file load -- it must mutate NO live dict; build-new-then-rebind, never mutate
    the live snapshot's dicts as a swap mechanism). It returns ``None`` (or raises) to
    signal a failed/empty build.

    On SUCCESS (a non-None Snapshot):
      1. atomically rebind the single module ``_snapshot`` ref (one GIL-atomic STORE --
         shared __main__ dict + GIL, so the new snapshot is visible to every query
         worker without a lock on the hot path);
      2. ``decisionDB.clear()`` -- the unified per-name LRU query memo (#67/#70/#72).
         It is otherwise reset only by ``init`` re-creating it, so a no-restart swap
         MUST clear it or ``operate()`` re-serves a STALE block/allow verdict on a cache
         miss (a newly-added name would stay unblocked, a newly-removed name blocked).
         The clear alone is NOT sufficient (issue #1074): a query thread that captured
         the OLD snapshot can memoize its verdict AFTER this clear, so every memo is
         also stamped with its ``Snapshot.gen`` and a reader rejects a foreign-
         generation entry -- the clear remains as eager eviction, the stamp is the
         correctness guard;
      3. reset the DNSBL Reports cache through ``_db_reset_cache`` (``_db_lock``-
         serialized, parity with the init-time wipe -- never an off-thread file touch);
      4. re-emit ``pfb_py_count`` / ``pfb_py_regex_count`` (the ``DNSBL_Regex`` UI alias)
         from the NEW snapshot so the UI reflects the live lists without a restart --
         skipped when ``emit_counts=False`` (init opts out: it keeps its own existing
         path-specific inline emits to stay byte-identical -- see the call site).

    On FAILURE (builder returns ``None`` or raises): keep the OLD ``_snapshot``, touch
    NEITHER cache (decisionDB AND the Reports sqlite stay intact), log, and return
    ``False`` -- fail-closed, mirroring init's ``build_result is not None`` guard. The
    swap NEVER installs an empty/partial set on a build error; the resolver keeps
    serving the last good snapshot (the background reload-watcher relies on exactly
    this so a failed reload is a no-op, not an outage).

    ``init_standard`` calls it SYNCHRONOUSLY (net init behaviour unchanged: the same
    snapshot, a no-op decisionDB clear on the fresh empty cache, a Reports reset in
    parity with the init os.remove, and -- with ``emit_counts=False`` -- init's own
    unchanged inline count emits). The background reload-watcher thread calls this
    same function with the default ``emit_counts=True``.
    """
    global _snapshot

    try:
        new_snapshot = build_snapshot()
    except Exception as e:
        # Fail-closed: a raising build leaves the live snapshot + both caches intact.
        sys.stderr.write("[pfBlockerNG]: DNSBL rebuild failed, keeping current snapshot: {}".format(e))
        return False

    if new_snapshot is None:
        # Fail-closed: a None build (absent/unparseable manifest, build error) is a
        # no-op -- the old snapshot keeps serving, no cache is reset.
        return False

    # SUCCESS: install the new snapshot with one GIL-atomic store, then reset the
    # query memo + Reports cache and re-emit the UI counts off the NEW snapshot.
    _snapshot = new_snapshot
    decisionDB.clear()
    _db_reset_cache()
    # #714 FIX #2: a swap installs a brand-new regex_db/allow_regex_db, so the runtime
    # warn-suppression + perf-fallback strike bookkeeping keyed on pattern NAME must not
    # survive it -- a name reused across reloads (a re-added or edited rule) would
    # otherwise inherit stale strikes/suppression from the OLD pattern object. Mirrors
    # the init_standard clear (ADR-07) so a no-restart swap resets the same state a
    # restart would.
    _regex_warned.clear()
    _regex_perf_strikes.clear()
    # ADR-10: refresh the MASTER DNSBL gate from the new snapshot, parity with init
    # (init sets pfb["python_blacklist"] True when any blocking stratum loaded -- line
    # ~1061). operate() gates ALL DNSBL evaluation on this flag; it is otherwise written
    # only at init, so a swap that loads lists into a previously-empty module (e.g. a
    # regex-ONLY feed when the last init had no lists) would leave the gate False and the
    # newly-swapped lists would never block. Mirror init: enable when the new snapshot has
    # any block/allow stratum. (A python_control runtime disable re-clears it afterwards;
    # a reload that brings lists legitimately re-enables blocking, exactly as init does.)
    if new_snapshot.data_db or new_snapshot.zone_db or new_snapshot.regex_db or new_snapshot.allow_regex_db:
        pfb["python_blacklist"] = True
    # Issue #862 (sibling of #860): a swap that NEWLY satisfies _dnsbl_stats_wanted()
    # -- python_blacklist just flipped True above (feeds added post-boot, no Unbound
    # restart) -- must open the stats DB init skipped at boot, or every per-feed and
    # Upstream counter increment silently no-ops until the next restart. Shared with the
    # PFBL-03 control-channel enable path (issue #870); see _open_dnsbl_stats_db_if_wanted().
    _open_dnsbl_stats_db_if_wanted()
    if emit_counts:
        dnsbl_emit_count(pfb["pfb_py_count"], new_snapshot.counts)
        dnsbl_emit_count(pfb["pfb_py_regex_count"], new_snapshot.regex_count)
        # ADR-48 (issue #789): re-emit the reject-stats artifact from the new
        # snapshot on a no-restart swap too, exactly like the UI counts above.
        # ``.get()`` (not a bare index): unit tests build a bare ``pfb`` dict
        # without this key and must not KeyError on an unrelated code path.
        reject_stats_path = pfb.get("pfb_py_reject_stats")
        if reject_stats_path:
            dnsbl_emit_reject_stats(reject_stats_path, new_snapshot.rejects)
    return True


def iter_domain_suffixes(name: str) -> Iterator[str]:
    q = name
    for _ in range(name.count(".") + 1, 0, -1):
        yield q
        q = q.split(".", 1)[-1]


def find_zone_match(q_name: str, zone_db: dict[str, Any]) -> tuple[str, dict] | tuple[None, None]:
    for q in iter_domain_suffixes(q_name):
        entry = zone_db.get(q)
        if entry is not None:
            return q, entry
    return None, None


def find_noaaaa_wildcard_parent(q_name: str, noaaaa_db: dict[str, Any]) -> str | None:
    q = q_name.split(".", 1)[-1]
    for _ in range(q.count("."), 0, -1):
        if noaaaa_db.get(q):
            return q
        q = q.split(".", 1)[-1]
    return None


def _white_entry_wildcard(entry: Any) -> bool:
    """Wildcard flag of a whiteDB value, tolerant of both shapes.

    ADR-07 widens whiteDB values from a bare ``bool`` (wildcard?) to
    ``{"wildcard": bool, "important": bool}``. Existing callers/tests still seed bare
    bools (e.g. ``add_white`` and the retained ADR-06 oracle), so the matcher accepts
    either: a dict reads ``["wildcard"]``; a bare bool IS the wildcard flag.
    """
    if isinstance(entry, dict):
        return bool(entry.get("wildcard", False))
    return bool(entry)


def _white_entry_important(entry: Any) -> bool:
    """Sovereignty flag of a whiteDB value (ADR-07). Bare-bool legacy entries are
    treated as not-important (False); only the new dict shape can carry it. Consulted
    solely by the numeric 6-band branch (unreachable while important_rules is False)."""
    if isinstance(entry, dict):
        return bool(entry.get("important", False))
    return False


def _white_entry_band(entry: Any) -> int:
    """Numeric band of a whiteDB value (ADR-07). A dict entry carries an explicit
    ``band`` (feed allow 2/4, user allow 6); else it is derived from ``important``
    (an important entry is a user allow -> band 6, a bare-bool/legacy feed allow ->
    band 2). Consulted only by the numeric 6-band branch."""
    if isinstance(entry, dict):
        band = entry.get("band")
        if isinstance(band, int):
            return band
        return PRIO_USER_ALLOW if entry.get("important", False) else PRIO_FEED_ALLOW
    return PRIO_FEED_ALLOW


def whitelist_lookup_domain(name: str, white_db: dict[str, Any], tld_seg: int) -> tuple[bool, bool]:
    """Resolve a whitelist hit to ``(matched, important)``.

    Same match algorithm as the historical ``whitelist_check_domain`` (exact, then
    ``www.``-strip, then a parent-suffix walk gated by ``tld_seg`` that only honours
    WILDCARD entries), but also returns the matched entry's ``important`` flag so the
    numeric 6-band resolution can place a user allow in band 6. Behaviour for the
    boolean ``matched`` result is byte-identical to the pre-ABP function.
    """
    entry = white_db.get(name)
    if entry is not None:
        return True, _white_entry_important(entry)
    if name.startswith("www."):
        entry = white_db.get(name[4:])
        if entry is not None:
            return True, _white_entry_important(entry)
    q = name.split(".", 1)[-1]
    for x in range(q.count(".") + 1, 0, -1):
        if x >= tld_seg:
            entry = white_db.get(q)
            if entry is not None and _white_entry_wildcard(entry):
                return True, _white_entry_important(entry)
        q = q.split(".", 1)[-1]
    return False, False


def whitelist_check_domain(name: str, white_db: dict[str, Any], tld_seg: int) -> bool:
    matched, _ = whitelist_lookup_domain(name, white_db, tld_seg)
    return matched


def resolve_feed_group(index: Any, feed_group_index_db: dict[int, Any]) -> tuple[Any, Any]:
    feedGroup = feed_group_index_db.get(index)
    if feedGroup is not None:
        return feedGroup["feed"], feedGroup["group"]
    return "Unknown", "Unknown"


def hsts_check_domain(
    name: str,
    hsts_db: dict[str, Any],
    hsts_tlds: tuple[str, ...] | list[str],
    tld: str,
) -> tuple[bool, str]:
    if tld in hsts_tlds:
        return True, "HSTS_TLD"
    q = name
    # issue #713: this walk must check EVERY parent suffix (stride -1) -- a stride of
    # -2 skips every other suffix level, so a name whose HSTS parent sits at a skipped
    # level would fall through to "Python" (VIP block) instead of "HSTS" (NULL block),
    # serving the block page over the wrong cert for an HSTS-preloaded parent.
    for _ in range(q.count(".") + 1, 0, -1):
        if hsts_db.get(q) is not None:
            return True, "HSTS"
        q = q.split(".", 1)[-1]
    return False, "Python"


@dataclass(slots=True)
class DnsblDecision:
    is_found: bool
    in_whitelist: bool
    in_hsts: bool
    null_blocking: bool
    # issue #31: NXDOMAIN block shape (log_type "3"/"4"). Distinct from null_blocking
    # (0.0.0.0/::) and VIP -- operate() returns a bare NXDOMAIN rcode with no answer
    # records, so HSTS's null-override is irrelevant (no TLS handshake to guard).
    nxdomain: bool
    log_type: Any
    b_type: str
    p_type: str
    feed: Any
    group: Any
    b_eval: str
    # ADR-08: a Confusable-mode ALERT (suspicious/flagged, or malicious with
    # block disabled) does NOT block -- the name resolves (is_found stays False) -- but
    # the anomaly must be surfaced. When an alert fired this carries its
    # (feed, group, b_eval) so operate() emits a dnsbl.log line in the same shape as a
    # block; None means no IDN alert. Default None so a block/allow verdict (and every
    # pre-ADR construction site) is unchanged.
    idn_alert: Any = None


class _Unset:
    # Sentinel: a Decision axis has not been evaluated yet for this name -- distinct
    # from an evaluated allow/no-match (dnsbl.is_found False / noaaaa False /
    # safesearch None). One shared immutable instance, UNSET, below.
    __slots__ = ()


UNSET: Any = _Unset()


@dataclass(slots=True)
class Decision:
    # The single per-domain verdict across every axis operate() decides. Each axis is
    # filled lazily (its check runs at a different point in operate(): noAAAA + SafeSearch
    # pre-resolution on q_name_original, DNSBL post-resolution on the chain) and cached
    # in decisionDB, so repeat queries skip re-evaluation. This replaces the separate
    # dnsblDB/excludeDB (Stage 1) AND excludeAAAADB/excludeSS/noAAAADB-memo (Stage 2).
    dnsbl: Any = UNSET  # DnsblDecision once the DNSBL stratum evaluated the name
    noaaaa: Any = UNSET  # bool (AAAA-only): True = block, False = allow
    safesearch: Any = UNSET  # matched safeSearchDB {A,AAAA} entry, or None = no match
    # issue #1074: Snapshot.gen this Decision was computed against. 0 (no real
    # generation) never matches, so an unstamped entry always reads as stale.
    snap_gen: int = 0


def _decision_for(name: str, snap_gen: int) -> Decision:
    # Get-or-create the one Decision entry for a name; axes are filled in by the caller.
    # issue #1074: a memo is only valid for the generation that produced it -- a
    # foreign-generation entry is replaced, never extended.
    dec = decisionDB.get(name)
    if dec is not None and dec.snap_gen > snap_gen:
        # An older-generation straggler neither evicts the newer entry nor extends it:
        # it writes into a throwaway Decision no reader will ever see (gen advances
        # monotonically, so its verdict can never become current again).
        return Decision(snap_gen=snap_gen)
    if dec is None or dec.snap_gen != snap_gen:
        dec = Decision(snap_gen=snap_gen)
        decisionDB[name] = dec
    return dec


class _LruCache:
    # Bounded, LRU-evicting, dict-compatible store for decisionDB. Recency is bumped on
    # both get and set, so frequently-queried names stay resident while the
    # least-recently-used entry is evicted once maxsize is exceeded (maxsize <= 0 ->
    # unbounded, the pre-LRU behaviour). Mutating and recency operations are serialized
    # by a per-instance lock: operate() runs on several Unbound worker threads and a
    # get()+move_to_end() is compound (a lock-free version races -> KeyError / over-evict).
    # The lock is uncontended (the GIL already serializes Python), so the cost is a few
    # brief acquires per query.
    def __init__(self, maxsize: int = 0) -> None:
        self.maxsize = maxsize
        self._d: OrderedDict[str, Any] = OrderedDict()
        self._lock: Any = threading.Lock() if pfb.get("mod_threading") else nullcontext()

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            if key in self._d:
                self._d.move_to_end(key)
                return self._d[key]
            return default

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            self._d.move_to_end(key)
            return self._d[key]

    def __setitem__(self, key: str, value: Any) -> None:
        with self._lock:
            self._d[key] = value
            self._d.move_to_end(key)
            if 0 < self.maxsize < len(self._d):
                self._d.popitem(last=False)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._d

    def __delitem__(self, key: str) -> None:
        with self._lock:
            del self._d[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._d)

    def clear(self) -> None:
        with self._lock:
            self._d.clear()


# ADR-07: the 6-band precedence scale (ADR.md SS2). Highest wins;
# a block wins iff block_prio > allow_prio (no ties: block in {1,3,5}, allow in {2,4,6}).
#   6 user allow   5 user block   4 feed allow+important
#   3 feed block+important   2 feed allow (@@)   1 feed block (||)
# The numeric resolution engages whenever important_rules is True: a feed @@ allow
# (reconcile, ~line 4095), a feed regex, or a permit-feed allow insertion (ADR-31 §2.2.3,
# permit_allow_inserted in build()). Otherwise the fast path runs (any whiteDB hit
# overrides any block). USER blocks (Custom_List, provenance='user') emit at band 5 in
# build(); feed blocks at band 1 (3 with $important).
PRIO_FEED_BLOCK = 1
PRIO_FEED_ALLOW = 2
PRIO_FEED_BLOCK_IMPORTANT = 3
PRIO_FEED_ALLOW_IMPORTANT = 4
PRIO_USER_BLOCK = 5
PRIO_USER_ALLOW = 6


def _block_priority(important: bool, *, user: bool = False) -> int:
    """Band of a matched BLOCK. ``user`` is reserved for a later provenance-tagging
    phase; production blocks are feed-sourced today (band 1, or 3 with $important)."""
    if user:
        return PRIO_USER_BLOCK
    return PRIO_FEED_BLOCK_IMPORTANT if important else PRIO_FEED_BLOCK


def _allow_priority(important: bool, *, user: bool = False) -> int:
    """Band of a matched ALLOW. A user allow (whiteDB ``important`` entry / TOP1M /
    settings whitelist) is band 6; a feed allow (@@/allow-regex) is band 2, or 4 with
    $important."""
    if user:
        return PRIO_USER_ALLOW
    return PRIO_FEED_ALLOW_IMPORTANT if important else PRIO_FEED_ALLOW


def _block_entry_band(entry: Any) -> int:
    """Numeric band of a block payload (dataDB / zoneDB / regexDB value).

    A payload carries an explicit ``band`` (ABP feed/user block, 1/3/5); a payload
    without one is the historical feed block and is derived from its ``important``
    flag (band 3 if $important, else feed block band 1) -- so a synthetic strata-test
    payload (no ``band`` key) still resolves to the right band. A bare compiled
    pattern (legacy/user regex) is a non-important feed block (band 1)."""
    if isinstance(entry, dict):
        band = entry.get("band")
        if isinstance(band, int):
            return band
        return _block_priority(bool(entry.get("important", False)))
    return PRIO_FEED_BLOCK


def _scan_block_band(
    q_name: str,
    cfg: dict[str, Any],
    data_db: dict[str, Any],
    zone_db: dict[str, Any],
    regex_db: dict[str, Any],
) -> tuple[int, dict[str, Any] | None]:
    """Highest block band that matches ``q_name`` across dataDB (exact), zoneDB (the
    suffix walk) and the block-regex DB, AND the winning entry that carries it.

    Returns ``(best_band, best_meta)``: ``best_band`` is the max matching band (0 if
    none match), and ``best_meta`` describes the entry whose band IS that max so the
    caller can RE-ATTRIBUTE feed/group/log_type/b_type/b_eval to the rule that
    actually won (issue #47). Returning only the band lost that identity, so a
    higher-band rule decided correctly but the response was shaped/reported from the
    first-discovered entry. ``best_meta`` is one of:

    * ``{"kind": "data", "entry": <payload>}`` -> b_type "DNSBL", b_eval q_name
    * ``{"kind": "zone", "entry": <payload>, "matched": <suffix>}`` -> b_type "TLD"
    * ``{"kind": "regex", "key": <name>}`` -> feed=key, group "DNSBL_Regex"

    ``None`` when nothing matched. The numeric 6-band resolution takes the max block
    band (decide() semantics) -- the fast-path discovery short-circuits on the first
    hit, which is wrong for the max. Snapshot-iterates the regex DB (eviction
    safety). On a tie the first scanned kind (data -> zone -> regex) holds best_meta,
    but the caller only re-attributes when this band strictly exceeds the discovered
    one, so a tie never disturbs the discovered attribution."""
    best = 0
    best_meta: dict[str, Any] | None = None
    if cfg.get("dataDB"):
        entry = data_db.get(q_name)
        if entry is not None:
            band = _block_entry_band(entry)
            if band > best:
                best, best_meta = band, {"kind": "data", "entry": entry}
    if cfg.get("zoneDB"):
        for q in iter_domain_suffixes(q_name):
            entry = zone_db.get(q)
            if entry is not None:
                band = _block_entry_band(entry)
                if band > best:
                    best, best_meta = band, {"kind": "zone", "entry": entry, "matched": q}
    if cfg.get("regexDB") and q_name:
        # Literal-prefilter: build (or reuse) a first-char bucket index so only rules
        # whose required literal substring is present in the query reach re.search.
        # A necessary-condition guard -- a rule whose literal is absent cannot match,
        # so skipping its re.search changes no decision.  Rules with no extractable
        # literal (pure alternation, complex anchors) are always-run.  The full
        # re.search still runs on the ORIGINAL q_name (not the lowercased form used
        # for the membership test), so case handling is unchanged.  The warn/evict
        # ReDoS guard is unaffected: a slow rule is still timed and evicted on the
        # queries where it actually runs.
        global _block_regex_index
        if _block_regex_index is None or _block_regex_index[0] is not regex_db:
            _buckets, _always = _build_regex_index(regex_db)
            _block_regex_index = (regex_db, _buckets, _always)
        _bi_buckets, _bi_always = _block_regex_index[1], _block_regex_index[2]
        q_lower = q_name.lower()
        cand: set[str] = set(_bi_always)
        for _ch in set(q_lower):
            _b = _bi_buckets.get(_ch)
            if _b:
                for _name, _lit in _b:
                    if _lit in q_lower:
                        cand.add(_name)
        # Snapshot-iterate + time each match (ADR-07), same warn/evict policy as the
        # fast-path discovery scan; collect evicted names and pop AFTER the loop.
        warn_ms = cfg.get("regex_warn_ms", REGEX_WARN_MS_DEFAULT)
        evict_ms = cfg.get("regex_evict_ms", REGEX_EVICT_MS_DEFAULT)
        to_evict: list[str] = []
        for _k in cand:
            r = regex_db.get(_k)
            if r is None:  # evicted since the index was built -> skip (safe)
                continue
            pattern = r.get("re") if isinstance(r, dict) else r
            match, elapsed_ms = _regex_timed_search(pattern, q_name)
            if _regex_should_evict(_k, elapsed_ms, warn_ms, evict_ms, "DNSBL_Regex", _k):
                to_evict.append(_k)
                continue
            if match:
                band = _block_entry_band(r)
                if band > best:
                    best, best_meta = band, {"kind": "regex", "key": _k}
        if to_evict:
            _regex_evict_names(regex_db, to_evict)
    return best, best_meta


def _scan_allow_regex_band(
    q_name: str,
    allow_regex_db: dict[str, Any],
    warn_ms: float = REGEX_WARN_MS_DEFAULT,
    evict_ms: float = REGEX_EVICT_MS_DEFAULT,
) -> int:
    """Highest allow band over the allow-regex (@@/re/) entries that match ``q_name``;
    0 if none match. Values mirror regexDB's tolerant shape: a bare compiled pattern,
    or a {"re", "important", "band"} payload. Iterates a SNAPSHOT (list(...)) and TIMES
    each match (ADR-07): over the warn ceiling logs once, over the evict ceiling is
    removed from the live allow-regex DB AFTER the loop (snapshot-iterate, evict-after-
    loop -- the same warn/evict policy as the block-regex scans; fact 3)."""
    if not q_name:
        return 0
    # Literal-prefilter: same necessary-condition guard as _scan_block_band (see
    # that function's comment).  Separate cache slot keyed to allow_regex_db's identity.
    global _allow_regex_index
    if _allow_regex_index is None or _allow_regex_index[0] is not allow_regex_db:
        _ai_buckets, _ai_always = _build_regex_index(allow_regex_db)
        _allow_regex_index = (allow_regex_db, _ai_buckets, _ai_always)
    _ai_buckets, _ai_always = _allow_regex_index[1], _allow_regex_index[2]
    q_lower = q_name.lower()
    cand: set[str] = set(_ai_always)
    for _ch in set(q_lower):
        _b = _ai_buckets.get(_ch)
        if _b:
            for _name, _lit in _b:
                if _lit in q_lower:
                    cand.add(_name)
    best = 0
    to_evict: list[str] = []
    for _k in cand:
        r = allow_regex_db.get(_k)
        if r is None:  # evicted since the index was built -> skip (safe)
            continue
        pattern = r.get("re") if isinstance(r, dict) else r
        match, elapsed_ms = _regex_timed_search(pattern, q_name)
        if _regex_should_evict(_k, elapsed_ms, warn_ms, evict_ms, "DNSBL_AllowRegex", _k):
            to_evict.append(_k)
            continue
        if match:
            important = bool(r.get("important", False)) if isinstance(r, dict) else False
            band = r.get("band") if isinstance(r, dict) else None
            if not isinstance(band, int):
                band = _allow_priority(important)
            best = max(best, band)
    if to_evict:
        _regex_evict_names(allow_regex_db, to_evict)
    return best


def whitelist_lookup_band(name: str, white_db: dict[str, Any], tld_seg: int) -> int:
    """Highest whiteDB allow band that matches ``name`` (exact, ``www.``-strip, then
    the wildcard suffix walk gated by ``tld_seg``); 0 if no whitelist entry matches.
    A user whitelist / TOP1M entry is band 6; a feed @@/reduced-allow entry carries
    its reconciled band (2 or 4). The match algorithm is identical to
    whitelist_lookup_domain; this variant returns the numeric band for the 6-band
    resolution instead of a bare ``important`` bool."""
    entry = white_db.get(name)
    if entry is not None:
        return _white_entry_band(entry)
    if name.startswith("www."):
        entry = white_db.get(name[4:])
        if entry is not None:
            return _white_entry_band(entry)
    best = 0
    q = name.split(".", 1)[-1]
    for x in range(q.count(".") + 1, 0, -1):
        if x >= tld_seg:
            entry = white_db.get(q)
            if entry is not None and _white_entry_wildcard(entry):
                best = max(best, _white_entry_band(entry))
        q = q.split(".", 1)[-1]
    return best


def _resolve_numeric_allow(
    q_name: str,
    q_name_original: str,
    is_cname: bool,
    cfg: dict[str, Any],
    white_db: dict[str, Any],
    allow_regex_db: dict[str, Any],
    block_band: int,
) -> bool:
    """Numeric 6-band resolution (ADR.md SS2): return True iff an ALLOW overrides the
    matched BLOCK (i.e. the name resolves) -- mapped onto ``in_whitelist`` so the
    downstream hsts/null-blocking logic is shared with the fast path.

    A block always matched here (the caller gates on ``is_found``); ``block_band`` is
    its highest matching band (computed by the caller over data/zone/block-regex).
    Blocked iff ``block_band > allow_band``; with no allow match ``allow_band`` is 0
    so the block stands. Engaged only when ``important_rules`` is True (an ABP
    $important / feed @@ / feed regex was loaded); proven against the 6-band precedence
    table by synthetic-payload unit tests and the production ABP equivalence tests.
    """
    allow_band = 0
    names = [q_name] + ([q_name_original] if is_cname else [])
    if cfg["whiteDB"]:
        for n in names:
            allow_band = max(allow_band, whitelist_lookup_band(n, white_db, cfg["python_tld_seg"]))

    if cfg.get("allowRegexDB", False):
        allow_band = max(
            allow_band,
            _scan_allow_regex_band(
                q_name,
                allow_regex_db,
                cfg.get("regex_warn_ms", REGEX_WARN_MS_DEFAULT),
                cfg.get("regex_evict_ms", REGEX_EVICT_MS_DEFAULT),
            ),
        )

    return allow_band >= block_band


def evaluate_domain(
    q_name: str,
    q_name_original: str,
    tld: str,
    is_cname: bool,
    cfg: dict[str, Any],
    containers: dict[str, Any],
) -> DnsblDecision:
    is_found = False
    log_type: Any = False
    in_whitelist = False
    in_hsts = False
    null_blocking = True
    nxdomain = False
    b_type = "Python"
    p_type = "Python"
    feed: Any = "Unknown"
    group: Any = "Unknown"
    b_eval = ""
    # ADR-08: a Confusable-mode ALERT (non-blocking) records its attribution here
    # so operate() can log it while the name still resolves; None on the common path.
    idn_alert: Any = None
    # The dual-form description of a Confusable BLOCK (xn-- [decoded] script), captured in
    # the IDN branch and written into b_eval AFTER the generic "b_eval = q_name" below, so
    # the log line is actionable instead of the bare A-label.
    idn_block_b_eval: str | None = None

    # ``block_band`` carries the discovered block's numeric band (1-5) into the numeric
    # resolution below; it stays at the feed-block default on the fast path. The fast
    # path never reads it (the historical "allow overrides block" early-exit).
    block_band = 0

    data_db: dict[str, Any] = containers["dataDB"]
    zone_db: dict[str, Any] = containers["zoneDB"]
    white_db: dict[str, Any] = containers["whiteDB"]
    regex_db: dict[str, Any] = containers["regexDB"]
    allow_regex_db: dict[str, Any] = containers.get("allowRegexDB", {})
    feed_group_index_db: dict[int, Any] = containers["feedGroupIndexDB"]
    hsts_db: dict[str, Any] = containers["hstsDB"]

    # STEP A/B/C strata (ADR.md SS2): user-allow / user-block / feed rules. Provenance
    # is not tagged on loaded entries yet, so today's discovery is structurally the
    # feed stratum -- data (exact) -> zone (wildcard) -> tld-allow -> idn -> block-regex.
    if cfg["python_blocking"]:
        if cfg["dataDB"]:
            data_entry = data_db.get(q_name)
            if data_entry is not None:
                is_found = True
                log_type = data_entry["log"]
                feed, group = resolve_feed_group(data_entry["index"], feed_group_index_db)
                b_type = "DNSBL"
                b_eval = q_name
                block_band = _block_entry_band(data_entry)

        if not is_found and cfg["zoneDB"]:
            matched_q, zone_entry = find_zone_match(q_name, zone_db)
            if matched_q is not None and zone_entry is not None:
                is_found = True
                log_type = zone_entry["log"]
                feed, group = resolve_feed_group(zone_entry["index"], feed_group_index_db)
                b_type = "TLD"
                b_eval = matched_q
                block_band = _block_entry_band(zone_entry)

    if not is_found:
        if (
            cfg["python_tld"]
            and cfg["python_tlds"]
            and tld != ""
            and q_name not in (cfg["dnsbl_ipv4"], cfg["dnsbl_ipv6"])
            and tld not in cfg["python_tlds"]
        ):
            is_found = True
            feed = "TLD_Allow"
            group = "DNSBL_TLD_Allow"
            # Feed-stratum block band (mirrors the IDN arms below): without it
            # block_band stays 0, and the numeric important_rules resolution
            # (_resolve_numeric_allow: blocked iff block_band > allow_band) would treat
            # band 0 as already overridden by any allow (allow_band >= 0 is always true),
            # so a disallowed-TLD query would resolve instead of being blocked.
            block_band = PRIO_FEED_BLOCK

        # ADR-08: the IDN feed. ``idn_mode`` is the three-valued selector (IdnMode enum
        # internally); derive it from the legacy cfg["python_idn"] when a cfg predates the
        # key (legacy callers/tests still pass only python_idn -- True->All-IDN).  The
        # explicit None check is REQUIRED: IdnMode.Off is truthy so an ``or`` idiom would
        # bypass the stored value whenever Off is present (ADR-28 landmine fix).
        if not is_found:
            _raw = cfg.get("idn_mode")
            if isinstance(_raw, IdnMode):
                idn_mode = _raw
            elif isinstance(_raw, str) and _raw in (IDN_MODE_OFF, IDN_MODE_ALL, IDN_MODE_CONFUSABLE):
                idn_mode = IdnMode(_raw)
            else:
                # None (key absent) or unrecognised string -> legacy fallback preserving
                # the pre-ADR-08 behaviour (python_idn=True -> All-IDN, False -> Off).
                idn_mode = idn_mode_from_legacy(cfg.get("python_idn", False))
            # All-IDN / Off arm -- BYTE-IDENTICAL to today (the golden gate):
            # idn_mode_decision blocks IFF All-IDN on an xn-- query, as the old inline test.
            if idn_mode_decision(q_name, idn_mode):
                is_found = True
                feed = "IDN"
                group = "DNSBL_IDN"
                # An IDN block is a feed-stratum block: give it the feed band so the
                # numeric important_rules path doesn't treat block_band=0 as already
                # overridden (allow_band >= 0 is always true) and resolve it anyway.
                block_band = PRIO_FEED_BLOCK
            elif idn_mode is IdnMode.Confusable:
                # Confusable arm: decode + TR39 mixed-script analysis, PER-LABEL,
                # gated by is_idn_domain (a non-xn-- query pays nothing). classify_idn is
                # decode-safe -- a malformed label is FLAGGED, never raised into the resolver.
                action, verdict = idn_confusable_action(
                    q_name,
                    block_malicious=cfg.get("python_idn_block_malicious", True),
                    escalate_suspicious=cfg.get("python_idn_escalate_suspicious", False),
                )
                if action == IDN_ACT_BLOCK and verdict is not None:
                    # Malicious (or escalated suspicious/flagged) -> block. Distinct
                    # feed/group so it is attributed apart from the blunt All-IDN feed.
                    is_found = True
                    # Feed-stratum block band (see the All-IDN arm above) so the
                    # numeric important_rules resolution honours the homoglyph block.
                    block_band = PRIO_FEED_BLOCK
                    if verdict.severity == SEV_MALICIOUS:
                        feed = IDN_FEED_MALICIOUS
                        group = IDN_GROUP_MALICIOUS
                    else:
                        feed = IDN_FEED_SUSPECT
                        group = IDN_GROUP_SUSPECT
                    idn_block_b_eval = _idn_dual_form(verdict)
                elif action == IDN_ACT_ALERT and verdict is not None:
                    # Suspicious/flagged (or malicious with block disabled) -> ALERT only:
                    # the name still resolves (is_found stays False); record the attribution
                    # so operate() emits a log line in the block-line shape (dual-form b_eval).
                    is_malicious = verdict.severity == SEV_MALICIOUS
                    idn_alert = (
                        IDN_FEED_MALICIOUS if is_malicious else IDN_FEED_SUSPECT,
                        IDN_GROUP_MALICIOUS if is_malicious else IDN_GROUP_SUSPECT,
                        _idn_dual_form(verdict),
                    )
                # IDN_ACT_NONE (legit, or a non-xn-- name) -> no IDN action, resolves.

        if not is_found and cfg["regexDB"] and q_name:
            # Snapshot-iterate (list(...)) so the runtime eviction can mutate the live
            # regexDB without corrupting this scan (fact 3). Each match is TIMED (per-
            # thread CPU); a pattern over the warn ceiling logs once, over the evict
            # ceiling is removed from the live DB AFTER the loop -- so it cannot hang
            # twice (the accepted residual is the single slow first-hit; fact 2).
            warn_ms = cfg.get("regex_warn_ms", REGEX_WARN_MS_DEFAULT)
            evict_ms = cfg.get("regex_evict_ms", REGEX_EVICT_MS_DEFAULT)
            to_evict: list[str] = []
            for k, r in list(regex_db.items()):
                # regexDB values may be a bare compiled pattern (today / user-regex) or
                # a {"re", "important", "band"} payload (ABP feed block-regex). Read
                # both shapes; the bare-pattern path is byte-identical to today.
                pattern = r.get("re") if isinstance(r, dict) else r
                match, elapsed_ms = _regex_timed_search(pattern, q_name)
                if _regex_should_evict(k, elapsed_ms, warn_ms, evict_ms, "DNSBL_Regex", k):
                    to_evict.append(k)
                    continue
                if match:
                    is_found = True
                    feed = k
                    group = "DNSBL_Regex"
                    block_band = _block_entry_band(r)
                    break
            if to_evict:
                _regex_evict_names(regex_db, to_evict)

        if is_found:
            b_eval = q_name
            log_type = "1"
            # ADR-08: a Confusable BLOCK reports the dual-form (xn-- [decoded] script)
            # instead of the bare A-label, so the dnsbl.log line / alerts page are
            # actionable. Only set on the homoglyph block path; the All-IDN feed and every
            # other stratum keep b_eval = q_name untouched.
            if idn_block_b_eval is not None:
                b_eval = idn_block_b_eval

    # Resolution stratum. FAST PATH (important_rules False): the historical "a block is
    # found, then an allow overrides it" -- whiteDB checked as a plain override,
    # byte-for-byte the pre-ABP matcher; this is the path when no ABP @@/regex/$important
    # is loaded. The numeric 6-band resolution is the important_rules==True branch -- it
    # IS reached in production once an ABP feed (or user regex / Custom_List) loads a
    # feed @@ / $important / feed-regex (ADR-07 wired it; not just synthetic tests).
    if is_found:
        if not cfg.get("important_rules", False):
            if cfg["whiteDB"]:
                names = [q_name] + ([q_name_original] if is_cname else [])
                in_whitelist = any(whitelist_check_domain(n, white_db, cfg["python_tld_seg"]) for n in names)
        else:
            # NUMERIC 6-band path (an ABP $important / feed @@ / feed regex is loaded).
            # decide() resolves by the HIGHEST matching block band vs the highest
            # matching allow band, so augment the first-discovered block's band with a
            # full scan over every matching block (data/zone-suffix/block-regex) -- the
            # discovery above short-circuits on the first hit (right for metadata, but
            # the resolution needs the max band). When a STRICTLY higher band wins,
            # re-attribute feed/group/log_type/b_type/b_eval to that entry (issue #47):
            # the band decides priority, but reporting AND the response shape (log_type
            # -> null_blocking below) must follow the rule that actually won, not the
            # first discovered. A tie keeps the discovered attribution (block bands are
            # distinct odds, so a tie is the same entry / same priority).
            scan_band, scan_meta = _scan_block_band(q_name, cfg, data_db, zone_db, regex_db)
            if scan_meta is not None and scan_band > block_band:
                block_band = scan_band
                if scan_meta["kind"] == "regex":
                    feed = scan_meta["key"]
                    group = "DNSBL_Regex"
                    log_type = "1"
                    b_type = "Python"
                    b_eval = q_name
                else:
                    entry = scan_meta["entry"]
                    log_type = entry["log"]
                    feed, group = resolve_feed_group(entry["index"], feed_group_index_db)
                    if scan_meta["kind"] == "zone":
                        b_type = "TLD"
                        b_eval = scan_meta["matched"]
                    else:  # data
                        b_type = "DNSBL"
                        b_eval = q_name
            in_whitelist = _resolve_numeric_allow(
                q_name,
                q_name_original,
                is_cname,
                cfg,
                white_db,
                allow_regex_db,
                block_band,
            )

    if is_found and not in_whitelist:
        if cfg["hstsDB"]:
            in_hsts, p_type = hsts_check_domain(q_name, hsts_db, cfg["hsts_tlds"], tld)

        if log_type == "1" and not in_hsts:
            null_blocking = False
        # issue #31: NXDOMAIN block shape ("3" logged / "4" silent). It bypasses the
        # synthesized A/AAAA reply entirely, so the HSTS null-override above does not
        # apply (NXDOMAIN never triggers a TLS handshake). null_blocking stays True so
        # the per-event logger does not treat it as a VIP block (get_details_dnsbl).
        # HSTS played no part in this decision, so clear the attribution hsts_check_domain
        # set above -- otherwise an NXDOMAIN block on an HSTS-listed name would mislog its
        # p_type as HSTS / HSTS_TLD (the response shape is right, the "why" would be wrong).
        elif log_type in ("3", "4"):
            in_hsts = False
            p_type = "Python"
            nxdomain = True

        if is_cname:
            b_type = b_type + "_CNAME"

    return DnsblDecision(
        is_found=is_found,
        in_whitelist=in_whitelist,
        in_hsts=in_hsts,
        null_blocking=null_blocking,
        nxdomain=nxdomain,
        log_type=log_type,
        b_type=b_type,
        p_type=p_type,
        feed=feed,
        group=group,
        b_eval=b_eval,
        idn_alert=idn_alert,
    )


def evaluate_noaaaa(q_name: str, noaaaa_db: dict[str, Any]) -> bool:
    if noaaaa_db.get(q_name) is not None:
        return True
    return find_noaaaa_wildcard_parent(q_name, noaaaa_db) is not None


def _load_safesearch_db() -> None:
    """Parse the SafeSearch Redirection CSV (``pfb["pfb_py_ss"]``) into ``safeSearchDB``.

    Extracted out of ``init_standard`` (#714 FIX #6) so the load -- and its failure
    diagnostic -- are unit-testable without the full Unbound ``env``/``id`` init rig.
    Behaviour-preserving: same parse rules, same ``pfb["safeSearchDB"]`` flag.
    """
    if os.path.isfile(pfb["pfb_py_ss"]):
        try:
            with open(pfb["pfb_py_ss"]) as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=",")
                for row in csv_reader:
                    # 3 cols: domain,A,AAAA (A/AAAA rewrite or nxdomain).
                    # 5 cols: domain,cname,target,baked_v4,baked_v6 -- a CNAME
                    # redirect (issue #149); v4/v6 are the #2 baked fallback IPs.
                    if row and len(row) == 3:
                        safeSearchDB[row[0]] = {"A": row[1], "AAAA": row[2]}
                    elif row and len(row) == 5:
                        safeSearchDB[row[0]] = {"A": row[1], "AAAA": row[2], "v4": row[3], "v6": row[4]}
                    else:
                        sys.stderr.write("[pfBlockerNG]: Failed to parse: {}: {}".format(pfb["pfb_py_ss"], row))

                pfb["safeSearchDB"] = True
            pfb_py_status_close("dnsbl", pfb["pfb_py_ss"], "parse")
        except Exception as e:
            # #714 FIX #6: name the SafeSearch source (pfb_py_ss), not pfb_py_zone -- a
            # copy-paste leftover from the zone-list loader below sent a real SafeSearch
            # load failure diagnostic at the wrong file.
            sys.stderr.write("[pfBlockerNG]: Failed to load: {}: {}".format(pfb["pfb_py_ss"], e))
            pfb_py_status_open("dnsbl", pfb["pfb_py_ss"], "parse", "Failed to load: {}: {}".format(pfb["pfb_py_ss"], e))
    else:
        pfb_py_status_close("dnsbl", pfb["pfb_py_ss"], "parse")


def safesearch_entry(q_name_original: str) -> Any:
    """Look up (and memoize on the Decision) the SafeSearch entry for a name.

    Returns the matched ``{A, AAAA, ...}`` dict, or ``None`` for no match. The
    verdict is memoized on the name's Decision (safesearch axis): ``UNSET`` = not
    yet evaluated, the dict = rewrite, ``None`` = no match (the old excludeSS
    negative memo). Shared by the pre-resolution (NEW) and post-resolution
    (MODDONE, CNAME redirect) passes so both agree on the same memoized verdict.
    """
    dec = _decision_for(q_name_original, _snapshot.gen)
    if dec.safesearch is UNSET:
        entry = safeSearchDB.get(q_name_original)
        # Validate 'www.' Domains
        if entry is None and not q_name_original.startswith("www."):
            entry = safeSearchDB.get("www." + q_name_original)
        dec.safesearch = entry
    return dec.safesearch


def _ss_answer_has_cname_to(qstate: module_qstate, target: str) -> bool:
    """True if the resolved answer carries a CNAME pointing at ``target``.

    Identifies the post-restart pass of the SafeSearch CNAME redirect: the
    iterator has chased the ``orig -> CNAME -> target`` referral we planted, so
    the answer now contains that CNAME. A genuine answer for the original name
    would not CNAME to our SafeSearch target.
    """
    rm = getattr(qstate, "return_msg", None)
    if rm is None or getattr(rm, "rep", None) is None:
        return False
    rep = rm.rep
    target = target.rstrip(".").lower()
    for i in range(0, rep.an_numrrsets or 0):
        rr = rep.rrsets[i]
        if rr.rk.type_str != "CNAME":
            continue
        for j in range(0, rr.entry.data.count):
            if convert_other(rr.entry.data.rr_data[j]).rstrip(".").lower() == target:
                return True
    return False


def _ss_answer_has_address(qstate: module_qstate) -> bool:
    """True if the resolved answer carries at least one A/AAAA RRset.

    On the post-restart pass this means the iterator successfully chased the
    CNAME to the target's address (the #1 live path); its absence means the
    chase produced only a bare CNAME and the #2 baked fallback must answer.
    """
    rm = getattr(qstate, "return_msg", None)
    if rm is None or getattr(rm, "rep", None) is None:
        return False
    rep = rm.rep
    for i in range(0, rep.an_numrrsets or 0):
        if rep.rrsets[i].rk.type_str in ("A", "AAAA"):
            return True
    return False


def _safesearch_baked_fallback(id: int, qstate: module_qstate, q_type: Any, isSafeSearch: Any) -> bool:
    """#2 fallback: answer a SafeSearch CNAME name with the baked target IP.

    Used when the #1 live chase yields no address (this Unbound refuses to chase
    a module-planted CNAME, or the target failed to resolve). The baked v4/v6 are
    resolved by PHP at list-build and kept ~15-min-fresh by the freshness cron.
    Returns True if it answered (caller must ``return True``), False to fall
    through (no baked IP available for this qtype).
    """
    ip = isSafeSearch.get("v4") if q_type == RR_TYPE_A else isSafeSearch.get("v6")
    if not ip:
        return False
    rrtype = "A" if q_type == RR_TYPE_A else "AAAA"
    qname = qstate.qinfo.qname_str
    msg = DNSMessage(qname, q_type, RR_CLASS_IN, PKT_QR | PKT_RA)
    msg.answer.append("{} 300 IN {} {}".format(qname, rrtype, ip))
    if not msg.set_return_msg(qstate):
        qstate.ext_state[id] = MODULE_ERROR
        return True
    qstate.return_rcode = RCODE_NOERROR
    # Synthesized, deliberately unsigned -> stop the validator marking it bogus.
    qstate.return_msg.rep.security = sec_status_insecure
    qstate.ext_state[id] = MODULE_FINISHED
    return True


def safesearch_cname_redirect(id: int, qstate: module_qstate, q_type: Any, isSafeSearch: Any) -> bool:
    """SafeSearch CNAME redirect (e.g. duckduckgo.com -> safe.duckduckgo.com).

    Unbound will not chase a CNAME a module hands it (NLnetLabs/unbound #976), so
    this uses the field-proven nxforward technique post-resolution (MODDONE):

      1. First pass: plant the synthetic ``orig -> CNAME -> target`` into
         Unbound's message cache as a REFERRAL and restart the iterator
         (MODULE_RESTART_NEXT) so the ITERATOR chases the target's A/AAAA itself.
         If the plant fails to store (real Unbound's silent falsy failure --
         issue #749), restarting would chase a referral that was never actually
         cached, so this falls back to the baked target IP (#2) instead -- never
         MODULE_RESTART_NEXT on a failed store.
      2. Post-restart pass (the answer now carries our CNAME): if the chase
         produced an address, force ``rep.security`` so the unsigned synthesized
         hop is not marked bogus (the historical DNSSEC blocker, issue #149),
         re-cache as a final answer and finish -- a failure to re-cache here
         (issue #749) only means the chased answer isn't cached, not that the
         already-built, already-validated reply is invalid, so it still
         finishes; if the chase produced no address, fall back to the baked
         target IP (#2).

    Runs only for A/AAAA queries. Returns True if it took over the query (caller
    must ``return True``), False to let normal processing continue.
    """
    target = isSafeSearch.get("AAAA")
    if not target or q_type not in (RR_TYPE_A, RR_TYPE_AAAA):
        return False

    # Post-restart pass: the iterator has chased our planted CNAME.
    if _ss_answer_has_cname_to(qstate, target):
        if _ss_answer_has_address(qstate):
            qstate.return_rcode = RCODE_NOERROR
            # The orig->target hop is synthesized (unsigned); without this the
            # validator marks a signed original zone bogus -> SERVFAIL (issue #149).
            qstate.return_msg.rep.security = sec_status_insecure
            invalidateQueryInCache(qstate, qstate.qinfo)
            qstate.no_cache_store = 0
            if not storeQueryInCache(qstate, qstate.qinfo, qstate.return_msg.rep, 0):
                # A cache-store failure must not SERVFAIL an already-built, already-
                # validated answer -- log it and finish anyway (issue #749).
                log_info(
                    "[pfBlockerNG]: SafeSearch: failed to re-cache chased answer for {}".format(qstate.qinfo.qname_str)
                )
            qstate.ext_state[id] = MODULE_FINISHED
            return True
        # #1 chase yielded only a bare CNAME -> #2 baked fallback.
        return _safesearch_baked_fallback(id, qstate, q_type, isSafeSearch)

    # First pass: plant the synthetic CNAME referral and restart the iterator.
    qname = qstate.qinfo.qname_str
    cname_msg = DNSMessage(qname, q_type, RR_CLASS_IN, PKT_QR | PKT_RD | PKT_RA)
    cname_msg.answer.append("{} 3600 IN CNAME {}".format(qname, target))
    if not cname_msg.set_return_msg(qstate):
        qstate.ext_state[id] = MODULE_ERROR
        return True
    invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
    if not storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 1):
        # The planted referral isn't actually in cache -- restarting the iterator
        # would chase nothing and fruitlessly loop back into this first pass
        # (issue #749). Fall back to the baked target IP instead of restarting.
        log_info("[pfBlockerNG]: SafeSearch: failed to store planted CNAME referral for {}".format(qname))
        if _safesearch_baked_fallback(id, qstate, q_type, isSafeSearch):
            return True
        qstate.ext_state[id] = MODULE_ERROR
        return True
    qstate.no_cache_store = 1
    qstate.ext_state[id] = MODULE_RESTART_NEXT
    return True


def operate(id: int, event: int, qstate: module_qstate, qdata: Any) -> bool:
    global pfb, dataDB, zoneDB, hstsDB, whiteDB, decisionDB
    global noAAAADB, gpListDB, safeSearchDB

    qstate_valid = False
    q_type: Any = None
    q_name_original = ""
    q_ip = ""
    try:
        if qstate is not None and qstate.qinfo.qtype is not None:
            qstate_valid = True
            q_type = qstate.qinfo.qtype
            q_name_original = get_q_name_qstate(qstate).lower()
            q_ip = get_q_ip(qstate)
        else:
            sys.stderr.write("[pfBlockerNG] qstate is not None and qstate.qinfo.qtype is not None")
    except Exception as e:
        sys.stderr.write("[pfBlockerNG] qstate_valid: {}: {}".format(event, e))
        pass

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        # no AAAA validation. The verdict is memoized on the name's Decision (noaaaa
        # axis): UNSET = not yet evaluated, True = block, False = allow (the old
        # excludeAAAADB negative memo). No separate excludeAAAADB / noAAAADB-memo.
        if qstate_valid and q_type == RR_TYPE_AAAA and pfb["noAAAADB"]:
            dec = _decision_for(q_name_original, _snapshot.gen)
            if dec.noaaaa is UNSET:
                dec.noaaaa = evaluate_noaaaa(q_name_original, noAAAADB)

            # Create FQDN Reply Message (AAAA -> A)
            if dec.noaaaa:
                msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA)
                if msg is None or not msg.set_return_msg(qstate):
                    qstate.ext_state[id] = MODULE_ERROR
                    return True

                qstate.return_rcode = RCODE_NOERROR
                qstate.return_msg.rep.security = 2
                qstate.ext_state[id] = MODULE_FINISHED
                return True

        # SafeSearch Redirection validation
        if qstate_valid and pfb["safeSearchDB"]:
            isSafeSearch = safesearch_entry(q_name_original)

            if isSafeSearch is not None:
                ss_found = False
                msg = None
                if isSafeSearch["A"] == "nxdomain":
                    qstate.return_rcode = RCODE_NXDOMAIN
                    qstate.ext_state[id] = MODULE_FINISHED
                    return True

                # CNAME redirect (duckduckgo.com / pixabay.com) is deferred to the
                # post-resolution MODDONE pass (safesearch_cname_redirect): Unbound
                # will not chase a CNAME we hand it here (issue #149 / unbound #976),
                # so we plant it in the cache and let the iterator chase the target.
                elif isSafeSearch["A"] == "cname":
                    pass
                else:
                    if (q_type == RR_TYPE_A and isSafeSearch["A"] != "") or (
                        q_type == RR_TYPE_AAAA and isSafeSearch["AAAA"] == ""
                    ):
                        msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA)
                        msg.answer.append("{} 300 IN {} {}".format(qstate.qinfo.qname_str, "A", isSafeSearch["A"]))
                        ss_found = True
                    elif q_type == RR_TYPE_AAAA and isSafeSearch["AAAA"] != "":
                        msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_AAAA, RR_CLASS_IN, PKT_QR | PKT_RA)
                        msg.answer.append(
                            "{} 300 IN {} {}".format(qstate.qinfo.qname_str, "AAAA", isSafeSearch["AAAA"])
                        )
                        ss_found = True

                if ss_found:
                    if msg is None or not msg.set_return_msg(qstate):
                        qstate.ext_state[id] = MODULE_ERROR
                        return True

                    qstate.return_rcode = RCODE_NOERROR
                    qstate.return_msg.rep.security = 2
                    qstate.ext_state[id] = MODULE_FINISHED
                    return True

        # Python_control - Receive TXT commands from pfSense local IP
        # PFBL-03: DEPRECATED legacy DNS-TXT control transport. Inert unless the operator
        # explicitly opts back in via ``python_control_legacy``; OFF by default, no DNSBL
        # control command is honoured over DNS-TXT. DNSBL control is CLI-driven
        # (pfblockerng dnsbl-control ...) over the local privileged command file. This whole
        # branch is deprecated and will be removed in a future release.
        if (
            pfb["python_control_legacy"]
            and qstate_valid
            and q_type == RR_TYPE_TXT
            and q_name_original.startswith("python_control.")
        ):
            control_rcd = False
            control_msg = ""
            # PFBL-03: accept the loopback address over either family (the old check was IPv4-only).
            if pfb["python_control"] and q_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                control_command = q_name_original.split(".")
                # PFBL-03: route to the SINGLE shared handler (also used by the local
                # privileged command channel) -- one implementation of the grammar.
                control_rcd, control_msg = pfb_apply_control_command(control_command)

                if control_rcd:
                    q_reply = "python_control"
                else:
                    if control_msg == "":
                        control_msg = "Python_control: Command not authorized! [ {} ]".format(q_name_original)
                    q_reply = "python_control_fail"

                txt_msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_TXT, RR_CLASS_IN, PKT_QR | PKT_RA)
                txt_msg.answer.append('{}. 0 IN TXT "{}"'.format(q_reply, control_msg))

                if txt_msg is None or not txt_msg.set_return_msg(qstate):
                    qstate.ext_state[id] = MODULE_ERROR
                    return True

                qstate.return_rcode = RCODE_NOERROR
                qstate.return_msg.rep.security = 2
                qstate.ext_state[id] = MODULE_FINISHED
                return True

    # DNSBL Validation for specific RR_TYPES only
    if qstate_valid and pfb["python_blacklist"] and q_type in pfb["rr_types"]:
        # Group Policy - Bypass DNSBL Validation
        bypass_dnsbl = False
        if pfb["gpListDB"]:
            q_ip = get_q_ip(qstate)

            if q_ip != "Unknown":
                isgpBypass = gpListDB.get(q_ip)

                if isgpBypass is not None:
                    bypass_dnsbl = True

        # ADR-10: capture the ONE live matcher snapshot ref for this query. Every
        # name in this query (the original + any CNAME-chain targets) is evaluated
        # against this single immutable snapshot, so a swap that rebinds ``_snapshot``
        # mid-query never tears a decision across names (ADR.md SS2 atomic-swap shape).
        snap = _snapshot

        # Create list of Domain/CNAMES to be evaluated
        validate = []

        # Skip 'in-addr.arpa' domains
        if not q_name_original.endswith(".in-addr.arpa") and not bypass_dnsbl:
            validate.append(q_name_original)

            # DNSBL CNAME Validation
            if pfb["python_cname"] and qstate.return_msg:
                r = qstate.return_msg.rep
                if r.an_numrrsets > 1:
                    for i in range(0, r.an_numrrsets):
                        rr = r.rrsets[i]

                        if rr.rk.type_str != "CNAME":
                            continue

                        for j in range(0, rr.entry.data.count):
                            # #714 FIX #3: compare the is_unknown() sentinel BEFORE
                            # lowering it. convert_other() returns the literal "Unknown"
                            # (capital U) on decode failure; lowering first turns it into
                            # "unknown", which never equals "Unknown", so the guard became
                            # a no-op and the bogus "unknown" string was DNSBL-evaluated.
                            domain = convert_other(rr.entry.data.rr_data[j])
                            if domain != "Unknown":
                                validate.append(domain.lower())

        isCNAME = False
        for val_counter, q_name in enumerate(validate, start=1):
            if val_counter > 1:
                isCNAME = True

            # One coherent verdict per name in decisionDB: a block, OR an allow
            # ("let Unbound resolve it" / whitelisted) -- both are decisions, both
            # are memoized. A repeat query (including a CNAME-blocked name, keyed on
            # the original) short-circuits here without re-resolving or re-evaluating.
            # issue #1074: a foreign-generation memo is stale -- a thread racing
            # rebuild_and_swap's clear() can re-insert an old-snapshot verdict after
            # the swap, so the stamp, not mere presence, decides validity.
            dec = decisionDB.get(q_name)
            dnsbl = dec.dnsbl if dec is not None and dec.snap_gen == snap.gen else UNSET
            if dnsbl is UNSET:
                # The original query's TLD comes from qstate; a CNAME target (isCNAME)
                # has its own TLD, so derive it from the target name being evaluated --
                # else the TLD-Allow / HSTS checks use the wrong TLD for the target.
                tld = get_tld_from_name(q_name) if isCNAME else get_tld(qstate)
                # ADR-10: the per-stratum presence gates + the ``important_rules``
                # fast-path flag MUST come from the captured snapshot ``snap`` -- NOT from
                # the ``pfb[...]`` booleans, which are written ONLY in init_standard and are
                # NOT refreshed by a background swap. Reading them from ``pfb`` froze the
                # gate at the last restart's state: a zero-downtime swap that introduced a
                # NEW stratum (e.g. feed/user regex, or data/zone when the prior init had
                # none) left its gate False, so evaluate_domain skipped that stratum and the
                # newly-swapped block never applied (the regex/important/custom-list smoke
                # failures). Deriving them from ``snap`` (the same object the dicts come
                # from) keeps the gate consistent with the live lists on every swap, and is
                # decision-identical at idle (init sets snapshot + pfb flags together, so
                # bool(snap.data_db) == pfb["dataDB"], etc.). The remaining keys are genuine
                # config (not list-presence) and correctly stay sourced from ``pfb``.
                cfg = {
                    "python_blocking": pfb["python_blocking"],
                    "dataDB": bool(snap.data_db),
                    "zoneDB": bool(snap.zone_db),
                    "python_tld": pfb["python_tld"],
                    "python_tlds": pfb["python_tlds"],
                    "dnsbl_ipv4": pfb["dnsbl_ipv4"],
                    "dnsbl_ipv6": pfb["dnsbl_ipv6"],
                    "python_idn": pfb["python_idn"],
                    # ADR-08: derive defensively so a pfb that predates the key (a
                    # hand-edited ini, or a test seeding only python_idn) still resolves
                    # to today's mode rather than KeyError-ing.
                    "idn_mode": pfb.get("idn_mode") or idn_mode_from_legacy(pfb.get("python_idn", False)),
                    # ADR-08: the Confusable sub-toggles (only read in IDN_MODE_CONFUSABLE).
                    # Default-ON malicious block, opt-in suspicious escalation.
                    "python_idn_block_malicious": pfb.get("python_idn_block_malicious", True),
                    "python_idn_escalate_suspicious": pfb.get("python_idn_escalate_suspicious", False),
                    "regexDB": bool(snap.regex_db),
                    "whiteDB": bool(snap.white_db),
                    "allowRegexDB": bool(snap.allow_regex_db),
                    "important_rules": bool(snap.important_rules),
                    "regex_warn_ms": pfb["regex_warn_ms"],
                    "regex_evict_ms": pfb["regex_evict_ms"],
                    "python_tld_seg": pfb["python_tld_seg"],
                    "hstsDB": bool(snap.hsts_db),
                    "hsts_tlds": pfb["hsts_tlds"],
                }
                # ADR-10: read every matcher stratum off the ONE captured snapshot
                # ref (``snap``, taken once at the top of this per-name loop) instead of
                # re-assembling ``containers`` from separate module globals. ``snap`` is
                # immutable for this query, so a swap that rebinds ``_snapshot`` mid-query
                # cannot tear this decision (consistent-by-construction, ADR.md SS2).
                containers = snap.containers()
                dnsbl = evaluate_domain(q_name, q_name_original, tld, isCNAME, cfg, containers)

                # A block found via a CNAME chain is recorded against the ORIGINAL
                # queried name, so a later query for it short-circuits on this entry.
                if dnsbl.is_found and not dnsbl.in_whitelist and isCNAME:
                    q_name = q_name_original

                # Memoize the DNSBL verdict on the name's Decision (block OR allow), so
                # this name is decided once; the other axes share the same entry. The
                # memo is stamped with THIS query's snapshot generation (issue #1074).
                _decision_for(q_name, snap.gen).dnsbl = dnsbl

                # Add domain data to DNSBL cache for Reports tab (fresh block only)
                if dnsbl.is_found and not dnsbl.in_whitelist:
                    pfb_db_enqueue(("cache", (dnsbl.b_type, q_name, dnsbl.group, dnsbl.b_eval, dnsbl.feed)))

                # ADR-08: a Confusable-mode ALERT (suspicious/flagged, or malicious with
                # block disabled) does NOT block -- the name resolves -- but the anomaly is
                # surfaced once, here on the fresh evaluation, in the same dnsbl.log shape as
                # a block (dual-form b_eval so it is actionable). A repeat query reuses the
                # cached decision and is not re-logged (the name resolves normally).
                elif dnsbl.idn_alert is not None:
                    _log_idn_alert(q_name, q_ip, dnsbl.idn_alert, get_q_type(qstate, None))

            # Block iff found and not whitelisted; an allow decision falls through to
            # the resolver (the WAIT_MODULE below).
            if dnsbl.is_found and not dnsbl.in_whitelist:
                # issue #31: NXDOMAIN block shape ("3" logged / "4" silent). Return a
                # bare NXDOMAIN rcode with NO answer records -- no DNSMessage, no
                # sinkhole IP, no DNSBL webserver redirect. Still attributed and logged
                # via get_details_dnsbl (which internally drops the log line for "4");
                # not cached, for the same #43 reasons as the VIP/null path below.
                if dnsbl.nxdomain:
                    get_details_dnsbl("dnsbl", None, qstate, None, {"pfb_addr": q_ip})
                    qstate.return_rcode = RCODE_NXDOMAIN
                    qstate.no_cache_store = 1
                    qstate.ext_state[id] = MODULE_FINISHED
                    return True

                # Create FQDN Reply Message
                msg = DNSMessage(qstate.qinfo.qname_str, q_type, RR_CLASS_IN, PKT_QR | PKT_RA)

                if q_type == RR_TYPE_A or q_type == RR_TYPE_ANY:
                    msg.answer.append(
                        "{}. 3600 IN A {}".format(q_name, "0.0.0.0" if dnsbl.null_blocking else pfb["dnsbl_ipv4"])
                    )
                if q_type == RR_TYPE_AAAA or q_type == RR_TYPE_ANY:
                    msg.answer.append(
                        "{}. 3600 IN AAAA {}".format(q_name, "::" if dnsbl.null_blocking else pfb["dnsbl_ipv6"])
                    )

                if msg is None or not msg.set_return_msg(qstate):
                    qstate.ext_state[id] = MODULE_ERROR
                    return True

                # Log entry
                kwargs = {"pfb_addr": q_ip}
                if qstate.return_msg:
                    get_details_dnsbl("dnsbl", None, qstate, qstate.return_msg.rep, kwargs)
                else:
                    get_details_dnsbl("dnsbl", None, qstate, None, kwargs)

                qstate.return_rcode = RCODE_NOERROR
                qstate.return_msg.rep.security = 2
                # Do not store the synthetic block reply in Unbound's C message cache
                # (#43). A cached block is served ahead of this module, so repeat queries
                # skip operate() -> the feed-attributed logger (get_details_dnsbl:
                # dnsbl.log + per-group counter) never runs and per-feed block stats
                # under-count; the cache-hit path logs only an unattributed DNS-reply. It
                # also keeps a cached 0.0.0.0/VIP serving for up to the TTL after a name is
                # removed from a list (block->allow staleness). The reply is synthetic, so
                # not caching it costs only the ~1us in-process matcher re-run (the
                # decisionDB memo still short-circuits re-evaluation), never an upstream
                # round-trip. Mirrors the SafeSearch CNAME path, the module's only other
                # no_cache_store.
                qstate.no_cache_store = 1
                qstate.ext_state[id] = MODULE_FINISHED
                return True

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        # SafeSearch CNAME redirect (duckduckgo.com / pixabay.com). Handled here,
        # post-resolution, because Unbound will not chase a CNAME the module hands
        # it (issue #149 / unbound #976): we plant the synthetic CNAME in the cache
        # and restart the iterator so it chases the target itself. The first pass
        # (plant + restart) and the second pass (fix DNSSEC + finish, or the baked
        # fallback) are distinguished inside safesearch_cname_redirect by the
        # resolved answer.
        if qstate_valid and pfb["safeSearchDB"]:
            isSafeSearch = safesearch_entry(q_name_original)
            if isSafeSearch is not None and isSafeSearch["A"] == "cname":
                if safesearch_cname_redirect(id, qstate, q_type, isSafeSearch):
                    return True

        # Log entry
        if qstate_valid and qstate.return_msg:
            kwargs = {"pfb_addr": q_ip}
            get_details_reply("reply", None, qstate, qstate.return_msg.rep, kwargs)
        else:
            get_details_reply("reply", None, qstate, None, None)

        qstate.ext_state[id] = MODULE_FINISHED
        return True

    log_err("[pfBlockerNG]: BAD event")
    qstate.ext_state[id] = MODULE_ERROR
    return True


log_info("[pfBlockerNG]: pfb_unbound.py script loaded")
