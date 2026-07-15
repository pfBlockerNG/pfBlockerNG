# ADR-03: Persistent sqlite connection + persistent log handles (eliminate per-call open/close)

- **Status:** **Accepted** (2026-06-15; implemented 2026-05-31) — persistent WAL connection + batched relative-increment writes (DB worker) and stdlib `QueueListener` + `WatchedFileHandler` logging. Log/DB CONTENT is pinned byte-identical off-box by the golden harness; the live persistent-logging IO path is now exercised on a real pfSense VM by `tests/smoke/test_smoke_matrix.py::test_dnsbl_block_writes_persistent_log_line` (a VIP block reaches `dnsbl.log` under the chrooted Unbound python loader), green on **CE 2.8 + Plus 26.03**. The old "no live Unbound in CI" blocker is void (ADR-04). (Originally IMPLEMENTED — pending smoke test, 2026-05-31.)
- **Date:** 2026-05-31
- **Branch:** `adr/03` (off `devel`)
- **Components:**
  - `src/usr/local/pkg/pfblockerng/pfb_unbound.py` — DB writes (`write_sqlite`) + file logging (`log_entry`), dispatched via the async worker.
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — PHP sqlite access (`pfb_open_sqlite`/`pfb_close_sqlite`, `pfBlockerNG_clearsqlite`) and log trimming (`pfb_log_mgmt`).
  - `src/usr/local/www/pfblockerng/pfblockerng_log.php` — log "clear" action.
- **Target runtime:** Python 3.11+ inside Unbound's `pythonmod` (stdlib only); PHP 8.3 (pfSense CE 2.8).
- **Test suite:** `tests/test_pfb_unbound.py`, `tests/conftest.py`.

---

## 1. Context

### Today

`pfb_unbound.py` runs inside Unbound's embedded Python. DB writes and log writes are pushed off the DNS-response path onto **one shared async worker thread** fed by a bounded `queue.Queue(5000)` (`pfb_async` / `pfb_async_worker`); the worker drops tasks when the queue is full (`async_dropped`) and `deinit` drains it with a 5s join. On that worker:

- **`write_sqlite()`** opens a **new `sqlite3` connection per call** (`connect(timeout=100s)`), runs `CREATE TABLE IF NOT EXISTS` *every time*, executes, `commit`s, and `close`s. Three DBs: `pfb_py_resolver.sqlite` (`resolver`), `pfb_py_dnsbl.sqlite` (`dnsbl`), `pfb_py_cache.sqlite` (`dnsblcache`). Per-call connect was a deliberate workaround (BBcan177) for connection-stability issues on pfSense.
- **`log_entry()`** does `open(append)` → write → `close` **per line** to `dnsbl.log`, `dns_reply.log`, `unified.log`. (`py_error.log` already goes through stdlib `logging` with a persistent handler.)

The async worker hides the latency, but the per-call `connect()`/`open()` syscalls are still wasteful.

### Constraints discovered (load-bearing)

1. **Threading model:** Unbound shares one Python interpreter across its worker threads (GIL); the `not pfb.get("async_worker")` guard makes worker/queue creation happen **once**. So a connection held by a worker thread is a **single writer** — a persistent connection is feasible.
2. **PHP is a concurrent *writer*, not just a reader.** `pfBlockerNG_clearsqlite()` (`inc:6743`) runs `UPDATE resolver SET totalqueries = 0, queries = 0` and `UPDATE dnsbl SET counter = 0` **live from the UI** (`pfblockerng.php:69/73`, `pfblockerng.widget.php:175-191`) with **no Unbound restart**. The widget also `INSERT`s the default `resolver` row. → real writer/writer concurrency against the same files Python holds open.
3. **Recovery scope is narrow** (per design decision): only pfb's own file delete/recreate (`write_sqlite` removes the cache on error, `inc/init` recreate) + Unbound restarts (which kill and re-`init` the process). No external file replacement, no RAM-disk special-casing — treat the DB as a plain on-disk file.
4. **A configurable line-cap already exists** and already covers our three logs: `pfb_log_mgmt()` (`inc:1227`) trims via `tail -n N > tmp; mv` using the `log_max_dnslog` / `log_max_dnsreplylog` / `log_max_unilog` knobs (UI "Log Settings (max lines)" in `pfblockerng_general.php`; default 20000, `'nolimit'` disables; runs on the cron/update path `pfblockerng.php:703` + `inc:6607`). The viewer "clear" (`pfblockerng_log.php:308`) already uses **`ftruncate`-in-place for the held-open `py_error.log`** and `unlink`+`touch` for the others. Both the trim (`mv`) and the clear (`unlink`) **change the inode**.
5. **No pfSense precedent to borrow:** no other package (PHP or Python) uses sqlite; only 4 Python files exist across all packages and none run in Unbound. The reusable, well-tested tools are therefore **sqlite's own WAL/busy_timeout** and the **stdlib `logging`** framework — not a pfSense library.

---

## 2. Decision

Replace per-call open/close with persistent, recoverable I/O, split into two independent async subsystems (DB worker, log worker). Behaviour-preserving for every observable output.

| Area | Decision |
| --- | --- |
| **DB (Python)** | One persistent `sqlite3` connection per file, owned solely by a **DB-worker thread** (`check_same_thread` satisfied), opened lazily, kept open. On (re)connect: `PRAGMA journal_mode=WAL`, `busy_timeout`, `synchronous=NORMAL`, then `CREATE TABLE IF NOT EXISTS`. **Batched** writes flushed on a short timer + on `deinit`: counters accumulate a **per-key delta** flushed as **relative** `… = … + :delta` (never absolute); cache rows buffer in **FIFO** and flush via one `executemany` transaction. **Reconnect-on-fault**: on `OperationalError`/malformed/file-gone → close, reconnect, re-`CREATE TABLE`, **re-run the pending op** (bounded retries; never silently drop a dequeued write). |
| **DB (PHP)** | `pfb_open_sqlite` sets `journal_mode=WAL` + `busy_timeout` consistently; **reconcile the `PRAGMA journal_mode = delete` at `inc:6297`** so nothing flips the file out of WAL under the live Python connection. |
| **Logging** | stdlib `logging`: `QueueHandler` (DNS path, bounded, drop-on-full) → `QueueListener` (**log-worker thread**) → one **`WatchedFileHandler`** per file with a **raw `%(message)s`** formatter (byte-identical lines). The existing line-cap is reused unchanged; `WatchedFileHandler` re-`stat`s before each emit, so it tolerates the trim (`mv`) and the clear (`unlink`) **without modifying either**. |
| **Threads** | Two independent workers (DB, log). Only **intra-stream** order matters: counters are commutative (`+= 1`), so per-key delta summation is order-free even for the same key; **cache inserts preserve FIFO** (same-domain re-blocks). No cross-stream (log↔db) ordering. |
| **Durability** | `≥` today. Hard floor: never block the DNS path → keep the **bounded queue + drop-on-full**. `deinit` **drains both queues and flushes the DB batch** before join (the "better than today" win, since pfBlockerNG restarts Unbound on every reload). |

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

- `resolver.totalqueries += 1` per counted query; `dnsbl.counter += 1 WHERE groupname = ?`; `dnsblcache` gets one `INSERT` per block event. **All counter writes stay relative** (`+= delta`) so a concurrent UI reset is never clobbered.
- Cache-insert row order is preserved within a flush (same-domain ordering).
- Each app-log line is written **verbatim** (`line + "\n"`, no added level/timestamp/encoding) to the **same file** as today (`dnsbl.log` / `dns_reply.log` / `unified.log`).
- Drop-on-full and the set of log files/targets are unchanged.

### Explicitly kept / out of scope

- The existing line-cap (`pfb_log_mgmt`, `log_max_*`) and its UI — reused as-is (no new knob).
- The `sqlite3_resolver_con` gate (`pfb_unbound.py:309/639/964/1083`) — fold its meaning into the new connection state rather than adding a parallel flag.
- `py_error.log`'s existing stdlib-logging handler — extend the same pattern to the three app logs.

---

## 3. Consequences

**Positive**

- Eliminates a `connect()`+`CREATE TABLE`+`close` per DB write and an `open`+`close` per log line → fewer syscalls, lower worker latency, higher sustainable throughput.
- A recoverable persistent connection (reconnect-on-fault) is more robust than the implicit "reconnect every call," while WAL lets PHP read/reset concurrently.
- `deinit` drain+flush reduces loss on the frequent reload restarts (better than today's 5s-join truncation).

**Negative / risks**

- **No live Unbound in CI.** Equivalence is pinned by pytest golden tests + manual smoke on pfSense (`scripts/deploy.sh`). Non-negotiable.
- **WAL must be consistent across Python *and* PHP** or the two contend/lock; the `journal_mode=delete` path is a live hazard until reconciled. This makes the change cross-component, not Python-only.
- **Batching widens the crash-loss window** to the un-flushed delta (bounded by the flush timer); acceptable because these are stats/counters and graceful reload flushes. Absolute-write batching would clobber UI resets — forbidden.
- `WatchedFileHandler` adds a `stat()` per emitted line (vs the old `open`+`close`); still far cheaper, but **measure** it.

---

## 4. Requirements (acceptance)

1. **DB outcomes identical:** same tables/rows/values produced under normal operation; failure-time loss no worse than today; UI resets via `pfBlockerNG_clearsqlite` still take effect.
2. **Log outcomes identical:** byte-identical lines to the same files.
3. **No regression** to the PHP widget/alerts reads/writes of these DBs (verified under WAL).

---

## 5. Constraints (from `CLAUDE.md`)

- **Python:** stdlib only (Unbound loader); 3.11+; 4-space; type hints on new fns; no bare `except`; `from __future__ import annotations` already present. New injected Unbound symbols (none expected) go in `stubs/python/unboundmodule.py`.
- **PHP:** tabs; PHP 8.3; no `die()`/`exit()` in library code; pfSense fns via `stubs/pfsense/`.
- Run `python -m pytest`, `ruff check .`, `ruff format .` after any `pfb_unbound.py`/`tests/` change. ShellCheck/intelephense clean.
- Commit style `<scope>: <imperative summary>`; **work inline on `adr/03`, one commit per phase, push directly** (no worktree isolation — per project workflow). PR bodies via `--body-file`.

---

## 6. Action plan

Each phase is one commit, leaves `python -m pytest` green, and is behaviour-preserving for observable outputs. Implementation phases (P1, P2) ship with their own golden-equivalence tests; P3 is the cross-cutting validation.

### Phase 1 — DB subsystem: persistent connection + WAL + batching + reconnect

Prompt: `01_DB_Persistent_Connection.txt`

- Python: DB-worker thread owning persistent per-file connections; WAL + busy_timeout + synchronous=NORMAL; batched relative-increment counters + FIFO cache inserts; reconnect-on-fault; `deinit` flush+drain.
- PHP: WAL + busy_timeout in `pfb_open_sqlite`; reconcile `journal_mode=delete` (`inc:6297`).
- Golden tests: identical `resolver`/`dnsbl`/`dnsblcache` table state for a fixed op sequence, old vs new; relative-increment-survives-reset test.

### Phase 2 — Logging subsystem: QueueListener + WatchedFileHandler

Prompt: `02_Logging_Persistent_Handles.txt`

- Replace `log_entry` open-per-write with stdlib `QueueHandler → QueueListener → WatchedFileHandler` (one logger/file, raw `%(message)s`); reuse the existing line-cap; confirm trim(`mv`)/clear(`unlink`) coexistence.
- Golden tests: byte-identical file contents for a fixed log sequence, old vs new; reopen-after-rename/unlink test.

### Phase 3 — Integration validation + manual smoke

Prompt: `03_Validation.txt`

- Concurrency: PHP-style `clearsqlite` reset interleaved with Python increments under WAL → resets stick, post-reset increments count, no `locked`.
- Fault injection: delete the cache file mid-run → reconnect, no loss of subsequent ops.
- Perf: `connect()`/`open()`/`stat()` syscall counts + throughput, old vs new (reuse `benchmarks/`).
- Shutdown: `deinit` drains+flushes (no loss on graceful reload).
- Manual smoke checklist on a live pfSense box (no live Unbound in CI).

---

## 7. Definition of done

- `python -m pytest` green incl. new golden/concurrency/fault tests; `ruff` clean; ShellCheck/intelephense/`php -l` clean.
- Persistent connection + WAL on both sides; batched relative-increment counters; reconnect-on-fault; two async workers; `deinit` flush+drain.
- Byte-identical logs + identical DB table dumps vs current, under the golden harness.
- Status → **Accepted** after the manual smoke passes on a live box.

---

## Post-acceptance addendum (2026-07-15 — issue #1349)

The accepted body above is the historical record of the original three-DB
implementation. Issue #1349 later retired the unconsumed per-block reports-cache
SQLite writer/table. The active persistent-DB contract covers only
`pfb_py_resolver.sqlite` (`resolver`) and `pfb_py_dnsbl.sqlite` (`dnsbl`): no
`dnsblcache` write, FIFO, golden-state, fault-injection, action-plan, or
definition-of-done requirement survives.

The two active stats DBs retain their WAL connections, relative counters, batching,
worker drain, and PHP concurrency rules. Current recovery uses
`_validate_db_with_recovery()` to remove a malformed stats DB plus WAL/SHM and
revalidate once, while `_db_run()` reconnects file-gone connections. References in
the accepted body to `write_sqlite`, the third cache DB, or "the cache file" are
historical and must not be reintroduced as active requirements.
