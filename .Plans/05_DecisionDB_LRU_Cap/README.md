# Plan 05 — Bound decisionDB with a configurable LRU cache (#72)

- **Status:** Implemented — PR #72 merged (`devel` `52f966c` + review fix `557a07a`, 2026-06-04)
- **Component:** `pfb_unbound.py`, `pfblockerng.inc`, `pfblockerng_dnsbl.php`, `stubs/pfsense/`, `tests/`

## Context / problem

`decisionDB` (the unified per-domain `Decision` cache, plans 02 + 04) grew **unbounded** —
one entry per unique queried name, reset only at `init()` / the ADR-10 swap. Bound it so
memory is capped while the **hot working set stays resident**.

## Decision

An **LRU** (frequently-queried domains survive; least-recently-used evicted at the cap —
not FIFO), **configurable via the WebUI**, default **10000**, `0` = unlimited.

- `_LruCache` (`pfb_unbound.py`): `OrderedDict`-backed; recency bumped on **get and set**;
  evict-LRU when `0 < maxsize < len`; `maxsize <= 0` = unbounded (pre-LRU behaviour). All
  ops under a **per-instance lock** — `operate()` runs on several Unbound worker threads
  and `get()`+`move_to_end()` is compound. Dict-compatible API → existing access sites
  unchanged.
- `@dataclass(slots=True)` on `Decision`/`DnsblDecision` → ~2–3× less RAM per entry.
- Config: WebUI (*DNSBL Configuration → "Decision cache max entries"*) → `config.xml`
  (`pfb_py_cache_max`) → `pfb_unbound.ini [MAIN] decisiondb_max` → `init_standard`
  `config.getint` → cache `maxsize`.

## Findings

- **`0` is meaningful** (unlimited), so the load/save/read deliberately avoid the
  `?: default` idiom across all three layers — `0` is falsy and would silently reset to
  the default.
- **RAM sizing** ("not too much RAM, not too little caching"): ~0.6–0.9 KB/entry (≈ 2–4 MB
  with slots) → 10k ≈ single-digit MB, covering ~10k hot unique names.
- **Stub-over-baseline side win:** adding the new `Form_Input` would have bumped a PHPStan
  `class.notFound` baseline count. Instead the pfSense WebUI `Form_*` builder classes were
  stubbed (`stubs/pfsense/forms.php`, variadic ctor + `__call`), which let PHPStan resolve
  them and **removed all 77 `Form_*` baseline entries** (126 → 49). Future WebUI edits no
  longer touch the baseline.

## Result

PR #72 merged (`devel` `52f966c` + `557a07a`). 1019 pytest, PHPStan green, 115 PHPUnit,
all linters clean. `_LruCache` units (recency-on-get keeps hot, evict-LRU-at-cap,
`0`=unbounded, clear, del) plus an `operate()`-level cap test; `conftest` resets
`decisionDB` to a real `_LruCache(0)`.

CodeRabbit review caught two real issues, both fixed (`557a07a`): (a) `pfb_global` could
pass a **non-numeric** config value through to `intval()` = `0` = silently unlimited —
now digits-only-validated + clamped; (b) `pfb_py_cache_max` was wrongly added to
`$select_options`, whose generic validator would dereference an undefined
`$options_pfb_py_cache_max` (`null`) → PHP 8 TypeError on save — removed (it's a numeric
input with its own validation).
