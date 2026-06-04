# Plan 01 — DNSBL block replies: stop caching them (#43)

- **Status:** Implemented — PR #64 merged (`devel` `b7a371c`, 2026-06-04)
- **Component:** `src/usr/local/pkg/pfblockerng/pfb_unbound.py`

## Context / problem

DNSBL block replies (`NOERROR` + `A 0.0.0.0`/VIP) were built at TTL 3600 **without**
`no_cache_store`, so Unbound stored them in its C message cache and served repeats from
there — *ahead of* the python module. Consequences:

- **Per-feed under-count (#43):** the feed-attributed logger (`get_details_dnsbl` →
  `dnsbl.log` + per-group counter) runs only on a cache **miss** from `operate()`. On a
  hit, `inplace_cb_reply_cache` → `get_details_reply("cache")` fires instead → an
  unattributed `DNS-reply`, no feed/group. A name blocked once then served N× from cache
  logged one attributed event.
- **block→allow staleness:** a removed name kept serving the cached `0.0.0.0`/VIP until
  TTL.

## Decision

Set `qstate.no_cache_store = 1` on the block path (issue **option 2**), over option 1
(attribute on the cache-hit path via `dnsblDB`). Every blocked query re-runs `operate()`
→ always attributed + delisting is immediate.

## Findings

- The block reply is **synthetic** → not caching it costs only the in-process matcher
  re-run (memoised), **no** upstream round-trip. Mirrors the SafeSearch CNAME path — the
  module's only other `no_cache_store`.
- Option 1 was rejected on **correctness**, not perf: the C-cache can't carry feed/group,
  so attribution needs the `dnsblDB` sidecar, whose lifetime ≠ the C-cache TTL → an
  attribution hole across reloads. And option 1 wouldn't fix block→allow staleness.
- Python **is** entered on a cache hit (the inplace callback — that's *why* #43 exists),
  so the perf delta between the options is ~a wash; the decision is correctness-driven.
- ADR-10's C-cache flip simplifies to **unidirectional** (allow→block only) once blocks
  aren't cached.

## Result

PR #64 merged. Pinned by `test_block_sets_no_cache_store` /
`test_pass_through_leaves_cache_store_enabled`. Set up the cache-attribution discussion
that led to plans 02–05.
