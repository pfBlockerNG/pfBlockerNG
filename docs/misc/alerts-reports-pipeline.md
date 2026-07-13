# Alerts/Reports pages — attribution pipeline and render-time costs

How `src/usr/local/www/pfblockerng/pfblockerng_alerts.php` gets its data, why the page
re-queries feed/DNSBL state on every load even though the logs already carry full
attribution, and where the load time goes. Read this before touching the Alerts/Reports
render path, the log converters, or either report cache. Perf work on this path is
tracked in issue #809.

---

## The two-phase attribution model

Every reported event is attributed **twice**, at different times, answering different
questions:

1. **Event time (write path)** — "which feed/entry caused this, at the moment it
   happened?" Computed once, by the log writers, and baked into the log line.
2. **Render time (read path)** — "is that attribution *still* true right now?" Computed
   by the Alerts page per displayed row, against the current feed/DNSBL state, to render
   drift (the struck-through "Previous Feed:" display) and to pick the action icons
   ("not currently listed", whitelist `+`, TLD carve-out, unlock, …).

The logs are self-sufficient for rendering a complete table; the render-time pass is a
freshness feature layered on top. It is also where virtually all of the page's load time
goes (see "Render-time costs" below).

## Write path — who fills in what

| Log | Writer | Attribution filled at event time |
| --- | ------ | -------------------------------- |
| `dnsbl.log` | `pfb_unbound.py` (`_log_dnsbl` path) | full verdict: block type, group, evaluated domain/zone, feed, query type |
| `dns_reply.log` | `pfb_unbound.py` | reply type/record, TTL, resolved address, GeoIP iso code |
| `ip_block/permit/match.log` | filterlog daemon (`pfb_daemon_filterlog`, `pfblockerng.inc`) | pf tracker → pfB rule/alias, matching feed + IP/CIDR entry (`find_reported_header()`), GeoIP (`mmdblookup`), rDNS, ASN |
| `unified.log` | filterlog daemon (sole writer, ADR-38 Amendment 1) | reformatted copies of the three streams above |

The daemon reconstructs the bare pf event into a fully attributed record **once**, at
event time, and caches its lookups in the `ipcache` SQLite table so repeated offenders
are cheap on the write path. `pfb_unbound.py` similarly enqueues every fresh block's
verdict into the `dnsblcache` SQLite table, pre-warming the Reports-tab lookup described
below.

## Read path — the Alerts page

Landing view defaults to **Unified** (`pfbpageload` default `'unified'`) with 200
entries (`pfbunicnt`); the classic Alerts view renders four tables (DNSBL + Block +
Permit + Match, 25 entries each); the page auto-refreshes every 60 s (`alertrefresh`
default on). Each table render does `tail -r <log> > <log>.rev` (a full on-disk copy),
then walks the reversed file with `fgetcsv`, feeding each line to a converter:

- `convert_dnsbl_log()` — DNSBL rows. Renders the logged fields, then calls
  `pfb_dnsbl_parse('alerts', …)` to fetch the domain's *current* group/feed/eval/mode
  and strikes through whatever changed. Also decides the whitelist/exclusion/unlock
  icons (`dnsbl_whitelist_type()`).
- `convert_dns_reply_log()` — DNS-reply rows. String work only; cheap.
- `convert_ip_log()` — IP rows. Re-validates that the logged IP/CIDR is still present
  in the logged feed's file; on a miss, hunts for where the IP lives *now* (new feed,
  new CIDR, new alias table) and renders the drift.

### Ordering constraint in `convert_dnsbl_log`

The expensive lookups run **before** the filter/limit gates, and that order is partly
load-bearing: the Alert-filter match runs against the **corrected** fields (post
`pfb_dnsbl_parse`), so a user filtering on a feed name matches the domain's *current*
feed, not the stale logged one. The filter gate therefore cannot be hoisted above the
parse without changing filter semantics. The **counter/limit** gate is independent of
the parse and can move (issue #809 Phase 1). Consequence of today's order: with
filtering enabled, every line of the whole log pays the full lookup, matching or not.
`convert_ip_log` has the opposite (cheap-first) order: it filters on raw log fields, so
its exec cost is bounded by accepted rows.

## The two report caches

| Cache | Table/file | Written by | Read by | Invalidation |
| ----- | ---------- | ---------- | ------- | ------------ |
| DNSBL report cache | `dnsblcache` (SQLite) | `pfb_unbound.py` on each fresh block; PHP on each render-time miss | `pfb_dnsbl_parse()` (Alerts page + daemon mode) | **wiped on every DNSBL swap** (`_db_reset_cache`, ADR-10 P3 — the no-restart equivalent of the old wipe-on-restart) |
| IP event cache | `ipcache` (SQLite) | filterlog daemon at event time | filterlog daemon only | rebuilt as events arrive |

Two asymmetries worth knowing:

- The DNSBL render path has a cache in front of it; the IP render path has **none** —
  `ipcache` is never consulted by the Alerts page, so IP re-validation re-greps the
  feed directories on every load and every 60 s refresh.
- Because `dnsblcache` is wiped on every swap while the logs still hold pre-swap lines,
  the first page loads after a feed update miss for most rows and repopulate the cache
  through the slow path.

## Render-time costs (per displayed row)

DNSBL row, `pfb_dnsbl_parse('alerts', …)` on a cache miss:

- SQLite SELECT, then INSERT — one open/close pair for the whole page load (issue #809
  Phase 1: `pfb_dnsbl_parse()` memoizes its result per domain and reuses a single
  dnsblcache handle across the page), not per row;
- `grep -shm1` over the whole DNSBL data file (`unbound_py_data`) — a de-listed domain
  scans all of it — **unless** the row's domain was already resolved by the batched
  prefetch pass below;
- one `grep` of the TLD zone file per domain label — same prefetch exception;
- a live `drill` to the external DNS server (`pfbextdns`, default 8.8.8.8) to chase
  CNAMEs when the domain itself is not found — network round-trip, per domain, with
  drill's retry/timeout behaviour when the upstream is slow. The prefetch pass never
  touches this: a CNAME target is only known after the data/zone lookup runs, so it
  cannot be pre-collected.

**Batched prefetch (issue #809 Phase 3a), scope-limited:** the per-type DNSBL table
(`convert_dnsbl_log()` via the `DNSBL Block`/`DNSBL Python` branch in
`pfblockerng_alerts.php`) runs a two-pass render **only when `!$pfb['filterlogentries']`**
— buffer every row this render will walk, `pfb_dnsbl_prefetch()` the distinct domain set
in ONE `grep -F` pass per file (data + zone), then replay the normal per-row loop, which
transparently consults the seeded result instead of re-`exec`'ing. Filtered mode is
untouched (the Alert-filter match runs against the *corrected*, post-parse fields, so a
row can't be pre-collected without parsing it first — see "Ordering constraint" above).
The Unified table is untouched too (its own accept/skip decisions are converter-internal,
so an exact pre-collection can't be proven equivalent there); it still benefits from
Phase 1's per-domain memo and shared SQLite handle, just not the batched grep.

IP row (`convert_ip_log`):

- validate: `find <feed dirs> | xargs grep '^<ip>'` (narrowed to the logged feed's file
  in the common case; the whole dir for GeoIP/ET rows) — **unless** the row was already
  resolved by the batched prefetch pass below;
- on a miss: `find_reported_header()` — an exact-IP grep across every file in the
  deny+native (or GeoIP) dirs, then a first-octet/prefix grep whose output PHP walks
  doing per-CIDR math — plus one more `find | xargs grep` across **all of
  `/var/db/aliastables/*.txt`** (millions of lines with large/aggregated tables) — same
  prefetch exception.

**Batched prefetch (issue #809 Phase 3b), scope-limited:** the per-type Block/Permit/Match
table (`convert_ip_log()` via the `Block`/`Permit`/`Match` branch in
`pfblockerng_alerts.php`) runs a two-pass render whenever a **finite row bound** exists —
non-filter mode, or filter mode with a real per-row limit (`$ipfilterlimitentries != 0`)
*and* real filter fields set. Pass 1 buffers the rows the render will walk (run-length
compressing `'-'` duplicate markers, exactly like Phase 3a); in filter mode it replays
`pfb_match_filter_field()` on a copy and compresses each mixed run of dup-marker and
REJECTED lines into one gap marker `(had-reject, dups-after-last-reject)` — sound because
a rejected row's entire streamed-loop effect is constant and field-independent (the
`$dup = 0` reset plus `$p_query_port = ''`), so only the dups after the run's last reject
survive into the next rendered row's badge. That bounds the buffer at ≤ (limit + 1) field
arrays plus ≤ (limit + 2) scalar/marker entries regardless of log size or filter
selectivity — O(rows rendered), never O(rows scanned). Pass 1.5
derives every accepted row's query (`pfb_ip_render_query()` — the SAME derivation
`convert_ip_log()` itself uses) and hands them to `pfb_ip_prefetch()`, which runs, in a
bounded number of `grep -f <patternfile>` passes: the validate round (grouped by the
shared file-listing pipeline), the miss round (`pfb_find_reported_headers()`, a batched
exact + prefix/CIDR sibling of `find_reported_header()` sharing `pfb_match_reported_cidr()`
with it), and the aliastables round (one pass across every still-missing row). Pass 2
replays the buffer through the unchanged per-row loop body, which transparently consults
the seeded results (`pfb_ip_render_memos()`) instead of re-`exec`'ing. Filter mode with
`$ipfilterlimitentries == 0` (genuinely unbounded — the log is scanned to EOF regardless)
and the degenerate `empty($filterfieldsarray[0])` case both keep the single-pass streaming
loop verbatim. The Unified table is untouched, same reasoning as the DNSBL Phase 3a
carve-out (its own accept/skip decisions are converter-internal).

Page level:

- one full `tail -r` log copy per table per load;
- the Unified loop reads the reversed log to EOF even after all row limits are filled
  (the converters no-op, but `fgetcsv` still parses every remaining line);
- stat views (`*_stat`): ~14 `cut|sort|uniq|sed` pipelines over the full log per view.
  The total is no longer a `grep -c ^` fork (issue #1261 — it is `pfb_count_lines()`,
  in-process), and it is computed once before the per-stat loop, not recomputed per
  iteration (issue #809) — the loop body only assigns the precomputed value.

## Why load time varies day to day

- A feed update ran → `dnsblcache` wiped + entries de-listed/moved → most rows take the
  miss paths above (the worst-case ones).
- The path to the external DNS server is slow/filtered → each `drill` fallback stalls
  for its timeout.
- The logs grew — every `tail -r`, converter walk and stats pipeline scales with log
  size until rotation trims them.

A quick on-box check: time a load right after a Force Reload (cache freshly wiped)
against a second load of the same view (cache warm), and `ls -lh /var/log/pfblockerng/`.
