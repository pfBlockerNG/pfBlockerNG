# Alerts/Reports pages — attribution pipeline and render-time costs

How `src/usr/local/www/pfblockerng/pfblockerng_alerts.php` gets its data, why the IP rows
still re-query feed/alias state on every load even though the logs already carry full
attribution, and where the load time goes. Read this before touching the Alerts/Reports
render path, the log converters, or the IP report cache. Perf work on this path is tracked
in issue #809.

---

## Attribution: DNSBL is one-phase, IP is two-phase

DNSBL rows are attributed **once**, at event time, by the log writer, and rendered as
logged (ADR-65). There is no render-time re-check: `pfb_dnsbl_query()` — the same live
matcher the resolver itself uses — is asked only by the write-path webserver-hit attributor
below, never by the page render.

IP rows keep the older **two-phase** model:

1. **Event time (write path)** — "which feed/entry caused this, at the moment it
   happened?" Computed once, by the log writers, and baked into the log line.
2. **Render time (read path)** — "is that attribution *still* true right now?" Computed
   by the Alerts page per displayed IP row, against the current feed state, to render drift
   and pick the action icons ("not currently listed", unlock, …).

The IP logs are self-sufficient for rendering a complete table; the render-time pass is a
freshness feature layered on top, and it is where virtually all of the IP tables' load time
goes (see "Render-time costs" below). DNSBL rows pay none of that cost — see issue #1349 for
the retirement of the now-orphaned DNSBL render-time-recheck helpers this model change left
behind.

## Write path — who fills in what

| Log | Writer | Attribution filled at event time |
| --- | ------ | -------------------------------- |
| `dnsbl.log` | `pfb_unbound.py` (`_log_dnsbl` path) | full verdict: block type, group, evaluated domain/zone, feed, query type |
| `dns_reply.log` | `pfb_unbound.py` | reply type/record, TTL, resolved address, GeoIP iso code |
| `ip_block/permit/match.log` | filterlog daemon (`pfb_daemon_filterlog`, `pfblockerng.inc`) | pf tracker → pfB rule/alias, matching feed + IP/CIDR entry (`find_reported_header()`), GeoIP (`mmdblookup`), rDNS, ASN |
| `unified.log` | filterlog daemon (sole writer, ADR-38 Amendment 1) | reformatted copies of the three streams above |

The daemon reconstructs the bare pf event into a fully attributed record **once**, at
event time, and caches its lookups in the `ipcache` SQLite table so repeated offenders
are cheap on the write path.

A DNSBL webserver-hit (block-page load) is attributed the same way: `pfb_log_event()`
(`pfblockerng.inc`) asks the live matcher via `pfb_dnsbl_query($domain)` — the read-only
query channel ADR-65 added — for the domain's current verdict, uses the returned
group/feed to build the `dnsbl.log` line it appends, and increments the per-group widget
counter (`UPDATE dnsbl SET counter = counter + 1`). A miss (`NULL` or `blocked=false`)
renders every field `Unknown` rather than guessing. `pfb_unbound.py` still enqueues every
fresh DNS-side block into the `dnsblcache` SQLite table, but no render path reads it
anymore — the table and its lone remaining reader are vestigial and tracked for removal in
issue #1349.

## Read path — the Alerts page

Landing view defaults to **Unified** (`pfbpageload` default `'unified'`) with 200
entries (`pfbunicnt`); the classic Alerts view renders four tables (DNSBL + Block +
Permit + Match, 25 entries each); the page auto-refreshes every 60 s (`alertrefresh`
default on). Each table render does `tail -r <log> > <log>.rev` (a full on-disk copy),
then walks the reversed file with `fgetcsv`, feeding each line to a converter:

- `convert_dnsbl_log()` — DNSBL rows. Renders the row's own logged fields (group@6,
  feed@8) directly — no external lookup, no re-check. Also decides the
  whitelist/exclusion/unlock icons (`dnsbl_whitelist_type()`).
- `convert_dns_reply_log()` — DNS-reply rows. String work only; cheap.
- `convert_ip_log()` — IP rows. Re-validates that the logged IP/CIDR is still present
  in the logged feed's file; on a miss, hunts for where the IP lives *now* (new feed,
  new CIDR, new alias table) and renders the drift.

Because DNSBL rows need no lookup, `convert_dnsbl_log()`'s counter/limit gate runs first,
unconditionally, before any per-row work — there is no "corrected fields" ordering
constraint to preserve on the DNSBL side anymore. `convert_ip_log` keeps its own
cheap-first order: it filters on raw log fields, so its exec cost is bounded by accepted
rows, and the IP filter-match ordering constraint (below) still applies.

### IP filter/lookup ordering

The IP-side expensive lookups run **before** the filter/limit gates, and that order is
load-bearing: the Alert-filter match runs against the **corrected** fields (post
re-check), so a user filtering on a feed name matches the IP's *current* feed, not the
stale logged one. The filter gate therefore cannot be hoisted above the lookup without
changing filter semantics. The **counter/limit** gate is independent of the lookup and can
move (issue #809 Phase 1). Consequence of today's order: with filtering enabled, every
line of the whole log pays the full lookup, matching or not.

## The IP report cache

| Cache | Table/file | Written by | Read by | Invalidation |
| ----- | ---------- | ---------- | ------- | ------------ |
| IP event cache | `ipcache` (SQLite) | filterlog daemon at event time | filterlog daemon only | rebuilt as events arrive |

`ipcache` is never consulted by the Alerts page, so IP re-validation re-greps the feed
directories on every load and every 60 s refresh — there is no render-time cache on the IP
side at all. DNSBL rows need no cache: nothing external is read at render time.

## Render-time costs (per displayed row)

DNSBL rows have no render-time cost beyond parsing their own logged fields — the SQLite
cache read/insert, the `unbound_py_data`/`unbound_py_zone` grep, the TLD-zone grep, and
the external `drill` CNAME chase that used to run per DNSBL row are all gone (they were
`pfb_dnsbl_parse()`/`pfb_dnsbl_parse_compute()` machinery; the functions stay defined,
unreachable from this page — issue #1349 tracks their removal). There is likewise no
DNSBL-side batched prefetch pass anymore: `pfb_dnsbl_prefetch()` and its helpers are
defined but uncalled from `pfblockerng_alerts.php`.

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
compressing `'-'` duplicate markers); in filter mode it replays `pfb_match_filter_field()`
on a copy and compresses each mixed run of dup-marker and REJECTED lines into one gap
marker `(had-reject, dups-after-last-reject)` — sound because a rejected row's entire
streamed-loop effect is constant and field-independent (the `$dup = 0` reset plus
`$p_query_port = ''`), so only the dups after the run's last reject survive into the next
rendered row's badge. That bounds the buffer at ≤ (limit + 1) field arrays plus
≤ (limit + 2) scalar/marker entries regardless of log size or filter selectivity —
O(rows rendered), never O(rows scanned). Pass 1.5 derives every accepted row's query
(`pfb_ip_render_query()` — the SAME derivation `convert_ip_log()` itself uses) and hands
them to `pfb_ip_prefetch()`, which runs, in a bounded number of `grep -f <patternfile>`
passes: the validate round (grouped by the shared file-listing pipeline), the miss round
(`pfb_find_reported_headers()`, a batched exact + prefix/CIDR sibling of
`find_reported_header()` sharing `pfb_match_reported_cidr()` with it), and the aliastables
round (one pass across every still-missing row). Pass 2 replays the buffer through the
unchanged per-row loop body, which transparently consults the seeded results
(`pfb_ip_render_memos()`) instead of re-`exec`'ing. Filter mode with
`$ipfilterlimitentries == 0` (genuinely unbounded — the log is scanned to EOF regardless)
and the degenerate `empty($filterfieldsarray[0])` case both keep the single-pass streaming
loop verbatim. The Unified table is untouched — its own accept/skip decisions are
converter-internal, so an exact pre-collection can't be proven equivalent there.

Page level:

- one full `tail -r` log copy per table per load;
- the Unified loop reads the reversed log to EOF even after all row limits are filled
  (the converters no-op, but `fgetcsv` still parses every remaining line);
- stat views (`*_stat`): ~14 `cut|sort|uniq|sed` pipelines over the full log per view.
  The total is no longer a `grep -c ^` fork (issue #1261 — it is `pfb_count_lines()`,
  in-process), and it is computed once before the per-stat loop, not recomputed per
  iteration (issue #809) — the loop body only assigns the precomputed value.

## Why load time varies day to day

- The path to the external DNS server is slow/filtered → each IP-side re-check that
  ends up hunting a moved entry can involve slow filesystem scans over large alias
  tables.
- The logs grew — every `tail -r`, converter walk and stats pipeline scales with log
  size until rotation trims them.

A quick on-box check: time a load of the IP tables right after a feed update (entries
moved/de-listed, so more rows take the miss path above) against a second load of the same
view once nothing has changed, and `ls -lh /var/log/pfblockerng/`.
