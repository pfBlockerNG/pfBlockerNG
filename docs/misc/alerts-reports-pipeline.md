# Alerts/Reports pages — attribution pipeline and render-time costs

Scope: Alerts/Reports attribution pipeline, render-time costs. Load when: touch Alerts/Reports render path, log converters, or IP report cache.

How `src/usr/local/www/pfblockerng/pfblockerng_alerts.php` get data, why IP rows still re-query feed/alias state every load even though logs already carry full attribution, where load time go. Read before touching Alerts/Reports render path, log converters, or IP report cache. Perf work on this path tracked in issue #809.

---

## Attribution: DNSBL is one-phase, IP is two-phase

DNSBL rows attributed **once**, at event time, by log writer, rendered as logged (ADR-65). No render-time re-check: `pfb_dnsbl_query()` — same live matcher resolver itself use — asked only by write-path webserver-hit attributor below, never by page render.

IP rows keep older **two-phase** model:

1. **Event time (write path)** — "which feed/entry caused this, at moment it happened?" Computed once, by log writers, baked into log line.
2. **Render time (read path)** — "is that attribution *still* true right now?" Computed by Alerts page per displayed IP row, against current feed state, to render drift and pick action icons ("not currently listed", unlock, …).

IP logs self-sufficient for rendering complete table; render-time pass is freshness feature layered on top, and it is where virtually all IP tables' load time go (see "Render-time costs" below). DNSBL rows pay none of that cost — see issue #1349 for retirement of now-orphaned DNSBL render-time-recheck helpers this model change left behind.

## Write path — who fills in what

| Log | Writer | Attribution filled at event time |
| --- | ------ | -------------------------------- |
| `dnsbl.log` | `pfb_unbound.py` (`_log_dnsbl` path) | full verdict: block type, group, evaluated domain/zone, feed, query type, client transport, receiving IP and address-owner interface |
| `dns_reply.log` | `pfb_unbound.py` | reply type/record, TTL, resolved address, GeoIP iso code, client transport, receiving IP and address-owner interface |
| `ip_block/permit/match.log` | filterlog daemon (`pfb_daemon_filterlog`, `pfblockerng.inc`) | pf tracker → pfB rule/alias, matching feed + IP/CIDR entry (`find_reported_header()`), GeoIP (`mmdblookup`), rDNS, ASN (3 CSV columns, issue #1369 — see below) |
| `unified.log` | filterlog daemon (sole writer, ADR-38 Amendments 1/4) | reformatted IP rows; byte-identical RFC4180 DNSBL and DNS-reply rows |

Daemon reconstructs bare pf event into fully attributed record **once**, at event time, caches its lookups in `ipcache` SQLite table so repeated offenders cheap on write path.

DNSBL webserver-hit (block-page load) attributed same way: `pfb_log_event()` (`pfblockerng.inc`) asks live matcher via `pfb_dnsbl_query($domain)` — read-only query channel ADR-65 added — for domain's current verdict, uses returned group/feed to build `dnsbl.log` line it appends, increments per-group widget counter (`UPDATE dnsbl SET counter = counter + 1`). Miss (`NULL` or `blocked=false`) renders every field `Unknown` rather than guessing. Issue #1349 retired unconsumed reports-cache SQLite writer/table; event log is sole durable per-block record.

### DNS transport (issue #3751)

Transport is append-only: DNSBL field **11** follows query type at 10; DNS reply field **10** follows GeoIP at 9 (zero-based). Historical DNSBL rows with 10/11 fields and reply rows with 10 fields retain every existing offset. Reports and Unified show a dedicated Transport column; only exact `TCP`, `UDP`, `DoT`, `DoH`, `DoQ` strings are accepted. Absent or invalid metadata stays internally `Unknown` and displays **—**, never a guessed UDP value. The existing regex filters use DNSBL key 21 and reply key 90 against the displayed transport; use `^—$` to select unavailable metadata.

The daemon copies both DNS CSV rows verbatim into Unified, preserving quoted commas/quotes in names and answers. DNS reply still never emits a syslog event. Stats retain their old indexed fields, and raw log downloads retain original bytes.

### Receiving endpoint (issue #3757)

DNSBL appends receiving IP/interface at indexes **12/13** after transport; DNS Reply appends them at **11/12**.
The existing client and Resolved IP columns keep their meanings. Reports and Unified show Receiving IP and Receiving
interface columns; regex filter keys are DNSBL **22/23** and reply **91/92**. Missing or malformed metadata displays
**—**, including historical rows and native/observer events without a supported endpoint API; `^—$` selects it.

The gateway snapshots the actual receiving socket address and its pfSense address-owner description at query time.
This is not the client-subnet-derived Interface column or packet ingress. A loopback-owned VIP is `Localhost`,
and later VIP moves/renames do not reinterpret stored rows. DNSBL's existing syslog path accepts the new 14-field
rows alongside older 11/12-field rows and adds known `listener_ip`/`listener_interface` tokens using existing escaping.
The separate opt-in client-metrics setting does not remove client addresses from logs.

### ASN CSV columns, no back-compat for log entries (issue #1369, ADR-38 Amendment 3)

IP feature logs and `unified.log` used to embed ASN metadata as single pipe-delimited blob field (`|ASN:  AS50360 | domain:  4vendeta.com | name:  Tamatiya EOOD |` — flattened `mmdblookup` output, `pfblockerng.sh`'s `iptoasn()`). That field now **three plain CSV columns** — `asn`, `asn_domain`, `asn_name` — written via `fputcsv()` with explicit empty escape argument (RFC4180 quoting, never PHP's default backslash-escape quirk) and CR/LF normalized to space first, so row always stays one physical line. Feature-log rows go from 21 to 23 fields; `unified.log` IP rows (leading event-type field included) go from 22 to 24. Internal pipe blob itself **unchanged** — `iptoasn()`, `asncache.asn` SQLite column, syslog `asn=` value (ADR-38 §2.1) all keep it; only *log-line* representation changed. `pfb_asn_blob_split()`/`pfb_asn_csv_fields()` (`pfblockerng_extra.inc`) are pure helpers bridging the two.

**No back-compat for log entries** (owner decision, 2026-07-18): `convert_ip_log()`, Top ASN statistics pipeline, and Unified view parse **only** current field-count schema. Any other count — including every pre-upgrade legacy row still on disk — skipped silently, zero PHP warnings, until log rotation removes it (`pfb_ip_log_row_schema_ok()`, checked before timestamp-shift reorder in every one of `convert_ip_log()`'s three call sites, plus two-pass buffer's Pass 1). See ADR-38 Amendment 3 for full contract, reader `fgetcsv()` escape-parameter correction it required, and Top ASN `awk` field-count gate's known comma-in-name limitation.

## Read path — the Alerts page

Landing view defaults to **Unified** (`pfbpageload` default `'unified'`) with 200 entries (`pfbunicnt`); classic Alerts view renders four tables (DNSBL + Block + Permit + Match, 25 entries each); page auto-refreshes every 60 s (`alertrefresh` default on). Each table render does `tail -r <log> > <log>.rev` (full on-disk copy), then walks reversed file with `fgetcsv`, feeding each line to converter:

- `convert_dnsbl_log()` — DNSBL rows. Renders row's own logged fields (group@6, feed@8) directly — no external lookup, no re-check. Also decides whitelist/exclusion/unlock icons (`dnsbl_whitelist_type()`).
- `convert_dns_reply_log()` — DNS-reply rows. String work only; cheap.
- `convert_ip_log()` — IP rows. Re-validates logged IP/CIDR still present in logged feed's file; on miss, hunts where IP lives *now* (new feed, new CIDR, new alias table) and renders drift.

The Reports settings form omits controls for disabled DNSBL or DNS reply logging. On save, omitted select fields take their declared defaults before option validation; valid submitted selections remain unchanged.

Because DNSBL rows need no lookup, `convert_dnsbl_log()`'s counter/limit gate runs first, unconditionally, before any per-row work — no "corrected fields" ordering constraint to preserve on DNSBL side anymore. `convert_ip_log` keeps own cheap-first order: filters on raw log fields, so exec cost bounded by accepted rows, and IP filter-match ordering constraint (below) still applies.

### IP filter/lookup ordering

`convert_ip_log()` filters and applies counter/limit gates to raw, timestamp-reordered fields before attribution. Accepted rows then call package seam `pfb_ip_render_attribution()`, which owns per-row validate/miss/alias fallback and returns values needed for rendering. Bounded Block/Permit/Match path derives same queries in Pass 1.5 for `pfb_ip_prefetch()`; page remains consumer and keeps filter, counter, icon, HTML decisions.

## The IP report cache

| Cache | Table/file | Written by | Read by | Invalidation |
| ----- | ---------- | ---------- | ------- | ------------ |
| IP event cache | `ipcache` (SQLite) | filterlog daemon at event time | filterlog daemon only | rebuilt as events arrive |

`ipcache` never consulted by Alerts page, so IP re-validation re-greps feed directories every load and every 60 s refresh — no render-time cache on IP side at all. DNSBL rows need no cache: nothing external read at render time.

## Render-time costs (per displayed row)

DNSBL rows have no render-time cost beyond parsing own logged fields — SQLite cache read/insert, `unbound_py_data`/`unbound_py_zone` grep, TLD-zone grep, external `drill` CNAME chase that used to run per DNSBL row all gone (were `pfb_dnsbl_parse()`/`pfb_dnsbl_parse_compute()` machinery, removed in issue #1349). Likewise no DNSBL-side batched prefetch pass anymore: `pfb_dnsbl_prefetch()` family removed in issue #1349 too.

IP row (`convert_ip_log` via `pfb_ip_render_attribution`):

- validate: `find <feed dirs> | xargs grep '^<ip>'` (narrowed to logged feed's file in common case; whole dir for GeoIP/ET rows) — **unless** row already resolved by batched prefetch pass below;
- on miss: `find_reported_header()` — exact-IP grep across every file in deny+native (or GeoIP) dirs, then first-octet/prefix grep whose output PHP walks doing per-CIDR math — plus one more `find | xargs grep` across **all of `/var/db/aliastables/*.txt`** (millions of lines with large/aggregated tables) — same prefetch exception.

**Batched prefetch (issue #809 Phase 3b), scope-limited:** per-type Block/Permit/Match table (`convert_ip_log()` via `Block`/`Permit`/`Match` branch in `pfblockerng_alerts.php`) runs two-pass render whenever **finite row bound** exists — non-filter mode, or filter mode with real per-row limit (`$ipfilterlimitentries != 0`) *and* real filter fields set. Pass 1 buffers rows render will walk (run-length compressing `'-'` duplicate markers); in filter mode it replays `pfb_match_filter_field()` on copy and compresses each mixed run of dup-marker and REJECTED lines into one gap marker `(had-reject, dups-after-last-reject)` — sound because rejected row's entire streamed-loop effect is constant and field-independent (`$dup = 0` reset plus `$p_query_port = ''`), so only dups after run's last reject survive into next rendered row's badge. That bounds buffer at ≤ (limit + 1) field arrays plus ≤ (limit + 2) scalar/marker entries regardless of log size or filter selectivity — O(rows rendered), never O(rows scanned). Pass 1.5 derives every accepted row's query (`pfb_ip_render_query()` — SAME derivation `pfb_ip_render_attribution()` uses) and hands them to `pfb_ip_prefetch()`, which runs, in bounded number of `grep -f <patternfile>` passes: validate round (grouped by shared file-listing pipeline), miss round (`pfb_find_reported_headers()`, batched exact + prefix/CIDR sibling of `find_reported_header()` sharing `pfb_match_reported_cidr()` with it), and aliastables round (one pass across every still-missing row). Pass 2 replays buffer through unchanged per-row loop body; its attribution seam transparently consults seeded results (`pfb_ip_render_memos()`) instead of re-`exec`'ing. Filter mode with `$ipfilterlimitentries == 0` (genuinely unbounded — log scanned to EOF regardless) and degenerate `empty($filterfieldsarray[0])` case both keep single-pass streaming loop verbatim. Unified table untouched — its own accept/skip decisions converter-internal, so exact pre-collection can't be proven equivalent there.

Page level:

- one full `tail -r` log copy per table per load;
- Unified loop reads reversed log to EOF even after all row limits filled (converters no-op, but `fgetcsv` still parses every remaining line);
- DNSBL and DNS Reply Stats aggregate enabled categories, physical-line totals and hourly timeline buckets in one streaming pass through `pfb_dns_stats()` (#3754). Unquoted rows use direct field splitting; any quoted record is read by PHP's native CSV parser, including embedded newlines. Totals follow raw physical boundaries even if the final quoted record is truncated. Domain/type and domain/IP consumers preserve commas within domains. Counts are sorted after aggregation, and repeated hours are combined even when log rows are out of order.
- Requested domain-suffix categories count each row at its deepest eligible selected depth, then propagate distinct bucket frequencies to shallower selected depths (#3759). This avoids repeated per-row suffix aggregation without caching domains or discarding history.
- IP stat views retain their per-category `cut|sort|uniq|sed` pipelines. Their total is computed once with `pfb_count_lines()`, not once per category.

Both DNS Stats views render a lightweight shell, then make one authenticated, read-only GET to `pfblockerng_alerts.php?view=<view>&stats_data=1`, where `<view>` is `dnsbl_stat` or `dnsbl_reply_stat` (#3759). Authorization remains native; the data request releases the session lock before aggregation and uses `Cache-Control: no-store`. The response contains `total`, request-local `timeline` points and escaped panel fragments with structured pie data. An uncomputed total (all log categories hidden) is `null`, distinct from an empty log's zero. Loading status and explicit failure/Retry states keep navigation usable; off-screen tables and charts mount only when visible or expanded. Range changes reuse the retained response rather than scan the log again.

The package-side `pfblockerng_stats.inc` and feature asset `pfblockerng_stats.js` share panel/chart rendering across both DNS views and the three synchronous IP Stats views. Native filter-input change handlers preserve field feedback without creating autocomplete widgets for Stats submit buttons. Timelines no longer write or fetch the shared web-root `chart_stats.csv`; installation removes the obsolete generated file. IP aggregation retains its original consecutive-hour grouping and order.

The shared Event Timeline selects native NVD3 x-axis ticks from the available chart width and measured label width, recalculating on resize and date-range changes. Fewer axis labels do not remove event bars or full timestamps from tooltips.

## Why load time varies day to day

- Each IP-side re-check that ends up hunting moved entry can involve slow filesystem scans over large alias tables. (DNSBL side no longer re-checks at render time — ADR-65 — so cost is IP-only.)
- Logs grew — every `tail -r`, converter walk, stats pipeline scales with log size until rotation trims them.

Quick on-box check: time load of IP tables right after feed update (entries moved/de-listed, so more rows take miss path above) against second load of same view once nothing changed, and `ls -lh /var/log/pfblockerng/`.
