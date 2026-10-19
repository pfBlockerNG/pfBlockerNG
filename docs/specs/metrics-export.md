# Metrics export (node_exporter textfile)

Issue: [#3522](https://github.com/pfBlockerNG/pfBlockerNG/issues/3522)

## Goal

Operators who run Prometheus can graph and alert on pfBlockerNG: block rates, table
sizes, stale or failing feeds, and update passes that did not finish. pfBlockerNG
publishes its metrics as a Prometheus text-format file that the existing pfSense
node_exporter package serves. pfBlockerNG opens no listener of its own.

## Fixed constraints

- Transport is the node_exporter `textfile` collector. `pfSense-pkg-node_exporter`
  enables that collector by default, and the FreeBSD `node_exporter` rc script points
  it at `/var/tmp/node_exporter` (`node_exporter_textfile_dir`). pfBlockerNG writes
  `/var/tmp/node_exporter/pfblockerng.prom`. It never creates that directory and never
  changes node_exporter's configuration.
- The package dependency is `pfSense-pkg-node_exporter`. Presence is checked with
  pfSense core's `is_pkg_installed()` (`pkg info -e`).
- The configuration field goes through `PfbConfig` (`docs/misc/config-gateway.md`).
- Collection is read-only. In particular, the DNSBL and resolver SQLite files are
  opened with `SQLITE3_OPEN_READONLY`, not through `pfb_open_sqlite()`, because that
  helper can create, repair, or drop tables.
- Language: PHP only, no appliance Python, matching the rest of the package's cron
  entry points.
- Labels are bounded by configuration. No metric carries a per-domain, per-client, or
  per-IP label.

## Decisions

### Configuration and UI

- New registered field `gen/pfb_metrics_export`: toggle, default off, `sync => 'local'`
  (each HA node runs its own exporter), with a `no_grandfather` reason.
- The General tab gets a **Metrics export** checkbox. Its help text says the option
  publishes Prometheus metrics through the node_exporter package's textfile collector.
- When `pfSense-pkg-node_exporter` is not installed:
  - The checkbox is rendered disabled.
  - Red text below it reads "Requires the node_exporter package", linking to
    `/pkg_mgr_install.php?pkg=pfSense-pkg-node_exporter`.
  - Saving `on` is rejected with an input error, so a crafted POST cannot enable the
    option without the package. Saving `off` is always accepted.

### Scheduling and lifecycle

- New CLI verb `php /usr/local/www/pfblockerng/pfblockerng.php metrics` runs
  `pfb_metrics_write()`.
- While pfBlockerNG's master enable and the option are both on, a cron entry runs that
  verb every minute (`* * * * *`), installed with `install_cron_job()`. The command is
  `/usr/bin/timeout -s TERM -k 5 50 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics`,
  which sends TERM at 50 seconds and KILL 5 seconds later, so a hung source cannot pile
  up runs even if it ignores TERM. The one-minute cadence matches node_exporter's own
  `interface-collector.py`.
- Turning the option off, or turning pfBlockerNG's master enable off, removes the cron
  entry and deletes `pfblockerng.prom`. Package deinstall does the same.
- Enable and disable take an exclusive lock on `.metrics.lock` in the pfBlockerNG db
  directory around the files only: enabling creates the `.metrics_enabled` sentinel, and
  disabling removes the sentinel, `pfblockerng.prom` and the dir-missing marker. The lock
  is released before the cron entry is installed or removed, because
  `install_cron_job()` can start cron, which would inherit a held lock and block every
  publish. `pfb_metrics_write()` collects and renders outside the lock, then takes the
  same lock and publishes only while the sentinel exists, so a run that began before a
  disable cannot recreate the file after it. The lock wait is bounded at 10 seconds; a
  publish that cannot get the lock drops its output, and an enable or disable that cannot
  get it proceeds without it, so a wedged holder never blocks a settings change.
- The cron state is reconciled wherever pfBlockerNG already reconciles its other cron
  entries on save and install. No separate daemon is added.
- If `/var/tmp/node_exporter` does not exist (node_exporter disabled or never started),
  the verb logs once to the pfBlockerNG error log and exits without writing.

### Code structure

- `pfb_metrics_render(array $sources): string` is a pure function in `pfblockerng.inc`.
  It turns already-collected source data into exposition text and does no I/O, so tests
  can drive it from fixtures.
- `pfb_metrics_write()` collects each source and calls the renderer, then
  `pfb_metrics_publish()` publishes the file atomically under the lock: a temp file in
  the same directory without a `.prom` suffix (the collector ignores it), `chmod 0644`,
  then `rename()`.
- The per-rule packet aggregation currently inline in `pfBlockerNG_update_table()`
  (`pfblockerng.widget.php`) moves into a shared `pfblockerng.inc` helper. The widget
  and the exporter both call it, and the widget's output does not change.
- Update-pass timing: `sync_package_pfblockerng()` records its start time when an
  Update pass begins and its end time when it reaches `UPDATE PROCESS ENDED`. Both go
  into a new state file, `/var/db/pfblockerng/pfb_pass_status.json`
  (`{"last_start": int, "last_end": int}`), written atomically. No other state file
  records whole-pass timing today. Settings-save passes (`$pfb['save']`, which includes
  the `noupdates` verb) are not counted: the start is recorded only after the pass's run
  plan has fixed `$pfb['save']`, and neither the start nor the end is recorded for a
  save pass.

### Metrics

All names carry the `pfblockerng_` prefix. `# HELP` and `# TYPE` lines are emitted for
every family that has at least one series, and label values are escaped per the
Prometheus text format (`\\`, `\"`, `\n`).

| Metric | Type | Labels | Source |
| --- | --- | --- | --- |
| `pfblockerng_info` | gauge (always 1) | `version` | `pfb_pkg_ver()` |
| `pfblockerng_ip_table_entries` | gauge | `table` | `pfb_pfctl_tables_parse()` addresses, adjusted by `pfb_widget_alias_display_count()` (placeholder-only table = 0) |
| `pfblockerng_ip_rule_packets_total` | counter | `table` | extracted per-rule helper (sum of `pfSense_get_pf_rules()` packets per pfB alias) |
| `pfblockerng_dnsbl_blocked_queries_total` | counter | `group` | `dnsbl.counter` in `pfb_py_dnsbl.sqlite`, including the `Upstream` row |
| `pfblockerng_dnsbl_group_entries` | gauge | `group` | `dnsbl.entries`; rows marked `disabled` are omitted |
| `pfblockerng_dnsbl_resolver_queries_total` | counter | none | `pfb_py_resolver.sqlite` row 0, `totalqueries + queries` (same value the widget shows) |
| `pfblockerng_feed_last_success_timestamp_seconds` | gauge | `feed` | `last_successful_check` per item in `pfb_schedule_state.json`; `feed` is the schedule item ID (for example `ipv4:Alias_v4`, `dnsbl:Group`) |
| `pfblockerng_feed_failing` | gauge (1) | `facility`, `feed`, `stage` | open entries in `pfb_sync_status.json` (PHP) and `/var/unbound/pfb_py_status.json` (Python); present only while a failure is open |
| `pfblockerng_update_last_start_timestamp_seconds` | gauge | none | `pfb_pass_status.json` `last_start` |
| `pfblockerng_update_last_end_timestamp_seconds` | gauge | none | `pfb_pass_status.json` `last_end` |
| `pfblockerng_metrics_source_up` | gauge | `source` | 1 when that source was collected, 0 when it failed |

`source` values: `pfctl`, `pf_rules`, `dnsbl_db`, `resolver_db`, `schedule_state`,
`sync_status`, `py_sync_status`, `pass_status`.

Semantics operators rely on:

- Counters reset to 0 when the operator clears statistics (widget "clear", or the
  scheduled `cleardnsbl` / `pfctl -z`). Prometheus `rate()` and `increase()` treat that
  as a counter reset.
- A pass is unfinished or crashed when `last_start > last_end`.
- Writer freshness comes from node_exporter's built-in `node_textfile_mtime_seconds`, so
  pfBlockerNG adds no metric for it.
- Hidden tables follow the widget's rules (`pfb_widget_alias_hidden()`): the DNSBL VIP
  table and aggregated aliases are omitted unless the widget's "Show Aggregated Aliases"
  is on.

### Error handling

Each source is collected independently. A failing source drops only its own families
and sets `pfblockerng_metrics_source_up{source="…"} 0`. A source fails when:

- `pfctl` exits non-zero, even if it printed some tables first (a zero exit with no
  output is up with an empty table set);
- a SQLite file cannot be opened or queried (an open waits for a locked database for
  `$pfb['sqlite_timeout']`, capped at 5 seconds, before it counts as a failure);
- a status or state file fails to parse, including `pfb_sync_status.json` that is
  unreadable, is not JSON, or is not an object, or whose read lock times out;
- the source's collection code throws.

A source that is absent because its feature is off (a missing SQLite or status file, an
absent or empty `pfb_sync_status.json`, an empty Python status file) reports
`source_up 1` with no series. While the DNSBL option is off the DNSBL and resolver
databases are not read at all: both sources report `source_up 1` with no series. The one
exception is an absent `pfb_pass_status.json` (no pass recorded yet): it reports
`source_up 1` and both update timestamps as 0. The file is still published. A failed
atomic publish leaves the previous file in place and removes the temp file.

## Acceptance criteria

1. With **Metrics export** on, `pfblockerng.prom` appears within one minute and the
   Prometheus Python client's text parser accepts it (checked in the smoke suite).
2. With the option off, the cron entry is absent and `pfblockerng.prom` does not exist.
   Toggling on and then off returns the box to that state.
3. Without node_exporter installed, the General tab shows the checkbox disabled, the red
   notice, and the working install link. A POST of `on` is refused with an input error
   and the stored value stays off.
4. Each source failure is isolated: the remaining families are still written and that
   source reports `source_up 0`.
5. The widget's per-alias packet column is byte-identical before and after the helper
   extraction.
6. A blocked DNSBL query increments `pfblockerng_dnsbl_blocked_queries_total` for its
   group on the next write.
7. An update pass that runs to completion sets `last_end >= last_start`. A pass killed
   mid-run leaves `last_start > last_end`.

## Tests

Each behavior is proven red-before-green per `.agents/policy/testing.md`:

- PHPUnit: renderer output against exact expected text (types, HELP lines, escaping of
  hostile label values, `source_up 0` on a failed source, omission of disabled DNSBL
  rows and hidden tables).
- PHPUnit: the extracted rule-packet helper against the widget's current aggregation,
  using fixture rules and pf rule counters.
- PHPUnit: atomic publish (target replaced on success; mode 0644; the previous file is
  preserved on a failure because publishing is a single `rename()`, which is atomic, and
  the failure test puts a directory at the target so `rename()` fails even as root; no
  temp file survives either way).
- PHPUnit: config registry entry, toggle round-trip, the save rejecting `on` without the
  package, and cron install/removal on toggle (including that enable and disable keep the
  sentinel in step with the cron entry).
- PHPUnit: a write without the sentinel publishes nothing; a body rendered before a
  disable is not published after it; a write waiting for the lock is refused when the
  export is disabled meanwhile (a second process holds the lock); a publish gives up
  while another run holds the lock; a disable waits out a publish in flight and removes
  what it wrote; a disable goes ahead when the lock is wedged; the lock is free while the
  cron entry is installed or removed.
- PHPUnit: source health: a throwing source is down while the others still publish; a
  non-zero `pfctl` exit is down even with output; a damaged, empty, absent, or locked
  `pfb_sync_status.json` and a corrupt resolver database each read as specified;
  DNSBL off skips both databases; a busy database is waited for.
- PHPUnit: update-pass timing records Update passes and nothing for a settings-save
  pass.
- UI tier (per architecture-notes "Web UI test tiers"): disabled checkbox, red notice,
  and link target when the package is absent, and a General save POSTing `on` without the
  package is refused with the exact error and the stored value stays off; enabled
  checkbox when present.
- Smoke (VM): run the `metrics` verb and assert the published file's families and that it
  parses with the Prometheus Python client's text parser; a settings-save pass leaves the
  pass times alone; the verb publishes nothing while the option is off. The smoke image
  installs packages offline and cannot install node_exporter, so the smoke creates the
  textfile directory itself and enables the option through the config gateway.

## Out of scope

- A pfBlockerNG-owned HTTP endpoint or listener.
- A configurable write interval.
- Per-table pfctl in/out byte and packet counters. Whether pfB tables carry the pf
  counters flag is unverified, and per-rule packets already cover the widget's view.
- Per-domain, per-client, or per-source-IP metrics.
- Unbound's own statistics (covered by dedicated Unbound exporters).
- Grafana dashboards or alert rule files.

## Open forks

None.
