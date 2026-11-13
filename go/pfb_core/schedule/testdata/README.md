# Schedule evaluation parity corpus

Language-neutral record of how today's scheduler decides what runs (issue #3938, map #3813). Two runners replay every
case and must agree with it:

- Go: `go/pfb_core/schedule/corpus_test.go` (the Core package).
- PHP (the old path): `tests/php/ScheduleCorpusTest.php`, through the production functions themselves.

The expectations were produced by the old path (PHP 8.4 reading the host's system tz database, `timezone_version_get()`
`0.system`) and then reviewed row by row; they are frozen.

## Common rules

- One JSON object: `schema` (1), then one list per section in this order: `next_occurrence`, `plan`, `extra_plan`,
  `next_due`, `quiet_hours`, `state_valid`, `set_pending`, `record_outcome`, `model`, `blacklist`.
- A case holds exactly its section's keys, in order: `id`, `description`, the inputs, `expect`. A missing, unknown or
  reordered key and a duplicate `id` in a section are errors in both runners, never skips.
- Times are Unix seconds. `timezone` is an IANA name; the zones and dates used have had stable rules for years.
- Weekdays are ISO (1 Monday to 7 Sunday); minutes are quarter hours (0, 15, 30, 45). Cadences: `Never`, `01hour`,
  `02hours`, `03hours`, `04hours`, `06hours`, `08hours`, `12hours`, `EveryDay`, `Weekly`.
- Object key order is not part of an answer; list order is.
- An entry is `{id, cadence, enabled, override}`; `override` is null or a schedule `{weekday, hour, minute}`. An id is
  `ipv4:<header>_v4`, `ipv6:<header>_v6`, `dnsbl:<header>`, `extra:dcc` or `extra:bl`.
- A state (`state`, and a state `expect`) is the `items` object of `pfb_schedule_state.json`: id to
  `{last_successful_check, last_completed_occurrence, completion_outcome, pending_occurrence, pending_attempted}`, each
  field optional.

## Sections

| Section | Old path | Inputs | `expect` |
|---|---|---|---|
| `next_occurrence` | `pfb_schedule_next_occurrence()` | `timezone`, `cadence`, `weekday`, `hour`, `minute`, `reference` | the first occurrence strictly after `reference`, null (`Never`), or `"invalid"` |
| `plan` | `pfb_schedule_plan()` | `timezone`, `default` schedule, `now`, `groups` (entries, each with an optional `last_completed_occurrence`) | `{due, next_due, occurrences}`: due ids in group order, the earliest next occurrence of an eligible group (or null), and each due id's latest occurrence |
| `extra_plan` | `pfb_schedule_extra_plan()` | `timezone`, `default`, `now`, `entries` (the Extras), `state`, `cache` (null, or id to `{next_due}`), `geoip_ready` | `{due, occurrences}` |
| `next_due` | `pfb_schedule_cache_refresh()` into an empty ledger directory | `timezone`, `scheduled`, `default`, `now`, `entries`, `state` | the ledger entries it writes, `cron`, `extra:dcc`, `extra:bl`, each `{last_run, next_due, jitter}` |
| `quiet_hours` | `pfb_quiet_hours_in_window()` | `timezone` (the system zone), `now`, `window` | true: apply now; false: defer |
| `state_valid` | `pfb_schedule_state_read()` | `input`, the file's text | whether the file is a valid state |
| `set_pending` | `pfb_schedule_state_set_pending()` | `state`, `occurrences` (id to occurrence) | the state written, or `"rejected"` |
| `record_outcome` | `pfb_schedule_state_record_outcome()` | `state`, `item` (an id), `outcome` (`success`, `retry-cap-reached`), `now`, `expected_occurrence` (null or an occurrence) | the state written, or `"rejected"` |
| `model` | `pfb_schedule_runtime_model()` | `general` (the General settings), `sections` (`ipv4`, `ipv6`, `dnsbl` group lists as config.xml holds them), `extras` (null, or `{dcc, bl: {enabled, cadence}}`) | `{scheduled, default, entries, config_hash}` with entries in config order, or `{reject}` with the logged reason |
| `blacklist` | `pfb_schedule_runtime_config()`, the `extra:bl` it derives | `blacklist`, the Blacklist section | `{enabled, cadence}`, or `{reject}` with the logged reason |

## What the corpus pins

- DST: New York (a skipped 02:xx hour, a repeated 01:xx hour whose second pass is a separate occurrence), Berlin, Lord
  Howe (30-minute shifts), Apia's skipped 2011-12-30, Monrovia 1970's -0:44:30 offset, Kathmandu's +05:45.
- Missed occurrences collapse into the latest one; the search reaches back 15 days at most.
- Quiet hours: local time, start inclusive and end exclusive, a window across midnight, and every fail-safe (empty,
  malformed, out of range, zero width) answering apply-now.
- Extras: `extra:dcc` precedes `extra:bl` in the model; a GeoIP generation in the middle of a swap forces `extra:dcc`
  due, appended after a due `extra:bl`.

## Known limits

- Core takes the sections and rows of `model` and the Blacklist `item` as JSON lists. PHP also accepts an object there
  (a PHP array); config.xml never holds one, and the corpus has none.
- `extras` is built by `pfb_schedule_runtime_config()` itself, never read from config; Core types it, so the old path's
  check of a missing `dcc` has no case.
- `pfb_schedule_plan()`'s `$since` and `$next_occurrence` arguments are always the defaults in production; Core has
  neither. A model entry always has `has_active_rows` true (the runtime model only lists rows that have a URL and are not
  Disabled), so the corpus does not carry it.
- Not in the corpus: the tick's feed plan (inline in `pfblockerng_tick()`: `pfb_schedule_plan()` over the feed entries with
  `last_completed_occurrence` alone as the cursor, nothing when scheduled updates are off; `CacheEntries` also counts an
  attempted pending occurrence, so the cutover must not reuse its cursor), the tick's own reservation step (raising `pending_occurrence` to a newer occurrence inside
  `pfblockerng_tick()`), the merge of the ledger's other entries and its `pending_apply` flag, and the 900-second
  `ss_refresh`/`apply_reconcile` ledger entries.
