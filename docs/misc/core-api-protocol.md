# Core API protocol

Scope: the HTTP+JSON API of the pfBlockerNG Core daemon (`go/pfb_core`, binary `pfb-core`, issue #3841; map #3813), the
conventions every Core method follows, the settings methods and backends (issues #3842, #3913, #3924), the singleton Update,
its scheduler and `--update-cmd` (issue #3941), who may call it, and how the package runs it. Load when: adding a Core
method or settings projection, calling Core from PHP or another local process, or changing `go/pfb_core`,
`pfb_core_service()` or `pfb_core_call()`.

Core is its own process and binary, separate from `pfb-dns`: either keeps running when the other fails. It runs whether
pfB-DNS is enabled or not.

## Transport

- HTTP/1.1 over a Unix socket. pfSense: `/var/run/pfb_core/api.sock`.
- One path per method: `POST /v1/<Method>`, for example `/v1/GetVersion`. The version is in the path. An incompatible change
  is `/v2`; within `v1` only compatible additions are made (a new method, a new optional parameter, a new reply field).
- The request body is one JSON object: the method's parameters. An empty body is the empty object `{}`. Anything else, a
  second value after the object included, is `invalid_argument`. An unknown parameter is `invalid_argument` with a field
  error naming it.
- Every reply to a request that reached a method's routing is one JSON object, `Content-Type: application/json`,
  `Cache-Control: no-store`. A client ignores reply fields it does not know. A request that is not valid HTTP (a malformed
  or oversized header) gets Go's own plain-text `400` or `431` before any routing.
- Any HTTP method but `POST` is `method_not_allowed` (`Allow: POST`). A path that is not `/v1/<a method Core has>` is
  `not_found`, an unknown version included.

The method names and shapes are transport-neutral (map #3813, accepted proposal): a gRPC adapter can serve the same methods.

## Methods

| Method | Parameters | Reply |
|---|---|---|
| `GetVersion` | none | `{"service": "pfblockerng-core", "apiVersion": "v1", "status": "serving"}` |
| `GetSettingsSchema` | none | the native schema: `{"schemaVersion", "projections": [{"id", "fields": [...]}]}` |
| `GetSettings` | `projectionIds` (optional; none: all) | `{"initialized", "revision", "projections": [{"resourceId", "generation", "value"}]}` |
| `InitializeSettings` | `requestId`, `settings` | `{"revision": 1, "projections": [...]}`: every projection |
| `SaveSettings` | `requestId`, `expectedRevision`, `changes` | `{"revision", "projections": [...]}`: the projections whose value changed, and the revision, as Core read the backend again after the write (a failed read keeps what was written) |
| `ValidateSettings` | `changes` | `{}`, or the errors `SaveSettings` would give; changes nothing |
| `SettingsChanged` | none | what `GetSettings` answers: Core read its backend again |
| `StartUpdate` | `requestId`, `trigger`: `manual` (`scope`, `force`), `apply` or `retry` | `{}` once the Update is admitted; `conflict` while one runs |
| `GetUpdate` | `after` (optional cursor, a decimal string; default: the start) | `{"running", "update", "log", "next"}`: the current or last Update and a chunk of its log; `next` is a string |
| `GetSchedule` | none | `{"scheduled", "feeds", "extras"}`: when the scheduled Updates last ran and are next due |

`GetVersion` is also the health check: a `200` with `status` `serving` means Core takes requests.

## Settings

Core's native settings (issue #3842). Core holds them in memory, loaded from a [settings backend](#settings-backends)
(issue #3924), and serves `GetSettings`, `GetSettingsSchema` and `ValidateSettings` from memory.

- **Schema.** A projection is a group of fields, published as the resource `settings/<id>`. A field has a `name`, a
  `type` (`bool`, `int`, `enum`, `string`, `list`) and a `default`. It may also have:
  - `enum`: the allowed values;
  - `min` / `max`;
  - `pattern`: a regular expression (RE2) a string matches whole; `reserved`: values a string may not take;
  - `secret: true`;
  - `requires`: a bool field of the same projection; while that one is false, this bool is held false;
  - for a `list`: `items`, the fields of each item (a JSON object), and `key`, the item field that identifies it,
    required and unique in the list. A list is set whole: an item missing from it goes, and an item's missing fields
    keep the values of the item with the same key (a secret the client cannot read survives), else take their defaults.
- **Revision and generations.** The configuration *revision* is the optimistic lock. It comes from the backend and is
  compared only for equality. A projection's *generation* is derived from its value as a read shows it (53 bits of the
  SHA-256 of its JSON, secrets as their presence): it is never stored, stays equal across Core restarts while the value
  is unchanged, and moves when what a read shows changes.
- **`settings` / `changes`.** An object of projection id → field → value. JSON `null` resets a field to its default.
  `InitializeSettings` fills every field it is not given with its default.
- **Validation.** The whole resulting configuration is checked before anything is written. Any error rejects it all:
  `invalid_argument`, with one field error per fault (`changes.dns.decisionCacheMax`, `changes.<unknown projection>`).
- **Conflicts** (`conflict`):
  - `InitializeSettings` on an initialized Core (always, on the adapter backend), or whose write the backend refuses as a
    conflict (Core then reads the backend again);
  - `SaveSettings` before initialization;
  - `SaveSettings` whose `expectedRevision` is not the current revision (a field error names `expectedRevision`), as
    Core holds it or as the backend finds it when it writes (Core then reads the backend again, so the next
    `GetSettings` shows the revision that moved). The client reads again and reapplies its change.
- **Backend failure** (`unavailable`): the backend could not be read or written. Core keeps the values it last read.
- **No run.** A save starts no run.
- **Secrets are write-only.** A read shows a secret field as `{"present": true|false}`, never its value, in list items too.
- **One Core per state directory.** Core holds an exclusive `flock` on `core.lock` in `--state-dir` while it runs, with
  either backend. A second `pfb-core` on the same directory does not start. With `--update-cmd` the directory also holds
  `schedule_state.json` and `update.log` ([Update command](#update-command)).
- **Schema growth.** A projection or field the backend does not hold yet reads as its default. A projection or field
  the schema no longer has stops the start (file backend) or fails the read (adapter): removing one needs a migration.
- **Replay and restarts.** The `requestId` memory is the process's own. A retry after a restart gets `conflict` (the
  revision moved, or the settings are initialized) instead of the first result; the client then reads `GetSettings`.

### Settings backends

`settings.Backend` (`go/pfb_core/settings/backend.go`) reads the projections with a revision and writes a whole new
configuration against an expected revision. Core reads it at start (a failed read stops the start; `daemon(8)` starts
Core again) and on `SettingsChanged`, and writes through it on `InitializeSettings` and `SaveSettings`. Values flow only
from the backend into Core's memory.

| Deployment | Flag | Backend |
|---|---|---|
| Standalone Core | none | **File** (`FileBackend`): `settings.json` in `--state-dir` |
| Outpost-authoritative (pfSense) | `--settings-backend-cmd PATH` | **Adapter** (`AdapterBackend`): the platform configuration, through the Outpost's command |

**File backend.** One document, `settings.json` (0600, in the 0700 state directory): `{"format": 1, "revision": N,
"projections": {"<id>": {"values": {...}}}}`. The revision is 1 after `InitializeSettings` and advances on every accepted
`SaveSettings`. A save writes `settings.json.tmp`, syncs it, renames it into place and syncs the directory, so a crash
leaves the previous revision readable. A store file Core cannot read stops the start; Core never comes up uninitialized
over it.

**Adapter backend.** Core holds no platform path or name: the command comes only from the flag. Each call runs the
command once, writes one JSON request to its stdin and reads one JSON reply from its stdout (exit status 0). A read may
take 10 s, a write 20 s; past it the command's whole process group is killed, and the group is killed when any call ends, so
nothing the command started outlives the call. Calls run one at a time, so a call queued behind another can take the sum of
both bounds. A write that timed out may still have been applied: the Outpost's next
tick finds the revision moved and Core reads it. A reply
over 32 MiB (the feed projections carry custom lists), a non-zero exit, a reply that is not exactly one JSON object of version 1, a revision of 0, or read values
the schema refuses fail the call. The configuration always exists, so `InitializeSettings` is refused, and Core never
writes `settings.json`.

Protocol, version 1:

| Request | Reply |
|---|---|
| `{"version": 1, "op": "read"}` | `{"version": 1, "revision": N, "settings": {"dns": {...}, "feeds/ipv4": {...}, "feeds/ipv6": {...}, "feeds/dnsbl": {...}, "schedule": {...}}}` |
| `{"version": 1, "op": "write", "expectedRevision": N, "settings": {...every projection, every field}}` | `{"version": 1, "revision": M}` |

A read carries secrets (feed credentials) to Core; only Core's API hides them.

A refusal is `{"version": 1, "error": {"code", "message", "fieldErrors"}}`: `conflict` (the configuration is not at
`expectedRevision`), `invalid_argument` (a malformed request or value; nothing written), `unavailable` (nothing was
written: a lock stayed taken, the platform refused the write, ...). The adapter never calls Core while it serves Core.

### SettingsChanged

The Outpost's notice that its configuration may have changed. Core reads the backend again and answers what
`GetSettings` answers for every projection. It takes no parameters and no `requestId`. A failed read is `unavailable`,
and Core keeps the values it last read. The Outpost calls it:

- after every `write_config()` of a save page that writes a Core-modelled setting;
- on its periodic tick, when the revision its configuration projects differs from the one `GetSettings` reports. So a
  failed notice, or a change made outside the save pages (a restore, a config history revert, an HA receive, a
  migration), reaches Core by the next tick.

A failed notice never blocks or undoes the Outpost's change: it is reported, and the next tick sends it again.

Validation: before the Outpost persists a change, it calls [`ValidateSettings`](#validatesettings) with it. An
`invalid_argument` blocks the change, with nothing persisted. When Core does not answer, the Outpost's own checks decide.

### ValidateSettings

A dry run of `SaveSettings`: `changes` is validated over the current settings (the defaults while Core is uninitialized)
and the reply is `{}`. It takes no `requestId` and no `expectedRevision`, and it changes nothing: no write, no revision or
generation change. A fault is the same `invalid_argument` with the same field errors `SaveSettings` gives for these
`changes` (`changes.dns.decisionCacheMax`). A pass says the values are valid, not that a later `SaveSettings` finds the
revision unchanged.

### Projection `dns`

The DNSBL resolver settings `pfb-dns` reads from `pfb_unbound.ini` today. `pfb-dns` will fetch them as `settings/dns`
(map #3813, owner 2026-11-12). The field list with registry keys is on [#3842](https://github.com/pfBlockerNG/pfBlockerNG/issues/3842#issuecomment-6834529521).

| Field | Type, default |
|---|---|
| `replyLogging`, `hstsNullBlocking`, `pslIncludePrivate`, `idnBlockMalicious` | bool, `true` |
| `tldWildcard`, `pslAllowPrivate`, `idnEscalateSuspicious`, `logViaWebserver`, `cnameValidation`, `control`, `regexCap`, `metricsClientIp` | bool, `false` |
| `controlLegacy` | bool, `false`; `requires` `control` |
| `pslFeedPrivatePolicy`, `pslFeedIcannPolicy` | enum `ignore` / `apex` / `honor`, `honor` |
| `idnMode` | enum `off` / `confusable` / `on`, `off` |
| `decisionCacheMax` | int 0 to 5000000 (0: unlimited), `10000` |

Parity fixture: `tests/core/fixtures/settings_dns_parity.json`. `CoreSettingsDnsParityTest` (PHPUnit) freezes it against
today's PHP. `go/pfb_core/settings/parity_test.go` runs Core against it.

### Projections `feeds/ipv4`, `feeds/ipv6`, `feeds/dnsbl`

The groups of the IPv4, IPv6 and DNSBL Groups pages, as far as downloading and parsing their feeds needs (issue #3937;
the field inventory with config.xml keys and readers is on [#3937](https://github.com/pfBlockerNG/pfBlockerNG/issues/3937#issuecomment-6851184458)).
Each holds one field, `groups`: a list keyed by `name`, in config order. Firewall rule options and the DNSBL build
options stay with the Outpost; the schedule override is in [`settings/schedule`](#projection-schedule).

| Group field | Type, default |
|---|---|
| `name` (key) | string `[A-Za-z0-9_]+`, IP at most 24 characters |
| `action` | enum: IP `Disabled` `Deny_*` `Permit_*` `Match_*` (`Inbound`/`Outbound`/`Both`) `Alias_Deny` `Alias_Permit` `Alias_Match` `Alias_Native`; DNSBL `Disabled` `unbound`; `Disabled` |
| `updateFrequency` | enum `Never` `01hour` `02hours` `03hours` `04hours` `06hours` `08hours` `12hours` `EveryDay` `Weekly`, `Never` |
| `bindAddress` | string, an IP address or `""` (the source interface, translated by the Outpost), `""` |
| `preScript`, `postScript` | string, a file name in Core's script directory or `""`, `""` |
| `customList` | string, `""` |
| `suppressionCidr` (IPv4) | int 0 to 32 (0: off), `0` |
| `whoisConvert` (IP) | bool, `false` |
| `feeds` | list keyed by `header`, `[]` |

| Feed field | Type, default |
|---|---|
| `header` (key) | string `[A-Za-z0-9_]+`, not `DNSBLIP` or a GeoIP continent alias; unique across the groups of the type (it names one file) |
| `state` | enum `enabled` `disabled` `hold` `flex`, `enabled` |
| `format` | enum: IP `auto` `geoip` `regex` `whois` `asn` `rsync`; DNSBL `auto` `rsync`; `auto` |
| `url` | string without control characters or `<>"`, no userinfo, a local file as `file://`; unless `disabled`, required and without `_API_KEY_`; `""` |
| `credentials` | secret string: the URL's userinfo (only beside a `scheme://` url; no `/`, `?`, `#`), `""` |
| `action` (DNSBL) | enum `deny` `permit`, `deny` |

The adapter answers only groups and feeds that pass these rules; one that does not (a duplicate or reserved header, a
name that is not a word) is left out of the read and left alone by a write. A write changes only the config.xml keys
whose value changed. Groups and feeds are matched by key: a rename is a delete and an add (the Outpost-only fields of
the old one go); the ones Core keeps take their slots in Core's order, one that does not project keeps its slot; a
deleted name or header goes with every stored duplicate of it. A feed added to a group whose first row has no source
is refused (pfBlockerNG ignores every row of such a group). The revision is keyed (HMAC with a per-box key, root's
alone, in `/var/db/pfblockerng/core_revision.key`), so it confirms no guess of a credential. `bindAddress` is the
interface's IPv4 address, so a changed interface address moves the revision.

Parity fixture: `tests/core/fixtures/settings_feeds_parity.json`. `CoreSettingsFeedsParityTest` (PHPUnit) freezes it
against today's PHP and the adapter. `go/pfb_core/settings/feeds_parity_test.go` runs Core against it.

### Projection `schedule`

The scheduler's inputs beside `feeds/*` (issue #3941), published as `settings/schedule`.
`ModelFromSettings` (`go/pfb_core/schedule/settings.go`) builds the runtime model from these values and the three feed
projections, keyed by `feeds/ipv4`, `feeds/ipv6` and `feeds/dnsbl`.

| Field | Type, default | config.xml |
|---|---|---|
| `scheduledUpdates` | bool, `true` | `gen/pfb_scheduled_feed_updates` |
| `weekday` | int 1 to 7, `7` | `gen/pfb_schedule_weekday` |
| `hour` | int 0 to 23, `0` | `gen/pfb_schedule_hour` |
| `minute` | int 0 to 45, a multiple of 15, `0` | `gen/pfb_schedule_minute` |
| `groups` | list keyed by `id`, `[]` | the same groups as `feeds/*`, families in IPv4, IPv6, DNSBL order, config order within each |
| `categoryUpdates` | bool, `false` | Blacklist `blacklist_enable` is not empty and not `Disable`, as the runtime model reads it; Core writes `Enable` or `Disable` |
| `categoryFrequency` | enum `Never` `EveryDay` `Weekly`, `Never` | Blacklist `blacklist_freq` |
| `categoryProviders` | list keyed by `id`, `[]` | Blacklist `item`, in config order |

| Group field | Type, default |
|---|---|
| `id` (key) | string `(ipv4\|ipv6\|dnsbl)/[A-Za-z0-9_]+`: family/group name |
| `override` | bool, `false`: `schedule_override` is `on` |
| `weekday`, `hour`, `minute` | the same types and defaults as the default slot; `schedule_weekday`, `schedule_hour`, `schedule_minute` |

| Provider field | Type, default |
|---|---|
| `id` (key) | string `[A-Za-z0-9_-]+`, not `0`: the item's `xml` |
| `selected` | bool, `false`: id in `blacklist_selected` |
| `categories` | string `[A-Za-z0-9_,.-]*`, `""`: the item's `selected` CSV |

A missing or invalid stored slot field reads as its default, independently of the other slot fields. This differs from
the old PHP runtime model: an override on with an invalid slot rejects that entire model, while the projection gives
Core a valid defaulted slot. A provider with an invalid identity or categories, titled `Shallalist`, with no feed, or
repeating an earlier id is left out. Blacklist updates run only when enabled, with a selected provider whose categories
are not PHP-empty (`""` or `"0"`), and frequency `EveryDay` or `Weekly`; only `Weekly` gives weekly cadence.

Writes change only changed keys, together with the other projections in one `write_config()`. An unknown group or
provider id is `invalid_argument` naming the field: this projection cannot create them. An item left out of either list
is unchanged, not deleted. Provider selection removes its id from `blacklist_selected` or appends it, preserving the
other ids' order. Category changes write the existing item's `selected` CSV. Group patches apply after feed merges;
a group deleted by a feed projection in the same save is not patched. All these values participate in the revision.
After a `SaveSettings`, Core reads its backend again, so derived schedule membership is current at once.

Parity fixture: `tests/core/fixtures/settings_schedule_parity.json`. `CoreSettingsScheduleParityTest` freezes the adapter
read and PHP runtime model; `go/pfb_core/settings/schedule_parity_test.go` checks validation and read-back, and
`go/pfb_core/schedule/settings_test.go` compares the models, including `config_hash`. Rejected PHP models are recorded
as `null`, separately from the valid defaulted projection.

## Update and schedule

Core runs the singleton Update and its quarter-hour scheduler (issue #3941, map #3813) when it starts with
`--update-cmd PATH` ([Update command](#update-command)). Without the flag Core runs no scheduler and `StartUpdate`,
`GetUpdate` and `GetSchedule` answer `unavailable` ("Core runs no scheduler: start it with --update-cmd"). The pfSense
layer relays these calls from its authenticated pages; Core is never exposed to a browser.

- **One Update at a time.** Every trigger goes through one gate: the scheduler's own `scheduled`, and `manual`, `apply` and
  `retry` from `StartUpdate`. The gate is a nonblocking lock held for the whole run: a second Update is refused, never
  queued. A `scheduled` trigger that finds it taken is skipped (its occurrences stay unreserved, so the next quarter hour
  plans them again); a `StartUpdate` gets `conflict` ("an Update is running") and can read the running Update with
  `GetUpdate`.
- **Scheduler.** At every quarter-hour boundary (a Unix time that is a multiple of 900 s, read in the host's time zone)
  Core plans what is due from `settings/schedule` and the `settings/feeds/*` projections as they are then (a save or
  `SettingsChanged` refreshes them), reserves the occurrences and starts a `scheduled` Update with the feeds and Extras
  (`extra:dcc`, `extra:bl`) that are due. Nothing due starts nothing.
- **Restarts.** Core starts idle. The pending occurrences and outcomes are kept in `schedule_state.json`; a missing or
  unusable file starts empty and the next quarter hour plans what is due. The Update, its log and its result are in
  memory and in `update.log`, which a new Update starts again: nothing of an Update survives a restart. A stop while an
  Update runs ends it, and the next Core starts fresh and resumes nothing.

### StartUpdate

Asks for an Update. It takes a `requestId` ([replay](#requestid-and-replay)) and `trigger`, which is required:

| `trigger` | Runs | Other parameters |
|---|---|---|
| `manual` | the feeds and Extras of `scope` (`ip`, `dnsbl` or `both`, default `both`) with `force` (`none`, `parse`, `download` or `both`, default `none`) | `scope`, `force` |
| `apply` | the apply, without feeds or Extras | none: `scope` and `force` are refused |
| `retry` | the pending feeds and due Extras, the way a quarter-hour run plans them, even when nothing is due | none: `scope` and `force` are refused |

The reply is `{}` once the Update is admitted, not when it ends: read it with `GetUpdate`. A value the table does not allow
(`scheduled` is not one) is `invalid_argument` with one field error per fault (`trigger`, `scope`, `force`) and nothing
starts. `conflict` means an Update is running. `unavailable` means Core is stopping or runs no scheduler. A `retry` plans like
a quarter-hour run, so one whose model cannot be built from the settings (not initialized, or a value the schedule refuses)
starts nothing and is `unavailable` too, with the reason, as `GetSchedule` is; a `scheduled` one is logged and skipped. An
`apply` plans nothing and needs no model.

### GetUpdate

Progress is polled, not streamed. `after` is an opaque cursor: the `next` of an earlier reply, passed back as the decimal
string it is (`{"after": "1099511627800"}`). A client never builds, orders or does arithmetic on one. Absent (or `null`) and
`"0"` read from the start of the Update's log. A value that is not a string of decimal digits, or does not fit 63 bits (a JSON
number, `"-1"`, `"abc"`, `"1.5"`, `""`), is `invalid_argument` with a field error on `after`. The reply is:

| Field | Value |
|---|---|
| `running` | `true` while an Update runs, explicitly `false` otherwise |
| `update` | `null` until this Core's first Update; else `{"trigger", "scope", "force", "startedAt", "finishedAt", "result"}`: `startedAt` and `finishedAt` in Unix seconds, `finishedAt` and `result` only once it ended, `result` `success` (the program exited 0 and its result, if any, was usable) or `failed` |
| `log` | the log's bytes from the cursor, at most 64 KiB, never ending inside a UTF-8 character; `""` before the first Update |
| `next` | the cursor after `log`, a JSON string: pass it as `after` in the next call; `"0"` before the first Update |

The last Update stays readable until the next one starts. A client follows an Update by calling again with the last `next`
as `after`. The cursor names the Update it belongs to, so the first call after a new Update has started reads that Update's
log from its start: the client needs no other signal. A cursor of an earlier Update, or one past the log's end, reads from the
start. It is a string because it exceeds 2^53, which a browser or a PHP float holds exactly, from the 8193rd Update of a Core.

The cursor's Update is counted from this Core's start, so a cursor from before a restart can match the new Core's first
Update and skip the start of its log. `update.startedAt` is the hint for that case only: a client that sees it differ from the
one it followed drops its cursor and calls without `after`.

### GetSchedule

Takes no parameters; the reply is computed from the settings and the scheduler's state at the call:
`{"scheduled": bool, "feeds": {"lastRun", "nextDue"} or null, "extras": {"extra:dcc": {...}, "extra:bl": {...}}}`. `scheduled`
is the General switch for scheduled feed updates. `feeds` is the feeds' entry, `null` when scheduled updates are off or no
feed is or will be due. `extras` holds the Extras that are enabled and will be due. A time is Unix seconds, `lastRun` 0 when
never run. When the model cannot be built (the settings are not initialized, or hold a value the schedule refuses) the call is
`unavailable` with the reason.

### Update command

`--update-cmd PATH` names the program that runs each Update; the path comes only from the flag. Core runs it once per Update:

- **stdin:** one JSON object, `{"version": 1, "trigger": "scheduled|manual|apply|retry", "scope": "ip|dnsbl|both",
  "force": "none|parse|download|both", "feeds": [ids], "extras": ["extra:dcc", "extra:bl"]}`. `feeds` and `extras` are left out
  when empty; a feed id is the schedule's (`ipv4:<header>_v4`, `ipv6:<header>_v6`, `dnsbl:<header>`). A `scheduled` or `retry`
  Update names what to run; a `manual` one runs its scope.
- **stdout and stderr:** the progress log, `update.log` in `--state-dir`: a regular file Core owns, never a pipe (an Update
  restarts daemons, and one that inherited a pipe would hold it open). A new Update truncates it.
- **fd 3:** a second regular file, for the result: `{"version": 1, "outcomes": {id: "success"|"retry-cap-reached"},
  "attempted": [ids], "geoipReady": bool}`. Nothing written is nothing reported. Anything else that is not exactly one such
  object of at most 1 MiB fails the Update and records nothing.
- **Exit status:** 0 is success. A non-zero exit fails the Update, and a valid result it wrote still counts.
- **Process group and bounds:** the program runs in its own process group. The group is killed (TERM, then KILL after 5 s)
  at a hard cap of 4 hours, when the Update is cancelled and when Core stops; never when the program exits by itself, so a
  daemon it started keeps running.

Core then records the result in `schedule_state.json` (0600, `{"schema": 1, "items": {...}}`, replaced atomically): each
feed's outcome, the attempted ids that stay pending, and the GeoIP readiness the program saw (`true` until the first report).
The Extras plan uses the last readiness reported. The cutover imports configuration only, so a Core that finds no state file
starts empty.

**Stopping.** TERM or INT during an Update cancels it: the program's group gets TERM, and KILL 5 s later if it is still there,
and Core stops after that. A program that ignores TERM keeps Core's stop past the rc script's 5 s before KILL. The Update is
not resumed: the next Core starts idle and the scheduler plans from its state file.

## Errors

Every error is the same envelope, with the HTTP status its code maps to:

```json
{"error": {"code": "invalid_argument", "message": "a mutating method needs a valid requestId",
  "fieldErrors": [{"field": "requestId", "message": "required"}]}}
```

`fieldErrors` is present only when a named parameter is at fault. `message` is for people; a client decides on `code`.

| `code` | HTTP | When |
|---|---|---|
| `invalid_argument` | 400 | Body not one JSON object, unknown or mistyped parameter, bad or missing `requestId` |
| `unauthenticated` | 401 | The caller is not an admitted local process (see [Local authentication](#local-authentication)) |
| `not_found` | 404 | No such method, or no such API version |
| `method_not_allowed` | 405 | Not `POST` |
| `conflict` | 409 | A `requestId` reused with a different body; a settings call the store's state refuses ([Settings](#settings)); `StartUpdate` while an Update runs ([Update and schedule](#update-and-schedule)) |
| `payload_too_large` | 413 | Body over the limit |
| `internal` | 500 | The method failed unexpectedly or ran past its deadline (logged); also any code a method returns that is not in this table |
| `unavailable` | 503 | A repeat of a `requestId` whose first request still ran when the repeat's own deadline passed; the settings backend failed; Core runs no scheduler (no `--update-cmd`) or is stopping; the schedule cannot be computed ([Update and schedule](#update-and-schedule)) |

## requestId and replay

A mutating method (`InitializeSettings`, `SaveSettings`, `StartUpdate`) takes a `requestId` in its parameters: a string of 1 to
128 printable ASCII characters without spaces. The method declares `requestId` in its own parameters, since unknown
parameters are refused. The client makes one per logical operation (a UUID will do) and sends it
again, with the byte-identical body, to resolve an unknown outcome such as a timeout.

- The first request with a `requestId` runs the method, to its end even when its caller disconnects (up to the method
  deadline). Every repeat with the same method, `requestId` and body gets the
  first response, status and bytes, whatever it was (an error included), and the method does not run again.
- A repeat that arrives while the first still runs waits for its result; it never runs the method itself.
- The same `requestId` with a different body is `conflict`, and nothing runs.
- Core remembers the last 4096 finished `requestId`s (one still running is never forgotten), in memory only: a
  restarted Core remembers none. A client that cannot tell
  whether its request ran before a restart reads the state it changed instead of repeating it.

A read-only method takes no `requestId` and is never replayed.

## Limits and timeouts

| Limit | Value |
|---|---|
| Request body | 1 MiB (`payload_too_large` above) |
| Request header | 16 KiB |
| Reading the header | 5 s; a client that has not sent it by then is disconnected |
| Reading the whole request | 10 s |
| Running a method | 25 s (its context is cancelled) |
| Writing the reply | 45 s from the end of the header (covers the body read and the method) |
| Idle keep-alive connection | 60 s |

## Local authentication

**Decision: Unix socket, file permissions plus the kernel's credential of the caller.** Only processes on the pfSense host
can reach a Unix socket at all, so Core is unreachable from any other host by construction, with no listener and no
firewall rule to get wrong. Each connection's uid comes from the kernel (`LOCAL_PEERCRED` on FreeBSD, `SO_PEERCRED` on
Linux), so there is no secret to create, store, rotate or leak. PHP reaches the socket with native curl
(`CURLOPT_UNIX_SOCKET_PATH`). Loopback TCP plus a token file was rejected: any local user can connect to loopback, so
everything would rest on keeping the token file secret, and a client would need to read it.

Two fences, each enough on its own against an unprivileged user:

1. **File permissions.** Core creates the socket's directory mode 0700 and the socket 0600, both its own (root's). An
   existing directory is used only while it is a real directory (not a symlink) of Core's user with mode 0700 or 0750;
   anything else, a shared directory such as `/tmp` included, stops the start instead of being changed. Another
   user cannot even connect (`EACCES`).
2. **Caller uid.** Every request is checked against the admitted uids. Any other caller gets `unauthenticated` and no
   method runs.

Flags: `--allow-uid UID` is the privileged caller (default 0, root: PHP on pfSense). Each `--client-uid UID` admits one more
local client. `--socket-group GID` opens the socket's directory (0750) and the socket (0660) to that group, so a client that
is not root can connect. Even then, the uid check decides who is served: group membership alone is not enough.

**A second local client: pfb-dns.** pfb-dns will fetch `dnsbl/*` and its settings from Core over this API (map #3813). It
drops privileges to its own user after start. The pfb-dns ticket admits it by adding `--client-uid <that user's uid>` and
`--socket-group <a group of that user>` to Core's rc line; Core needs no new code. pfb-dns runs as `unbound` today, so
admitting that uid admits every process of that user, Unbound included. A dedicated pfb-dns user narrows that, and the
pfb-dns ticket decides it.

## On pfSense

| What | Where |
|---|---|
| Binary | `/usr/local/pkg/pfblockerng/core/bin/freebsd-amd64/pfb-core`, `.../freebsd-arm64/pfb-core` (static, `CGO_ENABLED=0`; built by `scripts/build-pfb-dns.py`) |
| rc script | `/usr/local/etc/rc.d/pfb_core.sh`, written by `pfb_core_service()`; pfSense service `pfb_core`; it starts pfb-core with `--settings-backend-cmd` and `--update-cmd` |
| Supervisor | `daemon(8) -r -R 5 -t pfb_core`, pidfiles `/var/run/pfb_core_daemon.pid` (supervisor) and `/var/run/pfb_core.pid` (pfb-core) |
| Log | `/var/log/pfblockerng/core.log` (pfb-core's stderr, through `daemon -o`) |
| Socket | `/var/run/pfb_core/api.sock` |
| State (`--state-dir`) | `/usr/local/etc/pfb_core` (0700): Core's data and its lock, never settings; with `--update-cmd` also `schedule_state.json` and `update.log`; outside `/var`, so it survives a RAM-disk reboot |
| Settings backend | `/usr/local/pkg/pfblockerng/pfb_core_settings.sh` (`--settings-backend-cmd`): `config.xml` through PHP |
| Update program | `/usr/local/pkg/pfblockerng/pfb_core_update.sh` (`--update-cmd`): the `core_update` verb of `pfblockerng.inc` |

- **Start** and **Stop** run under one lock (`lockf -k -t 20 /var/run/pfb_core.lock`; status 75 when another start or
  stop holds it). **Start** keeps a pfb_core supervisor that already runs. Otherwise it runs this machine's binary (picked by `uname -p`), and it
  fails when `daemon(8)` fails or its pidfile names no supervisor within 5 s; it returns once the supervisor runs, not once
  the socket listens. A package without an executable `pfb-core` for this machine starts nothing and logs why. That is not
  a failure. An unknown machine is a failure.
- **Stop** sends TERM to the supervisor and to pfb-core, then KILL at 5 s. It signals a process only while its pidfile names it
  and its command line is pfb_core's, so a reused pid is never signalled. pfb-core first ends a running Update (the
  program's process group gets TERM, and KILL 5 s later), then finishes the requests in flight (up to
  3 s) and removes its socket. A process still running at 7 s fails the stop, keeps the pidfiles and fails a start or
  restart over it.
- **Package lifecycle.** The install and every upgrade regenerate the script and restart the service. pfSense starts it at
  boot with the package's services. A removal stops it and deletes the script. Regenerating the script deletes
  the #3842/#3913 leftovers: `settings.json`, `settings.json.tmp` and `settings.lock` in the state directory, and
  `core_pushed` / `core_push_failed` in `/var/db/pfblockerng`, and (#3941) the PHP scheduler's `pfb_schedule_state.json` in
  `/usr/local/etc` and the schedule entries of `/var/db/pfblockerng/pfb_due_ledger.json` (`extra:dcc`, `extra:bl`, the cache
  stamp and the times of `cron`; its `pending_apply` flag, `ss_refresh` and `apply_reconcile` stay). With Keep Settings off, a removal also deletes the state
  directory once `pfb_core` is stopped (`pfb_core_state_teardown()`).
- **Paths.** Core reads every path from a flag. It names no pfSense path and imports nothing but the standard library, its
  own packages, `golang.org/x/net` and `golang.org/x/text` (the feed parser's UTS #46 conversion), `golang.org/x/sys` (CPU
  feature detection for xxh128), all pinned in `go.mod` to the versions of `go/pfb_dns_gateway`, and
  `github.com/pfBlockerNG/xxh3` (the feed content digest, xxh128 as PHP writes it; the pfBlockerNG fork of `zeebo/xxh3`,
  #3925). `go/pfb_core/boundary_test.go` enforces this, build-constrained files included, and fails on a violation. The CI Go gate (`test.yml` `go-quality`, `scripts/agent/run-gates.sh`) runs it.

Log lines (stderr): `serving API v1 on <socket> for uid <uid>, clients [<uids>]` once it listens; `refused a caller of uid
<uid>: ...` per refused request; `<Method> failed: ...` for an internal error; `stopped` after a clean stop.

## Calling from PHP

```php
$r = pfb_core_call('GetVersion');
// ['status' => 200, 'body' => ['service' => 'pfblockerng-core', 'apiVersion' => 'v1', 'status' => 'serving'], 'error' => NULL]
```

`pfb_core_call($method, $params)` posts `$params` as one JSON object. It returns the HTTP status and the decoded reply
object, the error envelope included. When no HTTP reply came (Core down, socket missing, timeout), `status` is 0 and `error`
says why. The optional last parameter `$timeout` is the total time in seconds (default 30). Pinned by `PfbCoreCallTest`;
the rc script by `PfbCoreServiceTest`; the server by `go/pfb_core/*_test.go`.

On pfSense `config.xml` is Core's settings backend. The rc script starts Core with `--settings-backend-cmd
/usr/local/pkg/pfblockerng/pfb_core_settings.sh`, which runs `pfblockerng.inc core_settings`: `pfb_core_settings_backend()`
answers `read` with `pfb_core_dns_settings()` and writes under the DNS config lock (`pfb_dns_config_lock()`): it checks the
revision, writes only the fields that differ, runs `write_config()` (so Config History, backups and HA sync cover the
change), marks the changes pending for the next Update, and reports a refused `write_config()` as `unavailable`. A change
of `metricsClientIp` goes through `pfb_metrics_client_save()`, as the General page's does. The revision is
`pfb_core_settings_revision()`: 52 bits of the SHA-256 of the projected values.
`pfb_core_settings_validate()` is the dry run a page calls after its own checks and before `write_config()`: only
`invalid_argument` refuses the save, which then writes nothing; DNS > General, DNS > DNSBL and General are the pages. The dry
run runs under the DNS config lock, which other saves wait for at most `PFB_DNS_CONFIG_LOCK_WAIT` (10 s), so it asks with
`PFB_CORE_VALIDATE_TIMEOUT` (3 s) instead of the default 30 s: a Core that has not answered by then could not judge, and the
page's own checks decide. A save's other side effects wait for the written config too: DNS > DNSBL invalidates the TOP1M
baseline, requests the TOP1M rebuild and replaces the served block page only after `write_config()` succeeded. After
a written save they call `pfb_core_settings_changed(NULL, TRUE)` (`SettingsChanged`); the tick calls it unforced (compare,
then notify). A save works while Core is down. A failed notice is logged once per outage and kept in
`/var/db/pfblockerng/core_settings_failed` until one succeeds; DNS General shows it as a notice. Pinned by
`CoreSettingsBackendTest`, `CoreSettingsChangedTest`, `CoreSettingsPageSavesTest` and `CoreSettingsValidateTimeoutTest`.

A package without `pfb-core` is not supported. `stage_pfb_dns()` in `scripts/build-pkg-portable.py` stages `pfb-core` in the
same helper run as pfB-DNS whenever the source carries `go/pfb_core` and the port installs the `dns_proxy` payload (it
returns early otherwise), so a package built from this tree with the port as it is always ships it. On a build without it no
Core ever reads `config.xml`, and the notice "pfBlockerNG Core has not read the saved settings yet" stays on DNS General for
good: by design, nothing hides it.

On pfSense Core runs each Update through `--update-cmd /usr/local/pkg/pfblockerng/pfb_core_update.sh`, which runs
`pfblockerng.inc core_update`: `pfb_core_update_serve()` validates the request ([Update command](#update-command); version 1,
a trigger, a scope and a force of the protocol's vocabulary, feed ids by `pfb_schedule_feed_id()`'s rules, each id once,
no other field; a refused request runs nothing, writes no result and exits 2) and runs it with the Outpost's passes:

- `scheduled` and `retry`: the Extras named (dcc, then bl; one the Outpost skips is `attempted`, so Core does not ask again
  every quarter hour), the GeoIP readiness (not ready: no feed pass and no apply, the feeds get no outcome), then the feed pass
  (`pfblockerng_sync_cron()` on exactly the feeds named, beside the `*.fail` retries as always) when feeds are named, a `*.fail`
  marker of an enabled feed exists or the DNSBL manifest is absent, and the apply of a dcc that changed content;
- `apply`: the pending apply, its ledger flag cleared first; a failed apply keeps the flag and the marker and exits 1;
- `manual`: the scope with the force the page asked for (`none`: `sync_package_pfblockerng()` as Run Now; `parse`: forced;
  `download`, `both`: the Force Check pass, `both` clearing the hashes too).

`scheduled`, `retry` and `apply` hold the dispatcher and feed-pass locks for the whole Update, which serialize the entry points
Core does not start (a page save, an HA receive); a lock that is held defers the Update (exit 75). Progress is stdout: while it
serves, `pfb_logger()` mirrors to stdout, which is Core's `update.log`, and a hook's output is appended to the same file; the
`pfblockerng_run.log` is not opened. The result goes to fd 3, the exit status is 0 on success and 1 on a failed Extra, pass or
apply. Pinned by `CoreUpdateServeTest`.

The tick (`pfblockerng_tick()`) keeps the Outpost's duties and asks Core for the two Updates only the Outpost can tell are due:
`StartUpdate` of `apply` for a pending change inside the apply window (outside it, the tick logs that it is deferred and the apply
record says waiting), and of `retry` for a `*.fail` marker of an enabled feed or an absent DNSBL manifest. `conflict` is a logged
skip and an unreachable Core a logged notice: nothing runs in the tick instead. It reads and writes no schedule state or cache,
and skips log maintenance while Core reports an Update running. Pinned by `TickCoreUpdateTest` and `DnsblManifestTickRecoveryTest`.
