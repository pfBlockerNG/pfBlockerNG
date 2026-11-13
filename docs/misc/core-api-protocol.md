# Core API protocol

Scope: the HTTP+JSON API of the pfBlockerNG Core daemon (`go/pfb_core`, binary `pfb-core`, issue #3841; map #3813), the
conventions every Core method follows, the settings methods and backends (issues #3842, #3913, #3924), who may
call it, and how the package runs it. Load when: adding a Core method or settings projection, calling Core from PHP or
another local process, or changing `go/pfb_core`, `pfb_core_service()` or `pfb_core_call()`.

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
  either backend. A second `pfb-core` on the same directory does not start.
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
| `bindAddress` | string, an interface's IPv4 address, `127.0.0.1` for `lo0`, or `""` for the default route; `""` |
| `preScript`, `postScript` | string, a file name in Core's script directory or `""`; not `.` or `..`, no leading `-`, `/` or control character; `""` |
| `customList` | UTF-8 string (invalid stored bytes scrubbed on read without rewriting storage), `""` |
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

A group whose stored Source Interface is missing or has no IPv4 address does not project, including IPv6 groups. Hiding a
group never promotes a later one: a group of the same name stays hidden too, and so does a feed whose header a row of an
earlier group holds (a row of a hidden group included). A new group cannot take the name of a stored group that does not
project; a new feed cannot take the header of any stored row of its type that does not project. Edit these entries on
the Groups page first. A write leaves a hidden group's own fields and rows untouched; the one exception is the type-wide
rule above: a header Core drops from the type is removed from every group of the type, hidden ones included.
After a successful write, each changed custom list (new non-empty lists included) is flagged for the next Update
with `<folder>/<name>_custom<suffix>.update`, as on the Groups page: the stored action determines the folder,
including Advanced Invert routing; the suffix is `_v4`, `_v6` or empty for DNSBL. An action with no list folder
(Disabled), an unchanged list, or a refused or failed write flags nothing.

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
| `conflict` | 409 | A `requestId` reused with a different body; a settings call the store's state refuses ([Settings](#settings)) |
| `payload_too_large` | 413 | Body over the limit |
| `internal` | 500 | The method failed unexpectedly or ran past its deadline (logged); also any code a method returns that is not in this table |
| `unavailable` | 503 | A repeat of a `requestId` whose first request still ran when the repeat's own deadline passed |

## requestId and replay

A mutating method (`InitializeSettings`, `SaveSettings`) takes a `requestId` in its parameters: a string of 1 to
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
| rc script | `/usr/local/etc/rc.d/pfb_core.sh`, written by `pfb_core_service()`; pfSense service `pfb_core` |
| Supervisor | `daemon(8) -r -R 5 -t pfb_core`, pidfiles `/var/run/pfb_core_daemon.pid` (supervisor) and `/var/run/pfb_core.pid` (pfb-core) |
| Log | `/var/log/pfblockerng/core.log` (pfb-core's stderr, through `daemon -o`) |
| Socket | `/var/run/pfb_core/api.sock` |
| State (`--state-dir`) | `/usr/local/etc/pfb_core` (0700): Core's data and its lock, never settings; outside `/var`, so it survives a RAM-disk reboot |
| Settings backend | `/usr/local/pkg/pfblockerng/pfb_core_settings.sh` (`--settings-backend-cmd`): `config.xml` through PHP |

- **Start** and **Stop** run under one lock (`lockf -k -t 20 /var/run/pfb_core.lock`; status 75 when another start or
  stop holds it). **Start** keeps a pfb_core supervisor that already runs. Otherwise it runs this machine's binary (picked by `uname -p`), and it
  fails when `daemon(8)` fails or its pidfile names no supervisor within 5 s; it returns once the supervisor runs, not once
  the socket listens. A package without an executable `pfb-core` for this machine starts nothing and logs why. That is not
  a failure. An unknown machine is a failure.
- **Stop** sends TERM to the supervisor and to pfb-core, then KILL at 5 s. It signals a process only while its pidfile names it
  and its command line is pfb_core's, so a reused pid is never signalled. pfb-core finishes the requests in flight (up to
  3 s) and removes its socket. A process still running at 7 s fails the stop, keeps the pidfiles and fails a start or
  restart over it.
- **Package lifecycle.** The install and every upgrade regenerate the script and restart the service. pfSense starts it at
  boot with the package's services. A removal stops it and deletes the script. Regenerating the script deletes
  the #3842/#3913 leftovers: `settings.json`, `settings.json.tmp` and `settings.lock` in the state directory, and
  `core_pushed` / `core_push_failed` in `/var/db/pfblockerng`. With Keep Settings off, a removal also deletes the state
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
