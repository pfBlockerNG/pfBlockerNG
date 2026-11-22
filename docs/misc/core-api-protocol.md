# Core API protocol

Scope: the HTTP+JSON API of the pfBlockerNG Core daemon (`go/pfb_core`, binary `pfb-core`, issue #3841; map #3813), the
conventions every Core method follows, the settings methods and backends (issues #3842, #3913, #3924), the singleton Update,
its scheduler and `--update-cmd` (issue #3941), the resource store, `GetResources` and `GetResourceBody` (issues #4032, #4049), `ReportApplied` (issue #4036), who may call it, and how the package runs it. Load when: adding a Core
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
  `Cache-Control: no-store`, with one exception: a successful `GetResourceBody` is plain text ([Resources](#resources)). A
  client ignores reply fields it does not know.
  *Amendment 2026-11-20 (issue #4049): `GetResourceBody` is the protocol's first reply that is not JSON. Its errors keep
  the JSON envelope.* A request that is not valid HTTP (a malformed
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
| `ValidateSettings` | `changes` | `{}`, or the errors `SaveSettings` would give (bar the rule for an added `noAaaaList` entry); changes nothing |
| `SettingsChanged` | none | what `GetSettings` answers: Core read its backend again |
| `StartUpdate` | `requestId`, `trigger`: `manual` (`scope`, `force`), `apply` or `retry`; optional `lifecycle`, `pkgOp` | `{}` once the Update is admitted; `conflict` while one runs |
| `GetUpdate` | `after` (optional cursor, a decimal string; default: the start) | `{"running", "update", "log", "next"}`: the current or last Update and a chunk of its log; `next` is a string |
| `GetSchedule` | none | `{"scheduled", "feeds", "extras", "lastSuccessfulCheck"}`: when the scheduled Updates last ran and are next due, and each item's last successful check |
| `GetResources` | `resources` (optional; none: nothing is read): resource id to cursor | `{"resources": {id: item}}`: per resource unchanged, a delta from the cursor, or the full body, described without its members; read-only |
| `GetResourceBody` | `id`, `generation`, `part` (`members`, `add` or `remove`), `from` (with `add` and `remove`) | the part's lines as `text/plain`, streamed from the store; read-only |
| `ReportApplied` | `requestId`, `resources`: `dnsbl/*` resource id to the generation and digest the caller serves | `{}` once the report is recorded in the state directory |

`GetVersion` is also the health check: a `200` with `status` `serving` means Core takes requests.

The privileged uid is served every method. A further local client (`--client-uid`) is served only `GetVersion`,
`GetSettings`, `GetResources`, `GetResourceBody` and `ReportApplied`, and reads through them only the `dns` and
`policy/dnsbl` settings projections and the `dnsbl/*` resources ([Local authentication](#local-authentication)).

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

  A projection may carry `readOnly: true` (issue #3975): Core only reads it, from its backend. `InitializeSettings`,
  `SaveSettings` and `ValidateSettings` refuse a change set that names it, with any content (also `{}` and `null`):
  `invalid_argument`, one field error naming the projection (`changes.ingest`, or `settings.ingest` for `InitializeSettings`, whose argument is
  `settings`), and nothing of the change set is applied.
  `InitializeSettings` gives it its defaults. [`ingest`](#projection-ingest), [`maintenance`](#projection-maintenance) and
  [`hooks`](#projection-hooks) are read-only.
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
- **Backend failure** (`unavailable`): the backend could not be read or written. Core keeps the values it last read. A
  call that the method's 25 s deadline cut off answers `internal` (logged) instead.
- **No run.** A save starts no run.
- **Secrets are write-only.** A read shows a secret field as `{"present": true|false}`, never its value, in list items too.
  Code inside Core's process (the feed phase) reads a projection with its secrets in clear through `Store.GetClear`
  (`go/pfb_core/settings`); no API method answers it, and a test pins that `GetSettings` still shows presence only.
- **One Core per state directory.** Core holds an exclusive `flock` on `core.lock` in `--state-dir` while it runs, with
  either backend. A second `pfb-core` on the same directory does not start. With `--update-cmd` the directory also holds
  `schedule_state.json` and `update.log` ([Update command](#update-command)).
- **Schema growth.** A projection or field the backend does not hold yet reads as its default. A projection or field
  the schema no longer has stops the start (file backend) or fails the read (adapter): removing one needs a migration.
  *Amendment 2026-11-18 (issue #4055): a field the schema retires is listed as retired in its projection, and a load
  drops it instead of refusing (`dns.logViaWebserver`, `dns.hstsNullBlocking`, `ingest.sinkholeV4`,
  `ingest.sinkholeV6`); the next save stores the settings without it. The API still refuses the name. Any other
  unknown field still stops the start. Likewise a field may map a legacy stored token to its current value, as
  `PfbConfig`'s read adapters do (#4060): a DNSBL mechanism `enabled`, the removed VIP response, loads as
  `disabled_log`, and the API refuses `enabled`.*
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
take 10 s, a write 20 s, and neither outlasts the 25 s of the method that asked: past either, the command's whole process
group is killed, and the group is killed when any call ends, so nothing the command started outlives the call. Calls run
one at a time. The method's 25 s starts with the method, so the wait for a turn counts against it: a call whose deadline
has passed when its turn comes never starts the command. The wait itself is not cut short by the deadline. A write that
timed out may still have been applied: the Outpost's next tick finds the revision moved and Core reads it. A reply over
32 MiB (the feed projections carry custom lists), a non-zero exit, a reply that is not exactly one JSON object of
version 1, a revision of 0, or read values the schema refuses fail the call. The configuration always exists, so
`InitializeSettings` is refused, and Core never writes `settings.json`.

Protocol, version 1:

| Request | Reply |
|---|---|
| `{"version": 1, "op": "read"}` | `{"version": 1, "revision": N, "settings": {"dns": {...}, "feeds/ipv4": {...}, "feeds/ipv6": {...}, "feeds/dnsbl": {...}, "schedule": {...}, "ingest": {...}, "policy/ip": {...}, "feeds/geoip": {...}, "policy/dnsbl": {...}, "extras": {...}, "hooks": {...}, "maintenance": {...}}, "platform": {"pendingToken": "..."}}` |
| `{"version": 1, "op": "write", "expectedRevision": N, "settings": {...every projection, every field}}` | `{"version": 1, "revision": M}` |

A read also answers `platform.pendingToken` (issue #4031): the Outpost's pending-changes token (`pfb_pending_changes_token()`), a
string, or `null` when nothing is marked. The adapter takes it before it reads the settings, as the apply pass does, so a change
marked meanwhile stays pending. It is not a setting and not part of the revision. Core keeps its JSON value as the adapter wrote
it (`Store.PendingToken`, in-process only), hands it back to the platform in the apply request and never parses, compares or logs
it; no API method answers it. A token JSON cannot carry unaltered (bytes that are not UTF-8) refuses the read whole
(`unavailable`). A write's reply holds no `platform`.

A read carries secrets (feed credentials, the proxy password, the Blacklist providers' passwords) to Core; only Core's API hides them. A write carries `ingest`
as Core read it; the adapter never writes it, and refuses (`invalid_argument`, field errors `ingest.<field>`) a write whose
`ingest` differs from what config.xml and the platform project, after the revision check: a Core that read the box before
an address or the proxy changed gets `conflict` and reads again.

A refusal is `{"version": 1, "error": {"code", "message", "fieldErrors"}}`: `conflict` (the configuration is not at
`expectedRevision`), `invalid_argument` (a malformed request or value; nothing written), `unavailable` (nothing was
written: a lock stayed taken, the platform refused the write, ...). The adapter never calls Core while it serves Core.

### SettingsChanged

The Outpost's notice that its configuration may have changed. Core reads the backend again and answers what
`GetSettings` answers for every projection. It takes no parameters and no `requestId`. A failed read is `unavailable`
(`internal`, logged, when the method's 25 s deadline cut it off), and Core keeps the values it last read. The Outpost
calls it:

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
`changes` (`changes.dns.decisionCacheMax`), except the rule for an entry a write adds to `noAaaaList`, which only
`SaveSettings` applies: a page's dry run sends the projection as `config.xml` holds it, which may carry an entry Core has
not loaded yet. A pass says the values are valid, not that a later `SaveSettings` finds the revision unchanged.

### Projection `dns`

The DNSBL resolver settings `pfb-dns` reads from `pfb_unbound.ini` today. `pfb-dns` will fetch them as `settings/dns`
(map #3813, owner 2026-11-12). The field list with registry keys is on [#3842](https://github.com/pfBlockerNG/pfBlockerNG/issues/3842#issuecomment-6834529521).

| Field | Type, default |
|---|---|
| `replyLogging`, `pslIncludePrivate`, `idnBlockMalicious` | bool, `true` |
| `tldWildcard`, `pslAllowPrivate`, `idnEscalateSuspicious`, `cnameValidation`, `control`, `regexCap`, `metricsClientIp` | bool, `false` |
| `controlLegacy` | bool, `false`; `requires` `control` |
| `pslFeedPrivatePolicy`, `pslFeedIcannPolicy` | enum `ignore` / `apex` / `honor`, `honor` |
| `idnMode` | enum `off` / `confusable` / `on`, `off` |
| `decisionCacheMax` | int 0 to 5000000 (0: unlimited), `10000` |
| `noAaaa`, `groupPolicy` | bool, `false` |
| `noAaaaList` | list keyed by `domain`, `[]`: a domain, with a leading `.` for a wildcard entry |
| `groupPolicyBypassList` | list keyed by `cidr`, `[]`: an IP address or a CIDR |

The noAAAA and Group Policy fields (issue #4036) are what `pfb-dns` takes from the `[noAAAA]` and `[GP_Bypass_List]`
sections of `pfb_unbound.ini`. The ini carries a section only while its switch is on. Core holds the switch and the
stored list separately, so a list survives while its switch is off.

- A `noAaaaList` entry is a domain as `pfb-dns` keys its noAAAA table: printable ASCII except `,`, `%`, `#` and upper
  case, and no second leading dot. A leading dot is the wildcard flag (the ini's `domain,1`). The table keeps one flag
  per domain, the last row's, so the list names each domain once, plain or as a wildcard, never both.
- A write may add only a noAAAA entry the DNSBL page saves: `pfb_filter()`'s domain rule once its trailing dots are off
  (letters, digits, `_` and `-` in labels of at most 63 characters joined by dots, none empty). A stored entry outside
  that rule would make every later save of the page fail. An entry the list already holds stays writable whatever it is,
  so a client can write back what it read: Core's load takes the list the Outpost reads, and only an item a write adds is
  held to the page's rule. The rule applies to a write (`SaveSettings`, and the adapter's write), not to the
  `ValidateSettings` dry run.
- A `groupPolicyBypassList` entry is an IP address without a zone, or an address with a prefix length of digits within
  its family. Host bits under the prefix and a prefix length with leading zeros are allowed, as `pfb-dns` reads them. The
  entry is lower case, as the Outpost stores it. Each entry is listed once. Entries are compared as written, so one network
  under two spellings (`10.0.0.1`, `10.0.0.1/32`, `10.0.0.1/032`) is two entries.
- The Outpost does not project an entry that `pfb-dns` skips (a row the ini writer drops, a row of three fields). Beyond
  that, three departures from the ini are deliberate. A noAAAA row holding `%` is not held: today a `%` that is not a valid
  interpolation makes `pfb-dns` refuse the whole ini, and a valid one (`a%%b.com`, `%(0)s`) is interpolated into another
  name. A noAAAA name with white space is not held: it matches no query. A bypass entry in netmask form
  (`10.0.0.0/255.255.255.0`) or with an IPv6 zone (`fe80::1%em0`) is not held: `pfb-dns` takes both from the ini, but the
  DNSBL page never saves either.
- On a write, the Outpost merges each list into its text area: a line whose entry stays is kept, a line holding no entry
  Core can hold (a comment, a departure above) is kept, a line whose entry went is dropped, and a new entry is appended.
  A list is compared as a set, so a write that only reorders it changes nothing.

Parity fixture: `tests/core/fixtures/settings_dns_parity.json`. `CoreSettingsDnsParityTest` (PHPUnit) freezes it against
today's PHP. `go/pfb_core/settings/parity_test.go` runs Core against it: a posted case is saved, and a stored case is loaded
as the adapter's read brings it in, then written back. Its `refused` rows are values of the noAAAA and Group Policy fields
that both the Outpost's write and Core refuse, naming the field. A case of those fields also holds, under `ini`, the raw
text of the `[noAAAA]` and `[GP_Bypass_List]` sections today's writer gives for its stored values (null: no section), which
`CoreSettingsDnsParityTest` freezes, so that `pfb-dns` can be shown to build the same tables from either input.

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
| `listClass` (IP, derived) | enum `none` `deny` `permit` `match` `native`, `none` |
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

`listClass` (issue #4031) is where the Update pass keeps the group's list, derived by the adapter and never stored: `none` for a
`Disabled` group; `native` when either Advanced Inbound or Outbound invert (`autoaddrnot_in`, `autoaddrnot_out`) is stored `on`
(any case; `yes`, `1`, `on` with a leading space and an array are not on); else `match`, `permit` or `deny` by the action's family, and `native` for
`Alias_Native`. A write validates the token and ignores it: no key is stored for it, and the next read derives it again from
the stored action and inversions, so a write that changes `action` leaves the inversions alone.

Parity fixture: `tests/core/fixtures/settings_feeds_parity.json` (its `listClasses` rows hold the action and inversions of a
group, the folder today's PHP builds its list in and the class). `CoreSettingsFeedsParityTest` (PHPUnit) freezes it
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
| `title`, `feed` | text, `""`: the item's `title` and `feed`, set by the package's Blacklist definitions. The pfSense adapter refuses a write that changes one |
| `username` | text, `""`: the item's `username`, which the Extras transfer of the provider's archive authenticates with |
| `password` | secret text, `""`: the item's `password` |

Text is a string of valid UTF-8 without a control character or a BOM, the characters the GUI's free-text filter refuses (#1723).
An item whose title, feed, username or password is not text does not project, like one whose categories hold another
character: Core then neither schedules nor downloads that provider, where PHP's `bl` verb still would. The Blacklist page
stores a username or password HTML-escaped and trimmed (`PFB_FILTER_HTML`); the projection reads the stored value as it
is, and a Core write stores the value as Core sends it.

A missing or invalid stored slot field reads as its default, independently of the other slot fields. This differs from
the old PHP runtime model: an override on with an invalid slot rejects that entire model, while the projection gives
Core a valid defaulted slot. A provider with an invalid identity or categories, titled `Shallalist`, with no feed, or
repeating an earlier id is left out. Blacklist updates run only when enabled, with a selected provider whose categories
are not PHP-empty (`""` or `"0"`), and frequency `EveryDay` or `Weekly`; only `Weekly` gives weekly cadence.

Writes change only changed keys, together with the other projections in one `write_config()`. An unknown group or
provider id is `invalid_argument` naming the field: this projection cannot create them. An item left out of either list
is unchanged, not deleted. Provider selection removes its id from `blacklist_selected` or appends it, preserving the
other ids' order. Category changes write the existing item's `selected` CSV, and a changed username or password writes the item's
`username` or `password` (`""` clears it). A write that changes a provider's title or feed is `invalid_argument` after
the revision check, so a Core that read before config.xml moved gets `conflict`. Group patches apply after feed merges;
a group deleted by a feed projection in the same save is not patched. All these values participate in the revision.
After a `SaveSettings`, Core reads its backend again, so derived schedule membership is current at once.

Parity fixture: `tests/core/fixtures/settings_schedule_parity.json`. `CoreSettingsScheduleParityTest` freezes the adapter
read and PHP runtime model; `go/pfb_core/settings/schedule_parity_test.go` checks validation and read-back, and
`go/pfb_core/schedule/settings_test.go` compares the models, including `config_hash`. Rejected PHP models are recorded
as `null`, separately from the valid defaulted projection.

### Projection `ingest`

**Amendment 2026-11-17 (issue #4053):** the DNSBL WebServer/VIP response is removed, and with it the `sinkholeV4` and
`sinkholeV6` fields, and `dns`'s `logViaWebserver`.

What the feed phase (the Core translation of the download and parse stages, map #3813) reads of the package settings and of the
platform it runs on (issue #3975), published as `settings/ingest`. It is **read-only** ([`readOnly`](#settings)): Core never
changes it, the adapter never writes it, and a change set that names it is refused. A fact that is the box's own (an interface
address, a VIP, the proxy) moves the revision when it changes, as `bindAddress` does; a Core that read before it gets `conflict`
once and reads again, and the Update's start reads the backend again ([Update and schedule](#update-and-schedule)).

| Field | Type, default | config.xml / platform (PHP reader) |
|---|---|---|
| `suppression` | bool, `true` | ip `suppression` is `on` (`$pfb['supp']`) |
| `suppressionCidrV4` | int 0 to 17 (0: Disabled), `0` | ip `suppression_cidr`: plain digits 1 to 17, else 0 |
| `suppressionCidrV6` | int 0 to 64 (0: Disabled), `0` | ip `suppression_cidr_v6`: plain digits 1 to 64, else 0 |
| `dnsblIp` | bool, `false` | DNSBL `action` is valid and not `Disabled` (`pfb_dnsblip_action_value()`) |
| `dnsblLenient` | bool, `false` | DNSBL `pfb_dnsbl_lenient` is `on` |
| `feedHostFilter` | bool, `true` | `pfb_feed_filter_enabled()` |
| `feedHostAllowlist` | list keyed by `cidr`, `[]`; item `{cidr: string}` | `pfb_feed_internal_allowlist()`: IP addresses and CIDRs, each once |
| `selfAddresses` | list keyed by `address`, `[]`; item `{address: string}` | the addresses `pfb_ip_is_self()` accepts beyond `127.0.0.1` and `::1` |
| `proxyUrl` | string `scheme://host:port` (`http`, `https`, `socks5`, `socks5h`) or `""`; `""` | System `proxyurl` and `proxyport`; a host without a scheme means HTTP |
| `proxyUser` | string, `""` | System `proxyuser`, or decoded proxy URL userinfo |
| `proxyPassword` | secret string, `""` | System `proxypass`, or decoded proxy URL userinfo |
| `proxyUnusable` | bool, `false` | A configured proxy that Core cannot represent; remote transfers refuse instead of bypassing it |
| `scheduledWorkDisabled` | bool, `false` | The `.pfb_cron_disable` marker is a file (`pfb_cron_disabled()`); its content is ignored (issue #4031) |

- **Suppression limits.** A limit beyond what the IP page offers (hand-edited config.xml: 18, 8.5, `1e1`, negative) reads as
  0, as a group's own `suppressionCidr` reads a value out of its range; today's PHP applies such a number as typed. A limit
  applies only while `suppression` is on.
- **Allowlist.** Split on whitespace and commas, base64 as General stores it, an entry that is no address or subnet dropped,
  as PHP drops it. Core's list holds an address or a CIDR with no zone and no leading zero in the prefix length, each once, so
  an entry PHP keeps and Core's list cannot hold (`fe80::1%em0`, `10.0.0.0/08`) is not listed. The list is read whether the
  filter is on or off.
- **Self addresses.** What pfSense lists as the box's own: interface addresses, virtual IPs (CARP and IP alias) and the PPPoE
  server's address, IPv4 then IPv6 (`get_configured_ip_addresses()`, `get_configured_ipv6_addresses()`), each once. Never
  listed, though PHP would call them the box's own: `0.0.0.0`, `::`, link-local addresses, an IPv4-mapped IPv6 address and any
- **Proxy.** `pfb_global()` configures `CURLOPT_PROXY` only when `system/proxyurl` is nonempty (`"0"` is empty). The ingest mapper preserves HTTP, HTTPS, SOCKS5/SOCKS5h, hostnames, and IPv4/IPv6 literals; it strips brackets only for validation and rebuilds bracketed IPv6 URLs. Unsupported schemes, malformed hosts, whitespace, and non-scalar nonempty URLs set `proxyUnusable`, never “no proxy.” cURL ignores the proxy URL's path, query, and fragment; Core drops them.
- `CURLOPT_PROXYPORT` is considered only if the proxy URL has no port: that URL port wins even when `proxyport` is set. Otherwise PHP's `empty()` means `""` and `"0"` leave the option unset; numeric prefixes are read (`3128abc` → 3128), while `00`, `abc`, and service names read as zero. The default is 443 for HTTPS proxies and 1080 for other supported schemes. Ports outside 1–65535 are unusable to Core.
- Encoded URL userinfo is decoded into `proxyUser` and secret `proxyPassword`; explicit `proxyuser` and `proxypass` replace it only when both are nonempty. Core sends these as Basic proxy credentials; PHP's legacy `CURLOPT_PROXYAUTH` string disables authentication for explicit credentials, a documented divergence in the feed-fetch parity fixtures.
- `feedfetch` refuses remote feeds with `proxy_unusable` when the configured proxy cannot be used, preserving last-known-good; for FTP it supports only an HTTP proxy and refuses HTTPS/SOCKS rather than sending Basic credentials in cleartext. The proxy is not applied to local files, self-hosted feeds (PHP uses its stream wrapper), or rsync. An empty URL (`""` or `"0"`) means no proxy.
- **Sinkhole addresses.** What `pfb_global()` resolves from the stored VIP ids, whatever the DNSBL state. A VIP id that resolves to
  nothing, or to an address of the other family or with a zone (a link-local VIP: today's PHP writes it as typed), reads as `""`.
  *Withdrawn 2026-11-18 (issue #4053): the fields are removed with the VIP response; see the amendment above.*
- **Core refuses what it reads.** `proxyUrl` must use `http`, `https`, `socks5` or `socks5h` with a port from 1 to 65535 and no userinfo; a listed self address an IP address that is not unspecified, link-local, IPv4-mapped or zoned; an allowlist entry an address or a CIDR without a zone. A backend answer that breaks a rule fails the read ([Settings backends](#settings-backends)).

Parity fixture: `tests/core/fixtures/settings_ingest_parity.json`. `CoreSettingsIngestParityTest` (PHPUnit) freezes it
against today's readers (`pfb_global()`, `pfb_list_cidr_floors()`, `pfb_feed_internal_allowlist()`, `pfb_ip_is_self()`, the
cURL proxy options) and the adapter. `go/pfb_core/settings/ingest_parity_test.go` runs Core against it, hostile rows
included.

### Projection `policy/ip`

The IP policy the Update loop applies after the feeds are downloaded (issue #4031), published as `settings/policy/ip`; writable.
The adapter builds it from one field table (`pfb_core_policy_ip_fields()`: field, config.xml key, kind), shared by the read,
the write validation and the merge, and Core's schema (`go/pfb_core/settings/policy.go`) holds the same rules.

| Field | Type, default | config.xml (PHP reader) |
|---|---|---|
| `dedup` | bool, `false` | ip `enable_dup` is `on`, any case (`$pfb['dup']`) |
| `aggregate` | bool, `false` | ip `enable_agg` (`$pfb['agg']`) |
| `max` | bool, `false` | Reputation `enable_rep` (`$pfb['rep']`) |
| `maxLimit` | int 0 to 50 (0: none), `0` | Reputation `p24_max_var`: plain decimal digits 1 to 50 as typed, else 0 |
| `pMax` | bool, `false` | Reputation `enable_pdup` (`$pfb['prep']`) |
| `pMaxLimit` | int 0 to 50, `0` | Reputation `p24_pmax_var`, as `maxLimit` |
| `dMax` | bool, `false` | Reputation `enable_dedup` (`$pfb['drep']`) |
| `dMaxLimit` | int 0 to 50, `0` | Reputation `p24_dmax_var`, as `maxLimit` |
| `countryWhitelistAction` | enum `ignore` `match`, `ignore` | Reputation `ccwhite`: `match` only when stored exactly so |
| `countryBlacklistAction` | enum `none` `block` `match`, `none` | Reputation `ccblack`: `block` or `match` only when stored exactly so; `none` is stored as `""` |
| `countryWhitelist` | list keyed by `code`, `[]`; item `{code: string [A-Z][A-Z0-9]}` | Reputation `ccexclude` (CSV) |
| `etBlock`, `etMatch` | list keyed by `category`, `[]`; item `{category: string ET_[A-Za-z0-9_]+}` | Reputation `etblock`, `etmatch` (CSV) |
| `suppressionV4` | list keyed by `cidr`, `[]`; item `{cidr: string}` | ip `v4suppression` (base64 text area) |
| `suppressionV6` | list keyed by `cidr`, `[]`; item `{cidr: string}` | ip `v6suppression` (base64 text area) |

- **Limits.** A value that is no plain decimal 1 to 50 (`abc`, `-5`, `1e1`, `8.5`, `51`, `5,10`, `05`, a leading space, an array)
  reads as 0. Today's PHP passes on as typed to the shell script any value of the characters `[a-zA-Z0-9,_-]` (`abc`, `-5`,
  `1e1`, `51`, `05`, `5,10`) and treats `8.5`, a leading space, an empty value, `0` and an array as unset (`x`); Core reads a
  limit it cannot use as none. A write of N above 0 stores `N`, a write of 0 stores `""`.
- **CSV lists.** The whole stored CSV must pass `PFB_FILTER_CSV` (`[a-zA-Z0-9,_-]+`), as today's PHP requires, else the list is
  empty. The tokens that match the item pattern are listed, each once (the first): a token PHP would pass on as typed (`USA`,
  `us`, `DE_rep`, `Spam`) is dropped. A write stores the list as a CSV in the given order.
- **Suppression lists.** The entries `pfb_text_area_decode()` yields (comments cut, lower-cased) that the IP page accepts
  (`pfb_validate_suppression_line()`) and that are a CIDR as `netip.ParsePrefix` reads it: an address, `/`, a prefix length of
  plain digits from 8 to 32 (IPv4) or 32 to 128 (IPv6), no zone. Each is listed once. An entry PHP writes to the suppression
  file though the page would refuse it (no mask, `10.0.0.0/08`, `0.0.0.0/0`, a zone) is not listed. A write whose entry **set**
  differs from the read's rewrites the text: every line whose entry stays is kept with its comment, a line that holds no entry
  (blank, comment, invalid) is kept, a line whose entry went is dropped and each new entry is appended as a line; a reorder alone
  writes nothing. Kept lines are written back as the text-area sanitizer leaves them (control characters stripped, line ends
  normalized), as every page save stores them.
- **Core refuses what it reads.** A limit outside 0 to 50, an action outside its tokens, a country code or ET category outside
  its pattern, a repeated item, and a suppression entry that is no CIDR of its family within its range, has a zone or an
  upper-case letter. The adapter's write validation names the same fields (`policy/ip.<field>[<i>].<item field>`).
- **Write.** Only the keys of the fields whose value differs from what the read gives are written, with the other
  projections in the one `write_config()` under the DNS config lock; an unchanged write is a no-op. A value the read normalizes
  (a limit of `abc` reads 0) stays until Core changes that field. All values participate in the revision.

Parity fixture: `tests/core/fixtures/settings_policy_ip_parity.json`. `CoreSettingsPolicyIpParityTest` freezes it against
today's PHP (the Reputation block and the toggles of `sync_package_pfblockerng()`, run as shipped, and
`pfb_create_suppression_file()`) and the adapter read; `CoreSettingsPolicyIpBackendTest` covers the write.
`go/pfb_core/settings/policy_ip_parity_test.go` runs Core against it, hostile rows included.

### Projection `feeds/geoip`

The nine GeoIP continents of the Continents pages (issue #4031), published as `settings/feeds/geoip`; writable. One field,
`groups`: a list keyed by `name` that always holds each continent once, in the order of `$pfb['continents']`: `pfB_Top`,
`pfB_Africa`, `pfB_Antarctica`, `pfB_Asia`, `pfB_Europe`, `pfB_NAmerica`, `pfB_Oceania`, `pfB_SAmerica`, `pfB_PS`. Core
cannot add or remove a continent. The section of a continent is `installedpackages/pfblockerng<name in lower case without
spaces>/config/0` (`pfblockerngtopspammers`, `pfblockerngafrica`, ..., `pfblockerngproxyandsatellite`); a section never saved
projects the defaults.

| Group field | Type, default | config.xml |
|---|---|---|
| `name` (key) | enum of the nine | |
| `action` | enum of the IP group actions (see above), `Disabled` | `action`; one the apply pass skips (not an IP action, an array, missing) reads `Disabled` |
| `listClass` (derived) | enum `none` `deny` `permit` `match` `native`, `none` | from `action`, `autoaddrnot_in` and `autoaddrnot_out`, as for an IP group |
| `countriesV4`, `countriesV6` | list keyed by `code`, `[]`; item `{code: string}` matching `(A[12]_)?[A-Z][A-Z0-9](_rep)?` | `countries4`, `countries6`: a CSV of the codes the page stores (`US`, `US_rep`, `A1`, `A2`, `A1_US_rep`) |

- **Country lists.** Today's PHP splits the CSV on `,` and names a file `{ccdir}/{token}_v4.txt` after each token with no check.
  The adapter lists the tokens that match the item pattern, each once (the first): `USA`, `us`, `U`, `../x`, a code with a leading space and an empty
  token are dropped, and an array where the CSV belongs reads as no country. There is no whole-CSV rule, unlike `policy/ip`.
  A write stores the list as a CSV in the given order.
- **Write.** The groups must hold exactly the nine names, once each: an unknown, missing or repeated name, a field missing from or
  added to a group, or a value of the wrong type is `invalid_argument` naming `feeds/geoip.groups[<i>]...`, and nothing is
  written. A continent whose `action` or country lists changed has only those keys of its own section written (a section never
  saved is created holding only them), in the one `write_config()` of the other projections; an unchanged write is a no-op.
  `listClass` is validated as the enum and ignored.
- **Core refuses what it reads.** A name outside the nine or repeated, a number of groups other than nine, an action outside
  the IP actions, a list class outside the five, a country outside its pattern or repeated, an unknown field.

Parity fixture: `tests/core/fixtures/settings_feeds_geoip_parity.json`. `CoreSettingsFeedsGeoipParityTest` freezes it against
today's PHP (the continent statements of `sync_package_pfblockerng()`, replayed with their source anchored) and the adapter read;
`CoreSettingsFeedsGeoipBackendTest` covers the write. `go/pfb_core/settings/feeds_geoip_parity_test.go` runs Core against it,
hostile rows included.

### Projection `policy/dnsbl`

The DNSBL build policy the Update loop applies (issue #4031), published as `settings/policy/dnsbl`; writable. The adapter builds
it from the field table `pfb_core_policy_dnsbl_fields()` (field, config.xml key, kind), the mechanism of `policy/ip` extended with
kinds for the Enable/Disable switches, a bounded count, CSVs without the whole-CSV rule, text areas with their own line reading and
derived fields; Core's schema (`go/pfb_core/settings/policy.go`) holds the same rules. Nothing reads it yet. `dns.idnMode` stays
the only projection of the IDN mode.

| Field | Type, default | config.xml (PHP reader) |
|---|---|---|
| `enabled` | bool, `false` | dnsbl `pfb_dnsbl` is `on`, any case |
| `whitelist` | list keyed by `domain`, `[]`; item a lower-case domain | dnsbl `whitelist` (base64 text area), the lines `pfb_dnsbl_whitelist_lines()` yields |
| `top1m` | bool, `false` | dnsbl `top1m_enable` |
| `top1mCount` | int 1 to 1000000, `1000` | dnsbl `top1m_count`: plain digits 1 to 1000000, else 1000 |
| `top1mInclusions` | list keyed by `tld`, `[]`; item `[A-Za-z0-9_-]+` | dnsbl `top1m_inclusion` (CSV, whole-CSV rule) |
| `tldBlacklist` | list keyed by `tld`, `[]`; item without control character, space or upper case | dnsbl `tld_wildcard_blacklist` (text area), listed whether `dns.tldWildcard` is on or not |
| `tldExclusions` | list keyed by `domain`, `[]`; same item | dnsbl `tld_wildcard_exclusion` (text area) |
| `tldAllow` | bool, `false` | dnsbl `tld_allow` |
| `tldAllowGtld`, `tldAllowCctld`, `tldAllowItld`, `tldAllowBgtld` | list keyed by `tld`, `[]`; item without control character, space or comma | dnsbl `tld_allow_gtld`, `_cctld`, `_itld`, `_bgtld` (CSV, no whole-CSV rule) |
| `regex` | bool, `false` | dnsbl `pfb_regex` |
| `regexList` | list keyed by `pattern`, `[]`; item trimmed, not starting with `#`, no control character | dnsbl `pfb_regex_list` (base64 text), the lines pfB-DNS loads |
| `safeSearch` | bool, `false` | SafeSearch `safesearch_enable` is exactly `Enable` |
| `safeSearchYoutube` | enum `Disable` `Moderate` `Strict`, `Disable` | SafeSearch `safesearch_youtube`, the exact token |
| `safeSearchDoh` | bool, `false` | SafeSearch `safesearch_doh` is exactly `Enable` |
| `safeSearchDohList` | list keyed by `host`, `[]`; item without control character, space or comma | SafeSearch `safesearch_doh_list` (CSV, each token trimmed) |
| `dnsblIpAction` | enum of the IP group actions, `Disabled` | dnsbl `action`, as `pfb_dnsblip_action_value()` |
| `logging` (derived) | enum `disabled_log` `disabled` `nxdomain_log` `nxdomain` `nodata_log` `nodata`, `disabled_log` (issue #4053 removed `enabled`, the VIP) | the mechanism of `pfb_dnsbl_policy_config()` (dnsbl `global_log_mode`, `global_log`) |
| `blacklistLogging` (derived) | same enum | what the Blacklist categories log with: `pfb_dnsbl_effective_logging()` over their stored `blacklist_logging` |
| `groups` (derived) | list keyed by `name`, `[]`; item `{name, logging: the enum above, primary: bool, top1mFilter: bool}` | the groups `feeds/dnsbl` projects, in its order: the effective logging of the group, whether its stored `order` is `primary`, whether its `filter_top1m` toggle is on |

- **Lists.** Each entry is listed once (the first). A whitelist, TLD blacklist or TLD exclusion entry is what
  `pfb_text_area_decode()` yields (comments cut, lower-cased, a whitelist's IDN punycoded, a NUL stripped, a CR a line end); a
  whitelist entry must also pass the domain filter. An entry Core cannot hold (a TLD entry with a space inside) is not listed. The
  **Regex list** is not read by PHP but by pfB-DNS: the stored text must be strictly valid base64 (a missing padding is an error) of
  valid UTF-8, else the list is empty; each line, split at CR or LF and trimmed of Python's white space, that is not blank and does
  not start with `#` is an entry, **kept whole** (an inline `#` description, upper case); an entry holding a control character
  (pfB-DNS would take it) is not listed. The TLD Allow buckets and the DoH list take the stored CSV's tokens (the DoH ones
  trimmed), the gtld bucket's empty token after `arpa` (no local TLD) is dropped, and an array where a scalar is stored reads as no
  entry. A write of a text area follows the rule of `policy/ip`: lines whose entry stays are kept, lines that hold no entry are
  kept, and the other entries are appended; a CSV is stored in the given order. A text entry its own reader would cut or skip (one
  holding `#`: the text area ends a line there) is refused, since it would not be read back. A write that changes `top1m`,
  `top1mCount` or `top1mInclusions` flags the TOP1M whitelist for a rebuild on the next Update (`top-1m.update`), as the DNSBL
  page's save does. A stored regex list pfB-DNS cannot decode (text
  that is not strict base64, as a hand edit can leave it) reads as no entries, and a write of the list replaces that text.
- **TOP1M count.** Plain digits whose value is 1 to 1000000 are the count; anything else (`-1`, `abc`, `1e1`, `5abc`, `+5`,
  `1000001`, an array, `0`, empty) is 1000. Today's PHP keeps `-1`, `abc`, `1e1`, `1000001` as typed, and an array.
- **Derived fields.** `logging`, `blacklistLogging` and `groups` are answered by every read and validated for type, and a write
  ignores them: they follow `global_log`, `global_log_mode`, each group's `logging`, `order`, `filter_top1m` and the Blacklist
  page's `blacklist_logging`, which the Outpost owns. Core reads again after each save. The revision covers them, so it moves
  when a group's stored logging changes.
- **SafeSearch.** The three switches are exactly `Enable` and `YouTube` exactly `Moderate` or `Strict`; today's PHP runs the
  SafeSearch phase for any stored value other than `Disable` (`enable`, an array), and acts only on the exact tokens: Core reads the
  exact ones.
- **Core refuses what it reads.** A `top1mCount` outside 1 to 1000000, an entry that is empty, repeated or off its pattern, an
  action or mechanism outside its tokens, a `groups` item with a repeated or non-word name; the adapter's write validation names
  the same fields (`policy/dnsbl.<field>[<i>].<item field>`).
- **Write.** Only the keys of the fields whose value differs from what the read gives are written, in the one `write_config()`
  with the other projections; an unchanged write is a no-op.

Parity fixture: `tests/core/fixtures/settings_policy_dnsbl_parity.json`. `CoreSettingsPolicyDnsblParityTest` freezes it against
today's PHP (the statements of `pfb_global()` and the apply pass, run as shipped, `pfb_dnsbl_whitelist_lines()` and the decoders
of the manifest builder) and the adapter read; `CoreSettingsPolicyDnsblBackendTest` covers the write.
`go/pfb_core/settings/policy_dnsbl_parity_test.go` runs Core against it, hostile rows included.

### Projection `extras`

What the Extras stage of an Update (the MaxMind, IPinfo ASN and TOP1M downloads, map #3813) reads of the package settings
(issue #4031), published as `settings/extras`. The key and the two tokens are **secrets**: the adapter's read carries them to Core
in clear, as it carries feed credentials, and only Core's API hides them. Whether the TOP1M whitelist is on is
`policy/dnsbl`'s `top1m`.

| Field | Type, default | config.xml (PHP reader) |
|---|---|---|
| `maxmindAccount` | string `[A-Za-z0-9_]*`, `""` | ip `maxmind_account`, as `pfb_global()` filters it (`$pfb['maxmind_account']`): a word, not `0`, else `""` |
| `maxmindKey` | secret string `[A-Za-z0-9_]*`, `""` | ip `maxmind_key`, the same rule (`$pfb['maxmind_key']`) |
| `maxmindLocale` | enum `en` `fr` `pt-BR` `de` `ja` `zh-CN` `es`, `en` | ip `maxmind_locale`: a locale the IP page offers, else `en` |
| `maxmindCsvDisabled` | bool, `false` | ip `database_cc` is `on` (`$pfb['cc']`) |
| `ipinfoToken` | secret string without control characters, `""` | ip `asn_token` (`$pfb['asn_token']`; a stored `0` is none) |
| `top1mProvider` | enum `tranco` `cisco` `openpagerank` `majestic` `cloudflare`, `tranco` | DNSBL `top1m_source`, as its gateway adapter reads it (`alexa` is Tranco, `domcop` Open PageRank) |
| `top1mToken` | secret string without control characters, `""` | DNSBL `top1m_token` |

- **Where Core and today's PHP differ.** A locale the page never stores (`EN`, `xx`, a path in a hand-edited config.xml) is used as
  typed in a file name by PHP and reads as `en`. A token holding a control character (a line break, a NUL) or bytes that are not
  UTF-8 is URL-encoded or header-stripped by PHP and reads as `""`: Core's tokens go into a URL or an HTTP header as they are.
- **Writes.** Only a changed field is stored, in its registered key; `""` clears a secret (no page can). An unchanged write, its
  secrets in clear, writes nothing. A secret takes part in the revision, which is keyed.
- **Core refuses what it reads.** An account or key outside `[A-Za-z0-9_]`, a locale or provider outside its tokens, a token with a
  control character, and `0` as the account, the key or the IPinfo token (the Outpost reads a stored `0` as none).

Parity fixture: `tests/core/fixtures/settings_extras_parity.json`. `CoreSettingsExtrasParityTest` (PHPUnit) freezes it against
today's readers (`pfb_global()`, the gateway) and the adapter, with the write path. `go/pfb_core/settings/extras_parity_test.go`
runs Core against it, hostile rows included, and pins that a read shows each secret as its presence only.

### Projection `hooks`

The Update hook rows of the Hooks page (issue #4031), published as `settings/hooks`. It is **read-only**
([`readOnly`](#settings)): the Outpost's page owns the rows, the adapter never writes them, and a write whose `hooks` differs from
what config.xml projects is refused (`invalid_argument`, field errors `hooks.<field>`), after the revision check, as for `ingest`.
It holds one field, `rows`: a list keyed by `id`, in the stored order.

| Row field | Type, default | Stored row (PHP reader) |
|---|---|---|
| `id` (key) | string, a decimal number | the row's index in the stored list (`hooks/row`, a bare list or a lone row, as `pfb_get_hooks()` tolerates) |
| `when` | enum `pre` `post` | `when`, exactly one of the two |
| `script` | string `hook_<when>_*.sh` or `.py`: a file name, no `/`, no control character | `script` |
| `description` | string without control characters, `""` | `description`, sanitized and trimmed |
| `timeout` | int, at least 1 (seconds), `60` | `timeout` as `pfb_hook_timeout()` reads it: a number of at least 1, else 60 |
| `enabled` | bool, `false` | `enabled` is exactly `on`, as the runner reads it |

- **Rows that are not listed.** A row today's runner would never run: `when` that is not `pre` or `post`, a `script` that is not a
  bare file name `hook_<when>_*.sh` or `.py` (a path, `..`, a leading `-`, another extension, the other fire point's name), a row
  that is not an object. Core is stricter in one case: a script name holding a control character, which today's
  `pfb_hook_script_valid()` accepts when such a file exists, is not listed. A disabled row is listed, with `enabled` false. The ids
  of the rows that follow a row that is not listed keep their stored index.
- **Not in the projection.** Whether the script file exists in the hook directory: whoever runs the hook checks that, against its
  own directory.
- **A timeout stored as an array** (hand-edited config.xml) reads as the default; `pfb_hook_timeout()` reads PHP's `1`.
- **Core refuses what it reads.** A script that is not such a file name or names the other fire point, `when` outside its tokens, a
  timeout below 1, an id that is no index or repeats, a description with a control character.

Parity fixture: `tests/core/fixtures/settings_hooks_parity.json`. `CoreSettingsHooksParityTest` (PHPUnit) freezes it against
today's readers (`pfb_get_hooks()`, `pfb_hook_timeout()`, `pfb_hook_script_valid()`) and the adapter.
`go/pfb_core/settings/hooks_parity_test.go` runs Core against it, hostile rows included.

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
- **Scheduler.** At every quarter-hour boundary (a Unix time that is a multiple of 900 s) Core reads the schedule in the
  host's time zone, which `--zoneinfo PATH` names as a time zone file (TZif) that Core reads again at every evaluation and at
  every `GetSchedule`, so a change of the host's zone applies at the next one without a restart. Without the flag, or when the
  file is missing or damaged, it is the process's local zone (logged once per outage). Core plans what is due from
  `settings/schedule` and the `settings/feeds/*` projections as they are then (a save or `SettingsChanged` refreshes them),
  reserves the occurrences and starts a `scheduled` Update with the feeds and Extras (`extra:dcc`, `extra:bl`) that are due.
  Nothing due starts nothing.
- **Fresh facts at the start.** Before each Update's program runs, Core reads its settings backend again, as `SettingsChanged`
  does (issue #3975): the interface addresses and the proxy of [`settings/ingest`](#projection-ingest) change outside Core, and
  the Outpost's tick that tells Core is up to 15 minutes away. A failed read keeps the values in memory, is logged once per
  outage, and the Update runs on them.
- **Restarts.** `schedule_state.json` retains settled outcomes and pending occurrences. Each admitted Update has an independent worker
  holding the private `update.log.lock` flock and `update.log.request`, `.result` and `.status` receipts. Stopping or losing Core
  stops scheduling and API observation, not that worker; its log continues and its result file remains until the next admission
  replaces it. Startup and each `GetUpdate` reconcile a terminal receipt before returning status. A busy lock and valid status
  identify the original live worker and prevent a duplicate. A malformed receipt makes the API unavailable, not idle. If a worker
  dies before publishing completion, Core salvages complete result lines, records failure and does not rerun the transaction.

### Projection `maintenance`

What Core's timed lanes decide from (issue #3996), published as `settings/maintenance`. It is **read-only**
([`readOnly`](#settings)): config.xml and the platform own it, and a change set that names it is refused.

| Field | Type, default | config.xml / platform (PHP reader) |
|---|---|---|
| `enabled` | bool, `false` | General `enable_cb` is `on` |
| `scheduledWorkDisabled` | bool, `false` | the file `.pfb_cron_disable` exists |
| `metricsExport` | bool, `false` | General `pfb_metrics_export` is `on` |
| `clearIpCounters` | enum `never`, `daily`, `weekly`; `never` | `pfblockerngglobal` `widget-clearip` |
| `clearDnsblCounters` | enum `never`, `daily`, `weekly`; `never` | `pfblockerngglobal` `widget-cleardnsbl` |

- **Garbage reads as never.** A counter cadence that is none of the three exact values (`Daily`, `1`, empty, an array, absent) is `never`.
  Core refuses what a backend answers outside the schema, as for `ingest`: an unknown enum value, a non-string enum, a bool that is not a JSON bool and
  a field the projection lacks fail the read naming `maintenance.<field>`; a field the backend leaves out is its default.

Parity fixture: `tests/core/fixtures/settings_maintenance_parity.json` (`config` as sections `gen` and `pfblockerngglobal`, the sentinel as `cronDisable`).

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

Two optional parameters, which any trigger takes, name the package operation the Update runs for (issue #4035; spec
`docs/specs/go-updater-pipeline.md` section 5, "Install and upgrade are one Update"):

| Parameter | Values | The Update's hooks see |
|---|---|---|
| `lifecycle` | `install`, or absent | `PFB_POST_INSTALL=1` with `install`, else `0`; `PFB_PRE_UNINSTALL` is always `0` |
| `pkgOp` | `install`, `upgrade`, `reinstall`, `delete` or `""` (the same as absent) | `PFB_PKG_OP` set to it, empty when absent |

Any other value, `null` aside, is `invalid_argument` with a field error on the parameter, and nothing starts. `uninstall` is
not a `lifecycle` an Update takes: the uninstall runs its hooks through [`--run-hooks`](#hooks-outside-an-update). Core copies
both into the request the Update command receives on stdin, whose worker gives them to the Update's hooks (see
[Update command](#update-command)). The package resync that sends them is not wired yet.

### GetUpdate

Progress is polled, not streamed. `after` is an opaque cursor: the `next` of an earlier reply, passed back as the decimal
string it is (`{"after": "1099511627800"}`). A client never builds, orders or does arithmetic on one. Absent (or `null`) and
`"0"` read from the start of the Update's log. A value that is not a string of decimal digits, or does not fit 63 bits (a JSON
number, `"-1"`, `"abc"`, `"1.5"`, `""`), is `invalid_argument` with a field error on `after`. The reply is:

| Field | Value |
|---|---|
| `running` | `true` while an Update runs, explicitly `false` otherwise |
| `update` | `null` until Core has a current Update or retained worker receipt; otherwise `{"trigger", "scope", "force", "startedAt", "finishedAt", "result"}` from that Update's status: times are Unix seconds, `finishedAt` and `result` appear only once it ended, `result` `success` (exit 0 and usable result), `skipped` (exit 75) or `failed` |
| `log` | the per-Update transcript's bytes from the cursor, at most 64 KiB, never ending inside a UTF-8 character; `""` before the first Update |
| `next` | the cursor after `log`, a JSON string: pass it as `after` in the next call; `"0"` before the first Update |

The last Update stays readable until the next one starts. A client follows an Update by calling again with the last `next`
as `after`. The cursor names the Update it belongs to, so the first call after a new Update has started reads that Update's
log from its start: the client needs no other signal. A cursor of an earlier Update, or one past the log's end, reads from the
start. It is a string because it exceeds 2^53, which a browser or a PHP float holds exactly, from the 8193rd Update of a Core.

The cursor generation is stored with worker status and remains valid for the same retained log across a Core restart. Before
following a cursor after a new admission, clients should compare `update.startedAt` and drop `after` if it changed. `startedAt`
has one-second precision and may not distinguish two Update admissions made in the same second.

### GetSchedule

Takes no parameters; the reply is computed from the settings and the scheduler's state at the call:
`{"scheduled": bool, "feeds": {"lastRun", "nextDue"} or null, "extras": {"extra:dcc": {...}, "extra:bl": {...}}, "lastSuccessfulCheck":
{id: time}}`. `scheduled` is the General switch for scheduled feed updates. `feeds` is the feeds' entry, `null` when scheduled
updates are off or no feed is or will be due. `extras` holds the Extras that are enabled and will be due. A time is Unix seconds,
`lastRun` 0 when never run. `lastSuccessfulCheck` is always an object: the time of the last successful check of every item (a feed
id or an Extra) that has had one, `{}` when none has; it is the metrics export's `pfblockerng_feed_last_success_timestamp_seconds`. When the model cannot be built (the settings are not initialized, or hold a value the schedule refuses) the call is
`unavailable` with the reason.

### Update command

`--update-cmd PATH` names the program an independent worker runs for each admitted Update; the path comes only from the flag. Core refuses to start (exit status 2, a line naming the flag) when it is not valid UTF-8 or holds a control character, with or without `--update-loop`.
The worker receives this request on stdin and reports progress and results as follows:

- **stdin:** one JSON object, `{"version": 1, "trigger": "scheduled|manual|apply|retry", "scope": "ip|dnsbl|both",
  "force": "none|parse|download|both", "feeds": [ids], "extras": ["extra:dcc", "extra:bl"], "lifecycle": "install", "pkgOp":
  "install|upgrade|reinstall|delete"}`. `feeds`, `extras`, `lifecycle` and `pkgOp` are left out when empty, and the last two
  are what `StartUpdate` was given; a feed id is the schedule's (`ipv4:<header>_v4`, `ipv6:<header>_v6`, `dnsbl:<header>`). A `scheduled` or `retry`
  Update names what to run; a `manual` one runs its scope. The worker (`pfb_core_update_request()`) accepts `lifecycle` only as
  `install` and `pkgOp` only as `install`, `upgrade`, `reinstall` or `delete`; absent or `null` is none, and any other value or
  type refuses the request (exit 2, nothing runs), as an unknown field does. Every hook the Update fires gets
  `PFB_POST_INSTALL=1` with `lifecycle` `install` (else `0`), and `PFB_PKG_OP` set to `pkgOp`; without `pkgOp` it is read from
  a `pkg` ancestor process, as outside an Update. The requests Core writes are pinned on both
  sides by `tests/core/fixtures/update_request_v1.json`.
- **stdout and stderr:** the per-Update transcript, `update.log` in `--state-dir`: a regular file, never a pipe. `GetUpdate`
  reads this file; the browser never tails the rotating main log. There is no whole-transcript cap or trimming. For PHP hook and
  per-list script invocations, the transcript includes the first 1,048,576 combined stdout/stderr bytes and one notice only
  when an additional byte exists; the remaining captured bytes are appended once to the main log. The allowance resets for
  each invocation. Ordinary progress and later scripts remain visible; Go FeedPhase output is unchanged by this PHP-only rule.
  A Core restart does not truncate the transcript; completion retains it until a later admitted Update replaces the pathname.
  Admission succeeds before replacement, and descriptors opened before replacement remain attached to the old inode; they
  cannot write into the new transcript.
- **fd 3:** the worker's durable `update.log.result` file: result lines, each one JSON object `{"version": 1, "outcomes": {id:
  "success"|"retry-cap-reached"}, "attempted": [ids], "geoipReady": bool}` and a newline, every field but `version` optional. The
  program writes each outcome as it finishes. Complete lines are preserved for recovery; if the final unterminated line is invalid,
  that line is dropped and the Update fails while earlier complete lines remain settleable. Any malformed complete line or more than
  1 MiB in all fails validation without a usable result. The result file remains after the run and is replaced by the next admission.
- **Exit status:** 0 is success. A non-zero exit fails the Update, and a valid result it wrote still counts. **75** means the
  program deferred the Update (a lock held, the schedule switched off): the Update ends with the result `skipped`, not
  `failed`, whatever the program wrote on fd 3 is not recorded (no outcome, no attempt, no GeoIP readiness), and the
  reserved occurrences stay pending for the next quarter hour. A skipped Update replaces the previous transcript like any other, and its
  own transcript holds what the program printed before it deferred.
- **Worker lifetime and bounds:** Core admits one Update under the private `update.log.lock` flock, then the independent worker
  owns the transaction, command and receipt. Stopping or losing Core does not signal the worker or its program; a restarted Core
  observes the busy lock or reconciles the terminal receipt at startup and before `GetUpdate`. There is no whole-Update timeout or
  Core-owned process-group kill. Downloads and scripts keep their operation-level bounds; a worker killed before completion is
  recovered as failed from its complete result lines, never relaunched.

- **Scheduled maintenance.** With `--maintenance-cmd PATH`, each quarter-hour boundary admits a separate maintenance worker; a busy lane skips rather than queues.
  Core reads [`maintenance`](#projection-maintenance) again before each decision and runs the worker only while `enabled` is true and `scheduledWorkDisabled` is false;
  it logs one line when the lane flips between running and skipping, and a failed read keeps the values read last (logged once per outage). The program is run with no arguments.
  It uses `maintenance.log` and its own `maintenance.log.lock`, `.request`, `.result` and `.status` receipts, never the Update lease or `Scheduler.Done`.
  Core shutdown ends observation but the worker keeps its lock and can finish; a restarted Core cannot start a duplicate. Update and maintenance use different locks and can overlap.
  Exit status 75 and `ErrRunning` are benign skips of a program that defers itself; other failures are logged. Maintenance has no whole-program timeout; bounds belong to the invoked operations.
- **Timed lanes.** Core, not the Outpost, decides when each program is due, from `maintenance` in memory or, at a day change, read again.
  With `--metrics-cmd PATH`, Core starts PATH with no arguments at every Unix minute boundary while `enabled` and `metricsExport` are true; `scheduledWorkDisabled` does not stop it, and a minute boundary never reads the backend.
  With `--counters-cmd PATH`, at each boundary that falls on a later local date (in the `--zoneinfo` zone) than the previous boundary, Core reads `maintenance` again and starts PATH with the verbs due as arguments, `clearip` when `clearIpCounters` is `daily` (or `weekly` on a Sunday), then `cleardnsbl` likewise; none due starts nothing. It ignores `enabled` and `scheduledWorkDisabled`.
  A day-change read that fails keeps the values read last (logged once per outage), and a Core stopped during it starts nothing after it.
  Core logs one line when the metrics lane flips between starting and skipping its runs, and one line at each day change naming the counter verbs it starts, or that none is due.
  A lane whose previous run is still alive skips the boundary rather than queueing it. Core only starts and observes: it never signals the program, a Core stop leaves a running one alone, and its output is discarded.
  A failure to start or a non-zero exit is logged once per outage, as is settings that cannot be read, in which case nothing starts. The bound of a run belongs to the program Core is given.

The scheduler records the result in `schedule_state.json` (0600, `{"schema": 1, "items": {...}}`, replaced atomically), either
when the worker reports completion or when a later Core reconciles its receipt: each feed's outcome, the attempted ids that stay
pending, and the GeoIP readiness the program saw (`true` until the first report). The Extras plan uses the last readiness reported.
The cutover imports configuration only, so a Core that finds no state file starts empty.

**Stopping.** TERM or INT stops scheduling and ends Core's Update observation; it does not signal an admitted worker or its program.
The worker retains its lock, log and receipt until its transaction completes. A new Core observes a live worker or reconciles its
terminal receipt; it does not relaunch the same transaction.

### The Core Updater loop

**Not used in production yet** (issue #4038, spec `docs/specs/go-updater-pipeline.md` section 3). With `--update-loop`,
which needs `--update-cmd`, each admitted Update runs the Core Updater loop in its worker instead of the `--update-cmd`
program. Without the flag nothing changes: the worker runs the program as above, and its private state has no `loop`
member. The rc script does not pass the flag.

- **Paths.** Core copies its path flags into the worker's request as a `loop` object: `settingsCmd`
  (`--settings-backend-cmd`; absent means `settings.json` in `--state-dir`), `resourceDir`, `feedLocalDirs`, `scriptDirs`,
  `rsyncBin`, `hookDir`, `pythonWrapper` and `mainLog` (`--main-log PATH`, the package's main log, which needs
  `--update-loop`). Settings never go there. A path must be absolute, clean, valid UTF-8 and free of control characters; an empty
  single path means none, an empty list item is refused. With the switch on, Core refuses to start (exit status 2, a line
  naming the flag) when a flag, `--settings-backend-cmd` among them, gives such a path. An Update whose loop holds one is
  refused at admission, before the schedule occurrence is committed or `update.log` is replaced, and the worker refuses a
  request whose `loop` has an unknown member or such a path. Only the request carries `loop`: the status the worker
  publishes never does, so a Core that does not know the member still reads it.
- **Snapshot.** Once it has completed the ownership handshake with Core and holds `update.log.lock`, the worker reads the
  settings backend once itself (the Core API's own read before the launch stays) and keeps the settings and
  `platform.pendingToken` in memory only. A backend that fails, does not answer within its read timeout, answers revision
  0, or holds no initialized settings fails the Update before any later stage. A `scheduled` Update ends `skipped` when
  `ingest.scheduledWorkDisabled` is true, as for exit status 75; other triggers run.
- **Output.** The loop writes its lines to `update.log` and, with `--main-log`, appends them to the main log too. A stage
  that fails writes one line, sanitized as program output is (control characters, TAB and LF escaped) and cut to 300
  bytes of reason; the same text is the receipt's failure. A missing main log is created as the PHP logger creates it:
  mode 0666 less the umask. A main log that is a symbolic link, not a regular file (a FIFO is refused without waiting
  for a reader) or a file with more than one hard link fails the Update before the snapshot.
- **Stages.** The stages after the snapshot are empty for now, so an Update reports success with an empty result and
  starts no program.
- **Lock.** In loop mode the worker itself holds the Update lock, so killing the worker frees the lock while processes
  it started may still run. The limit stays until sub-slices 9i and 9j-2 of issue #4038.

### Update command, version 2

**Not used in production yet.** Version 2 is the contract of the Outpost apply (issue #4037; spec
`docs/specs/go-updater-pipeline.md` section 8). The Outpost validates the request and writes the result lines
(`pfb_core_update_v2_request()`, `pfb_core_update_v2_result()` in `pfblockerng_extra.inc`), but nothing serves version 2:
Core's worker writes version 1 until the Core Updater loop (#4038) and the cutover (#3977). The contract is frozen in
`tests/core/fixtures/apply_contract_v2.json`, which `tests/php/CoreUpdateV2ContractTest.php` runs and #4038 runs from Go.

The invocation is the one above: the same `--update-cmd`, stdin and stdout as regular files, the result lines on fd 3, and the
same meaning of the exit status (0 success, 75 deferred, 2 a refused request, anything else failure).

**stdin:** one JSON object of at most 1,048,576 bytes and nothing after it but white space, nested at most seven levels deep
(the object itself is the first level). A request nested deeper is refused as "the request is not one JSON object". Of keys
that appear twice in one object, the last is read:

```json
{"version": 2, "trigger": "scheduled", "scope": "both", "pendingToken": "0123456789abcdef", "pendingOutsideWindow": false,
 "resources": [{"id": "ip-set/Abuse/ipv4", "generation": "42", "action": "deny", "direction": ["ingress", "egress"], "entries": 15234},
               {"id": "ip-aggregate/deny/ipv4", "generation": "17", "action": "alias_only", "entries": 90211},
               {"id": "geo-catalog", "generation": "3"}],
 "removed": ["ip-set/Old/ipv4"],
 "dnsbl": {"generation": "88", "groups": [{"name": "Ads", "entries": 120344, "changed": true}]},
 "issues": [{"resource": "feed/ipv4:Foo_v4", "stage": "download", "code": "curl_incomplete", "message": "..."}]}
```

The request is validated whole before anything runs. Anything it does not understand refuses it: the program logs the reason,
writes no result and exits 2. A field that is `null` is absent; an unknown field, at any level, is refused.

| Field | Rule |
|---|---|
| `version` | the integer `2` |
| `trigger` | required: `scheduled`, `manual`, `apply` or `retry` |
| `scope` | `ip`, `dnsbl` or `both`; `both` when absent |
| `pendingToken` | 1 to 64 printable ASCII characters other than the space; compared and stored, never parsed |
| `pendingOutsideWindow` | a boolean; `false` when absent |
| `resources` | a list of resources (below) |
| `removed` | a list of the ids whose resources left the configuration |
| `dnsbl` | `{"generation", "groups"}`: `groups` a list of at most 4,096 `{"name", "entries", "changed"}`, a name of 1 to 128 letters, digits and underscores, each once |
| `issues` | a list of at most 4,096 `{"resource", "stage", "code", "message"}` |

`resources` and `removed` hold at most 2,048 ids together, so that the report of every request accepted fits one result line
(below). `scope` does not constrain what the request lists (`scope: "dnsbl"` with an `ip-set` is accepted): the validator
checks the request's shape, and the apply honours `scope` when it acts. Each of `resources` and `removed` is still
refused over 4,096 entries with `<list> holds more than 4096 entries`, a check that runs before the combined bound.

- **A resource** is `{"id", "generation", "action", "direction", "entries"}`. The `id` is a [resource id](#resources) the
  apply handles: an `ip-set`, an `ip-aggregate` or the `geo-catalog`, never a `dnsbl/*` id (pfB-DNS fetches those). Each
  id appears once across `resources` and `removed`. The `geo-catalog` takes only its `id` and `generation`.
- **A generation** is a string of 1 to 20 ASCII decimal digits, leading zeros included, whose value fits an unsigned 64-bit
  integer; it is kept as the string it is (`"007"` stays `"007"`).
- **`action`** is `deny`, `permit`, `match` or `alias_only`; every `ip-aggregate` is `alias_only`. **`direction`** is a
  non-empty list of `ingress` and `egress`, each once, for an `ip-set` whose action is not `alias_only`, and absent
  otherwise. **`entries`** is a non-negative integer of at most 9223372036854775807 (2^63-1); a larger number is refused, as
  it is in a DNSBL group's `entries`.
- **An alias.** Each `ip-set` and `ip-aggregate` id maps to the alias the apply loads: `ip-set/<group>/ipv4` (or `ipv6`) is
  `pfB_<group>_v4` (or `_v6`), and `ip-aggregate/<class>/<family>` is the ADR-11 alias `pfB_<Class>_Aggregated_v4|_v6` of
  the class `deny`, `permit`, `match` or `native` (lower case in the id). An alias is at most 31 characters, the longest
  name pf takes for a table (a group of at most 24 characters), and the eight aggregate aliases are reserved: an `ip-set`
  whose alias would be one of them (`ip-set/Deny_Aggregated/ipv4`) maps to no alias. An id that maps to no alias (another
  class, a group with `-`, a group too long, a reserved name) refuses the request. Distinct ids therefore never share an
  alias. The id is never used as a path or a table name; the alias is.
- **An issue's** `resource` and `code` are strings of 1 to 256 printable ASCII characters (bytes 0x20 to 0x7E): any other
  byte, a non-ASCII character included, refuses the request, so no Unicode version can make the two sides disagree.
  Its `stage` is one of the sync-status ledger's:
  `download`, `script`, `parse`, `dedup` or `apply`. Its `message` is any string, kept as bounded text: invalid UTF-8 is
  replaced, each run of control characters and line or paragraph separators becomes one space (so the lines of a tool's
  error output stay apart as words), every other `\p{C}` character is removed, the surrounding white space is trimmed, the
  text is cut to at most 1,024 bytes, never inside a character, and trimmed again. Markup in it stays as it is, for the page
  that shows it to escape.

**fd 3:** result lines, each one JSON object and a newline, in printable ASCII, written as each step finishes. The fields
appear in this order; a field is left out when the apply has nothing to say in it, and `version` is always present:

```json
{"version": 2, "applied": {"ip-set/Abuse/ipv4": "42"}, "removed": ["ip-set/Old/ipv4"], "changedAliases": ["pfB_Abuse_v4"],
 "ipChanged": true, "dnsblChanged": false, "reloadLaunched": true,
 "failed": [{"id": "ip-set/Big/ipv4", "stage": "apply", "message": "pfctl: table limit"}]}
```

| Field | Meaning |
|---|---|
| `applied` | each resource applied, its id mapped to the generation string the request gave |
| `removed` | each removal applied, the ids as the request gave them |
| `changedAliases` | the alias of every table the apply pushed to pf: the `post` hook's `PFB_CHANGED_IP_ALIASES` |
| `ipChanged`, `dnsblChanged` | the `post` hook's `PFB_IP_CHANGED` and `PFB_DNSBL_CHANGED` |
| `reloadLaunched` | whether the filter reload was launched |
| `failed` | `{"id", "stage", "message"}` per resource not applied, `stage` being `fetch` or `apply`, the message bounded as an issue's is, except that its 1,024 bytes are counted as written on the line, JSON escapes included |

Every id on a result line is one a request may hold: the `geo-catalog`, or an id that maps to an alias. A `changedAliases`
entry is a pfBlockerNG alias name: `pfB_` and letters, digits and underscores, at most 31 characters. `applied`, `removed`
and `failed` name at most 2,048 ids together, each id once across the three, and `changedAliases` at most 2,048 aliases,
each once. Each of `applied`, `removed` and `failed` is still refused over 4,096 entries the same way, before their
combined bound of 2,048 ids; `changedAliases` is refused over 2,048 with `changedAliases holds more than 2048 entries`.

A result line is at most 524,288 bytes, its newline included: half of the 1 MiB Core reads back from fd 3 in all, so the
lines of one Update leave room for each other. When a line would be longer, every `failed` message longer than
`left out to fit the result line` (31 bytes, as written) becomes that text, and a shorter one is kept, so shortening never
lengthens a line; nothing else is ever shortened or left out. With the bounds above, the report of every request accepted
fits: the longest, every one of 2,048 ids of 36 bytes failed and every alias of 31 characters changed, is 286,826 bytes
once shortened. A report beyond the bounds is refused, and no line is written for it.

Core reads the result file whole and holds the apply (#4037, slice 8e) to three rules of the file, beyond those of each line:

- an id is named on one result line only, across the whole file: an id on two lines (applied on one and failed on another,
  or applied twice) refuses the result;
- `changedAliases` names only aliases of ids the request holds, in `resources` or in `removed`: any other alias refuses the
  result;
- the file as a whole stays within 1 MiB. When it is longer, Core keeps the complete lines inside the first 1 MiB and reports
  the rest as cut: what those lines report is settled, and the ids they do not name stay pending.

A line Core refuses (another version, an unknown field, an id outside the request, a failure message holding a control
character or a line or paragraph separator) refuses the whole result, unless it is the unterminated last line of a file
within 1 MiB, cut short by the apply's death: then the lines before it count.

With `pendingOutsideWindow` true the apply marks the changes pending and applies nothing, so its one line holds no `applied`.

### Hooks outside an Update

`pfb-core --run-hooks pre|post` runs the ADR-12 hooks of one fire point once and exits (issue #4035; spec
`docs/specs/go-updater-pipeline.md` section 5, "Hooks outside an Update"). It is for the two callers that fire hooks without an
Update, while the Core API may be stopped: the uninstall disable pass and the `runhooks` test verb of `pfblockerng.php`. Neither
calls it yet; they still run `pfb_run_hooks()` until the cutover.

```text
pfb-core --run-hooks pre|post --hook-dir PATH (--settings-backend-cmd PATH | --state-dir DIR) [--python-wrapper PATH] < context
```

- **Flags.** The same flags the daemon takes. The hook rows come from the [`hooks`](#projection-hooks) projection, read once
  through the settings backend: the adapter program of `--settings-backend-cmd`, else `settings.json` in `--state-dir`. Only
  that projection is read, as `pfb_run_hooks()` reads only the hook rows: another projection holding a value Core refuses, or
  one Core does not know, does not stop the run, although the daemon refuses to start on it. A state directory without
  `settings.json` is an uninitialized Core, which the daemon serves: one line is logged, no hook runs, and the status is 0.
  A `--state-dir` that does not exist or is not a directory is not one: one line, which quotes the path and gives the reason,
  is logged, no hook runs, and the status is 1.
  `--hook-dir` is the absolute folder the hook files are vetted in and run from; `--python-wrapper` is the absolute path of the
  program a `.py` hook runs through (without it a `.py` hook is logged and skipped). Other daemon flags are accepted and
  ignored. It opens no socket, takes neither `core.lock` nor the Update lock, waits for neither, and publishes nothing.
- **stdin.** Exactly one JSON object, with only these members, each optional:

  | Member | Type and values | Hook variable |
  |---|---|---|
  | `trigger` | string | `PFB_TRIGGER` |
  | `lifecycle` | `"uninstall"` | `PFB_PRE_UNINSTALL=1` (absent: `0`); `PFB_POST_INSTALL` is always `0` |
  | `pkgOp` | `"install"`, `"upgrade"`, `"reinstall"`, `"delete"` or `""` | `PFB_PKG_OP` (absent: empty) |
  | `ipChanged`, `dnsblChanged` | bool, `post` only | `PFB_IP_CHANGED`, `PFB_DNSBL_CHANGED`: `1` or `0` |
  | `changedIpAliases`, `changedDnsblGroups` | string, `post` only (the names separated by spaces) | `PFB_CHANGED_IP_ALIASES`, `PFB_CHANGED_DNSBL_GROUPS` |

  A member that is absent sets no variable, except as the table says. `PFB_WHEN` is the fire point, and `post` also gets
  `PFB_STATUS=ok`, the reserved value. A string reaches the hook as the UTF-8 text its JSON decodes to, escapes resolved, as an
  environment entry, never through a shell. A string value may not hold U+FFFD, which is also what invalid UTF-8 and a lone
  surrogate escape (`"\ud800"`) decode to; a valid surrogate pair is its character. The hook's environment is pfb-core's own
  without any `PFB_*` entry, plus the variables above, so a `PFB_*` variable of the caller never reaches a hook; the Python
  wrapper's `--print-interpreter` probe gets the same environment. This departs from `pfb_run_hooks()`, which passes an
  inherited `PFB_*` variable through unless the context sets the same name: the wrapper's own overrides (`PFB_PYTHON_DIR`,
  `PFB_PKG_BIN`, `PFB_PYTHON_DEPENDENCIES`) are dropped too. The `runhooks` verb's context is `{"trigger": "manual-test"}`
  for `pre` (or the trigger argument it is given) and, for
  `post`, the trigger with `"ipChanged": false, "dnsblChanged": false, "changedIpAliases": "", "changedDnsblGroups": ""`.
- **Refusals.** A member not in the table (names are case-sensitive), a member given twice, a value of another type or outside
  its values, a `post` member for `pre`, a string holding a NUL or U+FFFD (invalid UTF-8 and a lone surrogate escape
  included), input over 16 MiB, and input that is not exactly one JSON object (empty input, `null`, an array, two objects,
  trailing data) refuse the run: nothing runs, the settings backend is not called, one line is logged, with any member name
  it gives quoted, and the exit status is 2.
- **The run.** The hook runner of the Core Updater runs the enabled rows of the fire point one after another in list order,
  with its vetting, launchers, per-hook timeouts and survivor lifetime. A hook that is skipped, fails or times out is logged
  and the next one runs. TERM, INT or HUP ends a running hook as an Update's cancellation does: no further hook starts, one
  line says the run was cancelled, and the exit status is 1. Every enabled row of the fire point not yet started counts as
  not run, a row whose script vetting would have skipped included. A hook that the same signal ends first, as one sent to
  the whole process group does (a terminal's Ctrl-C, a hangup, `kill -TERM -<pgid>`), counts as cut short: a hook that ends
  by a signal or with a status above 128 while, or within 250 ms before, the run is cancelled. Its status line is logged
  first, as for any failed hook, then the line that the run was cancelled. A hook that exits 130 on its own, with no signal
  to the one-shot, is a failed hook. Three limits follow. First, a hook that handles the signal itself and exits with a
  status from 1 to 128 counts as run, so with nothing else left unrun the status is 0. Second, a group signal that the
  one-shot acts on more than 250 ms after the last hook's death (a starved host) is not seen as cutting that hook short,
  and the status is 0.
  Third, a HUP or INT that pfb-core inherited ignored (`nohup`, a background job of a shell without job control) stays
  ignored, and its hooks inherit that ignore. A signal that comes while the one-shot waits for its context ends the wait:
  one line is logged, nothing runs, and the status is 1; when the context had been read in full by then, the one-shot goes
  on with it as if the signal had come next. One that comes during the settings read is acted on once that read ends (at
  most the adapter's 10 s read timeout); it leaves the status 0 when the fire point has no enabled hook.
- **Output.** stderr is the main log: every runner line and all of each hook's sanitized output, without time stamps. The
  one-shot's own lines (a refused context, settings it cannot read, an uninitialized Core) carry the `pfb_core:` prefix and
  the date and time, as the daemon's do. With `"lifecycle": "uninstall"` stdout, the package operation's console, gets the
  same text, each piece after the main log has it, the one-shot's own lines on settings it cannot read included; a failed
  write to either, a closed pipe included (SIGPIPE does not end the one-shot), is dropped and never stops the other. A
  refused context, and a signal while the context is read, are logged to stderr alone: the lifecycle is not known then.
  Without a lifecycle stdout stays empty. There is no transcript and no
  separate error log. Two departures from `pfb_run_hooks()`: while `$pfb['hook_lifecycle']` is set it copies the main log to
  stdout with `pfb_logger()`'s date and time at the start of each runner line, where the one-shot's copy is unstamped; and
  without a lifecycle it still copies the runner's lines to stdout when that is a terminal, where the one-shot copies
  nothing.
- **Exit status.** 0 once the hooks ran, whatever they did, and for an uninitialized Core; 1 when the hooks did not all run:
  the settings cannot be read (a missing or failing backend, a `--state-dir` that is no directory, or hook rows Core refuses,
  as for a Core that cannot read its settings at start), when nothing runs, a signal came while the context was read, or a
  signal left an enabled hook unrun or cut one short; 2 for a usage error (`--run-hooks` without `pre` or
  `post`, an argument after the flags, no `--hook-dir`, neither backend flag, a relative `--hook-dir` or `--python-wrapper`)
  or a refused context, when nothing runs.

Corpus: `tests/hooks/fixtures/oneshot`, run through today's callers by `tests/php/HookOneShotCorpusTest.php` and through the
binary by `go/pfb_core/hooks/oneshot_test.go`.

## Resources

The resource store is a directory (`--resource-dir`) that holds the bodies the Core Updater publishes for the Outpost apply and for
pfB-DNS to fetch: IP sets, IP aggregates, the geo catalog and DNSBL scopes (issue #4032; spec `docs/specs/go-updater-pipeline.md`
section 8.2). Only the Core Updater writes it. The Core API reads it and never writes it, never creates its directory, and
never follows a symlink out of it. It holds data and caches, never settings or secrets. Per resource it keeps the current
generation, the applied baseline (the generation its consumer last reported applied: the Outpost apply, or pfb-dns
through [`ReportApplied`](#reportapplied) for `dnsbl/*`) and the delta between them, and nothing else.

**Resource ids.** `ip-set/<group>/<family>`, `ip-aggregate/<class>/<family>`, `geo-catalog` and `dnsbl/<scope>`. A
`<group>`, `<class>` or `<scope>` is one segment of `[A-Za-z0-9_-]+`, a `<family>` is `ipv4` or `ipv6`, and an id is at most
128 bytes. Any other id is `invalid_argument`.

**Body and digest.** A body is canonical: its members are unique and sorted in byte order, one per line, each line ending
in a newline. Its `digest` is the xxh128 of that body, 32 lower-case hexadecimal characters, and `entries` is the number of
members. A member is not empty, is valid UTF-8, holds no control character, does not start with `#` and is at most 1 MiB
long. A body whose records carry one value each (IP or CIDR members, domains) holds that value per line; a body whose
records carry several fields (a `dnsbl/*` scope with per-entry flags, the `geo-catalog` rows) holds one JSON object per
line (JSON Lines), each line a member like any other (owner, 2026-11-17, #4049). A **generation** is a number the Core Updater advances when a body or its `metadata` changes. `metadata` is an object the
Core Updater publishes with the body (for an IP set, its action and direction). A change of metadata alone is a new generation,
answered as a `delta` whose `addEntries` and `removeEntries` are `0`.

**Request.** `{"resources": {"<id>": <cursor>, ...}}`. A cursor is `{}` (none) or `{"generation": "<decimal string>", "digest":
"<32 hex>"}`: the generation and digest of the body the caller applied. Both fields come together; a field that is `null` is
absent. A missing or empty `resources` answers `{"resources": {}}`. A caller never does arithmetic on a generation: it keeps the
strings it was given and sends them back. A generation is a string because it can exceed 2^53.

**Reply.** HTTP `200` and `{"resources": {"<id>": <item>, ...}}`, one item per requested id. An item carries no members:
`GetResourceBody` streams them. It is exactly one of:

| Item | When | Keys |
|---|---|---|
| `{"kind": "unchanged"}` | the cursor's generation is the current one and its digest matches | `kind`, `generation` |
| `{"kind": "delta"}` | the store holds the cursor's generation with that digest: it is the applied baseline, the only generation kept besides the current one, and the delta from it is held | `kind`, `generation`, `from` (the cursor's generation), `addEntries`, `removeEntries`, `digest`, `entries`, `metadata` |
| `{"kind": "full"}` | there is no cursor, the store does not hold the cursor's generation (it is neither the current one nor the applied baseline), the digest differs, or the applied baseline's body or a part of the delta from it fails verification | `kind`, `generation`, `digest`, `entries`, `metadata` |
| `{"error": {"code": "not_found", ...}}` | the store has no such resource: never published, removed, or the store directory or its index does not exist | `error` |
| `{"error": {"code": "unavailable", ...}}` | the store cannot serve it: its index cannot be read, or its body is missing, not a regular file, or fails verification | `error` |

A key that does not belong to the kind is absent. `generation`, `digest`, `entries` and `metadata` describe the current body;
the delta's `add` part is what turns the body of the cursor's generation into it with its `remove` part, and
`addEntries` and `removeEntries` are their line counts. A resource's error does not change the HTTP status, so one
unreadable resource does not hide the others. A caller treats `not_found` as a resource that left the configuration.

*Amendment 2026-11-20 (issue #4049): the reply no longer carries `members`, `add` and `remove`; `GetResourceBody` streams
them from disk, and a delta carries `addEntries` and `removeEntries` instead. The Core Updater writes the delta from the
applied baseline when it publishes a generation, by one merge pass over the two sorted bodies, so a read only streams
files. Every file a reply relies on is verified whole against the index at the call, a chunk at a time: neither side holds
a body in memory.*

Fetching never advances a cursor and never changes the store. The digest in the cursor is what makes the fallback safe: a store
that was lost and rebuilt, edited by hand, or that reuses a generation number answers `full`.

**Refusals.** `invalid_argument` (`400`), with nothing read from the store, when `resources` or a cursor is not a JSON object,
a cursor holds an unknown key, an id is not a valid resource id (field `resources`, the message quotes the id), a cursor has
only one of `generation` and `digest`, a `generation` is not a string of ASCII decimal digits that fits 64 bits (`"007"` is
valid, `"-1"`, `"1.5"` and `""` are not), or a `digest` is not 32 lower-case hexadecimal characters. The field of a fault in a
cursor is `resources.<id>.generation` or `resources.<id>.digest`. More than 16 resources in one call are refused too, with the
field `resources`. The reply's size does not grow with the bodies: it carries none.

Without `--resource-dir` the call is `unavailable` (`503`), whatever it asks. A `--resource-dir` that does not exist is not an
error at start: every resource is `not_found` until the Core Updater creates it.

### GetResourceBody

`{"id": "<id>", "generation": "<decimal string>", "part": "members"}` asks for the body of a generation the store holds: the
current one or the applied baseline. `{"id": "<id>", "generation": "<g>", "part": "add" | "remove", "from": "<f>"}` asks for
a part of the delta from generation `f` to the current generation `g`; a `delta` item names both. The generations are the
strings `GetResources` gave, sent back as they are. A field that is `null` is absent, as in a `GetResources` cursor.

**Reply.** HTTP `200`, `Content-Type: text/plain; charset=utf-8`, `Cache-Control: no-store` and a `Content-Length`: the
part's lines, one per line, each ending in a newline, in canonical order (byte order, unique). A `members` body is exactly
the bytes whose xxh128 is the item's `digest`; its line count is `entries`. An `add` or `remove` part's line count is
`addEntries` or `removeEntries`. Core reads the file whole against its index before it sends the first byte, so a damaged
file is never served; the body comes from disk a chunk at a time. A caller writes it to a file (curl's `CURLOPT_FILE`),
checks the digest over those bytes, and hands the file on (`pfctl -T replace|add|delete -f`) without parsing it into an
array.

The Outpost apply (issue #4037) takes an `ip-set/*` or `ip-aggregate/*` part only when every line is safe to hand to pf as
one entry of the resource's family: one address, or one address followed by `/` and a prefix length, where `inet_pton()`
parses the address as that family (so no range, netmask, host name, zone or white space) and the prefix length is decimal
digits without a sign or a leading zero, at most the family's width. It does not compare spellings: hexadecimal digits in
either case and an uncompressed IPv6 address are taken, and one canonical spelling per network is the Core Updater's to
publish. One line that fails refuses the whole resource, which keeps its cursor. The Outpost also bounds every part by what
`GetResources` said of it: its line count times the longest line a member may be, 64 bytes and a line feed for an IP
member (no address or prefix the rule takes is longer) and 1 MiB and a line feed for any other. A `Content-Length` over
that bound is refused before the body is read, and a body that runs past it is cut off there and refused. Any other
answer is an error envelope, read at most 64 KiB whatever its status; a longer one is malformed. The Outpost sends its
stored cursor only while its mirror on disk is the body that cursor records (the same digest); a mirror edited, missing or
not a regular file sends `{}`, so a store rebuilt with another body under the same generation cannot answer `unchanged` to
it. A delta part that does not arrive as `GetResources` described it (over its bound, not plain text, another line count,
members out of byte order or a line repeated), parts that name one member in both (Core never emits that), a mirror this host
cannot open for the merge, or a merge that is not the item's `digest` and `entries`, is discarded and the full body asked
for; a line that is not a member is not, even in a part that is also out of byte order. A part the transport ends part way (the call's
deadline, a reset, a connection closed short of its `Content-Length`) is Core not answering: the resource fails as
unreachable and no full body is asked for under the same deadline. Any failure of the transfer itself, a reply curl cannot frame
included, counts as unreachable and does not fall back. A part this host cannot write whole (a full disk), or a merged mirror it
cannot create, write or close, fails the resource as a mirror failure, and no full body is asked for.

**Errors**, in the JSON envelope: `not_found` (`404`) when the store does not hold that part (the resource is unknown or
removed, the generation is neither the current one nor the applied baseline, or the delta is not the one from that
generation to the current one: it was pruned when another generation was published or applied; ask `GetResources` again);
`unavailable` (`503`) when the store's index cannot be read or the file fails verification, or without `--resource-dir`; `invalid_argument` (`400`) when `id` is
missing or not a resource id, `generation` or `from` is not a string of decimal digits that fits 64 bits, `part` is not one
of the three, `from` is missing with `add` or `remove`, or present with `members`. The field error names the parameter.

### ReportApplied

Issue #4036: pfb-dns reports the generation of each `dnsbl/*` resource it serves, after each swap and once after it
starts. This report is what makes a generation the applied baseline of `dnsbl/*` (spec
`docs/specs/go-updater-pipeline.md` sections 7 and 9).

**Request.** `{"requestId": "<id>", "resources": {"<id>": {"generation": "<decimal string>", "digest": "<32 hex>"},
...}}`: every `dnsbl/*` resource the caller serves, with the generation and digest of the body it applied, the strings
`GetResources` gave. A report replaces the previous one whole: a resource it does not list is one the caller no longer
serves. `{"resources": {}}` reports that it serves none.

**Reply.** `{}` once the report is written to `applied.json` in Core's state directory (written to `applied.json.tmp` by
one report at a time, synced, then renamed over the old one; a temporary file a crash left is taken over by the next
report; an empty directory at the record's name is replaced, and a non-empty one fails the report),
where it survives a restart. Core never writes the resource store for it: the Core Updater,
the store's only writer, folds the recorded report into the store (`resources.Store.FoldApplied`). A listed resource
whose generation and digest the store holds as its current body gets that generation as its applied baseline; a removed
resource the report no longer lists is deleted. A resource or generation the store does not hold changes nothing, so a
report naming one is recorded: the store can change between the report and the fold. The Core Updater does not fold
reports yet.

**Refusals.** `invalid_argument`, with nothing recorded, when `resources` is missing or `null`, lists more than 4096
resources, names an id that is not a `dnsbl/*` resource id, or holds a `null` entry (field `resources`; an id that is
not a resource id at all is not quoted in the message); when an entry
is a string, a number or another value that is not an object (field `resources.<id>`); or when an entry lacks its
`generation` or `digest`, or one of them has the shape a `GetResources` cursor refuses (field
`resources.<id>.generation` or `resources.<id>.digest`). It is a mutating method: a repeat of its `requestId` with the
same body gets the first answer, and with another body `conflict` ([requestId and replay](#requestid-and-replay)).

**The record at start.** Core reads `applied.json` when it starts and logs how many resources it holds. A record that is
not a regular file (a symbolic link is not followed), is larger than 1 MiB, or is not a report `ReportApplied` would
accept is logged as ignored and never used; the next report replaces it.

## Errors

Every error is the same envelope, with the HTTP status its code maps to:

```json
{"error": {"code": "invalid_argument", "message": "a mutating method needs a valid requestId",
  "fieldErrors": [{"field": "requestId", "message": "required"}]}}
```

`fieldErrors` is present only when a named parameter is at fault. `message` is for people; a client decides on `code`.

A refusal's `message` never quotes an id that is not a resource id (longer than 128 bytes, or of another shape). A
`field` name may carry the key as sent: a mistyped entry is reported under `resources.<key>` before the key is
validated, and for a client the 4 KiB cap below bounds that. A refusal to a
further local client (`--client-uid`) is under 4 KiB, its newline included: one that would be longer keeps its `code`
and is sent with a short fixed `message` and no `fieldErrors`. However much a client sends, Core echoes little of it,
and the answers its replay memory keeps stay small.

| `code` | HTTP | When |
|---|---|---|
| `invalid_argument` | 400 | Body not one JSON object, unknown or mistyped parameter, bad or missing `requestId`, a `GetResources` request that names a bad id or cursor or more than 16 resources, a `GetResourceBody` request with a bad `id`, `generation`, `part` or `from` ([Resources](#resources)), a `ReportApplied` request with a bad id or entry or more than 4096 resources ([ReportApplied](#reportapplied)) |
| `unauthenticated` | 401 | The caller is not an admitted local process, or is a further local client calling a method it is not served (see [Local authentication](#local-authentication)) |
| `not_found` | 404 | No such method, or no such API version; a `GetResourceBody` part the store does not hold |
| `method_not_allowed` | 405 | Not `POST` |
| `conflict` | 409 | A `requestId` reused with a different body; a settings call the store's state refuses ([Settings](#settings)); `StartUpdate` while an Update runs ([Update and schedule](#update-and-schedule)) |
| `payload_too_large` | 413 | Body over the limit |
| `internal` | 500 | The method failed unexpectedly or ran past its deadline (logged); also any code a method returns that is not in this table |
| `unavailable` | 503 | A repeat of a `requestId` whose first request still ran when the repeat's own deadline passed; the settings backend failed; Core runs no scheduler (no `--update-cmd`) or no resource store (no `--resource-dir`), or is stopping; the schedule cannot be computed ([Update and schedule](#update-and-schedule)) |

## requestId and replay

A mutating method (`InitializeSettings`, `SaveSettings`, `StartUpdate`, `ReportApplied`) takes a `requestId` in its
parameters: a string of 1 to 128 printable ASCII characters without spaces.
The method declares `requestId` in its own parameters, since unknown
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
- The privileged uid's requests and the further local clients' (`--client-uid`) are remembered apart, 4096 each, so
  nothing a client sends makes Core forget a privileged `requestId`. The clients share one memory of 4096, but each
  client uid's `requestId`s are its own: one client uid can neither answer nor conflict with another's. The memory
  itself is shared, so one client can still make Core forget another client's `requestId`s, and a repeat of a
  forgotten one runs again.

A read-only method takes no `requestId` and is never replayed.

## Limits and timeouts

| Limit | Value |
|---|---|
| Request body | 1 MiB (`payload_too_large` above) |
| Resources per `GetResources` call | 16 (`invalid_argument` above) |
| Resources per `ReportApplied` call | 4096 (`invalid_argument` above) |
| A refusal to a further local client | under 4 KiB ([Errors](#errors)) |
| `applied.json` read at start | 1 MiB (ignored above) |
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
   method runs. A further local client is then checked against the method it calls: it is served only `GetVersion`,
   `GetSettings`, `GetResources`, `GetResourceBody` and `ReportApplied`. Any other method, an unknown one included,
   answers it `unauthenticated` and does not run, so a client learns nothing of the methods it may not call.
   Within those methods a client reads only what pfb-dns builds from: `GetSettings` serves it the `dns` and
   `policy/dnsbl` projections (with no `projectionIds`, those two), and refuses any other id as it refuses a projection
   that does not exist (`invalid_argument`, `no such projection`, field `projectionIds[<i>]`). `GetResources` answers
   an id outside `dnsbl/*` `not_found` for that id, and `GetResourceBody` answers its body `not_found`, as for a
   resource the store does not hold. A uid that is both `--allow-uid` and a `--client-uid` is the privileged caller
   and is served everything. Each request Core serves carries which of the two it is. The mark decides what
   `GetSettings`, `GetResources` and `GetResourceBody` serve and whether a refusal is shortened, and a call that carries
   no mark is limited as a client's: only a request checked as the privileged uid's lifts those limits. Which methods
   a caller may call at all is decided where the request is admitted, not by the mark.

Flags: `--allow-uid UID` is the privileged caller (default 0, root: PHP on pfSense). Each `--client-uid UID` admits one more
local client, limited to the methods above.
`--socket-group GID` opens the socket's directory (0750) and the socket (0660) to that group, so a client that
is not root can connect. Even then, the uid check decides who is served: group membership alone is not enough.

**A second local client: pfb-dns.** pfb-dns will fetch `dnsbl/*` and its settings from Core over this API (map #3813). It
drops privileges to its own user after start. The pfb-dns ticket admits it by adding `--client-uid <that user's uid>` and
`--socket-group <a group of that user>` to Core's rc line. pfb-dns runs as `unbound` today, so admitting that uid admits
every process of that user, Unbound included. A dedicated pfb-dns user narrows that, and the pfb-dns ticket decides it.

*Amendment 2026-11-21 (issue #4036): a further local client was served every method, so admitting pfb-dns's user would
have let any process of that user call `SaveSettings` or `StartUpdate`. It is now served the read methods pfb-dns needs
and `ReportApplied` only, reads only the `dns` and `policy/dnsbl` projections and the `dnsbl/*` resources, and has
a replay memory of its own.*

## On pfSense

| What | Where |
|---|---|
| Binary | `/usr/local/pkg/pfblockerng/core/bin/freebsd-amd64/pfb-core`, `.../freebsd-arm64/pfb-core` (static, `CGO_ENABLED=0`; built by `scripts/build-pfb-dns.py`) |
| rc script | `/usr/local/etc/rc.d/pfb_core.sh`, written by `pfb_core_service()`; pfSense service `pfb_core`; it starts pfb-core with `--settings-backend-cmd`, `--update-cmd`, `--maintenance-cmd`, `--metrics-cmd`, `--counters-cmd`, `--zoneinfo /etc/localtime` (the host's zone, which the scheduler reads local time in) and the feed phase's flags below |
| Feed phase flags | `--feed-local-dir` once per folder a `file://` feed may sit directly in: the 14 of `pfb_filter()`'s local-path rule (`/var/db/pfblockerng` and its `deny`, `permit`, `match`, `native`, `original`, `dnsbl`, `dnsblorig`, `ET`, `ut1` and `shallalist` folders, `/usr/local/www`, `/usr/local/share/GeoIP`, `…/GeoIP/cc`) and the real path of the database folder (resolved when the script is generated, when it exists); `--script-dir` twice, in search order (`/usr/local/pkg/pfblockerng/list_scripts`, then `/usr/local/pkg/pfblockerng`); `--rsync-bin /usr/local/bin/rsync`; `--user-agent` the cURL user agent of the package, `pfSense/pfBlockerNG cURL download agent-<unique id>`, as one quoted argument without the line break an id may end with. Each value is `escapeshellarg()`-quoted; Core refuses a relative path and a user agent with a control character as a usage error (exit status 2) |
| Supervisor | `daemon(8) -r -R 5 -t pfb_core`, pidfiles `/var/run/pfb_core_daemon.pid` (supervisor) and `/var/run/pfb_core.pid` (pfb-core) |
| Log | `/var/log/pfblockerng/core.log` (pfb-core's stderr, through `daemon -o`) |
| Socket | `/var/run/pfb_core/api.sock` |
| State (`--state-dir`) | `/usr/local/etc/pfb_core` (0700): Core's data and its lock, never settings; with `--update-cmd` also `schedule_state.json` and `update.log`; outside `/var`, so it survives a RAM-disk reboot |
| Settings backend | `/usr/local/pkg/pfblockerng/pfb_core_settings.sh` (`--settings-backend-cmd`): `config.xml` through PHP |
| Update program | `/usr/local/pkg/pfblockerng/pfb_core_update.sh` (`--update-cmd`): the `core_update` verb of `pfblockerng.inc` |
| Metrics program | `/usr/local/pkg/pfblockerng/pfb_core_metrics.sh` (`--metrics-cmd`): runs the `metrics` verb under `timeout -s TERM -k 5 50`; it tests nothing, Core decides |
| Counters program | `/usr/local/pkg/pfblockerng/pfb_core_counters.sh` (`--counters-cmd`): the `core_counters` verb of `pfblockerng.inc`, argument `clearip`, `cleardnsbl` or both |

- **Start** and **Stop** run under one lock (`lockf -k -t 20 /var/run/pfb_core.lock`; status 75 when another start or
  stop holds it). **Start** keeps a pfb_core supervisor that already runs. Otherwise it runs this machine's binary (picked by `uname -p`), and it
  fails when `daemon(8)` fails or its pidfile names no supervisor within 5 s; it returns once the supervisor runs, not once
  the socket listens. A package without an executable `pfb-core` for this machine starts nothing and logs why. That is not
  a failure. An unknown machine is a failure.
- **Stop** sends TERM to the supervisor and to pfb-core, then KILL at 5 s. It signals a process only while its pidfile names it
  and its command line is pfb_core's, so a reused pid is never signalled. pfb-core first ends a running Update (the
  program's process group gets TERM, and KILL 3 s later), then finishes the requests in flight (up to
  3 s) and removes its socket. A process still running at 7 s fails the stop, keeps the pidfiles and fails a start or
  restart over it.
- **Package lifecycle.** The install and every upgrade regenerate the script and restart the service. pfSense starts it at
  boot with the package's services. A removal stops it and deletes the script. Regenerating the script deletes
  the #3842/#3913 leftovers: `settings.json`, `settings.json.tmp` and `settings.lock` in the state directory, and
  `core_pushed` / `core_push_failed` in `/var/db/pfblockerng`, and (#3941) the PHP scheduler's `pfb_schedule_state.json` in
  `/usr/local/etc` and the schedule entries of `/var/db/pfblockerng/pfb_due_ledger.json` (`extra:dcc`, `extra:bl`, the cache
  stamp and the times of `cron`; its `pending_apply` flag, `ss_refresh` and `apply_reconcile` stay). With Keep Settings off, a removal also deletes the state
  directory once `pfb_core` is stopped (`pfb_core_state_teardown()`).
- **Paths.** Core reads every path from a flag (`--resource-dir`, `--feed-local-dir`, `--script-dir` and `--rsync-bin` must be absolute: a relative one is a usage error; the rc script does not pass `--resource-dir` yet, as nothing publishes into the store, so `GetResources` answers `unavailable` on pfSense for now). It names no pfSense path and imports nothing but the standard library, its
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
baseline and requests the TOP1M rebuild only after `write_config()` succeeded. After
a written save they call `pfb_core_settings_changed(NULL, TRUE)` (`SettingsChanged`); the tick calls it unforced (compare,
then notify). The Groups pages and the DNSBL Category (Blacklist) page notify the same way after their written saves, pinned
by `CoreSettingsFeedPageSavesTest`. A save works while Core is down. A failed notice is logged once per outage and kept in
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
`pfblockerng_run.log` is not opened. The result goes to fd 3: a line for each feed's terminal check and each Extra that succeeded,
written as it finishes, and the whole result as the last line. The exit status is 0 on success and 1 on a failed Extra, pass or
apply. Pinned by `CoreUpdateServeTest`.

The `.pfb_cron_disable` sentinel (`pfb_cron_disabled()`) suppresses scheduled work, and Core starts the scheduled Update by itself, so
the verb honours it for trigger `scheduled` only: it runs nothing, writes an empty result (no outcome, nothing attempted, GeoIP
not reported: the feeds Core reserved stay pending and are planned again), logs one line naming the sentinel and exits 75.
`manual`, `apply` and `retry` are unaffected. Pinned by `CoreUpdateCronDisableTest`.

**The Update page** (`pfblockerng_update.php`) is Core's client. Run Now, Force and the Wizard reload call `pfb_update_start()`: a
`StartUpdate` of `manual` with the page's scope and force (allow-listed before the call), and an Update that already runs is
`conflict`, reported as "An Update is running." The live view polls `?ajax=update[&after=<cursor>]` once a second:
`pfb_update_view_response()` relays `GetUpdate` as `{running, done, log, next, update}` (`after` only as the string of decimal digits
it is; anything else is dropped), and the poller stops when `done` and the log is drained. A changed `update.startedAt` clears
the viewed log and drops the cursor; a Core that restarted answers `update` null, which leaves what is shown as it is. The status
line is `GetUpdate.running` (`pfb_update_running()`), and the Schedule section is `GetSchedule` (`pfb_update_schedule_view()`): Feed
groups from `feeds`, Extras from `extras["extra:dcc"]`, DNSBL Category from `extras["extra:bl"]`. A row says "Core is not answering"
(the transport's reason on hover) only when no HTTP reply came, and "Core cannot give the schedule: <Core's message>" when Core
answered with an error. Every call of the page is bounded by `PFB_CORE_PAGE_TIMEOUT` (5 s, not `pfb_core_call()`'s 30 s), so a wedged
Core does not hold a php-fpm worker. Pinned by `UpdateViewResponseTest`, `UpdateScheduleRowTest`, `UpdateCoreCallBoundsTest` and
`UpdatePageCoreTest`.

The tick (`pfblockerng_tick()`) keeps the Outpost's duties and asks Core for the two Updates only the Outpost can tell are due:
`StartUpdate` of `apply` for a pending change inside the apply window (outside it, the tick logs that it is deferred and the apply
record says waiting), and of `retry` for a `*.fail` marker of an enabled feed or an absent DNSBL manifest. `conflict` is a logged
skip and an unreachable Core a logged notice: nothing runs in the tick instead. It reads and writes no schedule state or cache,
and skips log maintenance while Core reports an Update running. Pinned by `TickCoreUpdateTest` and `DnsblManifestTickRecoveryTest`.
