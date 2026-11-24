# Go Core Updater pipeline

This specification resolves the owner decision of 2026-11-17 on map
[Wayfinder: grow pfBlockerNG Core in Go](https://github.com/pfBlockerNG/pfBlockerNG/issues/3813)
([decision comment](https://github.com/pfBlockerNG/pfBlockerNG/issues/3813#issuecomment-6939397673)) and the owner's answers of the same day to the
forks of the first proposal. It supersedes the "Option A" decision on #3977 (a PHP-sequenced Update calling a `FeedPhase`
method) and slices 8 and 9 of the #3905 cutover plan, and it merges steps 2, 4 and 5 of the map's subsystem order.

Read at `devel` `53ef24d5d` (2026-11-17); branch `origin/wip/issue/3977` at `5b4867668`. No test, build or smoke was run for
this document. `pfblockerng.sh`'s dedup and reputation verbs were located (`pfblockerng.sh:2638-2715`) but not read line by
line, and the `wip/3977-*` side branches were not examined.

File abbreviations, all under `src/usr/local/`:

| Short | Path |
|---|---|
| `apply.inc` | `pkg/pfblockerng/pfblockerng_apply.inc` |
| `pfb.inc` | `pkg/pfblockerng/pfblockerng.inc` |
| `extra.inc` | `pkg/pfblockerng/pfblockerng_extra.inc` |
| `cron.inc` | `pkg/pfblockerng/pfblockerng_cron.inc` |
| `pfb.sh` | `pkg/pfblockerng/pfblockerng.sh` |
| `www.php` | `www/pfblockerng/pfblockerng.php` |
| `protocol.md` | `docs/misc/core-api-protocol.md` (repo root) |

## Goal

An Update is one loop, run from start to finish by the **Core Updater**: it reads the settings, decides the work, runs the Extras,
fetches and parses every feed, runs every script and hook, builds the DNSBL data, DNSBLIP and the IP sets, publishes them as
generations, invokes the Outpost apply once, and settles. The Outpost takes part only through the Settings backend read and the Outpost
apply. It makes no fetch, parse or policy decision. The PHP, shell and Python code that sequences, downloads, parses,
deduplicates and aggregates today is removed in the cutover.

## Fixed constraints

- **Owner, 2026-11-17:** "PHP is the outpost bridge only and nothing else. All the download, parsing, etc. must be in Go.
  [...] At most Update can call shell script and programs, and PHP is only at the end, when applying it to pfSense."
- **Owner, 2026-11-17, on where the stages run:** "In the Update worker."
- **Owner, 2026-11-17, on scripts and hooks:** post-scripts are run by the Core Updater; "Pre nowadays is run during the update
  process, so the Updater should run it"; and for a hook after the apply: "Either way. Updater runs them."
- **Owner, 2026-11-17, on `post`:** "I think the 'post' hooks running after apply itself is an accident. A happy one, but one
  nonetheless. I think it was just the easiest place to put those things. I think the only thing I truly wanted was for it to
  run after the whole feed and file processing was done."
- **Owner, 2026-11-17, on set bodies:** "Core API with deltas between generations, is how we had originally envisioned it."
- One Update at a time, never queued; a scheduled trigger that finds one running is skipped (#3813, 2026-11-11).
- An admitted Update owns its lifetime: stopping or losing the Core API does not signal it (#4022, landed by #4025;
  `protocol.md:347-352,431-435`).
- No pfSense path or import in `go/pfb_core`; every path comes from a flag; `go/pfb_core/boundary_test.go` keeps passing
  (`protocol.md:557-561`).
- On pfSense `config.xml` is the Settings backend through the Outpost's adapter command; Core persists data and caches, never
  settings (#3813, 2026-11-13).
- pfB-DNS is a Core API client; nothing writes files for it; it may keep a private startup cache (#3813, 2026-11-12).
- "Applied" means the `pfctl` operations succeeded and the reload was launched; ruleset convergence is reported separately
  (#3813, accepted boundary proposal).
- One generation per logical set and address family; an action or direction change is a change of that resource (same).
- Reports, Alerts and Stats stay in the Outpost for the MVP (same).
- Method: a parity corpus frozen from today's behaviour, a direct translation against it, then a cutover; no redesign during a
  port and no long-lived dual path (#3813, method).
- Every registered config field goes through `PfbConfig`; no direct interpreter on the appliance outside `pfb_python.sh`
  (`AGENTS.md`).
- **Timing (owner, 2026-11-17):** "don't use time to handle concurrency, nor waiting, in production and tests" and "Polling
  with short ticks is fine-ish. 'Wait 30s because I think this is long enough here' is not." Synchronize on events where
  possible. Short-tick polling of a real condition is allowed. A fixed delay that decides ordering is forbidden, in production
  code and in tests. A cap that only fails a hung test is allowed where `.agents/policy/waits.md` permits it
  (`.agents/policy/testing.md`: duration is never an assertion).

## Decisions

### 1. Terminology

The vocabulary is the committed glossary: `UBIQUITOUS_LANGUAGE.md`, section "Core and Outpost" (`devel` `afe7deda6`). This
spec, the tickets and the code comments use its terms and nothing else for these roles:

| Term | In this spec |
|---|---|
| **Core** | The platform-neutral Go side: the **Core API**, the **Core Updater** and **pfB-DNS** |
| **Core API** | The `pfb-core` process that admits and schedules Updates and serves settings and resources. It runs no stage of an Update |
| **Core Updater** | The `pfb-core --update-worker` process that owns one Update from start to finish (§3) |
| **Update** | One run of the Core Updater, admitted by the Core API |
| **pfB-DNS** | The DNS engine, its own process, a Core API client |
| **Outpost** | The pfSense PHP package in its platform role. It decides nothing about an Update |
| **Outpost apply** | The Outpost step the Core Updater triggers once at the end of an Update |
| **Settings backend** | `config.xml`, read and written through the Outpost's adapter command (`--settings-backend-cmd`) |

Name the process that does a step. Never write "Core decides" or "PHP decides" for a step of an Update. "PHP" in this
document means the language or today's code, never a role.

### 2. Who does what

- **Core API:** evaluates the schedule, admits one Update under the lifetime lock, starts the Core Updater, serves `GetUpdate`,
  `GetSchedule`, `GetSettings` and `GetResources`, and settles the schedule state from the Core Updater's result.
- **Core Updater:** everything between admission and the end of the Update (§3). It reads the Settings backend itself, once,
  after it holds the lock. Settings and secrets stay in its memory.
- **Outpost:** the Settings backend read at the start of the Update, and the Outpost apply at the end. Nothing in between.

Today's Core Updater has one step, "run the program" (`go/pfb_core/update/worker.go:520-599`). The stages of §3 replace it.

### 3. The Update loop, in order

The order is today's order (Appendix A), so the parity corpus compares stage by stage.

1. **Admit** (Core API, exists): scheduler or `StartUpdate`, lifetime lock `update.log.lock`, transcript replaced.
2. **Snapshot** (Core Updater): read the Settings backend, with the opaque pending token (§8.6). A `scheduled` Update ends
   `skipped` when the adapter reports scheduled work disabled (§12).
3. **Work list** (Core Updater), decided now, under the lock, from the snapshot, the request (feed ids, Extras, scope, force) and
   the Core Updater's own state (`.update` and `.fail` markers, baselines). Rules kept: a feed with a `.fail` marker is always added
   (`cron.inc:409-414`); Hold with a published list is success and skipped (`cron.inc:392-398`); the retry cap
   (`cron.inc:89-97`); a narrower scope never settles work outside it (#3977, 2026-11-15 completion contract).
4. **`pre` hook** (Core Updater), where it fires today: before any feed work (`apply.inc:1454`).
5. **Extras**, `extra:dcc` then `extra:bl` (`extra.inc:6875`): transfer, change detection and publication of MaxMind, IPinfo
   ASN, TOP1M and the Blacklist archives; GeoIP and ASN conversion when their source changed. A failed Extra is `attempted`,
   keeps the previous data and does not stop the Update. An Extra whose data is missing is due, which folds in today's
   on-demand fetches (`apply.inc:2428,2553,3761`).
6. **Change detection** per feed of the work list, IPv4, IPv6, DNSBL, groups in config order (`cron.inc:352`).
7. **Apply-window check** (`cron.inc:443-463`): outside the window the Update ends without building or applying and reports
   pending work, which the Outpost apply records in its pending marker on the next apply request.
8. **DNSBL stage**, per group in config order, per feed: reuse decision, transfer, custom list, normalize, pre-script, parse,
   post-script, DNSBL IP side lists, counts. Then SafeSearch, whitelist, TOP1M whitelist, TLD, regex and IDN inputs.
9. **DNSBLIP**: `DNSBLIP_v4` and `_v6` from the side lists of stage 8.
10. **Publish `dnsbl/*`** when the data or its policy changed.
11. **GeoIP sets**: continent sets from the converted country lists.
12. **IP stage**, IPv4 then IPv6, groups in config order, the DNSBLIP group where today's loop adds it (`apply.inc:4022`):
    per feed the steps of stage 8, then per-feed dedup, aggregation and reputation, and the pre-suppression snapshot.
13. **Cross-feed recompute** in member order, then `pmax` (`apply.inc:4603-4675`).
14. **Suppression** after the recompute (`apply.inc:4812-4849`), then the canonical set per logical set and family.
15. **Uber aggregates**.
16. **Publish `ip-set/*`, `ip-aggregate/*`, `geo-catalog`** (§7).
17. **Feed outcomes** go to the durable result as each feed finishes (kept from #4002), not at the end.
18. **Outpost apply** (§8), once.
19. **`post` hook** (Core Updater), after the Outpost apply returned, still under the Update lock (§5).
20. **Settle**: the Core Updater records the applied generations and reports the Update finished; the Core API settles the
    schedule state from the result.

The three hazards the Option A comments raised are kept by construction:

| Hazard | Today | In the Core Updater |
|---|---|---|
| Extras run first | `extra.inc:6875-6909` | Stage 5 precedes every feed stage |
| DNSBLIP is built mid-sync | side files `apply.inc:3001-3019`, assembly `apply.inc:3209-3266`, use `apply.inc:4022` | Stages 8, 9 and 12 are sequential in one process |
| The work list is decided under the locks | `apply.inc:1226-1227`; `cron.inc:271-309` | Stage 3 runs after the lifetime lock and the snapshot |

*Amendment 2026-11-24 (issue #4038, sub-slice 9k): what slice 9 built, where it differs from the list above. Stage 3 keeps
the per-feed `.fail` marker but no per-feed `.update` marker: the feeds a `Pending` decision leaves are kept in the Core
Updater's own state, `updater.json` in Core's state directory (`pendingFeeds`; also `requested` and `requestedRemoved`,
what the last apply that ran to its end was asked to load and remove), and an `apply` Update builds exactly those feeds,
with no change detection and no Extras. The Blacklist providers' `.update` markers and `geoip.update` stay, consumed only
once the settle succeeded. The `pre` hook (stage 4) fires after the Extras, the change detection and the apply-window
check, and only when a pass runs, where today's pass fires it: today the Extras run before the pass
(`extra.inc:6875`), so the order above put it too early. The loop's stages are therefore snapshot, work list, Extras,
change detection, apply window, `pre` hook, then stages 8 to 20 (`go/pfb_core/update/loop.go`). Stage 7: outside the apply window nothing is built, but the Outpost apply is still invoked
once, with `pendingOutsideWindow: true`, so that it records the pending work. A narrow-scope manual Update runs only its
own side's stages. DNSBL downloads are kept in `dnsbl` under the database folder, not `dnsblorig`; the cutover (#3977)
decides. The loop runs only with the `pfb-core` flag `--update-loop`, which the rc script does not pass: it passes the
loop's folders, so a real Update still runs the `--update-cmd` program alone (`protocol.md` "On pfSense").*

### 4. Locks

| Lock today | Where | After |
|---|---|---|
| Scheduler dispatcher lock | `extra.inc:5973-6006` | **Removed.** It serialized entry points that start no Core Update (`extra.inc:6781-6782`); §11 leaves none that fetch or parse. |
| Feed-pass lock | `pfb.inc:28377,28341` | **Kept, as the apply lock.** The Outpost apply holds it for its whole run. It serializes the apply against the Outpost paths that run without an Update: the boot branch (`apply.inc:1397-1422`), the uninstall teardown (`pfb.inc:29189`), the tick's ADR-61 `pfctl` retries (`extra.inc:6560-6575`). Held: the apply exits 75. |
| DNSBL publication lock | `pfb.inc:17222` | **Removed** with the manifest. |
| GeoIP generation lock and readiness check | `pfb.inc:9860`; `extra.inc:3605` | **Removed** for data: the conversion runs inside the one Update. |
| DNS config lock | `pfb.inc:19183` | Kept (Outpost): it protects `config.xml`, also against the settings adapter (`protocol.md:578-582`). |
| `update.log.lock` | `protocol.md:431-435` | **The single Update lock**, held by the Core Updater from admission to the end of settle. |
| Normalization cache lock | `go/pfb_core/feedparse/normcache.go` | Kept, internal to the Core Updater. |

No lock crosses a process boundary: the Core Updater holds Core's lock, the Outpost apply takes its own.

*Amendment 2026-11-24 (issue #4038, sub-slice 9k): `update.log.lock` does cross into two holder processes, on purpose
(#4226). No child of the Core Updater inherits it, except through a holder: the apply's holder keeps it while the apply
runs, and each hook runs under a holder (`--hook-hold`) that keeps it until the hook's own process exits and closes it
before the hook starts, so a service the hook leaves running never holds it. The hook dies with its holder. rsync dies
with the Core Updater (parent-death signal). A killed Core Updater's settings adapter call is left to finish, and a
pre-script being ended by its watchdog may outlive the lock for the watchdog's TERM grace.*

### 5. Scripts and hooks: the Core Updater runs them

| What | Today | After |
|---|---|---|
| Per-feed pre-script | PHP `pfb_list_pre_script_run` (`pfb.inc:11066`); a Go port exists, uncalled (`go/pfb_core/feedparse/prescript.go`) | Core Updater, strict policy |
| Per-feed post-script | PHP `pfb_list_script_exec` (`pfb.inc:10877-10884`), 300 s, `timeout` in reaper mode; DNSBL runs it on a staged copy (`apply.inc:2980-2992`), IP renames its output over the baseline (`apply.inc:4448-4462,4573`) | Core Updater, strict policy, same point and same inputs |
| ADR-12 `pre` hook | PHP `pfb_run_hooks('pre')` at the top of the pass (`apply.inc:1454`) | Core Updater, stage 4 |
| ADR-12 `post` hook | PHP `pfb_run_hooks('post')` at the closing tail (`apply.inc:5582`) | Core Updater, stage 19 |

*Amendment 2026-11-21 (issue #4035, slice 6b): the IP post-script row above is wrong about the output. Today's code, and the
Go port (`feedparse.PostScript`), run the IP post-script on the download itself; the staged copy is a restore point, not the
script's input. The restore point is renamed back over the download at once when the script fails, and otherwise after the
empty-feed check. The script's output therefore reaches only that check and is never kept as the baseline.*

**The `post` contract.** The Core Updater runs `post` after all feed and file processing. That is what the owner wanted from
it. Today's code also fires it after the pfSense apply (`apply.inc:5542-5544`: "AFTER the IP/DNSBL reloads,
filter_configure(), and the FINAL REPORTING 'closing' step"); the owner calls that a happy accident, and it is kept: `post`
runs after the Outpost apply returned, still inside the Update, while the Core Updater holds the Update lock, and before the
Update is reported finished.

Its context is unchanged: `PFB_IP_CHANGED`, `PFB_DNSBL_CHANGED`, `PFB_CHANGED_IP_ALIASES` and `PFB_CHANGED_DNSBL_GROUPS`
(`apply.inc:5582-5591`). The first three come from what the Outpost apply reports on fd 3 (§8.4), alias names included, since
Core does not know alias names. `PFB_CHANGED_DNSBL_GROUPS` is the Core Updater's own.

Not part of the contract, by the owner's waiver of 2026-11-17: whether the Outpost apply lock is still held when `post` runs,
and whether the pending-changes mark is already settled. Today `post` runs before both (`apply.inc:5605-5639`); after the
cutover it runs after both. No parity test covers either point.

**The hook runner is ported to Go** (`pfb_run_hooks`, `pfb.inc:12645-12732`), with the same rules:

- Hooks come from the settings (a `hooks` projection: rows of `when`, `script`, `description`, `timeout`, enabled, in list
  order; `pfb_get_hooks`, `pfb.inc:12305`). No enabled hook for a fire point: nothing runs.
- Vetting at run time: the script is a bare basename named `hook_<when>_*.sh` or `.py` that exists in the hook directory
  (`pfb_hook_script_valid`, `pfb.inc:12431-12439`; the directory, `pfb.inc:4114-4115`, comes from a flag). Anything else is
  logged and skipped, never run.
- Launcher: a `.sh` runs directly; a `.py` runs through the Python wrapper, whose path comes from a flag
  (`pfb_hook_script_command`, `pfb.inc:12445-12453`; `AGENTS.md` never-list). No usable launcher: logged and skipped.
- Environment: `PFB_WHEN`, `PFB_TRIGGER`, `PFB_POST_INSTALL`, `PFB_PRE_UNINSTALL`, `PFB_PKG_OP`, and for `post`
  `PFB_IP_CHANGED`, `PFB_DNSBL_CHANGED`, `PFB_STATUS` (the reserved `ok`), `PFB_CHANGED_IP_ALIASES`,
  `PFB_CHANGED_DNSBL_GROUPS` (`pfb.inc:12655-12684`; `apply.inc:5582-5591`). A name that is not `[A-Z0-9_]+` is dropped. The
  variables are set on the child only, never in the Core Updater's own environment.
- Lifecycle context. `PFB_POST_INSTALL`, `PFB_PRE_UNINSTALL` and `PFB_PKG_OP` are facts only the Outpost knows
  (`pfb.inc:12470-12475,12602-12612`). `StartUpdate` gains two optional parameters, `lifecycle` (`install`) and `pkgOp`
  (`install`, `upgrade`, `reinstall`, `delete` or empty), which the Core Updater copies into the environment of both hooks.
  Without them both lifecycle flags are `0` and `PFB_PKG_OP` is empty.
- Lifetime: per-hook timeout (default 60 s, `pfb.inc:4052-4053`), TERM then KILL after 5 s (`pfb.inc:4057-4058`), applied to
  the hook's own process only. A daemon the hook started survives (`timeout --foreground`, `pfb.inc:12718-12721`;
  `docs/misc/external-process-waits.md:34`). This is a policy of its own in `internal/process`, beside the strict `Run` that
  exists today (`docs/misc/external-process-waits.md:38-43`) and the `RunIndependent` that #4020 adds for the apply program.
  The hook slice adds it.
- A timeout or a non-zero exit is logged and the next hook runs; the Update never fails because of a hook.
- Output: captured to a regular file, never a pipe; sanitized; the first 1,048,576 bytes per invocation go to the Update
  transcript with one notice, the whole output to the main log (`protocol.md:413-417`).
- Hooks run one after another, in list order.

**Install and upgrade are one Update.** The package resync after an install or an upgrade
(`pkg/pfblockerng.xml:112`; `pkg/pfblockerng/pfblockerng_install.inc:58-59,1073`) starts one Update through the Core API with
`lifecycle: install` and its `pkgOp`. The hooks fire once in that Update, with `PFB_POST_INSTALL=1`, as today.

**Hooks outside an Update.** Two callers fire hooks without an Update, and the Core API may be stopped when the first one
runs: the uninstall disable pass (`pfb.inc:29186`) and the `runhooks` test verb (`www.php:93-104`). Today both call
`pfb_run_hooks()` from PHP. After the cutover they call a one-shot mode of the same binary:

- `pfb-core --run-hooks <pre|post>` runs the Core Updater's hook runner once and exits. It reads the hook rows through the
  Settings backend, takes its directories and the Python wrapper from the same flags the Core Updater gets, and needs no
  running Core API. It takes no Update lock and publishes nothing.
- The context comes from the caller, as one JSON object on stdin with a fixed vocabulary: `trigger`, `lifecycle`
  (`uninstall` or absent), `pkgOp`, and for `post` `ipChanged`, `dnsblChanged`, `changedIpAliases`, `changedDnsblGroups`. An
  unknown field or value refuses the run: nothing executes.
- The vetting, launcher, environment, lifetime, failure and output rules are the ones above. There is one hook runner.

### 6. Settings the Core Updater reads

Present: `settings/dns`, `feeds/ipv4`, `feeds/ipv6`, `feeds/dnsbl`, `schedule`, `ingest` (`protocol.md:165-322`). Added, all
through the Settings backend's adapter, each with a parity fixture frozen against today's reader:

| Input | Today's reader | Projection |
|---|---|---|
| Dedup, aggregation, reputation switches and limits, ET IQRisk categories, country white and black lists | `apply.inc:1522-1575` | `policy/ip` |
| IPv4 and IPv6 suppression lists (text in the IP section, not a firewall alias) | `pfb.inc:15274-15295` | `policy/ip` |
| Effective list class per group (Advanced invert forces Native and bypasses dedup) | `apply.inc:1756,1839,4205` | a field on `feeds/*` groups |
| Continent groups: action, selected countries per family | `apply.inc:3793-3822` | `feeds/geoip` |
| MaxMind account and key, IPinfo token, TOP1M provider and token, locale | `www.php:565,582-595` | `extras` (secrets write-only) |
| DNSBL build policy: whitelist, TOP1M count and inclusions, TLD lists, regex list, IDN mode, SafeSearch, per-group logging mechanism, DNSBLIP action | `apply.inc:1536-1543,2238-2462,2690-2699` | `policy/dnsbl` |
| Hook rows | `pfb.inc:12305` | `hooks` |
| Scheduled work disabled (`.pfb_cron_disable`) | `extra.inc:6744-6747` | read-only field in `ingest` |
| Sinkhole addresses (§12) | `pfb.inc:19714` | read-only box fact; withdrawn 2026-11-17 (issue #4053) |

Interfaces reach Core only as `bindAddress` and `selfAddresses`, and the proxy is in `ingest`; all three exist
(`protocol.md:194,297-301`). Rule interfaces, gateways, rule selectors, alias names, the placeholder address
(`apply.inc:1529`) and kill-states never reach Core.

### 7. Resources, generations and retention

| Resource | Body | Metadata |
|---|---|---|
| `ip-set/<group>/<family>` | canonical IP/CIDR members | `action`: `deny`, `permit`, `match`, `alias_only`; `direction`: `ingress`, `egress` or both; `entries`; `digest` |
| `ip-aggregate/<class>/<family>` | Uber union | `alias_only`; `entries`; `digest` |
| `geo-catalog` | countries, continents, counts, ASN choices | `digest` |
| `dnsbl/<scope>` | DNSBL data for pfB-DNS (§9) | `sinkholeRequired`, per-group counts |
| `settings/<projection>` | exists | exists |

*Amendment 2026-11-18 (issue #4053): with the WebServer/VIP response removed, nothing needs a sinkhole, so `dnsbl/<scope>`
carries no `sinkholeRequired`; the per-group counts stay. The same holds for the `dnsbl` object of the example below.*

*Amendment 2026-11-20 (issue #4034, slice 5b): the `geo-catalog` body is the file `.geo_catalog` that the GeoIP conversion
(`go/pfb_core/geoip`) writes into each country-list generation, so the lists and the catalog are published together or not
at all. It is JSON Lines in byte order, one row per line:*

- *a `page` row per continent page: `{"kind": "page", "page": <continent_en>, "continent": <locale name>}`;*
- *a `country` row per entry of a page's lists: `{"kind": "country", "page", "family": 4 | 6, "position" (from 1), "iso",
  "country", "networks"}`;*
- *a `reputation` row per entry of the Reputation tab's IPv4 list: `{"kind": "reputation", "position", "iso", "country",
  "networks"}`.*

*The rows carry what `pfblockerng_get_countries()` writes into the `pfblockerng_<Continent>.php` pages and the Reputation
page today, as data rather than page source; the Outpost apply renders the pages from them (#4037). The tests read today's
pages back and compare their digests. The rows follow the page source: an ISO listed twice in a list (a country that is
also a Top Spammer, in the Reputation list) has two rows, and a renderer keys the options by `iso` as today's array literal
does, so the option keeps its first position and shows its last row. A name is JSON text: the conversion refuses a
localized Locations file with a row whose first six fields (the id, locale, continent code and name, ISO code and country
name) are not UTF-8, and a control character in a name is escaped, so every line is a valid resource member. The English
continent name only names the page, which needs a word. ASN choices come with slice 5c.*

*Amendment 2026-11-21 (issue #4034, slice 5c): the ASN choices are the ASN table, `pfblockerng_asn.txt`, which the ASN
conversion (`go/pfb_core/geoip`, `ASNTable`) writes from IPinfo's `asn.csv` as today's `pfblockerng.sh asn_table` does:
one `AS<number> [ <name> ]` line per AS number, in AS-number order, the first row of a number kept, and a name cut at
its first comma and stripped of its quotes, as today, read as the C locale reads it (bytes, no thousands separator). It
is published whole (a new file of mode 0644 written beside the live table, then renamed over it), so a failure keeps the
previous table, where today's shell truncates it first, keeping its mode and writing through a symbolic link. Its source
changes apart from MaxMind's, so it is not part of the country-list generation. How the `geo-catalog` resource carries
it, and in which order, is slice 9 (#4038).*

*Amendment 2026-11-21 (issue #4149, owner decision): the `reputation` rows leave out a country's proxy and satellite
lists (`A1_<ISO>`, `A2_<ISO>`), which today's PHP conversion never writes, so today's tab never offers them: the
Reputation stage compares an offender's plain ISO code with the country list, now entry by entry rather than as a
substring, so such an entry could never match. The plain `A1` and `A2` entries stay, as today.*

*Amendment 2026-11-23 (issue #4036, slice 7a): `dnsbl/<scope>` is five kinds of resource, written by `go/pfb_core/dnsbl`
(`Publish`): `dnsbl/feed-<feed>` per feed (plain text: the rows a `.raw` file holds, a domain or a verbatim ABP rule each),
`dnsbl/top1m` (plain text), `dnsbl/safesearch` and `dnsbl/psl` (JSON Lines), and `dnsbl/manifest` (JSON Lines), published
last: its rows carry the config, the whitelist, unlock and TLD entries, and one row per feed and per other body naming that
body's generation and digest. A body can move on before a client fetches it (the store keeps only the current and the
applied generation); the client then keeps its set and retries at its next poll. The per-group counts are the manifest's metadata. The generation
of `dnsbl/manifest` is the `dnsbl.generation` of the apply request (8.1). A feed's rows are a sorted set (owner,
2026-11-23): its irreducible regex rules are numbered and scanned in byte order, a row repeated in one feed is counted once,
and of two ABP rules of one feed on the same key the later in byte order wins. A row the store cannot hold is left out and
counted. The rows and the departures: `docs/misc/core-api-protocol.md` "DNSBL resources",
`tests/core/fixtures/dnsbl_resources_parity.json`.*

- **Canonical body:** members sorted and unique in byte order, one per line, the order `pfb_canonical_alias_set` produces
  (`pfb.inc:14880`; `docs/misc/architecture-notes.md:1194-1197`). `digest` is the xxh128 of that body.
- **Generation:** a `uint64` per resource, written as a decimal string on the wire, as `GetUpdate`'s cursor is
  (`protocol.md:386-388`). It advances only when the canonical body or the metadata changes. An unchanged rebuild publishes
  nothing.
- **Store:** a directory named by a new flag, written only by the Core Updater (temporary file, sync, rename, then the index), read
  by the Core API. It holds data and caches, never settings.
- **Retention:** per resource the store keeps the **current** generation and the **applied baseline**, the generation its
  consumer last reported applied. Everything else is deleted at settle. With one co-located consumer that is at most two
  bodies per resource. A resource that left the configuration is kept until the consumer reports its removal applied.
- **Empty set:** a valid desired state with its own generation. The placeholder is an Outpost detail.

*Amendment 2026-11-24 (issue #4038, sub-slice 9k): "canonical IP/CIDR members" is one spelling per network, what Go's
`netip.Prefix.Masked()` prints: a bare address for a host, `address/length` without host bits for a prefix, the length in
canonical decimal (`/024` is published as `/24`). A row that is no address or prefix of the family is left out with an
issue, as is one the #1922 address guard refuses on the masked network: an IPv4 network whose first octet is 0, the IPv6
network `::`, and so any prefix length of 0. The guard is applied at publication (`go/pfb_core/update/apply/member.go`).
Core writes no placeholder: an empty set is published empty (owner, 2026-11-23).*

### 8. The apply contract

#### 8.1 Invocation

The Core Updater runs the program `--update-cmd` names (`pfb_core_update.sh`; the name stays) as its direct child, with stdin and
stdout as regular files and fd 3 as the durable result file, as today (`protocol.md:404-435`). No whole-apply cap and no group
kill.

stdin, one JSON object, protocol version 2:

```json
{
  "version": 2,
  "trigger": "scheduled|manual|apply|retry",
  "scope": "ip|dnsbl|both",
  "pendingToken": "<opaque, from the settings adapter>",
  "pendingOutsideWindow": false,
  "resources": [
    {"id": "ip-set/Abuse/ipv4", "generation": "42", "action": "deny", "direction": ["ingress", "egress"], "entries": 15234},
    {"id": "ip-aggregate/deny/ipv4", "generation": "17", "action": "alias_only", "entries": 90211},
    {"id": "geo-catalog", "generation": "3"}
  ],
  "removed": ["ip-set/Old/ipv4"],
  "dnsbl": {"generation": "88", "sinkholeRequired": true,
            "groups": [{"name": "Ads", "entries": 120344, "changed": true}]},
  "issues": [{"resource": "feed/ipv4:Foo_v4", "stage": "download", "code": "curl_incomplete", "message": "..."}]
}
```

*Amendment 2026-11-18 (issue #4053): `sinkholeRequired` in the example above is withdrawn; the `dnsbl` object carries
only `generation` and `groups`.*

The request names resources and generations. It carries no members.

#### 8.2 `GetResources`: deltas between generations

The Outpost apply pulls each body it needs from the Core API, one resource per call:

```json
{"resources": {"ip-set/Abuse/ipv4": {"generation": "41", "digest": "<digest of the applied body>"}}}
```

A resource without a cursor is `{}`. The reply, per resource, is one of:

| `kind` | When | Fields |
|---|---|---|
| `unchanged` | the cursor's generation is the current one and the digest matches | `generation` |
| `delta` | the store holds the cursor's generation with that digest | `generation`, `from`, `add`, `remove`, `digest` (of the new body), metadata |
| `full` | no cursor; the store does not hold the cursor's generation; the digest differs | `generation`, `members`, `digest`, metadata |

- `add` and `remove` are computed at request time by one merge pass over the two sorted bodies.

  *Amendment 2026-11-20 (issue #4049): members, `add` and `remove` leave the reply. The Core Updater writes the delta from
  the applied baseline when it publishes, by one streaming merge of the two sorted bodies, and prunes it with them. The
  reply describes a `full` body (`generation`, `digest`, `entries`, metadata) or a `delta` (adding `from`, `addEntries`,
  `removeEntries`), and the new `GetResourceBody` streams each part as plain text, one member per line, from disk
  (`docs/misc/core-api-protocol.md`, "GetResourceBody"); it is the protocol's first reply that is not JSON. The Outpost
  apply writes each part to a file with curl, checks the digest over the bytes, and hands the file to `pfctl -f`, never
  decoding members into a PHP array. Neither Core nor the Outpost holds a body in memory.*
- Fetching never advances a cursor.
- The digest in the cursor is what makes the fallback safe: a store that was lost and rebuilt, a mirror edited by hand, or a
  generation number reused after a loss all answer `full`.
- An unknown resource id is `not_found` for that resource; the apply treats it as removed.

#### 8.3 Mapping a delta onto the ADR-40 forward-delta path

The Outpost apply keeps one mirror per table, the alias file pfSense rebuilds the table from, as today
(`docs/misc/architecture-notes.md:1194-1197`). Its cursor file holds, per resource, the applied generation and the mirror's
digest.

1. **Patch the mirror:** new mirror = (old mirror minus `remove`) plus `add`, sorted, written by temporary file and rename.
   *Amendment 2026-11-20 (issue #4049): `add` and `remove` are the files `GetResourceBody` streamed; the patch is a merge
   of the three sorted files, line by line.*
2. **Verify:** the new mirror's digest must equal the reply's `digest`. A mismatch discards the patch, asks again without a
   cursor and applies the `full` body.
3. **Apply to pf**, with the mode the operator configured (`gen/pfb_alias_delta_mode`, `apply.inc:5286-5287`):
   - `delta`, or `auto` under the churn threshold: `pfctl -T add` then `-T delete` in batches, exactly the loop of
     `pfb_apply_alias_delta` (`pfb.inc:15086-15150`), fed with Core's `add` and `remove` instead of `array_diff`. The churn is
     `(|add| + |remove|) / max(entries, previous entries)` against the same 0.05 threshold
     (`docs/misc/architecture-notes.md:1205-1210`).
   - `replace`, or `auto` at or over the threshold: `pfctl -T replace -f <mirror>`.
   - Always replace from the mirror, whatever the mode, in the cases that force it today: an empty kernel table, a table the
     apply has no cursor for, the rule-change path where `filter_configure` rebuilds every table from the mirrors
     (`apply.inc:5214-5246`), and a forced re-block after a temporary unlock (`apply.inc:5262-5275`).
   - A `full` reply writes the mirror and replaces.
4. **Advance the cursor** only after the `pfctl` operations for that table succeeded.

The end-state invariant of ADR-40 holds: the table's membership equals the canonical desired set, whichever path ran.

#### 8.4 What the apply does and reports

The Outpost apply is today's `sync_package_pfblockerng` minus every fetch, parse, set calculation, script and hook: the rows
marked "Outpost apply" in Appendix A, plus filing the Core Updater's issues as notices and ADR-61 ledger entries, writing the DNSBL
statistics rows, and regenerating the country pages when `geo-catalog` moved.

fd 3, result lines as today, each one JSON object, written as each step finishes:

```json
{"version": 2, "applied": {"ip-set/Abuse/ipv4": "42"}, "changedAliases": ["pfB_Abuse_v4"]}
{"version": 2, "applied": {"geo-catalog": "3"}, "reloadLaunched": true, "ipChanged": true, "dnsblChanged": false,
 "failed": [{"id": "ip-set/Big/ipv4", "stage": "apply", "message": "pfctl: table limit"}]}
```

`changedAliases`, `ipChanged` and `dnsblChanged` are what the `post` hook's context needs (§5).

Exit status: 0 success; 75 deferred (the apply lock or a config lock is held, or the Core API did not answer
`GetResources`): the Update is `skipped`, nothing is settled, the work stays pending; anything else is failure, and complete
result lines still count (as #4002 established).

*Amendment 2026-11-24 (issue #4038, sub-slice 9k): a result line also carries `removed`, the removals applied, beside
`applied` (`{"version": 2, "applied": {"ip-set/Abuse/ipv4": "42"}, "removed": ["ip-set/Old/ipv4"], "changedAliases":
["pfB_Abuse_v4"]}`). The apply's fd 3 is a file of its own, `update.log.apply` beside the
Update log; the Core Updater's feed outcomes keep `update.log.result` in the version 1 shape (§8.1's "durable result
file" is that one). Exit status 2 means the apply refused the request and ran nothing: the Update fails and nothing is
settled. Core holds the apply to three rules of the whole file: an id is named on one result line only; `changedAliases`
names only aliases of ids the request holds; the file stays within 1 MiB, and when it is longer Core keeps the complete
lines inside the first 1 MiB and reports the rest as cut (`protocol.md` "Update command, version 2").*

#### 8.5 Failure and retry

| Failure | Result | Retry |
|---|---|---|
| A feed fails to fetch, a script fails, a parse is empty | The feed keeps last-known-good; an issue is raised; its outcome is not `success` | The schedule (the occurrence stays pending) and the feed's `.fail` state |
| An Extra fails | `attempted`; previous data kept | next quarter hour |
| The Core Updater dies before the apply | The Update is `failed`; published generations stay; no cursor moved | The next Update finds generation and cursor apart and applies |
| The apply defers (exit 75) | `skipped`; nothing settled | The tick asks the Core API for an `apply` Update (`extra.inc:6489-6505`) |
| The apply fails for one resource | That cursor stays; the others advance; exit 1 | The pending marker and ledger flag stay (`extra.inc:6859-6863`); the tick's `apply` Update and the ADR-61 reconcile retry |
| The Core API is down | No new Update; a running one continues, and its apply defers if it cannot fetch | The tick logs it and tries again |

#### 8.6 The pending token

The pending marker stays the Outpost's retry state. Its token must be taken before the settings are read (`apply.inc:1207`),
and the Outpost's settings adapter reads them. Its read reply gains one opaque field, which the Core Updater hands back unread
in the apply request:

```json
{"version": 1, "revision": 123, "settings": {...}, "platform": {"pendingToken": "..."}}
```

The apply settles exactly that token (`apply.inc:5617`), so a change marked while the Update ran stays pending.

### 9. DNSBL data

- pfB-DNS reads its inputs from the module directory today (`go/pfb_dns_gateway/decider/pfb_unbound.go:327-345`) and builds
  from the manifest and the raw feed files (`decider/pfb_unbound_build.go:522,1309-1355`). #3511 left the fate of that
  interface unspecified; the #3813 decision redefines it as a Core resource.
- The Core Updater publishes what the manifest holds today (`pfb.inc:18049-18067`: config, feeds, user unlock) with each feed's
  rows, the TOP1M whitelist, SafeSearch, and the PSL, TLD and HSTS reference lists. pfB-DNS keeps its `build()` and feeds it
  from fetched data. The build is not moved or redesigned.
  *Amendment 2026-11-18 (issue #4053, #4056): the HSTS preload list is removed; it only turned a VIP answer into a null
  answer. The reference lists are the PSL and TLD lists.*
  *Amendment 2026-11-23 (issue #4036): the TLD lists are page arrays, not a pfB-DNS input; pfB-DNS gets only the chosen
  TLDs, through `policy/dnsbl`. The PSL is the one reference list, published as `dnsbl/psl` (section 7).*
- The Outpost apply keeps the VIP, NAT, certificate and webserver from `sinkholeRequired`, with the hold-down while the
  previous generation still answers (`apply.inc:3350-3384,3730`), the Resolver move, and the re-lock of temporary unlocks.
  *Amendment 2026-11-17 (issue #4053): the WebServer/VIP response is removed, so there is no VIP, NAT, certificate,
  webserver or hold-down to keep; the Outpost apply keeps the Resolver move and the re-lock.*
- The reload sentinel, applied marker and fingerprint (`apply.inc:3626-3709`) go. pfB-DNS asks the Core API and reports the
  generation it serves; that report is the applied baseline of `dnsbl/*`.

### 10. Logs

The Update transcript is `update.log`, as today. The Core Updater also appends its lines to the package's main log, whose path
comes from a flag, because the log browser and `pfb_log_mgmt` work on that file; log maintenance already skips while an Update
runs (`extra.inc:6596-6598`).

### 11. Entry points

Every entry that runs a pass today starts an Update through the Core API (#3977, owner decision 2, still valid): the CLI
verbs `cron`, `update`, `updateip`, `updatednsbl`, `pfb_trigger`, `forcecheck` (`www.php:272-330`), the General save
(`www/pfblockerng/pfblockerng_general.php:309`), the TOP1M trigger (`www.php:532`), and the package resync
(`pkg/pfblockerng.xml:112`). `cron` stays as a deprecated verb. The resync after an install or upgrade passes `lifecycle` and
`pkgOp` (§5). Two Outpost paths run without an Update because they fetch and parse nothing: the boot branch
(`apply.inc:1397-1422`, which returns before any hook) and the uninstall disable pass (`pfb.inc:29189`); both call the apply
code under the apply lock. The uninstall disable pass fires its hooks through `pfb-core --run-hooks` (§5).

### 12. Defaults applied (the owner may override)

1. **Encoding of large bodies.** JSON, one resource per call, member lists as arrays. A measurement on a lab box is an
   acceptance item of the resource-store slice; a line-per-member body for member lists is the fallback if it fails.
   `dnsbl/*` follows the same rule.
2. **Sinkhole addresses.** A read-only box fact in a settings projection, as `selfAddresses` is; pfB-DNS gets it with
   `settings/dns`. The control socket stays for listeners, certificates and the Resolver move. *Amendment 2026-11-17
   (issue #4053): withdrawn; with the VIP response removed, every block answers `0.0.0.0` / `::` or NXDOMAIN/NODATA.*
3. **Alerts read the feed folders** the Core Updater writes, for IP-to-feed attribution, during the MVP. It is a recorded
   transitional coupling, replaced when Reports move.
4. **Software-update check** (`cron.inc:469`): Outpost, in the maintenance lane of #3996. It is a package-manager call, not a
   feed transfer.
5. **#4020's Kea hold** is overtaken: nothing kills the Update's process group any more
   (`docs/misc/external-process-waits.md:45-48`). One native lab run confirms it before the hold is closed.
6. **`.pfb_cron_disable`** reaches the Core Updater as a read-only field in `ingest`.
7. **GeoIP moves ahead of its place in the subsystem order** (it was step 6): once the Outpost stops sequencing, nothing
   else can build the continent sets.

### 13. Slices

| # | Slice | Depends on |
|---|---|---|
| 1 | Settings projections for the whole loop | none |
| 2 | Resource store and `GetResources` with deltas | none |
| 3 | Extras in Go (rewrites #3978) | 1 |
| 4 | IP set algebra in Go | none |
| 5 | GeoIP and ASN conversion in Go | 3 |
| 6 | Hook and script runner in Go, with the one-shot `--run-hooks` | 1, #4020 |
| 7 | DNSBL data in Core, pfB-DNS as a Core API client | 1, 2 |
| 8 | Outpost apply behind the contract | 2 |
| 9 | The Core Updater loop, not yet triggered | 1-7 |
| 10 | Cutover (rewrites #3977) | 8, 9 |

Slices 1 to 9 land on `devel` without changing what an Update does. Slices 3, 4, 6 and 8 can run in parallel. The tickets
are sub-issues of map #3813; their bodies are the task packets.

## Acceptance criteria

- WHEN a scheduled and a manual Update run on a lab box after the cutover THEN the transcript names each feed as fetched and
  parsed by the Core Updater, and the process table shows no PHP process between the settings read and the apply.
- WHEN a feed's server answers 304 THEN its sets are not rebuilt and no generation advances.
- WHEN a download fails THEN the previous data stays, the feed is marked failed, and its occurrence stays pending.
- WHEN the end-to-end parity corpus runs THEN the Core Updater's desired sets, DNSBL data, outcomes and issues equal the ones frozen
  from today's PHP Update, with one case each for: Extras first, DNSBLIP mid-loop, the work list under the lock, late pending
  work, a narrower scope.
- WHEN one member of a set changes THEN `GetResources` answers a `delta`, the apply patches the mirror, the digest matches, and
  `pfctl -T show` equals the canonical set.
- WHEN the cursor file is missing, the store was rebuilt, or the mirror was edited THEN `GetResources` answers `full` and the
  table ends equal to the canonical set.
- WHEN the Core API is stopped or killed during an Update THEN the Update finishes or defers, the apply is neither lost nor
  repeated, and a restarted Core API reports its result.
- WHEN a `pre` hook, a pre-script, a post-script and a `post` hook are configured THEN each runs once, at the point of §3, as a
  child of the Core Updater; a hook that is not a vetted file in the hook directory never runs.
- WHEN a `post` hook runs THEN every feed and file stage has ended, the Outpost apply has returned, the Update lock is still
  held, and `GetUpdate` still reports the Update running.
- WHEN `pfb-core --run-hooks pre` runs with the Core API stopped THEN the configured `pre` hooks run once with the given
  context, and no Update is admitted.
- WHEN the package is installed or upgraded THEN one Update runs and each hook fires once in it, with `PFB_POST_INSTALL=1`
  and the `PFB_PKG_OP` the Outpost passed.
- WHEN the apply lock is held THEN the apply exits 75, the Update is `skipped`, and no cursor or pending marker moves.
- WHEN the cutover lands THEN `git grep` finds no caller of the functions its ticket lists for removal, and pfB-DNS serves the
  generation the Core Updater published.
- Measured and recorded in the resource-store PR: time and peak PHP memory for a full body of 2,000,000 entries and for a 1 %
  delta of it.

## Out of scope

- Reports, Alerts and Stats (they stay in the Outpost for the MVP).
- HA sync (the map's step 6) and the maintenance lane (#3996); both follow the cutover.
- Remote or multi-Outpost deployment, and retention for more than one consumer per resource.
- A redesign of the DNSBL build, of the ADR-40 apply path, or of any set calculation.
- The Core WebUI and the PHP GUI.

## Open forks

None.

## Appendix A: today's Update, stage by stage

"After" names the process that does the step once the cutover lands. **Gone** means the step disappears with a file protocol or
with the PHP sequencing.

### A.1 Entry and sequencing

| Stage | Where | After |
|---|---|---|
| Schedule, admit, re-read the backend, start the worker | `protocol.md:331-352`; `go/pfb_core/update/worker.go:56-63,520-597` | Core API; the backend read moves to the Core Updater |
| Run `--update-cmd`: stdin request, stdout transcript, fd 3 result | `protocol.md:404-435`; `worker.go:599`; `go/pfb_core/update/gate.go:32-45` | Core Updater runs it once, at the end |
| Request validation | `extra.inc:6666-6712` | Outpost apply (validates the version 2 request) |
| `.pfb_cron_disable` skips a `scheduled` Update | `extra.inc:6744-6747` | Core Updater, from a fact the settings adapter reports |
| Dispatcher lock, then feed-pass lock | `extra.inc:6792-6831` | Gone; apply lock (§4) |
| Extras first: `dcc`, then `bl`, each a PHP re-entry | `extra.inc:6875-6909,6260-6272`; `pfb.inc:11021` | Core Updater |
| GeoIP readiness gate | `extra.inc:6910-6916,3605` | Gone |
| Apply window; pending when outside | `extra.inc:6918-6924`; `cron.inc:443-458` | Core Updater checks; Outpost apply keeps the marker |
| `apply` trigger: clear the flag, sync, restore on failure | `extra.inc:6835-6866` | Outpost apply |
| `manual` trigger: Run Now, forced parse, Force Check | `extra.inc:6792-6801` | Core Updater |

### A.2 Change detection (`pfblockerng_sync_cron`)

| Stage | Where | After |
|---|---|---|
| Force Check clears validators and hashes | `cron.inc:310-313`; `pfb.inc:26787` | Core Updater |
| Walk IPv4, IPv6, DNSBL groups in config order | `cron.inc:352-365` | Core Updater |
| Hold with a published list | `cron.inc:392-398` | Core Updater |
| `.fail` always re-checks | `cron.inc:409-414` | Core Updater |
| `pfb_update_check`: gates, retry cap, whois/asn/geoip/rsync rules, local hash, conditional GET, `.update` | `cron.inc:24-248` | Core Updater |
| An enabled continent forces a sync | `cron.inc:429-440` | Core Updater |
| Sync, pending, or `noupdates` | `cron.inc:446-463` | Core Updater |
| Software-update check | `cron.inc:469`; `pfb.inc:11995` | Outpost, #3996 lane |

### A.3 `sync_package_pfblockerng` (`apply.inc:1204-5642`)

| Stage | Where | After |
|---|---|---|
| Pending token before config is read | `apply.inc:1207` | The Outpost's settings adapter supplies it; Outpost apply settles it |
| `pfb_global()` | `apply.inc:1211`; `pfb.inc:4307` | Core Updater reads the backend; Outpost apply keeps its own |
| Stage/publish recovery | `apply.inc:1272`; `pfb.inc:10109` | Core Updater |
| HA receive-suppression flag | `apply.inc:1296` | Outpost apply |
| DNS listener VIPs under the DNS config lock | `apply.inc:1298-1322` | Outpost apply |
| DNSBL policy upgrade | `apply.inc:1329` | Outpost apply |
| Syslog routing registration | `apply.inc:1359-1394` | Outpost apply |
| Boot/install early return | `apply.inc:1397-1422` | Outpost, no Update |
| `pre` hook | `apply.inc:1454`; `pfb.inc:12645` | Core Updater |
| Run plan: reuse, forced reparse, masterfiles | `apply.inc:1456-1473,24` | Core Updater |
| Pass status start and end | `apply.inc:1477,5629` | Outpost apply |
| RAM-disk handling of alias tables and the DNSBL cache | `apply.inc:1491-1495,3694`; `pfb.inc:25646,25769` | Outpost apply; the pfB-DNS cache moves with pfB-DNS |
| Table entries limit | `apply.inc:1498-1502` | Outpost apply |
| Settings load | `apply.inc:1516-1588` | Core Updater (§6); Outpost apply for rule options |
| Tracker IDs, rule suffix, interfaces | `apply.inc:1608-1726` | Outpost apply |
| Removed-list cleanup | `apply.inc:1728-2085` | Core Updater |
| Disabled with Keep off: clear contents | `apply.inc:2087-2096`; `pfb.inc:28740` | Core Updater for its data; Outpost apply for pfSense objects |
| Suppression files | `apply.inc:2099-2104`; `pfb.inc:15274-15295` | Core Updater |
| Load DNSBL statistics | `apply.inc:2200`; `pfb.inc:391` | Outpost apply |
| Manifest-missing check | `apply.inc:2226` | Gone |
| SafeSearch table | `apply.inc:2238` | Core Updater |
| DNSBL whitelist | `apply.inc:2390` | Core Updater |
| TOP1M: download when stale, reprocess | `apply.inc:2428,61,623-667`; `pfb.inc:21010` | Core Updater |
| Blacklist categories and their databases | `apply.inc:2472,2553-2564` | Core Updater |
| DNSBL per feed: reuse, download, custom, normalize, pre-script, parse, post-script, IP side files, markers, ledger | `apply.inc:2586-3112` (download `2831`, normalize `2886`, pre `2908`, parse `2948`, post `2980-2992`, IP files `3001-3019`) | Core Updater |
| Group statistics, IDN, TLD Allow, Regex rows | `apply.inc:3130-3199`; `pfb.inc:15300` | Core Updater counts; Outpost apply writes the rows |
| DNSBLIP | `apply.inc:3209-3266`; `pfb.inc:2793-2850` | Core Updater |
| Manifest and raw files for pfB-DNS | `apply.inc:3273-3330`; `pfb.inc:17798-18067` | Gone: `dnsbl/*` |
| VIP, NAT, certificate, webserver | `apply.inc:3350-3384,3730` | Gone (issue #4053, 2026-11-17) |
| `pfb_unbound.ini`, Resolver integration | `apply.inc:3377-3380`; `pfb.inc:19714,15990` | Ini Gone (`settings/dns`); Resolver move Outpost apply |
| DNS redirect NAT, DoT/DoQ rules | `apply.inc:3401-3483,3499-3616` | Outpost apply |
| Reload sentinel, applied marker, re-lock, cache flush | `apply.inc:3626-3709`; `pfb.inc:20802-20940` | Handshake Gone; re-lock and flush Outpost apply |
| Ensure the DNS proxy runs | `apply.inc:3719` | Outpost apply |
| MaxMind download when missing | `apply.inc:3757-3777` | Core Updater |
| MaxMind and ASN credential notices | `apply.inc:3801-3804,4091-4106` | Core Updater raises the issue; Outpost apply files the notice |
| Continent sets | `apply.inc:3815-3925` | Core Updater |
| Continent rule template | `apply.inc:3956` | Outpost apply |
| IP group list with DNSBLIP | `apply.inc:3994-4022` | Core Updater |
| IP per feed: floors, scripts, reuse, ET, download, whois, custom, normalize, pre-script, parse, post-script, empty check | `apply.inc:4112-4485` (ET `4250-4274`, download `4280`, whois `4342`, normalize `4390`, pre `4406`, parse `4425`, post `4448-4462`) | Core Updater |
| Per-feed dedup, aggregation, reputation, snapshot | `apply.inc:4510-4534` | Core Updater |
| Cross-feed recompute, `pmax` | `apply.inc:4603-4675` | Core Updater |
| Suppression per alias | `apply.inc:4812-4849`; `extra.inc:7750` | Core Updater |
| Canonical set, compare with mirror and kernel, write mirror | `apply.inc:4868-4905`; `pfb.inc:14880,14904` | Core Updater builds the set; Outpost apply patches the mirror (§8.3) |
| Kill tables of removed aliases | `apply.inc:4753` | Outpost apply |
| Rule templates per alias | `apply.inc:4929`; `pfb.inc:25373` | Outpost apply |
| Uber aggregates | `apply.inc:4977`; `pfb.inc:14666` | Core Updater builds the union; Outpost apply registers it |
| Alias objects, rules, `write_config` | `apply.inc:4992-5010,5069-5169` | Outpost apply |
| `pfctl`: pre-sync, kill, delta or replace, forced re-block | `apply.inc:5214-5323` | Outpost apply |
| Save settings, NAT alias migration | `apply.inc:5341-5383` | Outpost apply |
| Filter reload, `pfb_filter` service | `apply.inc:5397-5438,1185-1201` | Outpost apply |
| Kill states | `apply.inc:5452-5453` | Outpost apply |
| XMLRPC sync | `apply.inc:5458-5462`; `pfb.inc:29370` | Outpost apply |
| Crontab entries | `apply.inc:5478-5516` | Gone with #3996 |
| Final reporting: `closing`, dedup ledger check | `apply.inc:5530-5538` | Core Updater |
| `post` hook | `apply.inc:5582` | Core Updater, after the Outpost apply, under the Update lock |
| Settle the pending marker, apply record, HA findings | `apply.inc:5605-5625` | Outpost apply |

## Appendix B: the #3977 branch (`origin/wip/issue/3977`, 38 commits)

Reusable:

- The per-feed pipeline, `go/pfb_core/feed_phase_pipeline.go` (782 lines): `runFeed` (hold, force, custom lists, whois, probe
  then ingest, ET reprocess), `parseAndPublish`, `parseIP`, `parseDNSBL`, staged publish with snapshot and restore of the
  baseline. It becomes the Core Updater's feed stage, without the API wrapper.
- Feed lookup from settings in `feed_phase.go`: `feedFor`, `blacklistFeedFor`, `fetcherFor`, `feedRequest`, and the id grammar
  for `custom:` and `synthetic:` DNSBLIP ids.
- Library fixes: `feedfetch` ET IQRisk reprocess, whois partial results, FTP probing, the unusable-proxy refusal;
  mapped-drop counts in `feedparse`; schedule provider titles; `settings/ingest` additions; the feed directory flags.
- Go tests for the above (about 3,500 lines), renamed away from the API entry.
- Smoke and Python tests about the Update itself: scheduled exception, due feed group, recovery oracle, disposition, capture,
  IP script order.
- The bypass-entry routing (`db1b9e068`, `e0aa9474c`, `bcbfe1458` and their tests) and the removal list of the PHP fetch and
  parse paths (`98b71c92b`), as the starting point of the cutover's deletions.

Obsolete:

- The `FeedPhase` API method, its validation and its 4-hour timeout (`feed_phase.go`, `update_api.go`).
- The per-Update token: `update/gate.go` `WithFeedPhase` and `activeToken`, `update/token_test.go`, `FeedPhaseTokenTest.php`.
- The PHP client and call sites `pfb_core_feed_phase*`, with `FeedPhaseClientTest`, `FeedPhaseCallSitesTest`,
  `FeedPhaseArtifactTest`.
- The PHP loops rewritten to consume `FeedPhase` results. The cutover deletes those loops.
- The protocol and architecture text describing `FeedPhase`.

The branch conflicts with `devel` in six files, all around the Core Updater code #4025 rewrote. Carry files over by path; do not rebase
the 38 commits.
