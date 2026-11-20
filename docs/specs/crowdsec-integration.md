# CrowdSec integration (pfb_crowdsec bouncer)

Issue: [#1585](https://github.com/pfBlockerNG/pfBlockerNG/issues/1585) · map
[#1577](https://github.com/pfBlockerNG/pfBlockerNG/issues/1577) · implementation
[#4068](https://github.com/pfBlockerNG/pfBlockerNG/issues/4068)

## Goal

An operator who runs a CrowdSec Security Engine elsewhere can have pfSense drop the
addresses that engine bans, on every interface and in both directions, without installing
the CrowdSec package. pfBlockerNG gains a **CrowdSec** tab and `pfb_crowdsec`, a small Go
daemon whose only job is to be a CrowdSec firewall bouncer: it polls the engine's Local API
(LAPI) every 10 s and keeps two PF tables equal to the engine's active bans. pfBlockerNG
generates the rules that use those tables, runs the daemon as a service, shows its status
and exports its metrics.

The daemon's behaviour is modelled on the official firewall bouncer's pf mode
(`crowdsecurity/cs-firewall-bouncer`), without what that bouncer carries for other
platforms and for CrowdSec's generated API client.

pfSense's own logs reach the remote engine through pfSense's built-in remote syslog. The
engine does all parsing and decides; pfSense only enforces.

## Fixed constraints

- **Our own daemon, standard library only.** `pfb_crowdsec` lives in `go/pfb_crowdsec/`,
  a Go module whose `go.mod` has no `require` lines: no third-party modules and no
  `golang.org/x`. It is built by the same builder and go recipe route as `pfb-core`
  (`docs/build-pkg-portable.md`): CGO off, `-trimpath`, `GOTOOLCHAIN=local`, one binary per
  machine (`freebsd-amd64`, `freebsd-arm64`), installed as
  `/usr/local/pkg/pfblockerng/crowdsec/bin/<machine>/pfb_crowdsec`.
- **Licensing.** The daemon is pfBlockerNG code under Apache-2.0. Upstream's bouncer is MIT,
  so chunks of it may be adapted; any source file that does keeps upstream's copyright and
  MIT notice at its top, and the package then ships upstream's `LICENSE` beside the binary.
  `crowdsecurity/pfSense-pkg-crowdsec` carries no licence, so none of its PHP is copied; only
  its approach (the settings it offers and the rule shape) is reused.
- **Part of pfBlockerNG, not a feed.** The bouncer runs only while pfBlockerNG's master
  enable and the CrowdSec enable are both on. It never goes through the feed or Update
  pipeline, and `pfb-core` neither runs nor watches it.
- **Nothing in `config.xml` but settings.** No aliases and no rules are stored, and the
  banned addresses exist only in the daemon's memory and the PF tables. The only `config.xml`
  side effect of the rule hook is pfSense core's own
  `installedpackages/package/<n>/filter_rule_function` registration, which
  `pkg-utils.inc` writes at install from `<filter_rules_needed>`.
- Settings fields go through `PfbConfig` (`docs/misc/config-gateway.md`).
- Appliance code outside the daemon is PHP and POSIX sh only.

## Decisions

### D1. The daemon

**Invocation.** `pfb_crowdsec -c <config>` runs it; `pfb_crowdsec -t -c <config>` validates
the config and exits; `pfb_crowdsec -version` prints the version.

**Config.** A JSON file (D3) with `api_url`, `api_key`, `update_frequency` (default and
minimum `10s`), `table_v4`, `table_v6`, `log_level` and `status_file`. Unknown keys are
an error.

**Start-up.**

1. Validate the config and check that `/sbin/pfctl` and `/dev/pf` exist.
2. Create both tables if missing with `pfctl -t <table> -T add -f /dev/null` (pfctl creates
   a persistent, empty table; see the #4070 amendment), then flush both.
3. Pull the full decision set with `GET /v1/decisions/stream?startup=true`. Until that
   succeeds, retry every `update_frequency`, log each failure, and leave the tables empty.

**Loop.** Every `update_frequency`, `GET /v1/decisions/stream` (without `startup`) and apply
its `deleted` list, then its `new` list:

- Only decisions of type `ban` with scope `ip` or `range` (case-insensitive) are used. Each
  value is parsed with `net/netip` as an address or prefix; anything else is logged once
  per pull and skipped. A value goes to `table_v4` or `table_v6` by family.
- The daemon keeps, per value, the set of decision IDs that ban it. A value is added to its
  table when its first decision arrives, and deleted when its last decision is deleted.
  Expiry needs no local timer: the LAPI reports expired decisions as deleted.
- Adds and deletes are batched: one `pfctl -t <table> -T add|delete -f <file>` per table
  per pull, from a mode-`0600` temp file holding one validated address per line. Values
  never reach a shell; pfctl runs with an argument vector.
- For newly added single addresses only, states are killed as upstream does: the daemon
  reads `pfctl -s states` once per pull and, for each new address found there, runs
  `pfctl -k <addr>` and `pfctl -k 0.0.0.0/0 -k <addr>` (`::/0` for IPv6).
- A failed pull keeps the tables as they are and is retried on the next tick. Enforcement
  continues on the last known set while the LAPI is unreachable. The retry is a full pull
  (#4077 amendment).

**Reconcile.** After every pull, and immediately on `SIGUSR1`, the daemon reads
`pfctl -vvs Tables` once. If a table is missing, it re-creates it as at start-up. If a
table is missing or its address count differs from the in-memory set, it replaces the table's
contents with `pfctl -t <table> -T replace -f <file>`. This is how the tables come back
after a filter reload, which kills them (#4070 amendment; D5).

**Shutdown.** `SIGTERM` or `SIGINT` flushes both tables and exits 0. A stopped bouncer
enforces nothing (fail-open), as with the official bouncer.

**LAPI client.** One `net/http` client with keep-alive and a 30 s timeout per request.
Requests send `X-Api-Key` and `User-Agent: pfb_crowdsec/<version>`. TLS uses the system
trust store. Response bodies are capped at 256 MiB, and a body that is not valid JSON fails
the pull.

**Usage metrics.** Every 15 minutes (go-cs-bouncer's default), the daemon posts to
`POST /v1/usage-metrics` a `remediation_components` entry of type `pfb_crowdsec` with its
version, start time, the window, and per window:

- `dropped` packets and bytes per `ip_type`;
- `active_decisions` per `origin` and `ip_type`.

These follow the official bouncer's metric names and units. A failed post is logged and
dropped.

**Counters.** Each pull, the daemon reads `pfctl -v -s rules` and takes the packet and byte
counters of the inbound rule for each table. It finds them the way upstream does, matching
`^block .* from <table> .* label "`.

**Status file.** After each pull, the daemon writes `status_file` atomically (temp file and
`rename()`, mode `0644`, no secrets) as JSON with:

- version and start time;
- time of the last successful pull, and time and text of the last error;
- LAPI request and error counts since start;
- banned values per family and per origin;
- dropped packets and bytes per family.

**Logging.** Plain lines on stdout, `level=<lvl> msg=<text>`, filtered by `log_level`. The
service sends them to syslog (D4).

**Left out on purpose.** Everything the official bouncer carries that pf mode on pfSense
does not need:

- the Prometheus listener;
- systemd notification;
- host and OS probing;
- log-file rotation;
- YAML;
- the iptables, nftables and ipset backends;
- the generated API client and JWT machine login;
- TLS client certificates;
- anchors;
- decision types other than `ban`.

### D2. Settings

A new **CrowdSec** tab in pfBlockerNG has two subtabs: **Settings**
(`/pfblockerng/pfblockerng_crowdsec.php`) and **Status**
(`/pfblockerng/pfblockerng_crowdsec_status.php`, D7). The fields mirror the
firewall-bouncer part of the official package and live in a new `PFB_SECTIONS` alias
`crowdsec` (`installedpackages/pfblockerngcrowdsec/config/0`).

| Key | UI | Default | Sync | Validation |
| --- | --- | --- | --- | --- |
| `crowdsec/enable` | Enable checkbox | off | policy | — |
| `crowdsec/lapi_url` | Remote LAPI URL | empty | policy | `http://` or `https://` URL with a host; required when enabled |
| `crowdsec/api_key` | Bouncer API key (password field) | empty | **local** | 1–256 printable ASCII, no whitespace; required when enabled |
| `crowdsec/log_level` | Log level select | `info` | local | `debug`, `info`, `warning`, `error` |
| `crowdsec/rules_all_interfaces` | Apply to all interfaces | on | local | — |
| `crowdsec/rules_interfaces` | Interface selection (multi) | empty | local | each a configured interface; at least one when "all" is off |
| `crowdsec/rules_log` | Log blocked packets | off | policy | — |
| `crowdsec/rules_tag` | Tag | empty | policy | empty, or `[A-Za-z0-9_-]{1,63}` |
| `crowdsec/rule_v4` | Enable the IPv4 rules | on | policy | — |
| `crowdsec/rule_v6` | Enable the IPv6 rules | on | policy | — |

- Sync classes follow `docs/specs/xmlrpc-per-field-sync.md`'s rule: the key is a
  credential, the interfaces are interfaces and the log level is a log setting, so they are
  `local`; the rest is `policy`. `pfblockerngcrowdsec` joins the synced sections in
  allowlist mode. Each node registers its own bouncer on the engine, so the key never leaves
  the node. A peer that receives
  `enable` without having its own key shows that on its Status subtab and does not start the
  bouncer.
- The page tells the operator to register the bouncer with `cscli bouncers add <name>` and
  paste the key, as the official package does.
- The key is never echoed back into the form, logged, or shown on any page. An empty key
  field on save keeps the stored key.

### D3. Config file

- `/usr/local/etc/pfb_crowdsec.json`, owner root, mode `0600`, outside the `/var` RAM disk.
  It is written atomically (temp file in the same directory, `chmod 0600` before the key is
  written, `rename()`), and removed when the bouncer is off.
- Values: `api_url`, `api_key` and `log_level` from D2, `update_frequency` `10s`,
  `table_v4` `crowdsec_v4`, `table_v6` `crowdsec_v6`, and `status_file`
  `/var/run/pfb_crowdsec.json`.
- The table names contain neither each other nor the official package's
  `crowdsec_blacklists`/`crowdsec6_blacklists`. They are outside the `pfB_` prefix that
  pfBlockerNG's table cleanup matches (`grep '^pfB_'`, case-sensitive).

### D4. Service

- New `<service>` entry `pfb_crowdsec` ("pfBlockerNG CrowdSec bouncer"), rc file
  `/usr/local/etc/rc.d/pfb_crowdsec.sh`, status `isvalidpid('/var/run/pfb_crowdsec.pid')`.
- The rc script is generated with `write_rcfile()` the way `pfb_core_service()` generates
  Core's. It picks this machine's binary by `uname -p`, and runs it under daemon(8) with
  restart on exit (`-r -R 5`), supervisor and child pidfiles, std fds detached, and output
  to syslog (`-S -l daemon -T pfb_crowdsec`). With no binary for this machine it logs and
  starts nothing. Stop sends TERM, and KILL after 5 s.
- **Should run** = pfBlockerNG master enable on, `crowdsec/enable` on, and a stored key.
  - The Settings subtab's save writes the config file and applies at once: start, restart
    when the file changed, or stop. It reloads the filter when the enable or any rule
    setting changed.
  - pfBlockerNG's sync pass (master enable changes, XMLRPC receive, install and upgrade)
    applies the same "should run" decision, so turning pfBlockerNG off stops the bouncer
    and removes its rules.
  - The daemon creates its own tables (D1), so there is no ordering to get right between
    the filter reload and the start.
- Deinstall stops the service and removes the rc file, the binaries, the config file and
  the status file.

### D5. Firewall rules

- `pfblockerng.xml` gains
  `<filter_rules_needed>pfb_crowdsec_rules</filter_rules_needed>`. pfSense calls it for
  each rule type; it returns rules only for `pfearly`, and only while the bouncer should
  run (D4).
- For each enabled family, two rules in the official package's shape. The daemon's counter
  parser relies on the inbound rule's shape:

```text
block drop in  {log} quick {on {ifaces}} inet  from <crowdsec_v4> to any label "CrowdSec IPv4" {tag tag}
block drop out {log} quick {on {ifaces}} inet  from any to <crowdsec_v4> label "CrowdSec IPv4 out" {tag tag}
block drop in  {log} quick {on {ifaces}} inet6 from <crowdsec_v6> to any label "CrowdSec IPv6" {tag tag}
block drop out {log} quick {on {ifaces}} inet6 from any to <crowdsec_v6> label "CrowdSec IPv6 out" {tag tag}
```

- `{ifaces}` are the real interface names from `get_real_interface()`, and are omitted
  when "all interfaces" is on. `{log}` and `{tag}` appear only when set.
- The tables are never declared with `table <…>` in the ruleset.
- **Filter reloads.** pfSense kills both tables after every filter reload (#4070
  amendment). When `pfb_crowdsec_rules('pfearly')` returns rules, it also registers a
  shutdown function that sends `SIGUSR1` to the daemon's pid (from
  `/var/run/pfb_crowdsec.pid`, checked with `isvalidpid()`). The shutdown function runs
  after the kill, and the daemon re-creates and refills both tables at once (D1 Reconcile).
  If the signal is missed, the next pull's reconcile restores them within
  `update_frequency`. pfBlockerNG keeps no copy of the addresses.
- A reboot needs nothing: the daemon pulls the full decision set at start-up.

### D6. Logs, telemetry and metrics

- The daemon's log goes to syslog under the tag `pfb_crowdsec` (D4), so it lands in the
  system log and goes wherever the operator's remote syslog sends it.
- pfSense's own logs (filter, pfBlockerNG, HAProxy, nginx) reach the remote engine through
  **Status > System Logs > Settings > Remote Logging**. pfBlockerNG configures none of
  this, and the Settings subtab says so in one line.
- **node_exporter.** pfBlockerNG's metrics export (`docs/specs/metrics-export.md`) gains a
  `crowdsec` source. While the bouncer should run, `pfb_metrics_write()` reads
  `/var/run/pfb_crowdsec.json` and writes these families into `pfblockerng.prom`:
  - `fw_bouncer_dropped_packets`, `fw_bouncer_dropped_bytes` (per `ip_type`) and
    `fw_bouncer_banned_ips` (per `origin` and `ip_type`), under the official bouncer's names
    so its dashboards work;
  - `pfblockerng_crowdsec_lapi_requests_total`, `pfblockerng_crowdsec_lapi_errors_total`,
    `pfblockerng_crowdsec_last_pull_timestamp_seconds` and
    `pfblockerng_crowdsec_last_error_timestamp_seconds`.

  The source reports `source_up 0`, with the rest of the file intact, when the service is
  not running or the status file is missing, unreadable, or more than
  `3 × update_frequency` old. With the bouncer off, the source is absent.
- **LAPI usage metrics** are pushed by the daemon itself (D1).

### D7. Status subtab

The bouncer-only subset of the official package's status page:

- **Service:** running or stopped, or why it does not run (pfBlockerNG off, CrowdSec off,
  no key on this node).
- **LAPI:** the LAPI URL (never the key), the last successful pull, the last error with
  its time, and the request and error counts.
- **Decisions:** banned values per family and per origin, and the contents of each table
  from `pfctl -T show`, paged 100 per page.
- **Lookup:** one address field. The server queries `GET /v1/decisions?ip=<addr>` with the
  bouncer key and shows each matching decision's value, scope, origin, scenario, type and
  expiry. The address is validated as an IP before the request, which has a 5 s timeout.
- **Counters:** dropped packets and bytes per family.
- **Log:** the last 50 system log lines tagged `pfb_crowdsec`.

Everything except the table contents, the lookup and the log comes from the status file.
Everything is read on page load; there is no control socket and no write action. The
engine-side views (log processors, remediation components, alerts, hub, deleting
decisions) stay on the remote engine.

## Acceptance criteria

1. With the bouncer enabled and a reachable LAPI, the service runs, both tables exist,
   and a ban added on the engine is in the matching table within 20 s. Removing it on the
   engine removes it from the table within 20 s. A value banned by two decisions stays
   until both are removed.
2. Traffic from and to a banned address is dropped on the selected interfaces only, and
   the rules carry the configured log and tag options. An established connection from a
   newly banned address is cut.
3. The config file exists with mode `0600` and the D3 values, and is absent with the
   bouncer off. The key appears in no log, page, status file, metrics file or sync payload.
4. After a filter reload (Status > Filter Reload and `/etc/rc.filter_configure_sync`), both
   tables hold the full set again within 2 s. With the signal suppressed, they are back by
   the next pull.
5. Enabling the bouncer on a box that has never had it starts it on the first try.
6. Stopping the service empties both tables. Turning the bouncer off, or pfBlockerNG's
   master enable off, also removes the rules and the config file and stops the process.
7. A reboot brings the service back with the full decision set and no manual step.
8. With the LAPI unreachable, the tables keep their contents, errors are logged and shown,
   and pulls resume when it returns.
9. Nothing listens on a TCP or UDP port for the bouncer (`sockstat -l`).
10. `go/pfb_crowdsec/go.mod` has no `require` lines, and the binary's `go version -m`
    lists no dependencies.
11. `pfblockerng.prom` carries the D6 families, with `source_up 1` while the bouncer
    runs, and `source_up 0` (other sources intact) when it is stopped or its status file is
    stale.
12. The LAPI receives usage metrics from the bouncer (visible with `cscli metrics`).
13. The Status subtab shows every D7 item, and the lookup of a banned address shows its
    decision.
14. XMLRPC sync carries exactly the D2 fields marked `policy`, never the key. No address,
    table or rule is synced.
15. Deinstall leaves no rc file, binary, config file, status file or table contents behind.

## Tests

Red-before-green per `.agents/policy/testing.md`:

- Go unit tests, with a fake pfctl runner and an `httptest` LAPI:
  - stream parsing, including hostile input: malformed JSON, oversized bodies, bad and
    mixed-family values, unknown scopes and types, duplicate IDs;
  - per-value reference counting;
  - batching, and the files passed to pfctl;
  - state kills limited to new single addresses found in the states list;
  - reconcile on a missing table, on a short table, and on `SIGUSR1`;
  - start-up retry, shutdown flush, and a failed pull leaving the tables alone;
  - the status file's content and atomic write;
  - the usage-metrics payload against the LAPI schema;
  - log-level filtering;
  - the key never written to logs or the status file.
- PHPUnit:
  - registry entries, sync classes and validation of every D2 field, with hostile values
    for the URL, key, tag and interfaces;
  - config file rendering and its atomic `0600` write;
  - rule text for every combination of families, interfaces, log and tag, and no output
    for other rule types or when the bouncer should not run;
  - the shutdown-function signal;
  - the generated rc script;
  - the "should run" decision on save and in the sync pass;
  - the metrics source, including the stale and missing status-file cases.
- UI tier: both subtabs. Fields and validation messages, the key never rendered, every
  "does not run" reason, and the status sections against a fixture status file and a stub
  LAPI answer.
- Smoke (VM): the built daemon against a stub LAPI in the smoke harness, serving
  `/v1/decisions/stream`, `/v1/decisions` and `/v1/usage-metrics` and able to add and remove
  decisions. It covers criteria 1, 3–9, 11, 12 and 15.

## Out of scope

- Shipping any CrowdSec binary: the Security Engine, log processor, LAPI, parsers,
  scenarios, hub, or the official bouncer.
- Routing decisions through the feed or Update pipeline, or through `pfb-core`.
- CrowdSec change hooks, and a HAProxy, AppSec or captcha bouncer of pfBlockerNG's own
  (HAProxy uses the official SPOA bouncer).
- Decision types other than `ban` (captcha, throttle), and TLS client certificates.
- Migrating settings or state from the official CrowdSec package.
- Configuring pfSense remote syslog.
- CARP-aware behaviour; each node runs its own bouncer with its own key.
- Separate resource or response-time budgets.

## Open forks

None.

## Amendment 2026-11-19 — criteria 4 and 5 verified on pfSense CE (#4070)

Run on pfSense CE 2.8.1 with the upstream cs-firewall-bouncer v0.0.38 FreeBSD binary, the
four D4 rules injected at `pfearly` through a package `filter_rule_function`, and a stub LAPI.
Commands and output: [#4070 evidence](https://github.com/pfBlockerNG/pfBlockerNG/issues/4070#issuecomment-7002188805).

- **D3's table creation is needed.** Tables that only the rules reference are not listed by
  `pfctl -s Tables`, and the bouncer exits with `pf init failed: table crowdsec_v4 doesn't
  exist`. `pfctl -t <table> -T add -f /dev/null` creates each table (persistent, empty, and
  idempotent on a second run), and the bouncer then starts and fills them. The rc script's
  start runs it for both tables on every start, not only on the first enable.
- **D4's save-and-restore is needed.** A filter reload does not empty the tables; it removes
  them. pf's own ruleset load keeps them, but after the load `filter_configure_sync()` runs
  `pfctl -t <name> -T kill` on every table in `pfctl -sT` that is not a configured alias, a
  captive portal alias or a `get_pf_reserved()` name. That happens on both
  `/etc/rc.filter_configure_sync` and Status > Filter Reload (`filter_configure()`), and pfSense
  has no hook that adds a name to the list. A prototype of D4's save-and-restore kept both
  tables' contents on both paths: the shutdown function runs after the kill, in the CLI process
  and in the php-fpm worker that serves `check_reload_status`. The restore must first re-create
  each table with `pfctl -t <table> -T add -f /dev/null`, also when the saved list is empty,
  and then feed the saved addresses through `xargs`.
- pfSense Plus was not tested: the smoke pool has no Plus VM identity outside CI secrets. The
  kill comes from pfSense core's `filter.inc`, so Plus is expected to behave the same, but
  this is unverified until it runs on a Plus box.

## Amendment 2026-11-19 — own daemon instead of the official bouncer

The owner replaced the packaged official bouncer with `pfb_crowdsec`, pfBlockerNG's own
standard-library daemon. The official bouncer pulls in CrowdSec's generated API client and
about 40 modules that pf mode does not use. The bouncer also moved into pfBlockerNG as the
CrowdSec tab, and runs only while pfBlockerNG is enabled. The previous amendment's findings
still hold and are met differently. That amendment uses the earlier numbering: its D3
(service) and D4 (rules) correspond to this version's D4 and D5.

- the daemon creates its own tables at start-up and on every reconcile (D1), instead of the
  rc script;
- after a filter reload, the rule hook signals the daemon, which refills the tables from
  memory (D5), instead of pfBlockerNG saving and restoring them.

## Amendment 2026-11-19 — a failed delta pull is followed by a full pull (#4077)

The owner amended D1's "A failed pull keeps the tables as they are and is retried on the
next tick" ([#4077](https://github.com/pfBlockerNG/pfBlockerNG/issues/4077)). The LAPI moves
a bouncer's stream cursor as soon as it has written a `/v1/decisions/stream` reply. A delta
the daemon then fails to use (body over the cap, invalid JSON, or a timeout while reading it)
is lost, and a retried delta would only ask for the changes after it. A missed delete would
stay banned and a missed ban would stay missing until the next restart.

- A failed pull still changes nothing in pf. Enforcement continues on the last known set
  while pulls fail.
- After any failed pull, the next pull asks for `startup=true` again, and keeps doing so
  until one succeeds.
- A successful `startup=true` reply replaces the daemon's whole in-memory set. Both tables
  are then replaced with `pfctl -t <table> -T replace -f <file>`, and states are killed for
  the single addresses that were not banned before, as for a delta. The start-up pull takes
  the same path, which is the same as adding to the empty tables.
- The pull after a successful full pull is a delta again.

## Amendment 2026-11-19 — the pidfiles and the tab (#4071)

- **Pidfiles.** daemon(8) does not handle `SIGUSR1`, so the signal kills its supervisor (#4069 verification). The rc
  script therefore writes the bouncer's own pid (`daemon -p`) to `/var/run/pfb_crowdsec.pid`, the file D4's service
  status and D5's shutdown function read, and the supervisor's (`daemon -P`) to `/var/run/pfb_crowdsec_daemon.pid`.
  Stop sends TERM to the supervisor, which passes it on to the bouncer.
- **Start condition.** The config file exists exactly while the bouncer should run, so the rc script's start, the boot
  start included, starts nothing without it.
- **Tab.** The CrowdSec tab follows Sync on every top row. Its second row holds Settings, and Status joins it with D7.

## Amendment 2026-11-19 — the rule hook registers itself (#4072)

- **Registration.** pfSense's `install_package_xml()` sets `filter_rule_function` from `<filter_rules_needed>` in memory
  only, and then runs the package's install command. That command's `pfb_global()` re-reads `config.xml`, which drops the
  unsaved registration, so pfSense CE 2.8.1 showed an empty `filter_rule_function` after `pkg add` of the package. The
  update pass, which also runs as the install's resync, therefore writes the same registration itself when it is missing
  (`pfb_crowdsec_register_rule_hook()`), as it already does for the package's `<logging>` block. It is still the only
  `config.xml` side effect of the hook. A registration it writes while the bouncer should run reloads the filter at once,
  since an install or upgrade, and a pass that ends early, never reach the pass's own reload.
- **Tag.** The tag is written quoted (`tag "<tag>"`), as pfSense writes its own rules' tags. Unquoted, pf reads a tag the
  Settings accept, such as `123` or `quick`, as a number or a keyword, and pfSense then drops every CrowdSec rule.
- **Should run in a filter reload.** pfSense calls the hook without loading pfBlockerNG's globals, so "should run" (D4)
  reads the stored master enable when `pfb_global()` has not run in that process.
- **Interfaces per family.** `{ifaces}` is resolved per family (`get_real_interface($name, 'inet6')` for the IPv6 rules), so
  a 6rd or 6to4 WAN gets its IPv6 rules on `<name>_stf`. A family with no selected interface left gets no rules.
- **Signal.** The shutdown function sends `SIGUSR1` with `pkill -F <pidfile> -f <the bouncer's command line>` once
  `isvalidpid()` confirms the pid, so a stale pidfile that names a reused pid signals nothing.

## Amendment 2026-11-19 — the Status subtab and the metrics source (#4073)

- **Staleness.** The status file carries `updated_at` and `update_frequency_seconds`, so D6's "more than
  `3 × update_frequency` old" uses the daemon's own frequency. "Running" is a live process in
  `/var/run/pfb_crowdsec.pid`, the service status D4 uses. A status file written more than one interval in the
  future also counts as stale. Without this rule, a file written before the clock stepped back would stay fresh
  however old it got.
- **Shape.** The page and the metrics source read the status file only after checking every field: counts are
  integers from 0 up to PHP's integer maximum, the update frequency is positive, and both families are present in
  `banned` and `dropped`. Anything else, or a file over 1 MiB, reads as unreadable, so the source reports
  `source_up 0` and the page shows no status.
- **Families.** The `fw_bouncer_*` families are gauges, as in the official bouncer, with an `ip_type` of `ipv4` or
  `ipv6`. `fw_bouncer_banned_ips` has one series per origin. The two `_total` families are counters.
- **Lookup.** The key travels only in the `X-Api-Key` header. Redirects are not followed, because a redirect would
  send the key to another host. The stored URL and key are checked again as the Settings check them before any
  request, because a synced or hand-edited value could otherwise reach curl unchecked. An answer over 1 MiB fails the
  lookup. The LAPI answers `null` when no decision
  matches, and the page shows that as "No decision".
- **Log.** The page reads the last 1 MiB of `/var/log/system.log` and keeps the lines whose program is
  `pfb_crowdsec`, in either the BSD or the RFC 5424 log format. It drops the partial line where that window
  starts.

## Amendment 2026-11-20 — two starts at once leave one bouncer (#4123)

At boot pfSense CE 2.8.1 runs two starts of the rc script in the same second: `rc.start_packages`' service start and
pfBlockerNG's own update pass (`sync_package`, which applies D4's "should run" decision). Both found no supervisor in its
pidfile. The start then ran the stop, whose last step removed both pidfiles, and one start's removal landed after the
other's daemon(8) had locked them. daemon(8)'s lock no longer protected an unlinked file, so both launched, the pidfiles
named one pair, and the service's stop left the other running (2 of 3 reboots on the smoke pool).

- **Start.** A daemon(8) that finds the pidfiles locked (exit status 3, "already running") is not a failure: the start
  waits for the running supervisor in its pidfile, as for its own, and fails only if none appears within 5 s.
- **Stop.** TERM, the wait and KILL find the supervisors and bouncers by command line alone, not by pidfile, so every
  bouncer stops, including a pair no pidfile names. A reused pid still never matches.
- **Pidfiles.** daemon(8) removes its own pidfiles when it exits. The stop removes the ones a KILL left with
  `lockf -s -n -t 0 <pidfile> /usr/bin/true`, which removes a file only while no daemon(8) holds it locked. A
  concurrent start's daemon(8) therefore keeps its lock, and the second daemon(8) cannot launch.
