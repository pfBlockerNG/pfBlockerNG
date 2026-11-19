# CrowdSec integration (packaged firewall bouncer)

Issue: [#1585](https://github.com/pfBlockerNG/pfBlockerNG/issues/1585) · map
[#1577](https://github.com/pfBlockerNG/pfBlockerNG/issues/1577)

## Goal

An operator who runs a CrowdSec Security Engine elsewhere can have pfSense drop the
addresses that engine bans, on every interface and in both directions, without installing
the CrowdSec package. The pfBlockerNG package ships the official CrowdSec firewall bouncer
(`cs-firewall-bouncer`, pf mode) unchanged and adds only what pfSense needs around it: a
settings page, the bouncer's config file, a service, the firewall rules that use its
tables, a status page and metrics. The bouncer keeps working across pfSense upgrades
because it comes with the pfBlockerNG package.

The bouncer is a separate component that only ships in the pfBlockerNG package. It has
its own page, menu entry and enable switch, and works whether pfBlockerNG itself is
enabled or not. It shares pfBlockerNG's build, packaging, coding and testing standards,
and its conventions for logs and metrics, nothing else.

pfSense's own logs reach the remote engine through pfSense's built-in remote syslog. The
engine does all parsing and decides; pfSense only enforces.

## Fixed constraints

- **The bouncer is upstream's, unmodified.** `crowdsecurity/cs-firewall-bouncer` is built
  from a pinned release tag through the same go recipe route as `pfb-core`
  (`docs/build-pkg-portable.md`): vendored, CGO off, `-trimpath`, one binary per machine
  (`freebsd-amd64`, `freebsd-arm64`). No patches. Its behaviour is the bouncer's own:
  - it drives PF through `/sbin/pfctl` (batched `-T add`/`-T delete` from a temp file,
    `-k` to kill the states of newly banned addresses);
  - its decision loop is go-cs-bouncer's `StreamBouncer`: a full pull with
    `startup=true`, then deltas every `update_frequency` (10 s);
  - it refuses to start if a configured table is not found in `pfctl -s Tables` output
    (a substring match), and flushes both tables when it stops;
  - it pushes usage metrics to the LAPI itself;
  - TLS uses the system trust store, and the LAPI is reached through the routing table.
- **Licensing.** cs-firewall-bouncer, go-cs-bouncer, crowdsec and the hub are MIT, which is
  compatible with pfBlockerNG's Apache-2.0. The bouncer's licence text and its
  dependencies' notices ship with the package, the same way `pfb-core`'s third-party
  notices do. `crowdsecurity/pfSense-pkg-crowdsec` carries no licence, so none of its PHP
  is copied; this spec reuses its approach only (the settings it offers, the rule shape,
  the `filter_rules_needed` hook and the table snapshot around filter reloads).
- **Independent of pfBlockerNG at runtime.** pfBlockerNG's master enable, its sync pass,
  its feed and Update pipeline, `pfb-core`, its XMLRPC sync and its metrics export never
  start, stop, configure or read the bouncer, and the bouncer's code never calls them.
- **Nothing in `config.xml` but settings.** No aliases and no rules are stored. The only
  `config.xml` side effect of the rule hook is pfSense core's own
  `installedpackages/package/<n>/filter_rule_function` registration, which
  `pkg-utils.inc` writes at install from `<filter_rules_needed>`.
- Its settings fields go through `PfbConfig` (`docs/misc/config-gateway.md`), like every
  field the package registers.
- Appliance code is PHP and POSIX sh only.

## Decisions

### D1. Settings

A new page `/pfblockerng/crowdsec_bouncer.php`, with its own menu entry
**Firewall > CrowdSec Bouncer**, holds the settings and, below them, the status (D7).
The fields mirror the firewall-bouncer part of the official package. They live in a new
`PFB_SECTIONS` alias `crowdsec` (`installedpackages/pfblockerngcrowdsec/config/0`). All of
them are `sync => 'local'`: each node registers and runs its own bouncer, and XMLRPC sync
never copies a LAPI key to a peer.

| Key | UI | Default | Validation |
| --- | --- | --- | --- |
| `crowdsec/enable` | Enable checkbox | off | — |
| `crowdsec/lapi_url` | Remote LAPI URL | empty | `http://` or `https://` URL with a host; required when enabled |
| `crowdsec/api_key` | Bouncer API key (password field) | empty | 1–256 printable ASCII, no whitespace; required when enabled |
| `crowdsec/log_level` | Log level select | `info` | `trace`, `debug`, `info`, `warning`, `error` |
| `crowdsec/rules_all_interfaces` | Apply to all interfaces | on | — |
| `crowdsec/rules_interfaces` | Interface selection (multi) | empty | each a configured interface; at least one when "all" is off |
| `crowdsec/rules_log` | Log blocked packets | off | — |
| `crowdsec/rules_tag` | Tag | empty | empty, or `[A-Za-z0-9_-]{1,63}` |
| `crowdsec/rule_v4` | Enable the IPv4 rules | on | — |
| `crowdsec/rule_v6` | Enable the IPv6 rules | on | — |
| `crowdsec/metrics_export` | Metrics export | off | as `gen/pfb_metrics_export` (D6) |

- The page tells the operator to register the bouncer on the engine with
  `cscli bouncers add <name>` and paste the key, as the official package does.
- The key is never echoed back into the form, logged, or shown on the status page. An
  empty key field on save keeps the stored key.
- The page's own save applies everything (D3); it never runs pfBlockerNG's sync pass.

### D2. Bouncer config file

- Path `/usr/local/etc/crowdsec_bouncer/crowdsec-firewall-bouncer.yaml`, owner root, mode
  `0600`, outside the `/var` RAM disk. It is written atomically (temp file in the same
  directory, `chmod 0600` before the key is written, `rename()`).
- A save rewrites it while the bouncer is enabled, and removes it when disabled.
- Content is the official pf-mode file with these values; every other key keeps upstream's
  default:

```yaml
mode: pf
update_frequency: 10s
log_mode: stdout
log_level: <crowdsec/log_level>
api_url: <crowdsec/lapi_url>
api_key: <crowdsec/api_key>
insecure_skip_verify: false
disable_ipv6: false
deny_action: DROP
deny_log: false
supported_decisions_types:
  - ban
blacklists_ipv4: crowdsec_v4
blacklists_ipv6: crowdsec_v6
pf:
  anchor_name: ""
prometheus:
  enabled: false
```

- `disable_ipv6` stays false even when the IPv6 rules are off, so both tables always
  exist and the status page and metrics stay uniform.
- The table names `crowdsec_v4` and `crowdsec_v6` contain neither each other nor the
  official package's `crowdsec_blacklists`/`crowdsec6_blacklists`, so the bouncer's
  substring table check cannot match the wrong table. They are outside the `pfB_` prefix
  that pfBlockerNG's table cleanup matches (`grep '^pfB_'`, case-sensitive).
- The bouncer's Prometheus listener stays off, as in the official package. Nothing listens
  on a port; the page and the export collect the same numbers themselves (D6).

### D3. Service

- New `<service>` entry `crowdsec_bouncer` ("CrowdSec firewall bouncer"), rc file
  `/usr/local/etc/rc.d/crowdsec_bouncer.sh`, status
  `isvalidpid('/var/run/crowdsec_bouncer.pid')`.
- The rc script is generated with `write_rcfile()` the way `pfb_core_service()` generates
  Core's. It picks this machine's binary by `uname -p`, and runs it under daemon(8) with
  restart on exit (`-r -R 5`), supervisor and child pidfiles, std fds detached, and its
  output sent to syslog (`-S -l daemon -T crowdsec_bouncer`). With no binary for this
  machine it logs and starts nothing.
- Stop sends TERM, and KILL after 5 s, as Core's does. The bouncer flushes both tables
  on a clean stop, so a stopped service enforces nothing (fail-open), as with the official
  package.
- The page's save starts the service when the bouncer turns on, restarts it when the
  config file content changed, and stops it when the bouncer turns off. It reloads the
  filter (D4) when any rule setting or the enable changed, and turning the bouncer on
  reloads the filter before starting the service, so the tables exist when the bouncer
  checks for them.
- The package's install and upgrade regenerate the rc script and, while the bouncer is
  enabled, the config file; the service then starts with the other package services.
- At boot, pfSense loads the filter before it starts package services, which gives the
  same order.
- If acceptance criterion 5 shows that the bouncer's table check fails on tables that
  exist only through rule references, the rc script's start first runs
  `pfctl -t <table> -T add -f /dev/null` for both tables. pfctl creates a missing table
  as persistent and adds nothing. A table created this way is not declared in the
  ruleset, so criterion 4 is re-checked against it.
- Deinstall stops the service and removes the rc file, the binary, the config file, the
  metrics file and the cron entry (D6).

### D4. Firewall rules

- `pfblockerng.xml` gains
  `<filter_rules_needed>crowdsec_bouncer_rules</filter_rules_needed>`. pfSense calls it
  for each rule type; it returns rules only for `pfearly`, and only while the bouncer is
  enabled.
- For each enabled family, two rules, in the official package's shape, which the
  bouncer's metrics parser expects (`^block .* from <table> .* label "`):

```text
block drop in  {log} quick {on {ifaces}} inet  from <crowdsec_v4> to any label "CrowdSec IPv4" {tag tag}
block drop out {log} quick {on {ifaces}} inet  from any to <crowdsec_v4> label "CrowdSec IPv4 out" {tag tag}
block drop in  {log} quick {on {ifaces}} inet6 from <crowdsec_v6> to any label "CrowdSec IPv6" {tag tag}
block drop out {log} quick {on {ifaces}} inet6 from any to <crowdsec_v6> label "CrowdSec IPv6 out" {tag tag}
```

- `{ifaces}` are the real interface names from `get_real_interface()`, and are omitted
  when "all interfaces" is on. `{log}` and `{tag}` appear only when set.
- The tables are never declared with `table <…>` in the ruleset. They exist because the
  rules reference them.
- **Filter reloads.** If a reload empties the tables (verified by acceptance criterion 4),
  `crowdsec_bouncer_rules('pfearly')` saves the tables' contents with `pfctl -T show`
  before pfSense loads the new ruleset. It restores them afterwards from a shutdown
  function, feeding addresses through `xargs pfctl -t <table> -T add` so no single
  command exceeds `ARG_MAX`. This is an original implementation of the approach the
  official package uses. If the reload keeps the contents, this code is not added.
- A reboot needs nothing: the bouncer pulls the full decision set at startup.

### D5. Logs and telemetry

- The bouncer logs to syslog under the tag `crowdsec_bouncer` (D3), so it lands in the
  system log and goes wherever the operator's remote syslog sends it.
- pfSense's own logs (filter, pfBlockerNG, HAProxy, nginx) reach the remote engine through
  **Status > System Logs > Settings > Remote Logging**. The bouncer configures none of
  this, and the settings page says so in one line.

### D6. Metrics

- **LAPI usage metrics:** the bouncer pushes them itself (go-cs-bouncer
  `MetricsProvider`), with upstream's default interval. This needs no listener.
- **Collector.** One PHP function, `crowdsec_bouncer_collect()`, gathers what the bouncer's
  own pf-mode metrics would show, the same way the bouncer does it:
  - dropped packets and bytes per family, from the inbound rule's label counters in
    `pfctl -v -sr`;
  - addresses in each table, from `pfctl -T show`;
  - whether the service is running, and the time and text of the last error line the
    bouncer logged.

  The status page (D7) calls it on load. Nothing is lost against the bouncer's
  own pf-mode metrics, which come from the same `pfctl` output with an empty `origin`
  label. Only go-cs-bouncer's LAPI request counters are not available.
- **node_exporter export.** It follows `docs/specs/metrics-export.md`'s rules for the
  `Metrics export` field (requires `pfSense-pkg-node_exporter`; disabled checkbox, red
  notice and install link when absent; a POST of `on` without it refused), but runs on its
  own:
  - While the bouncer and its `Metrics export` are both on, a pfSense cron entry
    (`install_cron_job()`) runs `crowdsec_bouncer_collect()` every minute under
    `timeout -s TERM -k 5 50` and publishes `/var/tmp/node_exporter/crowdsec_bouncer.prom`.
    It publishes by atomic `rename()` with mode `0644`, never creates the directory, and
    refuses a symlinked one.
  - Families use the bouncer's upstream names and labels, so dashboards built for the
    official bouncer work as-is: `fw_bouncer_dropped_packets`, `fw_bouncer_dropped_bytes`
    and `fw_bouncer_banned_ips`, each with `ip_type` (`ipv4`/`ipv6`) and `origin=""`.
    Added to them are `crowdsec_bouncer_up` (service running, 0/1) and
    `crowdsec_bouncer_last_error_timestamp_seconds`.
  - Turning either off, or deinstalling, removes the cron entry and the file.

### D7. Status

Below the settings, the page shows the bouncer-only subset of the official package's
status page, from `crowdsec_bouncer_collect()` and two direct reads:

- **Service:** running or stopped.
- **LAPI:** the LAPI URL (never the key), and the last error the bouncer logged, with its
  time.
- **Decisions:** addresses per family, and the contents of each table from
  `pfctl -T show`, paged 100 per page.
- **Lookup:** one address field. The server queries `GET /v1/decisions?ip=<addr>` with the
  bouncer key and shows each matching decision's value, scope, origin, scenario, type and
  expiry. The address is validated as an IP before the request, which has a 5 s timeout.
- **Counters:** dropped packets and bytes per family.
- **Log:** the last 50 system log lines tagged `crowdsec_bouncer`.

Everything is read on page load; there is no control socket and no write action. The
engine-side views (log processors, remediation components, alerts, hub, deleting
decisions) stay on the remote engine.

## Acceptance criteria

1. With the bouncer enabled and a reachable LAPI, the service is running, both tables
   exist, and a ban added on the engine is in the matching table within 20 s. Removing it
   on the engine removes it from the table within 20 s.
2. Traffic from and to a banned address is dropped on the selected interfaces only, and
   the rules carry the configured log and tag options.
3. The config file exists with mode `0600` and the exact content of D2. It is absent with
   the bouncer off. The key appears in no log, page or metrics file.
4. A filter reload (Status > Filter Reload) leaves both tables' contents unchanged.
   Verified first without D4's save-and-restore. If contents are lost, the save-and-restore
   is added and the check must then pass.
5. Enabling the bouncer from a box that has never had it starts it on the first try: the
   bouncer's table check passes on tables that exist only through the generated rules
   (otherwise D3's table creation is added and the check must then pass).
6. Stopping the service empties both tables. Disabling the bouncer also removes the rules,
   the config file and the running process.
7. A reboot brings the service back with the full decision set and no manual step.
8. The bouncer runs, starts, stops and reports the same with pfBlockerNG's master enable
   on or off, and no pfBlockerNG save, sync pass or Update touches it.
9. Nothing listens on a TCP or UDP port for the bouncer (`sockstat -l`).
10. With `Metrics export` on, `crowdsec_bouncer.prom` appears within one minute, parses
    with the Prometheus Python client, and its counters match `pfctl -v -sr` and the table
    sizes.
11. The status page shows every item in D7, and the lookup of a banned address shows its
    decision.
12. Neither `config.xml` nor XMLRPC sync carries any CrowdSec rule, alias or table, and the
    LAPI key never reaches a sync peer.
13. Deinstall leaves no rc file, binary, config file, metrics file, cron entry or table
    contents behind.

## Tests

Red-before-green per `.agents/policy/testing.md`:

- PHPUnit: registry entries and validation of every D1 field, including hostile values for
  the URL, key, tag and interfaces. A saved empty key keeps the stored key.
- PHPUnit: config file rendering against exact expected YAML. Atomic write with mode
  `0600` set before the key is written, and removal when disabled.
- PHPUnit: rule generation against exact expected text for each combination of families,
  interfaces, log and tag, and no output for other rule types or when disabled.
- PHPUnit: the generated rc script against expected text (binary choice by machine,
  daemon(8) flags, stop timing).
- PHPUnit: the save's start, restart-on-change, stop and filter-reload decisions, with the
  filter reload ordered before the first start, and none of them depending on
  pfBlockerNG's master enable.
- PHPUnit: the collector against fixture `pfctl -v -sr`, `pfctl -T show` and log output,
  and the rendered `.prom` text against exact expected output; the cron entry added and
  removed with the two toggles; the export rules shared with `metrics-export.md`.
- PHPUnit: if D4's save-and-restore is added, its batching through `xargs` and its
  restore after a simulated reload.
- UI tier: the page's fields, validation messages, the key never rendered, the metrics
  checkbox states without node_exporter, and the status sections against fixture
  collector output and a stub LAPI answer.
- Smoke (VM): the built bouncer against a stub LAPI in the smoke harness (serving
  `/v1/decisions/stream`, `/v1/decisions` and the usage-metrics endpoint) covers criteria
  1, 3–10 and 13.

## Out of scope

- Shipping the CrowdSec Security Engine, log processor, LAPI, parsers, scenarios or hub on
  pfSense; the bouncer is the only CrowdSec binary the package ships.
- Modifying or forking the bouncer, and enabling its Prometheus listener.
- Routing decisions through the feed or Update pipeline, or through `pfb-core`.
- CrowdSec change hooks, and a HAProxy, AppSec or captcha bouncer of the package's own
  (HAProxy uses the official SPOA bouncer).
- Migrating settings or state from the official CrowdSec package.
- Configuring pfSense remote syslog.
- Showing CrowdSec data in pfBlockerNG's own pages, reports, alerts, widget or metrics.
- CARP-aware behaviour; each node runs its own bouncer.
- Separate resource or response-time budgets.

## Open forks

None. Criteria 4 and 5 are verifications with the fallback already decided in D3 and D4.
