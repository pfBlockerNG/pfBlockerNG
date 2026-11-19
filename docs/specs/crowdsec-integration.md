# CrowdSec integration (packaged firewall bouncer)

Issue: [#1585](https://github.com/pfBlockerNG/pfBlockerNG/issues/1585) · map
[#1577](https://github.com/pfBlockerNG/pfBlockerNG/issues/1577)

## Goal

An operator who runs a CrowdSec Security Engine elsewhere can have pfSense drop the
addresses that engine bans, on every interface and in both directions, without installing
the CrowdSec package. pfBlockerNG ships the official CrowdSec firewall bouncer
(`cs-firewall-bouncer`, pf mode) unchanged and adds only what pfSense needs around it: a
settings page, the bouncer's config file, a service, the firewall rules that use its
tables, a status page and metrics. The bouncer keeps working across pfSense upgrades
because it comes with pfBlockerNG.

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
  - it refuses to start if either configured table does not exist, and flushes both
    tables when it stops;
  - it pushes usage metrics to the LAPI and can serve Prometheus metrics on a local port;
  - TLS uses the system trust store, and the LAPI is reached through the routing table.
- **Licensing.** cs-firewall-bouncer, go-cs-bouncer, crowdsec and the hub are MIT, which is
  compatible with pfBlockerNG's Apache-2.0. The bouncer's licence text and its
  dependencies' notices ship with the package, the same way `pfb-core`'s third-party
  notices do. `crowdsecurity/pfSense-pkg-crowdsec` carries no licence, so none of its PHP
  is copied; this spec reuses its approach only (the settings it offers, the rule shape,
  the `filter_rules_needed` hook and the table snapshot around filter reloads).
- **Not a feed.** The integration never goes through the feed or Update pipeline and never
  through `pfb-core`. Core does not start, stop or watch it.
- **Nothing in `config.xml` but settings.** No aliases and no rules are stored. The only
  `config.xml` side effect of the rule hook is pfSense core's own
  `installedpackages/package/<n>/filter_rule_function` registration, which
  `pkg-utils.inc` writes at install from `<filter_rules_needed>`.
- Every settings field goes through `PfbConfig` (`docs/misc/config-gateway.md`).
- Appliance code is PHP and POSIX sh only.

## Decisions

### D1. Settings

A new **CrowdSec** tab (`/pfblockerng/pfblockerng_crowdsec.php`) holds the settings and,
below them, the status (D7). The fields mirror the firewall-bouncer part of the official
package. They live in a new `PFB_SECTIONS` alias `crowdsec`
(`installedpackages/pfblockerngcrowdsec/config/0`). All of them are `sync => 'local'`:
each node registers and runs its own bouncer, and XMLRPC sync never copies a LAPI key to
a peer.

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

- The page tells the operator to register the bouncer on the engine with
  `cscli bouncers add <name>` and paste the key, as the official package does.
- The key is never echoed back into the form, logged, or shown on the status page. An
  empty key field on save keeps the stored key.
- The integration runs only while both `crowdsec/enable` and pfBlockerNG's master enable
  are on.

### D2. Bouncer config file

- Path `/usr/local/etc/pfblockerng/crowdsec-firewall-bouncer.yaml`, owner root, mode
  `0600`, outside the `/var` RAM disk. It is written atomically (temp file in the same
  directory, `chmod 0600` before the key is written, `rename()`).
- Every sync pass rewrites it while the integration is enabled, and removes it when
  disabled.
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
blacklists_ipv4: pfb_crowdsec
blacklists_ipv6: pfb_crowdsec6
pf:
  anchor_name: ""
prometheus:
  enabled: true
  listen_addr: 127.0.0.1
  listen_port: 60601
```

- `disable_ipv6` stays false even when the IPv6 rules are off, so both tables always
  exist and the status page and metrics stay uniform.
- Table names are lowercase `pfb_crowdsec`/`pfb_crowdsec6`, outside the `pfB_*` alias
  namespace, so pfBlockerNG's own alias table housekeeping never touches them.
- The Prometheus listener is loopback only. It is the bouncer's own listener, used by the
  status page and the metrics export (D6, D7); pfBlockerNG still opens none.

### D3. Service

- New `<service>` entry `pfb_crowdsec` ("pfBlockerNG CrowdSec bouncer"), rc file
  `/usr/local/etc/rc.d/pfb_crowdsec.sh`, status
  `isvalidpid('/var/run/pfb_crowdsec.pid')`.
- The rc script is generated with `write_rcfile()` the way `pfb_core_service()` generates
  Core's. It picks this machine's binary by `uname -p`, and runs it under daemon(8) with
  restart on exit (`-r -R 5`), supervisor and child pidfiles, std fds detached, and its
  output sent to syslog (`-S -l daemon -T pfb_crowdsec`). With no binary for this machine
  it logs and starts nothing.
- Stop sends TERM, and KILL after 5 s, as Core's does. The bouncer flushes both tables
  on a clean stop, so a stopped service enforces nothing (fail-open), as with the official
  package.
- A sync pass starts the service when the integration turns on, restarts it when the
  config file content changed, and stops it when the integration turns off. Turning it on
  reloads the filter (D4) before starting the service, so the tables exist when the
  bouncer checks for them.
- At boot, pfSense loads the filter before it starts package services, which gives the
  same order.
- If acceptance criterion 5 shows that the bouncer's table check fails on tables that
  exist only through rule references, the rc script's start first runs
  `pfctl -t <table> -T add -f /dev/null` for both tables. pfctl creates a missing table
  as persistent and adds nothing. A table created this way is not declared in the
  ruleset, so criterion 4 is re-checked against it.
- Deinstall stops the service and removes the rc file, the binary and the config file.

### D4. Firewall rules

- `pfblockerng.xml` gains `<filter_rules_needed>pfb_crowdsec_rules</filter_rules_needed>`.
  pfSense calls it for each rule type; it returns rules only for `pfearly`, and only while
  the integration is enabled.
- For each enabled family, two rules, in the official package's shape, which the
  bouncer's metrics parser expects (`^block .* from <table> .* label "`):

```text
block drop in  {log} quick {on {ifaces}} inet  from <pfb_crowdsec>  to any label "CrowdSec IPv4" {tag tag}
block drop out {log} quick {on {ifaces}} inet  from any to <pfb_crowdsec>  label "CrowdSec IPv4 out" {tag tag}
block drop in  {log} quick {on {ifaces}} inet6 from <pfb_crowdsec6> to any label "CrowdSec IPv6" {tag tag}
block drop out {log} quick {on {ifaces}} inet6 from any to <pfb_crowdsec6> label "CrowdSec IPv6 out" {tag tag}
```

- `{ifaces}` are the real interface names from `get_real_interface()`, and are omitted
  when "all interfaces" is on. `{log}` and `{tag}` appear only when set.
- The tables are never declared with `table <…>` in the ruleset. They exist because the
  rules reference them.
- **Filter reloads.** If a reload empties the tables (verified by acceptance criterion 4),
  `pfb_crowdsec_rules('pfearly')` saves the tables' contents with `pfctl -T show` before
  pfSense loads the new ruleset. It restores them afterwards from a shutdown function,
  feeding addresses through `xargs pfctl -t <table> -T add` so no single command
  exceeds `ARG_MAX`. This is pfBlockerNG's own implementation of the approach the official
  package uses. If the reload keeps the contents, this code is not added.
- A reboot needs nothing: the bouncer pulls the full decision set at startup.

### D5. Logs and telemetry

- The bouncer logs to syslog under the tag `pfb_crowdsec` (D3), so it lands in the system
  log and goes wherever the operator's remote syslog sends it.
- pfSense's own logs (filter, pfBlockerNG, HAProxy, nginx) reach the remote engine through
  **Status > System Logs > Settings > Remote Logging**. pfBlockerNG configures none of
  this, and the settings page says so in one line.

### D6. Metrics

- **LAPI usage metrics:** the bouncer pushes them itself (go-cs-bouncer
  `MetricsProvider`), with upstream's default interval.
- **node_exporter:** the existing metrics export (`docs/specs/metrics-export.md`) gains a
  `crowdsec` source.
  - While the integration is enabled, `pfb_metrics_write()` reads
    `http://127.0.0.1:60601/metrics` with a 5 s timeout. It copies the bouncer's
    `fw_bouncer_*` families and go-cs-bouncer's LAPI request families into
    `pfblockerng.prom` unchanged, under their upstream names, so dashboards built for the
    official bouncer work as-is.
  - The source reports `source_up` like every other source; a failed read writes `0` and
    leaves the rest of the file intact.
  - With the integration off, the source is absent.

### D7. Status

Below the settings, the CrowdSec tab shows the bouncer-only subset of the official
package's status page:

- **Service:** running or stopped, from the service status.
- **LAPI:** the LAPI URL (never the key), plus LAPI request and error counts from the
  bouncer's metrics.
- **Decisions:** active banned addresses per family and per origin (from
  `fw_bouncer_banned_ips`), and the contents of each table from `pfctl -T show`, paged 100
  per page.
- **Lookup:** one address field. The server queries `GET /v1/decisions?ip=<addr>` with the
  bouncer key and shows each matching decision's value, scope, origin, scenario, type and
  expiry. The address is validated as an IP before the request, which has a 5 s timeout.
- **Counters:** dropped and processed packets and bytes per family, from the bouncer's
  metrics.
- **Log:** the last 50 system log lines tagged `pfb_crowdsec`.

Everything is read on page load; there is no control socket and no write action. The
engine-side views (log processors, remediation components, alerts, hub, deleting
decisions) stay on the remote engine.

## Acceptance criteria

1. With the integration enabled and a reachable LAPI, the service is running, both tables
   exist, and a ban added on the engine is in the matching table within 20 s. Removing it
   on the engine removes it from the table within 20 s.
2. Traffic from and to a banned address is dropped on the selected interfaces only, and
   the rules carry the configured log and tag options.
3. The config file exists with mode `0600` and the exact content of D2. It is absent with
   the integration off. The key appears in no log, page or metrics file.
4. A filter reload (Status > Filter Reload) leaves both tables' contents unchanged.
   Verified first without D4's save-and-restore. If contents are lost, the save-and-restore
   is added and the check must then pass.
5. Enabling the integration from a box that has never had it starts the bouncer on the
   first try: the bouncer's table check passes on tables that exist only through the
   generated rules.
6. Stopping the service empties both tables; disabling the integration also removes the
   rules, the config file and the service's running process.
7. A reboot brings the service back with the full decision set and no manual step.
8. `pfblockerng.prom` carries the bouncer's families with `source_up 1` while it runs, and
   `source_up 0` (other sources intact) while its endpoint is unreachable.
9. The status page shows every item in D7, and the lookup of a banned address shows its
   decision.
10. Neither `config.xml` nor XMLRPC sync carries any CrowdSec rule, alias or table; the
    LAPI key never reaches a sync peer.
11. Deinstall leaves no rc file, binary, config file or table contents behind.

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
- PHPUnit: the sync pass's start, restart-on-change and stop decisions, and the filter
  reload ordered before the first start.
- PHPUnit: the metrics `crowdsec` source copies the expected families unchanged and
  reports `source_up 0` on a failed read.
- PHPUnit: if D4's save-and-restore is added, its batching through `xargs` and its
  restore after a simulated reload.
- UI tier: the tab's fields, validation messages, the key never rendered, and the status
  sections against a fixture metrics body, table contents, log lines and a stub LAPI
  answer.
- Smoke (VM): the built bouncer against a stub LAPI in the smoke harness (serving
  `/v1/decisions/stream` and `/v1/decisions`) covers criteria 1, 3–8 and 11.

## Out of scope

- Shipping the CrowdSec Security Engine, log processor, LAPI, parsers, scenarios or hub on
  pfSense; the bouncer is the only CrowdSec binary pfBlockerNG ships.
- Modifying or forking the bouncer.
- Routing decisions through the feed or Update pipeline, or through `pfb-core`.
- CrowdSec change hooks, and a HAProxy, AppSec or captcha bouncer of pfBlockerNG's own
  (HAProxy uses the official SPOA bouncer).
- Migrating settings or state from the official CrowdSec package.
- Configuring pfSense remote syslog.
- Showing CrowdSec data in pfBlockerNG's reports, alerts, widget or dashboards.
- CARP-aware behaviour; each node runs its own bouncer.
- Separate resource or response-time budgets.

## Open forks

None. Criteria 4 and 5 are verifications with the fallback already decided in D3 and D4.
