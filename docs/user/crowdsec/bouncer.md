# CrowdSec bouncer

pfBlockerNG can act as a CrowdSec firewall bouncer: it pulls the bans of a CrowdSec Security Engine and drops traffic
from and to the banned addresses on pfSense. The bouncer is part of pfBlockerNG and is configured under
**Firewall > pfBlockerNG > CrowdSec**. It needs no CrowdSec package on pfSense.

This guide lives in `docs/user/crowdsec/` because it is operator documentation. The
[design specification](../../specs/crowdsec-integration.md) records the decisions behind the bouncer and how they were
verified.

**Baseline checked on 2026-11-21:** labels and behavior at devel `1721d1852`, CrowdSec's decision origins and LAPI
replies at `crowdsecurity/crowdsec` master, and the official pfSense CrowdSec package (`pfSense-pkg-crowdsec` 0.1.8) at
`crowdsecurity/pfSense-pkg-crowdsec` master. The timings under [Checking that it works](#checking-that-it-works) were
measured on a pfSense deployment that runs the nightly package.

## What the bouncer does and does not do

The bouncer is a small daemon, `pfb_crowdsec`, that pfBlockerNG runs as the service **pfBlockerNG CrowdSec bouncer**.
Every 10 seconds it asks the engine's Local API (LAPI) for new and deleted decisions, and keeps two pf tables,
`crowdsec_v4` and `crowdsec_v6`, equal to the engine's active bans. pfBlockerNG adds the firewall rules that drop
traffic matching those tables.

- It enforces decisions of type `ban` with scope `ip` or `range`. Other types (such as `captcha`) and other scopes
  (such as `country` or `as`) are ignored.
- It is a bouncer only. It does not parse logs, detect attacks, or run a LAPI. The CrowdSec Security Engine, with its
  LAPI, runs elsewhere: on another host, or on this firewall through the official CrowdSec package (see
  [Using the official package's LAPI on the same firewall](#using-the-official-packages-lapi-on-the-same-firewall)).
- It does not send pfSense's logs to the engine. Forward them with pfSense's own remote syslog, under
  **Status > System Logs > Settings > Remote Logging**, which pfBlockerNG does not configure.
- It opens no listening port.
- It does not go through pfBlockerNG's feeds or Update pass. Saving or running an update neither starts, stops nor
  restarts it.
- When the bouncer stops, it empties both tables, so nothing is blocked until it runs again (fail-open), as with the
  official CrowdSec firewall bouncer. While the LAPI is unreachable, the bouncer keeps enforcing the last set of bans
  it received.

## Before you start

1. A CrowdSec Security Engine with its LAPI, reachable from pfSense over HTTP or HTTPS. By default the LAPI listens on
   `127.0.0.1:8080` only; to reach it from pfSense, make it listen on an address pfSense can reach (`listen_uri` under
   `api.server` in the engine's `config.yaml`) and allow pfSense to connect to that port.
2. A bouncer key for this firewall. On the engine, run:

   ```sh
   cscli bouncers add <name>
   ```

   `cscli` prints the key once. Copy it; it cannot be shown again.

Each firewall needs its own key, and a key should be used by one bouncer at a time. The LAPI keeps track, per key, of
which decisions it has already sent. Two bouncers that share a key each receive only part of the changes.

If you are replacing another bouncer, you can reuse its key, provided the old bouncer is stopped first. pfBlockerNG's
bouncer always asks for the complete set of decisions when it starts, so it does not depend on where the previous
bouncer left off.

## Setting up the bouncer

Open **Firewall > pfBlockerNG > CrowdSec > Settings**.

### CrowdSec Bouncer

| Setting | Default | Description |
| --- | --- | --- |
| **CrowdSec** (Enable) | off | Turns the bouncer on. |
| **Remote LAPI URL** | empty | The LAPI's address, for example `http://192.0.2.10:8080`. It must start with `http://` or `https://`, name a host, and carry no user name, password, query or fragment. Required when the bouncer is enabled. |
| **Bouncer API key** | empty | The key from `cscli bouncers add`. Required when the bouncer is enabled. Up to 256 printable ASCII characters, without spaces. |
| **Log level** | `info` | The lowest level the bouncer logs: `debug`, `info`, `warning` or `error`. See [Logs](#logs). |

The key is never shown again after you save it, and it is never written to a log, page, status file or metrics file.
When a key is stored, the field says so; leave it empty on a later save to keep the stored key, or enter a new one to
replace it.

With `https://`, the bouncer verifies the LAPI's certificate against pfSense's system trust store. There is no option to
skip that check, and TLS client certificates are not supported. The bouncer does not follow redirects, so the URL must
point at the LAPI itself.

### Firewall Rules

| Setting | Default | Description |
| --- | --- | --- |
| **All interfaces** | on | Applies the rules on every interface. |
| **Interface(s)** | none | The interfaces the rules apply on when **All interfaces** is off. Select at least one. |
| **Log blocked packets** | off | Adds `log` to the rules, so dropped packets appear in the firewall log. |
| **Tag** | empty | An optional pf tag added to the rules: up to 63 letters, digits, `_` or `-`. |
| **IPv4 rules** | on | Generates the IPv4 rules. |
| **IPv6 rules** | on | Generates the IPv6 rules. |

Click **Save**. The change takes effect at once: the bouncer starts, restarts or stops, and the filter is reloaded when
the bouncer was turned on or off or a rule setting changed.

### When the bouncer runs

The bouncer runs only while all three of these are true:

- pfBlockerNG is enabled (**pfBlockerNG** on **Firewall > pfBlockerNG > General**);
- **CrowdSec** is enabled on the CrowdSec Settings subtab;
- a bouncer key is stored on this firewall.

Turning any of them off stops the bouncer and removes its rules. The bouncer also follows a change to these settings
received through XMLRPC sync, the setup wizard, a package install or upgrade, and a reboot.

## Firewall rules and tables

For each enabled address family, pfBlockerNG adds two rules to pfSense's early ruleset, before the interface rules:

| Rule name | Direction | Matches | Tracker |
| --- | --- | --- | --- |
| `CrowdSec IPv4` | inbound | source in `crowdsec_v4` | `177400401` |
| `CrowdSec IPv4 out` | outbound | destination in `crowdsec_v4` | `177400402` |
| `CrowdSec IPv6` | inbound | source in `crowdsec_v6` | `177400601` |
| `CrowdSec IPv6 out` | outbound | destination in `crowdsec_v6` | `177400602` |

The rules drop packets silently (`block drop`) and use `quick`, so no later rule can pass a banned address.

- The rules do not appear under **Firewall > Rules**; pfSense adds them when it loads its ruleset. To see them, use
  **Diagnostics > Command Prompt** with `pfctl -sr | grep CrowdSec`.
- The trackers are fixed and never change across reloads or upgrades. pfSense's firewall log shows the tracker and the
  rule name, so with **Log blocked packets** on, **Status > System Logs > Firewall** names the CrowdSec rule that dropped
  each packet.
- With **All interfaces** off, the rules apply only on the selected interfaces. A family for which none of the selected
  interfaces exists gets no rules.
- The tables are not pfSense aliases and do not appear under **Firewall > Aliases**. They hold only what the bouncer puts
  in them, and only while it runs. pfBlockerNG stores no banned address in `config.xml`.
- A filter reload removes both tables. The bouncer is told to recreate and refill them immediately; if that signal is
  missed, its next pull restores them within 10 seconds.
- When a new single address is banned, the bouncer also kills the states of existing connections to or from it, so an
  established connection is cut.

## Checking that it works

### Status subtab

**Firewall > pfBlockerNG > CrowdSec > Status** shows the bouncer's state. The page is read-only; it reads everything when
it loads.

- **Bouncer Service**: **Running**, **Stopped**, or **Not running** with the reason (`pfBlockerNG is disabled`,
  `CrowdSec is disabled`, or `no bouncer API key is stored on this node`), plus the bouncer's version, its start time
  and when it last wrote its status. **(stale)** next to that time means the bouncer has not written its status for
  more than three pull intervals: it is stuck or stopped.
- **LAPI**: the LAPI URL (never the key), the last successful pull, the last error with its time, and the number of
  LAPI requests and failed requests since the bouncer started.
- **Decisions**: the number of banned values (addresses and ranges) per address family and per origin, with a total
  per family. Origins are reported by the LAPI as they are, for example `crowdsec` (the engine's own scenarios), `cscli`
  (added by hand), `cscli-import`, `CAPI` (the community blocklist), `lists` (blocklists subscribed through the CrowdSec
  console) and `console`. A value banned by decisions of several origins is counted once, under the origin of its
  lowest-numbered (usually oldest) decision.
- **Dropped**: packets and bytes dropped per address family since the bouncer started. These come from the inbound
  rule of each family only.
- **Table crowdsec_v4** and **Table crowdsec_v6**: the contents of each table, 100 entries per page.
- **Decision Lookup**: enter an IP address to ask the LAPI which decisions it holds on that address, with their value,
  scope, origin, scenario, type and remaining duration. The lookup uses the stored URL and key, and times out after
  5 seconds.
- **Log**: the last 50 system log lines from the bouncer.

### Dashboard widget

While the bouncer runs, the **pfBlockerNG** dashboard widget lists `crowdsec_v4` and `crowdsec_v6` after pfBlockerNG's
own aliases, with the number of entries in each table and the packets matched by its rules. Each name links to the
Status subtab.

### Timing

The bouncer pulls every 10 seconds, so a ban added on the engine reaches the table within about one interval plus the
time the engine takes to publish it. On one deployment, a ban added on the LAPI was in the pf table after about
9.5 seconds, and its removal took about 7 seconds.

To check this yourself, add a short test ban on the engine for an address you do not use, look it up on the Status
subtab or in the table, and then delete it:

```sh
cscli decisions add --ip 192.0.2.1 --duration 5m --reason "pfBlockerNG test"
cscli decisions delete --ip 192.0.2.1
```

On the engine, `cscli bouncers list` shows the bouncer and the time of its last pull. The bouncer also reports its
usage metrics to the LAPI every 15 minutes, so its dropped traffic and active decisions appear in `cscli metrics` on
the engine.

## Logs

The bouncer writes to the system log with the tag `pfb_crowdsec`. Each line has the form `level=<level> msg=<text>` and
is sent at the matching syslog severity: `debug`, `info`, `warning` or `err`. The bouncer's **Log level** decides which
lines it sends; pfSense then decides which of them it keeps.

pfSense keeps only lines at or above **Default Log Level** under **Status > System Logs > Settings**. On pfSense CE 2.9
and pfSense Plus, **Default** means `notice`, so only `warning` and error lines from the bouncer reach the system
log, the Status subtab's **Log** panel and remote syslog. To see `info` lines, such as each pull's additions and
deletions, set that level to **Info** (or **Debug** for the bouncer's `debug` lines). On pfSense CE 2.8, the
system log keeps `info` and above.

## Metrics

pfBlockerNG's metrics export (**Firewall > pfBlockerNG > General**, **Metrics export**) publishes Prometheus metrics
through the node_exporter package's textfile collector, in `/var/tmp/node_exporter/pfblockerng.prom`. While the bouncer
should run, the file includes these families:

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `fw_bouncer_banned_ips` | gauge | `origin`, `ip_type` | Values the bouncer bans, per origin and address family |
| `fw_bouncer_dropped_packets` | gauge | `ip_type` | Packets dropped by the inbound rule of each family since the bouncer started |
| `fw_bouncer_dropped_bytes` | gauge | `ip_type` | Bytes dropped by the inbound rule of each family since the bouncer started |
| `pfblockerng_crowdsec_lapi_requests_total` | counter | | LAPI requests completed since the bouncer started |
| `pfblockerng_crowdsec_lapi_errors_total` | counter | | Completed LAPI requests that failed since the bouncer started |
| `pfblockerng_crowdsec_last_pull_timestamp_seconds` | gauge | | Unix time of the last successful pull |
| `pfblockerng_crowdsec_last_error_timestamp_seconds` | gauge | | Unix time of the last error, `0` for none |

`ip_type` is `ipv4` or `ipv6`. The `fw_bouncer_*` names are those of the official CrowdSec firewall bouncer, so
dashboards built for it work with these metrics. The dropped counters are per address family only: there is one table,
and one counted rule, per family.

`pfblockerng_metrics_source_up{source="crowdsec"}` is `1` while the bouncer runs and its status is fresh, and `0` when
the service is not running or its status file is missing, unreadable or stale. The rest of the file is still written.
When the bouncer should not run, the `crowdsec` source and its families are absent.

Example alerting rules:

```text
pfblockerng_metrics_source_up{source="crowdsec"} == 0
time() - pfblockerng_crowdsec_last_pull_timestamp_seconds > 300
```

The first fires when the bouncer is down or stuck; the second when it has not completed a pull for five minutes, for
example because the LAPI is unreachable or refuses the key.

## High availability and XMLRPC sync

Each firewall in an HA pair runs its own bouncer, with its own key registered on the engine (`cscli bouncers add` once
per firewall). The key never leaves the firewall it was entered on.

With the **Sync** tab's scope set to **Policy and lists (local settings stay local)**, XMLRPC sync copies these
CrowdSec settings to the peers:

- synced: **CrowdSec** (Enable), **Remote LAPI URL**, **Log blocked packets**, **Tag**, **IPv4 rules**, **IPv6 rules**;
- kept on each firewall: **Bouncer API key**, **Log level**, **All interfaces**, **Interface(s)**.

The legacy scopes do not copy the CrowdSec settings. No banned address, table or rule is synced: each bouncer pulls its
own decisions from the LAPI.

A peer that receives the enable without having a key of its own does not start the bouncer; its Status subtab shows
`no bouncer API key is stored on this node`. Enter that firewall's own key on its Settings subtab.

The bouncer is not CARP-aware: it runs on every firewall where it is enabled, whether that firewall is the CARP primary
or not.

## Upgrades, restores and uninstall

- **Package upgrade or reinstall**: the bouncer keeps running while the package is replaced. Afterwards, the installer
  restarts it once if its program or configuration changed. A restart empties the tables until the first pull
  completes, usually a few seconds.
- **Reboot**: the bouncer starts with the other packages and pulls the full set of decisions. Nothing needs to be done.
- **Configuration restore**: restoring the whole configuration reinstalls the packages at the next boot, which applies
  the restored CrowdSec settings. Restoring only the **Package Manager** area reloads the filter, so the rules follow the
  restored settings at once, but the bouncer itself only follows them at the next save of the CrowdSec settings,
  pfBlockerNG's enable, or a reboot.
- **Uninstall**: removing pfBlockerNG stops the bouncer and removes its service script, its configuration file
  (`/usr/local/etc/pfb_crowdsec.json`), its status file and its program. Its rules disappear with the package. Its
  settings follow **Keep Settings** on **Firewall > pfBlockerNG > General**, like the rest of pfBlockerNG's settings.
  The bouncer stays registered on the engine; remove it there with `cscli bouncers delete <name>` if you no longer
  need it.

## Migrating from the official CrowdSec package

The official pfSense CrowdSec package (`pfSense-pkg-crowdsec`) runs its own firewall bouncer, and optionally a log
processor and a LAPI, on pfSense. Do not run its firewall bouncer and pfBlockerNG's bouncer at the same time: both
would block the same addresses through different tables, and both name their rules `CrowdSec IPv4`, `CrowdSec IPv6`,
and so on. pfBlockerNG's rules carry the fixed trackers listed above; the official package's rules carry none.

The two bouncers use different tables: the official package uses `crowdsec_blacklists` and `crowdsec6_blacklists`,
pfBlockerNG uses `crowdsec_v4` and `crowdsec_v6`. They do not interfere with each other.

pfBlockerNG does not import any setting from the official package. Note its **Remote LAPI URL** (or LAPI host and
port) and interface and rule options before you start.

### Replacing the package entirely

Use this when the LAPI runs on another host.

1. Take a configuration backup under **Diagnostics > Backup & Restore**.
2. Get a key for pfBlockerNG's bouncer: either run `cscli bouncers add <name>` on the engine, or reuse the official
   bouncer's key once it is stopped (see [Before you start](#before-you-start)).
3. Remove **crowdsec** under **System > Package Manager > Installed Packages**. Removing it deletes its aliases and
   its rules. Then check that the `crowdsec` and `crowdsec-firewall-bouncer` packages are gone too, under
   **Diagnostics > Command Prompt**:

   ```sh
   pkg info crowdsec crowdsec-firewall-bouncer
   ```

   Remove any that remain with `pkg delete crowdsec-firewall-bouncer crowdsec`.
4. Set up pfBlockerNG's bouncer as described in [Setting up the bouncer](#setting-up-the-bouncer), and check its
   Status subtab.

pfSense keeps an uninstalled package's settings in `config.xml` (`installedpackages/crowdsec`), including the official
bouncer's API key. `pkg` also keeps configuration files that were changed after installation, so
`/usr/local/etc/crowdsec` usually remains, with the official bouncer's configuration and key and, if the package ran a
log processor, its LAPI credentials. If you do not plan to reinstall the official package, delete that directory, and
remove the official bouncer's registration on the engine with `cscli bouncers delete <name>` unless pfBlockerNG reuses
its key.

### Using the official package's LAPI on the same firewall

You can keep the official package for its log processor and LAPI, and use pfBlockerNG's bouncer instead of its
firewall bouncer:

1. In the official package's settings, turn off **Enable** under **Remediation component (firewall bouncer)**, and
   save.
2. On pfSense, register pfBlockerNG's bouncer with `cscli bouncers add <name>` under **Diagnostics > Command Prompt**.
3. Set **Remote LAPI URL** to the LAPI address from the official package's **LAPI host** and **LAPI port** settings,
   for example `http://127.0.0.1:8088`.

The official package keeps its rules on its own, now empty, tables while it is installed. They match nothing.

## Troubleshooting

Start with the Status subtab: the service state, the **Last error** in the LAPI panel, and the **Log** panel. The
Status subtab's log shows only what pfSense keeps (see [Logs](#logs)); errors are always kept.

| Symptom | Cause and fix |
| --- | --- |
| **Not running: pfBlockerNG is disabled** | Enable pfBlockerNG on the General tab. |
| **Not running: CrowdSec is disabled** | Enable **CrowdSec** on the Settings subtab. On an HA peer, the enable may have been synced off. |
| **Not running: no bouncer API key is stored on this node** | Enter this firewall's own key. Keys are never synced. |
| **Stopped**, and the log shows `not started` | The log line names the reason, for example `no pfb_crowdsec for machine '…'` on an unsupported platform (only amd64 and arm64 are built). |
| Last error `GET /v1/decisions/stream: HTTP 403 Forbidden: {"message":"access forbidden"}` (in the log, after `LAPI pull failed:`) | The LAPI does not accept the key: it was mistyped, or the bouncer was deleted on the engine. Create a new key with `cscli bouncers add` and save it. |
| Last error with `connection refused`, `no such host`, `i/o timeout` or `Client.Timeout exceeded` | pfSense cannot reach the LAPI. Check the URL, that the LAPI listens on an address pfSense can reach, and the firewalls between them. |
| Last error with `x509:` or `tls:` | The LAPI's certificate is not trusted by pfSense, or does not match the host name in the URL. |
| Last error `HTTP 404` | The URL points at the wrong service or path. Use the LAPI's base URL, for example `http://192.0.2.10:8080`, without `/v1/...`. |
| Last error `HTTP 301` or `HTTP 302` | The URL redirects. The bouncer does not follow redirects; use the address the redirect points to. |
| **(stale)** next to **Status written** | The bouncer process is stuck or gone. Restart the `pfb_crowdsec` service (**pfBlockerNG CrowdSec bouncer**) under **Status > Services** and check the log. |
| **The table does not exist** | The bouncer is not running, or has not finished starting. |
| Tables are filled, but traffic passes | Check that the rules exist (`pfctl -sr \| grep CrowdSec`), that the right interfaces are selected, and that the address family's rules are enabled. |
| The log shows only warnings and errors | pfSense's system log level filters the rest; see [Logs](#logs). |
| The log shows `ignored N invalid ban values` | The LAPI sent ban values that are neither an IP address nor a range. The bouncer skips them; check the decision on the engine. |
| The log shows `usage metrics not sent` | The LAPI refused or did not answer the bouncer's usage report. Enforcement is not affected. |

After the LAPI comes back, the bouncer resumes on its next pull. After any failed pull it asks for the complete set of
decisions again, so no ban or removal is lost.

## Limitations

- Only `ban` decisions on IP addresses and ranges are enforced.
- Drops by the CrowdSec rules are not yet listed in pfBlockerNG's Alerts and Reports; this is tracked in
  [#4164](https://github.com/pfBlockerNG/pfBlockerNG/issues/4164). Use the firewall log with **Log blocked packets**,
  the Status subtab and the dashboard widget instead.
- The dropped counters count the inbound rules only.
- Each firewall needs its own key, and the bouncer is not CARP-aware.
