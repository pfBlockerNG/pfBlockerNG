<div align="center">

<img src="docs/assets/logo.svg" alt="pfBlockerNG logo" width="150">

<h1>pfBlockerNG</h1>

<p><strong>IP and DNS blocking for <a href="https://www.pfsense.org/">pfSense</a> (CE and Plus).</strong></p>

<p>
  <a href="https://github.com/pfBlockerNG/pfBlockerNG/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/pfBlockerNG/pfBlockerNG/test.yml?branch=devel&label=tests" alt="Tests"></a>
  <a href="https://github.com/pfBlockerNG/pfBlockerNG/releases"><img src="https://img.shields.io/github/v/release/pfBlockerNG/pfBlockerNG?include_prereleases&label=release&color=blue" alt="Latest release"></a>
  <a href="#installation"><img src="https://img.shields.io/badge/pfSense-CE%202.8%20%7C%20Plus%2026.03-212121" alt="Supported pfSense versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/pfBlockerNG/pfBlockerNG?color=green" alt="License: Apache-2.0"></a>
</p>

</div>

pfBlockerNG downloads curated IP and domain feeds and turns them into live
firewall and DNS policy: IP feeds become firewall rules, GeoIP lets you block
or permit by country, and DNSBL enforces domain blocklists directly in the
Unbound resolver. It adds reports, alerts, a dashboard widget, and HA/CARP
sync on top.

pfBlockerNG is developed in this repository —
[pfBlockerNG/pfBlockerNG](https://github.com/pfBlockerNG/pfBlockerNG) —
continuing the original package by [BBcan177](https://github.com/BBcan177),
under the **Apache License 2.0**.

> [!NOTE]
> For day-to-day usage and configuration, the
> [Netgate pfBlockerNG documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html)
> applies. This README covers installation and the features added on top of
> the classic pfBlockerNG.

## Features

- **IP blocking** — IPv4/IPv6 feeds become firewall rules (Deny / Permit /
  Match, inbound/outbound), with dedup, CIDR aggregation, and suppression of
  your own networks.
- **GeoIP** — block or permit by continent or country (MaxMind GeoLite2).
- **DNSBL** — domain blocklists enforced inside the Unbound resolver;
  sinkhole-VIP or NULL responses, SafeSearch enforcement, and per-name reports.
- **Adblock Plus / EasyList feeds** — full ABP syntax: allow (`@@`) exceptions,
  regex rules, and `$important` / `$badfilter` precedence.
- **IDN homoglyph protection** — blocks deceptive cross-script look-alike
  domains, e.g. a Cyrillic `аpple`.
- **Zero-downtime DNSBL updates** — updates swap the blocklist without
  restarting Unbound; queries keep flowing.
- **Aggregated ("Uber") aliases** — opt-in aliases holding the combined,
  CIDR-aggregated set of a whole action type, for use by your own rules or an
  external service such as HAProxy.
- **Update Hooks** — run your own `pre`/`post` scripts on each update pass.
- **Automatic DNSBL sinkhole VIP** — pfBlockerNG can own the sinkhole Virtual
  IP for you instead of a manual setup.

> [!WARNING]
> **The `pfB_` alias prefix is reserved.** pfBlockerNG recognizes its own
> firewall aliases by the `pfB_` prefix and deletes any `pfB_`-named alias it
> does not currently manage. Never give your own aliases a `pfB_` name; they
> can still reference `pfB_*` aliases as members.

## Installation

> [!TIP]
> The package repository's landing page —
> **[pfblockerng.github.io/pkg](https://pfblockerng.github.io/pkg)** — is the
> main installation page: current versions, ready-to-copy commands, and older
> releases, per pfSense edition.

Run the bootstrap **on the firewall** over SSH (as root), then install the
package for the channel you want:

```sh
fetch -qo - https://pfblockerng.github.io/pkg/add-repo.sh | sh
pkg install pfSense-pkg-pfBlockerNG-devel    # or: pfSense-pkg-pfBlockerNG (stable)
```

The bootstrap detects your pfSense edition, version, and architecture,
configures the matching package catalog, and keeps it correct automatically
across pfSense OS upgrades. The repository takes precedence over the Netgate
catalog, so the webConfigurator's **Install**/**Update** buttons pick up its
builds too.

Three channels are available — the packages conflict, so install **one**:

| Channel | Package | For |
|---------|---------|-----|
| **Stable** | `pfSense-pkg-pfBlockerNG` | Production use |
| **Development** | `pfSense-pkg-pfBlockerNG-devel` | Latest features, early testing |
| **Nightly** | `pfSense-pkg-pfBlockerNG-nightly` | Bleeding edge (see [Nightly channel](#nightly-channel)) |

Choose **stable** unless you specifically want to track development builds.

Stable and development are also available from pfSense's built-in Package
Manager (**System ▸ Package Manager ▸ Available Packages**), built and shipped
by Netgate — see [Other installation methods](#other-installation-methods).

Once installed, the interface lives in the webConfigurator under
**Firewall ▸ pfBlockerNG**.

## Version upgrades

The **Software** tab shows your channel and installed version against the
repository's latest, and can check for and install updates for you. Upgrades
always stay **within the same channel** (stable to stable, devel to devel,
nightly to nightly); to switch channels, reinstall as in
[Installation](#installation). A daily background check also
raises a pfSense notification — once per new version — when a newer build is
available; a checkbox on the tab turns it off.

Upgrading from the command line works too:

```sh
pkg upgrade pfSense-pkg-pfBlockerNG-devel        # or the installed package name
```

> [!NOTE]
> On an install from the Netgate catalog the Software tab is absent —
> pfSense's own update badge already covers those installs.

## Usage

The
[Netgate documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html)
is the general configuration reference. Two additions are worth calling out.

### Update Hooks

Run your own script before (`pre`) or after (`post`) every update pass — for
example, to reload a downstream service when the blocklist changes. Place an
executable script (`#!` shebang, `chmod +x`) on the firewall in
`/usr/local/pkg/pfblockerng/hooks/`, named `hook_pre_<name>.sh` or
`hook_post_<name>.sh` (`.sh` or `.py`), then enable it on the Update page's
**Hooks** tab. Hooks run as root under a timeout; a failing hook is logged and
never aborts the update.

A hook receives what changed in environment variables:

| Variable | Value |
| --- | --- |
| `PFB_WHEN` | `pre` or `post` |
| `PFB_TRIGGER` | `cron` \| `update` \| `force-reload` |
| `PFB_IP_CHANGED` | `1` if a firewall **rule** changed this pass — a content-only alias refresh leaves it `0` |
| `PFB_DNSBL_CHANGED` | `1` if DNSBL data changed this pass |
| `PFB_CHANGED_IP_ALIASES` | space-separated IP aliases (`pfB_*`) whose contents changed (empty when none) |
| `PFB_CHANGED_DNSBL_GROUPS` | space-separated DNSBL groups (`DNSBL_*`) updated (empty when none) |
| `PFB_STATUS` | reserved — currently always `ok` |

> [!TIP]
> To act when the blocklist **data** changed, guard on a **non-empty**
> `PFB_CHANGED_IP_ALIASES`, not `PFB_IP_CHANGED=1` — the latter fires only on
> a rule change and misses content-only feed refreshes.

Example — reload HAProxy gracefully after an IP update. Save as
`/usr/local/pkg/pfblockerng/hooks/hook_post_haproxy.sh` (`chmod +x`), then
pick it as a `post` hook:

```sh
#!/bin/sh
# hook_post_haproxy.sh — reload HAProxy after an IP update
[ "$PFB_IP_CHANGED" = "1" ] && echo 'require_once("haproxy/haproxy.inc"); haproxy_check_run(1);' | /usr/local/sbin/pfSsh.php
```

More recipes (e.g. notifying a webhook), the trust model, and the full
contract are in
[CONTRIBUTING.md](CONTRIBUTING.md#update-hooks-prepost-update-scripts-adr-12).

### DNSBL Control (CLI)

When **DNSBL Control** is enabled (DNSBL settings), DNSBL can be driven at
runtime from the local root CLI — manually or from CRON/Scheduler tasks; all
events are logged to the Reports tab:

```sh
pfblockerng dnsbl-control disable [seconds]   # seconds: 1-3600
pfblockerng dnsbl-control enable
pfblockerng dnsbl-control addbypass <ip> [seconds]
pfblockerng dnsbl-control removebypass <ip>
```

> [!IMPORTANT]
> The older DNS-TXT transport (`drill TXT python_control.*`) is **deprecated**,
> off by default, and will be removed in a future release — switch any
> scheduled task to the CLI above.

## Other installation methods

### pfSense Package Manager

pfBlockerNG ships in pfSense's built-in package catalog: in the
webConfigurator go to **System ▸ Package Manager ▸ Available Packages**,
search for `pfBlockerNG`, and install **pfBlockerNG** (stable) or
**pfBlockerNG-devel** (development). These builds are published by Netgate and
generally lag this repository's releases.

### Nightly channel

To track the development tip rebuilt every night, opt into the separate
`nightly` channel:

```sh
fetch -qo - https://pfblockerng.github.io/pkg/add-repo.sh | sh -s -- --nightly
pkg install pfSense-pkg-pfBlockerNG-nightly
```

The nightly package **replaces** a stable or `-devel` install (they conflict);
switch back any time by re-running the bootstrap without `--nightly` and
`pkg install`-ing the release package you want. Recent nightly builds stay in
the catalog, so a regression can be undone by installing an older build
explicitly.

### Rolling back a release

The catalog keeps several recent versions of the stable and devel packages.
You can pin any retained version by naming it explicitly:

```sh
pkg install -f pfSense-pkg-pfBlockerNG-devel-<version>   # pin to an older devel build
pkg install -f pfSense-pkg-pfBlockerNG-<version>         # pin to an older stable build
```

The `-f` (force) flag is **required to roll back** — without it `pkg` refuses
to downgrade. The
[repository landing page](https://pfblockerng.github.io/pkg) lists the
retained versions per pfSense edition, with their commit and date.

> [!CAUTION]
> Rolling back across a schema-changing release may leave the stored
> `config.xml` in a format the older code cannot read. Test first in a
> non-production VM.

### Building from the FreeBSD ports tree

On a FreeBSD machine with the ports tree available, the package can be built
directly — `make package` in `net/pfSense-pkg-pfBlockerNG` (stable) or
`net/pfSense-pkg-pfBlockerNG-devel` (devel); the resulting `.pkg` lands in
`work/pkg/`.

## Documentation

- **Using pfBlockerNG:**
  [Netgate documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html).
- **Developing, testing, and releasing this package:**
  [CONTRIBUTING.md](CONTRIBUTING.md).

## License & credits

Licensed under the **Apache License, Version 2.0**.

- Original author: [BBcan177](https://github.com/BBcan177).
- Copyright © 2015–2026 Rubicon Communications, LLC (Netgate) and contributors.
- GeoIP data by MaxMind Inc. (GeoLite2).
