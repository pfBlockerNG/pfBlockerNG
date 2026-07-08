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
firewall and DNS policy: IP feeds become pf alias tables with automatic firewall
rules, GeoIP lets you block or permit by country/continent, and DNSBL enforces
domain blocklists directly in the Unbound resolver. It adds reports, alerts, a
dashboard widget, and HA/CARP sync on top.

pfBlockerNG is developed in this repository —
[pfBlockerNG/pfBlockerNG](https://github.com/pfBlockerNG/pfBlockerNG) —
continuing the original package by [BBcan177](https://github.com/BBcan177),
under the **Apache License 2.0**.

> [!NOTE]
> For day-to-day usage and configuration, the
> [Netgate pfBlockerNG documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html)
> applies. This README covers **installation** and the **features added on top**
> of the classic pfBlockerNG; the per-feature design records live under
> [`.ADRs/`](.ADRs/).

## Table of contents

- [Features](#features)
- [Release channels](#release-channels)
- [Installation](#installation)
  - [Option 1 — pfSense Package Manager](#option-1--pfsense-package-manager)
  - [Option 2 — the pfBlockerNG `pkg` repository](#option-2--the-pfblockerng-pkg-repository)
  - [Building from the FreeBSD ports tree](#building-from-the-freebsd-ports-tree)
- [Version upgrades](#version-upgrades)
- [Usage](#usage)
  - [Update Hooks](#update-hooks)
  - [DNSBL Control (CLI)](#dnsbl-control-cli)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License & credits](#license--credits)

## Features

- **IP blocking** — IPv4/IPv6 feeds → pf alias tables + automatic firewall rules
  (Deny / Permit / Match / Native actions, inbound/outbound/both), with dedup,
  CIDR aggregation, and suppression of your own networks.
- **GeoIP** — block or permit by continent or country (MaxMind GeoLite2).
- **DNSBL** — domain blocklists enforced inside Unbound by a Python matcher;
  sinkhole-VIP or NULL responses, SafeSearch enforcement, and per-name reports.
- **Adblock Plus / EasyList feeds** — full ABP syntax parsed in Python: allow
  (`@@`) exceptions, regex rules, and `$important` / `$badfilter` precedence
  ([ADR-07](.ADRs/ADR_07_ABP_DNSBL_Support/ADR.md)).
- **IDN homoglyph protection** — a TR39 mixed-script analyzer blocks deceptive
  cross-script look-alike domains (e.g. a Cyrillic `аpple`)
  ([ADR-08](.ADRs/ADR_08_Homoglyph_Protection/ADR.md)).
- **Zero-downtime DNSBL updates** — feed/data updates swap the blocklist without
  restarting Unbound; queries keep flowing
  ([ADR-10](.ADRs/ADR_10_Zero_Downtime_DNSBL/ADR.md)).
- **Aggregated ("Uber") aliases** — opt-in Native aliases
  (`pfB_<Type>_Aggregated_v4`/`_v6`) holding the combined, CIDR-aggregated set of a
  whole action type, for reference by your own rules or an external service such as
  HAProxy ([ADR-11](.ADRs/ADR_11_Uber_Aliases/ADR.md)).
- **Update Hooks** — run your own `pre`/`post` scripts on each update pass
  (e.g. a graceful HAProxy reload), with a documented environment contract
  ([ADR-12](.ADRs/ADR_12_Update_Hooks/ADR.md)).
- **Automatic DNSBL sinkhole VIP** — pfBlockerNG can own the sinkhole Virtual IP
  for you instead of a manual setup
  ([ADR-13](.ADRs/ADR_13_Auto_DNSBL_VIP/ADR.md)).

> [!WARNING]
> **Reserved alias prefix (`pfB_`).** Every firewall alias pfBlockerNG creates is named with
> the `pfB_` prefix, and that prefix is how it recognizes its own aliases: on each reload it
> deletes any `pfB_`-named alias that is not one of its currently active aliases. **Do not give
> your own aliases a `pfB_` name** — including an "alias of aliases" that groups pfB tables — or
> pfBlockerNG will remove it on the next reload. Name such aliases without the `pfB_` prefix;
> they can still reference `pfB_*` aliases as members.

## Release channels

Two channels track two branches of this repository:

| Channel | Branch | Package | For |
|---------|--------|---------|-----|
| **Stable** | `main` | `pfSense-pkg-pfBlockerNG` | Production use |
| **Development** | `devel` | `pfSense-pkg-pfBlockerNG-devel` | Latest features, early testing |
| **Nightly** | `devel` (HEAD, built nightly) | `pfSense-pkg-pfBlockerNG-nightly` | Bleeding edge; Option 2 repo only |

New work lands on `devel` first; once it has settled it is promoted to `main` to
cut a stable release. **Nightly** rebuilds the `devel` tip each night as a separate,
opt-in package available **only** from the pfBlockerNG package repository (Option 2).
The three packages are mutually exclusive — install **one**. Choose **stable** unless
you specifically want to track development builds.

Releases follow semantic versioning: development releases are pre-releases
(`vX.Y.Z.alpha.N`, `vX.Y.Z.beta.N`, `vX.Y.Z.rc.N`) and stable releases are plain
`vX.Y.Z`.

## Installation

> [!TIP]
> The package repository's landing page —
> **[pfblockerng.github.io/pkg](https://pfblockerng.github.io/pkg)** — is the
> main installation page: it always shows the current package versions, ready-to-copy
> bootstrap and install commands, per-edition package tables, and the retained older
> releases. The instructions below are kept as a reference.

### Option 1 — pfSense Package Manager

pfBlockerNG ships in pfSense's built-in package catalog. In the webConfigurator go
to **System ▸ Package Manager ▸ Available Packages**, search for `pfBlockerNG`, and
install **pfBlockerNG** (stable) or **pfBlockerNG-devel** (development). This is the
simplest path and the right one for most users.

### Option 2 — the pfBlockerNG `pkg` repository

To run the **latest builds** — ahead of, and independent of, the Netgate
catalog — add the pfBlockerNG FreeBSD `pkg` repository. Run the bootstrap
**on the firewall** over SSH (as root), then install the package you want:

```sh
fetch -qo - https://pfblockerng.github.io/pkg/add-repo.sh | sh
pkg install pfSense-pkg-pfBlockerNG-devel    # or: pfSense-pkg-pfBlockerNG (stable)
```

The bootstrap detects your pfSense edition, version, and architecture and configures
the matching package catalog — and keeps it correct automatically across pfSense OS
upgrades. The repository is served over HTTPS and takes precedence over the Netgate
catalog, so the webConfigurator's **Install**/**Update** buttons pick up its builds
too. Design details live in [ADR-17](.ADRs/ADR_17_Pkg_Repository/ADR.md),
[ADR-20](.ADRs/ADR_20_CE_Plus_Variant_Distribution/ADR.md), and
[ADR-39](.ADRs/ADR_39_Meta_Package_Distribution/ADR.md).

#### Nightly channel (bleeding edge)

To track the **`devel` tip rebuilt every night**, opt into the separate `nightly`
channel:

```sh
fetch -qo - https://pfblockerng.github.io/pkg/add-repo.sh | sh -s -- --nightly
pkg install pfSense-pkg-pfBlockerNG-nightly
```

The nightly package **replaces** a stable or `-devel` install (they conflict); switch
back any time by re-running the bootstrap without `--nightly` and `pkg install`-ing
the release package you want. Recent nightly builds stay in the catalog, so a
regression can be undone by installing an older build explicitly.

#### Rolling back a stable or devel release

The catalog keeps several recent versions of the stable and devel packages. You can
pin any retained version by naming it explicitly:

```sh
pkg install -f pfSense-pkg-pfBlockerNG-devel-<version>   # pin to an older devel build
pkg install -f pfSense-pkg-pfBlockerNG-<version>         # pin to an older stable build
```

The `-f` (force) flag is **required to roll back** — without it `pkg` refuses to
downgrade. The **repository landing page**
([pfblockerng.github.io/pkg](https://pfblockerng.github.io/pkg)) lists the retained
versions per pfSense edition, with their commit and date — use it to find the version
string.

> [!CAUTION]
> **Config-schema note:** rolling back across a schema-changing release may leave the stored
> `config.xml` in a format the older code cannot read. Test first in a non-production VM.

### Building from the FreeBSD ports tree

On a FreeBSD machine with the ports tree available, the package can be built
directly — `make package` in `net/pfSense-pkg-pfBlockerNG` (stable) or
`net/pfSense-pkg-pfBlockerNG-devel` (devel); the resulting `.pkg` lands in
`work/pkg/`.

## Version upgrades

On a build installed from the pfBlockerNG package repository (Option 2), every
pfBlockerNG page has a **Software** tab
([ADR-19](.ADRs/ADR_19_Update_Channel_Panel/ADR.md)): it shows your channel and
installed version against the repository's latest, and can check for and install
updates for you. Upgrades always stay **within the same channel** (stable to stable,
devel to devel, nightly to nightly); to switch channels, reinstall as in Option 2.
A daily background check also raises a pfSense notification — once per new version —
when a newer build is available; a checkbox on the tab turns it off.

Upgrading from the command line works too, on any install:

```sh
pkg upgrade pfSense-pkg-pfBlockerNG-devel        # or the stable package name
```

> [!NOTE]
> On a stock install from the Netgate catalog (Option 1) the Software tab is absent —
> pfSense's own update badge already covers those installs.

## Usage

Most configuration lives in the webConfigurator under **Firewall ▸ pfBlockerNG**;
the [Netgate documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html)
is the general reference. A few notable additions are worth calling out.

### Update Hooks

The Update page's **Hooks** tab runs your own script at the start (`pre`) and end (`post`)
of every update pass — for example to reload a downstream service when the blocklist
changes. For security the hook is a **script file you place on the firewall**, not a
command typed into the GUI: author it over SSH/console (root shell) in
`/usr/local/pkg/pfblockerng/hooks/`, name it `hook_pre_<name>.sh` or
`hook_post_<name>.sh` (`.sh` or `.py`), and make it executable (`chmod +x`, with a
`#!` shebang) — then the tab's picker selects it. Each enabled hook runs as root (the
same trust class as pfSense's `shellcmd`/cron) under a timeout; a hook's failure is
logged and never aborts the update, and with no enabled hooks the pass is unchanged.

A `post` hook receives this environment:

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
> `PFB_CHANGED_IP_ALIASES`, not `PFB_IP_CHANGED=1` — the latter fires only on a rule
> change and misses content-only feed refreshes.

**Reload HAProxy after an IP update** — the motivating use case: block a
Cloudflare-fronted real client IP via an aggregate alias, refreshed by a graceful
HAProxy reload. Save this as
`/usr/local/pkg/pfblockerng/hooks/hook_post_haproxy.sh` (`chmod +x`), then
pick it as a `post` hook:

```sh
#!/bin/sh
# hook_post_haproxy.sh — reload HAProxy after an IP update
[ "$PFB_IP_CHANGED" = "1" ] && echo 'require_once("haproxy/haproxy.inc"); haproxy_check_run(1);' | /usr/local/sbin/pfSsh.php
```

**Notify a webhook of what changed** — fires on any blocklist-data change (including
content-only refreshes). Each field rides its own `--data-urlencode` so the
space-separated lists are encoded correctly. Save as
`/usr/local/pkg/pfblockerng/hooks/hook_post_webhook.sh` (`chmod +x`), then pick
it as a `post` hook:

```sh
#!/bin/sh
# hook_post_webhook.sh — notify a webhook of what changed
{ [ -n "$PFB_CHANGED_IP_ALIASES" ] || [ -n "$PFB_CHANGED_DNSBL_GROUPS" ]; } && /usr/local/bin/curl -sS -m 5 \
  --data-urlencode "ip_aliases=$PFB_CHANGED_IP_ALIASES" \
  --data-urlencode "dnsbl_groups=$PFB_CHANGED_DNSBL_GROUPS" \
  https://example.invalid/pfblockerng-update
```

The full trust model, the complete HAProxy frontend ACL setup, and the URL-encoding
rules are in [ADR-12](.ADRs/ADR_12_Update_Hooks/ADR.md) and
[CONTRIBUTING.md](CONTRIBUTING.md#update-hooks-prepost-update-scripts-adr-12).

### DNSBL Control (CLI)

When **DNSBL Control** is enabled (DNSBL settings), DNSBL can be driven at runtime
through the local root CLI:

```sh
pfblockerng dnsbl-control disable [seconds]   # seconds: 1-3600
pfblockerng dnsbl-control enable
pfblockerng dnsbl-control addbypass <ip> [seconds]
pfblockerng dnsbl-control removebypass <ip>
```

These commands can be incorporated in CRON/Scheduler tasks or run manually; all events
are logged to the Reports tab.

> [!IMPORTANT]
> **Migration:** the older `drill TXT python_control.*` DNS-TXT transport is
> **deprecated** and **off by default**. Switch any CRON/Scheduler task to the
> `pfblockerng dnsbl-control` CLI above. The **DNSBL Control (legacy DNS TXT)** sub-toggle
> re-enables the old path for migration; it is **deprecated**, **less secure**, and will be
> **removed in a future release**.

## Documentation

- **Using pfBlockerNG:**
  [Netgate documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html).
- **Design decisions** (one record per feature/subsystem):
  [`.ADRs/`](.ADRs/).
- **Developing, testing, and releasing this package:**
  [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

Development setup, the test suites (unit, PHP, shell, and the live-VM smoke / Web UI
tiers), linting, the build and release pipelines, and the internals of each
subsystem are all documented in **[CONTRIBUTING.md](CONTRIBUTING.md)**.

## License & credits

Licensed under the **Apache License, Version 2.0**.

- Original author: [BBcan177](https://github.com/BBcan177).
- Copyright © 2015–2026 Rubicon Communications, LLC (Netgate) and contributors.
- GeoIP data by MaxMind Inc. (GeoLite2).
