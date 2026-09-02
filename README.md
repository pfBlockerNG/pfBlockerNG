<div align="center">

<img src="docs/assets/logo.svg" alt="pfBlockerNG logo" width="150">

<h1>pfBlockerNG</h1>

<p><strong>This is the OFFICIAL repository for pfBlockerNG</strong></p>
<p>pfBlockerNG is created by <a href="https://github.com/BBcan177">BBcan177</a>, who designs, supports and maintains it with <a href="https://github.com/andrebrait">André Brait</a>.</p>
<p>
  <a href="https://github.com/pfBlockerNG/pfBlockerNG/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/pfBlockerNG/pfBlockerNG/test.yml?branch=devel&label=tests" alt="Tests"></a>
  <a href="https://github.com/pfBlockerNG/pfBlockerNG/releases"><img src="https://img.shields.io/github/v/release/pfBlockerNG/pfBlockerNG?label=release&color=blue" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/pfBlockerNG/pfBlockerNG?color=green" alt="License: Apache-2.0"></a>
</p>

</div>

pfBlockerNG downloads curated IP and domain feeds and turns them into live
firewall and DNS policy: IP feeds become firewall rules, GeoIP lets you block
or permit by country, and DNSBL enforces domain blocklists directly in the
Unbound resolver. It adds reports, alerts, a dashboard widget, and HA/CARP
sync on top.

> [!NOTE]
> For day-to-day usage and configuration, start with the
> [official pfBlockerNG documentation](https://pfblockerng.com/).

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
> **[pkg.pfblockerng.com](https://pkg.pfblockerng.com)** — is the
> main installation page: current versions, ready-to-copy commands, and older
> releases, per pfSense edition.

Run this **on the firewall** over SSH (as root), picking the channel you want:

```sh
t=$(mktemp "${TMPDIR:-/tmp}/pfb-install.XXXXXX") && fetch -T 60 -o "$t" https://pkg.pfblockerng.com/install.sh && [ -s "$t" ] && /bin/sh "$t" --channel stable; e=$?; [ -n "$t" ] && rm -f "$t"; (exit $e)
```

One command from **any** starting state: a fresh firewall, an existing Netgate
Package Manager install, a legacy `pfSense-pkg-pfBlockerNG-devel` install, or an
install already on a different channel. It subscribes the firewall to the
channel, installs or moves the package onto it, and is safe to re-run — a
firewall already converged performs no changes.

The script detects your pfSense edition and version, configures the matching
package catalog, and keeps it correct automatically across pfSense OS upgrades.
The repository takes precedence over the Netgate catalog, so the
webConfigurator's **Install**/**Update** buttons pick up its builds too.

Four channels are available, selected with `--channel`. They all publish the
**same** package name — `pfSense-pkg-pfBlockerNG` — from separate catalogs, so
a firewall subscribes to **exactly one** channel and the script removes any
other pfBlockerNG repository it finds:

| Channel | `--channel` | For |
|---------|-------------|-----|
| **Stable** | `stable` | Production use |
| **Testing** | `testing` | Prereleases validating the next stable |
| **Edge** | `edge` | Prereleases opening the next release family |
| **Nightly** | `nightly` | Bleeding edge, rebuilt from the development tip |

Choose **stable** unless you specifically want to track prerelease builds.

pfBlockerNG is also available from pfSense's built-in Package Manager
(**System ▸ Package Manager ▸ Available Packages**), built and shipped by
Netgate — see [Other installation methods](#other-installation-methods).

Once installed, the interface lives in the webConfigurator under
**Firewall ▸ pfBlockerNG**.

### Switching channels

Run the same one-liner as [Installation](#installation), just with a
different `--channel`:

```sh
t=$(mktemp "${TMPDIR:-/tmp}/pfb-install.XXXXXX") && fetch -T 60 -o "$t" https://pkg.pfblockerng.com/install.sh && [ -s "$t" ] && /bin/sh "$t" --channel edge; e=$?; [ -n "$t" ] && rm -f "$t"; (exit $e)
```

It moves the subscription, moves the installed package onto it, replaces a
legacy suffixed install (`pfSense-pkg-pfBlockerNG-devel`, `-nightly`) with the
canonical package, and verifies the result — identity, source repository,
version, installed files, and your pfBlockerNG configuration — before
reporting success. It refuses to touch anything it cannot verify, and going
**back** to a slower channel works the same way (that direction is a
downgrade, which is exactly the operation it performs). Moving **across**
release families (not just channels) prints a warning and proceeds — older
builds may not understand configuration state a newer build wrote.

> [!CAUTION]
> Back up the pfSense configuration (**Diagnostics ▸ Backup & Restore**) before
> moving to an older version. Older package artifacts remain available, but may
> not understand state written by a newer package; configuration or enforcement
> may fail. Recover by restoring that pre-move backup.

## Version upgrades

The **Software** tab shows your channel and installed version against the
repository's latest, and can check for and install updates for you. Upgrades
stay **within the channel you are subscribed to**; to move to a different one,
see [Switching channels](#switching-channels). A daily background check also
raises a pfSense notification — once per new version — when a newer build is
available; a checkbox on the tab turns it off.

Upgrading from the command line works too:

```sh
pkg upgrade pfSense-pkg-pfBlockerNG
```

> [!NOTE]
> On an install from the Netgate catalog the Software tab is absent —
> pfSense's own update badge already covers those installs.

## Usage

The [official documentation](https://pfblockerng.com/) is the
general configuration reference. Two additions are worth calling out.

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
| `PFB_POST_INSTALL` | `1` when this pass is the install/upgrade resync, else `0` |
| `PFB_PRE_UNINSTALL` | `1` when this pass is the pre-uninstall teardown, else `0` |
| `PFB_PKG_OP` | package-manager operation driving the pass — `install`, `upgrade`, `reinstall`, `delete`, or empty on a normal cron/manual update |

> [!TIP]
> To act when the blocklist **data** changed, guard on a **non-empty**
> `PFB_CHANGED_IP_ALIASES`, not `PFB_IP_CHANGED=1` — the latter fires only on
> a rule change and misses content-only feed refreshes.

For a worked example — a `post` hook that reloads HAProxy when pfBlockerNG's
aggregated aliases change — see
[this gist](https://gist.github.com/andrebrait/ee3a39dac388db0f2581be3a19449a7c).

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

### Migrating a legacy install

Installs made before the four-channel catalogs carry a suffixed package name —
`pfSense-pkg-pfBlockerNG-devel` or `pfSense-pkg-pfBlockerNG-nightly`. Those
names are no longer published, so they receive no further updates. Move one onto
a channel with the same one-liner as [Installation](#installation): it removes
the legacy package, installs the canonical `pfSense-pkg-pfBlockerNG` from the
channel you named, and verifies your configuration survived.

### Retained package versions

Each channel catalog keeps several recent versions, and a faster channel also
keeps everything its slower channels still carry — so an older build stays
available in the catalog you are already subscribed to. The
[repository landing page](https://pkg.pfblockerng.com) lists the retained
versions per pfSense edition, with their commit and date. Moving to one of them
is a channel-style downgrade; see the caution under
[Switching channels](#switching-channels).

### Building from the FreeBSD ports tree

On a FreeBSD machine with the ports tree available, the package can be built
directly — `make package` in `net/pfSense-pkg-pfBlockerNG` (stable) or the
channel recipe you want, e.g. `net/pfSense-pkg-pfBlockerNG-edge` (the line the
`devel` branch builds); the resulting `.pkg` lands in `work/pkg/`.

## Documentation

- **Using pfBlockerNG:**
  [official user documentation](https://pfblockerng.com/).
- **Installing project builds:**
  [package repository](https://pkg.pfblockerng.com).
- **Developing, testing, and releasing this package:**
  [CONTRIBUTING.md](CONTRIBUTING.md).

## License & credits

Licensed under the **Apache License, Version 2.0**.

- Created by: [BBcan177](https://github.com/BBcan177).
- Copyright © 2015–2026 Rubicon Communications, LLC (Netgate) and contributors.
- GeoIP data by MaxMind Inc. (GeoLite2).
