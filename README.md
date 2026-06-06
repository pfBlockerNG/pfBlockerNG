# pfBlockerNG

**IP and DNS blocking for [pfSense](https://www.pfsense.org/) (CE and Plus).**

pfBlockerNG downloads curated IP and domain feeds and turns them into live
firewall and DNS policy: IP feeds become pf alias tables with automatic firewall
rules, GeoIP lets you block or permit by country/continent, and DNSBL enforces
domain blocklists directly in the Unbound resolver. It adds reports, alerts, a
dashboard widget, and HA/CARP sync on top.

This repository is a community-maintained fork —
[andrebrait/pfBlockerNG](https://github.com/andrebrait/pfBlockerNG) — of the
original package by [BBcan177](https://github.com/BBcan177). It is licensed under
the **Apache License 2.0**.

> For day-to-day usage and configuration, the upstream
> [Netgate pfBlockerNG documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html)
> applies. This README covers what is specific to **installing this fork** and the
> features it adds on top; the per-feature design records live under
> [`.ADRs/`](.ADRs/).

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
- **Update Hooks** — run your own `pre`/`post` shell commands on each update pass
  (e.g. a graceful HAProxy reload), with a documented environment contract
  ([ADR-12](.ADRs/ADR_12_Update_Hooks/ADR.md)).
- **Automatic DNSBL sinkhole VIP** — pfBlockerNG can own the sinkhole Virtual IP
  for you instead of a manual setup
  ([ADR-13](.ADRs/ADR_13_Auto_DNSBL_VIP/ADR.md)).

## Release channels

Two channels track two branches of this repository:

| Channel | Branch | Package | For |
|---------|--------|---------|-----|
| **Stable** | `main` | `pfSense-pkg-pfBlockerNG` | Production use |
| **Development** | `devel` | `pfSense-pkg-pfBlockerNG-devel` | Latest features, early testing |

New work lands on `devel` first; once it has settled it is promoted to `main` to
cut a stable release. The two packages are mutually exclusive — install **one**.
Choose **stable** unless you specifically want to track development builds.

## Installation

### Option 1 — pfSense Package Manager

pfBlockerNG ships in pfSense's built-in package catalog. In the webConfigurator go
to **System ▸ Package Manager ▸ Available Packages**, search for `pfBlockerNG`, and
install **pfBlockerNG** (stable) or **pfBlockerNG-devel** (development). This is the
simplest path and the right one for most users.

### Option 2 — this fork's self-hosted `pkg` repository

To run **this fork's latest builds** — ahead of, and independent of, the Netgate
catalog — add our self-hosted FreeBSD `pkg` repository
([ADR-17](.ADRs/ADR_17_Pkg_Repository/ADR.md)). It resolves dependencies normally
(no `pkg add -f`). Run the bootstrap **on the firewall** over SSH, then install:

```sh
./scripts/add-repo.sh devel        # or: stable
pkg install pfSense-pkg-pfBlockerNG-devel
```

`add-repo.sh` writes `/usr/local/etc/pkg/repos/pfblockerng-<channel>.conf`, runs
`pkg update`, and verifies the package is visible. The configuration it writes is:

```sh
pfblockerng-devel: {
  url: "https://andrebrait.github.io/pfBlockerNG/${ABI}",
  mirror_type: none,
  signature_type: none,
  priority: 100,
  enabled: yes
}
```

- **`${ABI}`** is a `pkg(8)` variable (expanded by `pkg`, not the shell), so one
  configuration follows the box across a pfSense OS upgrade.
- The repository is **NONE-signed** — trust is anchored in HTTPS to the host.
- **`priority: 100`** places it above the Netgate `pfSense` repository, so cross-repo
  resolution (and the webConfigurator's **Install** button) picks our build.

> **Honest scope.** Because the repository sits above Netgate's, the GUI **Install**
> action and CLI `pkg install`/`upgrade` transparently pull our build. However,
> Available-Packages **discovery** and the GUI **"update available" badge** stay
> Netgate-bound (they query the `pfSense` repo only) — so newer builds are picked up
> via GUI Install or CLI `pkg upgrade`, not a GUI badge.

### Updating

```sh
pkg upgrade pfSense-pkg-pfBlockerNG-devel        # or the stable package name
```

### Building from the FreeBSD ports tree

On a FreeBSD machine with the ports tree available, the package can be built
directly — `make package` in `net/pfSense-pkg-pfBlockerNG` (stable) or
`net/pfSense-pkg-pfBlockerNG-devel` (devel); the resulting `.pkg` lands in
`work/pkg/`.

## Documentation

- **Using pfBlockerNG:**
  [Netgate documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html).
- **This fork's design decisions** (one record per feature/subsystem):
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
