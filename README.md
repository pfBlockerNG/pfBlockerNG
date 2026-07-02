# pfBlockerNG

**IP and DNS blocking for [pfSense](https://www.pfsense.org/) (CE and Plus).**

pfBlockerNG downloads curated IP and domain feeds and turns them into live
firewall and DNS policy: IP feeds become pf alias tables with automatic firewall
rules, GeoIP lets you block or permit by country/continent, and DNSBL enforces
domain blocklists directly in the Unbound resolver. It adds reports, alerts, a
dashboard widget, and HA/CARP sync on top.

This repository is a community-maintained fork —
[pfBlockerNG/pfBlockerNG](https://github.com/pfBlockerNG/pfBlockerNG) — of the
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
- **Update Hooks** — run your own `pre`/`post` scripts on each update pass
  (e.g. a graceful HAProxy reload), with a documented environment contract
  ([ADR-12](.ADRs/ADR_12_Update_Hooks/ADR.md)).
- **Automatic DNSBL sinkhole VIP** — pfBlockerNG can own the sinkhole Virtual IP
  for you instead of a manual setup
  ([ADR-13](.ADRs/ADR_13_Auto_DNSBL_VIP/ADR.md)).

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
| **Nightly** | `devel` (HEAD, built nightly) | `pfSense-pkg-pfBlockerNG-nightly` | Bleeding edge; self-hosted repo only |

New work lands on `devel` first; once it has settled it is promoted to `main` to
cut a stable release. **Nightly** rebuilds the `devel` tip each night as a separate,
opt-in package available **only** from this fork's self-hosted repository (Option 2).
The three packages are mutually exclusive — install **one**. Choose **stable** unless
you specifically want to track development builds.

Releases follow semantic versioning. Development releases are pre-release tags cut
from `devel` — `vX.Y.Z.alpha.N` (alpha), `vX.Y.Z.beta.N` (beta), `vX.Y.Z.rc.N`
(release candidate) — and stable releases are plain `vX.Y.Z`, cut from `main`. The
corresponding package versions order naturally for `pkg` (`4.0.0.alpha.1` <
`4.0.0.beta.1` < `4.0.0.rc.1` < `4.0.0`). Nightly builds are not published as GitHub
releases.

In the self-hosted repository the **stable** and **development** packages are served
from a single repo (`pfblockerng`) — exactly as Netgate ships `pfSense-pkg-pfBlockerNG`
and `-devel` from its one `pfSense` repo — so one bootstrap exposes both; you pick which
to `pkg install`. **Nightly** sits on its own catalog path and so has its own repo conf.

## Installation

### Option 1 — pfSense Package Manager

pfBlockerNG ships in pfSense's built-in package catalog. In the webConfigurator go
to **System ▸ Package Manager ▸ Available Packages**, search for `pfBlockerNG`, and
install **pfBlockerNG** (stable) or **pfBlockerNG-devel** (development). This is the
simplest path and the right one for most users.

### Option 2 — this fork's self-hosted `pkg` repository

To run **this fork's latest builds** — ahead of, and independent of, the Netgate
catalog — add our self-hosted FreeBSD `pkg` repository
([ADR-17](.ADRs/ADR_17_Pkg_Repository/ADR.md),
[ADR-20](.ADRs/ADR_20_CE_Plus_Variant_Distribution/ADR.md)). It resolves dependencies
normally (no `pkg add -f`). Run the bootstrap **on the firewall** over SSH, then install:

From a **checkout** (over SSH, cloned onto the box):

```sh
./scripts/add-repo.sh                       # adds the shared `pfblockerng` repo (stable + devel)
pkg install pfSense-pkg-pfBlockerNG-devel    # or: pfSense-pkg-pfBlockerNG (stable)
```

Or run the **published one-file bootstrap** (no checkout needed — safe to pipe; the hook
is embedded so it works when the script is not run from a file on disk):

```sh
fetch -qo - https://pfblockerng.github.io/pkg/add-repo.sh | sh
pkg install pfSense-pkg-pfBlockerNG-devel
```

`add-repo.sh` with no argument installs a small boot-time `rc.d` hook
(`pfblockerng_repo_generate.sh`), which detects the pfSense variant (CE vs Plus),
version, and arch and writes `/usr/local/etc/pkg/repos/pfblockerng.conf` pointing
**directly** to the correct, fully-resolved variant catalog on GitHub Pages (which
carries **both** the stable and devel packages — pick one at `pkg install`); the
bootstrap then runs `pkg update` and verifies a package is visible. The **nightly**
repo is opt-in — `./scripts/add-repo.sh --nightly` writes its own
`pfblockerng-nightly.conf` (bleeding edge, not for daily use). The configuration the
default run writes on a CE 2.8 / amd64 box is:

```sh
# Generated at boot by pfblockerng_repo_generate (ADR-39) — do not edit; re-run add-repo.sh to change.
pfblockerng: {
  url: "https://pfblockerng.github.io/pkg/release/ce-2.8/amd64",
  mirror_type: none,
  signature_type: none,
  priority: 100,
  enabled: yes
}
```

(Plus boxes get `release/plus-26.03/<arch>` instead of `release/ce-2.8/amd64`.)

- The URL is **fully resolved** for the box's edition/version/arch (no `${ABI}` token).
  The `rc.d` hook **regenerates** the whole conf on every boot, so after a pfSense OS
  upgrade (e.g. CE 2.8 → 2.9, which always reboots) the URL self-corrects to the new
  variant catalog with no manual step — local-file-only, no `pkg` call, ordered before
  any network catalog fetch ([ADR-39](.ADRs/ADR_39_Meta_Package_Distribution/ADR.md)).
- The repository is **NONE-signed** — trust is anchored in HTTPS to the host.
- **`priority: 100`** places it above the Netgate `pfSense` repository, so cross-repo
  resolution (and the webConfigurator's **Install** button) picks our build.

#### Nightly channel (bleeding edge)

To track the **`devel` tip rebuilt every night**, opt into the separate `nightly`
channel — a distinct package `pfSense-pkg-pfBlockerNG-nightly` served from a
`nightly/` catalog subtree:

```sh
./scripts/add-repo.sh --nightly             # from a checkout, or:
# fetch -qo - https://pfblockerng.github.io/pkg/add-repo.sh | sh -s -- --nightly
pkg install pfSense-pkg-pfBlockerNG-nightly
```

It **conflicts with the stable and `-devel` packages** (they install the same files),
so it replaces whichever you had; switch back any time with `./scripts/add-repo.sh`
and `pkg install` the release package you want (`pfSense-pkg-pfBlockerNG` or `-devel`).
Nightly versions order as
`<target>.YYYYMMDD.N`, so `pkg upgrade` always moves to the newest build, and the
source commit rides the package — `pkg info -A pfSense-pkg-pfBlockerNG-nightly` shows it.
The **last 14 builds** are kept, so you can roll back by installing an older version
explicitly (`pkg install pfSense-pkg-pfBlockerNG-nightly-<version>`).

#### Rolling back a stable or devel release

When the self-hosted repository is configured with a retention depth greater than one,
the release catalog lists **multiple versions** of the stable and devel packages. You can
pin to any retained version by specifying it explicitly:

```sh
pkg install -f pfSense-pkg-pfBlockerNG-devel-<version>   # pin to an older devel build
pkg install -f pfSense-pkg-pfBlockerNG-<version>         # pin to an older stable build
```

The `-f` (force) flag is **required to roll back**: `pkg install` never downgrades over a
newer already-installed build, so without it the command is a no-op. Dependencies are still
resolved from the catalog (unlike `pkg add <url>`). `pkg install <name>` with no version
always resolves the **highest** version listed in the catalog (newest-wins). Only the configured N most recent devel releases and M most recent
stable releases are retained; builds older than that window are no longer in the catalog. The
**repository landing page** ([pfblockerng.github.io/pkg](https://pfblockerng.github.io/pkg))
shows an "Older releases" disclosure per pfSense edition listing the retained versions with
their commit and date — use it to find the version string to pass to `pkg install`.

> **Config-schema note:** rolling back across a schema-changing release may leave the stored
> `config.xml` in a format the older code cannot read. Test first in a non-production VM.

### Updating

```sh
pkg upgrade pfSense-pkg-pfBlockerNG-devel        # or the stable package name
```

### Building from the FreeBSD ports tree

On a FreeBSD machine with the ports tree available, the package can be built
directly — `make package` in `net/pfSense-pkg-pfBlockerNG` (stable) or
`net/pfSense-pkg-pfBlockerNG-devel` (devel); the resulting `.pkg` lands in
`work/pkg/`.

## Usage

Most configuration lives in the webConfigurator under **Firewall ▸ pfBlockerNG**;
the [Netgate documentation](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html)
is the general reference. A couple of this fork's additions are worth calling out.

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

### Software tab — version + update notice for self-hosted builds

When pfBlockerNG was installed from **this fork's self-hosted repository** (Option 2
above), a **Software** tab appears on every pfBlockerNG page
([ADR-19](.ADRs/ADR_19_Update_Channel_Panel/ADR.md)). It is the substitute for the stock
GUI's "update available" badge, which only ever tracks the Netgate catalog and cannot see
our builds. The tab shows your current **channel** (stable / devel / nightly) and
**installed version** against **our repository's latest**, plus the last-checked time, and
offers two buttons:

- **Check now** — refresh the comparison from our repo (reads `pkg … -r <ourrepo>`, never
  the Netgate repo).
- **Update now** — a **same-channel** `pkg upgrade` of the installed package, streamed live
  (it never switches channels). The button is enabled only when an update is available.

> The Software tab, the page, and the update notice are present **only on a build installed
> from one of our repos** (`pfblockerng` / `pfblockerng-nightly`). On a stock
> **Netgate-ports** install they are **entirely absent** — Netgate's own repo-bound badge
> already serves those users, so ours would be redundant.

A daily background check (riding the existing pfBlockerNG cron) compares installed vs our
latest and raises a **de-duped notification** when a newer build exists — the pfSense bell
plus whatever remote channels you have configured (SMTP / Telegram / Pushover / Slack). It
fires **once per new version**, not once per day. It is governed by a single checkbox on the
Software tab, **Check for new versions** (`pfb_software_check`), **enabled by default** and
applied equally on every channel: when enabled, pfBlockerNG checks our repository and notifies
you of a newer build; untick it to stop the background checks and notifications. The page's
**Check now** button always runs a one-off check regardless of the setting.

Cross-channel **switching** from the GUI is not offered (the selector is read-only); switch
channels with `add-repo.sh` + `pkg install` as in Option 2 above.

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

> **Migration:** the older `drill TXT python_control.*` DNS-TXT transport is
> **deprecated** and **off by default**. Switch any CRON/Scheduler task to the
> `pfblockerng dnsbl-control` CLI above. The **DNSBL Control (legacy DNS TXT)** sub-toggle
> re-enables the old path for migration; it is **deprecated**, **less secure**, and will be
> **removed in a future release**.

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
