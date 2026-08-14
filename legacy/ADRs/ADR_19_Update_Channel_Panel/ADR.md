# ADR-19: A pfBlockerNG-owned "Software" update/channel panel + new-version notice

> **Amendment (2026-06-14, PR #216):** This (Proposed) design below assumes the per-channel
> conf section name is unchanged — `pfblockerng-devel` for devel, `pfblockerng` for stable.
> That no longer holds: `scripts/add-repo.sh` now writes ONE shared `pfblockerng` repo
> (`pfblockerng.conf`) for **both** stable and devel; only `nightly` is separate
> (`pfblockerng-nightly`). When this ADR is implemented, `pfb_pkg_repo_name_for_channel()`
> must map **both** stable and devel to `pfblockerng` (the channel selects the *package* —
> `pfSense-pkg-pfBlockerNG` vs `-devel` — not a per-channel repo name).
>
> **Amendment (2026-06-15, maintainer directive) — two hard constraints:**
>
> 1. **Provenance gate: the Software tab, the `pfblockerng_software.php` page, AND the cron
>    update `file_notice` are present ONLY on a build installed from one of OUR repos.**
>    When pfBlockerNG was installed from the **Netgate ports channel** (the stock `pfSense`
>    repo), the tab, the page, and the notice are **ENTIRELY ABSENT** — a Netgate-installed
>    add-on shows no update page and raises no update notification (Netgate's own
>    repo-bound badge already serves those users; ours would be redundant and is unwanted
>    there). Provenance is read from **`pkg query '%R' <pkgname>`** (the repo a package was
>    installed FROM); a **pure** `pfb_software_is_our_build($installed_repo)` returns true
>    only for `pfblockerng` / `pfblockerng-nightly`. The tab append, the page's top-of-file
>    guard, the `match[]` priv line, AND the cron notice all gate on it. Pinned both ways in
>    PHPUnit (ours → present; `pfSense` / empty / unknown → absent) and by a `repo`-smoke
>    case: a Netgate-decoy-installed box shows **no** Software tab and raises **no** notice;
>    an our-repo-installed box shows both.
> 2. **Nightly is the only separate channel.** stable + devel share ONE repo (`pfblockerng`)
>    and differ only by package name (`pfSense-pkg-pfBlockerNG` vs `-devel`); **nightly**
>    (`pfSense-pkg-pfBlockerNG-NIGHTLY`, repo `pfblockerng-nightly`) is the sole separately-
>    channelled build. "Read latest" maps channel -> repo: stable/devel -> `-r pfblockerng`,
>    nightly -> `-r pfblockerng-nightly`.

**Amendment (2026-06-19):** The background cron check now gates on `pfb_software_provenance_ok()` — the same predicate that gates the Software page's visibility — so the page and the background check share one displayability condition. A build that is not page-displayable (not installed from our repo, or overridden off) performs no background check and raises no update notice, even if "Check for new versions" remains enabled from a prior our-repo install.

- **Status:** **Accepted** (2026-06-15) — landed on `devel` (PR #232, rebase-merged);
  validated by the off-box gates + the live-VM `repo` positive journey and the `ui_render`
  negative gate. No separate manual maintainer sign-off is required per the CLAUDE.md
  "ADR acceptance — automated tests, not a manual maintainer sign-off" directive.
- **Date:** 2026-06-06
- **Branch:** `adr/19-update-channel-panel` (off **`devel`**; `{slug}` = sanitised
  ADR-title slug per CLAUDE.md "Branch naming") / **Component(s):** shipped `src/`
  GUI — a new `src/usr/local/www/pfblockerng/pfblockerng_software.php` page (+ its
  tab entry on every pfBlockerNG page and a `priv` match line), a small set of
  **pure** version/channel helpers + a thin pkg-IO wrapper in
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc`, a cron-driven background check
  raising a de-duped `file_notice`, and one new config knob. **Consumes, does not
  modify:** ADR-17's self-hosted repo (`scripts/add-repo.sh`, the per-`${ABI}`
  catalog) and ADR-18's nightly channel.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the page + helpers; POSIX `sh`
  for any client-side repo bootstrap reused from `scripts/add-repo.sh`. The version
  check shells to the base `pkg` binary on the live box. **This is the first
  pfBlockerNG ADR that ships `src/` GUI code** (ADR-17/18 were distribution-only).
- **Test suite:** `tests/php/` (PHPUnit — the pure helpers, loaded off-appliance via
  the real `pfblockerng.inc` + doubles); `tests/smoke/ui/` (ADR-14 Tier-A
  `ui_render` gate — the new page renders); `tests/smoke/test_repo_install.py`
  (ADR-17 `repo` marker — the end-to-end "newer build → notice + Update" journey on
  the live VM). Default `python -m pytest` stays unchanged.

---

## 1. Context

### Today (verified on `devel` @ 41d4a18, and against upstream `pfsense/pfSense` `master`)

1. **The GUI Install button already pulls our build — installation is NOT the gap.**
   `pkg_install()` (upstream `src/etc/inc/pkg-utils.inc:284`) runs
   `pkg install -y <name>` with **no `-r`**, so `pkg` resolves across all enabled
   repos and selection is keyed first on repo `priority:`. ADR-17's `add-repo.sh`
   sets our `priority: 100` above Netgate's `pfSense` repo (`0`), so the stock
   webConfigurator **Install** of `pfSense-pkg-pfBlockerNG-devel` already installs
   **our** build (ADR-17 §1.3, Phase-1 live-VM verified). This ADR adds **awareness +
   one-click same-channel update + opt-in notification** on top — not install.

2. **Discovery and the displayed version are hard-locked to the `pfSense` repo.**
   `get_pkg_info()` (upstream `pkg-utils.inc:350`) sets, for any `pfSense-pkg-*`,
   `$repo_param = "-r {$g['product_name']}"` → `pkg search -r pfSense …`
   (`pkg-utils.inc:407`), after running `pfSense-repo-setup`. So both the **Available
   Packages list entry** and the **version string the GUI shows** come **only** from
   the repo *named* `pfSense` (Netgate's). A third-party repo cannot inject a row nor
   change the shown version — and that file is base-system code pfBlockerNG does not
   ship and cannot patch.

3. **Both "update available" badges are Netgate-bound and out of our reach.**
   - **Per-package** (Installed Packages page): same `get_pkg_info()` `-r pfSense`
     path → "newer version" compares installed vs **Netgate's** catalog, never ours.
   - **System badge** `get_system_pkg_version()` (`pkg-utils.inc:1351`) inspects only
     `get_core_pkg_names()` / `get_meta_pkg_name()` (`:1307` / `:1294`) — base /
     core / meta packages. pfBlockerNG is **not in scope at all**.
   → Even though our repo wins an actual install, the GUI's **display** reads
   Netgate. This is the **ceiling**: we cannot fix the stock badge from a package; we
   can only ship **our own** indicator + notice as the substitute.

4. **pfSense has a first-class notification API we already use.** `file_notice($id,
   $notice, $category = "General", $url = "", $priority = 1, $local_only = false)`
   (upstream `src/etc/inc/notices.inc:110`) raises a **GUI bell notice** and, unless
   `$local_only`, queues **remote fan-out** to whatever the admin configured
   (SMTP / Telegram / Pushover / Slack — `notices.inc:373/527/566/614`). pfBlockerNG
   already calls it: `pfblockerng_install.inc:70` (DNSBL VIP), `pfblockerng.inc:10181`
   / `:10453` / `:10463` (MaxMind/ASN). So "a new pfBlockerNG version is available" has
   a **ready, idiomatic delivery path** — bell locally, plus the admin's existing
   remote channels — with **no new code** beyond the call.

5. **The GUI page surface is a fixed tab pattern; "Update" is already taken.** Each
   pfBlockerNG page builds `$tab_array[]` (`pfblockerng_general.php:209-218`); the
   **"Update"** tab is the **feed-update** terminal (`pfblockerng_update.php`, modeled
   on `pkg_mgr_install.php`) — a *different* concept (feeds, not the package). A new
   tab must avoid that collision (this ADR uses **"Software"**). Page access is gated
   by `page-firewall-pfblockerng` whose `match[]` list enumerates every page
   (`src/etc/inc/priv/pfblockerng.priv.inc:29-`); a new page needs a new `match[]`
   line or it 403s for non-admin operators.

6. **Config survives a channel change — but the deinstall hook is a live wire.** All
   three builds (stable / devel / nightly) ship the **same** `pfblockerng.xml` with
   `<name>pfblockerng</name>` (`pfblockerng.xml:33`), so the config section
   (`installedpackages/pfblockerng`) key is **channel-independent** and settings
   persist across a remove+install. BUT `pfblockerng.xml:72`
   `<custom_php_pre_deinstall_command>` runs on `pkg delete` — whether it preserves the
   config section across a channel switch is **a guarantee to pin with a test, not
   assume** (this is why channel-SWITCHING is deferred, §2).

7. **There is already a cron path to piggyback.** The scheduled job runs
   `pfblockerng.php cron` → `sync_package_pfblockerng('cron')` (`pfblockerng.inc`
   around `:1853`/`:1932`). A daily package-version check rides this — **no new
   scheduler**. `pkg` access from any context must respect base-system pkg locking
   (`is_subsystem_dirty('pkg')`, used by `get_pkg_info`).

8. **The repo plumbing this consumes already exists / is inbound.** ADR-17 is
   **Accepted + live**: per-`${ABI}` catalogs at `andrebrait.github.io/pfBlockerNG`,
   repo confs `pfblockerng` (stable) / `pfblockerng-devel` (devel) written by
   `scripts/add-repo.sh` (channels `devel|stable` today, `add-repo.sh:61`). ADR-18
   (**Proposed**) adds the **nightly** channel — a separately-named package
   (`pfSense-pkg-pfBlockerNG-NIGHTLY`, dated version, `conflicts` with the release
   names) and a `nightly` channel in `add-repo.sh`. This ADR **reads** latest versions
   from those repos via `pkg`; it does not change the repo or the builder.
   **ADR-20** (**Accepted**, 2026-06-10) supersedes ADR-17's single-ABI catalog model:
   it splits the catalog into version-keyed dirs (`ce-2.8/${ABI}/`, `plus-26.03/${ABI}/`)
   and routes requests via a Cloudflare Worker at `pkg.pfblockerng.workers.dev` that
   reads the pfSense `User-Agent` to redirect CE vs Plus boxes to the correct catalog.
   `add-repo.sh` writes a **single Worker URL** (no variant or pfSense version in the
   conf); the conf section name is **unchanged** — `pfblockerng-devel`, `pfblockerng`,
   `pfblockerng-nightly`. **Impact on this ADR:** the `pkg rquery -r <ourrepo>`
   invocation in §2 "Read latest" is **UNAFFECTED** — the repo section name remains
   `pfblockerng-devel` (or `pfblockerng` / `pfblockerng-nightly`); only the URL in the
   conf now points to the Worker. ADR-19 Phase-1 kill-gate is valid as written.

### Premise to falsify cheaply (the ADR-01 guard)

No perf/memory claim → no benchmark kill-threshold. The load-bearing premises are
**pkg/API mechanics**, mostly already proven by ADR-17; the residual unknowns are
cheap to settle and are the Phase-1 kill-gate:

- **Can we read our repo's latest version WITHOUT disturbing the `pfSense` repo or
  fighting `pfSense-repo-setup`?** Plan: `pkg update -r <ourrepo>` then
  `pkg rquery -r <ourrepo> '%v' <pkgname>` reads **only** our catalog DB and never
  invokes `-r pfSense`. **Reject/redesign** if reading our latest requires
  `get_pkg_info` (which would re-lock to `pfSense`) or if `pfSense-repo-setup`
  clobbers our conf on every check.
- **Does `file_notice` fire from the cron context** (bell + remote), and can we
  **de-dupe** it so a daily check doesn't renotify the same version every day?
  **Reject/redesign** the notice path if it cannot be made idempotent per version.
- **Does a same-channel `pkg upgrade <ourpkg>` from the GUI reliably pull our build?**
  Already proven for `pkg upgrade` precedence in ADR-17 Phase-5; this ADR only wraps
  it in a page. **Degrade** to a documented CLI step if the in-GUI run is unreliable.

If any premise fails on the live VM in Phase 1, the design is reshaped **before** the
page/cron code is built.

---

## 2. Decision

Ship a pfBlockerNG-owned **"Software"** tab (`pfblockerng_software.php`) that reads the
box's **current channel + installed version** and **our repo's latest** (via `pkg
… -r <ourrepo>`, never `-r pfSense`), shows the comparison, and offers **same-channel
"Update now"**, **"Check now"**, and a **repo-bootstrap** button (runs
`scripts/add-repo.sh` for the current channel). A **cron-driven background check**
caches the result and raises a **de-duped `file_notice`** when a newer build exists —
**default OFF, except the nightly channel where it defaults ON** (overridable by one
config knob). Cross-channel **switching is explicitly deferred** (its mechanism is
pre-decided below). **No base-system file is touched**; the stock badge stays
Netgate-bound by design (the ceiling, §1.3).

| Area | Decision |
| --- | --- |
| **Read latest (our repo)** | `pkg update -r <ourrepo>` + `pkg rquery -r <ourrepo> '%v' <pkgname>`; installed = `pkg query '%v' <pkgname>`. **Never** `get_pkg_info`/`-r pfSense`. Respect `is_subsystem_dirty('pkg')` (skip + reuse cache when pkg is locked). |
| **Channel detection** | From the **installed package name**: `pfSense-pkg-pfBlockerNG` → stable, `…-devel` → devel, `…-NIGHTLY` → nightly (ADR-18). The installed name is authoritative for "what channel am I on". |
| **Provenance gate (2026-06-15)** | The whole feature is present ONLY when `pkg query '%R' <pkgname>` is one of OUR repos (`pfblockerng`/`pfblockerng-nightly`) — pure `pfb_software_is_our_build()`. A Netgate-installed add-on (repo `pfSense`/unknown) shows **no** Software tab, **no** page (top-of-file guard `header(Location: /index.php)` + 403 via the absent `match[]`), and raises **no** cron notice. |
| **Version compare** | pfSense `pkg_version_compare()` (or `pkg version -t`) — never string compare; nightly's dated versions are only ever compared nightly-to-nightly (ADR-18 §1.5). |
| **Notice** | `file_notice('pfBlockerNG', "pfBlockerNG <ver> available (<channel>)", 'pfBlockerNG', '/pfblockerng/pfblockerng_software.php', 1)` when `latest > installed`. **De-duped** by persisting the last-notified version (notice fires once per new version, not per cron tick). Local bell + the admin's configured remote channels. |
| **Notify default** | One knob `pfb_software_notify` ∈ {`default`,`on`,`off`}. Unset/`default` resolves **per channel**: **nightly → ON, stable/devel → OFF**. Explicit `on`/`off` overrides. Quiet for release users; opt-out for nightly trackers (they opted into the tip). |
| **Background check** | Piggyback the existing `pfblockerng.php cron` path (~daily). Writes a cache file under `/var/db/pfblockerng/` (channel, installed, latest, last-checked, last-notified) — the page reads the cache; "Check now" forces a refresh. Mirrors pfSense's `version_cache_file` pattern. |
| **Page / tab** | New `pfblockerng_software.php`; tab label **"Software"** added to every page's `$tab_array[]`; new `match[]` line in `pfblockerng.priv.inc`. Shows channel, installed-vs-latest, last-checked, the notify knob, and the action buttons. |
| **Update now** | Same-channel `pkg upgrade -y <currentpkg>` via the existing live-terminal-output mechanic (reuse `pfblockerng_update.php`'s streaming pattern). **No cross-channel install.** |
| **Repo bootstrap** | Button → `scripts/add-repo.sh <current-channel>` (writes the conf for the channel the box is already on + `pkg update`). A convenience/repair; the conf usually already exists (ADR-17 install path). ADR-20 adds CE/Plus auto-detection to `add-repo.sh`; no variant argument is required — the script detects the variant from `globals.plus.inc`. The "Bootstrap repo" button invocation is unchanged (channel only). |
| **Helper seam (testability)** | **Pure** functions take strings — `pfb_channel_from_pkgname($name)`, `pfb_update_available($installed, $latest)`, `pfb_notify_default_for_channel($channel)`, `pfb_should_notify($cur, $last_notified, $available, $knob, $channel)` — fully PHPUnit-tested. A **thin** `pfb_pkg_*()` IO wrapper isolates the actual `pkg` shellout (covered by live smoke, not unit). |

### Semantics that MUST be preserved (the contract — pin with tests with the change)

- **No base-system change; the stock badge is untouched.** This ADR adds only
  pfBlockerNG-owned files. The Netgate-bound Available-Packages version + core update
  badge keep working exactly as before (documented ceiling, not a regression).
- **Reading latest never disturbs the `pfSense` repo.** The check uses `-r <ourrepo>`
  only; `pfSense-repo-setup` and Netgate discovery are not invoked or altered.
- **The notice is idempotent per version.** A newer build notifies **once**; repeated
  cron ticks at the same latest version do **not** renotify (pin with a before/after
  test: first tick notifies, second tick at same version does not, a newer version
  notifies again).
- **Notify default is channel-correct.** nightly defaults ON, stable/devel default
  OFF, with the knob overriding either way (each branch pinned).
- **A locked pkg subsystem is tolerated.** When `is_subsystem_dirty('pkg')`, the check
  skips the network op and serves the cache — never errors the page or the cron.
- **The page is operator-gated.** `pfblockerng_software.php` is covered by
  `page-firewall-pfblockerng` (priv `match[]`), like every other pfBlockerNG page.
- **Default `python -m pytest` unchanged**; smoke tree stays `--ignore`d.

### Explicitly kept / out of scope (deferred — mechanism pre-decided)

- **Cross-channel SWITCHING** (stable ⇄ devel ⇄ nightly) — **deferred**. It is a
  cross-*package-name* `pkg delete A && pkg install B`, a destructive op from a web
  request, and depends on ADR-18's nightly repo support landing. **Pre-decided
  mechanism for when it is picked up:** a single **vetted helper** (extends
  `add-repo.sh`) rewrites the conf + does the remove/install, invoked from the GUI
  behind an **explicit confirm dialog**, with a **config-preservation regression
  test** proving `installedpackages/pfblockerng` survives the
  `custom_php_pre_deinstall_command` (§1.6). Not built here; the v1 selector is
  **read-only** (shows the current channel).
- **Fixing pfSense's stock badge / Available-Packages version** — **impossible** from a
  package (base code, `-r pfSense`); our notice + panel is the substitute (§1.3).
- **Signing** — out; ADR-17's `signature_type: none` (TLS-anchored) is inherited.
- **A dashboard-widget badge** — out of v1 (the existing pfBlockerNG widget is
  unrelated); the `file_notice` bell is the v1 indicator. A natural follow-on.

---

## 3. Consequences

**Positive**

- **Closes ADR-17's deferred gap:** devel/nightly users get a `pkg`-native "newer
  build available" signal the stock GUI cannot give them, plus one-click same-channel
  update — without any base-system patch.
- **Notification rides existing infrastructure** (`file_notice` → bell + the admin's
  SMTP/Telegram/Pushover/Slack), zero new delivery code.
- **Quiet by default** (OFF for stable/devel), **opt-out for nightly** — matches user
  intent; no surprise emails for release users.
- **Pure-helper seam** makes the risky logic (version compare, notify decision,
  de-dupe) fully unit-testable off-appliance; only the thin `pkg` shellout needs the
  live VM.

**Negative / risks**

- **First shipped `src/` GUI code in this ADR series** → it must pass the ADR-14
  Tier-A `ui_render` PR gate (page 200, no `Fatal/Parse/Warning/Notice/Uncaught`, a
  page marker, no new `php_error.log` line). A `new shipped file` also needs no chroot
  copy (it is `www/`, not the Unbound module) but **does** ride the FreeBSD-ports
  `pkg-plist` — a new `www/` page must be added there or the portable build errors
  (see `[[feedback_new_shipped_file_chroot_plist]]`; `www/` plist entry, not chroot).
- **Couples to ADR-18 for nightly** — until ADR-18 lands, the nightly channel is
  detectable in code but has no live repo; the nightly path is unit-tested and
  smoke-deferred.
- **Couples to ADR-20 for variant-correct repo access.** ADR-20 (Proposed) splits the
  catalog into `ce/${ABI}/` and `plus/${ABI}/` subtrees. After ADR-20 Phase 4 lands,
  `add-repo.sh` writes a variant-specific URL; the `pkg rquery -r <ourrepo>` call in
  Phase-1 must target the variant-correct repo. If ADR-20 changes the conf section
  name (e.g. `pfblockerng-ce-devel`), this ADR's Phase-1 kill-gate must be re-run
  against the new name. ADR-20 Phase-7 resolves this dependency explicitly.
- **`pkg` shellout from a web request / cron** must respect pkg locking and DNS
  availability (mirror `get_system_pkg_version`'s `get_dnsavailable()` guard) or it
  stalls the page/cron.
- **De-dupe state is another file** under `/var/db/pfblockerng/` to manage (cleared on
  deinstall like sibling state).

## 4. Requirements (acceptance)

- A "Software" tab renders on every pfBlockerNG page; the new page shows current
  channel, installed version, our-repo latest, last-checked, and the notify knob.
- "Check now" refreshes the cache from our repo (`-r <ourrepo>`); "Update now" runs a
  same-channel `pkg upgrade` and streams output; "Bootstrap repo" runs `add-repo.sh`
  for the current channel.
- A cron tick computes latest-vs-installed and raises a **de-duped** `file_notice`
  per the channel-aware default + knob.
- Pure helpers are PHPUnit-tested for every branch (each channel, available/not,
  default/on/off, first-notify vs already-notified vs newer-version).
- The page passes the ADR-14 `ui_render` gate; a `repo`-marked live-VM journey proves
  "publish newer build → notice raised + cache updated → Update now pulls it".
- No base-system file changed; `python -m pytest` unchanged.
- **Provenance-gated:** on a Netgate-installed build the Software tab/page are absent and the
  cron raises no notice; only an our-repo build (`pfblockerng`/`pfblockerng-nightly`) shows them.

## 5. Constraints (from CLAUDE.md)

- PHP 8.3, **tabs** indent; no `die()/exit()` in library code; pfSense-injected
  functions resolved via `stubs/pfsense/` (add a stub for any new pfSense function the
  helpers call — e.g. confirm `pkg_version_compare`/`file_notice` stubs exist, add if
  not, **prefer a real stub over a baseline suppression**, `[[feedback_stub_over_phpstan_baseline]]`).
- Web-UI help text: brief, matching neighbouring fields' style.
- New variable / element `id` / config key follows the `pfB_*` / `pfb_*` neighbour
  pattern (e.g. `pfb_software_notify`), not an ad-hoc name.
- POSIX `sh` for anything reused from `add-repo.sh`; quote all expansions; the
  URL-encoding gate applies to any HTTP-client URL (none expected here).
- Worktree + **rebase-only PR** (this touches `src/` → full PR flow, **not** the
  ADR-docs carve-out); rebase onto latest `devel` before every push.
- PHPUnit + PHPStan are the PHP gates; the new page must clear the `ui_render` gate.
- **Tests must validate, not merely cover** (`[[feedback_tests_validate_not_cover]]`):
  branch coverage + before-state asserts + BDD spec for the notify/de-dupe state
  machine.

## 6. Action plan

The early phases are the behaviour-preserving **preparatory** pass — establish the
pure, fully-unit-tested decision core **before** any GUI/cron/IO wiring, so the risky
logic is pinned by oracle tests first.

### Phase 1 — KILL-GATE: pkg-read + notice mechanics on the live VM

- **Prompt:** `01_Kill_Gate_Read_And_Notice.txt`
- Cheaply prove on the ADR-04 VM, **before any src/ code**: (a)
  `pkg update -r <ourrepo>` + `pkg rquery -r <ourrepo> '%v' <pkgname>` reads our
  latest **without** touching the `pfSense` repo / `pfSense-repo-setup`; (b)
  `file_notice` fires (bell row present in `get_notices`) and can be **de-duped** by
  caller-side last-version state; (c) a same-channel `pkg upgrade <ourpkg>` advances
  the installed version from our repo (reuse ADR-17's `repo`-marked hermetic catalog
  helper). Record GO / REJECT per §1 premises in `RESULTS/01_Results.txt`.
- **Tests:** `repo`-marked cases in `tests/smoke/test_repo_install.py` (or a sibling),
  deselected from `-m smoke`; assert effective state (`pkg query`/`pkg rquery`/
  `get_notices`) by value, befores **and** afters. No `src/` change yet.

### Phase 2 — Pure decision core + PHPUnit oracle (behaviour-additive, no wiring)

- **Prompt:** `02_Pure_Helpers_And_Tests.txt`
- Add the **pure** helpers to `pfblockerng.inc`:
  `pfb_channel_from_pkgname()`, `pfb_update_available()` (via `pkg_version_compare`),
  `pfb_notify_default_for_channel()`, `pfb_should_notify()` (the de-dupe + knob +
  channel-default state machine). No GUI, no cron, no `pkg` IO — strings in, decisions
  out. Add `pkg_version_compare`/`file_notice` stubs to `stubs/pfsense/` if missing.
- **Tests:** `tests/php/` PHPUnit — every branch: each channel name → channel;
  newer/equal/older → available?; nightly→ON vs stable/devel→OFF default, knob
  on/off override; **de-dupe BDD**: first-notify (none→avail) notifies, second tick
  (same latest, already-notified) does **not**, a newer latest notifies again — assert
  the before-state each time.

### Phase 3 — Background check + de-duped notice on the existing cron

- **Prompt:** `03_Cron_Check_And_Notice.txt`
- Add the thin `pfb_pkg_*()` IO wrapper (the actual `pkg` shellout, pkg-lock- and
  DNS-guarded) and `pfb_software_update_check()` that: reads installed + our-repo
  latest, writes the cache file under `/var/db/pfblockerng/`, and calls the Phase-2
  `pfb_should_notify()` → `file_notice` (de-duped). Wire it into the
  `pfblockerng.php cron` path. Register the `pfb_software_notify` config field default.
- **Tests:** PHPUnit on the orchestration with the IO wrapper **doubled** (inject
  installed/latest, assert cache contents + whether `file_notice` was called, pkg-lock
  short-circuit serves cache). The live `pkg`/`file_notice` legs are Phase-4 smoke.

### Phase 4 — The "Software" page (display + actions) + UI render gate

- **Prompt:** `04_Software_Page_And_UI_Gate.txt`
- Add `pfblockerng_software.php`: channel + installed-vs-latest + last-checked from the
  cache, the `pfb_software_notify` knob, and buttons **Check now** (force refresh),
  **Update now** (same-channel `pkg upgrade`, reuse `pfblockerng_update.php`'s live
  terminal mechanic), **Bootstrap repo** (`add-repo.sh <channel>`). Add the **"Software"**
  tab to every page's `$tab_array[]` and a `match[]` line to `pfblockerng.priv.inc`.
  Add the `www/` page to the FreeBSD-ports `pkg-plist` (`[[feedback_new_shipped_file_chroot_plist]]`).
- **Tests:** ADR-14 Tier-A `ui_render` (PR gate) — GET the page → 200, body free of
  `Fatal/Parse/Warning/Notice/Uncaught`, a page-specific marker present, no new on-box
  `php_error.log` line. (Tier-B `ui_browser` for the buttons is schedule-only.)

### Phase 5 — End-to-end live journey (`repo` smoke) + docs + DoD

- **Prompt:** `05_E2E_Smoke_And_Docs.txt`
- Extend `tests/smoke/test_repo_install.py` (`repo` marker): GIVEN our build installed
  from a hermetic catalog; assert **no** notice + cache "up to date"; WHEN a newer
  build is published to the catalog and the check runs; THEN a `file_notice` row
  appears, the cache shows the newer latest, and **Update now** (`pkg upgrade`)
  advances the installed version from our repo — befores and afters by value. Pin
  notify-default per channel (nightly→notice, devel→no notice). Update README/docs;
  fill §7 DoD.
- **Tests:** the new `repo`-marked cases (dispatch `gh workflow run smoke.yml
  -f pytest_marker=repo`); `python -m pytest` unchanged; the `ui_render` gate green.

## 7. Definition of done

- All five phases merged to `devel` via rebase-only PRs; `python -m pytest`,
  `ruff`, PHPStan, PHPUnit, `markdownlint`, and the ADR-14 `ui_render` gate all green
  on each PR.
- The pure decision core is PHPUnit-tested for **every** branch (channels, available,
  default/on/off, de-dupe lifecycle) with before-state asserts.
- The `repo`-marked live-VM journey is **GREEN** (capture the run id): newer build →
  de-duped notice (channel-correct) + cache update + same-channel Update.

### DoD status / evidence (filled Phase 5, 2026-06-15)

- **Phase 1 kill-gate — GO.** `tests/smoke/test_software_update.py` (marker `repo`) proves
  all three §1 premises + the provenance amendment on the live VM: read-our-latest without
  touching the `pfSense` repo, per-version-idempotent `file_notice`, same-channel
  `pkg upgrade` from our repo, and `%R` discriminating our build from a decoy. (`RESULTS/01`.)
- **Phase 2 pure core — DONE.** `tests/php/SoftwareUpdateCheckTest.php` + the pure-helper
  tests pin every branch (each channel, available/not, default/on/off, de-dupe lifecycle)
  with before-state asserts. PHPUnit green (488 tests after the post-review hardening).
  (`RESULTS/02`, `RESULTS/03`.)
- **Post-review hardening (PR #232 / CodeRabbit, 2026-06-15).** Three quick-win findings
  applied + pinned: `pfb_pkg_latest()` wraps both networked `pkg` calls in `timeout(1)`;
  `pfb_software_write_cache()` is now genuinely atomic (`tempnam()` + `rename()`); and the
  cron check scopes cached `latest`/`last_notified` to the installed `pkgname` so a channel
  switch cannot surface a stale version or suppress the first valid notice
  (`testChannelSwitchDoesNotReuseStaleCache`).
- **Phase 4 page — DONE; NEGATIVE side GREEN live.** The ADR-14 Tier-A `ui_render` PR gate
  asserts the provenance gate **hides** the page + tab on the harness's `pkg add -f` install
  (non-our `%R`):
  `tests/smoke/ui/test_render_smoke.py::test_software_page_provenance_gate_hides_on_nonour_build`
  and `::test_software_tab_absent_on_nonour_build`. (`RESULTS/04`.)
- **Phase 5 POSITIVE journey — DONE (the `repo`-marked live journey above).** Two new
  `repo`-marked cases in `tests/smoke/test_software_update.py`, run on an **our-repo**
  install (`%R == pfblockerng`) so the provenance gate **opens**:
  - `test_software_positive_journey_on_our_repo_install` — `pfb_software_provenance_ok()`
    reads **true** on-box (live inverse of the Phase-4 negative), the shipped page parses
    (`php -l`) and carries its `pfb-software-panel` marker (so the `.pkg` carried Phase-4's
    page, built with `ports_ref=adr/19-update-channel-panel`), the orchestrator writes the
    cache up-to-date with **no** notice, a published newer build advances the cache `latest`
    and raises **exactly one** notice (a second check at the same latest raises none —
    de-dupe), and `pkg upgrade` advances the box from our repo with **no** re-notice — every
    before/after by value.
  - `test_software_notify_default_is_channel_correct` — paired channel-default branches:
    **devel → no notice by default**, **nightly → one notice by default** under the identical
    newer-build condition (nightly *channel* simulated via the orchestrator's `$io` seam, as
    the nightly repo/package is not in the hermetic CE image — noted in `RESULTS/05`).
- **Dispatch:** `gh workflow run smoke.yml -f pytest_marker=repo -f ports_ref=adr/19-update-channel-panel`
  (the `ports_ref` makes the built `.pkg` carry `www/pfblockerng/pfblockerng_software.php`
  via the FreeBSD-ports plist entry). The captured run id is recorded in `RESULTS/05`.
- **Docs — DONE.** `README.md` "Usage → Software tab" documents the tab, the three buttons,
  the provenance gate (present only on an our-repo build, absent on Netgate), and the
  `pfb_software_notify` knob with its channel-correct defaults; the Option-2 transition note
  now points at the Software tab instead of "no update badge".
- **Acceptance:** under the CLAUDE.md "ADR acceptance — automated tests, not a manual
  maintainer sign-off" rule, the green automated coverage above (PHPUnit branch coverage +
  the `ui_render` negative gate + the `repo` positive journey on the CE/Plus fan-out) is the
  acceptance basis. The manual checklist below is retained as **out-of-CI** confirmation
  (real remote-channel delivery, a real channel switch, a live nightly repo), **not** an
  acceptance blocker.

### Manual smoke checklist (owner: maintainer — what CI cannot fully cover)

1. On a live box on the **devel** channel with ADR-17's repo configured: confirm the
   Software tab shows installed-vs-latest correctly; "Check now" updates last-checked;
   with `pfb_software_notify=on`, a published newer devel build raises a **bell** notice
   **and** the configured remote channel (e.g. a test SMTP) receives it **once**.
2. Default-OFF holds on devel/stable (no notice without the knob); default-ON holds on
   **nightly** once ADR-18's nightly repo is live.
3. "Update now" upgrades from **our** repo (verify `pkg query %R`/version), pfBlockerNG
   restarts and runs; settings preserved.
4. "Bootstrap repo" writes the correct per-channel conf and `pkg update` succeeds.
5. With pkg locked (mid base-update), the page + cron degrade gracefully (serve cache,
   no error).

### Reject / redesign criteria

- **REJECT/redesign** if reading our latest cannot avoid `-r pfSense` (re-locks to
  Netgate) or `pfSense-repo-setup` clobbers our conf on every check (Phase-1 premise 1).
- **REJECT/redesign** the notice path if `file_notice` cannot be made **idempotent per
  version** from cron (Phase-1 premise 2).
- **DEGRADE** "Update now" to a documented CLI step if an in-GUI same-channel
  `pkg upgrade` is unreliable on the live VM (Phase-1 premise 3) — the display + notice
  still ship.

## Amendment — 2026-08-03: channel no longer derives from package name (issue #2140)

The four-channel release contract uses one exact package identity,
`pfSense-pkg-pfBlockerNG`. Consequently, package-name suffixes cannot remain the channel oracle
after catalog migration. Issue #2148 owns the on-box channel source, update behavior, and UI
transition, including explicit cross-channel movement. Until that work lands, this ADR's existing
runtime and package-name detection remain unchanged.

This amendment does not reinstate package downgrade. It only records the future client boundary
required by the release model; #2140 changes no PHP, cron, repository configuration, or UI.

## Amendment — 2026-08-14: notification handoff boundary (issue #1630)

`last_notified` remains producer-owned software-update state used only to suppress repeated
sends. `file_notice()` is a one-way handoff: the producer never queries, mutates, dismisses, or
otherwise uses the emitted pfSense notification as storage. Recipient and transport lifecycle
state is outside this ADR's software-update state model.
