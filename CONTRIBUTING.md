# Contributing to pfBlockerNG

This guide covers developing, testing, building, and releasing the package. For
installation and a feature overview, see the [README](README.md); the per-feature
design records (one Architecture Decision Record per subsystem) live under
[`.ADRs/`](.ADRs/).

## Development workflow

### Prerequisites

- A running pfSense instance accessible via SSH
- FreeBSD ports tree cloned at (e.g.) `~/git/FreeBSD-ports`
  ([pfsense/FreeBSD-ports](https://github.com/pfsense/FreeBSD-ports))
- Python 3.11+ for running tests locally

### IDE setup (VS Code)

Open the repository in VS Code and install the recommended extensions when
prompted (or run **Extensions: Show Recommended Extensions** from the command
palette).  The workspace ships with a full configuration in `.vscode/`:

| Extension | Purpose |
| --------- | ------- |
| [Intelephense](https://marketplace.visualstudio.com/items?itemName=bmewburn.vscode-intelephense-client) | PHP language server — `.inc` files are auto-associated as PHP |
| [Python + Pylance](https://marketplace.visualstudio.com/items?itemName=ms-python.python) | Python language support and type analysis |
| [ShellCheck](https://marketplace.visualstudio.com/items?itemName=timonwong.shellcheck) | POSIX sh linter — dialect is detected from the `#!/bin/sh` shebang |
| [markdownlint](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint) | Markdown linter — reads `.markdownlint.jsonc` / `.markdownlint-cli2.jsonc` |
| [EditorConfig](https://marketplace.visualstudio.com/items?itemName=editorconfig.editorconfig) | Enforces `.editorconfig` rules (tabs for PHP/shell, spaces for Python) |

#### PHP stubs

`stubs/pfsense/` contains PHP function and global-variable declarations for the
pfSense API.  Intelephense discovers these automatically and uses them for
autocomplete and type-checking instead of reporting every pfSense call as
"undefined".

To regenerate the stubs after a pfSense CE version bump, run:

```sh
python scripts/update-pfsense-stubs.py --version X.Y.Z
```

The default version is the minimum pfSense CE release supported by this package
(`MIN_PFSENSE_VERSION` at the top of the script).  The script fetches the
relevant pfSense source files from GitHub and rewrites all stub files except
`stubs/pfsense/globals.php`, which is manually maintained.

A CE version bump also requires updating the **supported-version matrix** and
refreshing the CI smoke image. See
[Rebuilding the image on a CE bump](#rebuilding-the-image-on-a-ce-bump) below for
the full three-step procedure (matrix edit → image refresh → smoke fan-out).

### Git hooks

The repository ships hooks in `.githooks/` — a tracked directory, so they are
shared and reviewed (the default `.git/hooks` is local-only and cannot be
committed):

- **`pre-commit`** runs the fast linters and the unit suites (Ruff, pytest,
  markdownlint, ShellCheck + `sh -n`, shellspec, `php -l`; PHPStan and PHPUnit
  only when `vendor/` is present) and blocks the commit on any failure. A check
  whose tool is not installed is skipped (CI is the hard gate); bypass with
  `git commit --no-verify`.
- **`pre-push`** enforces the tag naming convention before anything is pushed:

| Commit reachable from | Required tag form  |
| --------------------- | ------------------ |
| `origin/main`         | `vX.X.X`           |
| `origin/devel` only   | `vX.X.X-devel`     |
| Neither               | push is rejected   |

Activate the hooks once after cloning (git cannot auto-apply a committed hooks
path):

```sh
sh scripts/setup-hooks.sh    # sets core.hooksPath to .githooks
```

These are local client-side guards. CI enforces the same checks (and the tag
rules) server-side, so anything that bypasses a hook is still caught by GitHub
Actions.

### Shell setup (macOS, optional)

On macOS, Homebrew's `bin` is on `PATH` only for **login** shells (`brew shellenv`
lives in `~/.zprofile`), so the pre-commit hook's tools (`node`/`npx` for
markdownlint, `php`, `shellcheck`) can go missing in the non-login shells that
editors and agents spawn. The hook self-bootstraps Homebrew's `PATH` regardless,
but to make the same tools resolve in your own interactive/manual shells — and to
upgrade Apple's ancient `/bin/bash` 3.2 to Homebrew's bash — run once:

```sh
sh scripts/setup-dev-shell.sh
```

It writes a small idempotent managed block into `~/.brew_path.sh`, `~/.zshenv`,
`~/.bashrc`, `~/.bash_profile`, and `~/.profile`. It's macOS-only (it exits doing
nothing on other systems); if Homebrew isn't installed it prints an install hint and
exits **without changing any dotfiles**. It does not change your login shell or
`/etc/shells` — it only prints the optional `sudo` commands for those.

### Running the test suite locally

Python (the bulk of the suite):

```sh
python3 -m pytest
```

Test paths and options are configured in `pyproject.toml`; no `cd` is required.

Optional **branch**-coverage report for the Unbound matcher (issue #38 — line
coverage hides one-sided decision branches; this surfaces them):

```sh
python3 -m pytest --cov=pfb_unbound --cov-branch --cov-report=term-missing
```

Needs `pytest-cov` (`pip install pytest-cov`). It is informational only — CI runs
the same report (non-blocking), with no enforced floor.

PHP unit tests (PHPUnit) cover the pure/extractable PHP helpers
(input filtering, IDN/textarea decode, ABP-IP extraction, IPv4 normalisation,
the Python manifest writer). Install the dev dependencies once, then run:

```sh
composer install      # pulls phpunit/phpunit into vendor/
vendor/bin/phpunit     # config in phpunit.xml; no live pfSense needed
```

The suite loads the **real** `pfblockerng.inc` off-appliance via
`tests/php/bootstrap.php` (empty shims for the pfSense `require_once` includes
plus behavioural doubles for the pfSense runtime functions) — see
[`tests/php/README.md`](tests/php/README.md). Deep pfSense-runtime integration
stays the live-VM smoke's job (ADR-04).

### Shell tests (shellspec)

The POSIX `sh` — the `ip_pre_AWS_*.sh` region pre-scripts and the testable
functions in `pfblockerng.sh` — has a functional suite under `tests/shell/`, run
with [shellspec](https://shellspec.info/) (pure POSIX, native kcov coverage):

```sh
shellspec            # from the repo root; reads ./.shellspec
shellspec --kcov     # with coverage (informational; needs kcov)
```

Install with `brew install shellspec` (macOS) or the official installer
(`curl -fsSL https://git.io/shellspec | sh`). The pre-commit hook and CI run it
automatically when `shellspec` is present (coverage is informational, no floor).
See [`tests/shell/README.md`](tests/shell/README.md) for the harness contracts
(the `iprange` PATH shim, the AWS fixture, and the `PFB_SOURCED` source-for-test
pattern).

## Subsystem internals

### DNSBL list build (Python)

DNSBL blocklist preprocessing lives in the Python plugin
(`src/usr/local/pkg/pfblockerng/pfb_unbound.py`), not in shell/PHP. PHP/shell only
**download** each feed, run the **DNSBL-IP firewall pass** (embedded IPs →
`DNSBLIP_v4` pf alias, stripped from Python's input), and write a per-feed
**manifest** that the plugin reads at `init`:

- `/var/unbound/pfb_py_sources.json` — the manifest: a `config` block (TLD master
  path, TLD blacklist/exclusion, user whitelist, TOP1M list + enabled flag) plus
  one `feeds` row per raw file (`{raw, feed, group, format_hint, log_flag}`).
- `/var/unbound/pfb_py_raw/<feed>.raw` — per-feed IP-stripped bare-domain raw.

`pfb_unbound.dnsbl_build_from_manifest()` then does **parse → normalise → classify
(data/zone via the public-suffix master) → build** `dataDB`/`zoneDB` +
feed/group index + query-time `whiteDB`, and emits the loaded-entry total to
`/var/unbound/pfb_py_count`. The build performs **no** dedup, subdomain collapse,
or build-time whitelist/TOP1M removal (dict keys dedup for free; whitelist + TOP1M
apply at query time via `whiteDB`). It is a pure, reentrant `(manifest, config) →
BuildResult` function — no Unbound symbols, fully unit-testable. See
[ADR-06](.ADRs/ADR_06_DNSBL_Preprocessing_To_Python/ADR.md) for the full contract.

#### Full ABP/EasyList support (ADR-07)

ABP/EasyList feeds are parsed **entirely in Python** — the old PHP `$easylist`
lite parser is gone. PHP header-sniffs an ABP feed, tags it `format_hint = 'abp'`,
and passes its **raw** lines through verbatim (IP anchors `||1.2.3.4^` and hosts
IPs still diverted to the DNSBL-IP firewall pass). `parse('abp', line)` is the one
DNS-only ABP parser; it adds the rules the lite parser silently dropped:

- **`@@` allow exceptions** (block + allow) — fixes the systematic over-blocking.
- **Regex** `/re/` and `@@/re/`: anchored-reducible patterns fold to `dataDB`/
  `zoneDB`/`whiteDB` (zero per-query cost); only irreducible regex compiles into
  `regexDB` (block) / `allowRegexDB` (allow).
- **`$important` / `$badfilter`** precedence, resolved by a 6-band numeric scale
  (user allow/block always win; feed `$important` > feed plain; `@@` > `||`). A
  build-emitted `important_rules` flag keeps a **byte-identical fast path** when no
  ABP precedence feature is loaded (the no-regression guarantee).
- **Out of scope, parsed-and-skipped:** element-hiding (`##`/`#@#`/`#?#`),
  path/URL rules, and page-context `$options` — never approximated as DNS blocks.

Untrusted regex (feed **and** the user Python Regex List) is kept tolerable by a
best-effort safeguard, **not** vetting: an opt-in "Limit long/complex regex"
static cap drops over-long / nested-quantifier patterns at load, and an always-on
runtime guard times each match — warns over a ceiling and **evicts** the pattern
over a higher one (snapshot-iterate, evict-after-loop; thread-safe under the GIL).
The accepted residual is a single slow first-hit before eviction (`re` cannot be
interrupted mid-match). The `DNSBL_Regex` alias count now reflects the **admitted**
(cap-filtered) regex total, emitted by Python to `/var/unbound/pfb_py_regex_count`.
See [ADR-07](.ADRs/ADR_07_ABP_DNSBL_Support/ADR.md) for the full contract.

ABP feeds build through the Python manifest path regardless of the DNSBL **TLD**
mode: the manifest is written unconditionally and `parse('abp', …)` does its own
TLD classification. The legacy PHP `tld_analysis()` pass (which re-parses the
combined feed dump as `,domain,,log,feed,group` CSV) is **not** ABP-aware, so it
**skips** any feed carrying the persisted `.abp` marker — an ABP feed's raw lines
are never CSV-mangled, and its domains/regex still build in Python. Plain feeds
keep the legacy TLD behaviour unchanged. **Follow-up:** a later pass should review
the full ABP × DNSBL-TLD-mode integration (ideally folding the PHP TLD pass into
the Python build for all feeds).

The decision-equivalence of the ADR-06 move (block/resolve/whitelist/HSTS/noAAAA
across hosts/plain/csv:pon, plus feed/group attribution and the emitted count) is
pinned by the golden + build unit tests, and the ADR-07 ABP semantics + the
no-regression fast path by the `test_adr07_*` suite — all in the default `pytest`
run:

```sh
python -m pytest tests/test_adr06_golden_oracle.py \
                 tests/test_adr06_build_module.py \
                 tests/test_adr06_init_from_raw.py \
                 tests/test_adr06_php_boundary.py \
                 tests/test_adr07_decision_spec.py \
                 tests/test_adr07_parser.py \
                 tests/test_adr07_reconcile.py \
                 tests/test_adr07_matcher_strata.py \
                 tests/test_adr07_emit_wire.py \
                 tests/test_adr07_regex_safety.py \
                 tests/test_adr07_php_boundary.py
```

#### Zero-downtime DNSBL updates (ADR-10)

A DNSBL **data** update no longer restarts Unbound. The running Python module
rebuilds the matcher structures **on a background watcher thread** off the live
ones, then atomically swaps in a single immutable `Snapshot` reference — GIL-atomic,
so every query thread sees either the whole old snapshot or the whole new one, never
a torn mix. Queries keep flowing throughout the build (briefly stale by design):
there is **no stop/start window**, so the swap is **designed to avoid dropped queries**
(validated functionally in the live-VM smoke; the zero-dropped-queries-under-load
guarantee is pending the maintainer's §7 live-box smoke). PHP/shell drive it by
**atomically publishing** the manifest (stage → `fsync` → `rename`) and **flipping a
single generation sentinel** (`/var/unbound/pfb_py_reload`); the watcher wakes on it
(`kqueue` `EVFILT_VNODE`, mtime-poll fallback) and runs the rebuild + swap. A failed
or partial build is **fail-closed** — the last-good snapshot keeps serving.

**Data vs config — what swaps, what restarts:**

- **DATA = zero-downtime swap (no restart).** Scheduled/forced **feed/cron**
  updates, **and** the user custom-list edits — alerts **Lock/Unlock** and
  "add to whitelist", plus customlist add/delete (#51) — all take the no-restart
  fast path: publish + flip, the watcher swaps. Unbound's pid is unchanged.
- **CONFIG = restart (unchanged).** A change to `unbound.conf` / the DNS Resolver /
  mode toggles still stops/starts Unbound — only DNSBL data is zero-downtime.
- **Fallback = restart (fail-safe).** The swap falls back to today's restart when it
  cannot run safely: a **RAM-constrained box** (the ~2× transient build/swap footprint
  would not fit — a PHP RAM gate is the primary check, the Python watcher's free-page
  probe the secondary net), the **feature/python mode off**, Unbound not running, a
  staged config change present, or a **prior swap/sentinel error**. The restart never
  doubles RAM (the old set dies before the rebuild), so it is the safe floor.

**Cache behaviour on a swap:**

- **Reports** (the `dnsblcache` sqlite) is reset — parity with the restart.
- The unified query-time decision cache **`decisionDB` is cleared** on every swap, so
  no stale block/allow *decision* survives.
- **block→allow is immediate.** DNSBL blocks are not stored in Unbound's C message
  cache (`no_cache_store=1`, #43), so once `decisionDB` clears, a newly-**removed**
  name resolves its real answer at once — no flush needed.
- **allow→block** flushes the prior **resolved** answer from the C-cache: a **targeted
  delta flush** of the newly-blocked name(s) where the delta is known and small (the
  #51 single-domain Lock / "strip from whitelist" case), and a **TTL-bounded** wait
  for the feed/cron case (the allow→block delta is not cheaply diffable over
  multi-million-entry sets — and this is **not** a regression: today's restart
  preserves the resolved cache too, so its allow→block is equally TTL-stale).

See [ADR-10](.ADRs/ADR_10_Zero_Downtime_DNSBL/ADR.md) for the full contract; the
swap RAM kill-gate is `benchmarks/spike_adr10_swap.py`, and the snapshot-equivalence
/ fail-closed-swap / watcher guards are the `tests/test_adr10_*` suite.

#### IDN homoglyph protection (ADR-08)

The DNSBL settings page carries an **IDN Blocking** mode selector — **Off | All-IDN
| Confusable** (replacing the old on/off checkbox; a config that had `pfb_idn='on'`
comes up as **All-IDN**, byte-identical to today). **Off** takes no IDN action;
**All-IDN** blocks every `xn--` domain (the blunt legacy behaviour); **Confusable**
runs a TR39 mixed-script analyzer that decodes each `xn--` label and blocks only the
**deceptive cross-script** ones:

- **Catches:** cross-script confusable homographs — a single label mixing **≥2 of
  {Latin, Cyrillic, Greek}** (`Latin+Cyrillic`, `Latin+Greek`, **and** `Cyrillic+Greek`),
  e.g. `xn--pple-43d` = `аpple` (Cyrillic `а`). Malicious → **blocked by default**
  (sub-toggle, default-on); other non-restrictive multi-script mixes (e.g.
  Latin+Armenian/Cherokee/Coptic) → **suspicious → alerted** (opt-in sub-toggle
  escalates them to block).
- **Does NOT catch (documented limitation):** **whole-script confusables** (an
  all-Cyrillic `раураӏ` look-alike — single-script, passes restriction analysis) and
  **pure-ASCII typosquats** (`g00gle`) — those need a confusables + protected-brand
  table, deliberately out of scope.
- **Legit IDNs resolve untouched:** single-script (incl. all-Latin/Cyrillic/Greek)
  and Latin+CJK (Japanese/Korean/Chinese). Analysis is **per-label, never unioned
  across the dot**, so a legit ASCII/Latin SLD under an IDN ccTLD (`example.рф`,
  `site.中国`) resolves. Decode runs only on `xn--` queries; malformed labels are
  caught and flagged, never crash the resolver. The alert shows the decoded Unicode
  and the offending script (reusing the alerts page's `idn_to_utf8` display).

Measured over the FP/TP corpus (`tests/fixtures/adr08_corpus/`): **0** false
positives on the legitimate set (CJK and IDN-ccTLD both 0), **6/6** homographs
caught. See [ADR-08](.ADRs/ADR_08_Homoglyph_Protection/ADR.md) for the full contract;
the decision oracle + analyzer + matcher-wiring + corpus guards are the
`tests/test_adr08_*` suite.

The analyzer (inlined in `src/usr/local/pkg/pfblockerng/pfb_unbound.py`) resolves each
code point's script from the **stdlib `unicodedata.name()`** leading token (`LATIN…`,
`CYRILLIC…`, `GREEK…`, `CJK…`→Han, …) — no shipped Unicode table and no runtime
dependency. The script names are stable across UCD versions for the established
scripts in scope, so the FP/TP result holds across Python 3.11–3.14 (validated in the
`tests/test_adr08_*` suite against the version-pinned corpus/oracle).

### DNSBL sinkhole VIP

A DNSBL "VIP" block sinks the queried name to a **sinkhole Virtual IP** that the
DNSBL web server (lighttpd) listens on. That VIP must exist before DNSBL can be
enabled; `pfb_validate_vips` force-disables DNSBL if it is missing or invalid.

#### "Create VIPs automatically" (ADR-13)

The **DNSBL Virtual IP** group on the DNSBL settings page now includes a
**"Create VIPs automatically"** checkbox (`pfb_dnsvip_auto`, default **off**).
When checked, pfBlockerNG owns the sinkhole VIP(s) end-to-end — no manual VIP
creation at Firewall > Virtual IPs is needed.

**Address scheme.** The preferred addresses are:

- IPv4: `10.10.10.53/32` (a `.53` DNS homage)
- IPv6: `fd00::53/128` (ULA range)

On conflict, the package sweeps `10.10.X.53` / `fd00:X::53` (X = 0..15) and
picks the first address that overlaps no existing VIP or configured subnet.

**Ownership marker.** Auto-created VIPs carry the description
`pfB_AUTO_VIP_v4` / `pfB_AUTO_VIP_v6`. Only VIPs bearing that exact marker
are ever managed or removed by the package — a manually-created VIP is never
touched.

**Lifecycle.** The VIP is created when DNSBL is enabled
(`pfb_create_dnsbl('enabled')`) and removed when DNSBL or pfBlockerNG is
disabled — including on uninstall. The `pfb_dnsvip_auto` setting and the
stored address survive disable/re-enable; the VIP is re-created on the next
enable pass. Settings persist independently of VIP state.

**Edge: range fills up.** If the auto flag is on and the candidate range later
fills up (all `10.10.X.53` / `fd00:X::53` addresses conflict), the checkbox
renders disabled and unchecked with a warning on the settings page, while the
stored `pfb_dnsvip_auto` stays `on` until the next save. The lifecycle manager
no-ops safely when no free address is available — it logs and leaves the
existing config untouched.

**IPv6 — when do you want a v6 sinkhole VIP?** When the DNS Resolver listens on
IPv6, AAAA blocks should sink to a v6 sinkhole VIP too:

- **Auto mode** — pfBlockerNG provisions `fd00::53` automatically, no friction.
- **Manual mode** — a v6 VIP is **recommended but not required**. If the resolver
  listens on IPv6 and no v6 VIP is configured, pfBlockerNG logs a **non-blocking
  warning** and DNSBL keeps running on IPv4 (AAAA blocks simply are not
  sinkholed). It does **not** force-disable DNSBL — an earlier revision did, which
  broke existing manual setups that listen on IPv6 without a v6 VIP; enabling
  "Create VIPs automatically" provisions the v6 VIP for you.

**HA / CARP.** The `pfb_dnsvip_auto` flag and the address choice live in
`config.xml` and replicate to CARP secondaries. Each node creates and removes
its own node-local `lo0` IP-Alias VIP when it runs its own enable/disable pass
— this is correct; `lo0` aliases are node-local.

**If "Create VIPs automatically" is off** (the default), the existing manual
workflow is unchanged: pre-create an IP-Alias VIP at Firewall > Virtual IPs
(in an isolated range, e.g. `10.10.10.1/32` on `lo0`), then select it from
the IPv4 VIP / IPv6 VIP dropdowns on the DNSBL settings page.

See [ADR-13](.ADRs/ADR_13_Auto_DNSBL_VIP/ADR.md) for the full design.

### Aggregated Aliases ("Uber" aliases, ADR-11)

The **Aggregated Aliases** multi-select on the General settings tab builds, per
selected **action type** (`Deny` / `Permit` / `Match` / `Native`), a pair of
**Native** urltable aliases — `pfB_<Type>_Aggregated_v4` and `_v6` — each holding
the deduped, `iprange`-aggregated **union of that type's effective set** for the
family. `Deny` is the *effective* (post-suppression/whitelist) block set and folds
in **DNSBLIP**; **GeoIP folds in by each continent's configured action** (a
Deny-action continent lands in the Deny aggregate), so there is **no separate Geo
alias**. `Permit` / `Match` / `Native` are the exact unions of their own dirs.

- **Native = no firewall rule.** The aggregates are registered as `urltable`
  aliases only; pfBlockerNG creates **no rule** for them. They are **reference
  IP-sets** — a `Permit` or `Match` aggregate does **not** permit or match anything
  by itself. To use one, reference it by name in your own firewall rule or in an
  HAProxy/service ACL (the motivating use case, ADR-12 below).
- **Opt-in, default none.** With nothing selected the update pass is byte-identical
  to before. Each selected aggregate is a **wired kernel pf table** of its full
  union — RAM proportional to the union size, and the Deny set can run to **millions
  of entries**. Enable only the type(s) you actually consume.
- **Built in lockstep, mtime-gated.** Each selected aggregate is rebuilt **in the
  same update pass** as its members (`cat` → `sort -u` → `iprange`), with no extra
  cycle; an unchanged type is skipped via an mtime gate. Every built aggregate also
  writes a **never-empty** `-f` consumer file (a `#` placeholder line when the union
  is empty), so a downstream `-f` reference always validates.

**ADR-12 hand-off.** The Native aggregate aliases plus their never-empty `.lst`
consumer files are exactly what an HAProxy ACL (or any `-f`-reading service)
consumes. pfBlockerNG **loads each aggregate's pf table inline, before** the ADR-12
`post` update hook fires, so a hook always sees the **fresh** table; a rebuilt
aggregate's name is merged into `PFB_CHANGED_IP_ALIASES`. Freshness for HAProxy is
therefore a **pfBlockerNG-triggered graceful reload** from a `post` hook (the
HAProxy package re-reads its `-f` files only at reload), **not** a runtime-socket
push — see the HAProxy recipe under **Update Hooks** below.

See [ADR-11](.ADRs/ADR_11_Uber_Aliases/ADR.md) for the full design, the union-cost
benchmark, and the maintainer smoke checklist.

### Update Hooks (pre/post update scripts, ADR-12)

> The practical recipes (the environment table, the HAProxy reload, and the webhook)
> are summarized for users in the [README Usage section](README.md#usage). This
> section is the full reference: the trust model, the complete environment contract,
> and the rule-vs-data distinction.

The **Update Hooks** settings tab (after **Update**) lets an admin run their own
**script** at the **start** (`pre`) and **end** (`post`) of every pfBlockerNG update
pass — to nudge a downstream consumer (the worked HAProxy recipe below), restart a
service, push to an API, sync, or notify. It is a thin, safe **script** runner, not
an event system. These are distinct from the per-feed `ip_pre_*.sh` list pre-scripts:
an Update Hook runs **once per update pass**, not once per feed.

**Security model — pick a file, don't type a command.** A hook does **not** run a
command typed into the GUI (any WebCfg admin could then inject arbitrary root shell).
It runs a **script FILE a shell-access admin places on the box**, in the hook-script
dir `/usr/local/pkg/pfblockerng/list_scripts/` (`PFB_HOOK_SCRIPT_DIR`), named
`hook_pre_*` / `hook_post_*` (`.sh`/`.py`); the GUI only **picks** one from that folder
(the same model as the per-feed list pre/post-script picker). The picker, the save
handler, and the runner all gate on the same allow-list (`pfb_hook_script_valid()`):
a value that is not a `hook_<when>_*.{sh,py}` basename present in the folder is
rejected on save and skipped at run time — so a crafted/stale config value never runs.
This bounds the GUI's power to *selecting* an admin-vetted file; it does **not**
constrain what that script then does (its egress/side-effects are the author's
responsibility — there is no remote-domain sandbox).

**Model.** A list of hook entries in the pfBlockerNG config
(`installedpackages/pfblockerng/config/0/hooks`), each
`{ script, when: pre|post, enabled, description, timeout? }` (`script` = a basename in
the hook-script dir), run in **list order** (all `pre` before any processing, all
`post` after everything).

**Trust + execution.** Each enabled hook's selected `script` runs **as root** via its
own shebang + execute bit (the `list_scripts/` convention) — the **same trust class as
pfSense `shellcmd`/cron**, and the tab sits behind the existing admin-only pfBlockerNG
WebCfg privilege. Each hook is
run under `/usr/bin/timeout` (SIGTERM at the per-hook timeout, then SIGKILL after
a grace period; per-hook seconds, blank = the 60 s default). stdout+stderr are
captured to the pfBlockerNG log under a per-hook header. A hook's **non-zero exit
or timeout is logged and the update CONTINUES** — `pre` and `post` alike: a
bad/hung/typo'd hook can never abort or stall an update. With **no enabled
hooks** the update pass is byte-identical to before.

**Environment variables** (exported to the hook script; document only these —
no other value is promised):

| Var | When | Value |
| --- | --- | --- |
| `PFB_WHEN` | pre, post | `pre` or `post` |
| `PFB_TRIGGER` | pre, post | `cron` \| `update` \| `force-reload` |
| `PFB_IP_CHANGED` | post | `0` \| `1` — a firewall **rule** change happened this pass (a filter reload ran); **not** set by a content-only alias change |
| `PFB_DNSBL_CHANGED` | post | `0` \| `1` — DNSBL data changed this pass |
| `PFB_STATUS` | post | reserved placeholder — currently always `ok` |
| `PFB_CHANGED_IP_ALIASES` | post | space-separated list of IP firewall aliases (`pfB_*`) whose **contents** changed this pass; empty when none |
| `PFB_CHANGED_DNSBL_GROUPS` | post | space-separated list of DNSBL groups (`DNSBL_*`) genuinely updated this pass; empty when none |

`PFB_TRIGGER` emits exactly `cron | update | force-reload`: `update` is a settings
save, `force-reload` is a GUI IP-only / DNSBL-only Force Reload, and `cron` covers
scheduled cron **and** GUI Force Update / Force Reload (All) — the ADR's nominal
`force-update` collapses to `cron` because both arrive identically.

**`PFB_IP_CHANGED` is a rule-change signal, not a data-change signal.** It is `1`
only when the pass actually changed firewall **rules** (a filter reload ran). A pass
that merely refreshes an alias table's **contents** (the common case: a feed
re-downloaded with new entries, applied via `pfctl -T replace`) does **not** change
any rule, so `PFB_IP_CHANGED` stays `0` even though the table changed. To act when
the **blocklist data** changed, guard on a **non-empty** `PFB_CHANGED_IP_ALIASES`
(`[ -n "$PFB_CHANGED_IP_ALIASES" ]`), not `PFB_IP_CHANGED=1` — the latter misses
content-only updates. The HAProxy recipe below is the exception: it guards on
`PFB_IP_CHANGED` on purpose (it only needs to reload HAProxy when pfBlockerNG's
**rules** changed). `PFB_DNSBL_CHANGED` is the DNSBL data-changed flag.

`PFB_CHANGED_IP_ALIASES` and `PFB_CHANGED_DNSBL_GROUPS` list what the pass
**genuinely updated** this run (feeds re-processed / list rebuilt / removed) — the IP
firewall aliases (`pfB_*`) and the DNSBL groups (`DNSBL_*`) respectively, on their own
vars because DNSBL groups are not firewall aliases. The DNSBL list carries only groups
whose feed was actually (re)parsed this pass; the always-rebuilt internal specials
(`DNSBL_Regex` / `DNSBL_IDN` / `DNSBL_TLD_Allow`) are **excluded**. Both are
Reputation-mode-independent and are **not** a byte-level membership diff. `PFB_STATUS`
remains a stable reserved placeholder (no pass-wide error accumulator exists); its
**name** is stable, but do not branch a recipe on its value.
Hooks live in `config.xml`, so they **replicate to a CARP/HA secondary and run on
whichever node performs the update** — correct for the HAProxy recipe (the
secondary's HAProxy needs its own reload), but be aware a hook with an external
side effect runs once per updating node.

#### HAProxy recipe (reload to refresh CF-fronted real-client IP blocking)

The motivating use case (ADR-11 + ADR-12): block requests whose **real client IP**
(carried by Cloudflare in the `CF-Connecting-IP` header) is in pfBlockerNG's
aggregate alias. HAProxy only re-reads its `-f` ACL files **at reload** — the
pfSense runtime socket is stats + hitless-reload only and cannot inject ACL data
(`haproxy.inc:1562`) — so freshness requires a **graceful reload** after each
pfBlockerNG IP update.

**1. HAProxy config (frontend ACLs).** Add, on the frontend:

- a **`source_ip`** ACL (type *"Source IP matches IP or Alias"*) whose value is the
  alias **`pfB_Deny_Aggregated_v4`** (ADR-11). The HAProxy package emits the alias members
  to `ipalias_pfB_Deny_Aggregated_v4.lst` **only for a `source_ip`-type ACL referencing a
  pfSense alias** (`haproxy.inc:1084-1092`, written as `src -f …/ipalias_<alias>.lst`).
  This ACL exists purely to make the package emit and maintain that `.lst` file.
- a **custom header ACL** matching the CF real-client IP against that same file, e.g.
  `acl cf_blocked req.hdr_ip(CF-Connecting-IP) -f /var/etc/haproxy/ipalias_pfB_Deny_Aggregated_v4.lst`
  (use `req.hdr_ip(X-Forwarded-For)` if you front with XFF instead), and an action to
  `http-request deny if cf_blocked`.

> **Security — only trust the CF header from Cloudflare ranges.** `CF-Connecting-IP`
> (or XFF) is attacker-spoofable unless the connection actually came from Cloudflare.
> Gate the deny on the TCP source being a Cloudflare edge range (e.g. an additional
> `src -f` ACL of Cloudflare's published IP ranges) before honouring the header.

Because ADR-11 ships a **never-empty** `pfB_Deny_Aggregated_*` consumer file, an empty
aggregate still validates and reloads — **no `/../../` path trick or dummy-IP hack**
is needed (the old workarounds are gone).

**2. The post hook.** Save this as
`/usr/local/pkg/pfblockerng/list_scripts/hook_post_haproxy.sh` (`chmod +x`), then on
the **Update Hooks** tab add one entry — `when=post`, enabled — and pick it. The
script is POSIX-sh-safe and guards on the accurate flag so it only reloads when IP
data actually changed:

```sh
#!/bin/sh
# hook_post_haproxy.sh — reload HAProxy after a pfBlockerNG IP update
[ "$PFB_IP_CHANGED" = "1" ] && echo 'require_once("haproxy/haproxy.inc"); haproxy_check_run(1);' | /usr/local/sbin/pfSsh.php
```

`haproxy_check_run(1)` (wrapped by `haproxy_configure()`, `haproxy.inc:1347-1350`;
the reload core is `haproxy.inc:2491`) is the package's **graceful** reload: it
re-writes the config — re-emitting `ipalias_pfB_Deny_Aggregated_v4.lst` from the current
alias — and restarts with `-sf` (finish existing connections; hitless), **not** a
hard restart. `pfSsh.php` (`/usr/local/sbin/pfSsh.php`) is used rather than a bare
`php -r` because it bootstraps the pfSense environment (`globals.inc`/`functions.inc`/
`config.inc`/`util.inc`) so the `include_path` resolves `haproxy/haproxy.inc` and its
own `require_once` chain; it `eval`s the PHP piped on stdin. The hook runs on the
node that performs the update — on a CARP pair each node reloads its own HAProxy.

See [ADR-12](.ADRs/ADR_12_Update_Hooks/ADR.md) for the full design and the
maintainer smoke checklist.

#### Forwarding changed aliases to a webhook

To notify an external service of what a pass updated, save a `post` hook script that
`POST`s the changed-alias context to your endpoint (e.g.
`/usr/local/pkg/pfblockerng/list_scripts/hook_post_webhook.sh`, `chmod +x`), then pick
it on the tab. Guard on a **non-empty changed list** so the hook fires whenever the
blocklist **data** changed — including content-only refreshes that leave
`PFB_IP_CHANGED=0` (see the note above):

```sh
#!/bin/sh
# hook_post_webhook.sh — forward the changed-alias context to a webhook
{ [ -n "$PFB_CHANGED_IP_ALIASES" ] || [ -n "$PFB_CHANGED_DNSBL_GROUPS" ]; } && /usr/local/bin/curl -sS -m 5 \
  --data-urlencode "ip_aliases=$PFB_CHANGED_IP_ALIASES" \
  --data-urlencode "dnsbl_groups=$PFB_CHANGED_DNSBL_GROUPS" \
  --data-urlencode "ip_changed=$PFB_IP_CHANGED" \
  --data-urlencode "dnsbl_changed=$PFB_DNSBL_CHANGED" \
  https://example.invalid/pfblockerng-update
```

`curl` lives at `/usr/local/bin/curl` on pfSense. The guard above fires on **either**
side; to narrow to one, drop the other `[ -n … ]` test (e.g. keep only
`[ -n "$PFB_CHANGED_DNSBL_GROUPS" ]` for DNSBL-only notifications).

> **Guard on the changed-list, not `PFB_IP_CHANGED`.** `PFB_IP_CHANGED=1` means a
> firewall **rule** changed — it stays `0` on a pure alias-content refresh (the table
> is updated via `pfctl -T replace`, no rule change), so guarding on it would **miss**
> the data-changed case this recipe is for. `[ -n "$PFB_CHANGED_IP_ALIASES" ]` (a
> non-empty list of the IP aliases whose contents changed) is the correct
> "data changed" guard; `[ -n "$PFB_CHANGED_DNSBL_GROUPS" ]` is its DNSBL counterpart.
> `PFB_IP_CHANGED` / `PFB_DNSBL_CHANGED` are still forwarded in the payload above.
>
> **`PFB_CHANGED_IP_ALIASES` and `PFB_CHANGED_DNSBL_GROUPS` are space-separated
> lists (and may be empty) — they MUST be URL-encoded, never interpolated naked
> into a URL.** Pass each through its own `--data-urlencode` (as above), which sends
> them as a POST `application/x-www-form-urlencoded` body with the spaces encoded. A
> naive `?ip_aliases=$PFB_CHANGED_IP_ALIASES` in the URL is **broken**: the embedded
> space makes `curl` reject the URL (and an empty value yields a malformed query). To
> send them in the query string instead, use `--data-urlencode "…" --get` so `curl`
> still encodes each field.

## Benchmarks

`benchmarks/` holds an opt-in suite comparing the domain-trie matcher against the
flat-dict matcher it replaced (latency on positive/negative queries, and memory
footprint). It is dev-only, not shipped, and not collected by the default
`pytest` run. See [`benchmarks/README.md`](benchmarks/README.md):

```sh
python -m pip install -r benchmarks/requirements.txt
python -m pytest benchmarks/test_bench_matching.py --benchmark-columns=min,mean,ops
python -m pytest benchmarks/test_memory.py -s
```

It also holds the ADR-06 init-time / peak-RAM spike for the Python DNSBL build —
the kill-gate that gated moving preprocessing into the plugin (build wall-time and
retained dict footprint on a large, un-pruned ≥1M-entry corpus):

```sh
python -m pip install pympler    # dev-only retained-footprint tool (ADR-05 §3a)
SPIKE_N=5 SPIKE_SIZES=1000000 python benchmarks/spike_adr06_build.py
```

…and the ADR-07 regex/ReDoS spike (`spike_adr07_regex.py`, stdlib only) — the
de-risking measurement for full ABP support: regex reduction ratio, irreducible
count, added per-query latency at feed scale, and the worst real ReDoS first-hit
on a ≤253-char input vs the kill-threshold (run with `tracemalloc` off):

```sh
python benchmarks/spike_adr07_regex.py
SPIKE_COUNTS=10,100,1000 SPIKE_ROUNDS=50 python benchmarks/spike_adr07_regex.py
```

## Linting

### Python

[Ruff](https://docs.astral.sh/ruff/) is configured in `pyproject.toml`, enforced
in CI (`ruff check .` + `ruff format --check .`), and can be run locally:

```sh
pip install ruff
ruff check .        # lint
ruff check . --fix  # lint and auto-fix
ruff format .       # format
```

### PHP

[PHPStan](https://phpstan.org/) runs at level 0 and is configured in
`phpstan.neon`.  Pre-existing legacy errors are suppressed via
`phpstan-baseline.neon`; only errors introduced by new changes will fail.

Install dependencies once (requires [Composer](https://getcomposer.org/)):

```sh
composer install
```

Then run the analysis:

```sh
vendor/bin/phpstan analyse
```

The same `composer install` provides [PHPUnit](https://phpunit.de/) for the PHP
unit suite (`vendor/bin/phpunit`, config in `phpunit.xml`) — the fast functional
layer beneath the live-VM smoke. See
[Running the test suite locally](#running-the-test-suite-locally) and
[`tests/php/README.md`](tests/php/README.md).

### Shell

[ShellCheck](https://www.shellcheck.net/) is available as a VS Code extension
(see IDE setup above) and is also enforced in CI at `--severity=info`.
Configuration is in `.shellcheckrc`. Functional shell tests (shellspec) live in
`tests/shell/` — see [Shell tests (shellspec)](#shell-tests-shellspec) above.

### Markdown

[markdownlint](https://github.com/DavidAnson/markdownlint) runs as a VS Code
extension (see IDE setup above) and on the command line, and is enforced in CI:

```sh
npx markdownlint-cli2          # lint
npx markdownlint-cli2 --fix    # lint and auto-fix
```

The rule set is in `.markdownlint.jsonc` and the runner globs/ignores are in
`.markdownlint-cli2.jsonc`. The ruleset is pragmatic: it disables rules that
fight the documentation style (`MD013` line length, `MD060` table alignment,
`MD036` inline sub-headers, `MD041` first-line heading) and ignores the verbatim
`TRANSCRIPT.md`.

## Building and deploying

### Building via the FreeBSD ports system

On a FreeBSD machine with the ports tree available:

```sh
# Stable
cd /usr/ports/net/pfSense-pkg-pfBlockerNG
make package

# Devel
cd /usr/ports/net/pfSense-pkg-pfBlockerNG-devel
make package
```

The resulting `.pkg` file is in `work/pkg/`.

### Deploying to a pfSense box for testing

Use the helper script to push files directly to a running pfSense box
over SSH. The script copies changed source files to the correct system
paths and restarts the relevant services.

```sh
./scripts/deploy.sh <pfsense-host> [--channel devel|stable]
```

Example:

```sh
./scripts/deploy.sh root@192.168.1.1
./scripts/deploy.sh root@192.168.1.1 --channel stable
```

The script defaults to the **devel** channel (files from this branch).
Pass `--channel stable` when deploying from the `main` branch.

See [`scripts/deploy.sh`](scripts/deploy.sh) for full options.

### How the `pkg` repository is published (GitHub Pages)

The self-hosted repository (installed per the [README](README.md#option-2--this-forks-self-hosted-pkg-repository))
is a **derived index** — there is no stateful store to maintain. It is hosted and
deployed by the **separate [`pfBlockerNG/pkg`](https://github.com/pfBlockerNG/pkg) repo**
(its `publish.yml`), which deploys to **its own** GitHub Pages via same-repo OIDC — no
cross-repo deploy key. On each run it builds the current **devel** `.pkg` (running this
repo's `scripts/build-pkg-portable.py` against a checkout of the source), folds in the
`.pkg` assets of **all** GitHub Releases, buckets by ABI, **regenerates** a fresh `pkg`
catalog (`meta.conf`/`packagesite.pkg`/`data.pkg`) per ABI, and deploys the whole
`${ABI}/` tree. The site is replaced each run (no history), so every published version/ABI
is retained for free and a rollback is a re-deploy.

- **Per-`${ABI}` tree.** One catalog under `…/<ABI>/` (today only `FreeBSD:15:amd64` — CE
  2.8 and Plus 25.03 share it). The client conf's literal `${ABI}` lets one conf follow the
  box across a pfSense OS upgrade.
- **NONE-signed, TLS-anchored.** No signing key in CI; trust is HTTPS to the Pages host. The
  catalog is served at the project's GitHub Pages URL
  **`https://pfblockerng.github.io/pkg/${ABI}`**.
- **Generators.** `scripts/build-repo-portable.py` is the primary — pure Python (stdlib +
  `zstd`), no libpkg, run on a plain Linux runner. `scripts/build-repo.sh` (real `pkg repo`
  in a FreeBSD VM) is the fidelity fallback, and is also the single `--print-conf` source the
  bootstrap (`scripts/add-repo.sh`) and the inline conf in the README reuse byte-for-byte.
- **Triggers.** `pfBlockerNG/pkg`'s `publish.yml` runs on a daily `schedule` +
  `workflow_dispatch`, and `release.yml`'s `repo-publish` job fires it on each release
  (`gh workflow run`, auth via a GitHub App token from `actions/create-github-app-token@v3` —
  secrets `PKG_GITHUB_APP_ID` + `PKG_GITHUB_APP_PRIVATE_KEY`, `Actions:write` on
  `pfBlockerNG/pkg` only). That job is additive + isolated (only `needs: [release]`), so
  its failure never breaks the Release or the ports PR.

See [ADR-17](.ADRs/ADR_17_Pkg_Repository/ADR.md) for the full design.

## Smoke tests (live pfSense VM)

The smoke suite (ADR-04, `tests/smoke/`) boots a **real pfSense CE VM** under
QEMU/KVM, installs the branch's freshly-built `.pkg`, and asserts pfBlockerNG's
real behaviour end-to-end — the DNS path (Unbound + `pfb_unbound.py`, probed
with `dig`/`dnspython`) and the IP path (`pfctl` alias tables + rules, over
SSH). It is **dev-only**, marked `@pytest.mark.smoke`, and **deselected from the
default `python -m pytest`** (`pyproject.toml` `addopts: --ignore=tests/smoke`),
so the normal unit run is unaffected.

### Running it in CI

The **default full run is the fan-out**: `.github/workflows/smoke-fanout.yml`
runs the ADR-04 suite across **every `ci:true` image — CE *and* Plus** (ADR-24) —
in parallel (`fail-fast: false`), gated by the `all-smoke-passed` AND-check. It
takes **no inputs** (it reads the CI matrix from the `ci-metadata` branch), is the
validation an ADR is accepted against, and is what `version-tracker` dispatches on
a version bump (plus a nightly `schedule`). This is the canonical "run the smoke
suite" command:

```sh
gh workflow run smoke-fanout.yml                  # all ci:true legs (CE + Plus) — the default
```

Both it and the single-leg callee are **gated** — `workflow_dispatch` +
`workflow_call` (the fan-out also runs nightly) — **not** every-PR yet, because the
per-run wall-time has not been measured against §7's ~20 min/job budget.

For a **narrow, single-leg run** — one image, or a non-default `pytest_marker` the
fan-out can't select (e.g. the ADR-17 `repo` flow) — drive the reusable callee
`.github/workflows/smoke.yml` directly (it is also what the fan-out invokes per leg):

```sh
gh workflow run smoke.yml                          # single CE leg (composes the ref from the SMOKE_IMAGE_* vars)
gh workflow run smoke.yml -f image_ref=ghcr.io/<org>/pfsense-ce@sha256:<digest>
gh workflow run smoke.yml -f pytest_marker=repo    # ADR-17 repo-install flow (single leg)
```

The ADR-17 repository-install flow has its **own** fan-out too —
`.github/workflows/repo-install.yml` runs the `repo` marker across **every `ci:true`
leg (CE + Plus)** on a nightly `schedule` + `workflow_dispatch`, so the self-hosted
`pkg` repo is proven to install on Plus as well as CE.

The workflow builds the `.pkg` (`build-pkg-linux.yml`, portable Linux builder), pulls the pfSense
image from private GHCR, then runs `pytest -m smoke`. The test fixture **blocks
the runner's egress after `deploy()`** so the run is hermetic — feeds come from
an in-runner mock server reached over the SLIRP host alias `10.0.2.2`. Required
Actions
config (see `.ADRs/ADR_04_VM_Smoke_Tests/RESULTS/02_Results.txt`):
`SMOKE_IMAGE_REF`, `SMOKE_GHCR_USER`, `SMOKE_GHCR_TOKEN`, `SMOKE_SSH_PRIV_KEY`
(and, to match the baked image, `SMOKE_DNSBL_VIP4` / `SMOKE_CONTROL_NAME` /
`SMOKE_CONTROL_IP`).

### Running it locally

Needs `/dev/kvm`, `qemu-system-x86_64` + `qemu-img`, `oras`, `ssh`, and a built
`.pkg`. Then:

```sh
python -m pip install -r tests/smoke/requirements.txt
export SMOKE_IMAGE_REF=ghcr.io/<org>/pfsense-ce@sha256:<digest>   # private GHCR
export SMOKE_SSH_KEY=/path/to/guest_priv_key                      # mode 600
export SMOKE_PKG=/path/to/pfBlockerNG-*.pkg                       # from build-pkg
oras login ghcr.io                                                # for the pull
python -m pytest tests/smoke -m smoke --override-ini="addopts="
```

The fixture pulls the image by `SMOKE_IMAGE_REF` and boots an ephemeral overlay
(the base qcow2 is never mutated). Missing KVM/secrets/deps → the suite **skips**
cleanly, never errors. (CI sets `SMOKE_IMAGE_DIR` instead, pointing at the
pre-pulled image, so the fixture blocks egress after `deploy()` without
needing another network pull.)

### Rebuilding the image on a CE bump

When a new pfSense CE release lands (or you raise the minimum supported CE version),
follow this three-step procedure. The daily **version-tracker** (`version-tracker.yml`)
performs steps 2–3 automatically once the matrix is updated; you can also dispatch
each workflow manually.

**Step 1 — Update the supported-version matrix.**
Edit `supported-versions.json` on the `ci-metadata` orphan branch via a PR against
`ci-metadata`. Add a new entry (or update `status: "beta"` → `"GA"`; or drop the
oldest CE entry when the newest goes GA). Schema and lifecycle policy:
[`scripts/README.md`](scripts/README.md#supported-version-matrix).

**Step 2 — Refresh the CI smoke image.**
Dispatch `.github/workflows/image-refresh.yml` with `pfsense_version` and
`freebsd_version` from the new matrix entry. The workflow:

1. Pulls the current GHCR tag for this CE version.
2. Boots a copy and runs `pfSense-upgrade` (works for patch, minor, and major jumps).
3. Applies the **six-check sanity gate** (VM boots; SSH answers; `/etc/version` matches;
   `pfctl -sr` loads; `install-from-repo.sh` + `pfblockerng.php update` exit 0;
   `dig` control record resolves).
4. Publishes the new GHCR tag **only on gate pass** — fail-closed (a bad image is
   never published). Old tags are kept.

If the gate fails, use `scripts/image-publish.sh` to produce a fresh seed from a
clean manual install (manual fallback — see
[`.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`](.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md)).
The automated image refresh (`image-refresh.yml`) is **CE-only**; the **Plus** image is
refreshed **manually** with `scripts/image-publish.sh` (re-export + push the licensed,
private qcow2 — the MAC/SMBIOS uuid must stay constant, ADR-24). The seed and every version
snapshot are retained as immutable GHCR tags; the GHCR package is **private**.

**Step 3 — Run the smoke fan-out.**
Dispatch `.github/workflows/smoke-fanout.yml` (no inputs — it reads the CI matrix
itself). The fan-out runs the ADR-04 smoke suite across **all** `ci: true` images —
**CE and Plus** (ADR-24) — in parallel (`fail-fast: false`). The `all-smoke-passed`
AND-gate fails if any single leg fails — one red leg makes the whole gate red, no partial pass.

### Adding a matrix case

Cases live in `tests/smoke/test_smoke_matrix.py` and compose the Phase-4 helpers
(`tests/smoke/helpers.py`). The recipe (full version in
`RESULTS/05_Results.txt`):

1. Register the feed body in memory (hermetic, no fixture file):
   `feed_url = mock_feeds.register("smoke_<name>.txt", "<body lines>\n")`.
2. Build a spec — `h.DnsblCase(...)` (DNS path) or `h.IpCase(...)` (IP path) —
   choosing the response mode from the map: **NXDOMAIN** = `dnsbl_python` (exact
   match only, no subdomain block), **NULL** = `dnsbl_unbound` +
   `logging='disabled'`, **VIP** = `dnsbl_unbound` + `logging='enabled'`.
3. Drive it through `with h.CaseContext(deployed_vm, spec):` (it picks the
   reload verb; pass `scope="update"` for DNSBL-IP), then assert with
   `h.dns_probe` / `h.is_nxdomain` / `h.is_null_ip` / `h.is_vip` /
   `h.resolves_to`, and `h.pfctl_table_members` / `h.member_present` /
   `h.rule_references` for the IP side. `__exit__` resets to baseline.

### HTTP feed-load smoke (ADR-16)

`tests/smoke/test_smoke_feeds.py` (marker `smoke`) exercises the **real
HTTP fetch path** — pfBlockerNG's `curl` over SLIRP to the `_MockFeedServer`
— across the representative IP + DNSBL formats. This is the only place in the
suite where a feed arrives over HTTP rather than a local file (`write_local_feed`).

**Fixture files** live under `tests/smoke/fixtures/` and are committed to the
repo. Each file is the verbatim body `curl` fetches; the guest reaches it at
`http://10.0.2.2:<port>/<filename>` over SLIRP (survives the egress block):

| File | Format | Type |
|------|--------|------|
| `ip_plain_cidr.txt` | plain IPv4 + CIDR | IP v4 |
| `ip_range.txt` | IPv4 range `a-b` | IP v4 |
| `ip_ipv6.txt` | IPv6 single + CIDR | IP v6 |
| `dnsbl_plain.txt` | plain domain | DNSBL |
| `dnsbl_hosts.txt` | hosts `0.0.0.0 domain` | DNSBL |
| `dnsbl_abp.txt` | ABP / EasyList (\|\|d^ block, @@ allow) | DNSBL |

All data is inert: IP files use RFC 5737 / RFC 3849 documentation ranges;
DNSBL files use `uuid-<hex>.com` names.

**How cases register a fixture.** In a test, pass `mock_feeds.feed_url("<name>")`
as the `feed_url` to `IpCase`/`DnsblCase`. `_MockFeedServer.register()` is
called automatically for each file in `tests/smoke/fixtures/` when the
`mock_feeds` fixture starts. To add a new format:

1. Drop a fixture file into `tests/smoke/fixtures/` (follow the inert-data rule).
2. Update `tests/smoke/fixtures/README.md` to document its member/non-member set.
3. Add a case in `test_smoke_feeds.py` using `mock_feeds.feed_url("<name>")`.

**Kill-gate / gate status.** The HTTP-fetch reliability is the ADR-16 Part-C
kill-gate (≥ 4/5 clean runs). The test is authored in the `smoke` marker and
gated as part of the `ui-tests`-labeled PR suite; the GO/DEMOTE decision is
recorded in `.ADRs/ADR_16_Feeds_Tabs_And_Feed_Smoke/RESULTS/05_Results.txt`
(status: OPTIMISTIC-GO, pending the live CI run). If the live run shows
&lt; 4/5 clean, `test_smoke_feeds.py` is demoted to dispatch-only as a fast-follow.

## Web UI tests (live pfSense VM)

The UI suite (ADR-14, `tests/smoke/ui/`) drives the **webConfigurator** on the
same ADR-04 smoke VM — reusing the `smoke_vm` fixture and `helpers.py` — to catch
WebUI regressions that `php -l`/PHPStan structurally cannot (pages that 500,
render a PHP `Warning`/`Notice`, or break form persistence). It is **dev-only**,
deselected from the default `python -m pytest` exactly like the smoke suite
(`--ignore=tests/smoke`), so the normal unit run is unaffected. Three tiers, by
cost/frequency:

| Tier | Marker | What it does | When |
|------|--------|--------------|------|
| **A — render-smoke** | `ui_render` | Authenticated-HTTP GET of every pfBlockerNG page (the 14 main paths + the dashboard widget + the two DNSBL-VIP sinkhole pages) → 200, body free of `Fatal error`/`Parse error`/`Warning`/`Notice`/`Uncaught`, a page-specific marker present, **and** no new `php_error.log` line during the sweep. Cheap/hermetic. | **Per-PR** when PHP/JS files change (blocking); release |
| **B — functional** | `ui_e2e` | CSRF-POST flows (save General; add/save an IP feed/alias; toggle a DNSBL setting) → assert the **effective** `config.xml`/`pfctl`/unbound state via `helpers.config_get`, never the HTTP response alone. | Daily/on-demand; release |
| **B — browser** | `ui_browser` | Headless Playwright/Chromium reusing the auth session (injected `PHPSESSID` cookie — no second login) to exercise the JS-only UX (`enable_change_*`, `pfb_autocomplete*`, `pfb_chg_state_bkgd`, the dashboard widget) and capture **per-page screenshots** as artifacts. | Daily/on-demand; release |

The pass/fail oracle is **never HTTP 200 alone** (a 200 can carry a rendered PHP
warning or a blank body) — Tier A reads the body + the page marker + the on-box
`php_error.log`; Tier B asserts the effective state.

### Feeds page — IPv4 / IPv6 / DNSBL sub-tabs (ADR-16)

The **Feeds** page (`pfblockerng_feeds.php`) is organized into **IPv4 / IPv6 /
DNSBL sub-tabs** (`?type=ipv4|ipv6|dnsbl`, default `ipv4`), matching the IP /
DNSBL / Reports top-level structure. Each sub-tab renders only its own type's
Feed Settings alias-name inputs and predefined-feeds table; a bare URL defaults
to the IPv4 tab. The Tier-A render entries are `feeds_ipv4`, `feeds_ipv6`, and
`feeds_dnsbl` (three `ui_render` cases, one per `?type`). A `ui_browser` test
(`tests/smoke/ui/test_browser_feeds.py`, marker `ui_browser`) screenshots all
three tabs and asserts the second sub-tab row (`[IPv4 | IPv6 | DNSBL]`), the
active-tab highlight, and that each tab lists only its type.

### Running it in CI

`.github/workflows/ui-tests.yml` is a **reusable** workflow
(`workflow_call` + `workflow_dispatch` + a daily `schedule`), matrix-parametric
on **image-ref/version** and tier-selectable, building the branch `.pkg` via
`build-pkg-linux.yml` and booting the GHCR image. **One GH job per
(tier × version)** with `fail-fast: false`, so GitHub's "Re-run failed jobs"
re-runs only the flaky leg (no auto-retry on assertions; bounded readiness retry
only on boot/login). Diagnostics (screenshots + VM/boot logs + the smoke state
snapshot) upload `if: always()` as `ui-diagnostics-<tier>-<variant>-<version>`
(variant = ce/plus, e.g. `ui-diagnostics-browser-ce-2.8`). Wiring:

- **Tier A** runs per-PR (`test.yml`) on PRs touching `src/**/*.php`, `**/*.inc`,
  `src/**/*.js`, folded into the **"All tests passed"** aggregate (blocking).
- **Tier B** (functional + browser) runs on the daily `schedule` (skipped when no
  commit landed in 24 h) and on `workflow_dispatch` — **never** gating a PR.
- **Release** (`release.yml`) `needs:` the full suite (`tier: all`) via the
  `ui-suite` job before `release`/`ports-pr` — each leg re-runnable in isolation
  (a flaky browser leg costs one re-run, not a republish).

Dispatch a run with:

```sh
gh workflow run ui-tests.yml -f tier=render        # one tier
gh workflow run ui-tests.yml -f tier=all           # render + functional + browser
gh workflow run ui-tests.yml -f image_ref=ghcr.io/<org>/pfsense-ce@sha256:<digest>
```

### Running it locally

Same prerequisites as the smoke suite (`/dev/kvm`, `qemu`, `oras`, `ssh`, a built
`.pkg`) plus the UI deps. The browser tier also needs the Chromium binary
(a separate download from the `playwright` wheel) and skips cleanly without it:

```sh
python -m pip install -r tests/smoke/requirements.txt
python -m playwright install chromium                 # browser tier only
export SMOKE_IMAGE_REF=ghcr.io/<org>/pfsense-ce@sha256:<digest>
export SMOKE_SSH_KEY=/path/to/guest_priv_key          # mode 600
export SMOKE_PKG=/path/to/pfBlockerNG-*.pkg           # from build-pkg
export SMOKE_ADMIN_PASSWORD=<baked admin password>    # else the UI fixtures SKIP
python -m pytest tests/smoke/ui -m ui_render   --override-ini="addopts="   # Tier A
python -m pytest tests/smoke/ui -m ui_e2e      --override-ini="addopts="   # Tier B functional
python -m pytest tests/smoke/ui -m ui_browser  --override-ini="addopts="   # Tier B browser
```

Without `SMOKE_ADMIN_PASSWORD` the UI fixtures **skip** cleanly (never fail), so a
run that lacks the baked credential degrades gracefully. Screenshots land under
`$SMOKE_UI_SCREENSHOT_DIR/<version>/` (default `test-results/ui-screenshots/`, a
git-ignored build output).

### Version matrix and adding an image

The `version` axis is built **parametric** but runs the **single existing CE
image** today. Adding a second pfSense image (Plus / another CE) is a one-line
change — append a label to `DEFAULT_VERSIONS` in the `prepare` job of
`ui-tests.yml` and wire its image ref — then the matrix expands to one leg per
(tier × version) with no harness change. Building/publishing that image follows
[`.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`](.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md)
(see [Rebuilding the image on a CE bump](#rebuilding-the-image-on-a-ce-bump) above).

## Image pipeline (smoke-test base)

The CI smoke harness (ADR-04) boots a real pfSense CE VM. Three dev-only scripts
build and drive its disk image — no Packer, since pfBlockerNG compiles nothing:

- [`scripts/image-publish.sh`](scripts/image-publish.sh) — on the Proxmox host,
  export a powered-off VM's ZFS disk to a compressed qcow2 and `oras push` it to
  GHCR, tagged by CE version (older tags kept).
- [`scripts/image-upgrade.sh`](scripts/image-upgrade.sh) — pull a published tag,
  boot it, run `pfSense-upgrade`, power off, and publish the result as a new
  version tag (the source tag is left untouched).
- [`scripts/install-from-repo.sh`](scripts/install-from-repo.sh) — install
  pfBlockerNG onto a clean pfSense **from this repo's `src/`** (no Netgate pkg),
  via the port's `rc.packages … POST-INSTALL` hook. pfBlockerNG is not baked into
  the image; the harness runs this after every boot (the disk is immutable).

These produce one image per supported minor CE version; CI runs the smoke matrix
across all of them. See [`scripts/README.md`](scripts/README.md) for the build/ABI
details and [`.ADRs/ADR_04_VM_Smoke_Tests/`](.ADRs/ADR_04_VM_Smoke_Tests/).

## Releasing

New features land in `devel`; `devel` is promoted to `main` by rebase to cut a
stable release. When a version is ready to ship, tag the commit and push the tag:

```sh
# From devel (pre-release)
git tag v3.2.17-devel
git push origin v3.2.17-devel

# From main (production release)
git tag v3.2.16
git push origin v3.2.16
```

The release workflow will:

1. Run the test suite.
2. Publish a GitHub Release with a changelog.
3. Open a PR on [pfsense/FreeBSD-ports](https://github.com/pfsense/FreeBSD-ports)
   updating `GH_TAGNAME` in the corresponding port Makefile.
4. Publish the self-hosted `pkg` repository to GitHub Pages (see
   [How the `pkg` repository is published](#how-the-pkg-repository-is-published-github-pages)).

To update the ports tree manually instead:

```sh
# In your FreeBSD-ports clone, edit the appropriate Makefile:
# net/pfSense-pkg-pfBlockerNG/Makefile        (stable)
# net/pfSense-pkg-pfBlockerNG-devel/Makefile  (devel)

# Update GH_TAGNAME to the new tag, then bump PORTREVISION if the
# PORTVERSION is unchanged, or update PORTVERSION to match the new tag.
```
