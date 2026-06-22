# Architecture notes (dev-only)

Implementation detail extracted from `CLAUDE.md` to keep the always-loaded instructions
lean. This is the mid-level summary; the authoritative design for each item is its
`.ADRs/ADR_NN_*/` directory. Read the relevant section here before touching the code it
describes.

---

## DNSBL/ABP pipeline (ADR-06, ADR-07, ADR-10, ADR-12)

### ADR-06 — DNSBL list preprocessing moved to Python

DNSBL list preprocessing (parse → normalise → classify data/zone → build dicts + feed/group
index + `whiteDB`, then emit `pfb_py_count`) lives in `pfb_unbound.py`'s pure
`dnsbl_build_from_manifest()` / `build()`, fed by the PHP/shell-written manifest
(`/var/unbound/pfb_py_sources.json` + per-feed raw). PHP/shell only download + tag + run the
DNSBL-IP firewall pass. Decision-equivalence is pinned by `tests/test_adr06_*` (golden oracle,
build module, init-from-raw, PHP boundary); the init/peak-RAM kill-gate is
`benchmarks/spike_adr06_build.py` — it exits non-zero on NO-GO (`--report-only` forces exit 0).
Its synthetic `build()` on a generic runner is NOT the production number, so the CI
`benchmarks` job is **manual-only** (dispatch Tests with `run_benchmarks`, default off); the
real build-time/RAM regression gate is moving to the live smoke VM (timing `updatednsbl`
start→finish + unbound RSS) — see issue #76 and `.ADRs/ADR_06_DNSBL_Preprocessing_To_Python/`.

### ADR-07 — ABP / EasyList support

ABP/EasyList feeds are parsed **entirely in Python**: PHP header-sniffs an ABP feed, tags it
`format_hint='abp'`, and passes its raw lines through verbatim (IP anchors `||1.2.3.4^` and
hosts IPs still divert to the DNSBL-IP firewall pass); the old PHP `$easylist` lite parser is
deleted. `parse('abp', …)` is the one DNS-only ABP parser — it adds `@@` allow exceptions,
regex (block `regexDB` / allow `allowRegexDB`, with anchored patterns folded to dicts), and
`$important`/`$badfilter` precedence resolved by a 6-band numeric scale, with a build-emitted
`important_rules` flag preserving a byte-identical fast path when no ABP precedence feature is
loaded. Untrusted feed + user regex is guarded by an opt-in "Limit long/complex regex" static
cap (drops over-long/nested-quantifier patterns at load) plus an always-on runtime warn/evict
timer (warn 10 ms / evict 100 ms thread-CPU; snapshot-iterate, evict-after-loop). Pinned by
`tests/test_adr07_*` (decision spec/oracle, parser, reconcile, matcher strata, emit/wire,
regex safety, PHP boundary); the regex/ReDoS kill-gate is `benchmarks/spike_adr07_regex.py` —
it exits non-zero on NO-GO (`--report-only` forces exit 0), runnable via the manual-only CI
`benchmarks` job. See `.ADRs/ADR_07_ABP_DNSBL_Support/`.

### ADR-10 — zero-downtime DNSBL data swap

A DNSBL **DATA** update is a **zero-downtime background swap — no Unbound restart**. The module
holds the matcher strata as one frozen `Snapshot` behind a single module ref; a reload-watcher
daemon thread (`kqueue` `EVFILT_VNODE`, mtime-poll fallback) wakes on a generation **sentinel**
(`/var/unbound/pfb_py_reload`), rebuilds off the live snapshot, and **atomically swaps** the
single ref (GIL-atomic → visible to every query thread, no torn read, no dropped queries).
PHP/shell **atomically publish** the manifest (stage → `fsync` → `rename`) then **flip the
sentinel** (next integer) — the all-or-nothing commit. After flipping, PHP **waits (bounded)
for the watcher's applied-generation marker** to catch up, so the reload call returns only once
the new lists are LIVE (queries keep flowing on the old snapshot during the wait — still
zero-downtime; this restores the "lists live on return" invariant the restart had, so the
ADR-12 `post` hook sees the new state).

- **Data = swap; config = restart:** feed/cron updates AND the user custom-list edits (alerts
  Lock/Unlock + "add to whitelist" + customlist add/delete, #51) take the no-restart fast path;
  an `unbound.conf`/mode/Resolver change still restarts.
- **Fallback to restart (fail-safe)** when the swap can't run: a RAM-constrained box (PHP RAM
  gate primary, Python free-page probe secondary — the ~2× transient build/swap footprint is
  `benchmarks/spike_adr10_swap.py`'s kill-gate), the feature/python mode off, Unbound down, a
  staged config change, or a prior swap/sentinel error.
- **Cache on swap:** Reports reset; `decisionDB` cleared (no stale decision); **block→allow
  immediate** (blocks not C-cached since #43); **allow→block** flushes the prior resolved answer
  — a targeted delta flush for the #51 single-domain case, TTL-bounded for feed/cron (not a
  regression — the restart is TTL-stale there too).
- **Fail-closed:** a bad/partial build keeps the last-good snapshot serving.

Pinned by `tests/test_adr10_*` (snapshot equivalence, fail-closed swap, watcher); idle
decision-identity stays guarded by `tests/test_adr06_*`/`tests/test_adr07_*`. See
`.ADRs/ADR_10_Zero_Downtime_DNSBL/`.

### ADR-12 — update hooks (PHP/shell, no Python)

Admin-VETTED `pre`/`post` **scripts** run once per update pass from
`sync_package_pfblockerng` in `pfblockerng.inc` — `pfb_run_hooks($when, $ctx)` reads enabled
hooks from `installedpackages/pfblockerng/config/0/hooks` (`{script, when, enabled,
description, timeout}`), runs each **as root** via `/usr/bin/timeout … <script>` in list order,
captures output to the pfBlockerNG log, and **non-zero/timeout → log + continue** (a hook can
never abort/stall an update; no enabled hooks ⇒ byte-identical pass). Security model: `script` is
NOT a GUI-typed command — it is a `hook_<when>_*.{sh,py}` file a shell-access admin places in
`list_scripts/` (`PFB_HOOK_SCRIPT_DIR`); the picker/save/runner all gate on the same allow-list
(`pfb_hook_script_valid()`), so a GUI user can only *select* a vetted file, never inject shell.
Admin-only **Update Hooks** settings tab (`www/pfblockerng/pfblockerng_hooks.php`, same WebCfg
priv as the other settings).

Exported env (only these are promised):

- `PFB_WHEN` (`pre`|`post`)
- `PFB_TRIGGER` (`cron`|`update`|`force-reload` — the ADR's `force-update` collapses to `cron`)
- post-only `PFB_IP_CHANGED`/`PFB_DNSBL_CHANGED` (`0`|`1`, accurate — guard on these)
- `PFB_CHANGED_IP_ALIASES` (post-only, space-separated `pfB_*` IP firewall aliases updated this
  pass) and `PFB_CHANGED_DNSBL_GROUPS` (post-only, space-separated `DNSBL_*` groups updated this
  pass — split from the IP aliases because DNSBL groups are not firewall aliases); both sourced
  from the signal the pass already computes, Reputation-mode-independent, empty on a no-op pass
- `PFB_STATUS` (the sole remaining stable reserved placeholder: always `ok` — do not branch on
  its value)

The `post` hook sees the new DNSBL state live (ADR-10's bounded wait-for-apply runs before the
pass returns). Hooks live in config ⇒ replicate to a CARP/HA secondary and run on whichever node
updates. The shipped **HAProxy recipe** (README) is a `post` hook guarded on
`[ "$PFB_IP_CHANGED" = "1" ]` whose command pipes `haproxy_check_run(1)` (graceful reload)
through `/usr/local/sbin/pfSsh.php`; validation = `php -l`/PHPStan/ShellCheck + a maintainer
manual smoke (no pytest oracle). See `.ADRs/ADR_12_Update_Hooks/`.

### ADR-11 — aggregate ("Uber") aliases live smoke — `tests/smoke/test_smoke_aggregate.py`

`test_smoke_aggregate.py` (marker `smoke`, same ADR-04 harness/`deployed_vm` shape as the hooks
file) drives the opt-in `pfb_agg_types` multi-select end-to-end on a real pf table: none-selected
no-op, Deny builds the table with **no firewall rule** (Native), cross-type non-leakage
(Permit ∉ Deny aggregate), additive `{Deny}`→`{Deny,Permit}`, never-empty `.lst` on an empty
union, teardown on deselect, the DNSBLIP→Deny fold, and the **post-hook freshness** leg (the
`post` hook reads `pfctl -t pfB_Deny_Aggregated_v4 -T show` + its env after a forced feed change
and sees the **new** IP + the alias in `PFB_CHANGED_IP_ALIASES`). Setter `helpers.set_aggregate_types`
(read-back-guarded CSV scalar) + `aggregate_table`/`aggregate_consumer_path`. The membership
decision is unit-pinned off-box in `tests/php/AggregateMemberListTest.php`; HAProxy
referenceability + the GeoIP/suppress content spot-check stay ADR §7 maintainer-manual. The
General-page `pfb_agg_types` render is covered by the ADR-14 Tier-A gate (next section).

---

## Web UI test tiers (ADR-14) — `tests/smoke/ui/`

The Web-UI suite **reuses** the smoke `smoke_vm` fixture + `helpers.py` (no separate harness)
to drive the live webConfigurator. It is off the default `pytest` like the rest of
`tests/smoke/`. Three tiers, each its own pytest marker:

- **Tier A — `ui_render`** (cheap/hermetic, the **PR gate**): authenticated-HTTP GET of every
  pfBlockerNG page → 200, body free of `Fatal error`/`Parse error`/`Warning`/`Notice`/`Uncaught`,
  a page-specific marker present, **and** no new on-box `php_error.log` line. **Never HTTP 200
  alone** — body + marker + `php_error.log` is the oracle.
- **Tier B — `ui_e2e`** (daily/on-demand): CSRF-POST flows asserting the **effective**
  `config.xml`/`pfctl`/unbound state via `helpers.config_get`, not the HTTP response.
- **Tier B — `ui_browser`** (daily/on-demand): headless Playwright/Chromium reusing the auth
  session (injected `PHPSESSID` cookie — **no second login**), exercising the JS-only UX and
  capturing per-page screenshots. Needs the separately-downloaded Chromium binary
  (`python -m playwright install chromium`); module-level `importorskip` SKIPs cleanly without it.

Run a tier against a smoke VM exactly like the smoke suite — re-enable the package and select
the marker (`SMOKE_ADMIN_PASSWORD` must be set, else the UI fixtures SKIP, never fail):

```sh
python -m pytest tests/smoke/ui -m ui_render --override-ini="addopts="
```

The reusable `ui-tests.yml` (`workflow_call` + `workflow_dispatch` + daily `schedule`) is
matrix-parametric on image-ref/version and tier-selectable, **one GH job per (tier × version)**
(`fail-fast: false` → "Re-run failed jobs" re-runs only a flaky leg). Tier A gates PHP/JS PRs
(folded into "All tests passed"); Tier B is schedule/dispatch only (non-PR-blocking);
`release.yml` `needs:` the full suite (`tier: all`, the `ui-suite` job) before publishing, each
leg re-runnable in isolation. The version axis is parametric but runs the **single CE image**
today (B1) — adding one is a one-line `DEFAULT_VERSIONS` append + image-ref wire (IMAGE_RUNBOOK).
Diagnostics (screenshots + VM logs + smoke snapshot) upload `if: always()` as
`ui-diagnostics-<tier>-<variant>-<version>` (variant = ce/plus, e.g. `ui-diagnostics-browser-ce-2.8`).
The §7 browser reliability numbers are **CI-pending**; the
browser leg has a one-line demote/drop switch (drop `browser` from `DEFAULT_SCHEDULE_TIERS` +
run release `ui-suite` as `tier: functional`). Full design: `.ADRs/ADR_14_UI_UX_Testing/`.

---

## HTTP mock-feed load smoke (ADR-16 Part C) — `tests/smoke/test_smoke_feeds.py`

`test_smoke_feeds.py` (marker `smoke`) is the **only suite file that drives the real HTTP fetch
path**: each case points an `IpCase`/`DnsblCase` at a URL served by `_MockFeedServer` (the
in-runner stdlib HTTP server reachable by the guest at `http://10.0.2.2:<port>/<name>` over
SLIRP — survives the egress block), runs a real Force Update, and asserts the feed loaded on the
box. Every other smoke case supplies a local file via `write_local_feed`.

**Sample fixtures** live under `tests/smoke/fixtures/` (committed to the repo):

| File | Format | Type |
| --- | --- | --- |
| `ip_plain_cidr.txt` | plain IPv4 + CIDR | IP v4 |
| `ip_range.txt` | IPv4 range `a-b` | IP v4 |
| `ip_ipv6.txt` | IPv6 single + CIDR | IP v6 |
| `dnsbl_plain.txt` | plain domain | DNSBL |
| `dnsbl_hosts.txt` | hosts `0.0.0.0 domain` | DNSBL |
| `dnsbl_abp.txt` | ABP / EasyList (\|\|d^ block, @@ allow) | DNSBL |

All data is inert (RFC 5737 / RFC 3849 IPs; `uuid-<hex>.com` domains). The `mock_feeds` fixture
auto-registers every file in `tests/smoke/fixtures/` when it starts; individual cases call
`mock_feeds.feed_url("<name>")` to get the guest URL.

**How `_MockFeedServer.register()` works.** `register(name, body)` stores the body in an
in-memory dict; the HTTP handler serves it verbatim (plain body, no `Content-Encoding`, no
`Content-Disposition`) at `GET /<name>`. The fixture directory variant
(`mock_feeds.feed_url("<filename>")`) reads the file on first access and registers it under its
basename. `curl` does not send `Accept-Encoding: gzip` nor `If-Modified-Since`, so the mock
needs no compression or ETag/304 logic — plain body is fine.

**Adding a new format fixture.**

1. Drop the fixture file into `tests/smoke/fixtures/` (inert data — TEST-NET IPs / `uuid-*.com`
   domains; never RFC 6761 TLDs or HSTS-preload names).
2. Update `tests/smoke/fixtures/README.md` with the member/non-member set.
3. Add a case in `test_smoke_feeds.py` using `mock_feeds.feed_url("<filename>")`.

**Kill-gate / gate status (ADR-16 §7).** The Part-C premise is falsifiable: "a Force Update
reliably fetches an HTTP feed from the mock over SLIRP and loads it, in CI". The reliability bar
is **≥ 4/5 clean runs**. This test is `OPTIMISTIC-GO, PENDING-CI` — all 6 representative formats
are authored; the live CI run (the `ui-tests`-labeled PR suite) decides GO vs DEMOTE. If < 4/5
clean, `test_smoke_feeds.py` is demoted to dispatch-only (Part A still ships; the local-file load
coverage in `test_smoke_matrix.py` / `test_smoke_abp.py` remains). The final decision is recorded
in `.ADRs/ADR_16_Feeds_Tabs_And_Feed_Smoke/RESULTS/05_Results.txt`.

## Locale policy (ADR-26)

`pfblockerng.sh` (and any shell added here) sets locale **explicitly, per-command, never
exported process-wide**. Three rules:

1. **Byte-exact machine-data set ops → inline `LC_ALL=C`.** Every `sort -u` / `uniq` / `comm` /
   `join` (and any plain `sort` whose order feeds a downstream compare/diff) over machine data
   (IPs, punycode domains) carries an inline `LC_ALL=C` on that command — e.g.
   `LC_ALL=C sort -u "$f"`. Under a UTF-8/language `LC_COLLATE`, distinct strings can share a
   collation weight, so `sort -u`/`uniq` silently drop one as a "duplicate" — for a blocklist that
   is a silent hole in the block set, with no error. `C` makes uniqueness byte-exact and identical
   on FreeBSD and Linux. The data reaching the shell is already ASCII (IPv4/IPv6 + punycode; the
   ADR-08 IDN work is done in Python), so byte semantics are exactly right here.
2. **Never `export LC_ALL=C` / `LANG=C` script-wide.** A global export poisons every child the
   script spawns (`php`, `host`/`drill`, `mmdblookup`, list pre/post scripts) — ASCII-crippling
   tools that are legitimately UTF-8-aware and changing error-message language, date, and number
   formatting. It also creates a partial-adoption hazard: `comm`/`join`/`diff`/`uniq` need **all**
   inputs in the **same** collation, so a global default silently mismatches any pipeline mixing a
   `C`-sorted file with a locale-sorted one. Keep locale surgical and inline.
3. **Future raw-Unicode text → split the knobs, resolve `LC_CTYPE` at runtime.** No shell path
   today classifies or case-folds raw (un-punycode'd) Unicode — that work lives in Python. **If**
   one ever appears it does **not** use bare `C` (which silently misses non-ASCII); it splits the
   two concerns: `LC_COLLATE=C` on any sort/set op (deterministic order + byte-exact uniqueness)
   and `LC_CTYPE=<UTF-8 locale>` for the classify/case-fold step, where the UTF-8 locale is
   **resolved at runtime** — never hardcoded (`C.UTF-8` is not universal; see the table).

**`C.UTF-8` availability** (why the `LC_CTYPE` value must be resolved, not assumed):

| Platform | `C.UTF-8`? | Note |
| -------- | ---------- | ---- |
| FreeBSD 15 / pfSense CE 2.8 | yes | present |
| glibc Linux | yes (>= 2.35, 2022) | older/minimal images may lack it |
| musl / Alpine | n/a | the `C` locale is already UTF-8 |
| macOS (BSD libc) | **no** | only `en_US.UTF-8` & friends — the main off-appliance dev/CI hole |

**Deferred — resolver is a copy-ready snippet, not shipped code (ADR-26 Phase 2).** There is **no
caller today** (no raw-Unicode shell path), so the runtime resolver is kept here as a snippet
rather than an unused function in `pfblockerng.sh` — that would ship to users (release archives
carry `src/`) as dead code and trip "unused" lints. Drop it in (naming per the `pfb_*` convention)
the day the first `LC_CTYPE` caller lands (space-indented here for Markdown — reindent to tabs
when pasting into `pfblockerng.sh`):

```sh
# Resolve the best available UTF-8 ctype locale ONCE, with a fallback chain. Prefer C.UTF-8;
# else the first *.UTF-8 from `locale -a`; else C (degraded ASCII ctype, never wrong-silently).
# Read by future LC_CTYPE call sites; NEVER exported.
pfb_resolve_utf8_ctype() {
    _avail=$(locale -a 2>/dev/null)
    if printf '%s\n' "${_avail}" | grep -qiE '^C\.(UTF-8|utf8)$'; then
        printf 'C.UTF-8\n'
    elif _u=$(printf '%s\n' "${_avail}" | grep -iE '\.(UTF-8|utf8)$' | head -n 1) && [ -n "${_u}" ]; then
        printf '%s\n' "${_u}"
    else
        printf 'C\n'
    fi
}
# Usage at a (future) raw-Unicode site — split the knobs, never export:
#   _ctype=$(pfb_resolve_utf8_ctype)
#   LC_COLLATE=C LC_CTYPE="${_ctype}" awk '...Unicode-aware...'
```

## Self-hosted pkg distribution — ABI is NOT 1:1 with a pfSense version (varver keying is mandatory)

**Load-bearing invariant. Do not "simplify" it away** (it keeps getting wrongly re-derived). The
self-hosted catalog (ADR-17/20) is keyed by a **varver** — the pfSense edition+version slug
`ce-2.8` / `plus-26.03` (`catalog_name_from_version()` in `scripts/build-repo-portable.py`) —
**never** by the pkg `${ABI}` (`FreeBSD:<major>:<arch>`).

**Why (the trap).** pkg's `${ABI}` carries only the FreeBSD major + arch. A pfSense `${ABI}` is
**NOT in 1:1 correspondence** with a pfSense version or its package-build inputs (the `php<XY>` /
`py3<XY>` flavors). Multiple pfSense versions/editions can share one FreeBSD major — hence one
`${ABI}` — while shipping **different** PHP/Python. So `FreeBSD:16:amd64` does not tell you whether
the box needs the php8.5 build or some later/other php build; an `${ABI}`-keyed conf would serve the
wrong package. The varver encodes exactly the `(edition, version) → (php, py)` mapping that `${ABI}`
cannot.

**Proof (live, 2026-06, Plus 26.03.1).** `pkg config abi` → `FreeBSD:16:amd64`, but **Netgate's own
repo URL** is
`pkg+https://pfsense-plus-pkg.netgate.com/pfSense_plus-v26_03_1_amd64-pfSense_plus_v26_03_1` — it
bakes the **full product version** (`v26_03_1`), not the ABI. Netgate does not key by `${ABI}`
**because `${ABI}` is not unique to a version**; their proprietary `pfSense-repoc` rewrites the whole
version-pinned conf on each upgrade (server-side) instead.

**Do NOT conclude "the current matrix is 1:1, so `${ABI}` suffices."** That 1:1 (CE→FreeBSD15,
Plus→FreeBSD16) is **incidental and not guaranteed** — CE and Plus have shared FreeBSD bases before,
and the supported window can hold two versions on one major with different deps at any time. A
fail-closed CI guard may reject a matrix that introduces such a collision, but the design **stays
varver-keyed regardless**.

**Upgrade consequence (verified — libpkg + `pfSense-upgrade`).** Because the conf is version-pinned it
cannot auto-follow a version-crossing upgrade the way an `${ABI}` template would, and there is **no
third-party pre-solve hook** to rewrite it in time: `pfSense-repo-setup`/`repoc` manage only Netgate's
own `${PRODUCT}.conf` — they enumerate only `${PLUS_CERT_BASE}/pfSense-repo-*.name` (Netgate's own
staging dir) and never rewrite foreign conf content; a `+PRE_INSTALL` runs inside the locked libpkg
transaction where nested `pkg` is impossible; libpkg pins every version at solve time. Foreign confs
(ours) **persist** across upgrades (pfSense leaves them untouched), but a varver conf goes **stale**
on a version change and can only be corrected by a **separate, later** pkg run — a structural
one-pkg-run lag. The boot-time generator hook below closes that lag.

**`rc.d` generator hook (`scripts/rc.d/pfblockerng_repo_generate.sh`).** Installed on-box by
`add-repo.sh` into `/usr/local/etc/rc.d/`; runs at every boot. It is a pure conf **regenerator**:
for each of our conf files that exists, it detects the box's `<varver>/<arch>` and
**unconditionally overwrites** the conf with the canonical body (channel-correct URL + a marker
comment). **No `pkg` call, no network, no snapshot, no reconcile, no parse-and-compare** —
re-deriving the conf from scratch is strictly simpler than diffing and patching one in place, and
never wrong. Key properties:

- **Self-guarding:** a conf is regenerated only if it already exists; if neither the release nor
  the nightly conf is present the hook is a complete no-op (an orphaned hook left after the user
  removes our repo is inert, and a channel the user never bootstrapped is never created).
- **Ordering:** `REQUIRE: FILESYSTEMS` (so `/usr/local` is mounted) and `BEFORE: NETWORKING` — it
  runs *before* anything that could invoke `pkg` over the network, so the conf is already correct
  by the time the box first reaches for a catalog. Running this early is safe precisely because it
  is local-file-only (no network, no daemon).
- **Folded detection (KISS):** edition = "`/etc/product_label` contains `Plus`" → `plus`, else
  `ce`; version = major.minor of `/etc/version`; arch = the leaf of `pkg config abi`. This mirrors
  `catalog_name_from_version()` in `scripts/build-repo-portable.py`; there is **no** separate
  `/lib` detection helper (it is folded into the one self-contained hook file).
- **Byte-identical output:** the conf body the hook writes is byte-for-byte identical to
  `add-repo.sh --print-conf`, `build-repo.sh --print-conf`, and `build-repo-portable.py
  --print-conf` (drift-pinned by `tests/test_add_repo_conf.py` across all four producers).
- **Detection-failure safety:** if version or arch cannot be resolved the hook leaves the existing
  conf **unchanged** (warns) rather than writing a malformed URL.
- **Always `exit 0`:** every code path ends in `exit 0`. A non-zero exit would wedge the rc.d
  chain; this hook must never do that.
- **Verified findings (ADR-39 §1.3):**
  - *Every varver-changing upgrade reboots.* pfSense cannot swap the running ABI / PHP /
    Python interpreters live; any upgrade that changes build inputs rides the staged
    boot-upgrade (kernel `next_stage` annotation → reboot). So the hook is guaranteed a
    turn after every upgrade that could invalidate the conf.
  - *No third-party pre-solve hook exists.* Confirmed on CE 2.8.1 + Plus 26.03.1:
    `pfSense-repo-setup` only symlinks Netgate's own `${PRODUCT}.conf`; the proprietary
    `repoc` rewrites Netgate's conf content (server-side); neither touches foreign confs.
  - *`/usr/local/etc/rc.d/*.sh` survive reboots and BE-clone upgrades.* `/usr/local` rides
    the boot-environment clone, so a non-package hook placed there persists across the very
    upgrade it heals (maintainer-confirmed from long operational use).

**Published one-file bootstrap (`site/add-repo.sh`).** The repository copy of
`scripts/add-repo.sh` installs the `rc.d` hook by copying the sibling file
`scripts/rc.d/pfblockerng_repo_generate.sh` via `dirname "$0"`. That path resolution
fails when the script is **piped** into `sh` (e.g. `fetch … | sh`) because `$0` is then
`sh`, not the script path. `gen_landing.py`'s `write_site()` generates a self-contained
`site/add-repo.sh` by splicing the hook body between the `PFB_EMBED_HOOK_BEGIN` /
`PFB_EMBED_HOOK_END` marker comments inside `pfb_emit_embedded_hook()` — using a
**single-quoted heredoc** (`cat <<'PFB_HOOK_HEREDOC'`) so none of the hook's dollar-signs
or backticks are expanded. The installed file is identical to the repository sibling.
The published file lives at `pfblockerng.github.io/pkg/add-repo.sh` and is what the
landing page's copy-paste one-liners point to.

Full design: ADR-39.

## Managed firewall object ownership and teardown (ADR-35)

`pfblockerng_fwobj.inc` provides a small shared ownership-and-teardown layer for pfBlockerNG-managed
objects in pfSense-core sections (`virtualip/vip`, `nat/rule`, `filter/rule`). A pfBlockerNG object
is **owned** if and only if its `descr` carries a recognised marker. Marker recognition is the union
of the `pfB_` prefix (new convention, already in use on the filter side) plus the exact legacy strings
(`pfB_AUTO_VIP_v4`, `pfB_AUTO_VIP_v6`, `pfB DNSBL`, `pfB DNSBL - DO NOT EDIT`) — never rewritten,
because stored values are frozen (ADR-28). `pfb_fwobj_is_owned()` is the single recognition predicate;
`pfb_fwobj_sweep()` removes every owned entry from a given section by marker alone, without consulting
any secondary guard.

The sweep runs in two places: (1) **on disable**, as a defensive pass after `pfb_manage_dnsbl_vip` and
`pfb_create_dnsbl` have already run their own teardown — catching any half-written state those paths
may have left; (2) **on deinstall**, before `pfb_remove_config_settings()` wipes the
`installedpackages/pfblockerng*` reference data. This ordering is load-bearing: the sweep reads the
pfBlockerNG config sections to resolve the VIP double-guard reference; if the config were wiped first,
the reference would be gone and the guard would skip orphans.

`pfb_fwobj_register()` is the registration seam ADR-36 and ADR-37 plug into. A feature declares
`{ type, section, marker, builder, guard? }` once; the reconcile / remove / sweep machinery covers
it without per-feature boilerplate. The existing VIP and DNSBL-NAT objects are expressed as the first
two registrations, demonstrating the seam. User objects (no pfB marker) are **never** touched by any
remove or sweep — asserted by unit tests that seed sibling user rows and prove they survive.

Live-VM smoke: `tests/smoke/test_smoke_fwobj.py` (marker `smoke`).

## Optional NAT DNS-redirection (ADR-36)

When enabled, pfBlockerNG creates and maintains a pair of NAT port-forward (rdr) rules per
selected interface — one for IPv4 (`inet`, target `127.0.0.1:53`) and one for IPv6 (`inet6`,
target `::1:53`) — that redirect all outbound port-53 DNS traffic to the firewall's own
resolver. The firewall itself is structurally exempt: every generated rule carries a negated
`(self)` destination so the firewall's own outbound DNS queries are never intercepted, making
upstream resolution immune to the redirect. All four config.xml entries per interface (2 NAT
rdr + 2 associated filter PASS rules) carry a `pfB_DNS_Redirect_<iface>_{v4,v6}` marker and
are registered via `pfb_fwobj_register()` (ADR-35), so the reconcile / remove / sweep
machinery handles their full lifecycle without bespoke teardown code. The feature is
complementary to DoH/DoT domain-level NXDOMAIN blocking (DNSBL feeds) and to ADR-37's
port-853 blocking: this ADR closes only the plaintext port-53 bypass path.

Live-VM smoke: `tests/smoke/test_dns_redirect.py` (marker `smoke`).

## Optional DoT/DoQ BLOCK on port 853 (ADR-37)

When enabled, pfBlockerNG creates and maintains one `filter/rule` BLOCK entry per selected
interface that drops all TCP and UDP traffic destined for port 853 — the IANA-assigned port for
DNS-over-TLS (DoT, RFC 7858) and DNS-over-QUIC (DoQ, RFC 9250). A single `inet46` rule covers
both IPv4 and IPv6 clients without a per-family split: unlike NAT redirect (ADR-36), a BLOCK rule
carries no family-specific redirect target, so one rule is both simpler and correct. The firewall
itself is always exempt: every generated rule carries a negated `(self)` destination
(`<network>(self)</network><not/>`) so the firewall's own outbound port-853 connections are never
blocked, regardless of any future pfSense DoT/DoQ server role. Each rule is registered via
`pfb_fwobj_register()` (ADR-35) with the `pfB_DoT_Block_<iface>` marker, giving the reconcile /
remove / sweep machinery full lifecycle coverage — no bespoke teardown code.

ADR-36 (DNS-redirect) closes the plaintext port-53 bypass; ADR-37 (this feature) closes the
standard-port encrypted-DNS bypass (DoT/DoQ on port 853). For DNS-over-HTTPS (DoH, port 443),
the complementary approach is the DNSBL domain-block layer (known DoH hostnames) together with
IP-alias feeds such as the Dibdot DoH-IP feed that block known DoH resolver IPs — blocking port
443 directly would break all HTTPS traffic and is explicitly out of scope. Non-standard-port
DoT/DoQ also remains uncovered by this rule; that limitation is documented in the UI help text.

Live-VM smoke: `tests/smoke/test_dot_doq_block.py` (marker `smoke`).

## Syslog export of security events (ADR-38)

pfBlockerNG can export IP Block/Permit/Match and DNSBL block events to syslog in `key=value`
form, tagged `pfblockerng`. The feature is **opt-in** (default off) via the **Log Settings →
Send Security Events to System Log** toggle (`log_syslog`), with companion selects for facility
(`log_syslog_facility`, default `local6`) and severity (`log_syslog_priority`, default `notice`).

**Dedicated log** — pfSense's `<logging>` block in `pfblockerng.xml` routes `!pfblockerng`
tagged messages to `/var/log/pfblockerng_syslog.log` exclusively, keeping them out of
`/var/log/system.log`. The logsocket entry (`/var/unbound/var/run/log`) gives the Unbound
Python module a chroot-local socket path to deliver DNSBL records.

**Two emit paths:**

- **IP events** — `pfblockerng.inc` calls `pfb_syslog_event(pfb_syslog_format_ip($fields))` at
  the CSV write site when `log_syslog = PfbToggle::On`. PHP `openlog()` / `syslog()` with the
  resolved facility + severity constants. Fields: `act`, `dir`, `if`, `proto`, `src`, `dst`,
  `sport`, `dport`, `ipver`, `geoip`, `alias`, `feed`.
- **DNSBL events** — `pfb_unbound.py` calls `_emit_dnsbl_syslog(msg)` at the DNSBL match site
  when `syslog_enable = on` (written to `py_unbound.ini` by `pfblockerng.inc` at reload time).
  Uses stdlib `logging.handlers.SysLogHandler` with `address="/var/run/log"` (resolves in the
  Unbound chroot to `/var/unbound/var/run/log`). The handler degrades silently on socket failure
  — it never raises into the Unbound request path. Fields: `act=dnsbl`, `qname`, `qip`, `qtype`,
  `group`, `feed`, `btype` (VIP or NULL), `eval`.

**Remote delivery** — no in-package remote syslog target. Use pfSense
*Status → System Logs → Settings → Remote Logging → "Everything"* to forward the facility.

**Config keys** (all registered in `PfbConfig` / `pfb_cfg_registry()`):

| Key | Type | Default | Notes |
| --- | ---- | ------- | ----- |
| `log_syslog` | `toggle` | `''` (off) | PfbToggle; `'on'` enables both paths |
| `log_syslog_facility` | `plain` | `'log_local6'` | Maps to PHP `LOG_LOCAL6` constant |
| `log_syslog_priority` | `plain` | `'log_notice'` | Maps to PHP `LOG_NOTICE` constant |

Live-VM smoke: `tests/smoke/test_syslog_export.py` (marker `smoke`).
