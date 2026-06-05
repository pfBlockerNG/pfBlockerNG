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

Admin-configurable `pre`/`post` commands run once per update pass from
`sync_package_pfblockerng` in `pfblockerng.inc` — `pfb_run_hooks($when, $ctx)` reads enabled
hooks from `installedpackages/pfblockerng/config/0/hooks` (`{command, when, enabled,
description, timeout}`), runs each **as root** via `/usr/bin/timeout … /bin/sh -c
<escapeshellarg>` in list order, captures output to the pfBlockerNG log, and **non-zero/timeout
→ log + continue** (a hook can never abort/stall an update; no enabled hooks ⇒ byte-identical
pass). Admin-only **Update Hooks** settings tab (`www/pfblockerng/pfblockerng_hooks.php`, same
WebCfg priv as the other settings).

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
`ui-diagnostics-<tier>-<version>`. The §7 browser reliability numbers are **CI-pending**; the
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
