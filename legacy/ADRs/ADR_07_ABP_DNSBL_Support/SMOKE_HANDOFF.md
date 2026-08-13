# ADR-07 Smoke-Test Handoff

**For:** a fresh Opus instance tasked with executing the ADR-07 (Full ABP-style
DNSBL support) live smoke checklist and flipping the ADR to **Accepted**.
**From:** the implementing session (ADR-07 built, reviewed, CodeRabbit-clean; held
for ADR-04 to land so the live VM harness exists).
**Date:** 2026-06-03.

---

## 0. TL;DR — your mission

1. ADR-07 is **fully implemented** on branch `adr/07` and its status is
   `Implemented — pending live smoke`. It does **not** flip to **Accepted** until
   every box in the ADR's §"Manual smoke" checklist passes on a **live pfSense CE
   box** (CI cannot reach Unbound's Python loader or `pf`).
2. ADR-04 has now landed on `next` and `adr/07` was **rebased on top of it**, so
   the live-VM smoke harness (`tests/smoke/`) is present on your branch. That
   harness was built for ADR-04's scope (plain/hosts feeds) — it does **not yet
   model ABP** (`@@`, regex, `$important`/`$badfilter`, the regex-cap setting,
   ABP×TLD). **Your core job is to extend the harness to cover the ADR-07
   checklist, run it, and record results** — or, for the few items that resist
   automation (regex eviction timing/log observation), run them by hand on a live
   box.
3. **Done =** all 9 checklist items green, results recorded
   (`RESULTS/`-style, see §7), ADR-07 `ADR.md` status flipped to **Accepted**, the
   checklist boxes ticked, committed + pushed to `adr/07`, PR #20 updated.

---

## 1. Where things are

| Thing | Value |
| --- | --- |
| Feature branch | `adr/07` (off `next`, **rebased on `next` after ADR-04 merged**) |
| Remote tip | `origin/adr/07` @ `c3025e6` (`dev: enable ruff F401 globally`) |
| Local worktree | `/home/user/pfBlockerNG/.claude/worktrees/adr-07` (already reset to the remote tip) |
| Open PR | **#20** (`adr/07` → `next`); all 10 CodeRabbit threads resolved |
| ADR doc | `.ADRs/ADR_07_ABP_DNSBL_Support/ADR.md` (status, checklist, follow-ups) |
| Smoke harness | `tests/smoke/` (from ADR-04 — read its `conftest.py`/`helpers.py` headers) |
| VM image runbook | `.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md` |
| ADR-04 result logs | `.ADRs/ADR_04_VM_Smoke_Tests/RESULTS/0{1..7}_Results.txt` (read these — they document secrets, wall-time, the hermetic egress model) |

> Note: hashes differ from any earlier session log — the remote was **force-pushed
> after the rebase**. Compare by **content**, not hash. The 14 ADR-07 commits are
> intact in the same order on top of ADR-04's work.

First action in a fresh session: confirm hooks + branch.

```sh
git -C /home/user/pfBlockerNG/.claude/worktrees/adr-07 status
git config core.hooksPath        # expect .githooks; else: sh scripts/setup-hooks.sh
python -m pytest                 # the default unit suite must be green (934 tests, smoke deselected)
```

---

## 2. What ADR-07 actually shipped (so you know what to test)

Full ABP-style support, **DNS-only**, with the ABP parse moved out of the PHP
`$easylist` lite pass into the Python build (`pfb_unbound.py`). The pieces a smoke
must exercise:

- **`@@` allow exceptions** — un-block a name another rule blocks.
- **Regex rules** — block `/re/` and allow `@@/re/`; anchored-reducible patterns
  are folded to domain/wildcard dicts at build time, only irreducible ones stay
  compiled (`regexDB` / `allowRegexDB`).
- **`$important` / `$badfilter` precedence** — resolved by a **6-band numeric
  scale**: 6 user-allow · 5 user-block · 4 feed-allow+important · 3
  feed-block+important · 2 feed-allow · 1 feed-block. Block wins iff
  `block_band > allow_band`.
- **User sovereignty** — whitelist (settings textarea **and** the alerts "add to
  whitelist" button), user blocks, user regex, and TOP1M are treated as
  `$important` and are `$badfilter`-immune; a feed can never override them.
- **Regex safety (ReDoS)** — (a) opt-in **static cap** "Limit long/complex regex"
  drops over-long / nested-quantifier / alternation-overlap patterns at load;
  (b) always-on **runtime warn/evict** times each match on **thread CPU**
  (`time.thread_time`), warns at 10 ms, **evicts** the pattern from the live DB at
  100 ms (snapshot-iterate, evict-after-loop). Applies to feed **and** user regex.
- **DNSBL-IP coexistence** — IP-valued anchors (`||1.2.3.4^`, hosts `0.0.0.0 host`)
  still route to the `pfB_DNSBLIP_{v4,v6}` firewall aliases (PHP path); Python
  `parse('abp')` skips IP anchors (no-leak contract).
- **ABP × DNSBL-TLD mode** — `tld_analysis()` (legacy PHP CSV path) **skips** ABP
  feeds (detected via the `.abp` marker glob); ABP feeds build via the Python
  manifest path regardless. Plain feeds still TLD-analyse as before.
- **Counts/UI** — `pfb_py_count` and the `DNSBL_Regex` alias count still render;
  the regex count now reflects **admitted** (cap-filtered) patterns (value changes
  by design).
- **Fast path** — when no `$important`/`$badfilter`/feed-`@@`/feed-regex is loaded,
  a build-emitted `pfb["important_rules"]=False` keeps today's matcher byte-for-byte
  (no regression).

The decision logic is pinned in CI by `tests/test_adr07_*` (decision spec/oracle,
parser, reconcile, matcher strata, emit/wire, regex safety, PHP boundary) — those
already pass. The smoke proves the **same decisions hold end-to-end on a live
resolver**, which the unit oracle cannot.

---

## 3. How the ADR-04 smoke harness works

Read `tests/smoke/conftest.py` and `tests/smoke/helpers.py` docstrings in full
before writing anything — summarised here:

- **`smoke_vm`** (session fixture): pulls the pfSense CE qcow2 from private GHCR by
  immutable ref (`SMOKE_IMAGE_REF`), or reuses a local image dir
  (`SMOKE_IMAGE_DIR`), boots it headless under QEMU/KVM via `boot_vm.sh`
  (read-only base + CoW overlay), waits for SSH/WebUI via `wait_ready.sh`, yields a
  `SmokeVM` connection object, tears down on teardown. Host↔guest forwards:
  SSH `2222→22`, WebUI `8080→80`, DNS `5353→53` (tcp+udp). Guest reaches the runner
  at SLIRP alias **`10.0.2.2`**.
- **`mock_feeds`** (function fixture): serves `tests/smoke/fixtures/` + per-test
  registered content over stdlib `http.server`; the guest fetches feeds from
  `http://10.0.2.2:<port>/<name>`. **This is your ABP-feed delivery mechanism** —
  see §4.
- **Hermetic**: the workflow pulls the image, then `block_egress()` cuts the
  runner's outbound network so the only "internet" the guest sees is the mock feed
  server. A name that *should* be blocked but resolves to the stub sentinel
  (`203.0.113.99` / `2001:db8::99`) is a **true pass**, never a false-green.

Helper API you'll build on (`tests/smoke/helpers.py`):

```text
deploy(vm, pkg_path)            install the branch .pkg (install-pkg.sh)
write_local_feed(vm, name, s)   write arbitrary feed content onto the guest
mock_feeds.register(name, s)    serve arbitrary feed content from the runner
DnsblCase / IpCase              dataclass specs -> inject() writes config
inject(vm, spec)                write_config the case (DNSBL list / IP list)
set_control_records(...)        DNS-Resolver host overrides (control answers)
configure_upstream(vm)          point the stub upstream (sentinel answers)
ensure_dnsbl_vip(vm)            set pfb_dnsvip4 (VIP mode cases)
reload(vm, scope="update")      run a pfBlockerNG update/reload
reset(vm)                       tear config back to baseline between cases
php_eval(vm, snippet)           run arbitrary PHP in the pfSense config context
config_get(vm, path)            read a config path
dns_probe(vm, name, rtype)      dig/drill -> DnsAnswer
is_nxdomain / is_null_ip / is_vip / resolves_to   answer assertions
pfctl_table_members(vm, alias)  / rule_references(vm, alias)   IP-path assertions
wait_unbound_ready(vm)          poll until the resolver is serving
dump_diagnostics(vm)            on-failure state dump
CaseContext                     ctx manager: inject -> reload -> probe -> reset
```

Run the suite (NOT part of the default `pytest`; it's deselected by
`--ignore=tests/smoke`):

```sh
python -m pip install -r tests/smoke/requirements.txt
python -m pytest tests/smoke -m smoke --override-ini="addopts="
```

Secrets/vars the workflow needs (Actions; see `RESULTS/02_Results.txt`):
`SMOKE_IMAGE_REF`, `SMOKE_GHCR_USER`, `SMOKE_GHCR_TOKEN`, `SMOKE_SSH_PRIV_KEY`;
optional `SMOKE_DNSBL_VIP4`, `SMOKE_CONTROL_NAME`/`SMOKE_CONTROL_IP`.
The smoke workflow is `workflow_dispatch` / `workflow_call` only (gated, not
every-PR) until per-run wall-time is confirmed within budget.

---

## 4. The key enabler — and the gap you must close

**Enabler:** `mock_feeds.register(name, contents)` / `write_local_feed()` let you
serve **arbitrary raw feed text**. PHP header-sniffs an ABP feed (`[Adblock Plus]`,
`[uBlock Origin`, `! Title: AdGuard`) and tags it `format_hint='abp'`, so a feed
whose body is raw ABP syntax flows through the **new Python ABP parser**. That
means most ADR-07 items **can** be automated with the existing transport.

**Gap:** `DnsblCase` models only `aliasname/feed_url/mode/wildcard/whitelist/
dnsbl_ip_action/control_*`. It has **no** fields for: an ABP feed body, a second
feed (cross-feed `@@`), the user regex list (`pfb_regex`/`pfb_regex_list`), the
"Limit long/complex regex" setting (`pfb_regex_limit`-ish — confirm the exact
config key in `pfblockerng.inc`/`pfblockerng_dnsbl.php`), or DNSBL-TLD mode
(`dnsbl_pytld` + the `pfb_pytlds_*` sets). You will need to **extend the harness**:

- Add an ABP case spec (or reuse `DnsblCase` with an explicit
  `mock_feeds.register()` body of raw ABP lines and an ABP header line at top).
- Add helper setters for the user regex list, the regex-cap toggle, and TLD mode
  (thin `php_eval`/`config_set_path` snippets, mirroring `_dnsbl_inject_snippet`).
- Add assertions for log-side effects (warn/evict lines in the resolver log) —
  read `/var/log/...` or the unbound python log over SSH via `php_eval`/a new
  helper, since eviction is observable only in logs + subsequent fast queries.

Keep additions in the **same style** as `helpers.py` (dataclass spec → PHP
`config_set_path` snippet → `reload` → `dns_probe`/`pfctl_*` assert). Pin every
expected answer to the real matcher semantics (cite `pfb_unbound.py` lines), as the
existing matrix does, so a wrong expectation can't masquerade as a pass.

---

## 5. The checklist → how to drive each item

Source of truth: the "Manual smoke" section of `ADR.md`. For each, the **setup**,
**drive**, **expected**, and whether it's **automatable** with the harness.

### 5.1 `@@` exception un-blocks

- **Setup**: one ABP feed body blocking `||example.com^` and exempting
  `@@||sub.example.com^`. Serve via `mock_feeds.register`.
- **Expect**: `sub.example.com` resolves (to the stub sentinel); `example.com` and
  other subdomains stay blocked (NXDOMAIN/NULL/VIP per mode).
- **Assert**: `dns_probe` + `is_nxdomain`/`resolves_to`. **Automatable.**
- Also test **cross-feed** `@@` (exception in feed B un-blocks a block in feed A) —
  ADR calls this out as intended ABP semantics. Needs a 2-feed case.

### 5.2 Regex (block, allow, reducible vs irreducible) + count

- **Setup**: feed with a reducible regex (`/^(.+\.)?ads\.example\.com$/`), an
  irreducible one (`/ad[0-9]+\.example\.net/`), and an `@@/.../` allow.
- **Expect**: reducible blocks exactly its domain/wildcard equivalent; irreducible
  blocks as written; `@@` regex un-blocks; the **`DNSBL_Regex` alias count** equals
  the admitted regex total (reducibles fold out of the compiled set).
- **Assert**: `dns_probe`; read the alias count via `config_get`/`php_eval` or
  `pfctl`/UI count file (`/var/unbound/pfb_py_regex_count`). **Automatable.**

### 5.3 `$important` / `$badfilter`

- **Setup**: feed `||x.com^$important` together with feed `@@x.com^` (important
  block must win → x blocked); and feed `||y.com^$badfilter` with feed `||y.com^`
  (badfilter prunes the block → y resolves). Confirm neither touches a user rule.
- **Assert**: `dns_probe`. **Automatable.**

### 5.4 User sovereignty

- **Setup**: (a) whitelist a domain via the **settings textarea** (`suppression`)
  *and* separately via the **alerts "add to whitelist"** path; (b) a user-blocked
  domain vs a feed `@@…$important`; (c) a feed `$badfilter` targeting a user rule.
- **Expect**: whitelisted name always resolves regardless of any feed incl.
  `$important`; user block stays blocked despite feed `@@…$important`; no feed
  `$badfilter` removes a user rule. TOP1M (if enabled) behaves as a user allow.
- **Assert**: `dns_probe`. **Mostly automatable**; the alerts-button path may need
  a `php_eval` that calls the same backend the button does (find it in
  `pfblockerng_alerts.php`) rather than driving the GUI.

### 5.5 Regex safety (cap + runtime evict) — **hardest to automate**

- **Setup**: with "Limit long/complex regex" **ON**, a feed/user regex over the
  length / nested-quantifier / alternation-overlap ceiling → dropped at **load**
  (never compiled). Separately, a deliberately slow (but cap-passing) pattern that
  trips the **runtime** ceiling on a crafted query.
- **Expect**: over-cap pattern absent from `regexDB`/`allowRegexDB` at load; the
  slow pattern logs a **warning** (10 ms) then an **error + eviction** (100 ms), and
  **subsequent queries are fast**; the resolver stays responsive. Same for the user
  `pfb_regex_list`.
- **Assert**: inspect the resolver/unbound-python log for the warn/evict lines, and
  re-probe to confirm the pattern is gone and latency recovered. **Partially
  automatable** — the load-time drop is easy (check the count/DB); the runtime
  warn→evict needs log scraping + a pattern tuned to exceed `thread_time` ceilings
  reliably on the VM (timing is CPU-bound, so pad the input, e.g. a long
  near-match). Consider lowering the warn/evict thresholds via the advanced config
  for a deterministic trip, then restoring. If timing proves flaky in CI, run this
  one **by hand on a live box** and record the log excerpt.

### 5.6 DNSBL-IP intact

- **Setup**: ABP feed with embedded IPs incl. `||1.2.3.4^` and a hosts line
  `0.0.0.0 host`; set `dnsbl_ip_action="Deny_Both"`.
- **Expect**: `pfB_DNSBLIP_{v4,v6}` populated with the IPs; **no IP leaks into DNS
  blocking** (the IP anchor does not become a DNS block).
- **Assert**: `pfctl_table_members` for the DNSBLIP alias + `dns_probe` to confirm
  the IP-anchored name is not DNS-blocked. **Automatable** (mirrors ADR-04's
  `test_dnsblip_dual_stack_partition`).

### 5.7 No regression (plain/hosts)

- **Setup**: a non-ABP plain + hosts feed set (the existing ADR-04 matrix cases).
- **Expect**: blocks/resolves exactly as before; `pfb_py_count` renders.
- **Assert**: the existing `tests/smoke/test_smoke_matrix.py` cases should still
  pass unchanged. **Automatable** (largely already covered — just run them).

### 5.8 ABP × DNSBL-TLD mode

- **Setup**: enable DNSBL-TLD mode (`dnsbl_pytld='on'` + at least one `pfb_pytlds_*`
  set) with **one ABP feed and one plain feed**.
- **Expect**: the ABP feed's domains build via Python (no CSV-mangling — no garbage
  / empty entries from raw `||x^`/`@@`/`/re/`/`0.0.0.0 host` lines); plain feeds
  still TLD-analyse (data/zone classification) as before.
- **Assert**: `dns_probe` on ABP-feed domains + inspect `pfb_py_data`/`pfb_py_zone`
  (or counts) to confirm clean entries; plain-feed TLD behaviour unchanged.
  **Automatable** with a TLD-mode setter. This is the coexistence fix in
  `tld_analysis()` — exercise the `.abp` skip path directly.

### 5.9 Reload

- **Setup**: change a feed, the whitelist, the regex list, and the cap setting; run
  `reload`.
- **Expect**: all changes picked up correctly (new blocks/allows take effect, counts
  update). **Automatable** — assert before/after via `dns_probe` + counts.

---

## 6. Gotchas (learned the hard way)

- **Egress order**: pull the image first, *then* `block_egress()`. The guest's only
  reachable "internet" is the mock feed server at `10.0.2.2`.
- **DNSBL group action must be `'unbound'`** (not `'Enabled'`) or the feed writes
  nowhere → silent empty blocklist (see the comment in `_dnsbl_inject_snippet`).
- **`enable_cb='on'`** globally or the DNSBL/DNSBL-IP paths don't run.
- **False-green guard**: keep the stub sentinel distinct from every block shape; a
  "should-block" name that returns the sentinel = real pass. Don't assert "not
  resolved" loosely — assert the *exact* expected shape (NXDOMAIN/NULL/VIP/sentinel).
- **Regex eviction timing** uses **thread CPU**, not wall clock — a descheduled VM
  thread won't false-evict, but it also means you must burn real CPU to trip it.
  Pad the probe input; or temporarily lower warn/evict thresholds for determinism.
- **Counts change by design**: the `DNSBL_Regex` count now reflects *admitted*
  (cap-filtered) regex — don't treat a changed count as a regression.
- **Rebase reality**: never compare `adr/07` to remote by hash; compare by content.
- **Don't pollute the default suite**: anything you add stays under `tests/smoke/`
  behind the `smoke` marker + `--ignore` so `python -m pytest` is unchanged.
- **Markdown/lint**: the repo gates `ruff`, `markdownlint-cli2`, ShellCheck, `php -l`
  in pre-commit + CI. Keep new Python 4-space, type-hinted, stdlib-only in the
  matcher; helpers may use the smoke `requirements.txt` deps.

---

## 7. Definition of done

1. All **9 checklist items** pass on a live VM (CI dispatch of `smoke.yml`) and/or a
   hand-run live box for any item that resists automation (document which, and why).
2. Record results in the ADR-04 style: add
   `.ADRs/ADR_07_ABP_DNSBL_Support/RESULTS/` (or append a clearly-labelled ADR-07
   section under the existing ADR-04 `RESULTS/`) with the commands run, the VM
   image ref/digest, per-item PASS/FAIL, and any log excerpts (esp. the regex
   warn/evict lines from 5.5).
3. In `ADR.md`: tick every checklist box and flip
   **Status: `Implemented — pending live smoke` → `Accepted`** with the date.
4. Commit (`<scope>: <imperative>` style, e.g.
   `tests: ADR-07 live smoke matrix (ABP @@/regex/precedence/ReDoS/TLD)`),
   push to `adr/07` (`git push -u origin adr/07`), and note completion on **PR #20**.
5. If a checklist item **fails**, do **not** flip to Accepted — file the defect
   (GitHub issue, note in `ADR.md` follow-ups), and report which decision diverged
   from the unit oracle (that's the signal of a build/matcher integration bug the
   pure tests missed).

---

## 8. Recorded non-blocking follow-ups (carry forward, do NOT let them block Accept)

From the ADR's follow-up notes — these are tracked, not smoke gates:

- **Regex cap default + unkillable in-flight ReDoS**: the first hit of a
  pathological cap-passing pattern can still block one query (GIL); a future ADR
  revisits whether to ship the cap **on** by default and/or move to a killable
  engine (re2 / subprocess) — both out of stdlib, deferred.
- **Full ABP × TLD integration review**: ADR-07 makes them *coexist* (TLD skips ABP
  feeds); a deeper integration (TLD-classifying ABP-derived domains) is a separate
  follow-up.

Also live: GitHub issues #23–#30 are an **unrelated** legacy-code audit (separate
from ADR-07); don't conflate them with the smoke. #29 is closed (not a bug), #25 is
a downgraded defensive cleanup.

---

## 9. First moves for you

```sh
# 1. Land in the worktree, confirm green baseline.
cd /home/user/pfBlockerNG/.claude/worktrees/adr-07
git log --oneline -1            # expect c3025e6 (or newer if more landed)
python -m pytest                # 934 unit tests green, smoke deselected

# 2. Read the harness + checklist before writing anything.
sed -n '1,60p' tests/smoke/conftest.py
sed -n '1,120p' tests/smoke/helpers.py
sed -n '1,80p'  tests/smoke/test_smoke_matrix.py
$EDITOR .ADRs/ADR_07_ABP_DNSBL_Support/ADR.md          # the checklist
$EDITOR .ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md   # image + secrets
ls .ADRs/ADR_04_VM_Smoke_Tests/RESULTS/                # how results were logged

# 3. Decide automate-vs-manual per §5 item, extend tests/smoke/ for the ABP cases,
#    dispatch smoke.yml (or run a live box), record results, flip the ADR.
```

Good hunting. The decision logic is already proven in unit tests — the smoke is
about confirming the **live resolver + pf** agree with that logic end-to-end, and
that the ReDoS guard actually evicts on a real box.
