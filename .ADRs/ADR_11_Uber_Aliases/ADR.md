# ADR-11: Native aggregate ("Uber") block-IP aliases

- **Status:** **Proposed** (2026-06-02)
- **Date:** 2026-06-02
- **Branch:** `adr/11` (off **`devel`** — IP-side only, no Python/DNSBL coupling, so it does **not** depend on ADR-07/10; promote `devel → next` by rebase as usual) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (the IP update pass, alias registration, settings read), `pfblockerng.sh` (a new `aggregate` shell action reusing `cidr_aggregate`), `src/usr/local/www/pfblockerng/*` (one opt-in setting), `src/usr/local/pkg/pfblockerng/pfblockerng.xml`-side settings as needed.
- **Target runtime:** PHP 8.3 + POSIX `sh` (pfSense CE 2.8). **No Python** — this is entirely the IP/firewall side; the Unbound plugin is untouched.
- **Test suite:** **No `pytest` oracle** — this is PHP/shell with no unit-test harness in-repo. Validation = `php -l` + PHPStan + ShellCheck (the automated gate), a **cost benchmark** (union build time / peak RAM / entry count / pf-table load at scale), and a **manual smoke checklist** (live box) for the alias/table/HAProxy-referenceability CI cannot exercise.

---

## 1. Context

### Today

pfBlockerNG downloads IP feeds and, per list, builds a pf table exposed as a **`urltable` pfSense alias**:

1. **Alias type = `urltable`.** Each IP alias is registered with `'type' => 'urltable'`, `'url' => "{$pfb['weblocal']}?pfb={$alias}"`, `'address' => ''` (`pfblockerng.inc:9512-9520`; GeoIP continents the same, `:8702-8706`). The alias contents live in `{$pfb['aliasdir']}/{$alias}.txt`; pfSense caches the urltable under `/var/db/aliastables/` (`pfblockerng.sh:61`). UI counting keys on `type == 'urltable' && name ~ 'pfB_'` (`inc:4592`).
2. **Alias *action* decides the rule.** `pfb_firewall_rule($list['action'], …)` (`inc:4139`, called `:9526`) creates the filter rule; **"Alias Native"** is the action that registers the alias/table but **creates no rule** — the table is loaded (memory) but never evaluated per-packet (no CPU). This is exactly the user's manual workaround target.
3. **Per-type storage dirs.** `denydir`/`nativedir`/`matchdir`/`permitdir` under `/var/db/pfblockerng/` (`inc:47-50`); deny member files are `${pfbdeny}${alias}.txt`, already `sort -u`'d (`sh:323,519,585`).
4. **Dedup + CIDR aggregation already exist.** `cidr_aggregate()` (`sh:268`, dispatched `sh:956`) collapses overlapping subnets for an alias; suppression is applied via the suppression list (`sh:189`, `pfbsuppression`). So **per-alias** dedup/aggregation/suppression is solved machinery — there is no per-alias *union* across aliases.
5. **Empty aliases are pruned.** If an alias resolves to no IPs, its file is unlinked and the alias isn't created (`inc:9495-9498`) — i.e. an empty alias does not persist.
6. **The update pass** runs in `sync_package_pfblockerng()` (`inc:6556`); aliases are materialised and the tables reconciled (`pfb_aliastables()` `inc:4402`). There is **no step that unions the effective block set into a single alias.**

### The user's current workaround (the pain this kills)

To get "all blocked IPs under one name" (for HAProxy ACLs that check the *real* client IP from a Cloudflare header — see ADR-12), the user runs an **external script** that periodically writes a text file of all IPs, **registers that file with pfBlockerNG as a fake "download" list** in Alias Native mode so pfBlockerNG builds the alias, then references it. Costs: a **self-feeding loop** (pfBlockerNG re-ingesting its own output), **two-cycle staleness** (script after pfBlockerNG; pfBlockerNG picks the change up the *next* hour), and a **dummy-IP placeholder** to dodge empty-file validation downstream.

### Load-bearing facts

1. **All the machinery already exists** — `urltable` alias registration, `cidr_aggregate`, suppression, the `weblocal?pfb=` server, `pfb_aliastables`. This ADR **composes** them into a union step; it invents no new alias type and no new file format.
2. **A Native alias is CPU-free but not RAM-free.** An unused table loads into pf (kernel memory ≈ the union size) but is never evaluated. The user accepts this; it argues for **opt-in (default off)**.
3. **The premise is empirically proven.** The user already runs this exact union at real scale via the workaround — so "it fits" is true for ≥1 deployment. The open question is **cost characterisation** (build time / RAM at million-CIDR scale) and whether an **incremental** (rebuild-only-on-member-change) build is warranted — not whether the feature is viable.
4. **No PHP/shell test harness.** The repo's `pytest` suite covers only the Python DNSBL build. This feature is validated by lint (PHPStan/ShellCheck/`php -l`) + a cost benchmark + a manual live-box smoke. There is **no golden oracle** to diff against (this is new, additive behaviour, not a refactor).
5. **Consumption is ADR-12, reframed as *generic update hooks*.** ADR-11 only *produces* the aggregate alias + a stable consumer file. **ADR-12 is "run anything before/after a pfBlockerNG update" — generic pre/post update-command hooks — with HAProxy as the documented worked *recipe*, not hardcoded coupling** (project PoV: decouple from another package's churny internals; the same hooks serve CF-API push, service restarts, downstream sync, etc.). The HAProxy recipe: the package's official `source_ip` `ipalias_*.lst` emission (`haproxy.inc:1085`) provides the file; ADR-11's never-empty file makes the `/var/etc/haproxy_test` validation stage (`:1358`) + the `/../../` + dummy-IP hacks fall away; **freshness is a hook-triggered *graceful HAProxy reload*, NOT a runtime-socket push** — per the maintainer, replacing file/IP-table-backed ACLs via `/tmp/haproxy.socket` (`:1562`) does **not** work reliably on pfSense (effectively stats + a hitless-reload command, not data injection — socat crashes), and HAProxy only re-reads `-f` ACL files at reload regardless. A HAProxy-*package* improvement (emit header-ACL files natively) is a possible upstream contribution, not relied upon.

---

## 2. Decision

Add an **opt-in** step to the IP update pass that **unions the effective block set into Native `urltable` aliases**, one per family, in the **same pass** as the feeds — reusing the existing dedup/`cidr_aggregate`/registration machinery. Default **off**.

| Area | Decision |
| --- | --- |
| **What it produces** | Per family (v4/v6): **`pfB_Aggregate_v4` / `pfB_Aggregate_v6`** = the union of the **effective Deny set** (all Deny-action IP aliases, **incl. DNSBLIP_v4/_v6**, **excl. GeoIP**), and — separate opt-in (Phase 4) — **`pfB_GeoAggregate_v4` / `pfB_GeoAggregate_v6`** = the union of GeoIP block continents. Registered as standard pfB **`urltable`** aliases (mirror `inc:9512-9520`), **Native** (no `pfb_firewall_rule`). |
| **"Effective" set** | The **post-suppression / post-whitelist, block-action** members — i.e. *what pfBlockerNG actually blocks*, not raw feed contents. Reuses the same member files (`${pfbdeny}…`) after their normal processing. |
| **Dedup / aggregation** | `cat` the member files → existing **`sort -u` dedup** → existing **`cidr_aggregate`** collapse → write the aggregate file. A new `pfblockerng.sh aggregate <family>` action composes these (no new algorithm). |
| **Build hook (lockstep)** | Runs **inside `sync_package_pfblockerng()`** after all member aliases are materialised but before/with `pfb_aliastables()` — so the aggregate is current **in the same pass** (kills the two-cycle staleness). No second process, no self-download. |
| **Never-empty consumer file** | pfBlockerNG always writes a **stable, never-empty** `-f`-format file (a `#`-comment placeholder line when the union is empty) at a known path, so a downstream `-f` consumer (ADR-12) never hits empty-file validation — **killing the dummy-IP hack at the source.** (Distinct from the pf table, which simply isn't loaded when empty, per `inc:9495-9498`.) |
| **Opt-in** | A settings toggle **per aggregate** (Deny, GeoIP), **default off**. Off ⇒ no alias, no file, no table, **byte-identical to today**. |
| **Naming** | `pfB_Aggregate_{v4,v6}` and `pfB_GeoAggregate_{v4,v6}` (fixed; pfB_ prefix; documented). Not user-renamable in v1 (avoids alias-name-collision UI/validation; can be added later). |
| **Out-of-pass safety** | Purely **additive**: member aliases, their tables, and all existing rules are untouched; the aggregate adds rows nowhere except its own table. |

### Semantics that MUST be preserved (the contract)

- **Additive-only.** With the toggle **off**, behaviour is byte-identical to today. With it **on**, no existing alias/table/rule changes — only the new Native aggregate alias(es) appear.
- **Native means no rule.** The aggregate never injects a filter rule; if the user wants to use it in a rule, they add it themselves.
- **Correct union.** The aggregate = `sort -u` + `cidr_aggregate` of the *effective* (post-suppression/whitelist, block-action) member set for that family; DNSBLIP included, GeoIP excluded (Deny-aggregate).
- **In lockstep.** The aggregate reflects the **current** update pass — never one cycle stale relative to its members.
- **Never-empty consumer file.** The `-f` consumer artifact always exists and is non-empty (placeholder when the set is empty).
- **Clean teardown.** Turning the toggle off (or disabling pfBlockerNG) removes the aggregate alias/table/file with no orphans.

### Explicitly kept / out of scope

- **Generic pre/post update-command hooks + the HAProxy recipe** (the post-update hook that triggers a graceful reload; the documented `source_ip`-emission + header-ACL config) — **ADR-12**.
- **Permit/Match aggregates** — out (the ask is the *block* set). Trivial to add later via the same generic mechanism.
- **A new alias type or file format** — out; it's a standard pfB `urltable` alias.
- **User-renamable alias names** — out for v1.
- **Cloudflare-edge blocking** (pushing the list to CF via API) — a separate, additive future idea, not a replacement for the HAProxy enforcement.

---

## 3. Consequences

**Positive**

- Kills the self-feeding workaround + the two-cycle staleness: the union is produced **natively, in-pass**.
- Gives "all blocked IPs under one name" as a first-class, deduped, CIDR-aggregated Native alias — directly consumable by HAProxy (ADR-12) and anything else that takes an IP set by name.
- Reuses proven machinery (`urltable` registration, `cidr_aggregate`, suppression) — small, low-risk surface.
- Opt-in + default-off ⇒ zero impact for users who don't want it.

**Negative / risks**

- **RAM at scale.** The union of all deny feeds can be millions of CIDRs; the loaded (unused) pf table costs kernel memory. Mitigated by opt-in default-off + the Phase-1 measurement + (if needed) an incremental build.
- **Build-time cost in the update pass.** `cat`+`sort -u`+`cidr_aggregate` over the full union adds work each pass. Measured in Phase 1; if prohibitive, rebuild **only when a member changed**.
- **No automated correctness oracle.** PHP/shell, no unit harness → reliance on lint + manual smoke. Mitigated by keeping the logic a thin composition of already-trusted steps and a tight manual checklist.
- **Empty-set + downstream validation.** An empty union must still yield a non-empty consumer file (placeholder) or ADR-12's HAProxy validation breaks — pinned in the contract.

---

## 4. Requirements (acceptance)

1. **Opt-in, additive:** toggle off ⇒ byte-identical to today; toggle on ⇒ the Native aggregate alias(es) appear and **nothing else changes**.
2. **Correct content:** the aggregate = deduped + `cidr_aggregate`d union of the effective Deny set (incl. DNSBLIP, excl. GeoIP) for the family; GeoIP aggregate likewise from block continents.
3. **Native:** no firewall rule is created for the aggregate.
4. **Lockstep:** the aggregate is rebuilt in the same update pass as its members (no extra cycle).
5. **Never-empty consumer file** at a stable path (placeholder when empty).
6. **Cost characterised:** Phase-1 benchmark records union build time + peak RAM + entry count + table-load at scale; if over budget, the incremental-build mitigation is taken and documented.
7. **Lint-clean:** `php -l` + PHPStan + ShellCheck clean; no Python/`pytest` change.

---

## 5. Constraints (from `CLAUDE.md`)

- **PHP:** tabs, 8.3, no `die()`/`exit()` in library code, pfSense fns via stubs (add to `stubs/pfsense/` if a new one is used; PHPStan is the gate).
- **Shell:** POSIX `sh` only, quoted expansions, **absolute binary paths**, ShellCheck-clean; the new `aggregate` action mirrors the style of `cidr_aggregate`/`aliastables`.
- **No shipped Python change**; the Unbound plugin and the `pytest` suite are untouched.
- Commit style `<scope>: <imperative summary>`; **work inline on `adr/11`, one commit per phase, push directly** (PR only if rejected); promote `devel → next` by rebase + `--force-with-lease`. PR bodies via `--body-file`.
- **Docs:** README/CLAUDE.md + the settings help text updated when the feature/contract lands (final phase).

---

## 6. Action plan

Each phase = one commit, leaves the tree lint-clean (`php -l`/PHPStan/ShellCheck) and `python -m pytest` **untouched/green**. The **cost is measured first (Phase 1)**; a **behaviour-preserving extraction (Phase 2)** lands the union as an isolated, lint-clean building block before it is wired into the pass.

### Phase 1 — Measure the union cost (de-risk)

Prompt: `01_Measure_Union_Cost.txt`

- Build a standalone benchmark: at realistic scale (union of large deny feeds, millions of CIDRs), measure `cat`+`sort -u`+`cidr_aggregate` **wall-time + peak RAM**, the **resulting entry count** (dedup/aggregation ratio), and the **pf table load** time/RAM. Run on synthetic data (agent) + record the live-box procedure (maintainer).
- **Decide:** full-rebuild-each-pass vs **incremental** (rebuild only when a member file changed). Propose a soft budget; if full rebuild is prohibitive, specify the incremental trigger. Record in `RESULTS/01_Results.txt`.

### Phase 2 — PREP (behaviour-preserving): `pfblockerng.sh aggregate` action + member-list helper

Prompt: `02_Aggregate_Action_Prep.txt`

- Add a `pfblockerng.sh aggregate <family>` action: read a passed member-file list → `cat` → `sort -u` → `cidr_aggregate` → write the aggregate file + the never-empty `-f` consumer file (`#` placeholder when empty). Add a PHP helper that computes the **effective Deny member list** per family (post-suppression, block-action, incl. DNSBLIP, excl. GeoIP). **Not wired** into the update pass yet. ShellCheck/PHPStan clean. Standalone-valuable.

### Phase 3 — Wire the Deny-aggregate into the update pass + register the urltable alias (opt-in)

Prompt: `03_Wire_Deny_Aggregate.txt`

- Add the opt-in setting (default off). In `sync_package_pfblockerng()`, after members materialise, when enabled: compute the member list (Phase 2) → run `aggregate` → register `pfB_Aggregate_{v4,v6}` as a `urltable` Native alias (mirror `inc:9512-9520`, **no** `pfb_firewall_rule`) → load via `pfb_aliastables`. Toggle off ⇒ remove alias/table/file cleanly. Additive: existing aliases/rules unchanged.

### Phase 4 — GeoIP-aggregate (separate opt-in)

Prompt: `04_Geo_Aggregate.txt`

- Apply the same mechanism to the GeoIP **block** continents → `pfB_GeoAggregate_{v4,v6}`, behind its **own** toggle (default off). Reuse Phase-2/3 code; differ only in the member-set source (continent block aliases).

### Phase 5 — Settings UI + docs + benchmark + manual smoke + DoD

Prompt: `05_UI_Docs_Smoke_DoD.txt`

- Wire the two toggles into the settings page with help text; document the feature + naming + the RAM/opt-in caveat in README/CLAUDE.md; re-run the Phase-1 benchmark on the branch; finalise §7 manual smoke + reject criteria. Note the ADR-12 hand-off (the never-empty consumer file + the Native alias are what HAProxy will consume).

---

## 7. Definition of done

- Toggle off ⇒ byte-identical to today; toggle on ⇒ `pfB_Aggregate_{v4,v6}` (and, if enabled, `pfB_GeoAggregate_{v4,v6}`) appear as Native `urltable` aliases with the correct deduped+aggregated effective content, **no firewall rule**, rebuilt in-pass, with a never-empty consumer file.
- `php -l` + PHPStan + ShellCheck clean; `python -m pytest` untouched/green.
- The Phase-1 cost is characterised; incremental build taken if needed.
- Status → **Accepted** only after the maintainer confirms the manual smoke below on a live pfSense box.

### Reject / pivot criteria (decide cheaply, Phase 1)

- **Cost prohibitive at scale:** if a full per-pass union blows the update-pass time or box RAM at realistic million-CIDR scale → **pivot** to an incremental (rebuild-on-member-change) build, or keep it strictly opt-in with a documented RAM warning. (The feature is not rejected — it already runs in production via the workaround — but the *full-rebuild-each-pass* approach may be.)
- **Cannot stay additive:** if the union step can't be added without perturbing existing aliases/tables/rules → STOP and reconsider the hook point before shipping.

### Manual smoke (owner: maintainer) — required before Accept

> CI cannot load pf tables or run HAProxy. Run on a live pfSense CE box after a full pfBlockerNG update.

- [ ] **Off = no-op.** With both toggles off, no `pfB_Aggregate*`/`pfB_GeoAggregate*` alias/table/file exists; existing aliases/rules unchanged.
- [ ] **Deny-aggregate on.** `pfB_Aggregate_v4`/`_v6` appear as Native `urltable` aliases; contents = deduped+`cidr_aggregate`d union of the effective Deny set (spot-check a few member IPs present, a suppressed/whitelisted IP absent, a GeoIP-only IP absent, a DNSBLIP IP present); **no firewall rule** references them.
- [ ] **Lockstep.** A change to a member feed is reflected in the aggregate **in the same update pass** (no extra cycle).
- [ ] **Never-empty file.** With an empty union, the consumer `-f` file still exists and is non-empty (placeholder).
- [ ] **HAProxy referenceable (ADR-12 pre-check).** A `source_ip` ACL referencing `pfB_Aggregate_v4` causes HAProxy to emit `ipalias_pfB_Aggregate_v4.lst` (proves `is_alias()` + expansion work).
- [ ] **GeoIP-aggregate on.** `pfB_GeoAggregate_{v4,v6}` build from the block continents; off by default until enabled.
- [ ] **Teardown.** Toggling off removes alias/table/file cleanly (no orphans); disabling pfBlockerNG likewise.
