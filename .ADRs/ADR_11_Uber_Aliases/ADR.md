# ADR-11: Native aggregate ("Uber") IP aliases — per action type

- **Status:** **Proposed** (2026-06-02; re-scoped 2026-06-05 to per-type aggregates)
- **Date:** 2026-06-02
- **Branch:** `adr/11-uber-aliases` (off **`devel`** — IP-side only, no Python/DNSBL coupling, so it does **not** depend on ADR-07/10) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (the IP update pass, alias registration, settings read), `pfblockerng.sh` (a new `aggregate` shell action reusing `cidr_aggregate`/`iprange`), `src/usr/local/www/pfblockerng/*` (the opt-in multi-select), `pfblockerng.xml`-side settings as needed.
- **Target runtime:** PHP 8.3 + POSIX `sh` (pfSense CE 2.8). **No Python** — this is entirely the IP/firewall side; the Unbound plugin is untouched.
- **Test suite:** **No `pytest` oracle** — this is PHP/shell with no unit-test harness in-repo. Validation = `php -l` + PHPStan + ShellCheck (the automated gate), a **cost benchmark** (union build time / peak RAM / entry count / pf-table load at scale), and a **manual smoke checklist** (live box) for the alias/table/HAProxy-referenceability CI cannot exercise.

---

## 1. Context

### Today

pfBlockerNG downloads IP feeds and, per list, builds a pf table exposed as a **`urltable` pfSense alias**:

1. **Alias type = `urltable`.** Each IP alias is registered with `'type' => 'urltable'`, `'url' => "{$pfb['weblocal']}?pfb={$alias}"`, `'address' => ''` (`pfblockerng.inc:9512-9520`; GeoIP continents the same, `:8702-8706`). The alias contents live in `{$pfb['aliasdir']}/{$alias}.txt`; pfSense caches the urltable under `/var/db/aliastables/` (`pfblockerng.sh:61`). UI counting keys on `type == 'urltable' && name ~ 'pfB_'` (`inc:4592`).
2. **Alias *action* decides the rule.** `pfb_firewall_rule($list['action'], …)` (`inc:4139`, called `:9526`) creates the filter rule; **"Alias Native"** is the action that registers the alias/table but **creates no rule** — the table is loaded (memory) but never evaluated per-packet (no CPU). This is exactly the user's manual workaround target.
3. **Per-type storage dirs — one per action class.** `denydir`/`permitdir`/`matchdir`/`nativedir` under `/var/db/pfblockerng/` (`inc:47-50`). The action selector (`pfb_determine_list_detail`, `inc:1957-1982`) routes each list to its dir by action: `Deny_*`/`Alias_Deny` → `denydir` (`adv=TRUE` — dedup/reputation applies); `Permit_*`/`Alias_Permit` → `permitdir`; `Match_*`/`Alias_Match` → `matchdir`; `Alias_Native` → `nativedir`. Member files are `${dir}/${alias}.txt`, already `sort -u`'d for deny (`sh:323,519,585`).
4. **Dedup + CIDR aggregation already exist.** `cidr_aggregate()` (`sh:268`, dispatched `sh:956`) shells out to **`/usr/local/bin/iprange`** (a single C binary: sort + collapse overlapping/adjacent CIDRs into the minimal *exactly-equal* covering set — it never adds an address, so aggregation cannot widen a set). Per-alias dedup/aggregation/suppression is solved machinery; there is no per-alias *union* across aliases.
5. **GeoIP routes by action like any list.** Each enabled continent is run through the *same* `pfb_determine_list_detail($continent_config['action'])` (`inc:9926`), so a continent set to Deny lands in `denydir`, Permit in `permitdir`, etc. — GeoIP members are **already distributed into the per-type dirs by their action.** This is why the per-type aggregates fold GeoIP in correctly and for free (see §2), and why a *separate* GeoIP-only aggregate is the harder path, not the easier one.
6. **Empty aliases are pruned.** If an alias resolves to no IPs, its file is unlinked and the alias isn't created (`inc:9495-9498`).
7. **The update pass** runs in `sync_package_pfblockerng()` (`inc:6556`); aliases are materialised and the tables reconciled (`pfb_aliastables()` `inc:4402`). There is **no step that unions the effective set of any action class into a single alias.**

### The user's current workaround (the pain this kills)

To get "all blocked IPs under one name" (for HAProxy ACLs that check the *real* client IP from a Cloudflare header — see ADR-12), the user runs an **external script** that periodically writes a text file of all IPs, **registers that file with pfBlockerNG as a fake "download" list** in Alias Native mode so pfBlockerNG builds the alias, then references it. Costs: a **self-feeding loop** (pfBlockerNG re-ingesting its own output), **two-cycle staleness** (script after pfBlockerNG; pfBlockerNG picks the change up the *next* hour), and a **dummy-IP placeholder** to dodge empty-file validation downstream.

### Load-bearing facts

1. **All the machinery already exists** — `urltable` alias registration, `cidr_aggregate`/`iprange`, suppression, the `weblocal?pfb=` server, `pfb_aliastables`. This ADR **composes** them into per-type union steps; it invents no new alias type and no new file format.
2. **A Native alias is CPU-free but not RAM-free.** An unused table loads into pf (kernel memory ≈ the union size, wired) but is never evaluated. The user accepts this; it argues for **opt-in (default off)**.
3. **The premise is empirically proven.** The user already runs this exact union (for the deny set) at real scale via the workaround — so "it fits" is true for ≥1 deployment. Phase 1 characterised the cost.
4. **No PHP/shell test harness.** The repo's `pytest` suite covers only the Python DNSBL build. This feature is validated by lint (PHPStan/ShellCheck/`php -l`) + a cost benchmark + a manual live-box smoke. There is **no golden oracle** to diff against (additive behaviour, not a refactor).
5. **Consumption is ADR-12, reframed as *generic update hooks*.** ADR-11 only *produces* the aggregate aliases + stable consumer files. **ADR-12 is "run anything before/after a pfBlockerNG update"** — generic pre/post update-command hooks — with HAProxy as the documented worked *recipe*, not hardcoded coupling. The never-empty consumer file makes HAProxy's `/var/etc/haproxy_test` validation + the dummy-IP hack fall away; **freshness is a hook-triggered *graceful HAProxy reload*, NOT a runtime-socket push.**
6. **The four action classes are mechanically identical to union.** Each has its own dir of `${alias}.txt` member files in the same CIDR format. So "aggregate type X" is one generic operation — `cat <dir>/*.txt | sort -u | iprange` — parameterised by the type→dir map. Doing all four costs no more design than doing one; it is a loop.

---

## 2. Decision

Add an **opt-in** step to the IP update pass that **unions each selected action class into a Native `urltable` alias**, one per family, in the **same pass** as the feeds — reusing the existing dedup/`iprange`/registration machinery. Default **off** (nothing selected).

| Area | Decision |
| --- | --- |
| **What it produces** | Per family (v4/v6), per **selected** action type ∈ {Deny, Permit, Match, Native}: **`pfB_<Type>_Aggregated_{v4,v6}`** — `pfB_Deny_Aggregated_v4`, `pfB_Permit_Aggregated_v6`, `pfB_Match_Aggregated_v4`, `pfB_Native_Aggregated_v6`, … = the deduped + CIDR-aggregated **union of that type's dir** for the family. Registered as standard pfB **`urltable`** aliases (mirror `inc:9512-9520`), **Native** (no `pfb_firewall_rule`) — *regardless of which action class they aggregate* ("Native" the registration mode ≠ "Native" the aggregated type). |
| **Per-type member set** | **Deny** = `denydir` union — the post-suppression/whitelist **effective block set**, **incl. `DNSBLIP_v4/_v6`** and **incl. any Deny-action GeoIP continents** (they already live in `denydir`, §1.5). **Permit** = `permitdir` union. **Match** = `matchdir` union. **Native** = `nativedir` union (the user's own `Alias_Native` members). GeoIP is **never** a separate aggregate — it folds into whichever type matches each continent's action. |
| **Dedup / aggregation** | `cat <dir>/*.txt` → existing **`sort -u` dedup** → existing **`iprange` collapse** → write the aggregate file. A new `pfblockerng.sh aggregate <family> <memberlist>` action composes these (no new algorithm). `iprange` is **set-exact** (minimal CIDR set equal to the union) — aggregation never adds an address, so even a Permit aggregate referenced in a real pass rule cannot widen the allow-set. |
| **Build hook (lockstep)** | Runs **inside `sync_package_pfblockerng()`** after all member aliases are materialised (Deny **after** the per-member suppress step — denydir is post-suppression) but before/with `pfb_aliastables()` — so every selected aggregate is current **in the same pass** (kills the two-cycle staleness). No second process, no self-download. Rebuild is **mtime-gated per type**: a type's aggregate is rebuilt only when a member file in its dir changed since the last build (full rebuild of that one union; per Phase 1 the cost is dominated by the deny union and is acceptable). |
| **Order vs. the ADR-12 hooks** | The aggregate build → register → **table load** must complete **before** the ADR-12 **post-update** hook (`pfb_run_hooks('post', …)`, currently `inc:11764`, the closing tail). Place the build in the alias-reconcile region so the aggregate `urltable` is loaded by the normal `pfb_aliastables`/`filter_configure` path (≤`inc:11520`), guaranteeing the aggregate alias/table is **live** before any post-hook fires — so a hook consumer (e.g. an HAProxy graceful reload, ADR-12) always sees the **fresh** aggregate, never a stale one. The post-hook firing point does not move; ADR-11 only inserts its build ahead of it. When an aggregate is rebuilt this pass, its alias name **should** also be merged into the post-hook's `CHANGED_IP_ALIASES` context (the merge already happens at the tail) so a recipe can gate its reload on the aggregate actually changing. |
| **Never-empty consumer file** | For every built aggregate, pfBlockerNG writes a **stable, never-empty** `-f`-format file (a `#`-comment placeholder line when the union is empty) at a known per-(type,family) path, so a downstream `-f` consumer (ADR-12) never hits empty-file validation — **killing the dummy-IP hack at the source.** (Distinct from the pf table, which simply isn't loaded when empty, per `inc:9495-9498`.) |
| **Opt-in (multi-select)** | A settings **multi-select** of which types to aggregate (Deny / Permit / Match / Native), **default none selected**. None selected ⇒ no alias, no file, no table, **byte-identical to today**. Each selected type ⇒ its `pfB_<Type>_Aggregated_{v4,v6}` appears; deselecting tears it down. |
| **Naming** | `pfB_<Type>_Aggregated_{v4,v6}` with `<Type>` ∈ {`Deny`,`Permit`,`Match`,`Native`} — the GUI's own action-group labels (the action dropdown shows "Deny …", the Logs page "Deny Files", etc.). Fixed; `pfB_` prefix; documented. Not user-renamable in v1 (avoids alias-name-collision UI/validation; ≤ pf's 31-char table-name limit — longest is `pfB_Native_Aggregated_v4` = 24). |
| **Permit caveat (semantic, not mechanical)** | A Permit/Match/Native aggregate is a **named IP-set only** — registered Native, it carries **no** direction (In/Out/Both), ports, gateway, or rule ordering from the source lists, and creates **no rule**. It is for *reference* (HAProxy ACL, a hand-authored rule), **not** an auto-permit/auto-match. Mechanically identical and set-exact; it simply does not reconstruct rule semantics. |
| **Out-of-pass safety** | Purely **additive**: member aliases, their tables, and all existing rules are untouched; each aggregate adds rows nowhere except its own table. |

### Semantics that MUST be preserved (the contract)

- **Additive-only.** With **nothing selected**, behaviour is byte-identical to today. With a type selected, no existing alias/table/rule changes — only that type's new Native aggregate alias(es) appear. This holds for **every combination** of the four toggles.
- **Native means no rule.** No aggregate (of any type) ever injects a filter rule; to use one in a rule the user adds it themselves.
- **Correct, set-exact union.** Each aggregate = `sort -u` + `iprange` of *its* dir for the family. Deny reflects the **effective** (post-suppression/whitelist) block set incl. DNSBLIP and Deny-action GeoIP; Permit/Match/Native are exact unions of their dirs. No address is added or dropped versus the true union.
- **In lockstep.** Each aggregate reflects the **current** update pass — never one cycle stale relative to its members.
- **Hooks fire after the aggregates are ready.** A selected aggregate's alias/table is built and **loaded** before the ADR-12 post-update hook fires in that pass — a post-hook consumer never observes a half-built or stale aggregate.
- **Never-empty consumer file.** Every built aggregate's `-f` consumer artifact always exists and is non-empty (placeholder when the set is empty).
- **Clean teardown.** Deselecting a type (or disabling pfBlockerNG) removes that aggregate's alias/table/file with no orphans; other selected aggregates are unaffected.

### Explicitly kept / out of scope

- **Generic pre/post update-command hooks + the HAProxy recipe** — **ADR-12**.
- **A *separate* GeoIP-only aggregate** — **dropped.** GeoIP folds into the per-type aggregates by each continent's action (§1.5). (A dedicated Geo aggregate would require carving continent members back out of the dirs and would double-list them — explicitly not done.)
- **A new alias type or file format** — out; standard pfB `urltable` aliases.
- **User-renamable aggregate names** — out for v1.
- **Reconstructing Permit/Match rule semantics** (direction/ports/gateway) into the aggregate — out; aggregates are IP-sets, registered Native.
- **Cloudflare-edge blocking** (pushing the list to CF via API) — a separate future idea.

---

## 3. Consequences

**Positive**

- Kills the self-feeding workaround + the two-cycle staleness: each union is produced **natively, in-pass**.
- Gives "all IPs of an action class under one name" as a first-class, deduped, CIDR-aggregated Native alias — directly consumable by HAProxy (ADR-12) and anything that takes an IP set by name. Per-type selection means the user materialises only what they need.
- GeoIP correctness is **free** — continents fold into the matching type by action, no extra code, no double-listing.
- Reuses proven machinery (`urltable` registration, `iprange`, suppression) via one generic loop — small, low-risk surface; all four types share a single code path.
- Opt-in + default-none ⇒ zero impact for users who don't want it.

**Negative / risks**

- **RAM at scale.** The deny union can be millions of CIDRs; each loaded (unused) Native table costs wired kernel memory. Mitigated by opt-in default-none + the Phase-1 measurement + the mtime-gated rebuild + the per-type selection (enable only what you consume).
- **Build-time cost in the update pass.** `cat`+`sort -u`+`iprange` over a union adds work; dominated by the deny set (Phase 1). Permit/Match/Native dirs are small. Mitigated by the per-type mtime gate (rebuild only the types whose members changed).
- **No automated correctness oracle.** PHP/shell, no unit harness → reliance on lint + manual smoke. Mitigated by keeping the logic a thin generic composition of already-trusted steps and a tight per-type manual checklist.
- **Empty-set + downstream validation.** An empty union must still yield a non-empty consumer file (placeholder) or ADR-12's HAProxy validation breaks — pinned in the contract.
- **Permit/Match misuse.** A user might expect a Permit aggregate to *permit*; it does not (Native = no rule). Mitigated by help text + docs stating it is a reference IP-set.

---

## 4. Requirements (acceptance)

1. **Opt-in, additive:** nothing selected ⇒ byte-identical to today; any subset selected ⇒ exactly those Native aggregate alias(es) appear and **nothing else changes**, for every combination of the four toggles.
2. **Correct content:** each aggregate = deduped + `iprange`d, set-exact union of its dir for the family. Deny = effective (post-suppression/whitelist) block set incl. DNSBLIP and Deny-action GeoIP; Permit/Match/Native = exact dir unions.
3. **Native:** no firewall rule is created for any aggregate.
4. **Lockstep:** each selected aggregate is rebuilt in the same update pass as its members (no extra cycle); mtime-gated so an unchanged type isn't rebuilt.
5. **Never-empty consumer file** per built aggregate at a stable path (placeholder when empty).
6. **Cost characterised:** Phase-1 benchmark records union build time + peak RAM + entry count + table-load at scale; the per-type extension is bounded by the deny union; mtime-gate documented.
7. **Lint-clean:** `php -l` + PHPStan + ShellCheck clean; no Python/`pytest` change.

---

## 5. Constraints (from `CLAUDE.md`)

- **PHP:** tabs, 8.3, no `die()`/`exit()` in library code, pfSense fns via stubs (add to `stubs/pfsense/` if a new one is used; PHPStan is the gate).
- **Shell:** POSIX `sh` only, quoted expansions, **absolute paths for add-on binaries** (`iprange` via its `path*` var), ShellCheck-clean; the new `aggregate` action mirrors the style of `cidr_aggregate`/`aliastables`.
- **Naming — follow the pattern:** aggregate alias names use the GUI action-group labels (`Deny`/`Permit`/`Match`/`Native`); config keys follow neighbouring `pfb_*` settings.
- **No shipped Python change**; the Unbound plugin and the `pytest` suite are untouched.
- Commit style `<scope>: <imperative summary>`; one commit per phase; PRs rebase-only; PR bodies via `--body-file`.
- **Docs:** README/CLAUDE.md + the settings help text updated when the feature/contract lands (final phase).

---

## 6. Action plan

Each phase = one commit, leaves the tree lint-clean (`php -l`/PHPStan/ShellCheck) and `python -m pytest` **untouched/green**. Cost is measured first (Phase 1); a behaviour-preserving building block lands (Phase 2) before it is wired (Phase 3); membership correctness + additive-invariance are pinned (Phase 4); UI/docs/DoD close it out (Phase 5). The four types share **one** generic code path — phases build the mechanism once and apply it to the type→dir map.

### Phase 1 — Measure the union cost (de-risk) — DONE

Prompt: `01_Measure_Union_Cost.txt`

- Built a standalone benchmark; measured `cat`+`sort -u`+`iprange` wall-time, peak RAM, dedup ratio at million-CIDR scale; documented the live pf-table-load procedure. **Outcome:** primitive = `/usr/local/bin/iprange`; strategy = **full rebuild each pass, mtime-gated per type**; RAM caveat recorded. The deny union is the dominant cost; the per-type extension (smaller permit/match/native dirs) is bounded by it. GO. See `RESULTS/01_Results.txt`.

### Phase 2 — PREP (behaviour-preserving): `aggregate` action + per-type member helper

Prompt: `02_Aggregate_Action_Prep.txt`

- Add a `pfblockerng.sh aggregate <family> <memberlist>` action: read a member-file list → `cat` → `sort -u` → `iprange` → write the aggregate file + the never-empty `-f` consumer file (`#` placeholder when empty). Add a PHP helper that, given an action type, returns its **effective member-file list** per family (the type→dir map; Deny = post-suppression/whitelist block set incl. DNSBLIP, GeoIP folding in by action; Permit/Match/Native = their dirs). **Not wired** into the update pass yet. ShellCheck/PHPStan clean. Standalone-valuable.

### Phase 3 — Wire the per-type aggregates into the pass + register the urltable aliases (opt-in multi-select)

Prompt: `03_Wire_Aggregates.txt`

- Add the opt-in **multi-select** setting (default none). In `sync_package_pfblockerng()`, after members materialise (Deny **after** the suppress step), for each **selected** type × family: compute the member list (Phase 2) → run `aggregate` → register `pfB_<Type>_Aggregated_{v4,v6}` as a `urltable` Native alias (mirror `inc:9512-9520`, **no** `pfb_firewall_rule`) → load via `pfb_aliastables`; mtime-gate the rebuild. **Place the whole block in the alias-reconcile region (≤`inc:11520`) so the aggregate table is loaded before the ADR-12 post-update hook (`inc:11764`)** — and merge a rebuilt aggregate's name into the post-hook `CHANGED_IP_ALIASES` context. Deselect/disable ⇒ remove that aggregate's alias/table/file cleanly. One generic loop over the type→dir map. Additive: existing aliases/rules unchanged.

### Phase 4 — Effective-set & additive correctness (membership + all-combinations)

Prompt: `04_Effective_Set_Correctness.txt`

- Pin membership correctness: the **Deny** aggregate = the *effective* (post-suppression/whitelist) block set, with **DNSBLIP** present and **Deny-action GeoIP continents** present (and absent from Permit/Match unless their action says so); **Permit/Match/Native** = exact dir unions. Verify the **additive invariant across every toggle combination** (none / each single / pairs / all four) — existing aliases/tables/rules byte-identical, only the selected aggregates added. Cover edge cases: empty dir → never-empty file, single member, v4-only / v6-only, a type with no members at all. Refine the Phase-2 helper if any case is wrong.

### Phase 5 — Settings UI + docs + benchmark + manual smoke + DoD

Prompt: `05_UI_Docs_Smoke_DoD.txt`

- Wire the multi-select into the settings page with help text (what each creates, that they are Native/no-rule, the Permit "reference-only" caveat, the RAM caveat); document the feature + naming + opt-in/RAM note in README/CLAUDE.md; re-run the Phase-1 benchmark on the branch; finalise §7 manual smoke + reject criteria. Note the ADR-12 hand-off (the never-empty consumer file + the Native aliases are what HAProxy will consume; freshness = a pfBlockerNG-triggered graceful reload, not a socket push).

---

## 7. Definition of done

- Nothing selected ⇒ byte-identical to today; each selected type ⇒ `pfB_<Type>_Aggregated_{v4,v6}` appears as a Native `urltable` alias with the correct deduped+aggregated set-exact content for that action class, **no firewall rule**, rebuilt in-pass (mtime-gated), with a never-empty consumer file — for every toggle combination.
- `php -l` + PHPStan + ShellCheck clean; `python -m pytest` untouched/green.
- The Phase-1 cost is characterised; the per-type mtime-gated full rebuild is the chosen strategy.
- Status → **Accepted** only after the maintainer confirms the manual smoke below on a live pfSense box.

### Reject / pivot criteria (decide cheaply, Phase 1 — DONE)

- **Cost prohibitive at scale:** if a full per-pass union blows the update-pass time or box RAM at realistic million-CIDR scale → pivot to a finer incremental (set-hash) build, or keep strictly opt-in with the documented RAM warning. (Phase 1 chose full-rebuild + mtime-gate; the hook point is unchanged so a finer pivot stays contained.)
- **Cannot stay additive:** if the union step can't be added without perturbing existing aliases/tables/rules → STOP and reconsider the hook point before shipping.

### Manual smoke (owner: maintainer) — required before Accept

> CI cannot load pf tables or run HAProxy. Run on a live pfSense CE box after a full pfBlockerNG update.

- [ ] **None selected = no-op.** With no types selected, no `pfB_*_Aggregated_*` alias/table/file exists; existing aliases/rules unchanged.
- [ ] **Deny aggregate on.** `pfB_Deny_Aggregated_v4`/`_v6` appear as Native `urltable` aliases; contents = deduped+`iprange`d union of the effective Deny set (spot-check: a few member IPs present; a suppressed/whitelisted IP **absent**; a **DNSBLIP** IP present; a **Deny-action GeoIP** continent IP present); **no firewall rule** references them.
- [ ] **Permit / Match / Native aggregates on.** Each selected type produces `pfB_<Type>_Aggregated_{v4,v6}` from its dir; **no rule**; Permit aggregate is a plain IP-set (no direction/ports).
- [ ] **All-combinations additive.** Toggle each subset; existing aliases/tables/rules stay byte-identical; only the selected aggregates appear/disappear.
- [ ] **Lockstep.** A change to a member feed is reflected in that type's aggregate **in the same update pass** (no extra cycle); an unchanged type isn't rebuilt (mtime gate).
- [ ] **Never-empty file.** With an empty union for a selected type, its consumer `-f` file still exists and is non-empty (placeholder).
- [ ] **HAProxy referenceable (ADR-12 pre-check).** A `source_ip` ACL referencing `pfB_Deny_Aggregated_v4` causes HAProxy to emit `ipalias_pfB_Deny_Aggregated_v4.lst` (proves `is_alias()` + expansion work).
- [ ] **Post-hook fires after the aggregate is ready.** With a `post` update hook configured (ADR-12), force a member-feed change and run an update: the hook runs **after** the rebuilt `pfB_<Type>_Aggregated_*` table is loaded (the hook, e.g. `pfctl -t pfB_Deny_Aggregated_v4 -T show` or a freshness marker, sees the **new** content — never the prior pass's), and the aggregate's name appears in `PFB_CHANGED_IP_ALIASES`.
- [ ] **Teardown.** Deselecting a type removes its alias/table/file cleanly (no orphans), leaving other selected aggregates intact; disabling pfBlockerNG removes them all.
