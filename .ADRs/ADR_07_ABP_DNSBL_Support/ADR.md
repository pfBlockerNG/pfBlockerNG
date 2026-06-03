# ADR-07: Full ABP-style DNSBL list support (DNS-only, in the Python build)

- **Status:** **Implemented — pending live smoke** (2026-06-02; flips to **Accepted** only after the §7 manual smoke passes on a live pfSense box)
- **Date:** 2026-06-02
- **Branch:** `adr/07` (off **`next`** — depends on ADR-06 "DNSBL preprocessing → Python" having landed) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (the build layer + the query-time matcher), `pfblockerng.inc` (`$easylist` lite parser, the manifest writer `pfb_unbound_python_sources`, the DNSBL-IP firewall pass, the user-regex feature), `src/usr/local/www/pfblockerng/*` (the new "Limit long/complex regex" opt-in setting).
- **Target runtime:** Python 3.11+ inside Unbound's `pythonmod`, **stdlib only** (no subprocess, no out-of-stdlib regex engine; note 3.11+ gives atomic groups + possessive quantifiers in `re`); PHP 8.3; POSIX `sh`.
- **Test suite:** `tests/test_pfb_unbound.py`, `tests/conftest.py`, `tests/test_adr06_*` (the decision-equivalence guard that must keep passing); new `tests/test_adr07_*` (the ABP decision spec/oracle, parser, reconcile/precedence, regex-safety).
- **References (the ABP/AdGuard syntax this implements):** AdblockPlus filter cheatsheet <https://adblockplus.org/filter-cheatsheet>; AdGuard "create your own filters" (incl. DNS-relevant modifiers, `$important`, `$badfilter`) <https://adguard.com/kb/general/ad-filtering/create-own-filters/>; AdGuardHome adblock-style hosts-blocklist syntax <https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists#adblock-style-syntax>; ReDoS static-checker reference (for the safety classifier) <https://devina.io/redos-checker>.

---

## 1. Context

### Today (verified on `next`, post-ADR-06)

ADR-06 moved DNSBL list preprocessing into a pure, stdlib-only build layer in `pfb_unbound.py` (`parse`/`normalise`/`classify`/`build`, `pfb_unbound.py:1798-2058`) fed by a per-feed manifest the PHP/shell side writes. **But ABP/EasyList feeds are still handled by a "lite" parser, and it lives in PHP**, not in the Python build:

1. **ABP "lite" parse — PHP `$easylist` (`pfblockerng.inc:7796-7847`).** A feed is sniffed for an ABP header (`[Adblock Plus]`, `[uBlock Origin`, `! Title: AdGuard`); each line is kept **only** if it is `||domain^` with **no** `$`, `*`, or `/`, then the `||`/`.^`/`^` tokens are stripped (`$e_replace`) to a bare domain. **Everything else is dropped silently:** `@@` exceptions, `##`/`#@#`/`#?#` element-hiding, `$options`, paths/URLs, and all regex.
2. **PHP writes the manifest with `format_hint = 'plain'` for *every* feed** (`pfblockerng.inc:2385`, writer `pfb_unbound_python_sources` `:2319-2427`; paths `unbound_py_sources`/`unbound_py_rawdir` `:114-115`). So the Python plugin only ever receives pre-cleaned plain domains; its `parse('abp', …)` handler (`pfb_unbound.py:1798`, `_dnsbl_parse_abp_line:1768`) exists but **production never reaches it** (the dormant ABP seam ADR-06 left for *this* ADR).
3. **Query-time matcher (`evaluate_domain`, `pfb_unbound.py:2251`).** `dataDB` (exact block), `zoneDB` (wildcard block), `regexDB` (**block-regex, applied per query** `:2312-2318`), then `whiteDB` (**domain/wildcard allow**, applied as an override `:2324-2326`). Payloads are `{"log", "index"}`; `whiteDB[d]` is a bare wildcard bool (`:659`, normaliser `_dnsbl_normalise_whitelist:1936`, matcher `whitelist_check_domain:2201`). **There is no allow-regex path, and no notion of rule priority** — the model is "a block is found, then an allow can override it."
4. **`regexDB` is user-configured, not from feeds.** The existing "DNSBL Resolver python regex" feature (`$pfb['dnsbl_regex']`/`['dnsbl_regex_list']` = `dnsblconfig['pfb_regex']`/`['pfb_regex_list']`, `pfblockerng.inc:848-849`) writes the user's regex list into the plugin's python config (`:2608-2635`); the plugin compiles them into `regexDB` at init (`pfb_unbound.py:479`). The UI counts them under the `DNSBL_Regex` alias (`pfblockerng.inc:8324-8330`). **These regexes are currently un-vetted** (a user typo can already ReDoS the resolver).
5. **DNSBL-embedded IPs still feed the firewall** (ADR-06 fact 7, the "DNSBL IP" feature): PHP extracts IPs from downloaded feeds into the `DNSBLIP_v4`/`_v6` pf aliases. This stays entirely in PHP; the Python build never produces firewall input.

### The problem (maintainer-stated; justification is settled, **not** a premise to falsify)

> "We are right now completely unable to process **regex** and **exclusion (whitelist `@@`)** entries from ABP lists. Lists that block some overarching domains but whitelist a handful of others (because they provide important web functionality) simply do not work — so users think we 'over-block' relative to AdGuard Home."

Concretely, the lite parser applies a feed's `||domain^` **blocks** while silently dropping the paired `@@` **exceptions** meant to carve them back — systematic over-blocking, not a missing nicety. Plus regex-only rules are lost entirely. Unlike ADR-01/ADR-06, **the premise is accepted up front**; the falsifiable gates here are the *implementation risks* (per-query regex cost, ReDoS), not whether the feature is worth doing.

### Load-bearing facts

1. **The plugin runs inside Unbound's resolver process, pure-Python stdlib-only** (CLAUDE.md). Query-time work is *on the DNS critical path*; build/init work runs *in* Unbound at (re)load.
2. **`re` does not release the GIL during a match, and Python threads cannot be killed.** A catastrophic-backtracking ("ReDoS") regex is one long C-level call that **freezes the entire interpreter** — every Unbound query thread — until it returns (for an exponential pattern, effectively never). A thread/`ThreadPoolExecutor`/`asyncio.run_in_executor` "timeout" **cannot** interrupt it: the waiter can't even re-acquire the GIL to observe the timeout, and the runaway worker can't be cancelled. The maintainer has chosen **not** to pay for the only airtight fixes (a killable subprocess, or a linear-time engine like re2 — both outside stdlib) and instead **accepts a bounded residual risk**, mitigated by an opt-in static cap + always-on runtime self-eviction (§2). The accepted bet: at DNS-name scale (≤253 chars) a pathological match is unlikely to run for *minutes*, and any pattern that trips the runtime ceiling is **evicted** so it cannot hang twice.
3. **Regex safety is in-process + best-effort (no subprocess, no vetting).** An opt-in static cap drops over-long/over-complex patterns at load (no execution); always-on runtime timing in the matcher warns above one ceiling and **evicts** the pattern above a higher one (self-healing). Eviction mutates the live `regexDB`/`allowRegexDB` shared across Unbound query threads — under the GIL a `dict.pop` is atomic, but the scan must **iterate a snapshot and evict *after* the loop** (never mutate mid-iteration). Applies to feed **and** user regex (the user list is un-vetted today).
4. **No live Unbound in CI** (every prior ADR). The build layer and the matcher are pure functions pinned by a pytest oracle; everything new here must be the same shape (no Unbound symbols → unit-testable). The static cap + the runtime-timing logic are plain stdlib functions, also unit-testable.
5. **Query latency budget is ~1 µs/query** (ADR-05 §3a; dict ~0.7–1.9 µs). The existing per-query `regexDB` scan is O(n) over compiled patterns (`:2313`). Feeds can contribute *many* irreducible regexes — this is the ADR-01-class performance risk and is measured in Phase 1 with a kill-threshold.
6. **DNS-only is a hard scope rule (maintainer).** pfBlockerNG blocks **IP and DNS** only. ABP rules targeting an element/path/URL, or carrying page-context `$options`, do **not** imply a DNS decision and are **skipped**. Only whole-domain and domain-targeting-regex rules (with DNS-relevant options) are in scope.
7. **User intent is sovereign (maintainer).** User-provided block domains, user regex, the whitelist (settings textarea + alerts "add to whitelist" button), and the TOP1M whitelist must **never** be overridden by a feed rule, and are **never** removable by a feed `$badfilter`. They are treated as `$important` and `$badfilter`-immune.
8. **`pfb_py_count` + the `DNSBL_Regex` alias count drive the UI** (`pfblockerng.inc:3149`, `:8329`). Whoever produces the dicts/regex sets must keep emitting counts the UI can read.

---

## 2. Decision

Implement **full ABP-style support, DNS-only**, by moving the ABP parse out of the PHP `$easylist` lite pass into the Python build, and adding the three things the lite pass throws away: **`@@` exceptions, regex (block *and* allow), and ABP precedence (`$important`/`$badfilter`)**. The build is restructured as the maintainer proposed — **parse each line into a typed intermediate `Rule`, reconcile/prioritise the rule sets in-memory, then emit the final matcher structures + counts** — because `$badfilter` (and `$important`) cannot be expressed once rules are folded into domain-keyed dicts. The matcher gains a cheap **numeric precedence** with a **fast path** that is byte-for-byte today's behaviour when no `$important`/`$badfilter`/feed-`@@`/feed-regex is loaded. Untrusted regex is kept tolerable by a best-effort guard — an opt-in static cap + always-on runtime warn/evict self-healing — not by vetting or a (futile) query-time timeout.

| Area | Decision |
| --- | --- |
| **Parse boundary (full Python)** | Delete the PHP `$easylist` lite pass. PHP **header-sniffs** ABP feeds and tags them `format_hint = 'abp'` in the manifest, passing the **raw** ABP lines unmodified (non-ABP feeds stay `'plain'` as ADR-06 left them). Python `parse('abp', line)` becomes the full DNS-only ABP parser. Realizes ADR-06's "one parser in Python" goal and deletes PHP. |
| **DNSBL-IP coexistence** | The "DNSBL IP" firewall feature stays entirely in PHP (ADR-06 fact 7). With raw ABP lines now passed through, the PHP IP pass learns ABP-anchored IP syntax (`\|\|1.2.3.4^`, hosts `0.0.0.0 1.2.3.4`) → routes to `DNSBLIP_v4`/`_v6` exactly as today; Python `parse('abp')` **skips** IP-valued anchors (returns `None`, same no-leak contract as ADR-06). No double-handling: IP → firewall only, domain/regex → Python only. |
| **Intermediate `Rule` model** | `parse('abp', line) → Rule \| None` where `Rule(kind=block\|allow, target=domain\|regex, key/pattern, important: bool, badfilter: bool, provenance=user\|feed, feed, group, log, signature)`. The `signature` = `(pattern, sorted DNS-options)` minus `$badfilter`, used for `$badfilter` matching. This replaces ADR-06's `ParsedEntry` for the ABP path (ADR-06's `DnsblEntry` seam is the precedent). |
| **Scope — what is parsed (DNS-only)** | **Block:** `\|\|domain^`(+DNS-options), hosts `IP domain`, plain `domain`. **Allow:** `@@\|\|domain^`(+DNS-options). **Regex:** `/re/` (block), `@@/re/` (allow). **Kept only if** the target is a bare domain or a domain-targeting regex **and** every option is DNS-meaningful. **Skipped always:** `##`/`#@#`/`#?#` element-hiding, path/URL rules, page-context options (`$third-party`, `$domain=`, `$script`, `$image`, `$csp`, …). A path/element being blocked does **not** imply a DNS decision. |
| **Regex reduction** | Anchored-reducible patterns (`/^(.+\.)?example\.com$/`, `/^example\.com$/`, `/(^\|\.)example\.com$/`, …) are **converted to domain/wildcard rules** at build time (block → zone/data, allow → `whiteDB` wildcard) — zero added per-query cost. Only **irreducible** regex becomes a real compiled pattern. Do **not** expand finite classes (`ad[0-9]\.x` stays a regex; enumerating `ad0..ad9` is complexity for no gain). |
| **Regex safety (ReDoS)** | **No vetting, no subprocess** — minimum-effort, fully in-process (stdlib only). Two layers: (1) **opt-in static cap** — when the user enables "Limit long/complex regex", patterns over a length / nested-quantifier ceiling are dropped at load (cheap, no execution); (2) **always-on runtime self-eviction** — the matcher times each regex match; over a *warn* ceiling it logs a warning, over a higher *evict* ceiling it logs an error and **removes the pattern from the live DB** (snapshot-iterate, evict-after-loop) so it can't hang again. Both apply to feed **and** user regex (the user list is un-vetted today). **Accepted residual risk (maintainer):** the *first* match of a pathological pattern can still block that one query (and the interpreter, via the GIL) until it returns — judged unlikely to reach minutes at DNS-name scale. Timing uses per-match **thread CPU** (`time.thread_time` — jitter-robust vs wall clock, so a descheduled thread can't false-evict a good pattern); defaults **warn 10 ms / evict 100 ms**, both configurable (advanced). (re2 would remove the risk but is a non-stdlib compiled dep → out of scope.) |
| **`$badfilter` reconciliation** | Build-time, feed-only: collect feed `$badfilter` signatures; drop every **feed** rule whose signature matches; the `$badfilter` rules themselves don't emit. **User rules are skipped** by the prune (sovereignty, fact 7). |
| **Precedence (numeric, 6-band)** | One scale, highest wins: **6** user allow · **5** user block · **4** feed allow `+$important` · **3** feed block `+$important` · **2** feed allow (`@@`) · **1** feed block (`\|\|`). Blocked iff a block matches and `block_prio > allow_prio` (no ties: block∈{1,3,5}, allow∈{2,4,6}). This *is* today's "allow beats block" (2>1) plus the `$important` tiers and the sovereign user band. |
| **Query-time matcher** | `evaluate_domain` gains: an `allowRegexDB` check, an `important` field on `dataDB`/`zoneDB`/`regexDB`/`whiteDB` payloads, and the 6-band resolution. **Fast path:** a build-emitted `pfb["important_rules"]` flag — false (no `$important`/`$badfilter` loaded) keeps today's early-exit matcher unchanged (user-allow/user-block checked as cheap dict lookups; feed block found → feed `@@`/allow-regex overrides). Full numeric resolution engages only when important feed rules exist. |
| **Emit + counts** | Stage-C emits `dataDB`/`zoneDB` (`+important`), `regexDB` (block, `+important`), **`allowRegexDB`** (new), `whiteDB` (`{wildcard, important}`), the `important_rules` flag, and counts. `pfb_py_count` stays the loaded total in the format the UI reads (`inc:3149`); the `DNSBL_Regex` alias count (`inc:8329`) now reflects the **admitted** (cap-filtered) feed+user regex total (value changes by design). |
| **Reentrancy** | `build()` stays the pure `(manifest+config) → structure-set` reentrant function ADR-06 made it; the new rule model + reconcile are pure too. Runtime regex eviction is the one in-place mutation of a loaded structure — kept safe by snapshot-iterate + evict-after-loop (fact 3). (Zero-downtime swap remains a future ADR.) |

### Semantics that MUST be preserved (the contract — pin with tests *before* changing the matcher)

The contract is **net DNS decisions**. ADR-07 *adds* decisions (the `@@`/regex/precedence the lite parser dropped), so the invariants are:

- **No regression when no ABP feature is present.** For the ADR-06 corpus/config (plain/hosts/basic-`||domain^`, no `@@`, no feed regex, no `$important`/`$badfilter`), every decision (block shape / resolve / whitelist / HSTS / noAAAA / zone-subdomain) is **identical** old-vs-new — pinned by the *retained* ADR-06 golden oracle (`tests/test_adr06_*`). The Phase-3 matcher refactor and the `important_rules` fast path exist to guarantee this.
- **User sovereignty (fact 7) is absolute.** A user whitelist (textarea or alerts button) un-blocks regardless of any feed rule incl. `$important`; a user block stays blocked regardless of any feed `@@` incl. `$important`; **no feed `$badfilter` removes a user rule.** TOP1M (when enabled) behaves as a user allow.
- **ABP DNS semantics are correct** against the Phase-2 spec: `@@` un-blocks globally; reducible regex behaves identically to its dict form; irreducible regex matches as written; `$important` inverts allow-vs-block within the feed band; `$badfilter` deletes the matching feed rule; element/path/page-`$option` rules never become DNS decisions.
- **Regex safety is best-effort, applied to feed *and* user regex.** An opt-in static cap drops over-long patterns at load; runtime timing warns and then evicts a pattern that exceeds the ceiling. The accepted residual is a single slow first-hit before eviction (fact 2).
- **DNSBL-embedded IPs** still populate `DNSBLIP_v4`/`_v6` with the configured action (no IP leaks into DNS blocking; no IP lost to the new abp pass-through).
- **Counts** remain Python/PHP-emitted in the formats the UI reads; values change by design (regex/`@@`/un-pruned), which is not a regression.

### Explicitly kept / out of scope

- **DNS-only, always.** Element-hiding, cosmetic, path/URL, and page-context-`$option` rules are parsed-and-skipped, never approximated as DNS blocks.
- **Homoglyph / IDN-homograph protection** — a separate **future ADR** (already parked); not here, though it will build on the same Python preprocessing home.
- **Zero-downtime / restart-free reload** — still a future ADR; `build()` stays reentrant but the swap isn't implemented here.
- **The matcher data structures** (dict/zone, ADR-01/-05) — unchanged in *kind*; we only add an `important` field, an `allowRegexDB`, and the resolution logic.
- **The download mechanism, feed catalog, scheduling, auth/headers** — stay in PHP (network belongs out of the resolver).
- **Non-DNS AdGuard DNS modifiers** (`$dnsrewrite`, `$dnstype`, `$client`, `$ctag`) — **out of scope**; a rule whose *only* effect is one of these is skipped (we do block/allow, not rewrite). `$important`/`$badfilter` are in scope because they modify block/allow precedence.

---

## 3. Consequences

**Positive**

- Fixes the real, maintainer-stated over-blocking: feed `@@` exceptions are honoured, so pfBlockerNG stops blocking the carve-backs other ABP solutions (AdGuard Home) respect.
- One ABP parser, in Python, next to the matcher — deletes the PHP `$easylist` lite pass and realizes ADR-06's stated goal.
- Regex (block + allow), with anchored patterns folded to dicts (free) and the rest loaded behind the runtime safeguard — and the **existing user regex finally gets the same ReDoS safeguard** it never had.
- Spec-faithful precedence (`$important`/`$badfilter`) via a cheap numeric model with a zero-cost fast path for the common (no-important) deployment.

**Negative / risks**

- **Per-query regex cost (ADR-01-class).** Irreducible feed regex is O(n) per query at `:2313`. Mitigated by reduction-to-dict, the Phase-1 reduction-ratio/latency measurement + kill-threshold, and the `important_rules` fast path. If the irreducible count blows the budget → pivot (translate-only / drop irreducible).
- **ReDoS in the resolver (accepted, mitigated).** Untrusted feed/user regex + stdlib `re` with no query-time timeout. The maintainer accepts a bounded residual rather than pay for a subprocess/re2: an opt-in static cap + always-on runtime warn/evict self-healing bound the damage to a single slow first-hit per bad pattern. A query-time *thread* timeout is explicitly NOT used — it cannot interrupt a match (fact 2).
- **Precedence complexity.** `$badfilter` forces an intermediate rule model + a reconcile pass; `$important` adds a query-time band. Mitigated by the typed `Rule` model (which we wanted anyway) and the fast path.
- **Boundary + behaviour change across 4 languages.** Mitigated by incremental phases, the retained ADR-06 oracle (no-regression guard), and deleting the PHP lite pass only after the Python path is proven.
- **Cross-feed global `@@`.** An exception in one feed can un-block what another feed blocks (true ABP semantics, maintainer-chosen). Surfaced in the smoke checklist; user sovereignty still wins over any feed.

---

## 4. Requirements (acceptance)

1. **ABP-correct (DNS-only):** golden tests prove `@@` un-block, reducible+irreducible regex (block & allow), `$important`/`$badfilter` precedence, provenance/sovereignty, and element/path/page-`$option` skipping — per the Phase-2 spec.
2. **No regression:** the retained ADR-06 oracle passes unchanged for non-ABP corpora (the fast path is byte-identical to today).
3. **Within budget:** at feed-scale irreducible-regex counts, added per-query latency meets the Phase-1 kill-threshold; otherwise the documented pivot is taken.
4. **Regex safety (best-effort):** runtime timing warns then evicts a pattern over the ceiling (feed + user); the opt-in static cap drops over-long patterns at load; eviction is thread-safe (snapshot-iterate, evict-after-loop). Accepted residual: one slow first-hit.
5. **User sovereignty:** whitelist (both entry points) + user blocks + user regex + TOP1M always win over feeds and are `$badfilter`-immune.
6. **DNSBL-IP intact:** embedded IPs (incl. ABP-anchored) still build `DNSBLIP_v4`/`_v6`; no IP leaks into DNS blocking.
7. **UI intact:** `pfb_py_count` + `DNSBL_Regex` alias render; values legitimately differ.
8. **Default suite green:** `python -m pytest`, `ruff`, `php -l`, ShellCheck clean; no new shipped deps (stdlib only, no subprocess).

---

## 5. Constraints (from `CLAUDE.md`)

- **Plugin: stdlib only, Python 3.11+**, 4-space, type hints on new fns, no bare `except`, `from __future__ import annotations`. New build/parse/reconcile code references **no Unbound symbol** (unit-testable); any new injected symbol → `stubs/python/unboundmodule.py`.
- **PHP:** tabs, 8.3, no `die()`/`exit()` in library code, pfSense fns via stubs.
- **Shell:** POSIX `sh`, quoted, absolute binary paths, ShellCheck-clean.
- Run `python -m pytest` after any `pfb_unbound.py`/`tests/` change; `ruff check .`/`ruff format .` clean each commit.
- Commit style `<scope>: <imperative summary>`; **work inline on `adr/07`, one commit per phase, push directly** (PR only if rejected). PR bodies via `--body-file`.
- **Docs:** README/CLAUDE.md updated when the build/contract, the new setting, or test commands change (final phase).

---

## 6. Action plan

Each phase = one commit, leaves `python -m pytest` green, and **preserves net DNS decisions for non-ABP input** (the retained ADR-06 oracle). The **de-risking measurement is front-loaded (Phase 1)**, the **ABP decision spec/oracle (Phase 2)** is laid down before any logic, and a **behaviour-preserving matcher refactor (Phase 3)** lands before any ABP rule is parsed — all three retain standalone value even if later scope is trimmed.

### Phase 1 — Inventory the contract + ABP corpus + measure (regex latency / ReDoS / reduction) — de-risk

Prompt: `01_Inventory_Corpus_Spike.txt`

- **Inventory** the exact current state: the PHP `$easylist` lite parser, the manifest writer (`format_hint='plain'` today), the dormant Python `parse('abp')`, the `regexDB` load + per-query scan, the `whiteDB` shape + `whitelist_check_domain`, the `evaluate_domain` allow-override seam, the **user-regex** feature (`pfb_regex_list` → `regexDB`), the DNSBL-IP firewall pass, and the UI counts (`pfb_py_count`, `DNSBL_Regex` alias). Write it down as the **contract to preserve**.
- **Assemble a real ABP DNS-feed corpus** (AdGuard DNS filter, AdGuardHome, EasyList DNS-subset, hagezi) under `tests/fixtures/adr07_*` / `benchmarks/`; categorise line types and counts.
- **Measure:** (a) regex **reduction ratio** (% of `/re/` that fold to domain/wildcard), (b) **irreducible** regex count at feed scale, (c) added **per-query latency** of the inline regex pass at that count (vs the ~1 µs baseline), (d) **ReDoS exposure** (how many static-dangerous) + how slow the worst real patterns actually run on a ≤253-char input.
- **Confirm the runtime-safety mechanism + propose ceilings:** the warn/evict wall-time thresholds, the snapshot-iterate + evict-after-loop approach, and the opt-in static-cap heuristic (length / nested-quantifier). A quick demo confirms a thread/`asyncio` timeout can NOT interrupt a runaway match (GIL; fact 2) — which is *why* the design accepts a first-hit and evicts.
- **Gate:** GO/NO-GO vs a kill-threshold (propose: added median query latency ≤ a few µs at the measured irreducible count; reduction ratio high enough to bound it — tune with maintainer). Miss → pivot (translate-only / drop irreducible) and record it.

### Phase 2 — ABP DNS decision spec + golden oracle

Prompt: `02_Decision_Spec_Oracle.txt`

- There is **no code oracle** (we expand behaviour). Author the ABP **DNS-only** semantics as fixtures + a decision table under `tests/`: `(rules, query) → expected decision`, derived from the ABP/AdGuard references. Cover block (`||`/hosts/plain), `@@` allow (global), reducible + irreducible regex (block & allow), `$options` keep/skip, `$important` precedence, `$badfilter` prune (feed-only), provenance/sovereignty bands, and element/path/page-`$option` skipping. Pure pytest, CI-runnable.
- This is the oracle every later phase diffs against; standalone-valuable.

### Phase 3 — PREP (behaviour-preserving): matcher → priority/strata + payload widening

Prompt: `03_Matcher_Strata_Prep.txt`

- Refactor `evaluate_domain` into the user-strata + feed-priority resolution shape; widen `dataDB`/`zoneDB` payloads with an `important` field (default `False`), `whiteDB[d]` → `{wildcard, important}`, add an empty `allowRegexDB` container and the `pfb["important_rules"]` flag (false today). **MUST reduce to today's exact decisions** — pinned by the retained ADR-06 oracle (no ABP yet). Pure refactor; standalone-valuable (kept even if later scope trims).

### Phase 4 — Intermediate `Rule` model + Stage-A `parse('abp')` (pure, additive)

Prompt: `04_Rule_Model_Parser.txt`

- Define `Rule` (kind/target/key-or-pattern/important/badfilter/provenance/feed/group/log/signature). Implement the full DNS-only `parse('abp', line) → Rule | None`: `||domain^`(+DNS-options), `@@||domain^`, plain domain, hosts `IP domain`, `/re/`, `@@/re/`; parse `$options` (keep DNS-relevant **and** domain/regex-target, skip page-context); skip element/path/URL; **skip IP-valued anchors** (firewall path). Unit-test exhaustively vs the Phase-2 spec. **Not** wired into `build()`/init.

### Phase 5 — Stage-B reconcile (pure): `$badfilter` prune + regex reduction + classify + bands

Prompt: `05_Reconcile_Badfilter_Reduce.txt`

- `$badfilter` signature prune (feed-only; user rules immune). Anchored-regex **reduction** to domain/wildcard. `classify` domain blocks data/zone (reuse ADR-06 `classify`). Assign priority **bands** (user 5–6 always-important; feed 1–4 per `$important`). Produce the typed pre-emit rule sets + the irreducible-regex candidate list (input to Phase 6). Unit-test reconciliation/precedence vs Phase-2.

### Phase 6 — Stage-C emit + wire `build()` to abp feeds + live 6-band matcher (ABP active)

Prompt: `06_Emit_Wire_Matcher.txt`

- Emit `dataDB`/`zoneDB`(`+important`), `regexDB`(block,`+important`), `allowRegexDB`, `whiteDB`(`{wildcard,important}`), `important_rules`, counts. Wire `build()` to consume `format_hint='abp'` feeds (via Phase-4/5) + compile the reduced/irreducible regex sets; extend `evaluate_domain` to apply `allowRegexDB` + full 6-band resolution **live**. Decision-equivalent **off** (ADR-06 oracle) **and** ABP-correct **on** (Phase-2 oracle).

### Phase 7 — Regex safety: opt-in long-regex cap + runtime timing/eviction + setting + user-regex

Prompt: `07_Regex_Safety.txt`

- **No subprocess, no vetting (maintainer).** Add: (1) an **opt-in static cap** ("Limit long/complex regex" setting) dropping over-length / nested-quantifier patterns at load; (2) **always-on runtime timing** in the matcher's regex scan — warn over one ceiling, log-error + **evict** over a higher one (snapshot-iterate, evict-after-loop; thread-safe under the GIL). Apply both to **feed and user `pfb_regex_list`**. Add the setting (settings page) + the tunable ceilings (Phase-1 defaults). Unit-test: cap drops over-long; a synthetic slow pattern warns then evicts; eviction doesn't corrupt the scan.

### Phase 8 — Slim PHP: full-Python boundary + DNSBL-IP coexistence

Prompt: `08_Slim_PHP_Boundary.txt`

- PHP **header-sniffs** ABP feeds → `format_hint='abp'`, passes **raw** lines; **delete** the `$easylist` lite pass (`$e_replace`). Teach the **DNSBL-IP** pass ABP-anchored IP syntax (`||1.2.3.4^`, hosts IP) → `DNSBLIP_v4`/`_v6`; Python skips IPs (0 leak). UI reads the new counts. Decision-preserving for observable DNS output (Phase-2 + ADR-06 oracles; `php -l`/ShellCheck).

### Phase 9 — Validation, perf/ReDoS benchmark, manual smoke, DoD

Prompt: `09_Validation_Smoke_DoD.txt`

- Full ABP golden equivalence + no-regression; re-run the Phase-1 latency/ReDoS benchmark on `adr/07` vs threshold; finalise the setting UI text, README/CLAUDE.md. **Manual smoke (live box):** `@@` un-blocks; `$important`/`$badfilter` precedence; user sovereignty (whitelist both entry points; user block beats feed `@@$important`); a ReDoS feed regex is dropped + logged (resolver stays responsive); DNSBL-IP intact; counts; reload.

---

## 7. Definition of done

- `python -m pytest` green incl. the new ABP spec/oracle, parser, reconcile/precedence, and regex-safety tests **and** the retained ADR-06 oracle (no regression); `ruff` clean; `php -l` + ShellCheck clean.
- ABP DNS semantics are correct per the Phase-2 spec (`@@`, regex block+allow, `$important`/`$badfilter`, provenance/sovereignty, element/path/`$option` skip); the non-ABP fast path is byte-identical to today.
- Per-query regex cost meets the Phase-1 kill-threshold at feed scale (or the documented pivot was taken); the opt-in static cap + runtime warn/evict are in place (feed + user); a tripped pattern is evicted, not re-run.
- PHP `$easylist` lite pass deleted; ABP parse is one Python parser; DNSBL-IP (incl. ABP-anchored) intact; user `pfb_regex_list` now behind the same runtime safeguard.
- The opt-in "Limit long/complex regex" setting works; runtime warn/evict is active by default.
- Status → **Accepted** only after the manual smoke (below) passes on a live pfSense box.

### Build evidence (recorded Phase 9, on `adr/07`)

CPython 3.11, Linux; `tracemalloc` OFF (ADR-06 measurement note). All numbers
reproduced on-branch in Phase 9 — they match the Phase-1 spike (no drift).

**Test equivalence (`python -m pytest`): 917 passed, 0 failed.** Of these:

- **No-regression (ADR-06 golden oracle retained-green): 71 passed** —
  `test_adr06_golden_oracle.py` + `test_adr06_build_module.py` +
  `test_adr06_init_from_raw.py` + `test_adr06_php_boundary.py`. The non-ABP fast
  path (`important_rules` false) is byte-identical to today; every block/resolve/
  whitelist/HSTS/noAAAA/zone-subdomain decision is unchanged old-vs-new.
- **ABP DNS equivalence (Phase-2 spec/oracle): 662 passed** —
  `test_adr07_decision_spec.py` (spec/oracle), `_parser.py`, `_reconcile.py`,
  `_matcher_strata.py`, `_emit_wire.py`, `_regex_safety.py`, `_php_boundary.py`.
  Production (`build()` + `evaluate_domain` + the slimmed PHP boundary, end-to-end)
  is decision-equal to the spec across hosts/plain/abp incl. `@@` (block & allow),
  reducible + irreducible regex (block & allow), `$important`, `$badfilter`
  (feed-only prune), provenance/sovereignty bands, and element/path/`$option` skip.
- Remaining ~184 are the retained `test_pfb_unbound.py` matcher/init suite (also
  green) — the full default run.

**Perf / ReDoS benchmark (`benchmarks/spike_adr07_regex.py`, on `adr/07`):**
**GATE = GO.**

| metric | measured (on-branch) | kill-threshold | result |
| --- | --- | --- | --- |
| regex reduction ratio (`/re/` → dict, zero per-query cost) | 46% (18 of 39 fold) | ≥ 30% | PASS |
| per-irreducible-pattern added latency (negative query, worst case) | 0.1256 µs/pattern (linear) | "a few µs" / 50 µs hard ceiling | PASS |
| budget-bounded irreducible count at 50 µs | ~398 patterns | feed-scale ≫ realistic count | PASS |
| ReDoS: pathological (≥2 s) caught by static cap / MISSED | 4 caught / 0 missed (nested-quantifier + alternation-overlap) | static cap catches catastrophic shapes | PASS |
| worst cap-passing first-hit on a ≤253-char input | 0.087 ms | ≤ 500 ms (evict ceiling 100 ms) | PASS |
| GIL demo: thread/asyncio timeout cancels a runaway `re` match? | NO — waiter forced to 186× its 1 ms deadline; match uncancellable | (confirms accept-first-hit-then-evict is the only stdlib option) | — |

The benchmark probe was corrected to feed each pattern a genuinely FAILING
adversarial input (`"a"*(DNS_MAX_LEN-1)+"!"`, which fails the final anchor and so
maximises backtracking) rather than a masking all-`a` string that the classic
shapes simply match. That correction surfaced an alternation-overlap hole: `^(a|a)+$`
(and shapes generally where a quantified group's body contains `|`) PASSED the old
static cap yet backtracked catastrophically (2 s timeout). The static cap now also
flags a quantified group whose body contains `|` (`_REGEX_ALTERNATION_OVERLAP`), so
all four catastrophic corpus shapes are caught at load.

**Decision:** GO — no reject-criterion tripped. Irreducible regex is ~0.13 µs/
pattern (budget bounds to ~400; reduction + the `important_rules` fast path keep
typical deployments far under that); the only genuinely catastrophic shapes are
nested-quantifier AND alternation-overlap patterns the cheap opt-in static cap drops
with no execution and no corpus false-negatives; the residual one-slow-first-hit is
irreducible without a subprocess/re2 (both out of scope) and is bounded by always-on
runtime warn/evict.

**Runtime safety ceilings (shipped defaults):** warn 10 ms / evict 100 ms thread-CPU
per match (`time.thread_time`, jitter-robust); opt-in static cap drops length-/
nested-quantifier-over-cap patterns at load. Both apply to feed **and** user
`pfb_regex_list`. Eviction is snapshot-iterate + evict-after-loop (thread-safe under
the GIL).

**Docs / setting finalised:** README.md gains an "Full ABP/EasyList support (ADR-07)"
section + the `spike_adr07_regex.py` benchmark note; the "Limit long/complex regex"
setting help text (`pfblockerng_dnsbl.php`) states what it drops, the always-on
runtime warn/evict, and the accepted residual risk. CLAUDE.md's `pfb_unbound.py`
note updated to mention the ABP parser.

### Follow-up / known limitation (future ADR revision — NON-BLOCKING)

The corrected ReDoS probe (above) is a reminder that the regex-safety posture rests
on two soft guarantees, NOT a hard one. This is recorded as a future safety revision,
not a blocker for ADR-07:

- **The static cap is opt-in (OFF by default).** A deployment that never enables
  "Limit long/complex regex" gets only the runtime warn/evict timer.
- **The runtime evict CANNOT cancel an in-flight match (fact 2 — uninterruptible
  `re`).** It only measures AFTER a match returns, then evicts the pattern so it
  never runs again. The FIRST catastrophic hit still runs to completion (could be
  seconds) and stalls the resolver for that one query. So with the cap OFF, the only
  protection against a never-before-seen catastrophic pattern is "eat one slow hit,
  then evict."
- **Heuristic completeness is unprovable.** The static cap is a cheap denylist of
  KNOWN catastrophic shapes (length, nested-quantifier, alternation-overlap). The
  `(a|a)+` miss shows the denylist trails the threat: a new overlap shape can slip
  through until the heuristic is broadened.

A dedicated safety revision should weigh: defaulting the cap ON, a real ReDoS
linter (or `re2`/atomic-group rewrite) over the cheap heuristic, and/or a
process-isolated matcher so an in-flight match IS killable. Out of scope here.

### Reject criteria (decide cheaply, Phase 1, before building)

- **Regex latency blows the budget:** if, at the measured irreducible-regex count, added per-query latency exceeds the agreed threshold and the reduction ratio can't bound it → do **not** ship a slow resolver path; pivot to translate-only (drop irreducible) or force the opt-in cap on by default. Recorded in the ADR.
- **Runtime eviction proves insufficient / too risky:** if Phase 1 finds real feeds carry patterns that hang long enough to matter even with warn/evict (and the opt-in cap can't catch them cheaply) → fall back to translate-only (fold reducible regex into dicts, drop irreducible) rather than ship a resolver that can stall.
- **Sovereignty/precedence cannot be matched:** if the model can't preserve user sovereignty or reproduce ABP precedence on the Phase-2 spec → STOP and reconcile before deleting the PHP lite pass.

### Manual smoke (owner: maintainer) — required before Accept

> **Gate: Status flips to Accepted ONLY after every box below passes on a live pfSense CE box.** CI cannot reach Unbound's Python loader or pf. Run after a full DNSBL update (so the manifest + regex set + counts are freshly written) and a resolver reload.

- [ ] **`@@` exception un-blocks.** A feed that blocks `||example.com^` *and* exempts `@@||sub.example.com^` resolves the exempted name while the rest of the zone stays blocked.
- [ ] **Regex.** A reducible feed regex blocks exactly its domain/wildcard equivalent; an irreducible regex blocks as written; an `@@/re/` allow un-blocks. The `DNSBL_Regex` alias count reflects admitted regex.
- [ ] **`$important` / `$badfilter`.** A feed `||x^$important` beats a feed `@@x^`; a feed `||y^$badfilter` removes a feed `||y^` (y resolves). Neither touches a user rule.
- [ ] **User sovereignty.** A whitelisted domain (settings textarea *and* alerts "add to whitelist" button) resolves regardless of any feed rule incl. `$important`; a user-blocked domain stays blocked even against a feed `@@…$important`; no feed `$badfilter` removes a user rule. TOP1M (enabled) behaves as a user allow.
- [ ] **Regex safety.** With the opt-in "Limit long/complex regex" cap ON, an over-long feed/user regex is dropped at load. A deliberately slow regex trips the runtime ceiling: a warning then an error is logged and the pattern is **evicted** (subsequent queries fast); the resolver recovers. Same behaviour for the user `pfb_regex_list`.
- [ ] **DNSBL-IP.** A feed with embedded IPs (incl. `||1.2.3.4^`) still populates `DNSBLIP_v4`/`_v6` with the configured action; no IP leaks into DNS blocking.
- [ ] **No regression.** A non-ABP feed set (plain/hosts) blocks/resolves exactly as before; `pfb_py_count` renders.
- [ ] **Reload** picks up feed, whitelist, regex-list, and setting changes correctly.
