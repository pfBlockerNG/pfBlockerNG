# ADR-06: Move DNSBL list preprocessing out of shell/PHP into the Python plugin

- **Status:** **Accepted** (2026-06-15; implemented 2026-06-01) — decision-equivalence + the init/memory kill-gate are proven (§7 build evidence), and the live block/resolve/whitelist/zone build path is exercised end-to-end by the ADR-04 `-m smoke` matrix, green on **CE 2.8 + Plus 26.03** (fanout run 27547011086). Phases 1–6 on `adr/06`. (Originally Implemented — pending live smoke, 2026-06-01.)
- **Date:** 2026-06-01
- **Branch:** `adr/06` (off **`next`** — depends on ADR-02 "Python-only DNSBL" having landed) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (new build/parse layer + load path), `pfblockerng.inc` (`tld_analysis`, the download/parse loop, `pfb_unbound_python_whitelist`), `pfblockerng.sh` (`:470-523` finalize/dedup/count), `pfblockerng_dnsbl.php` / `pfblockerng_alerts.php` (UI reads of counts; whitelist entry points — preserved).
- **Target runtime:** Python 3.11+ inside Unbound's `pythonmod`, **stdlib only**; PHP 8.3; POSIX `sh`.
- **Test suite:** `tests/test_pfb_unbound.py`, `tests/conftest.py`; new golden/equivalence fixtures under `tests/`. Benchmarks reuse `benchmarks/` (the dict baseline + corpus tooling).
- **Reference (for the *future* ABP ADR this enables — not implemented here):** AdblockPlus filter cheatsheet <https://adblockplus.org/filter-cheatsheet>; AdGuard filter syntax <https://adguard.com/kb/general/ad-filtering/create-own-filters/>; AdGuardHome adblock-style hosts-blocklist syntax <https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists#adblock-style-syntax>.

---

## 1. Context

### Today (verified on `next`, post-ADR-02)

With ADR-02, **Python is the only DNSBL mode.** The DNSBL blocklist build pipeline, however, still runs almost entirely in shell + PHP — much of it shaped by the now-removed native Unbound mode:

1. **Download + per-format parse — PHP (`inc:~7600-8248`).** Each feed is fetched, validated/cleaned per format, and accepted domains are concatenated into the master `{dnsbl_file}.raw`. This includes the **basic EasyList/ABP pass** (`:7665-7900`, `$e_replace = ['||', '.^', '^']`) that strips ABP tokens to plain domains and **ignores** exceptions (`@@`), element-hiding (`##`), options (`$third-party`…), and regex — i.e. it is *not* ABP-conformant (the feed catalog itself says it "will only utilize those domains which are listed to be blocked in full", `pfblockerng_feeds.json:1059`).
2. **Classify — PHP `tld_analysis()` (`inc:2607-2920`).** Reads the master raw, uses the public-suffix/TLD master data to split entries into **data (exact)** vs **zone (wildcard)**, and writes `pfb_py_data.raw` / `pfb_py_zone.raw` as 6-column CSV (`,domain,,log,feed,group`) plus a `dnsbl_tld_remove` exclusion list. Still carries **dead native-mode branches** — e.g. `:2672` builds "a static local-zone Resolver entry (**Not required for python mode blocking**)".
3. **Finalize — shell `pfblockerng.sh:470-523`.** `sort -u` (dedup) → `/usr/local/bin/ggrep -vF -f dnsbl_tld_remove` (TLD filter) → final `pfb_py_data.txt` / `pfb_py_zone.txt` → `grep -c` → writes `pfb_py_count` (the UI reads it at `inc:3149`).
4. **Whitelist — PHP `pfb_unbound_python_whitelist()` (`inc:2259`).** The user DNSBL whitelist (`dnsblconfig['suppression']`, editable on the settings page **and** appended via the alerts/reporting "add to whitelist" button → `pfblockerng_alerts.php:235`) is normalised (www-strip, smallest-tld-segment, wildcard flag) into `pfb_py_whitelist.txt`.
5. **Load — `pfb_unbound.py init` (`:535-639`).** Reads the CSVs into `dataDB` / `zoneDB` (6-col, key=`row[1]`, log=`row[3]`, feed=`row[4]`, group=`row[5]`), `whiteDB` (2-col `domain,wildcard`), `hstsDB`, `safeSearchDB`. **The user whitelist is applied at *query time*** (`whiteDB` checked per query in the matcher), not as a preprocessing subtraction.

### Load-bearing facts

1. **The plugin is pure-Python, stdlib-only, runs inside Unbound's resolver process** (CLAUDE.md). Any work moved here runs *in* Unbound at (re)load — there is no out-of-process buffer anymore.
2. **No live Unbound in CI** (every prior ADR). The matcher is already pinned by a pure-function pytest oracle (`tests/test_pfb_unbound.py`); the new build/parse layer must be the same shape (no Unbound symbols → unit-testable).
3. **Shell/PHP does heavy build-time list processing today** (verified live on `next`, post-ADR-02): per-feed **dedup** (`dnsbl_scrub` `:363` within-list `sort -u` + `:380` cross-list `awk` so a domain in several feeds is kept once, attributed to the *first* feed); **user-whitelist removal** (`:392` `ggrep -vF -f pfbdnsblsuppression` — strips whitelisted domains *and* subdomains); **TOP1M removal** (`:425` `ggrep -vF -f pfbalexa`, only when `dnsbl_alexa`/`filter_alexa` enabled); and **subdomain collapse** (`tld_analysis` `:2867` writes `.{registrable-parent}` → `domaintldpy` `:498` `ggrep -vF` drops data entries already covered by a parent zone). Separately — and **not** an optimisation — `tld_analysis` also does the **data/zone classification** (registrable-parent → wildcard zone; deeper label → exact data) via the public-suffix master list. The user whitelist feeds **both** the build-time removal (`pfbdnsblsuppression.txt`, `:7324`) **and** the query-time `whiteDB` (`pfb_py_whitelist.txt`, `pfb_unbound_python_whitelist`) — from the **same** `dnsblconfig['suppression']` config, so they are redundant for the net "domain resolves" outcome.
4. **The UI depends on `pfb_py_count` and the per-entry feed/group attribution** (CSV `row[4]`/`row[5]`) for alerts/stats/widget. Whoever produces the dicts must also produce these.
5. **Reload model today = restart Unbound** so `init` re-reads the files. A future ADR wants **zero-downtime reload** (rebuild dicts in-process + clear caches, no restart) — explicitly **out of scope here**, but the build path is designed to make it possible.
6. **Baseline already measured (ADR-05 §3a):** the flat dicts cost ~**274 B/entry**; this is the memory reference for the spike's kill-threshold.
7. **DNSBL feeds also feed the *firewall* (the "DNSBL IP" feature).** While parsing DNSBL feeds, PHP extracts **IP addresses embedded in the lists** (`$pfb['dnsbl_ip']` = `dnsblconfig['action']`, UI on `pfblockerng_dnsbl.php`; generic bare-IP detection at `inc:7962-7973`, CSV-format IP columns at `:7824-7833`) into `$domain_data_ip` → per-header `*_v4.ip` files (`:8035`) → aggregated into the **`DNSBLIP_v4` pf alias** with the configured action (`:8183-8212`, rules at `:8574`/`:9171`). This is a **pf/firewall operation** the Unbound Python plugin cannot and must not perform. It **must keep working**, and **belongs with the IP/firewall pipeline (PHP), not the domain parser** — distinct from the separate standalone IP-feed pipeline. The detection is a format-light `is_ipaddrv4` check, so it does not require the domain/ABP parser.
8. **Reporting reads *query-time* artifacts, not the build.** The alerts page, widget, and stats read the sqlite DBs (`resolver` / `dnsbl` / `dnsblcache`) and the log files (`dnsbl.log` / `dns_reply.log` / `unified.log`) that the plugin writes **at query time** in `operate()` / `get_details_*` — those records embed `feed` / `group` / `b_type` / `b_eval` resolved through `feedGroupIndexDB` — plus `pfb_py_count` (total loaded entries, read at `inc:3149`). `operate()` is **unchanged** by this ADR, so reporting stays correct **iff the loaded structures are identical**: `dataDB`/`zoneDB` payloads, `feedGroupIndexDB` (feed/group↔index), and each entry's log flag. The one genuinely-new surface is that **counts move to Python** and must match the format/location the UI reads.

---

## 2. Decision

Move the DNSBL preprocessing **logic** into a new **pure, stdlib-only build layer in `pfb_unbound.py`**, redraw the shell↔Python boundary to **"shell/PHP fetch + tag; Python parse → normalise → classify (data/zone) → build dicts → emit counts"**, and **drop the build-time list *optimisations* entirely** (dedup, subdomain collapse, user-whitelist removal, TOP1M removal) — Python does **not** reimplement them. Net DNS *decisions* are preserved (data/zone classification stays; user whitelist + TOP1M move to the query-time `whiteDB`), but list contents, counts, and cross-feed-duplicate attribution change by design. **This is a deliberate relaxation of the same-behaviour constraint** (see §2 contract): we do not require identical lists/counts, because **ABP support is coming next and will force a rethink of the parsing/merging/whitelisting/collapse logic anyway** — reproducing today's exact output now would be throwaway work. **Falsify-first:** the init-time/memory cost of doing this inside Unbound is proven against a kill-threshold (Phase 1) before the move is built.

| Area | Decision |
| --- | --- |
| **Boundary (Aggressive)** | Shell/PHP responsibilities shrink to: **download each feed**, attach **feed/group + a format hint**, and hand Python the **raw feed entries** (literal downloaded lines) via a manifest. **Parsing/normalisation + data/zone classification** move to Python; the build-time **optimisations** (dedup, subdomain collapse, whitelist/TOP1M removal) are **dropped, not reimplemented** (see Build layer / Whitelist rows). |
| **DNSBL-embedded IPs (the "DNSBL IP" firewall feature)** | **Stays entirely in PHP** — it is a firewall/pf concern, not DNS preprocessing. Refactor it out of the domain-parse loop into an **independent, lightweight pass** over the downloaded raw feeds: detect IP entries (`is_ipaddrv4` after minimal line-cleaning; plus the existing CSV-format IP columns like `pon`), route them to the existing `*_v4.ip` → `DNSBLIP_v4` pf-alias machinery, and **strip the bare-IP lines from what Python receives**. **Python never produces firewall input** (and would skip stray IP lines anyway — they fail domain validation). Rationale: the firewall feature must keep working independently of the Python/Unbound build, and the IP scan is format-light (no ABP/domain sophistication), so keeping it in PHP costs nothing toward the one-parser/ABP goal. (Split is uniform — "entry is an IP → firewall; else domain → Python". A few structured CSV threat-feeds, e.g. `pon`, surface the entry via a specific column rather than as a bare line; PHP already reads that column. Confirmed in Phase 1.) |
| **New contract (shell→Python)** | A manifest (e.g. `pfb_py_sources.json`/CSV) mapping each raw feed file → `{feed, group, format_hint, log_flag}`, plus the config blob Python needs (TLD blacklist/exclusion, whitelist source, TOP1M settings, log/safesearch flags). Versioned; pinned by tests. (Exact shape finalised in Phase 1 from the current feed/group attribution.) |
| **Build layer (Python)** | New pure module/functions (`pfb_dnsbl_build`-style): `parse(format, line) → entries` → `normalise` → `classify (data/zone via the public-suffix master data)` → `build dataDB/zoneDB + feed/group index + counts`. **No dedup, no subdomain collapse, no build-time whitelist/TOP1M removal** — the dict load dedups keys for free, and redundant subdomains simply stay (the parent zone still matches them). **No Unbound symbols**, stdlib only, unit-testable. **Format-pluggable**, and **entries are kind-tagged** (`block` \| `allow` \| `regex`) so the model is **ABP-ready** — but ADR-06 only produces/applies `block` and still ignores `@@`/regex/element/`$options` as today. The `allow`/`regex` kinds + their query-time application (a matcher change) are the future ABP ADR — *not here*. |
| **Counts/stats** | **Python emits** `pfb_py_count` after the build, in the format the UI reads (`inc:3149`). Its **value legitimately changes** (lists are no longer dedup/collapse/whitelist-pruned, so it goes up); the UI still gets a valid Python-produced number. Phase 1 inventories any per-feed alias counts the UI needs and where they come from. |
| **User whitelist** | **Keeps working via the query-time `whiteDB`.** Pre-ADR the user whitelist was applied *both* at build time (removal from lists) *and* query time (`whiteDB`), from the same config — so ADR-06 **drops the build-time removal** and relies on `whiteDB` alone. The settings textarea and the alerts "add to whitelist" button still drive it; its input normalisation (`pfb_unbound_python_whitelist`) moves into the Python build. Whitelisted domains now stay *in* the lists but are un-blocked at query time (net "resolves" preserved; they appear in counts/logs as whitelist hits rather than being absent). |
| **TOP1M (Alexa/Tranco) whitelist** | Pre-ADR removed popular domains from the lists at build time (`ggrep -vF -f pfbalexa`). ADR-06 drops that pass and instead, **only when the user enables it** (`dnsbl_alexa` + per-list `filter_alexa`), loads the TOP1M list into the query-time `whiteDB` so those domains are un-blocked at query time — preserving the false-positive guard with no build-time pass. (When disabled, nothing changes.) |
| **Reentrancy (zero-downtime-ready)** | The build is a pure `(sources, config) → new structure-set` function that mutates nothing global until an atomic swap at the end — so a future ADR can run it on a background thread and swap without an Unbound restart. The swap itself is **not** built here. |
| **Dead/dropped code** | Delete the build-time list processing being dropped: `dnsbl_scrub` (dedup + user-whitelist + TOP1M removal), `domaintldpy` (dedup + collapse), `tld_analysis`'s **collapse/remove-file** logic, the basic-ABP `$e_replace` PHP pass, and native-mode leftovers (`:2672`). **Keep** `tld_analysis`'s **data/zone classification** (moved into the Python build) and the public-suffix master data (now a Python build input). |

### Semantics that MUST be preserved (the contract — pin with golden tests *before* moving)

The contract is at the level of **net DNS decisions**, **not** list contents. This is a **deliberate relaxation of the same-behaviour constraint**: ADR-06 does **not** require identical `dataDB`/`zoneDB` contents, `pfb_py_count` values, or cross-feed-duplicate attribution — those change by design (lists are no longer dedup/collapse/whitelist-pruned). The relaxation is justified because **ABP support is coming next and will force us to rethink the parsing, merging, whitelisting, and collapse logic anyway** — so reproducing today's exact list contents/counts here would be throwaway work. What must stay invariant is every **block/resolve decision**.

- **Identical block/resolve decisions.** For a representative query set against fixed raw feeds + config, every outcome (block shape / resolve / whitelist / HSTS / noAAAA / zone-subdomain) is identical old-pipeline vs new: a blocked non-whitelisted domain stays blocked; a whitelisted (or TOP1M-when-enabled) domain resolves via `whiteDB`; a subdomain of a zone entry stays blocked. This is the golden oracle — at the *decision* level.
- **Data/zone classification unchanged** (registrable-parent → wildcard zone; deeper label → exact data), so zone wildcard coverage, exact matches, TLD-blacklist (whole-TLD block) and TLD-exclusion behave as today.
- **User whitelist** (settings textarea or alerts "add to whitelist" button) still un-blocks via query-time `whiteDB`, wildcard semantics intact. **TOP1M**, when enabled, still un-blocks popular domains (now via `whiteDB`).
- **Feed/group + log attribution** per blocked domain still flows to the query-time log lines + sqlite rows (`operate()` untouched) — **except** a domain present in multiple feeds, now attributed *last-wins* (dict) instead of *first-feed*; per-feed counts for such duplicates change accordingly.
- **`pfb_py_count`** stays Python-emitted in the format the UI reads; its **value legitimately increases** (lists un-pruned) — expected, not a regression.
- **DNSBL-embedded IPs** still populate the **`DNSBLIP_v4` pf alias** with the configured action (the "DNSBL IP" feature, fact 7) — same IP set, same alias, same rules.

### Explicitly kept / out of scope

- **Future ABP/AdGuard support is DNS-level only** (future ADR; this one only leaves the pluggable parser seam, references in the header). When it lands, only **domain-name semantics** matter: whole-domain block rules, **domain `@@` exceptions**, and **domain-targeting regexes**. **Element-hiding (`##`/`#@#`), path/URL-specific rules, and non-domain `$options` are IGNORED** — a path or element being blocked/allowed does **not** imply DNS-level block/allow for the domain. ADR-06 ships the **ABP-ready seam** — a kind-tagged entry model (`block`/`allow`/`regex`) — but emits only `block` entries and still discards `@@`/element/path/`$options`/regex lines exactly as today; the ABP ADR adds the `allow`/`regex` kinds and their query-time application.
- **DNSBL-embedded-IP extraction (the "DNSBL IP" feature, fact 7) is PRESERVED — in scope.** Distinct from the **standalone IP-feed pipeline (out of scope)**: this ADR keeps DNSBL feeds populating the `DNSBLIP_v4` pf alias; pf-alias creation stays in PHP.
- **Zero-downtime / restart-free reload** — future ADR; designed-for (reentrant build) but not implemented.
- **GeoIP/ASN/MaxMind, SafeSearch redirection logic** — unchanged (SafeSearch file format untouched beyond reading).
- **The matcher itself** (ADR-01/-05 dicts) — unchanged; this ADR feeds it, doesn't restructure it.
- **The download mechanism, feed catalog (`feeds.json`), scheduling, auth/headers** — stay in PHP (network belongs out of the resolver).

---

## 3. Consequences

**Positive**

- One parser, in Python, next to the matcher and `whiteDB` — the **prerequisite** for conformant ABP support (the stated future goal) instead of logic split across `sh`/PHP/Python.
- **Deletes a large amount of fragile shell/PHP** — `dnsbl_scrub`, `domaintldpy`, and `tld_analysis`'s collapse machinery (`awk`/`ggrep`/`sort` pipelines) — rather than porting it. ABP will rework whitelisting/collapse anyway, so this is effort saved, not lost.
- Parsing + classification become **pure, unit-tested** functions (no live Unbound needed).
- Reentrant build is the seam a future **zero-downtime reload** needs.

**Negative / risks**

- **Init cost moves into Unbound (highest risk), now on *larger* lists.** Dropping dedup/collapse/whitelist-pruning means Python loads more entries → more parse/build work + peak RAM in the resolver at (re)load. **Mitigated by the Phase-1 spike + explicit kill-threshold**, measured on the *un-pruned* corpus.
- **Behaviour changes by design (not a silent regression).** List contents, `pfb_py_count`, and cross-feed-duplicate feed/group attribution all change; whitelisted/TOP1M domains now stay in the lists and are un-blocked at query time (so they appear in counts/logs). **Net DNS decisions are preserved** — pinned by the decision-level golden oracle. Accepted because ABP reworks this surface.
- **Safety-critical path.** It is the DNS *blocking* pipeline; the oracle compares **block/resolve decisions** old-vs-new before any deletion.
- **Large surface across 4 languages/files.** Mitigated by incremental phases and deleting shell/PHP only after the Python path is proven decision-equivalent.

---

## 4. Requirements (acceptance)

1. **Decision-equivalent:** golden tests prove identical **block/resolve decisions** (block shape / resolve / whitelist / HSTS / noAAAA / zone-subdomain) old pipeline vs new across hosts/plain/basic-ABP formats — *not* identical list contents/counts (those change by design).
2. **Within budget:** Python `init` building from the *un-pruned* raw feeds meets the Phase-1 init-time + peak-memory kill-threshold for a large (≥1M-entry) corpus.
3. **Whitelist intact:** settings-textarea and alerts-button whitelist entries still un-block via query-time `whiteDB`, wildcard intact; TOP1M (when enabled) still un-blocks popular domains via `whiteDB`.
4. **UI intact:** alerts/stats/widget render correctly off the Python-emitted `pfb_py_count` and the (unchanged) query-time logs/DBs; counts legitimately differ in value (un-pruned).
5. **DNSBL IP feature intact:** IPs embedded in DNSBL feeds still produce the same `DNSBLIP_v4` pf alias + rules with the configured action.
6. **Default suite green:** `python -m pytest`, `ruff`, `php -l`, ShellCheck all clean; no new shipped deps (stdlib only in the plugin).

---

## 5. Constraints (from `CLAUDE.md`)

- **Plugin: stdlib only, Python 3.11+**, 4-space, type hints on new fns, no bare `except`, `from __future__ import annotations`. New build/parse code must depend on **no Unbound symbol** (unit-testable like the matcher); any new injected symbol → `stubs/python/unboundmodule.py`.
- **PHP:** tabs, 8.3, no `die()`/`exit()` in library code, pfSense fns via stubs.
- **Shell:** POSIX `sh`, quoted, absolute binary paths, ShellCheck-clean.
- Run `python -m pytest` after any `pfb_unbound.py`/`tests/` change; `ruff check .`/`ruff format .` clean each commit.
- Commit style `<scope>: <imperative summary>`; **work inline on `adr/06`, one commit per phase, push directly** (PR only if rejected). PR bodies via `--body-file`.
- **Docs:** README/CLAUDE.md updated if the build/contract or test commands change (Phase 6).

---

## 6. Action plan

Each phase = one commit, leaves `python -m pytest` green, and **preserves net DNS decisions** (not list contents). The **de-risking spike is front-loaded (Phase 1)** and the **decision-level golden oracle (Phase 2)** is laid down before any logic moves — both retain standalone value even if the boundary is later trimmed.

### Phase 1 — Inventory the contract + spike & kill-gate (init-time/memory budget)

Prompt: `01_Inventory_Spike.txt`

- **Inventory** the exact current data flow + file formats: master `{dnsbl_file}.raw` line shape, how feed/group/log is attached, what `tld_analysis` classifies, the shell dedup/filter/count, build-time removals (TLD-exclusion, TOP1M) vs query-time `whiteDB`, the Python loader format, **and what the reporting page (alerts/widget/stats) reads and from where** (`pfb_py_count`, the sqlite tables, the log files, any per-feed counts). Confirm the **one raw file ↔ one feed/group/log** assumption the per-file manifest relies on (else keep per-line tags). Write it down as the **contract to preserve**.
- **Spike (out-of-tree/standalone):** a pure-Python prototype that parses a large representative raw corpus (reuse `benchmarks/_corpus.py`; target ≥1M entries) → builds data/zone/white dicts + counts, and **measures init time + peak RAM** vs today (dict baseline ~274 B/entry, ADR-05 §3a).
- **Gate:** record GO/NO-GO vs the kill-threshold (propose: added reload time ≤ a few seconds and peak RAM not materially worse than today — tune with maintainer). Miss → STOP; record pivot (keep heavy work in shell, or fall back to Moderate/Conservative boundary).

### Phase 2 — Golden oracle harness (pin current behaviour)

Prompt: `02_Golden_Oracle.txt`

- Capture the **current pipeline's block/resolve decisions** for a representative query set against representative raw feeds + config (hosts, plain-domain, basic-ABP; incl. whitelisted, TOP1M-when-enabled, and zone-subdomain queries) as **golden fixtures** under `tests/`. The oracle asserts **decisions** (block shape / resolve / whitelist / HSTS / noAAAA), **not** identical list contents/counts — those change by design. Pure Python, CI-runnable (no live Unbound).
- This is the oracle every later phase diffs against; standalone-valuable (kept even if the move is trimmed).

### Phase 3 — Pure `pfb_dnsbl_build` module (not yet wired)

Prompt: `03_Build_Module.txt`

- New stdlib-only, Unbound-symbol-free functions: `parse(format,line)` (format-pluggable; subsumes the current basic-ABP token-strip), `normalise`, `classify` (data vs zone via the public-suffix data), `build` → dicts + feed/group index + counts. **No dedup, no subdomain collapse, no build-time whitelist/TOP1M removal** (dict load dedups keys; redundant subdomains stay). Reentrant (returns a new structure-set; no global mutation).
- **Whitelisting is query-time:** the user whitelist loads into `whiteDB` (input normalisation moves here); the TOP1M list loads into `whiteDB` **only when enabled**. No build-time list pruning.
- **Entries are kind-tagged** (`block` | `allow` | `regex`) so the model is ABP-ready, but this phase **only produces `block`** and keeps ignoring `@@`/regex/element/`$options`. Shape the type now, don't populate `allow`/`regex` (the ABP ADR does).
- Unit-test every function against the Phase-2 decision oracle.

### Phase 4 — Wire `init` to build from raw + emit counts

Prompt: `04_Init_From_Raw.txt`

- `pfb_unbound.py init` consumes the new manifest + raw feeds via the Phase-3 build, producing decision-equivalent structures, loads `whiteDB` (user whitelist + TOP1M-when-enabled), and **writes `pfb_py_count`** for the UI (value changes — un-pruned). Python **ignores** any stray IP lines and **never** touches the firewall/IP path.
- Decision-equivalent to the old load (Phase-2 oracle). The build call site is the future zero-downtime swap point.

### Phase 5 — Slim shell/PHP; delete dead native logic

Prompt: `05_Slim_Shell_PHP.txt`

- PHP/shell now **download + tag feed/group + write the manifest/raw**, and run the **independent DNSBL-IP pass** (detect IPs → `*_v4.ip` → `DNSBLIP_v4`, strip bare-IP lines from Python's input). **Delete** `dnsbl_scrub` (dedup + user-whitelist + TOP1M removal), `domaintldpy` (dedup + collapse), `tld_analysis`'s **collapse/remove-file** logic, the PHP basic-ABP `$e_replace` pass, and native-mode leftovers (`:2672` etc.). **Keep** the data/zone **classification** (now in Python) and the DNSBL-IP → pf-alias path (PHP). UI reads Python-emitted counts.
- Decision-preserving for observable DNS output (Phase-2 oracle + `php -l`/ShellCheck).

### Phase 6 — Validation, manual smoke, DoD

Prompt: `06_Validation_DoD.txt`

- Full golden equivalence across formats incl. basic-ABP; re-run the Phase-1 init/mem benchmark on `adr/06` and record vs threshold; finalise README/CLAUDE.md.
- **Manual smoke (live box):** whitelist via settings textarea AND alerts button still un-blocks; counts/alerts/feed-group match; reload works.

---

## 7. Definition of done

- `python -m pytest` green incl. new golden/equivalence + build-module unit tests; `ruff` clean; `php -l` + ShellCheck clean.
- Python build-from-raw is **decision-equivalent** to the current pipeline (block/resolve, whitelist incl. TOP1M-when-enabled), and **meets the Phase-1 init/memory kill-threshold** on the *un-pruned* ≥1M-entry corpus.
- shell/PHP reduced to download+tag (+ the DNSBL-IP pass); `dnsbl_scrub`/`domaintldpy`/`tld_analysis`-collapse deleted; data/zone classification + whitelisting now in Python; counts Python-emitted.
- The build is a pure reentrant function (zero-downtime-ready) and the parser is format-pluggable (ABP-ready) — neither feature implemented here.
- Status → **Accepted** only after the manual smoke (below) passes on a live pfSense box.

### Build evidence (Phase 6, recorded on `adr/06`)

**Decision-equivalence — PASS.** Golden + build unit tests pin identical
block/resolve/whitelist/HSTS/noAAAA/zone-subdomain decisions across **all** formats:

- `tests/test_adr06_golden_oracle.py` — reference preprocessor → **production**
  `pfb_unbound.evaluate_domain`/`evaluate_noaaaa` over the golden query set, both
  TOP1M-disabled and TOP1M-enabled scenarios; the firewall-IP extraction set is
  asserted (`GOLDEN_EXTRACTED_IPS`) and confirmed absent from the block lists.
  Fixtures exercise **hosts / plain / basic-ABP / csv:pon** (`tests/fixtures/adr06_golden/`).
- `tests/test_adr06_build_module.py` — the pure `parse`/`normalise`/`classify`/`build`
  layer unit by unit.
- `tests/test_adr06_init_from_raw.py` — the **production** `dnsbl_build_from_manifest`
  over an on-box-shaped manifest, asserted decision-equal to **both** the golden map
  **and** the reference pipeline (parametrised over both TOP1M scenarios), plus
  feed/group attribution, the no-IP-leak invariant, and `dnsbl_emit_count` writing
  the loaded-entry total to `pfb_py_count`.
- `tests/test_adr06_php_boundary.py` — the shipped PHP "clean → emit as `plain`"
  boundary, round-tripped through the production build, decision-equal with no IP leak.

Full suite: **`python -m pytest` → 255 passed**; `ruff check .` / `ruff format --check .`
clean; `php -l` + ShellCheck clean (Phase 5).

**Init/memory kill-gate — GO (PASS, comfortable headroom).** Re-measured on `adr/06`
at the agreed ≥1M-entry un-pruned corpus (CPython 3.14, macOS dev box; threshold
build ≤ 8 s AND retained ≤ 410 B/entry vs the 274 B/entry ADR-05 §3a baseline):

| build path | size | build wall-time (median, N≥5) | peak RAM | retained B/entry | verdict |
| --- | --- | --- | --- | --- | --- |
| production `dnsbl_build_from_manifest` | 1,000,000 | **2.28 s** (max 2.33) | 141.5 MiB | 281.5 (+3%) | **PASS** |
| production `dnsbl_build_from_manifest` | 2,000,000 | **4.39 s** (max 4.43) | 266.8 MiB | 284.7 (+4%) | **PASS** |
| Phase-1 spike prototype | 1,000,000 | 1.47 s | 193.8 MiB¹ | 274.9 (+0%) | PASS |

Time is linear (~2.2 µs/raw-line); even 2M — the RESULTS/01 residual-risk size — is
4.4 s, well under the cap. Memory is at baseline parity (the trie was never the lever).
**Measurement note:** wall-time must be timed with `tracemalloc` **off** — instrumenting
every allocation inflates the build ~3–4×. The committed spike (`spike_adr06_build.py`)
and RESULTS/01 report the *instrumented* figure (5.3 s / 1M; 10.9 s / 2M); the
un-instrumented production figures above are the real init cost and the ones this gate
is decided on. ¹Spike peak RAM is higher because it materialises the full line list;
the production build streams feeds lazily (`_dnsbl_file_line_reader`), so its peak is
the dict floor.

### Reject criteria (decide cheaply, Phase 1, before the move)

- **Init/memory blows the budget:** if building from raw inside Unbound exceeds the agreed reload-time/peak-RAM threshold on a large corpus and cannot be brought under it (streaming/iterative build) → do **not** ship a slow reload; fall back to the Moderate/Conservative boundary (keep dedup/classify in shell/PHP) or keep it as-is. Recorded in the ADR. **Outcome (Phase 6): NOT triggered** — the production build is 2.28 s / 1M (4.39 s / 2M), well under the 8 s cap, and 281.5 B/entry, well under the 410 B/entry ceiling. The streaming reader already gives the dict-floor peak RAM, so no boundary pivot is needed. (If a *future* deployment's raw line count is so large that the linear build pushes reload time past the maintainer's tolerance, the documented fallback remains: move dedup/classify back to shell/PHP, or stage the build off-thread per the reentrant seam.)
- **Behaviour cannot be matched:** if the Python build cannot reproduce the current pipeline's decisions/attribution for some format → STOP and reconcile before deleting any shell/PHP. **Outcome (Phase 6): NOT triggered** — decisions are pinned identical across hosts/plain/basic-ABP/csv:pon (see Build evidence). Two *intended* behaviour changes are accepted by design (not regressions): cross-feed-duplicate attribution is now **last-wins** (was first-feed), and the TOP1M whitelist is a single **global** query-time `whiteDB` toggle (the old per-list `filter_alexa` build-time prune cannot be expressed query-time, so with TOP1M enabled popular domains are un-blocked across *all* lists). Both are called out in the smoke checklist below.

### Manual smoke (owner: maintainer) — required before Accept

> **Gate: Status flips to Accepted ONLY after every box below passes on a live
> pfSense CE box.** CI cannot reach Unbound's Python loader or pf, so these are the
> checks no automated test covers. Run after a full DNSBL update (so the manifest
> `/var/unbound/pfb_py_sources.json` + `/var/unbound/pfb_py_raw/` and `pfb_py_count`
> are freshly written) and a resolver reload.

- [ ] **Block decisions unchanged** for a known feed set: an exact (data) block, a
  wildcard/zone block *and a sub-domain of it*, an HSTS entry, and a noAAAA entry all
  behave as before. A non-listed domain resolves.
- [ ] **Whitelist — both entry points.** A domain whitelisted via the **settings
  textarea** resolves normally; so does one added via the **alerts "add to whitelist"
  button** (after the reload it triggers). Confirm a **wildcard** whitelist
  (leading-dot) un-blocks sub-domains too. The domain now stays *in* the list and
  shows as a whitelist hit (not absent) — expected.
- [ ] **Counts/UI.** Alerts, stats widget, and per-alias counts render. `pfb_py_count`
  (`/var/unbound/pfb_py_count`) is the **loaded-entry total** and may be **higher**
  than the old value — expected (lists are no longer dedup/collapse/whitelist/TOP1M
  pruned). No "OUT OF SYNC" log line; the update log shows `[ feed lines: N | loaded
  entries: M ]`.
- [ ] **TLD blacklist** (whole-TLD block) and **TLD exclusion** (forced exact) behave
  as before. With **TOP1M enabled**, a popular domain present in a feed resolves
  (un-blocked via `whiteDB`); with it **disabled**, the same domain blocks. **Note the
  accepted change:** TOP1M is now **global** — when enabled it un-blocks popular
  domains across *all* lists, not only the lists that had per-list `filter_alexa`.
- [ ] **DNSBL-IP firewall feature.** A DNSBL feed containing embedded IPs still
  populates the `DNSBLIP_v4` pf alias (with the configured action) and the firewall
  rule references it. The IP set is unchanged and no IP leaks into DNS blocking.
- [ ] **Reload** picks up both feed changes and whitelist changes correctly.
- [ ] **Retained CSV consumers (RESULTS/05 §5).** The alerts-page features that still
  read `pfb_py_data`/`pfb_py_zone` work: "add domain to group", "add to whitelist",
  and unlock/detail. (These PHP-produced CSVs are intentionally kept this ADR;
  migrating them onto the manifest/sqlite is a future follow-up.)
- [ ] **Cross-feed duplicate attribution** is now **last-wins** (a domain in several
  feeds is attributed to the last feed loaded, was first). Spot-check that a known
  duplicated domain's reported feed/group is sane — its per-feed count shifting is
  expected, not a regression.

## 8. Post-merge amendments (2026-07-14 — ADR-65)

Sections above stay as written for the record; **this section is the authoritative
correction.** ADR-65 made the manifest the single source of truth for DNSBL and retired
the `pfb_py_data.txt`/`pfb_py_zone.txt` interchange files this ADR introduced, end to end:

- **The interchange files are gone, not merely deprioritized.** Their writers — the
  `tld_analysis` TLD-classification pass and `pfb_dnsbl_py_swap` — are removed; no build
  produces these files anymore. This dissolves issues **#1244** (unchecked finalize
  rename logging "completed" regardless) and **#1245** (a failed publish leaving a stale
  TLD-origin `pfb_py_zone` in place) — the code both issues describe no longer exists.
- **The legacy fallback loaders are removed, not merely bypassed.** §4's "the legacy
  data/zone CSV load … FALLBACK … used only when no manifest is present" no longer holds:
  a manifest that cannot build now leaves the DNSBL structures **empty** and fails loud —
  the ADR-61 ledger plus a `file_notice` so the dashboard bell fires — never a silent
  stale-serve from the retired files. §7's "Retained CSV consumers (RESULTS/05 §5)" row
  is superseded the same way: migrating those alerts-page features off the CSVs is no
  longer a *future* follow-up, it already happened, because the CSVs they read no longer
  exist.
- **Alerts/Reports DNSBL rows are log-driven, not re-checked.** The render-time
  freshness re-check this ADR's `pfb_dnsbl_parse()` performed for the Alerts page is
  retired from that render path; each row shows exactly what `dnsbl.log` logged for it at
  block time. `pfb_dnsbl_parse()` itself stays defined (unreachable from the render path)
  pending a separate retirement pass.
- **Webserver-hit (block-page) attribution asks the live matcher, not a grep.** Where
  this ADR's `pfb_dnsbl_parse('daemon', …)` grepped the interchange files, the widget
  counter and `dnsbl.log` line for a block-page hit are now sourced from the read-only
  query channel `pfb_py_query` / `pfb_dnsbl_query()` ADR-65 added — the same decision
  engine the resolver itself uses, so a webserver hit gets byte-identical attribution to
  a real DNS block instead of a classified-subset approximation.

Full design, delta table, and semantics: `.ADRs/ADR_65_DNSBL_Manifest_Single_Source/ADR.md`.
