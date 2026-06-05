# ADR-08: Cross-script IDN homoglyph protection for DNSBL (TR39 mixed-script)

- **Status:** **Implemented — pending live smoke** (2026-06-05; authored 2026-06-02). All seven phases landed on `adr/08-homoglyph-protection`; the suite + FP/TP gate are green on-branch (§7 *Build evidence*). Status flips to **Accepted** only after the maintainer runs the live-box manual smoke below (CI cannot reach Unbound's Python loader).
- **Date:** 2026-06-02
- **Branch:** `adr/08-homoglyph-protection` (off `devel`; `next` retired) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (new punycode-decode + script analyzer + the matcher's IDN branch), `pfblockerng.inc` (`python_idn` config plumbing, `DNSBL_IDN` alias/count), `src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php` (the `pfb_idn` mode selector + help), a new **shipped Unicode data table** + its generator under `scripts/`.
- **Target runtime:** Python 3.11+ inside Unbound's `pythonmod`, **stdlib only** (the `'punycode'` codec decodes; the TR39 Scripts/Script_Extensions tables ship as **data**, not a dependency); PHP 8.3; POSIX `sh`.
- **Test suite:** `tests/test_pfb_unbound.py`, `tests/conftest.py`; new `tests/test_adr08_*` (the TR39 decision spec/oracle, the punycode+script analyzer, the matcher wiring, the FP/TP corpus).
- **References (the rule this enforces):** ICANN *Guidelines for the Implementation of Internationalized Domain Names, **Version 4.1*** (2022-09-22) <https://www.icann.org/en/system/files/files/idn-guidelines-22sep22-en.pdf>; EURid IDN policy <https://eurid.eu/en/knowledge-centre/domain-names-with-special-characters-idns/>; Unicode **UTS#39** Security Mechanisms (Restriction-Level Detection) <https://www.unicode.org/reports/tr39/>; ICANN SSAC IDN Homographs <https://itp.cdn.icann.org/en/files/meetings/presentation-ssac-idn-homograph-22oct18-en.pdf>.

---

## 1. Context

### Today (verified on `next`)

pfBlockerNG already has an "IDN Blocking" feature, and it is a **sledgehammer**:

1. **Toggle:** `pfb_idn` (UI `pfblockerng_dnsbl.php:2388-2393`, on/off) → written into the plugin's python config as `python_idn` (`pfblockerng.inc:2540-2599`) → `pfb["python_idn"]` (`pfb_unbound.py:417`).
2. **Detection:** `is_idn_domain(q_name)` = `q_name.startswith("xn--") or ".xn--" in q_name` (`pfb_unbound.py:755`) — a pure prefix match; **the plugin never decodes punycode.**
3. **Action:** at `evaluate_domain` (`pfb_unbound.py:2307-2310`), when `python_idn` is on and the name is IDN, it is **blocked** (`feed="IDN"`, `group="DNSBL_IDN"`), after the dict/zone/regex checks and before the whitelist. The `DNSBL_IDN` alias/count is maintained in PHP (`pfblockerng.inc:8305-8308`).
4. **UI help, verbatim:** *"This will block **all** IDN's and domains that include 'xn--'."* So today's feature blocks **every** internationalized domain — legitimate Chinese/Japanese/Arabic/Cyrillic sites included — which is why it is an opt-in most deployments leave **off**.

Separately, **PHP already handles punycode both ways**: `idn_to_ascii()` normalizes IDN *input* to punycode throughout (`pfblockerng.inc:1131/1136/1146/1151`, `:8133`, category-edit, ASN), and `idn_to_utf8()` decodes punycode → Unicode for **alert display** (`pfblockerng_alerts.php:2234/2247/2256`, e.g. `domain [münchen]`). The **Python matcher has no decode** — it only prefix-matches `xn--`.

### The problem

Block-all-IDN is too blunt to leave on, so the genuinely dangerous case — **homograph/homoglyph phishing**, where a name uses confusable characters from another script to impersonate a Latin-alphabet brand (`xn--pple-43d` = `аpple` with Cyrillic `а`) — is either unprotected (feature off) or drowned in false positives (feature on, every legit IDN blocked). The surgical fix: block/flag only the **deceptive cross-script** names, not all IDNs.

### Premise — VERIFIED (not a falsify-first guess; still corpus-checked in Phase 1)

The core claim — *mixing scripts in one label is illegitimate* — is confirmed across the authorities, **with one load-bearing nuance**:

- **ICANN IDN Guidelines v4.1:** *"All code points in a single label will be taken from the same script (UAX#24)."* Exceptions only for *"languages with established orthographies… that require the commingled use of multiple scripts,"* and *"visually confusable characters from different scripts will not be allowed to co-exist… unless a corresponding policy and character table is clearly defined."*
- **EURid (.eu):** *"you cannot combine characters from different scripts. All the characters… at the second level must come from the same script."* (digits/hyphen exempt; name script must match TLD).
- **Unicode UTS#39 Restriction Levels:** *Highly Restrictive* = single script **OR Latin + CJK** (`Han+Hiragana+Katakana`, `Han+Hangul`, `Han+Bopomofo`) — **these Latin+CJK mixes are legitimate**; *Moderately Restrictive* allows Latin + one other script **but explicitly excludes Cyrillic and Greek**.

**The nuance that makes or breaks the feature:** "any script mixing ⇒ block" would **false-positive on legitimate Japanese/Korean/Chinese domains**. The safe, ~zero-FP signal is **two or more *mutually-confusable* scripts co-occurring in one label — `Latin+Cyrillic`, `Latin+Greek`, *and* `Cyrillic+Greek`** (the trio that share look-alike letters; candidate additions Cherokee/Armenian/Coptic). No legitimate orthography mixes any pair of these, and all three authorities condemn it. So the malicious tier is decided by the **resolved script set alone (Scripts + Script_Extensions tables) — no confusables table required.**

### Load-bearing facts

1. **Query names reach the matcher as punycode ASCII** (`xn--…`, the DNS wire form). Script analysis is impossible on the A-label; the label **must be decoded to Unicode first**. stdlib does this with the raw `'punycode'` codec (`label[4:].encode("ascii").decode("punycode")`) — **per-label, no dependency**. Use the raw codec, **not** the higher-level `'idna'` codec (which adds IDNA2003 validation that *throws* on perfectly-analyzable attack labels). Decode failures are caught and flagged, never crash the resolver.
2. **`unicodedata` (stdlib) has no Script or Script_Extensions property and no confusables map.** So the TR39 **Scripts + Script_Extensions** tables ship as **shipped data** (compact range tables under `src/`, in the release archive — unlike dev-only stubs), generated by a pinned-Unicode-version tool. No confusables table is shipped (the script-set signal doesn't need it).
3. **No live Unbound in CI** (every prior ADR). The analyzer is a pure, Unbound-symbol-free function (decode → script set → restriction level → severity), unit-testable like the matcher; the FP/TP corpus is plain pytest.
4. **Cost is bounded to IDN queries.** The analyzer only runs when `is_idn_domain` is true (an `xn--` label is present) — a small fraction of traffic. Non-IDN queries pay nothing; the matcher fast path is unchanged.
5. **Registry rules ≠ resolver reality.** Registries block second-level script-mixing, but the resolver still sees mixed-script attacks via **attacker-controlled subdomains** (`раypal.example.com` — no registry validates subdomains), lax ccTLDs, and old registrations. Resolver-level detection adds value beyond registration policy.
6. **Backward compatibility:** `pfb_idn` is today an on/off toggle; existing configs carry `'on'`/`''`. The mode selector must map `'on'` → **All-IDN** (today's exact behaviour) and empty/off → **Off**, adding **Confusable** as the new value.
7. **Homoglyph analysis is per-label, never whole-name.** A name is judged label-by-label (the dot-separated parts): a label is suspect only if *it alone* mixes confusable scripts — e.g. `аpple` is Latin+Cyrillic *within one label*. Pooling all of a name's letters across the dots would falsely flag ordinary domains under foreign-script country TLDs — `site.中国` (Latin `site` + Han TLD label) or `example.рф` (Latin SLD + Cyrillic `.рф` TLD label) are **legitimate**, yet a whole-name union reads them as "Latin + Han/Cyrillic". So the resolved-script-set rule (§2) is computed **per label**, and a name is malicious iff *some* label is — which also correctly catches subdomain homographs (`раypal.example.com`, fact 5). This is the single largest false-positive class, eliminated by construction.

---

## 2. Decision

Turn the blunt block-all-IDN toggle into a **mode selector** and add a **TR39 mixed-script analyzer** that decodes each `xn--` label and classifies it by **resolved script set**, with a **two-tier action policy**: cross-script **confusable** mixes (Latin + Cyrillic/Greek-class) are **clearly malicious → blocked by default**; other non-restrictive mixes are **suspicious → alerted (block opt-in)**; legitimate single-script and Latin+CJK names are **untouched**. Scope is **cross-script IDN only**; pure-ASCII typosquats and whole-script confusables are explicit non-goals (they need a protected-brand set, deliberately not built here).

| Area | Decision |
| --- | --- |
| **Feature shape (mode selector)** | `pfb_idn` becomes **Off \| All-IDN \| Confusable**. **Off** and **All-IDN** preserve today's exact behaviour (`'on'` migrates to All-IDN, fact 6). **Confusable** (new) runs the analyzer. One backward-compatible feature, not a second toggle. |
| **Punycode decode (new, in-matcher)** | Decode each `xn--` label with the stdlib raw `'punycode'` codec, per-label, failures caught → flagged (never crash). Only on `is_idn_domain` queries (fact 4). The decoded Unicode + the offending codepoint(s) are logged (mirrors the alerts page's existing `idn_to_utf8` display). |
| **Detection (TR39 mixed-script)** | Pure analyzer: decoded label → per-codepoint script via the shipped **Scripts + Script_Extensions** tables → **resolved script set** (Common/Inherited transparent) → **restriction level** (UTS#39). **No confusables table.** |
| **Analysis granularity (per-label)** | Analyze **each label independently** (its own resolved script set); a label is flagged only if *it* mixes confusable scripts. **Never union scripts across the dot** — else a legit ASCII/Latin SLD under an **IDN ccTLD** (`example.рф`, `site.中国`) would falsely read as Latin+Cyrillic/Han. Analyze **all** labels (catches subdomain homographs, fact 5); a legit IDN-ccTLD label is single-script and passes. |
| **Tier — malicious (default block)** | Resolved set contains **≥2 of the mutually-confusable scripts {Latin, Cyrillic, Greek}** — i.e. **`Latin+Cyrillic`, `Latin+Greek`, OR `Cyrillic+Greek`** (candidate additions Cherokee/Armenian/Coptic — finalised in Phase 1 from the FP corpus). No legit orthography mixes any pair (ICANN/EURid/UTS#39 all condemn it). **Blocked by default** via a sub-toggle that is **default-on** (user can disable). |
| **Tier — suspicious (alert, block opt-in)** | Fails *Highly Restrictive* but isn't the malicious pair (e.g. other unusual multi-script combos). **Alerted/logged without breaking resolution**; an opt-in sub-toggle escalates suspicious → block. |
| **Legitimate (no action)** | Single-script (incl. all-Latin, all-Cyrillic, all-Greek), **Latin + CJK** (`Jpan`/`Kore`/`Hanb` per *Highly Restrictive*), and Common-only mixes (digits/hyphen). These must never be touched in Confusable mode. |
| **Attribution / counts** | A blocked homoglyph reports a distinct feed/group (e.g. `DNSBL_Homoglyph`); a suspicious alert its own (`DNSBL_Homoglyph_Suspect`). The `DNSBL_IDN` alias/count machinery (`pfblockerng.inc:8305`) is reused/extended; All-IDN mode keeps `DNSBL_IDN` exactly as today. |
| **Data + generator** | Ship `Scripts.txt` + `ScriptExtensions.txt`-derived **compact range tables** (binary-searchable, ~tens of KB) under the package dir; a `scripts/update-unicode-data.py` generator downloads a **pinned Unicode version** and emits them (pattern: `update-pfsense-stubs.py`). Document the version + update step in README/CLAUDE.md. |

### Semantics that MUST be preserved (the contract — pin with tests *before* changing the matcher)

- **Off and All-IDN are byte-identical to today.** Off → no IDN action; All-IDN → every `xn--` query blocked with `feed="IDN"`/`group="DNSBL_IDN"` exactly as `pfb_unbound.py:2307` does now. Migrating `pfb_idn='on'` → All-IDN changes nothing observable. Pinned by a golden before the mode plumbing lands.
- **Non-IDN queries are unaffected** in every mode — no `xn--` ⇒ no decode, no script work; the matcher fast path is unchanged.
- **No legitimate IDN is blocked in Confusable mode** — single-script and Latin+CJK resolve; the malicious tier fires only on confusable cross-script mixes. This is the FP (false-positive) contract, pinned by the Phase-1 corpus + the Phase-2 oracle.
- **Per-label, never cross-label union.** A legit ASCII/Latin SLD under an IDN ccTLD (`example.рф`, `site.中国`) resolves; only a single label that *itself* mixes confusable scripts is flagged. This prevents the largest FP class (ASCII/Latin domains under IDN ccTLDs).
- **The resolver never crashes on a malformed `xn--` label** — a punycode decode error is caught and the label flagged/skipped, not raised.
- **Whitelist still wins** — a user-whitelisted domain that happens to be a homoglyph still resolves (the analyzer feeds `is_found`; the existing whiteDB override applies after, unchanged).

### Explicitly kept / out of scope

- **Pure-ASCII typosquats** (`g00gle`, `1` vs `l`, `rn` vs `m`) — **out.** Single-script, no `xn--`; detecting them needs a protected-brand set + per-query skeleton on *all* queries (heavier, FP-prone). A feed or a future ADR. (If revisited, the protected set has a reputable source — the research-grade **Tranco** top-sites list, which pfBlockerNG **already ingests as the TOP1M whitelist**; the blockers are per-query-on-all-queries cost + "popularity ≠ protected" FP, **not** data availability. A tighter set would be the most-impersonated-brand lists, APWG/OpenPhish.)
- **Whole-script confusables** (an all-Cyrillic look-alike `раураӏ`) — **out, documented limitation.** Single-script ⇒ passes restriction-level analysis; catching it needs confusables + a protected set. Mixed-script detection catches *mixed* homographs only.
- **A confusables/skeleton table** — not shipped (the script-set signal is sufficient for the malicious tier; verified §1).
- **The matcher data structures / ABP / preprocessing** (ADR-06/-07) — unchanged; this ADR only adds the IDN branch analyzer.
- **Homoglyph detection on non-DNS layers** — out (DNS resolver only).

---

## 3. Consequences

**Positive**

- The block-all-IDN sledgehammer becomes usable: real protection against the actual threat (cross-script homographs) without nuking legitimate international domains — so it can be turned **on**.
- The signal is authority-backed (ICANN v4.1 / EURid / UTS#39) and needs **only script data, no confusables table** — minimal shipped data, no dependency.
- Catches **subdomain-level** homographs that registry policy can't (fact 5).
- The analyzer is pure + unit-tested; cost is bounded to `xn--` queries; the common path is untouched.

**Negative / risks**

- **False positives on legitimate IDNs (the ADR-01-class risk).** A naive "any mix ⇒ block" would break Japanese/Korean/Chinese domains. Mitigated by the TR39 restriction-level logic (Latin+CJK allowed) + the **Phase-1 FP corpus with a ~zero-FP kill-threshold on the legit set (esp. CJK)**.
- **Unicode-data freshness.** Scripts/Script_Extensions evolve; a stale table mis-scripts new codepoints. Mitigated by the pinned-version generator + a documented update step.
- **Incomplete by construction.** Whole-script confusables and ASCII typosquats are *not* caught — must be stated so operators don't over-trust the feature.
- **Punycode decode edge cases.** Malformed/abusive A-labels; mitigated by catching decode errors and flagging rather than raising.

---

## 4. Requirements (acceptance)

1. **Mode selector, backward-compatible:** `pfb_idn` → Off | All-IDN | Confusable; `'on'` migrates to All-IDN with no observable change; Off/All-IDN byte-identical to today (golden-pinned).
2. **Correct detection (TR39):** the analyzer classifies single-script, Latin+CJK, `Latin+Cyrillic`, `Latin+Greek`, `Cyrillic+Greek`, Common-mixes, and malformed labels per the Phase-2 oracle.
3. **~Zero FP on legit IDNs:** the Phase-1 corpus shows the malicious tier does not block any legitimate IDN (CJK especially); high TP on the homograph set. Else the malicious script-set is narrowed (or the ADR is rejected).
4. **Safe + bounded:** decode failures never crash; analysis runs only on `xn--` queries; non-IDN fast path unchanged.
5. **Data shipped + reproducible:** Scripts/Script_Extensions tables ship as data; the generator reproduces them from a pinned Unicode version; version documented.
6. **UI/counts intact:** mode selector + sub-toggles render; alerts show the decoded form + offending char; `DNSBL_IDN` (All-IDN) and the new homoglyph feed/group counts render.
7. **Default suite green:** `python -m pytest`, `ruff`, `php -l`, ShellCheck, markdownlint clean; no new shipped Python dependency (stdlib + data only).

---

## 5. Constraints (from `CLAUDE.md`)

- **Plugin + generator: stdlib only, Python 3.11+**, 4-space, type hints on new fns, no bare `except`, `from __future__ import annotations`. The analyzer references **no Unbound symbol** (unit-testable); any new injected symbol → `stubs/python/unboundmodule.py`.
- **PHP:** tabs, 8.3, no `die()`/`exit()` in library code, pfSense fns via stubs (prefer a stub over a phpstan baseline).
- **Shell:** POSIX `sh`, quoted, absolute binary paths, ShellCheck-clean.
- Run `python -m pytest` after any `pfb_unbound.py`/`tests/` change; `ruff check .`/`ruff format .` clean each commit.
- Commit style `<scope>: <imperative summary>`; **work inline on `adr/08`, one commit per phase, push directly** (PR only if rejected). PR bodies via `--body-file`.
- **Docs:** README/CLAUDE.md updated for the new setting + the Unicode-data version/update step (final phase).

---

## 6. Action plan

Each phase = one commit, leaves `python -m pytest` green, and **preserves Off/All-IDN behaviour** (the retained golden). The **FP/TP corpus de-risk is front-loaded (Phase 1)**, the **TR39 decision oracle (Phase 2)** precedes any logic, and a **behaviour-preserving extraction + mode plumbing (Phase 3)** lands before the analyzer is wired.

### Phase 1 — Inventory + IDN corpus + FP/TP measurement (de-risk)

Prompt: `01_Inventory_Corpus_FPTP.txt`

- **Inventory** the existing IDN feature end-to-end (`pfb_idn`→`python_idn`→`is_idn_domain:755`→`evaluate_domain:2307`; UI `:2388`; alias `:8305`; config write `:2540`; PHP `idn_to_ascii`/`idn_to_utf8`). Write the contract to preserve.
- **Corpus:** legit IDNs per script (Latin-accented, single-script Cyrillic/Greek, **Japanese/Korean/Chinese mixes**, Arabic, Thai, …) + a legit **ASCII/Latin SLD under an IDN ccTLD** (`example.рф`, `site.中国` — must be OK **per-label**) + known homograph-phishing (Latin+Cyrillic/Greek mixes) + a **malicious subdomain label** (`раypal.example.com`). Under `tests/fixtures/adr08_corpus/`.
- **Finalise the confusable script set** {Latin, Cyrillic, Greek, + decide Cherokee/Armenian/Coptic} and the rule (**≥2 of them co-occurring in one label → malicious, incl. `Cyrillic+Greek`, not only Latin-anchored**); the **per-label** granularity (never union across the dot); the **allowed combos** (UTS#39 Highly Restrictive); decide **Script vs Script_Extensions** fidelity.
- **Measure** FP (false positives — legit IDNs wrongly flagged; target **~0**, CJK + IDN-ccTLD must be 0) and TP (true positives — real homographs caught) over the corpus; sanity-check the per-`xn--`-query analyzer cost is negligible. Confirm stdlib `'punycode'` decode behaviour + edge cases.
- **Gate:** GO if malicious-tier FP ≈ 0 on legit (esp. CJK) and TP high; else narrow the malicious set or pivot/reject. Record it.

### Phase 2 — TR39 decision spec + golden oracle

Prompt: `02_Decision_Spec_Oracle.txt`

- Author `(label → resolved-script-set → restriction-level → severity → action)` as fixtures + a pure oracle: ASCII no-op; single-script legit; Latin+CJK legit; **`Latin+Cyrillic`, `Latin+Greek`, AND `Cyrillic+Greek` malicious→block**; Common-mix legit; Latin+Armenian/Cherokee suspicious→alert; **whole-script-Cyrillic look-alike → NOT caught (documents the limitation)**; malformed `xn--` → flagged, no crash; **per-label cases** (legit ASCII/Latin SLD under an IDN ccTLD → OK; a malicious subdomain *label* → block — never union scripts across the dot). Pure pytest.

### Phase 3 — PREP (behaviour-preserving): extract IDN unit + pin All/Off + mode plumbing inert

Prompt: `03_Extract_Mode_Plumbing.txt`

- Extract `is_idn_domain` + the `evaluate_domain:2307` IDN block into a named, testable unit; **pin today's Off + All-IDN behaviour with a golden** (no regression). Add the **Off | All-IDN | Confusable** mode plumbing (config + `pfb[...]`), with `'on'`→All-IDN migration; **Confusable is inert** this phase (no analyzer yet — behaves as Off until Phase 5). Behaviour-preserving.

### Phase 4 — Ship Scripts/Script_Extensions data + generator + pure analyzer (not wired)

Prompt: `04_Unicode_Data_Analyzer.txt`

- `scripts/update-unicode-data.py`: download a **pinned Unicode version** `Scripts.txt`/`ScriptExtensions.txt`, emit compact binary-searchable range tables shipped under the package dir. Pure analyzer: punycode-decode (stdlib, graceful) → per-codepoint script (Script_Extensions-aware, Common/Inherited transparent) → resolved set → restriction level → severity, iterating **per label** (flag if any single label mixes confusable scripts; never union across the dot). Unbound-symbol-free, unit-tested vs Phase-2. **Not wired.**

### Phase 5 — Wire the analyzer into the matcher (Confusable mode live)

Prompt: `05_Wire_Matcher.txt`

- In Confusable mode, on `xn--` queries: **malicious → block** (default-on sub-toggle), **suspicious → alert** (default; opt-in escalates to block). Distinct feed/group labels; **dual-form logging** (xn-- + decoded + offending char/script). Off/All-IDN decision-equivalent (golden). The analyzer feeds `is_found`; the existing whiteDB override still wins.

### Phase 6 — UI + PHP config

Prompt: `06_UI_Config.txt`

- Replace the `pfb_idn` on/off control with the **mode selector** (Off|All-IDN|Confusable) + the two sub-toggles (block-malicious default-on; suspicious alert↔block); help text spelling out the limitation (whole-script/ASCII not covered). PHP config plumbing into the python config; alerts display tie-in (`idn_to_utf8`). Backward-compat: existing `'on'` → All-IDN. `php -l`/stub/lint clean.

### Phase 7 — Validation, FP/TP on-branch, manual smoke, DoD

Prompt: `07_Validation_Smoke_DoD.txt`

- Full golden + no-regression; re-run the Phase-1 FP/TP on `adr/08` vs the threshold; finalise help text, README/CLAUDE.md (incl. the Unicode-data version + update step). **Manual smoke (live box):** a Latin+Cyrillic domain blocks; a **legit Japanese/Korean domain resolves**; All-IDN still blocks all IDN; Off resolves; alerts show decoded form + offending char; mode selector + sub-toggles work; backward-compat (`'on'`→All-IDN); malformed `xn--` doesn't crash the resolver.

---

## 7. Definition of done

- `python -m pytest` green incl. the TR39 oracle, the analyzer unit tests, the matcher wiring, and the FP/TP corpus; the retained Off/All-IDN golden green (no regression); `ruff`/`php -l`/ShellCheck/markdownlint clean.
- Confusable mode blocks cross-script confusable homographs (Latin+Cyrillic/Greek) by default, alerts suspicious mixes, and **does not block any legitimate IDN** (CJK incl.) per the Phase-1 corpus.
- Off/All-IDN are byte-identical to today; `pfb_idn='on'` migrates to All-IDN transparently.
- Scripts/Script_Extensions ship as data, reproducible from a pinned Unicode version (documented); no new shipped Python dependency.
- The limitation (whole-script confusables + ASCII typosquats not covered) is documented in the help text + README.
- Status → **Accepted** only after the manual smoke (below) passes on a live pfSense box.

### Build evidence (recorded Phase 7, on `adr/08-homoglyph-protection`)

CPython 3.11; pinned **Unicode 15.1.0** (`UNICODE_VERSION` in both
`scripts/update-unicode-data.py` and the shipped data module
`src/usr/local/pkg/pfblockerng/pfb_unicode_scripts.py`; matches the dev-box
`unicodedata.unidata_version` and the corpus/oracle `ucd_version`, so tables, corpus
and spec agree). All numbers reproduced on-branch in Phase 7 — they match the Phase-1
de-risk (no drift after the analyzer + matcher wiring).

**Test equivalence (`python -m pytest`): 1303 passed, 0 failed.** The ADR-08 suite is
**179** of these:

- **TR39 decision oracle (Phase 2): 49 passed** — `tests/test_adr08_decision_spec.py`
  (pure oracle graded against the golden `decision_table.json` + cross-checked against
  the Phase-1 `corpus.json`).
- **No-regression Off/All-IDN golden (Phase 3): 11 passed** —
  `tests/test_adr08_mode_baseline.py`. Off → no IDN action; All-IDN → every `xn--`
  query blocked with `feed="IDN"`/`group="DNSBL_IDN"`, byte-identical to today; the
  `'on'`→All-IDN migration changes nothing observable.
- **Pure analyzer vs oracle (Phase 4): 75 passed** — `tests/test_adr08_analyzer.py`
  (the shipped `pfb_idn_analyzer.classify_idn` decode / resolved-script-set / severity
  graded row-by-row against the oracle + the whole corpus).
- **Confusable matcher wiring (Phase 5): 44 passed** —
  `tests/test_adr08_confusable_matcher.py` (production `evaluate_domain` +
  `idn_confusable_action` across every severity tier × both sub-toggle states, with
  before/after toggle transitions; whitelist-wins; decode-safe; non-IDN pays nothing).

**FP/TP measurement (`python tests/fixtures/adr08_corpus/measure_fp_tp.py`, on-branch):
GATE = GO.**

| metric | measured (on-branch) | kill-threshold | result |
| --- | --- | --- | --- |
| malicious-tier FP on the legit set | 0 / 20 legit-tier labels | == 0 | PASS |
| **CJK FP** (Japanese/Korean/Chinese) | 0 | **must be 0** | PASS |
| **IDN-ccTLD per-label FP** (`example.рф` / `site.中国`) | 0 | **must be 0** | PASS |
| TP (homographs caught) | 6 / 6 (incl. pure `Cyrillic+Greek` + the subdomain homograph) | all homographs | PASS |
| punycode decode safe (no uncaught raise) | True | no propagated decode error | PASS |
| analyzer cost per `xn--` label | ~0.70 µs | negligible (runs only on `xn--` queries) | PASS |

The malicious rule (**≥2 of {Latin, Cyrillic, Greek} co-occurring in one label**, never
unioned across the dot) catches all six homographs — including the pure `Cyrillic+Greek`
`xn--mxa00ab` (proving the rule is not Latin-anchored) and the subdomain homograph
`xn--ypal-43d9g.example.com` (per-label catches what registries can't) — while flagging
no legitimate IDN: every CJK, single-script Cyrillic/Greek, Latin-accented, Arabic/Thai/
Hebrew/Devanagari name resolves, and both IDN-ccTLD per-label cases resolve (a whole-name
union of `example.рф` would read `{Cyrillic, Latin}` = malicious — the per-label rule
eliminates that FP class by construction). Latin+Armenian/Cherokee/Coptic land in the
**suspicious** (alert) tier, not malicious. The whole-script all-Cyrillic `xn--80ak6aa92e`
(`аррӏе`) is single-script → **not caught** (the documented limitation). Malformed labels
(`xn--zz`, `xn--0`) raise inside the decoder and are **caught + flagged**, never
propagated to the resolver.

**Decision:** GO — no reject-criterion tripped. FP is 0 on the legit set (CJK and
IDN-ccTLD both 0), TP is 6/6, decode is safe and cheap. Status held at **Implemented —
pending live smoke**; flips to **Accepted** only on the maintainer's live-box run below
(CI cannot reach Unbound's Python loader).

### Reject criteria (decide cheaply, Phase 1, before building)

- **False positives on legit IDNs can't be driven to ~0:** if the malicious tier blocks legitimate IDNs (especially CJK) and narrowing the malicious script-set can't fix it without gutting the true-positive catch → do **not** ship a resolver that breaks real international domains; reduce to alert-only, or reject.
- **Punycode/Script analysis can't be made safe/cheap in stdlib** on the target (decode crashes, or per-query cost on `xn--` queries is unacceptable) → STOP and reconsider (e.g. precompute, or keep All-IDN-only).

### Manual smoke (owner: maintainer) — required before Accept

> **Gate: Status flips to Accepted ONLY after every box below passes on a live pfSense CE box.** CI cannot reach Unbound's Python loader. Probe **on-box** (`drill @127.0.0.1 <name>` over SSH) after a resolver reload with the mode selected; the **first** response after `wait_unbound_ready` is authoritative. A Confusable **block** is the DNSBL block shape (NOERROR + the DNSBL VIP, or NULL `0.0.0.0`/`::` per the list `logging` field) — **never** NXDOMAIN; a **resolve** is the upstream answer (or NXDOMAIN if the name simply doesn't exist — the point is *no DNSBL action*). The exact `xn--` labels below come from `tests/fixtures/adr08_corpus/corpus.json`.
>
> Set DNSBL **IDN Blocking = Confusable** (with **block-malicious ON**, **escalate-suspicious OFF** unless a box says otherwise), reload Unbound, then:

- [ ] **Malicious blocked.** `xn--pple-43d` (`аpple`, Latin+Cyrillic) **and** `xn--mxa00ab` (`сαр`, **Cyrillic+Greek** — no Latin, proves the rule isn't Latin-anchored) both return the **block shape** in Confusable mode with block-malicious ON; the alert (Reports → DNSBL, or `/var/log/pfblockerng/dnsbl.log`) shows the decoded Unicode + the offending scripts (e.g. `xn--pple-43d [аpple] Cyrillic Latin`) under feed/group `Homoglyph`/`DNSBL_Homoglyph`.
- [ ] **Legit IDN resolves.** A legitimate **Japanese** (`xn--zckzah` = `テスト`), **Korean** (`xn--3e0bk47br7k` = `한국어`), **Chinese** (`xn--fiq228c` = `中文`) domain **and** a single-script Cyrillic (`xn--h1alffa9f` = `россия`) / Greek (`xn--hxakic4aa` = `ελλάδα`) name **resolve** in Confusable mode (no DNSBL block).
- [ ] **IDN ccTLD safe (per-label).** A legit ASCII/Latin SLD under an IDN ccTLD — `example.xn--p1ai` (`example.рф`) and `site.xn--fiqs8s` (`site.中国`) — **resolves** (no block): each label is single-script; the per-label rule never unions `{Latin, Cyrillic}`/`{Latin, Han}` across the dot.
- [ ] **Suspicious alerts (not blocks) by default.** `xn--bnk-1ce` (`bանk`, Latin+Armenian) **resolves but alerts** (group `DNSBL_Homoglyph_Suspect`, b_type `Homoglyph_Alert`) with escalate-suspicious OFF; flip **escalate-suspicious ON**, reload, and confirm it now returns the **block shape** (before/after: the SAME name, the toggle flips resolve→block).
- [ ] **All-IDN unchanged.** Switch the mode to **All-IDN**: every `xn--` domain (incl. the legit CJK ones above) returns the block shape with feed/group `IDN`/`DNSBL_IDN`, exactly as today. Switch to **Off**: all of them resolve.
- [ ] **Backward compat.** A config that carried `pfb_idn='on'` comes up in **All-IDN** mode (the selector shows All-IDN) with identical behaviour to the All-IDN box above.
- [ ] **Robustness.** A malformed/abusive `xn--` label (`xn--zz`, `xn--0` — these raise inside the punycode decoder) does **not** hang or crash the resolver: the query returns normally (the label is flagged/skipped; the resolver keeps answering subsequent queries). Check `py_error.log` shows no traceback.
- [ ] **Whitelist wins.** Add `xn--pple-43d` (the malicious homograph) to the DNSBL custom **whitelist**, reload, and confirm it now **resolves** (the analyzer feeds `is_found`, but the whiteDB override applies after — unchanged).
