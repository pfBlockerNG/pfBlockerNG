# ADR-64: Own the GeoIP country/continent truth in-tree — provider-independent, generated, tracked

- **Status:** **Proposed** (2026-07-13)
- **Date:** 2026-07-13
- **Branch:** `adr/64-geoip-truth-table` (off `devel`)
- **Folds in:** issue **#1235** (closed in favour of this ADR — its thread is the design record
  that produced §2); related: **#1246** (the continent-level rows have no test coverage),
  **#1221** (the `A1`/`A2` proxy/satellite aliases are provably dead on GeoLite2)
- **Blocks:** **ADR-32** (IPinfo as an alternative GeoIP/ASN provider) — this ADR is a
  **hard prerequisite for ADR-32 Phase 2**; ADR-32 §2.5 records why.
- **Component(s):** `src/usr/local/www/pfblockerng/pfblockerng.php`
  (`pfblockerng_uc_countries()`, `$pfb_geoip_all`, `$top_20`),
  `src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc`
  (`pfblockerng_get_countries()`, `pfb_build_reputation_tab()`),
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (`$pfb['continents']`,
  `$pfb['continent_list']`), a NEW committed table under
  `src/usr/local/pkg/pfblockerng/`, a NEW generator under `scripts/`, a NEW scheduled tracker
  under `.github/workflows/`
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the consumers; Python 3.11 for the dev-side
  generator (never on the appliance — CLAUDE.md hard constraint)
- **Test suite:** `tests/` (generator), `tests/php/` (PHPUnit — the parse/build oracle),
  `tests/smoke/` + `tests/smoke/ui/` (live-VM; Tier-A render)

## 1. Context — today

### 1.1 Two hardcoded truths, both unmaintained

`pfblockerng.php:941-1191` carries `$pfb_geoip_all` — **250 countries**, hand-written as
`geoname_id => array('iso', 'name', 'continent')`, commented *"List of all known Countries via
Geonames.org (Used to validate MaxMind Country listings)"*. `:883` carries `$top_20`, a second
hardcoded list. Nothing regenerates either.

`pfblockerng.inc:160-171` carries `$pfb['continents']` — the 7 continents plus two
non-geographic buckets (`Top Spammers`, `Proxy and Satellite`) — mapping each to an **alias
prefix** (`North America` → `pfB_NAmerica`).

### 1.2 Country identity is read out of the provider's files

`pfblockerng_uc_countries()` builds its country array from MaxMind's
`GeoLite2-Country-Locations-<locale>.csv`, keyed by `geoname_id` (`:887-918`), and the hardcoded
table only fills in what the provider did not list (`:1197-1213`). So *which countries exist*,
*what they are called*, and *which networks belong to them* all come from one vendor.

### 1.3 What that costs — measured on a real, licensed GeoLite2 dataset (2026-07-13)

| Fact | Measurement |
| --- | --- |
| Our table's ISO set | 250 = ISO 3166-1's 249 + `XK` (Kosovo, a user-assigned code) — **identical to MaxMind's set** |
| Our table's names vs current GeoNames | **6 differ**; four are renames the world made and we never picked up: **Swaziland** (Eswatini), **Macedonia** (North Macedonia), **Cape Verde** (Cabo Verde), **East Timor** (Timor Leste) |
| Our table's names vs current GeoLite2 | **21 differ** |
| GeoLite2's names vs GeoNames' | **17 differ** (`Türkiye`/`Turkey`, `Curaçao`/`Curacao`, `Congo (DRC)`/`Democratic Republic of the Congo`, `Palestine`/`Palestinian Territory`, …) — i.e. display names genuinely move with the provider |
| GeoNames `countryInfo.txt` | 252 codes — includes the **retired** `AN` (Netherlands Antilles, 2010) and `CS` (Serbia and Montenegro, 2006) |
| GeoLite2 proxy/satellite/anycast rows | **0** in both families (45 MB of Blocks data) — see #1221 |

### 1.4 Continent-level rows: "country unknown, continent known" is a real state

GeoLite2 emits Locations rows whose `geoname_id` **is a continent** and whose ISO code is empty —
the legacy `AP` (Asia/Pacific) and `EU` (Europe) pseudo-countries, for addresses it can only place
to a continent. Our Locations parse **drops** them (`:898` requires a non-empty ISO code *and*
name), so `pfblockerng.php:935-938` re-adds two hardcoded pseudo-countries keyed on the continent
geoname ids (`6255147` Asia, `6255148` Europe), rendered as `AA ASIA UNDEFINED` /
`AA EUROPE UNDEFINED`. Live data:

```text
Locations-en.csv rows with an empty country_iso_code:   exactly two (6255147 Asia, 6255148 Europe)
Blocks rows whose geoname_id IS a continent:            IPv4 539, IPv6 158   (registered_country: 0)
IPv4 address volume behind them:                        220,049 addresses (0.0051% of IPv4)
Any other continent used this way:                      0
```

MaxMind's current documentation does not mention continent-level `geoname_id`s or the `EU`/`AP`
codes at all — this behaviour is known only from the data. **#1246**: nothing tests it.

### 1.5 What `config.xml` actually stores (the frozen surface)

- Per-continent country selections store **ISO codes**: `countries4="US,BT"` under
  `installedpackages/pfblockerng<continent>/config/0`.
- The unknown-country buckets store the **GeoNames continent id** — the alias file is
  `cc/6255147_v4.txt`, its header `# ISO Code: 6255147`.
- Alias names (`pfB_NAmerica`), config-section roots (`pfblockerngnorthamerica`) and generated page
  filenames (`pfblockerng_North_America.php`) are **derived from the continent's name** and are
  therefore stored keys. ADR-28 forbids config migrations; these cannot be renamed.

## 2. Decision

**The country/continent truth lives in this repository, is generated from independent sources, is
keyed by ISO 3166-1 alpha-2, and is never defined by a GeoIP provider.** A provider supplies one
thing: **network → ISO code**.

The design below was settled on issue #1235 with @BBcan177 and @andrebrait; that thread is the
record.

### 2.1 The table

| Field | Source | Note |
| --- | --- | --- |
| **country set** | **ISO 3166-1 ∪ every SUPPORTED provider's codes** | 250 today = ISO's 249 + `XK`. Union over *all* supported providers, not the active one — otherwise switching provider would change which countries exist. The union also excludes GeoNames' retired `AN`/`CS` for free (neither ISO nor any provider lists them), so no "filter dead codes" rule is needed. |
| **ISO → continent** | **GeoNames `countryInfo.txt`** (CC BY 4.0) | ISO 3166 has no concept of a continent; this is the only thing it cannot answer. GeoNames' 7-continent model is the one the GeoIP pages already use (CLDR/UN M.49 splits the Americas differently and would not map onto them). |
| **continent set** | in-tree, 7 rows | code → GeoNames id (`6255146`…`6255152`, verified at `geonames.org/<id>`) → **frozen structural slug** → display name. |
| **display name (en)** | **curated in-tree**, seeded from CLDR/ISO, changed only by review | Upstream *renames* are surfaced by the tracker (§2.4) and accepted deliberately. Generating names wholesale from any upstream rewrites 25–36 of them at once and imports that vendor's style (`Congo - Kinshasa`, `Russian Federation`, `Hong Kong SAR China`); the value we need from upstream is **notification**, not dictation. |
| **localized names** | **generated** (CLDR; `iso-codes` `.po` as the alternative) | Covers every locale pfBlockerNG offers (`en fr de pt-BR ja zh-CN es`). Falls back to the curated English string. This retires "locale support depends on the provider": MaxMind's locale files become optional enrichment, and an IPinfo user gets the same localized UI. |
| **`XK` (Kosovo)** | carried explicitly | Not in ISO (user-assigned). GeoNames supplies its name + continent (`Kosovo`, `EU`, geoname `831053` — the same id MaxMind uses). A strict-ISO table would **drop Kosovo**, silently emptying a configured alias. |
| **`$top_20`** | stays curated | Our editorial choice, not provider data — but validated against the table so a typo or retired code cannot sit in it unnoticed. |

**Name precedence where a name must be derived:** curated → CLDR/ISO → GeoNames → provider. The
provider is the last resort and is load-bearing in exactly one place today: **localized `XK`
names** (`iso-codes` has no `XK` translations; MaxMind ships them).

### 2.2 The unknown-country bucket — per continent, not global

@BBcan177's call (#1235): *"When a data source can identify the continent but not a specific
country, that information still has value. Discarding it entirely feels like losing useful
signal."*

The truth models **one unknown-country bucket per continent**, keyed by that continent's GeoNames
id. It is generic across all seven; it is *populated* only where the active provider emits
continent-level rows (today: Asia + Europe on MaxMind), and the rest render `(0)`.

**Generalizing is free**: the bucket's stored key already *is* the GeoNames continent id
(`cc/6255147_v4.txt`, `# ISO Code: 6255147`), so `6255147`/`6255148` keep their exact stored values
— **no migration** — and the other five simply become selectable. A *global* bucket would have
needed a new key and a migration for anyone who had already selected the Asia/Europe entries.

### 2.3 The provider is validated against the truth; disagreement is surfaced, never applied

- A country in the table the provider has no networks for → renders `(0)`. Honest, and already
  today's behaviour.
- A **configured** country the provider dropped → a `file_notice`. The alias must not silently
  empty.
- An ISO code the provider emits that the table does not know → a `file_notice` **and** a tracker
  issue. Its networks are unassigned until the table is regenerated in a reviewed commit —
  **runtime never invents a country.** This is precisely what *"a subsequent MaxMind db could
  alter that"* (#1235) means, and the thing being prevented.
- A continent-level row for a continent the table does not surface → a `file_notice` (per
  @BBcan177: *"Maybe we just watch for changes"*).

### 2.4 Refresh is a scheduled tracker, not a hand edit

A **monthly** workflow re-derives the table from the pinned sources and, on any delta — a new or
retired ISO code, an upstream **rename**, a moved continent, a provider code we do not know —
**opens a GitHub issue** with the diff. House pattern: `version-tracker.yml`,
`top1m-healthcheck.yml`, `nightly-failure-alert.yml`. Regeneration stays a reviewed commit; the
tracker only says one is due.

### 2.5 Provider-specific pseudo-countries stay in the provider adapter

MaxMind's `A1`/`A2` (anonymous proxy / satellite) are not countries and are not in GeoNames. They
belong to the MaxMind adapter, not the truth table — and per #1221 they are provably empty against
real GeoLite2 data (0 flagged rows in 45 MB). Likewise `Top Spammers` and `Proxy and Satellite`
sit in `$pfb['continents']` but are **not geography**: they keep their structural bindings and stay
out of the generated table.

### Accepted user-visible deltas (the ONLY permitted output changes)

| # | Delta | Why it is acceptable |
| - | ----- | -------------------- |
| **D1** | ~5 country display names corrected (**Swaziland → Eswatini**, **Macedonia → North Macedonia**, **East Timor → Timor-Leste**, **Turkey → Türkiye**, **Cape Verde → Cabo Verde**) plus diacritics (`Åland Islands`, `Curaçao`, `Réunion`, `São Tomé and Príncipe`) | These are stale, not stylistic: the world renamed them. Display strings are **not** config keys (the stored value is the ISO code), so nothing in `config.xml` moves. Release-note it. |
| **D2** | 5 new selectable entries — the unknown-country bucket on Africa / North America / South America / Oceania / Antarctica — each rendering `(0)` until a provider emits rows | Additive; the two live buckets (Asia, Europe) keep their exact stored keys. |
| **D3** | Localized country names now come from the table rather than the provider's locale files | Same or better coverage for every locale we offer; removes the provider dependency. |
| **D4** | New `file_notice`s (§2.3) | Additive; no existing behaviour changes. |

Anything else changing — an alias name, a config key, a page filename, a country's membership, the
`(0)`/count rendering of an existing country — is a **defect**, not a delta.

### Semantics that MUST be preserved (pin with tests BEFORE any swap)

1. **Every stored key survives byte-identically**: `countries4`/`countries6` ISO codes, the
   unknown buckets' continent-geoname keys (`6255147`, `6255148`), alias names (`pfB_NAmerica`),
   config-section roots, generated page filenames, `cc/*.txt` file names.
2. **Country → network membership is unchanged** for every country the provider lists (the
   provider still supplies network → ISO; only *identity* moved).
3. **`XK` survives.** A strict-ISO generation would drop it.
4. **A provider absent a country renders `(0)`** — it does not vanish from the list.
5. **No live download in CI.** The generator runs dev-side against pinned, checksummed sources;
   the appliance only reads the committed table.

## 3. Consequences

- **ADR-32 shrinks.** The provider seam collapses to "network → ISO"; the country set, names,
  locales, continent mapping and unknown buckets stop being per-provider negotiations. The
  `supports_locale` capability flag and the "IPinfo → English only" degradation disappear.
- **A class of silent failure disappears**: a provider dropping a country can no longer quietly
  empty a user's alias — it raises a notice.
- **Four stale country names change in the UI** (D1). This is a fix, but it is user-visible.
- **We take on two upstream dependencies** (GeoNames for the mapping; CLDR/`iso-codes` for
  localized names) — both free, both pinned, both checksummed, neither on the appliance.
- **The tracker adds a monthly job** that can open issues. That is the point.

## 4. Requirements (acceptance)

1. The committed table reproduces byte-identically from the pinned sources (`--check` mode in CI).
2. The generator hard-fails (never guesses) on: a checksum mismatch; a provider/ISO code with no
   continent; a country in the union with no name from any source; a continent id it does not know.
3. The PHPUnit oracle proves the country/continent build output is unchanged **except** for the
   enumerated deltas D1–D4.
4. Tier-A `ui_render` covers the continent pages, the unknown buckets (including a `(0)` one), and
   the Reputation page.
5. A smoke row covers a **continent-level Blocks row** end-to-end (closes #1246).
6. The tracker demonstrates its red path in-session: a synthetic upstream delta opens an issue.

## 5. Constraints (from CLAUDE.md)

- **No Python on the appliance** — the generator is dev-side tooling; production reads a committed
  artifact.
- **PHP 8.3**, tabs, `TRUE`/`FALSE`, `PfbConfig` for any registered key.
- **ADR-28 storage rule**: no config migration; stored vocabulary is frozen.
- **Test coverage mandate**: behaviour-preserving phases pin the existing behaviour as an oracle;
  the behaviour-changing phase is red→green against that oracle, with the deltas enumerated above.

## 6. Action plan (phases)

### Phase 1 — Oracle: capture today's country/continent build (behaviour-preserving)

Golden fixtures of what `ugc` produces today: the per-ISO `cc/*.txt` inventory, the continent
files, `geoip_isos`, and the rendered per-continent option text — including the two unknown
buckets. This is the falsification harness every later phase is gated on.

### Phase 2 — The generator + the committed table (behaviour-preserving; nothing consumes it yet)

`scripts/update-country-table.py` (stdlib-only, pinned + sha256-verified sources, deterministic,
`--check` mode) → a committed table under `src/usr/local/pkg/pfblockerng/`. Unit tests incl. the
hostile-input set (missing continent, unknown code, retired code, non-ASCII, comma-in-name,
checksum drift, a provider code absent from ISO → `XK`).

### Phase 3 — Wire the build onto the table (behaviour-CHANGING: deltas D1 + D2 only)

`pfblockerng_uc_countries()` / `pfblockerng_get_countries()` (web dispatcher plus package-owned
generator) read identity from the table; the
provider's Locations CSV degrades to `geoname_id → ISO`. Red→green against the Phase-1 oracle: the
diff must be **exactly** D1 + D2. Delete `$pfb_geoip_all`; keep `$top_20` (validated).

### Phase 4 — Validation + notices (delta D4)

The §2.3 notices, each with a test that fires it: provider drops a configured country; provider
emits an unknown ISO; provider emits a continent-level row for an unmodelled continent.

### Phase 5 — The monthly tracker (`.github/workflows/`)

Scheduled re-derivation → issue on any delta, with a **red canary** in the same job (a synthetic
delta must open/flag it) per CLAUDE.md's CI-gate rule.

### Phase 6 — Smoke + UI + docs

Tier-A rows for the continent pages and the unknown buckets; the continent-level Blocks fixture row
that closes **#1246**; architecture-notes; release-note text for D1.

## 7. Definition of done

- All six phases landed; the canonical gates green.
- The Phase-1 oracle re-run shows **only** D1–D4.
- `config.xml` byte-identical across an upgrade on a box with GeoIP continents configured
  (including an unknown-country bucket selection).
- #1235 closed by this ADR (already), #1246 closed by Phase 6.
- ADR-32's prerequisite is satisfied and its §2.5 points here.

## 8. Rejected alternatives

- **Derive the table from the provider's Locations CSV** (the original #1235 proposal). Rejected:
  it makes the vendor the truth — the exact failure this ADR exists to prevent.
- **A single global "Unknown Country" bucket.** Rejected (@BBcan177, #1235): the continent is real
  signal, and a global bucket would need a new stored key + a migration.
- **Generate display names wholesale from ISO or CLDR.** Rejected: 25–36 names change at once and
  the result imports a vendor's style (`Congo - Kinshasa`, `Russian Federation`,
  `Taiwan, Province of China`). We take the *notification* from upstream, not the dictation.
- **Scrape ISO's OBP / buy the ISO collection file (300 CHF).** Rejected: `iso-codes` (LGPL-2.1)
  and CLDR already publish the same data, machine-readable and maintained.
