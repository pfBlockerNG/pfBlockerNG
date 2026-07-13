# ADR-32: Add IPinfo as an alternative GeoIP/ASN provider behind an abstraction

- **Status:** **Proposed** (2026-06-20; facts + anchors refreshed 2026-07-03 against `devel` —
  the consumer inventory was corrected to FIVE consumers across three languages (the original
  PHP-interface seam cannot serve them), `maxmind_account` added to the credential set, and
  the fetch re-routed onto the existing extras pipeline; the seam-level decision is the
  **§2.0 open fork** and blocks Phases 2–4)
- **Date:** 2026-06-20
- **Branch:** `adr/32-ipinfo-geoip` (off `devel`)
- **Folds in:** issue #291 ("Add IPinfo GeoIP")
- **Prerequisite (blocking, 2026-07-12):** issue **#1235** — the country/continent truth
  moves in-tree (GeoNames-generated, ISO-keyed, provider-independent) **before** Phase 2.
  Until it lands, this ADR's §2.1 rows for the country build and locale names are unsound:
  they let the *provider* define which countries exist and what they are called, so switching
  provider (or a provider dropping a country) would silently change a user's configured
  aliases. See §2.5.
- **Component(s):** `src/usr/local/www/pfblockerng/pfblockerng.php` (GeoIP/Reputation/ASN
  build + IP-tab settings), `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (MMDB log
  enrichment, ASN, reputation), `src/usr/local/pkg/pfblockerng/pfblockerng.sh` (DB
  download/convert), `config.xml` keys (`maxmind_key`, `asn_token`, …)
- **Target runtime:** PHP 8.3 (pfSense CE 2.8); POSIX sh for the download/convert path
- **Test suite:** `tests/php/` (PHPUnit, off-appliance), `tests/smoke/` (live-VM, ADR-04)

## 1. Context

GeoIP and ASN data are sourced from two vendors today, each wired directly into many call
sites with no abstraction layer:

- **MaxMind** is the GeoIP source — country databases drive the per-continent GeoIP block
  pages (`pfblockerng.php`), the **MMDB** lookup enriches firewall + DNSBL logs
  (PHP daemon: `pfblockerng.inc` ~`:11129` `mmdblookup`; **shell**: `pfblockerng.sh` reads
  the same MMDB via `$pathmmdblookup` for the reputation + ASN paths), and the IP
  **Reputation** feature consumes it. Credentials are **`maxmind_account` + `maxmind_key`**
  (both required upstream now — the account id was missing from this ADR's original
  inventory; see `pfb_maxmind_credential_notice()` ~`:1970` and the username/password
  download args in `pfblockerng.php`). MaxMind also carries **locale/language** country
  names and the legacy flags `is_anonymous_proxy` / `is_satellite_provider` / `is_anycast`
  (some now deprecated upstream). The `geoname` id is the key used to read the MaxMind DB
  and build the per-country GeoIP option lists.
- **IPinfo** is used **only for ASN** today (`asn_token`, `pfblockerng.inc` ~`:2038`,
  ~`:11513`, ~`:16012`; the `ipinfo.io` MIME carve-out at ~`:1258`). Note the in-tree
  precedent: the IPinfo ASN product is **already delivered as `asn.mmdb`** (+ `asn.csv.gz`)
  via `$pfb['extras']` in `pfblockerng.php` and read by the **same `mmdblookup`** as
  MaxMind's DBs. IPinfo now also ships GeoIP in **CIDR** IPv4/IPv6 form — and in **MMDB**
  form — so it is a viable GeoIP source; the delivery-format choice is part of the §2.0
  fork.

Load-bearing facts:

- **Storage follows the ADR-28 §2.2 behaviour-not-bytes rule** (corrected 2026-07-03 — the
  original "hard-frozen, stored values never change" wording predates the reconciled policy):
  there is no versioned migration routine, and behaviour must be preserved on upgrade. The
  operative conclusion stands — issue #291's "clean up users' config.xml … if features are
  removed" is a **notice**, not a migration (see §2.3).
- GeoIP/ASN data is consumed in **FIVE** distinct places (corrected 2026-07-03 — the original
  count of four missed one that **cannot consume a PHP seam**): (a) GeoIP country-block alias
  build (PHP), (b) firewall-log enrichment (PHP daemon), (c) DNSBL-log **reply** enrichment —
  **`pfb_unbound.py` opens `GeoLite2-Country.mmdb` directly via the Python `maxminddb`
  module inside Unbound's chroot** (`pfb["maxminddb"]` → `maxminddb.open_database` →
  `maxmindReader.get(r_addr)`), (d) IP Reputation (**POSIX sh** — `pfblockerng.sh` calls
  `mmdblookup` directly), and (e) the shell ASN lookup (`pfblockerng.sh`). Three languages
  reach the vendor data independently — there is no single *code* seam to swap; see the §2.0
  fork.
- Real DB downloads need **vendor credentials** (a MaxMind account+key / an IPinfo token),
  so the end-to-end download+convert path **cannot run in CI** — a documented out-of-CI
  limitation (per CLAUDE.md "ADR acceptance"), validated on a maintainer box.

## 2. Decision

Introduce a **provider abstraction** for GeoIP and ASN data, with **MaxMind and IPinfo as
two alternative implementations behind one normalized seam** — so the active provider is a
**single setting applied uniformly**, and switching it is trivial.

### 2.0 OPEN DESIGN FORKS (recorded 2026-07-03 — block Phases 2–4; maintainer's call)

1. **Seam level.** A PHP `GeoipProvider` interface (§2.1) cannot serve the §1 consumer set:
   reputation + shell-ASN are POSIX sh (`mmdblookup` direct) and DNSBL reply-enrichment is
   Python (`maxminddb` in the chroot, stdlib+maxminddb only) — neither can call a PHP
   interface per lookup. The alternative that leaves all five consumers untouched: **the MMDB
   file is the seam** — "provider" selects which vendor DB gets downloaded/normalised into
   the `GeoLite2-Country.mmdb`-shaped file every consumer already reads (strong precedent:
   IPinfo ASN already ships as `asn.mmdb` read by the same `mmdblookup`; IPinfo offers
   MMDB-format GeoIP). Choosing MMDB-as-seam likely collapses Phases 2–4 dramatically.
   Decide before Phase 2.
2. **Fetch routing.** Phase 3's fresh POSIX-sh token-authenticated downloader duplicates an
   existing, gated pipeline: vendor DBs are fetched via `$pfb['extras']` →
   `pfblockerng_download_extras()` → `pfb_download()`, which already carries the ADR-42
   conditional GET/304 + xxh128 sidecars, the ADR-44 MIME allowlist (incl. the existing
   `ipinfo.io` carve-out), and the ADR-45 structural gates — and refresh scheduling is the
   ADR-43 tick's daily-jittered `dcc` job. The IPinfo GeoIP fetch should ride that pipeline
   (and state its refresh schedule); a parallel downloader needs an explicit justification.
3. **Parser home language** (if the CIDR form is chosen over MMDB): PHP vs Python for the
   CIDR→normalised-record conversion is left open by Phase 3's "whichever hosts the parse
   tests" — pick one (remember: no Python interpreter on the appliance outside
   `pfb_unbound.py`). *Recommended (2026-07-03, non-binding): PHP — the conversion runs on the
   appliance as `pfb_download()` post-processing like the other extras, where Python is
   unavailable by hard constraint; moot if fork 1 resolves to MMDB-as-seam.*

**No per-consumer mix-and-match** (the maintainer's explicit call on #291): a provider is
selected once per data domain and used by *every* consumer of that domain. We do **not**
support "MaxMind for logs but IPinfo for reputation". Concretely:

- **One `geoip_provider` setting** (`maxmind` | `ipinfo`, default `maxmind`) drives **all**
  GeoIP consumers (country build, FW-log enrichment, DNSBL-log enrichment, Reputation)
  uniformly.
- **One `asn_provider` setting** (`maxmind` | `ipinfo`, default `ipinfo` — today's
  behaviour) drives ASN uniformly. GeoIP and ASN are independent databases (they already
  differ today), so they keep independent provider settings — but neither is mixed *within*
  itself.

### 2.1 Per-area decision

| Area | Today | Decision |
| --- | --- | --- |
| Lookup seam | direct `mmdblookup` / IPinfo calls scattered | a `GeoipProvider` interface returning a **normalized record** (`country_iso`, `country_name`, `continent`, `asn`, `as_org`, flags map); MaxMind + IPinfo implementations |
| GeoIP source | MaxMind only | `geoip_provider` setting selects one provider for **all** GeoIP consumers |
| ASN source | IPinfo only | `asn_provider` setting selects one provider for ASN (default `ipinfo` = today) |
| Country/continent build | MaxMind `geoname` | **the truth is ours, not the provider's** (§2.5, issue #1235): an in-tree GeoNames-generated table (ISO 3166-1 alpha-2 → name, continent) defines which countries exist and what they are called; the provider only supplies **network → ISO**. MaxMind's Locations CSV degrades to a `geoname_id → ISO` lookup; IPinfo emits ISO directly |
| Deprecated MaxMind flags | `is_anonymous_proxy`/`is_satellite_provider`/`is_anycast` | exposed only when the active provider supplies them; absent providers report "unavailable" — never a fatal |
| Locale country names | MaxMind only | names (and their locales) come from the **in-tree table** (§2.5), so the UI language no longer depends on the provider — this removes the `supports_locale` capability flag and the "IPinfo → English only" degradation. A provider's own localized names, where it ships them, are optional enrichment, never the source |
| `config.xml` deprecated fields | n/a | **kept inert, never migrated** (ADR-28); a GUI/`file_notice` flags settings that the active provider can't honour |

### 2.2 Semantics that MUST be preserved (the contract — pin with tests before any swap)

- **`geoip_provider = maxmind` ⇒ byte-identical behaviour to today** — the GeoIP option
  lists, MMDB log-enrichment strings, Reputation inputs, and per-continent alias membership
  are unchanged for existing MaxMind users. This is the regression oracle for Phases 1–2.
- **No stored key is renamed, removed, or rewritten by this ADR** (ADR-28 behaviour-not-bytes:
  the new provider keys default to today's behaviour, so no grandfather seed is needed).
  `maxmind_account`/`maxmind_key`/`asn_token` keep their exact stored vocabulary.
- **Absent/unsupported capability degrades, never crashes** — a provider that lacks a flag,
  locale, or field reports "unavailable"; consumers fall back to a neutral value.
- **No live DB download in CI** — the abstraction is unit-tested against committed sample
  fixtures; real downloads are manual smoke.

### 2.3 `config.xml` "cleanup" → notice, not migration

Issue #291 asks to clean up config that references removed/deprecated GeoIP features (e.g.
firewall rules using a continent/flag the active provider no longer supplies). Because the
config store is frozen (ADR-28), this ADR **does not mutate `config.xml`**. Instead it
**detects** such references at build time and emits a `file_notice` naming the affected
setting/rule and the reason ("the selected GeoIP provider does not provide
`is_anonymous_proxy`; this option is inert"). The user decides whether to change it. The
stored value is preserved for roll-forward/rollback.

### 2.4 Explicitly kept / out of scope

- **Per-consumer provider mixing** — out (maintainer's call). One provider per data domain.
- **Dropping MaxMind** — out; it stays the default and a first-class provider (locale
  support, existing keys).
- **A new GeoIP UI redesign** — out; reuse the existing IP-tab settings + per-continent
  pages, adding only the provider selectors + capability notices.
- **`config.xml` migration / field removal** — out (frozen store); notices only.

### 2.5 The country/continent truth is OURS, not the provider's (prerequisite: issue #1235)

Recorded 2026-07-12, after the maintainer's review of #1235: *"The predefined Geoname should be
the ultimate truth. Especially once we look at adding IPinfo or potentially any other GeoIP
provider."*

A provider abstraction that lets each provider define **which countries exist** is not an
abstraction — it leaks the vendor straight into the user's configuration:

- A country present in one provider/release/plan can be absent from the next. If the country
  list is the provider's, an alias the user configured yesterday can silently evaporate on
  tomorrow's download. A blocklist that quietly stops blocking is the worst failure mode this
  package has.
- Providers disagree on **names**: MaxMind renders geoname `248816` as "Hashemite Kingdom of
  Jordan"; GeoNames — and `$pfb_geoip_all` today — call it "Jordan". Whichever the UI shows
  would change with the provider.
- Locales differ per provider (MaxMind ships localized Locations files; IPinfo ships none), so
  provider-sourced names make the **UI language** a function of the provider setting.

Therefore, before Phase 2:

1. **The truth is a committed, generated table** — GeoNames `countryInfo.txt` (CC BY 4.0; 252
   countries; ISO, name, continent, geonameid) via a pinned, checksum-verified generator, the
   same shape as `scripts/update-geoip-fixtures.py`. Note this is not a new dependency: the
   `geoname_id`s in today's hardcoded `$pfb_geoip_all` **are** GeoNames ids (`JO`=248816,
   `US`=6252001, `BT`=1252634, `AQ`=6697173) — the table was scraped from GeoNames once and
   never refreshed.
2. **The canonical key is the ISO 3166-1 alpha-2 code**, never a provider's `geoname_id` —
   which is where the data model already points (`config.xml` stores `countries4="US,BT"`).
3. **A provider supplies network → ISO, nothing else.** MaxMind's Locations CSV becomes a
   `geoname_id → ISO` lookup; IPinfo needs no lookup at all. This shrinks the provider seam
   to the one thing providers genuinely differ on.
4. **Disagreement is surfaced, never silently applied** — a country the provider has no
   networks for renders `(0)` (honest); a **configured** country the provider dropped raises a
   notice; an ISO the provider emits that our table does not know raises a notice.
5. **Provider-specific pseudo-countries stay in the provider adapter** — MaxMind's `A1`/`A2`
   (anonymous proxy / satellite) are not countries and are not in GeoNames (see #1221, where
   they are already provably empty against real GeoLite2 data).

#### Continents are a second truth — and a *structural* one

`countryInfo.txt` gives a continent **code** (`AF`/`AN`/`AS`/`EU`/`NA`/`OC`/`SA`), not a name.
Continent identity is already in-tree today, in two places, and one of them is load-bearing in a
way country names are not:

| Thing | Example | May it change? |
| --- | --- | --- |
| **Structural binding** | alias prefix `pfB_NAmerica` (`pfblockerng.inc:160-171`), config section root `installedpackages/pfblockerng<continent>` , generated page `pfblockerng_North_America.php` | **No.** These are stored config keys and alias names. Renaming one breaks existing `config.xml` and firewall rules — and ADR-28 forbids migrations. They are frozen, whatever any provider calls a continent. |
| **Display name** | "North America"; localized variants | Per locale, yes — but never per *provider*. |

So the continent table (7 rows, in-tree) carries: **code** (the stable key) → **GeoNames id** →
**structural slug** (frozen) → **display name(s)**. The GeoNames continent ids are already in
this tree — `pfblockerng.php:935-938` keys its "AA ASIA/EUROPE UNDEFINED" buckets on `6255147`
and `6255148`. Verified at the source (`geonames.org/<id>`, 2026-07-12):

```text
6255146 Africa   6255147 Asia    6255148 Europe   6255149 North America
6255150 South America            6255151 Oceania  6255152 Antarctica
```

Consequences for this ADR:

- **Country → continent comes from GeoNames' `Continent` column, not from the provider.** A
  provider's own continent field is ignored for the build; where it disagrees with the table, that
  is a notice (a provider bug or a stale table), never a silent re-bucketing of a user's alias.
- **A provider can never rename an alias or a config section.** MaxMind localizes "North America";
  IPinfo may not; neither may touch `pfB_NAmerica`.
- **Two entries in `$pfb['continents']` are not continents at all** and must not enter the
  GeoNames-derived table: **"Top Spammers"** (`pfB_Top`) is our editorial `$top_20` bucket, and
  **"Proxy and Satellite"** (`pfB_PS`) is a MaxMind construct (see #1221) that belongs to the
  MaxMind adapter. They keep their structural bindings; they just are not geography.

#### Continent-level rows: what the "AA \<CONTINENT\> UNDEFINED" buckets actually are

`pfblockerng.php:935-938` hardcodes two pseudo-countries keyed on **continent** geoname ids —
`6255147` ("AA ASIA UNDEFINED") and `6255148` ("AA EUROPE UNDEFINED") — and none for the other
five continents. They are not arbitrary: MaxMind emits **continent-level location rows** for
addresses it can only place to a continent (the legacy `AP` = Asia/Pacific and `EU` = Europe
pseudo-countries). MaxMind's own published example carries exactly such a row — the only one in
the file with an empty `country_iso_code`:

```text
6255148,en,EU,Europe,,,0        <- geoname_id IS the continent; no country
```

A Blocks row may then reference `geoname_id = 6255148`, which is not a country. Our Locations
parse **drops** that row (`:898` requires a non-empty `country_iso_code` *and* `country_name`),
so the two hardcoded entries re-add what the parse discarded — without them, such a Blocks row
would index `$pfb_geoip['country'][6255148]['iso'][0]` on a missing key. MaxMind's current
documentation does not mention continent-level `geoname_id`s or the `EU`/`AP` codes at all
(checked 2026-07-12), so this behaviour is known only from the data.

This matters for the provider abstraction: **"the country is unknown, only the continent is
known" is a real state a provider can report**, and the in-tree truth must model it explicitly
(a country-less, continent-only bucket per continent) rather than leave it as two hardcoded
MaxMind-shaped special cases. IPinfo's equivalent state, if any, must map onto the same model.

Note the coverage gap this exposes: the smoke corpus (#1228) carries **no** continent-level row
(zero references to any of the seven continent ids across both Blocks CSVs), so this path is
currently exercised by nothing.

Open questions #1235 must settle (they do not block this ADR's other phases): which locales the
table carries and where the localized names come from (GeoNames `alternateNames` vs CLDR — for
countries **and** the 7 continents), whether MaxMind's locale files stay as optional enrichment
for MaxMind users, the refresh cadence, and how the continent-only bucket is modelled (one per
continent, generalizing today's Asia/Europe pair — or retired, if no provider still emits the
rows).

## 3. Consequences

**Positive**

- Users can choose IPinfo or MaxMind for GeoIP (and for ASN) with a trivial, uniform switch.
- A single normalized seam replaces scattered vendor calls — future providers are a new impl,
  not a new set of call-site edits.
- MaxMind users see **no change** (frozen config, identical output).

**Negative / risks**

- The five consumers (three languages) each reach the vendor directly today; routing them all through one seam
  is a non-trivial refactor (mitigated by front-loaded extraction + golden tests, Phases 1–2).
- IPinfo's field/flag set ≠ MaxMind's (deprecated flags, locale); the normalized record must
  model "unavailable" cleanly or risk subtle log/UI regressions.
- The real download+convert path is unverifiable in CI (credentials) — leans on manual smoke;
  a kill-risk if IPinfo's CIDR DB proves too heavy to ingest on small boxes (see §7).

## 4. Requirements (acceptance)

- A `GeoipProvider`/`AsnProvider` seam with MaxMind + IPinfo implementations returning one
  normalized record shape.
- `geoip_provider` + `asn_provider` settings (default `maxmind`/`ipinfo`); each applied
  uniformly to all consumers of its domain; no per-consumer mixing.
- `geoip_provider = maxmind` is byte-identical to today (oracle test green).
- IPinfo GeoIP ingests its CIDR v4/v6 DB and serves all five consumers.
- Deprecated/unsupported capabilities degrade with a `file_notice`; `config.xml` is never
  mutated.
- All gates green (§5); manual smoke (§7) covers the credentialed download path.

## 5. Constraints (from CLAUDE.md)

- PHP tabs, PHP 8.3; no `die()`/`exit()` in library code; new pfSense fns stubbed + doubled.
- ADR-28 behaviour-not-bytes storage; registered keys go through `PfbConfig` (ADR-29) —
  add any new key to `pfb_cfg_registry()` (+ `since`) + the sniff's `$registeredPaths` + the
  `docs/misc/config-gateway.md` inventory, with a round-trip test.
- New input-handling (provider key/token, downloaded-DB paths) honours PFBL-01 (validate
  before `exec`/path-build) and the URL-encoding gate for any HTTP client call.
- POSIX sh for the download/convert path; `LC_ALL=C` on any sort over machine data (ADR-26).

## 6. Action plan

### Phase 1 — Prep: extract + pin the current MaxMind/ASN paths (behaviour-preserving)

- Prompt: `01_Extract_And_Oracle.txt`
- Enumerate every MaxMind/IPinfo call site (the **five** consumers per §1 — incl. the
  `pfb_unbound.py` maxminddb reader and the `pfblockerng.sh` mmdblookup paths — + DB build);
  extract the PHP read/lookup pieces into named pure-ish functions without changing output
  (the sh/Python consumers are enumerated, not extracted).
- Golden tests freezing today's GeoIP option lists, MMDB enrichment strings, ASN output, and
  per-continent membership for a fixture corpus — the regression oracle for Phases 2–5.
- Tests: oracle green; `geoip_provider` absent ⇒ identical output.

### Phase 2 — Prep: define the normalized record + provider interface; wrap MaxMind behind it

- Prompt: `02_Provider_Interface.txt`
- **BLOCKED on §2.0 fork 1** (seam level — a PHP interface cannot serve the sh/Python
  consumers; MMDB-as-seam may replace this phase). If the interface route is chosen: define
  the normalized GeoIP/ASN record + `GeoipProvider`/`AsnProvider` interface; route the **PHP**
  consumers through it with **MaxMind as the only implementation** — output byte-identical
  (Phase-1 oracle stays green) — and state explicitly how the sh/Python consumers are served.
  No IPinfo yet, no new setting yet.
- Tests: oracle unchanged; interface unit tests (MaxMind impl returns the expected normalized
  record for fixture inputs).

### Phase 3 — IPinfo ingestion (download + parse the CIDR DB → normalized record)

- Prompt: `03_IPinfo_Ingest.txt`
- **Fetch rides the existing extras pipeline per §2.0 fork 2** (`$pfb['extras']` →
  `pfb_download()`: ADR-42 conditional GET + sidecars, ADR-44/45 gates, ADR-43 `dcc`
  refresh scheduling) — NOT a fresh POSIX-sh downloader. Parse IPinfo's DB into the
  normalized form (format + parser language per §2.0 forks 1/3); map IPinfo fields; model
  MaxMind-only flags/locale as "unavailable". Committed sample fixtures (inert,
  RFC 5737/3849) drive parse tests.
- Tests: parse fixtures → normalized record; malformed input rejected; capability flags
  (`supports_locale=false`, deprecated flags absent) correct. **Red→green** for the new
  behaviour (fail on pre-change code — this phase is not an oracle refactor).

### Phase 4 — IPinfo provider for enrichment + ASN

- Prompt: `04_IPinfo_Provider.txt`
- Implement the IPinfo `GeoipProvider`/`AsnProvider`: log enrichment, Reputation inputs, ASN
  lookups via the normalized seam. Keep block shapes/log formats stable.
- Tests: IPinfo impl returns normalized records matching the parse fixtures; enrichment
  strings well-formed; ASN parity with today where data permits. **Red→green** for every new
  behaviour branch.

### Phase 5 — UI: provider selectors + capability notices (config via PfbConfig)

- Prompt: `05_UI_Settings.txt`
- Add `geoip_provider` + `asn_provider` selectors to the IP tab — **the form is
  `www/pfblockerng/pfblockerng_ip.php`** (corrected 2026-07-03; `pfblockerng.php` is the
  argv-driven CLI/cron worker, not a settings page). Register both keys in
  `pfb_cfg_registry()` under the ipsettings section (+ `since` + `$registeredPaths` + the
  config-gateway.md inventory); show provider capabilities (locale, flags) and a notice when
  a stored setting is inert under the active provider. Server-side validation (PFBL-01).
- Tests: PHPUnit for the registry round-trip + the capability/notice decider; ADR-14
  `ui_render` for the changed IP/Reputation pages **plus Tier B `ui_e2e` — REQUIRED per
  CLAUDE.md test principle 4** (element addition + save/persist flow): select provider →
  save → reload → persisted, and the switch applies uniformly. **Red→green** for the new
  notice behaviour.

### Phase 6 — Deprecated-field detection + notices (no config mutation)

- Prompt: `06_Deprecation_Notices.txt`
- At build, detect config/firewall-rule references to GeoIP features the active provider can't
  supply; emit `file_notice` naming the setting + reason; **never write `config.xml`**.
- Tests: PHPUnit — given a config with a deprecated reference, a notice is produced and the
  store is untouched (assert byte-identical config before/after); **red→green** (the notice
  test fails on pre-change code).

### Phase 7 — Smoke + DoD + docs

- Prompt: `07_Smoke_DoD_Docs.txt`
- Live-VM smoke for the non-credentialed paths (provider-switch UI renders + persists,
  MaxMind path unchanged) — green on the **CE + Plus fan-out** (the default ADR-acceptance
  validation); the credentialed IPinfo download+convert and a small-box RAM check are
  **documented out-of-CI limitations** validated on a maintainer box (not the Accept gate);
  docs (`docs/misc/architecture-notes.md`, README) + stubs.

## 7. Definition of done

- [ ] Phase-1 oracle green; `geoip_provider = maxmind` byte-identical to today.
- [ ] Provider seam + MaxMind/IPinfo impls; one provider per domain, applied uniformly.
- [ ] IPinfo GeoIP serves all five consumers; deprecated capabilities degrade with a notice.
- [ ] `config.xml` never mutated (asserted) — cleanup is notice-only.
- [ ] All gates green: `vendor/bin/phpunit`, PHPStan, PHPCS, `php -l`, `python -m pytest`,
      ADR-14 `ui_render`.

**Manual smoke (owner: maintainer) — CI cannot cover credentialed downloads:**

- [ ] With a real MaxMind key: provider=MaxMind downloads + builds GeoIP + ASN as today.
- [ ] With a real IPinfo token: provider=IPinfo downloads the CIDR DB, builds GeoIP +
      ASN, enriches FW/DNSBL logs, and per-continent aliases populate.
- [ ] Switch provider both directions; confirm uniform application + inert-field notices.
- [ ] Small-box RAM/time check ingesting the full IPinfo CIDR DB.

**Reject criteria:** if ingesting IPinfo's CIDR DB blows the smallest-box RAM/time budget,
or IPinfo's field set cannot serve the five consumers without behavioural regressions that
can't be normalized away, **reduce** (IPinfo for ASN-only / log-enrichment-only) or
**reject** the GeoIP half, recording the numbers.
