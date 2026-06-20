# ADR-32: Add IPinfo as an alternative GeoIP/ASN provider behind an abstraction

- **Status:** **Proposed** (2026-06-20)
- **Date:** 2026-06-20
- **Branch:** `adr/32-ipinfo-geoip` (off `devel`)
- **Folds in:** issue #291 ("Add IPinfo GeoIP")
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
  (`pfblockerng.inc:8839` `mmdblookup`), and the IP **Reputation** feature consumes it. The
  account/licence key is `maxmind_key` (`pfblockerng.inc:1348`, `12462`, `12495`, `12780`;
  `pfblockerng.php`). MaxMind also carries **locale/language** country names and the
  legacy flags `is_anonymous_proxy` / `is_satellite_provider` / `is_anycast` (some now
  deprecated upstream). The `geoname` id is the key used to read the MaxMind DB and build
  the per-country GeoIP option lists.
- **IPinfo** is used **only for ASN** today (`asn_token`, `pfblockerng.inc:1416`, `9156`,
  `12791`; `ipinfo` at `pfblockerng.inc:775`). IPinfo now also ships GeoIP in **CIDR**
  IPv4/IPv6 form (previously range-only and too costly to convert), so it is a viable GeoIP
  source — but its database layout and field set differ from MaxMind's MMDB.

Load-bearing facts:

- **`config.xml` is hard-frozen (ADR-28 §2.2): stored values never change, no migration
  routine exists in this package.** Issue #291's "clean up users' config.xml … if features
  are removed" must therefore be a **notice**, not a migration (see §2.3).
- GeoIP/ASN data is consumed in **four** distinct places: (a) GeoIP country-block alias
  build, (b) firewall-log enrichment, (c) DNSBL-log enrichment, (d) IP Reputation. They all
  reach MaxMind independently — there is no single seam to swap.
- Real DB downloads need **vendor credentials** (a MaxMind licence key / an IPinfo token),
  so the end-to-end download+convert path **cannot run in CI** — it is a manual-smoke item.

## 2. Decision

Introduce a **provider abstraction** for GeoIP and ASN data, with **MaxMind and IPinfo as
two alternative implementations behind one normalized seam** — so the active provider is a
**single setting applied uniformly**, and switching it is trivial.

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
| Country/continent build | MaxMind `geoname` | provider yields the country→continent map; MaxMind keeps `geoname`, IPinfo supplies its own equivalent, both normalized to the same option-list shape |
| Deprecated MaxMind flags | `is_anonymous_proxy`/`is_satellite_provider`/`is_anycast` | exposed only when the active provider supplies them; absent providers report "unavailable" — never a fatal |
| Locale country names | MaxMind only | provider capability flag `supports_locale`; IPinfo → English only, surfaced in the UI |
| `config.xml` deprecated fields | n/a | **kept inert, never migrated** (ADR-28); a GUI/`file_notice` flags settings that the active provider can't honour |

### 2.2 Semantics that MUST be preserved (the contract — pin with tests before any swap)

- **`geoip_provider = maxmind` ⇒ byte-identical behaviour to today** — the GeoIP option
  lists, MMDB log-enrichment strings, Reputation inputs, and per-continent alias membership
  are unchanged for existing MaxMind users. This is the regression oracle for Phases 1–2.
- **`config.xml` stored values are frozen** — no key is renamed, removed, or rewritten by
  this ADR. `maxmind_key`/`asn_token` keep their exact stored vocabulary.
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

## 3. Consequences

**Positive**

- Users can choose IPinfo or MaxMind for GeoIP (and for ASN) with a trivial, uniform switch.
- A single normalized seam replaces scattered vendor calls — future providers are a new impl,
  not a new set of call-site edits.
- MaxMind users see **no change** (frozen config, identical output).

**Negative / risks**

- The four consumers each reach the vendor directly today; routing them all through one seam
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
- IPinfo GeoIP ingests its CIDR v4/v6 DB and serves all four consumers.
- Deprecated/unsupported capabilities degrade with a `file_notice`; `config.xml` is never
  mutated.
- All gates green (§5); manual smoke (§7) covers the credentialed download path.

## 5. Constraints (from CLAUDE.md)

- PHP tabs, PHP 8.3; no `die()`/`exit()` in library code; new pfSense fns stubbed + doubled.
- `config.xml` storage frozen (ADR-28); registered keys go through `PfbConfig` (ADR-29) —
  add any new key to `pfb_cfg_registry()` + the sniff's `$registeredPaths`.
- New input-handling (provider key/token, downloaded-DB paths) honours PFBL-01 (validate
  before `exec`/path-build) and the URL-encoding gate for any HTTP client call.
- POSIX sh for the download/convert path; `LC_ALL=C` on any sort over machine data (ADR-26).

## 6. Action plan

### Phase 1 — Prep: extract + pin the current MaxMind/ASN paths (behaviour-preserving)

- Prompt: `01_Extract_And_Oracle.txt`
- Enumerate every MaxMind/IPinfo call site (the four consumers + DB build); extract the
  read/lookup pieces into named pure-ish functions without changing output.
- Golden tests freezing today's GeoIP option lists, MMDB enrichment strings, ASN output, and
  per-continent membership for a fixture corpus — the regression oracle for Phases 2–5.
- Tests: oracle green; `geoip_provider` absent ⇒ identical output.

### Phase 2 — Prep: define the normalized record + provider interface; wrap MaxMind behind it

- Prompt: `02_Provider_Interface.txt`
- Define the normalized GeoIP/ASN record + `GeoipProvider`/`AsnProvider` interface; route the
  four consumers through it with **MaxMind as the only implementation** — output byte-identical
  (Phase-1 oracle stays green). No IPinfo yet, no new setting yet.
- Tests: oracle unchanged; interface unit tests (MaxMind impl returns the expected normalized
  record for fixture inputs).

### Phase 3 — IPinfo ingestion (download + parse the CIDR DB → normalized record)

- Prompt: `03_IPinfo_Ingest.txt`
- POSIX-sh download + parse of IPinfo's CIDR v4/v6 GeoIP DB into the normalized record; map
  IPinfo fields to the record; model MaxMind-only flags/locale as "unavailable". Committed
  sample fixtures (inert, RFC 5737/3849) drive parse tests.
- Tests: parse fixtures → normalized record; malformed input rejected; capability flags
  (`supports_locale=false`, deprecated flags absent) correct.

### Phase 4 — IPinfo provider for enrichment + ASN

- Prompt: `04_IPinfo_Provider.txt`
- Implement the IPinfo `GeoipProvider`/`AsnProvider`: log enrichment, Reputation inputs, ASN
  lookups via the normalized seam. Keep block shapes/log formats stable.
- Tests: IPinfo impl returns normalized records matching the parse fixtures; enrichment
  strings well-formed; ASN parity with today where data permits.

### Phase 5 — UI: provider selectors + capability notices (config via PfbConfig)

- Prompt: `05_UI_Settings.txt`
- Add `geoip_provider` + `asn_provider` selectors to the IP tab (registered in
  `pfb_cfg_registry()`); show provider capabilities (locale, flags) and a notice when a
  stored setting is inert under the active provider. Server-side validation (PFBL-01).
- Tests: PHPUnit for the registry round-trip + the capability/notice decider; ADR-14
  `ui_render` for the changed IP/Reputation pages.

### Phase 6 — Deprecated-field detection + notices (no config mutation)

- Prompt: `06_Deprecation_Notices.txt`
- At build, detect config/firewall-rule references to GeoIP features the active provider can't
  supply; emit `file_notice` naming the setting + reason; **never write `config.xml`**.
- Tests: PHPUnit — given a config with a deprecated reference, a notice is produced and the
  store is untouched (assert byte-identical config before/after).

### Phase 7 — Smoke + DoD + docs

- Prompt: `07_Smoke_DoD_Docs.txt`
- Live-VM smoke for the non-credentialed paths (provider-switch UI renders, MaxMind path
  unchanged); maintainer manual checklist for the credentialed IPinfo download+convert and a
  small-box RAM check; docs (`docs/misc/architecture-notes.md`, README) + stubs.

## 7. Definition of done

- [ ] Phase-1 oracle green; `geoip_provider = maxmind` byte-identical to today.
- [ ] Provider seam + MaxMind/IPinfo impls; one provider per domain, applied uniformly.
- [ ] IPinfo GeoIP serves all four consumers; deprecated capabilities degrade with a notice.
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
or IPinfo's field set cannot serve the four consumers without behavioural regressions that
can't be normalized away, **reduce** (IPinfo for ASN-only / log-enrichment-only) or
**reject** the GeoIP half, recording the numbers.
