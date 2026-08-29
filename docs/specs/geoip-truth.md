# GeoIP country and continent truth

## Goal

Make pfBlockerNG the provider-independent owner of GeoIP country identity,
localized display names, and structural-continent placement. A GeoIP provider
supplies network observations; it cannot add, remove, rename, or move a country.
The appliance consumes one reviewed, committed truth artifact and retains the
last complete output generation when truth or provider input is invalid.

This specification replaces the unimplemented plan in
[ADR-64](../../legacy/ADRs/ADR_64_GeoIP_Truth_Table/ADR.md). The historical ADR remains
unchanged as the rationale record.

## Fixed constraints

- The decisions in
  [Re-baseline ADR-64 preservation and coverage](https://github.com/pfBlockerNG/pfBlockerNG/issues/1561),
  [Choose ADR-64 upstream sources and country names](https://github.com/pfBlockerNG/pfBlockerNG/issues/1562),
  [Choose ADR-64 truth-table refresh policy](https://github.com/pfBlockerNG/pfBlockerNG/issues/1560),
  and
  [Lock ADR-64 runtime compatibility and validation](https://github.com/pfBlockerNG/pfBlockerNG/issues/1563)
  are fixed. Implementation may clarify mechanics but cannot reopen them.
- No Python runs on an appliance. The generator is Python 3.11+ developer/CI
  tooling; appliance consumers are PHP 8.3 or POSIX shell.
- Runtime never downloads truth. Normal CI uses the committed artifact. Only the
  review-refresh workflow downloads the latest stable `unicode-org/cldr-json`
  GitHub Release archive.
- Existing config keys, geographic section roots, alias bases, country-code
  membership, generated page names, file names, network ordering, and network
  lines stay byte-identical unless listed under Approved deltas.
- Every registered setting uses `PfbConfig`. No install-time config migration is
  permitted.
- Provider adapters supply observations. The truth artifact owns all supported
  country identities, names, and structural-continent placement.
- `Top Spammers` is a fixed, provider-independent system group. Its exact
  ordered country membership is pfBlockerNG-owned; every active GeoIP provider
  supplies only the networks for those countries.
- Failed truth loading, provider parsing, validation, generation, or publication
  leaves the complete last-known-good output set active. Partial or mixed
  generations are never accepted as success.

## Domain vocabulary

- **Country identity:** pfBlockerNG-owned row keyed by an uppercase country code.
  The supported set is the reviewed ISO 3166-1 alpha-2 allowlist plus `XK`.
- **Structural continent:** one of seven stable internal rows. It owns config,
  alias, file, and page bindings and is never derived from a translated label.
- **Display name:** CLDR-derived label for one supported locale. It is
  presentation data, never a config value or identity.
- **Provider locator:** adapter-private identity such as a MaxMind GeoNames ID.
- **Provider observation:** normalized network, country, continent, represented
  country, and provider-trait data emitted by an adapter.
- **Unknown bucket:** synthetic `UNK_*` selection identity. It is not a country.
- **System GeoIP group:** pfBlockerNG-owned ordered membership projected onto
  the active provider's normalized country outputs. It is not provider data or
  a truth-artifact continent.
- **Output generation:** the mutually consistent `geoip.txt`, country files,
  continent files, generated pages, aliases, and GeoIP availability-state ledger
  produced from one truth artifact and one complete provider input set.

## Decisions

### Committed artifact

The only generated data artifact is
`src/usr/local/pkg/pfblockerng/geoip_truth.json`. It is pretty-printed UTF-8
JSON, preserves Unicode characters, uses four-space indentation, has
deterministic key order, and ends with exactly one newline. Raw CLDR files and
generated sidecars are not committed.

The top-level key order and schema are exact:

```json
{
  "schema": 1,
  "provenance": {
    "source": "unicode-org/cldr-json",
    "release": "48.2.0",
    "archive_url": "https://github.com/unicode-org/cldr-json/archive/refs/tags/48.2.0.tar.gz",
    "sha256": "<64 lowercase hexadecimal characters>",
    "license": "Unicode-3.0",
    "copyright": "<CLDR copyright text>",
    "permission_notice": "<full Unicode permission notice>"
  },
  "locales": ["en", "fr", "de", "pt-BR", "ja", "zh-CN", "es"],
  "continents": {
    "Africa": {
      "code": "AF",
      "file_stem": "Africa",
      "config_root": "pfblockerngafrica",
      "alias_base": "pfB_Africa",
      "unknown": "UNK_AF",
      "names": {"en": "Africa", "fr": "Afrique", "de": "Afrika", "pt-BR": "África", "ja": "アフリカ", "zh-CN": "非洲", "es": "África"}
    }
  },
  "countries": {
    "AD": {
      "continent": "Europe",
      "names": {"en": "Andorra", "fr": "Andorre", "de": "Andorra", "pt-BR": "Andorra", "ja": "アンドラ", "zh-CN": "安道尔", "es": "Andorra"}
    }
  },
  "unknown_buckets": {
    "UNK_AF": {"continent": "Africa", "label": "Unknown (Africa)"},
    "UNK_WR": {"continent": null, "label": "Unknown (World)"}
  }
}
```

The example abbreviates repeated rows only. The committed document contains:

- all seven continent objects, ordered `Africa`, `Antarctica`, `Asia`,
  `Europe`, `North America`, `Oceania`, `South America`;
- all 250 country objects, ordered by country code;
- all eight unknown-bucket objects, ordered `UNK_AF`, `UNK_AN`, `UNK_AS`,
  `UNK_EU`, `UNK_NA`, `UNK_OC`, `UNK_SA`, `UNK_WR`;
- every locale key in the top-level locale order; and
- no unrecognized key at any level.

The remaining continent bindings are fixed:

| Structural continent | Code | File stem | Config root | Alias base | Unknown |
| --- | --- | --- | --- | --- | --- |
| Africa | `AF` | `Africa` | `pfblockerngafrica` | `pfB_Africa` | `UNK_AF` |
| Antarctica | `AN` | `Antarctica` | `pfblockerngantarctica` | `pfB_Antarctica` | `UNK_AN` |
| Asia | `AS` | `Asia` | `pfblockerngasia` | `pfB_Asia` | `UNK_AS` |
| Europe | `EU` | `Europe` | `pfblockerngeurope` | `pfB_Europe` | `UNK_EU` |
| North America | `NA` | `North_America` | `pfblockerngnorthamerica` | `pfB_NAmerica` | `UNK_NA` |
| Oceania | `OC` | `Oceania` | `pfblockerngoceania` | `pfB_Oceania` | `UNK_OC` |
| South America | `SA` | `South_America` | `pfblockerngsouthamerica` | `pfB_SAmerica` | `UNK_SA` |

`Top Spammers` and `Proxy and Satellite` retain their current structural pages
and aliases but are not truth-artifact continents. `Proxy and Satellite`
remains provider-trait output; `Top Spammers` follows the fixed system-group
contract below.

### Fixed Top Spammers group

`Top Spammers` is an ordered, provider-independent system group with this exact
country membership:

```text
CN RU JP UA GB DE BR FR IN TR IT KR PL ES VN AR CO TW MX CL
```

This list is a stable pfBlockerNG product contract, not a provider ranking or
capability. It is not stored in `geoip_truth.json` and no upstream refresh may
change it. Runtime validates that all 20 codes exist in truth, obtains their
localized names from truth, and projects each selected member onto that
country's ordinary and represented-country outputs from the active provider.

The group, its `Top_Spammers_v4.info`/`Top_Spammers_v6.info` files, generated
page, existing config, and `pfB_Top` alias binding remain available for every
GeoIP provider. Existing `countries4`/`countries6` selections continue to
choose which of the 20 members are enforced per family. Switching providers
rebuilds the group inside the same complete output generation: membership and
configuration stay fixed while network content may change with the provider.
A provider-absent member keeps its selection and renders empty under the normal
country-absence contract. Failed or partial provider input preserves the whole
last-known-good generation; networks from two providers are never mixed.

### Generator interface

`scripts/update-geoip-truth.py` is stdlib-only and exposes:

```text
python3 scripts/update-geoip-truth.py \
  [--archive PATH | --release TAG] \
  [--output PATH] [--check]
```

- `--archive PATH` consumes a local release archive and performs no network
  access. Unit tests and ordinary CI use this form.
- `--release TAG` downloads that stable GitHub Release archive. The refresh
  workflow resolves the latest stable tag first and passes it explicitly.
- Supplying neither source is an error. Supplying both is an error.
- `--output` defaults to the committed artifact path.
- Normal mode validates and atomically replaces the output only when bytes
  differ. `--check` writes nothing and exits `0` when regenerated bytes match,
  `1` on drift, and `2` on source, schema, licence, or generation failure.

Generation performs CLDR locale inheritance; maps `pt-BR` to CLDR `pt` and
`zh-CN` to CLDR `zh`; selects CLDR `short` only for `HK`, `MO`, `MM`, and `PN`;
falls back from requested form to locale default to English default; recursively
projects containment roots `002`, `003`, `005`, `009`, `142`, and `150`; then
applies this frozen-placement override:

```json
{
  "Antarctica": ["AQ", "BV", "GS", "HM", "TF"],
  "Asia": ["CC", "CX", "IO"],
  "Europe": ["CY"],
  "Oceania": ["TL"]
}
```

The reviewed 250-code allowlist, structural bindings, short-form selector map,
and containment override live as constants in the generator. Generated output,
not raw input, is the runtime source.

Generation rejects invalid UTF-8, malformed JSON/archive layout, missing CLDR
files/locales/forms, unsupported CLDR schema, missing or changed Unicode licence
identity/notice, duplicate country membership, zero/multiple continent
membership, an unknown override code, any country outside the allowlist, any
missing allowlisted country (including `XK`), retired `AN`/`CS`, absent names,
nondeterministic second-pass bytes, and an implausible country count.

### Runtime truth interface

The package-owned GeoIP module exposes one loader:

```php
pfb_geoip_truth_load(?string $path = NULL): array
```

`NULL` loads the installed `geoip_truth.json`; a path exists for tests. The
loader returns the decoded schema above, caches only the default installed path,
and throws on unreadable input, JSON errors, invalid UTF-8, unknown/missing keys,
wrong types, unsupported schema, invalid country/locale/bucket keys, duplicate
structural bindings, incomplete locale maps, invalid provenance, or inconsistent
continent references. Callers do not implement fallback truth.

`pfblockerng_uc_countries()` retains its no-argument public entry point and owns
the load, adapter selection, validation, staging, and publication sequence.
Existing `dc`, `gc`, `ugc`, `uc`, install, and update callers do not learn the
JSON schema or provider-locator rules.

### Provider-adapter handoff

Each provider adapter yields one complete family at a time through this exact
normalized row shape:

```text
network:                  canonical CIDR string
country_code:             uppercase code or null
continent_code:           AF|AN|AS|EU|NA|OC|SA or null
represented_country_code: uppercase code or null
anonymous_proxy:          boolean
satellite:                boolean
```

The MaxMind adapter privately resolves location, registered-country,
represented-country, and continent GeoNames IDs. Numeric locators never enter
the truth module, headers, UI, file names, or config. A later IPinfo adapter must
emit the same row shape; no caller changes.

Adapters do not emit or advertise a `Top Spammers` capability. After normalized
country outputs are complete, runtime projects the fixed system-group membership
onto those outputs. The same projection runs for every provider.

An adapter must reject its whole input set on a missing header, missing required
column, duplicate header, wrong field count, invalid CIDR/family, malformed or
ambiguous locator join, conflicting duplicate network, unsupported encoding,
truncation, read failure, or unsupported schema. Rows may not be silently
skipped. Both families are validated before either is published.

Routing is exact:

| Observation | Output identity |
| --- | --- |
| Supported `country_code`, including `XK` | Country code; structural continent comes from truth and provider continent is ignored |
| Missing/unsupported country with usable continent | That continent's `UNK_*` |
| Missing/unsupported country with no usable continent | `UNK_WR` |
| Represented country | Preserve current represented-country output in addition to the direct/registered route |
| Anonymous proxy or satellite | Preserve current `A1`/`A2` provider-specific output outside truth |
| Configured country absent from provider family | Empty country file and `(0)` option; selection unchanged |
| Selected `Top Spammers` member | Reuse that country's ordinary and represented outputs from the active provider; fixed group membership and selection remain unchanged |

Unknown provider country codes are nonfatal observations only after the adapter
has proved the input structurally complete. They route by usable continent or
to `UNK_WR` and participate in change notification; they never create truth.

### World-unknown coverage

For each family, `UNK_WR` is the union of explicit provider rows routed there
and public address space absent from provider coverage. The coverage complement
is built only when World-unknown is enabled for that family:

- IPv4: `0.0.0.0/0` minus all validated provider CIDRs and `/etc/bogons`, using
  the appliance's existing `iprange --except` primitive.
- IPv6: `::/0` minus all validated provider CIDRs and `/etc/bogonsv6`, using the
  existing `pfb_cidr_subtract_v6()` primitive.

The pfSense-owned bogon files are authoritative exclusions. Missing, unreadable,
malformed, or empty exclusion input is fatal for a requested World-unknown
rebuild and preserves its last-known-good generation. Private, reserved,
documentation, multicast, unallocated, and bogon ranges therefore never enter
World-unknown. The complement is canonicalized, sorted, deduplicated, and
validated against both the provider coverage and exclusions before publication.

### Unknown identities and configuration

The continent pages expose their matching `UNK_AF` through `UNK_SA` selections.
Their UI labels are fixed:

| Identity | UI label |
| --- | --- |
| `UNK_AF` | `Unknown (Africa)` |
| `UNK_AN` | `Unknown (Antarctica)` |
| `UNK_AS` | `Unknown (Asia)` |
| `UNK_EU` | `Unknown (Europe)` |
| `UNK_NA` | `Unknown (North America)` |
| `UNK_OC` | `Unknown (Oceania)` |
| `UNK_SA` | `Unknown (South America)` |

Each continent page renders its unknown selection first, followed by ordinary
countries sorted by display name. Ordering is explicit; label text is never a
sort key. This deliberately replaces the current `AA ASIA UNDEFINED` and
`AA EUROPE UNDEFINED` labels, whose `AA` prefix exists only to force that sort
position. `UNK_*` is the internal selection/config identity and is never the
display label.

Reads translate legacy `6255147` to `UNK_AS` and `6255148` to `UNK_EU`; the next
save writes only canonical keys. Existing alias behavior is preserved before
that save. No migration, legacy-value notice, or downgrade guarantee is added.

World-unknown has a generated `pfblockerng_Unknown.php` editor backed by
`installedpackages/pfblockerngunknown/config/0`. Its stable aliases are
`pfb_Geo_Unknown_v4` and `pfb_Geo_Unknown_v6`. It reuses the existing GeoIP
action, interface, logging, and advanced-rule controls. It has no country
picker. `countries4`/`countries6` store `UNK_WR` when the family is enabled and
an empty string otherwise. Reads and writes go through registered structural
section access in `PfbConfig`.

### Change notifications

Register `geoip_change_notifications` in the IP-settings section as a
default-enabled `PfbToggle`. The UI label is **GeoIP change notifications**.
Help text states that it reports significant provider changes which may affect
firewall-rule reliability or effectiveness.

An atomically written, producer-owned runtime ledger records the last
successfully published per-country/per-family empty/nonempty state and the
current unsupported-provider states. This GeoIP state, not any notification,
suppresses unchanged repeats. After a successful publication, compare old and
new ledgers and call `file_notice` only for these edges:

- selected country/family nonzero to zero;
- unsupported/unknown provider state first appears; and
- a GeoIP settings save while a selected country/family is empty.

Current country availability and unsupported/unknown provider conditions are
exposed separately as live GeoIP status. Recovery updates that status but emits
no notification. Notification emission is a one-way handoff; GeoIP never queries,
mutates, dismisses, or otherwise uses the notification as storage. No notification
fires for reboot or unchanged zero-to-zero updates. Disabling the setting suppresses
future nonfatal notifications only. Fatal truth, input, generation, and publication
failures remain visible. The ledger advances only with the output generation it
describes.

### Publication transaction

All output is built beneath a private staging root. Before publication the
pipeline validates file inventory, byte oracles, country and fixed-system-group
membership, every country/bucket family file, both `Top_Spammers` info files,
continent totals, page parseability, coverage complements, `geoip.txt`, and the
GeoIP availability-state ledger. No live target is touched before all checks pass.

Publication runs under the existing GeoIP update exclusion mechanism, snapshots
every replaced target, replaces targets with same-filesystem `rename()`, and
rolls back every replaced target if any write/rename fails. Downstream alias and
page regeneration starts only after the commit completes. Temporary state and
snapshots are removed after success; failures retain diagnostics and the
last-known-good live set.

### Review-only refresh workflow

`.github/workflows/geoip-truth-refresh.yml` runs weekly and by dispatch with one
concurrency group. It calls GitHub's latest-release endpoint, which excludes
drafts and prereleases, and stops before download when immutable tag
`geoip-cldr-checked/<release>` already exists.

For a new stable release it downloads only the release archive URL returned by
GitHub, computes SHA-256, validates licence/source/schema, runs the generator,
and compares normalized bytes:

- unchanged truth: leave the artifact and provenance untouched, create the
  checked tag, and produce no PR or issue;
- changed truth: rebuild one fixed bot-owned branch from current `devel`, commit
  only reviewed generated data/provenance changes, open or update one PR, dispatch
  required CI, then create the checked tag; and
- failure: create no checked tag and open or update one matching open failure
  issue with release, run, and diagnostics.

Failure issues deduplicate only while open. A successful retry closes that open
issue with its run/PR link. Closed issues are never reopened. Truth PRs never
push to `devel`/`main` directly and never auto-merge. PR metadata includes the
release, archive URL, and SHA-256.

Before schedule enablement, evidence must show: a fixture country-name change
makes `--check` report drift; a real dispatch validation failure opens an issue;
and a successful retry closes that same open issue. The workflow uses the
repository's HSTS/PSL refresh shape and adds no service or dependency.

### Approved deltas

Only these observable differences are allowed:

1. CLDR names for all seven locales, with short-form selection for `HK`, `MO`,
   `MM`, and `PN` and the fixed fallback order.
2. Removal of ordinary-country numeric GeoNames IDs from headers and UI rows.
3. Canonical `UNK_*` identities; five new continent-unknown selections; explicit
   unknown-first ordering; replacement of `AA ASIA/EUROPE UNDEFINED` with
   `Unknown (Asia)`/`Unknown (Europe)`; and canonical writes for legacy
   Asia/Europe values.
4. The new `Unknown (World)` editor and aliases.
5. The notification setting and edge-triggered notices.

All network lines, ordering, existing country/continent membership, existing
filenames, existing alias names, existing config roots, and existing generated
page names remain byte-identical for identical provider input. The fixed
`Top Spammers` membership, order, selections, files, page, and alias binding are
also unchanged.

## Hostile-input and invariant matrix

| Axis | Required rows and outcome |
| --- | --- |
| Truth JSON | missing/unreadable; malformed/truncated; invalid UTF-8; duplicate JSON key; unknown/missing key; wrong type; unsupported schema; invalid provenance; each fails before output publication |
| CLDR archive | invalid archive; missing required file/locale/licence; draft/prerelease tag; checksum mismatch; altered licence; inheritance cycle/missing parent; each exits generator `2` |
| Country set | exactly 249 reviewed ISO codes plus `XK`; `AN`/`CS` rejected; missing/extra/duplicate code rejected; `$top_20` must be a subset |
| Fixed system group | exact ordered `Top Spammers` 20-code membership; every code exists in truth; same membership and config under every provider; provider-specific v4/v6 and represented outputs; provider-absent member remains selected and empty |
| Names | seven locales; Unicode/diacritics; `pt-BR`/`zh-CN` mapping; four short forms; missing requested form; missing locale default; English fallback; missing English fails |
| Continents | six recursive CLDR roots; ten frozen overrides; Antarctica country versus `UNK_AN`; zero/multiple membership; unknown override; provider disagreement ignored for supported countries |
| Provider rows | v4/v6; direct/registered/represented; proxy/satellite; supported/unsupported/missing code; known/unknown/missing continent; bad CIDR; duplicate/conflicting network; ambiguous/missing join; truncated/read failure |
| Configuration | unconfigured/configured country; provider-present/absent; legacy `6255147`/`6255148` read and canonical save; all eight `UNK_*`; enabled/disabled notification setting |
| World complement | explicit unknown row; public uncovered space; provider-covered space; each private/reserved/bogon class; malformed/missing/empty exclusion file; IPv4 `iprange` error; IPv6 subtraction error |
| Publication | stage write failure; validation failure; each rename position fails; rollback failure is fatal and loud; no caller proceeds on an incomplete generation |
| Notifications/status | nonzero→zero notification; zero→nonzero status-only recovery; zero→zero; unknown appears notification/resolves status-only/unchanged; reboot; notification transport state does not affect producer decisions; save with empty selection; setting disabled; fatal errors always visible |
| Output | exact `geoip.txt`, per-selection, continent, represented/proxy, generated-page, alias, and log bytes; only Approved deltas excluded |

Every implementation packet enumerates the subset it changes across both
families and all seven locales. Parser, schema, and guard changes carry the
corresponding adversarial rows test-first.

## Acceptance criteria

- The committed JSON regenerates byte-identically from its recorded release and
  checksum; a second generation produces identical bytes.
- Runtime refuses every invalid truth and provider row in the matrix without
  replacing any live output.
- A full pre-swap oracle and post-swap run prove exact `geoip.txt`, country,
  continent, represented/proxy, page, alias, and log bytes except Approved
  deltas.
- `Top Spammers` always exposes the exact fixed 20-country order, preserves its
  per-family selections and `pfB_Top` binding, and derives member networks from
  the active provider. Two normalized provider fixtures with different country
  CIDRs produce the same group definition and their respective network content,
  with no stale or mixed-provider output.
- Exactly 250 countries render under the fixed structural continents. `XK`
  works for selection, both families, localization, provider presence/absence,
  and rendering.
- Every supported locale produces localized display names while structural
  file, alias, page, and config bindings remain English and byte-stable.
- All eight unknown identities work for both families. Every continent page
  renders its exact `Unknown (<Continent>)` selection first, then ordinary
  countries alphabetically. Legacy Asia/Europe reads preserve behavior while
  saving canonically.
- World-unknown contains explicit unknown rows and the public coverage
  complement, and contains no provider-covered/private/reserved/bogon address.
- A configured provider-absent country stays selected, emits empty output, and
  produces only the specified edge-triggered notices.
- Publication-failure tests prove the complete last-known-good generation
  remains active at every failure point.
- Tier-A covers every generated GeoIP page and its concrete rows. Tier-B covers
  the new World editor save/apply flow. Live smoke covers continent-only and
  World-unknown rows end-to-end for v4/v6.
- Exact-head CE and Plus smoke/UI fan-outs are green after the independent
  packaging blocker identified in the baseline is fixed.
- The refresh red canaries and failure-issue retry lifecycle execute successfully
  before schedule enablement.

## Implementation graph

The native issue graph is the execution source.

1. [Capture full GeoIP conversion preservation oracle](https://github.com/pfBlockerNG/pfBlockerNG/issues/1611).
2. [Generate committed ADR-64 GeoIP truth artifact](https://github.com/pfBlockerNG/pfBlockerNG/issues/1613).
3. [Move GeoIP conversion onto truth table and provider seam](https://github.com/pfBlockerNG/pfBlockerNG/issues/1609);
   blocked by 1 and 2.
4. [Add canonical unknown buckets and World editor](https://github.com/pfBlockerNG/pfBlockerNG/issues/1610);
   blocked by 3.
5. [Add edge-triggered GeoIP change notifications](https://github.com/pfBlockerNG/pfBlockerNG/issues/1608);
   blocked by 3.
6. [Automate review-only GeoIP truth refresh](https://github.com/pfBlockerNG/pfBlockerNG/issues/1614);
   blocked by 2.
7. [Prove ADR-64 acceptance on CE and Plus](https://github.com/pfBlockerNG/pfBlockerNG/issues/1612);
   blocked by 4, 5, and 6.

## Out of scope

- Selecting or implementing IPinfo. ADR-32 owns its adapter after this graph
  lands.
- Changing provider network-to-country membership, GeoIP firewall semantics,
  reputation/dedup behavior, the fixed `Top Spammers` membership/order/selection
  semantics, or `Proxy and Satellite`.
- Adding locales or replacing pfSense localization.
- Automatic truth merges, runtime truth downloads, appliance Python, or raw
  CLDR vendoring.
- Rollback from an unreleased 4.0 configuration to 3.2 without the normal full
  backup/restore procedure.

## Open forks

None.
