# Config gateway (PfbConfig) — reference

Scope: PfbConfig gateway contract, storage adapters, field inventory. Load when:
touching config fields, `PfbConfig`, or forward-upgrade behaviour.

Deep reference for ADR-28/29 config-storage adapters and `PfbConfig` gateway: gateway contract,
storage adapter rule, mechanics needed when adding field, preserving behaviour through upgrade,
or checking foreign-key exclusions.

## Gateway contract (ADR-29)

`PfbConfig` (`pfblockerng_extra.inc`) = **single access point for every registered
`installedpackages/pfblockerng*` scalar field**:

- **Read/write/delete via `PfbConfig::read/write/delete($key)`** — never direct
  `config_*_path` on registered key (enforced by
  `PfBlockerNG.Config.RequireConfigGateway` sniff; add registered key ⇒ also add to
  sniff's `$registeredPaths`).
- **Path addressing (issue #1931):** registry keys = `'<alias>/<config-key>'` path
  strings — `'gen/pfb_keep'`, `'ip/suppression'` — alias resolved through
  `PFB_SECTIONS` map (`gen`/`dnsbl`/`ss`/`ip`/`rep`, plus `global`/`sync` since
  issue #2123), single home of seven real section paths. Same-named keys in different
  sections cannot collide — which is what lets #2123 register the DNSBL page's
  `dnsbl/auto*` scalars while the identically named per-feed-row and per-continent keys
  stay foreign. Bare-name lookups throw (`InvalidArgumentException`) — no dual
  addressing. Entries carry no `section` attribute; key prefix outside `PFB_SECTIONS`
  fails `CfgGatewayTest`'s alias gate. Pre-change tuple parity pinned by
  `tests/php/fixtures/cfg_registry_pre1931_parity.json`.
  `global` (`installedpackages/pfblockerngglobal`) and `sync`
  (`installedpackages/pfblockerngsync/config/0`) each hold ONE registered key beside
  otherwise-foreign siblings — the same arrangement `rep` has: an unregistered sibling
  passes a section write through byte-identical, and adding an alias does not register
  the section.
- Section helpers (`readSection`/`writeSection`/`deleteSection`) for whole-section,
  non-per-field access. Unregistered key → `InvalidArgumentException`.
- **No `write_config()` inside gateway** — caller decide when to flush. Registry
  (`pfb_cfg_registry()`) read-only after boot.

## Write authorization (issue #1895)

Authorization = property of **write**, not call site (generalises
`pfblockerng_hook_edit.inc` GATE 1 precedent):

- Every registry entry may carry optional `write_priv` — page whose privilege the
  write re-asserts via `isAllowedPage()`. Absent means `PfbConfig::WRITE_PRIV_DEFAULT`
  (`pfblockerng/pfblockerng_general.php`, package page — pfSense grants all
  pfBlockerNG pages through one privilege entry, so finer per-page defaults meaningless).
  Explicit override: `pfb_software_check` → `pkg_mgr_installed.php` (#485
  Software-page secondary gate) — the control lives on the Software page.
- `PfbConfig::write()` / `writeSection()` enforce **fail-closed**: undefined
  `isAllowedPage()` (no web session — `priv.inc` only in web auth include chain)
  or FALSE return throws `RuntimeException`. `writeSection()` checks every registered
  field of section present in `$data` before any mutation. Loud throw deliberate:
  silent-FALSE alternative = exactly the CLI trap #1895 documents.
- `PfbConfig::writeSystem()` / `writeSectionSystem()` skip check — sanctioned
  path for cron, install/deinstall hooks, migrations, CLI, pfSense-core hooks
  (`pfb_alias_rename_followup()` runs from `firewall_aliases_edit` pre-write hook
  under firewall-alias-only privilege, so enforcement there breaks supported
  path). Bypass visible at call site, mechanically confined:
  `RequireConfigGatewaySniff` (`SystemWriteInWww`) refuses `*System()` variants in
  any file under `src/usr/local/www/`.
- `delete()` / `deleteSection()` carry no privilege check (outside #1895 scope).
- **`writeSection()`'s gate delta-aware** (issue #1895 addendum, found reviewing
  composition against `pfblockerng_general.php`'s whole-section readSection → modify one
  field → writeSection() save): registered field present in `$data` asserts its
  `write_priv` only when canonical incoming value differs from canonical
  currently-stored value (both sides run same read/write-adapter
  round-trip); unchanged read-modify-write pass-through (e.g. `pfb_software_check`
  riding along untouched while General page saves unrelated field) is not
  authorization event, silently skipped. `PfbConfig::write()` stays **strict** —
  explicit single-key write always authorization event, changed or not, since
  no read-modify-write section saver behind it.
- Coverage: `tests/php/CfgWriteAuthorizationTest.php` (deny/allow per entry point,
  per-field override, priv.inc-loaded CLI-trap regression, write/writeSystem
  parity, delta-aware pass-through/real-change/absent-vs-default rows) + sniff
  fixtures in `tests/php/RequireConfigGatewaySniffTest.php`.

## Storage adapter rule (ADR-28 §2.2)

- **Storage NOT frozen — forward-upgrade compatible where practical, not byte-for-byte.**
  No versioned migration routine. New options add new stored strings; read-boundary adapters
  absorb legacy tokens, writes emit canonical token (may differ from legacy one
  when behaviour-equivalent). Goal: preserve *behaviour* on upgrade, not bytes.
- **Forward-compat (upgrade) has two cases:** existing config with key absent reads to
  value that **preserves that user's prior behaviour**; brand-new config gets new
  default. When those differ, registry entry carries `grandfather` map (issue #1921)
  applied by one-pass registry reconciliation for existing installs at upgrade (bespoke
  `pfb_rdns_seed_value` cross-section seed = exception, stays hand-written),
  so absent-default never silently changes existing user's behaviour.
- **Canonical current storage.** Read adapters accept legacy tokens needed by supported forward
  upgrades; writes emit current canonical token. They do not constrain new storage to what
  older package understands.
- **Adapter presence owns empty-string semantics (issue #2120).** Genuinely absent/`NULL`
  value resolves to registry default before every read adapter. Stored `''` reaches
  adapter-bearing entry's read adapter, while plain scalar still treats `''` as not configured
  and resolves to registry default. `PfbConfig::read()` never exposes absence. Writing
  `NULL` to adapter-bearing entry deletes that key (section write omits it), so absence
  stays truthful instead of materialising default; plain-scalar behaviour unchanged.
- Enums/booleans = **internal runtime representation**; conversion at boundary:
  stored string → enum on read; enum → canonical stored string on write.
- **Enum owns its stored-value semantics** via `PfbStoredEnum` interface +
  `PfbStoredEnumAdapter` trait: `EnumClass::fromStored($raw)` (read) and `$enum->toStored()`
  (write). Per-field **absent default** = registry's `$entry['default']` (applied by
  `PfbConfig::read()` *before* adapter); enum's `default()` only
  **parse-fallback** for unknown/non-scalar tokens, never absent-default. Field's `''`
  vs `'off'` off-value handled by its own enum.
- **Round-trip pinned by tests** (`CfgAdaptersTest`): every canonical
  token round-trips (`write(read(v)) == v`); legacy token reads to right runtime value
  and writes to its behaviour-equivalent canonical token.
- **Explicitly out of scope (ADR-28 §2.4):** `config.xml` versioned schema/migrations;
  `py_unbound.ini` and any manifest/serialized/wire value read by Python or shell; ADR-26
  locale prefixes; genuine boolean predicates (return `bool`, not enum); mass realignment
  of untouched lines; `stubs/`, generated artifacts, vendored code.
- Per-field adapter inventory, field-vocabulary table, forward-upgrade invariants: sections below.

## Adapter inventory (field → enum)

- **PHP adapters / enums** (`PfbToggle`, `PfbIdnMode` + thin `pfb_cfg_*_read/write`
  delegations) in `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc`:
  - Every ADAPTER-CARRYING checkbox field → `PfbToggle` (issue #1887 merged former
    `PfbLenient` into it). Read deliberately narrow and case-insensitive: `on` in any
    case = `On`; every other present token (`''`, legacy `'off'`, junk) = `Off`.
    Only genuine absence consults field's registered default. Writes emit `'on'` for
    `On` and canonical `''` for `Off`; `'off'` accepted forever but never written
    (issue #2120, deliberately reversing #1887's explicit-`'off'` writer). Enum's
    `Off = 'off'` backing value remains its internal/render identity. Runtime `$pfb[]`
    toggle mirrors carry
    enum itself (never `->value`), so consumers compare `=== PfbToggle::On`.
    Registered checkbox fields still on `NULL`/`NULL` adapters (e.g. `pfb_regex`,
    `pfb_noaaaa`, `pfb_gp`, `pfb_py_nolog`, `tld_wildcard`, `top1m_enable`)
    keep raw `{'on', ''}` storage until they adopt pair — field joining
    adapter set moves all its consumers in same commit (see below).
  - **The seventeen #2123 relocations.** `PFB_FILTER_ON_OFF` save sites whose default,
    stored vocabulary and render comparison were still declared in the page (the 3.2
    arrangement) now read through the registry: `ip/{enable_dup,enable_agg,enable_log,`
    `enable_rdns,database_cc,enable_float,killstates}`,
    `dnsbl/auto{addrnot,ports,addr,not}_{in,out}` (the DNSBL page's two Advanced
    Firewall Rule panels), `sync/syncinterfaces`, and `global/alertrefresh`. Sixteen
    default `''`; `alertrefresh` defaults `'on'`, so absence reads On while an
    operator's stored `''` reads Off — the same shape as the nine below. Each save site
    keeps its `pfb_filter(…, PFB_FILTER_ON_OFF, …) ?: ''` (transport normalisation of a
    POST-absent checkbox, re-normalised by `writeSection()`); what moved is the READ
    default. Regrowth blocked by `scripts/check_toggle_registry.py` (below).
    Issue #2817 completed the runtime side: the seven IP consumers and the DNSBL
    settings-section `auto*` branch use `PfbConfig::read()`. Identically named
    per-feed-row and per-continent fields remain foreign; their direct reads pass
    through `pfb_dnsbl_toggle_enabled()` so they share the registered vocabulary.
  - **Ten adapter-bearing toggles default On:** `pfb_keep`, `pfb_software_check`,
    `pfb_feed_internal_filter`, `pfb_syntax_highlight`, `pfb_cache`, `pfb_py_reply`,
    `pfb_hsts`, `pfb_idn_block_malicious`, ip-section `suppression`, and (since #2123)
    `global/alertrefresh`. For all ten,
    absence reads On while stored `''` reads Off. Six former `'' => 'off'`
    grandfather arms (`pfb_keep`, `pfb_cache`, `pfb_py_reply`, `pfb_hsts`,
    `pfb_idn_block_malicious`, `suppression`) retired by #2120 because runtime
    adapter now preserves that legacy uncheck and canonical writes use `''`; separate
    `pfb_keep` absent → `'on'` grandfather remains. `pfb_py_reply`/`pfb_hsts`
    additionally get `issue1907-python-gated-toggles`
    migration: stored `'on'` beside pre-upgrade `dnsbl_mode` that is present and not
    `'dnsbl_python'` was inert (both consumers python-gated in 3.2) and is disabled
    before ADR-02 python force would otherwise activate it.
  - **`pfb_cache_flush` → `PfbToggle`**: default Off; enables post-handshake full Unbound
    cache flush for bulk zero-downtime DNSBL data swaps.
  - **`enable_rep`/`enable_pdup`/`enable_dedup` → `PfbToggle`** (issue #1896, Reputation
    "Max"/"pMax"/"dMax" toggles): default Off. Section
    (`pfblockerngreputation/config/0`) also holds unregistered scalars (`p24_*_var`,
    `ccwhite`/`ccblack`/`ccexclude`, `et_update`, `et_header`/`etblock`/`etmatch`) — only
    these three toggles registered; Reputation settings page's read/write routes
    through `PfbConfig::readSection()`/`writeSection()` so the three normalise while rest
    pass through byte-identical (direct section-level reads elsewhere stay legal —
    sniff gates exact key paths only).
  - **`pfb_alias_delta_mode` → `PfbAliasDeltaMode`** (ADR-40, registry adapters
    `pfb_cfg_alias_delta_mode_read/write`): tokens `'auto'` (new-install default) / `'delta'` /
    `'replace'`. Unknown or absent token reads as `Auto`. **Grandfather:** already-configured
    install pinned to `'replace'` (pre-ADR-40 full `-T replace`) by registry entry's
    `grandfather => [PFB_GF_ABSENT => 'replace']` map, applied once by registry pass at
    install/upgrade — so only brand-new install takes `'auto'` absent-default;
    upgrade keeps full replace.
    `pfb_alias_delta_batch` (plain string, `NULL`/`NULL` adapters) = batch-size companion
    field; stored value is decimal integer string, clamped to `[64, 4096]` at read time by
    `pfb_alias_delta_batch_clamp()`.
  - **`pfb_reentry_timeout`** (issue #2851, plain string — `NULL`/`NULL` adapters): the ONE
    global budget (whole seconds) for every nested `pfblockerng.php` re-entry an update pass
    launches — GeoIP, blacklist, TOP1M, ASN alike, no per-subsystem override. Default
    `'1800'` = the budget issue #2016 hardcoded, so an absent key preserves an upgrader's
    wait exactly (hence `no_grandfather`). Normalized at read time by
    `pfb_reentry_timeout()` (`pfblockerng.inc`): whole seconds in `[60, 7200]` pass
    through, everything else — absent, `''`, non-integral, signed, padded, zero, negative,
    out-of-range, 64-bit-overflowing, non-scalar — resolves to `1800`, never to no timeout.
    `pfblockerng_general.php` canonicalizes the POST through the same function, so the
    stored value is always the effective one. `pfblockerng.sh`'s own
    `pfb_reentry_timeout()` mirrors the window and default for the shell seam (it reads the
    key via `read_xml_tag.sh` — shell has no gateway); `ReentryTimeoutSettingTest` pins the
    two windows against each other.
  - **`pfb_idn` → `PfbIdnMode`** (registry adapters `pfb_cfg_idn_mode_read/write`): live
    cases `'on'` (= All), `'confusable'`, Off. `All` **reuses original `'on'`** block-all
    token, so current code reading pre-4.0.0 configuration preserves block-all with no
    migration. `PfbConfig::read('dnsbl/pfb_idn')` returns enum;
    `PfbConfig::write()` and `py_unbound.ini` build both emit `toStored()`: Off → `''`,
    All → `'on'`, Confusable → `'confusable'`. Reads accept both `''` and legacy `'off'`
    as Off. 4.0.0-alpha-only `'all'` token **not** carried (alpha compatibility
    intentionally not maintained) — like other unrecognised junk, keeps enum's
    existing `default()` fallback to Off. Consumers compare `=== PfbIdnMode::All` /
    `::Confusable`; form rendering uses enum's backing `->value`, not its storage token.
  - **`top1m_source` → `PfbTop1mSource`** (issue #877 review, registry adapters
    `pfb_cfg_top1m_source_read/write`): tokens `'tranco'` (default) / `'cisco'` /
    `'openpagerank'` (#928, replacing ADR-59 P4's `'domcop'`) /
    `'majestic'` (added ADR-59 P4) / `'cloudflare'` (added ADR-59 P5, first
    token-authenticated provider). TWO tokens READ-only, never re-emitted by write —
    `'alexa'` (dead Alexa TOP1M service, #872) coalesces to `Tranco`, and `'domcop'`
    (DomCop TOP1M list's hosting moved to OpenPageRank, #928) coalesces to
    `OpenPageRank`; `fromLegacy()` coalesces any other unknown/absent token to `Tranco`.
    Stored key was `alexa_type` until issue #1898 renamed it (see "Stored-key
    vocabulary" below); legacy *tokens* unaffected by that rename.
  - **`top1m_token`** (ADR-59 P5, plain string — `NULL`/`NULL` adapters): masked,
    write-only credential (currently consumed only by `cloudflare` `top1m_source`,
    ignored by every other provider), fed to `pfb_download()` via `pfb_top1m_auth_headers()`
    and ADR-59 P3 header-auth plumbing (`Authorization: Bearer <token>`). Default `''`.
    Never echoed back on GET (`pfblockerng_dnsbl.php`); blank POST preserves
    existing stored value rather than clearing it — field has no "off" state to
    round-trip, just identity pass-through like any other plain field. Validated on POST
    by `PFB_FILTER_TOKEN` (`pfblockerng.inc`) — base64url/JWT charset
    (`[A-Za-z0-9._~+/=-]`), NOT `PFB_FILTER_WORD` (which would reject real token).
- **Python** (`pfb_unbound.py`): **`IdnMode` enum** keeps internal cases
  `All = 'on'`, `Confusable = 'confusable'`, `Off = 'off'`. Present empty or legacy
  `'off'` ini value reads Off; absent `idn_mode` and unrecognised junk retain legacy
  `python_idn` fallback. Toggle enum has
  **no Python consumer** (`config.getboolean()` reads all bool toggles), so PHP-only adapter.

## Adding a new registered field

1. Add entry to `pfb_cfg_registry()` keyed `'<alias>/<config-key>'` (alias from
   `PFB_SECTIONS`; config-key part = exact `config.xml` key), with default
   stored string and adapter pair (or `NULL`/`NULL` for plain string).
   Giving EXISTING field an adapter changes what `read()` returns for it (enum, not
   string), so every consumer of that field moves in same commit — stale string
   comparison against enum fails silently in always-false direction (issue #1887).
2. Verify round-trip: `write(read(v)) == v` for every canonical stored vocabulary value.
   When field's owning page carries secondary privilege gate (like Software
   page), set `write_priv` on entry (see "Write authorization" above).
3. Add test in `tests/php/CfgGatewayTest.php` (round-trip + default-absent cases).
4. Update `$inventory` in `testInventoryCompletenessAllKnownKeysAccountedFor()`.
5. Classify grandfathering decision on entry itself — `grandfather` map or
   `no_grandfather` reason (issue #1921; trigger question under "Forward-upgrade
   contract"). `CfgRegistryGrandfatherGateTest` fails suite on unclassified entry.

When adding registered key, also add its full path to `$registeredPaths` property in
`tests/phpcs/PfBlockerNG/Sniffs/Config/RequireConfigGatewaySniff.php` (enforcement sniff).

### The toggle-contract gate (issue #2123)

`scripts/check_toggle_registry.py` keeps the on/off contract from growing back into the
pages. Wired into `.github/workflows/test.yml`, `.githooks/pre-commit` and
`scripts/agent/run-gates.sh`; covered by `tests/test_toggle_registry_check.py`.

- **RULE 1** — a `$pfb['<mirror>']['<key>'] = … PFB_FILTER_ON_OFF …` save into a section
  that `PFB_SECTIONS` knows MUST name a registered key. So a new settings checkbox
  cannot land without a registry entry.
- **RULE 2** — a registered field's default MUST NOT be restated by the page: no
  `$pconfig[…] = $pfb['<mirror>']['<key>'] ?: '<literal>'` and no
  `isset($pfb['<mirror>']['<key>']) ? … : '<literal>'`. Read it with `PfbConfig::read()`.
  issue #2994 widened this from toggles to every registered key after aligning the
  six page/registry scalar divergences (`pfb_dnsport`/`pfb_dnsport_ssl`/`aliaslog`
  follow the page, and a fresh install now seeds those values; `pfb_dnsbl_rule` keeps
  registry `Disabled`; `pfb_dnsvip4/6` store `''` and map the Form_Select sentinel
  `none` after the gateway read). The matchers require a literal key; a dynamic
  `$pfb['gconfig']['log_max_' . $suffix]` restatement is a documented ceiling, not a
  clean scan of those sites.
- The mirror → alias mapping is DERIVED from each page's own
  `$pfb['<mirror>'] = PfbConfig::readSection('<path>')`, so a new page needs no edit here.
- Fails CLOSED: an unreadable registry, an unparseable `PFB_SECTIONS`, or fewer than 100
  parsed keys exits 2 rather than reporting clean.
- `--self-test` is the red canary — a synthetic violating page must trip BOTH rules — and
  runs before the real scan in every wiring.
- Exemptions live in the checker's `EXEMPT` table, each with a reason;
  `test_every_exempt_row_still_names_a_live_site` fails on a stale row.

`tld_allow_sort` and `tld_allow_{gtld,cctld,itld,bgtld}` = plain registered scalars (`NULL`/
`NULL` adapters) since issue #1921 — previously on foreign-key exclusion list
below. They still stay legal on `pfblockerng_dnsbl.php`'s direct section-blob read/write (gateway
does not require every registered field to move its consumers in same step); registration
exists for `old_name` parity with rest of `pfb_pytld*` rename family.

## Forward-upgrade contract

Gateway preserves existing behaviour while configurations move forward:

- **Legacy-read invariant** (old store → new code): `PfbConfig::read($key)` on any supported
  legacy stored token returns well-formed runtime value — no crash, correct type, sane default
  for absent. Issue #2120 deliberately reverses #1887's `''`-equals-absence identity for
  adapter-bearing entries only: genuine absence resolves to registered default; stored
  `''` reaches adapter. Plain scalars retain #1887 identity. Shared normalization
  still makes `read()`, `write()`, `writeSection()` agree on same distinction.
- **Grandfather invariant (issue #1921)**: when absent current default — or raw legacy
  stored value — would change established behaviour, registry entry carries
  `grandfather` map: raw stored value → new value, with dedicated `PFB_GF_ABSENT` marker
  keying genuine absence (PHP array literal coerces `NULL` key to `''`, so absence needs
  explicit marker). One-pass registry reconciliation (below) applies map once at
  install/upgrade; unmapped values pass through unchanged. **Trigger is "did the
  behaviour this field controls change for someone upgrading?", never "did this key exist
  before?"** — field introduced in 4.0 to make previously *hardcoded* behaviour
  configurable is highest-risk case, not safe one, because its new-install default is
  chosen for new installs while every upgrader lived under old hardcoded behaviour.
  Shipped maps:

  | Field | Grandfather map | Why |
  | --- | --- | --- |
  | `gen/pfb_keep` | `[ABSENT => 'on']` | #281 upgrade keeps settings; #2120's runtime adapter owns the legacy `''` uncheck |
  | `gen/pfb_alias_delta_mode` | `[ABSENT => 'replace']` | ADR-40 — an upgrade keeps the pre-ADR-40 full replace |
  | `dnsbl/pfb_dnsbl_lenient` | `[ABSENT => 'on']` | ADR-22 — an upgrade keeps permissive parsing |

  **Every entry carries its decision.** Exactly one of `grandfather` map or
  `no_grandfather` reason string per registry entry, with two exceptions carrying neither:
  `gen/settings_family` (mode instrument, recorded by `pfb_settings_family_record()`)
  and `dnsbl/pfb_control_legacy` (PFBL-03 cross-key bespoke seed).
  `tests/php/CfgRegistryGrandfatherGateTest.php` enforces partition **totally** — new
  registered field with neither fails suite — plus **fixpoint rule** (no map output
  is also map input; `['on'=>'off','off'=>'on']` would oscillate across reinstalls) and
  `old_name` parity. Issue #1920's one-time 103-row audit thereby a standing gate.

  **Ordering is branch order, not pass order.** Former three-stage hazard (rename
  migration, then grandfather helpers, then seeding pass, mutual order pinned
  by a test) structurally gone: `pfb_registry_pass()` does rename → grandfather-map →
  seed as branch order inside one loop (see "The registry pass" below).
- **Canonical-write invariant**: current code writes current canonical representation.
- **Canonical-name invariant** (issue #1898): registered key's *name* = current domain
  vocabulary too, not frozen historical spelling. Renaming one ships one-time post-install
  migration in `pfb_migration_registry()`; after it runs, current code reads and writes only
  new name — no dual-read, no fallback, no shadow copy (see "Stored-key vocabulary" below).

Package downgrade unsupported. Current normalized state not rewritten for older
package, and adapters need not emit old-package-compatible tokens. Before upgrading, keep
pfSense configuration backup. If older package cannot consume upgraded state, restore
pre-upgrade backup or reinstall current package and continue forward.

### Section writes are normalised too (issue #930)

`PfbConfig::writeSection($section, $data)` applies **same** canonical normalisation
as single-key `PfbConfig::write()` — for every key in `$data` registered to EXACT
target `$section` (same-named key registered to *different* section = foreign data,
left untouched) and carrying **both** read and write adapter, value round-trips
`read_adapter()` then `write_adapter()` before section persisted. Key with no adapter
pair (plain string) or not present in `$data` passes through byte-identical; `writeSection()`
never calls `write_config()`.

For adapter-bearing key, explicit `NULL` removes that key from section before
section persisted; omitted key remains omitted. Matches single-key `write(NULL)`
deletion. Plain registered scalars retain existing byte-preserving section behavior.

Before this fix, `writeSection()` called `config_set_path($section, $data)` directly, bypassing
every adapter — legacy read-only token (`top1m_source` `'domcop'`/`'alexa'`, `pfb_idn` alpha-only
`'all'`) or hostile/junk value riding **any** section-blob write (`www/` save handler,
install seed, migration) persisted raw into `config.xml` instead of being coalesced to
canonical form. Consequently, legacy token riding `readSection()` → `writeSection()`
round-trip (restored backup, HA sync, hand-edited `config.xml`) coalesces to canonical
on next save — does not perpetually re-emit itself just because write went through
section-level helper instead of per-key one.

Coverage: `tests/php/CfgGatewayTest.php` — property test iterating `pfb_cfg_registry()` itself
(every adapter-bearing field × canonical/legacy/junk sample set, compared against
`PfbConfig::write()` oracle) plus targeted scenario and hostile-input tests (legacy `top1m_source`
tokens, alpha-only `pfb_idn`, non-scalar/`NULL`/enum-instance/int value, unadapted key,
same-named key in foreign section, mixed realistic section blob).

## Stored-key vocabulary (issue #1898)

ADR-29 §5 originally froze registry keys at "the EXACT existing `config.xml` keys (no renames)"
so 4.x code could share `config.xml` with 3.2.x package family. Owner retired that goal
on 2026-07-30 — downgrade safety now comes from settings-family snapshots
(`pfb_settings_family_save()` / `_replace()`), not from perpetuating obsolete spelling. Stored
keys therefore carry **current** domain vocabulary; existing installation carried
forward by one migration.

**The 15 retired names.** Four landed decisions had frozen a stored key while runtime/UI
vocabulary moved on: dead-Alexa TOP1M cluster (#872/#877), ADR-66 §2.1/§2.2's TLD Allow
and TLD Wildcard families, and DNSBL whitelist blob (stored as `suppression` until
issue #1921 renamed it to its true name).

| Old stored key | Current stored key |
| --- | --- |
| `alexa_enable` · `alexa_type` · `alexa_count` · `alexa_inclusion` | `top1m_enable` · `top1m_source` · `top1m_count` · `top1m_inclusion` |
| `filter_alexa` (dynamic `pfblockerngdnsbl/config/{row}`) | `filter_top1m` |
| `pfb_pytld` · `pfb_pytld_sort` · `pfb_pytlds_{gtld,cctld,itld,bgtld}` | `tld_allow` · `tld_allow_sort` · `tld_allow_{gtld,cctld,itld,bgtld}` |
| `pfb_tld` · `tldblacklist` · `tldexclusion` | `tld_wildcard` · `tld_wildcard_blacklist` · `tld_wildcard_exclusion` |
| `suppression` (DNSBL settings section) | `whitelist` |

**Scalar renames are `old_name` slots (issue #1921).** Every retired *scalar* spelling lives
as `old_name` slot on its registry entry; rename = first branch of registry
pass (below), so no later branch can ever observe value still under old name. One
per-feed **row** rename (`filter_alexa` → `filter_top1m`) stays a migration —
`PFB_LEGACY_KEY_RENAMES` + `pfb_legacy_key_rename_migrate()`, `issue1898-legacy-key-rename`
entry in `pfb_migration_registry()` — because feed rows are not registered scalars; that
migration keeps original #1898 semantics: per-row preflight, all-or-nothing across rows,
fail-closed on conflicting pair with `file_notice()` naming keys and never values.
`CfgRegistryGrandfatherGateTest`'s `old_name` parity pins retired-spelling set.

## The registry pass (issue #1921)

`pfb_registry_pass()` (`pfblockerng.inc`) replaces rename migration's scalar half,
grandfather helpers, and #1898 seeding pass with **one registry-driven loop**, called at
end of `pfblockerng_install.inc` after `pfb_run_migrations()` and after ADR-53
`pfBlockerNGSuppress` alias conversion (which keys on literal absence of
`ip/v4suppression` and must observe pre-pass state). After restoring the target settings
family, the installer captures each section's mode before migrations via
`pfb_registry_section_modes()` and supplies it to the pass:
`OLDCFG` iff the pre-migration section was non-empty under `pfb_gconfig_operator_view()`
(installer's `settings_family` marker never reads as operator data — #1770/#1771/#1775).
Direct callers that omit the mode map retain the original behavior of computing it from
the pass input. Per key:

- **NEWCFG** — seed registry default (stabilised through entry's own grandfather map
  so seeded value can never be re-mapped by later run).
- **OLDCFG** — rename (`old_name` value moves verbatim, `''` and `'0'` included;
  conflicting pair keeps new name, leaves old in place, raises one
  `file_notice()` naming keys, never values — per-key, not all-or-nothing); then
  grandfather map (`PFB_GF_ABSENT` covers genuine absence; unmapped values identity;
  `''` is stored value and moves/maps as one); then seed default if still absent.

Idempotent by construction: present key short-circuits everything except conflict
warning, and gate's fixpoint rule guarantees map output never a map input. Pass
returns only changed sections; caller persists them via `PfbConfig::writeSectionSystem()`
(pass's output riding adapters deliberate — that is what coalesces renamed key's
legacy token, e.g. `top1m_source` `'alexa'` → `'tranco'`).

**Migrations persist raw.** `pfb_run_migrations()` and every legacy-reshape write earlier in
`pfblockerng_install.inc` persist via `PfbConfig::writeSectionRawSystem()` (direct
`config_set_path()`, no adapter round-trip) — adapter-riding write-back before pass
would canonicalise bystander legacy token (for example `top1m_source = 'alexa'`) before
registry pass can inspect it. Canonicalisation is pass's job. Pinned by
`tests/php/InstallPrePassWriteOrderTest.php` (no `writeSectionSystem` before
pass call in installer) and raw-bystander regression in
`MigrationRegistryTest`.

**What stays outside the loop:**

| Piece | Why | Fate |
| --- | --- | --- |
| PFBL-03 `pfb_control_legacy_seed()` | cross-key: value depends on `pfb_control`, plus its own run-once marker | migration; runs before the pass, which then sees the key present and skips |
| `issue1907-python-gated-toggles` | cross-key: stored `'on'` + pre-upgrade `dnsbl_mode` present and ≠ `'dnsbl_python'` → `'off'` | migration; MUST run before the ADR-02 python force, which overwrites the `dnsbl_mode` evidence |
| ADR-02 python-mode force | not a grandfather — forces unregistered keys regardless of value | migration, after the #1907 exception |
| Row rename `filter_alexa` → `filter_top1m` | feed rows are not registered scalars | the residual `issue1898-legacy-key-rename` migration |
| `gen/settings_family` | the mode instrument, valued by the installing package | recorded by `pfb_settings_family_record()`; the pass skips it entirely |

**Consequence for future fields:** after pass, bare `!isset($cfg[$key])` no longer means
"existing install that predates this setting". New grandfather decides from *value*
via its map, or from dedicated one-shot marker (`pfb_control_legacy_seeded`'s shape), never
from key absence. Same applies to whole-section emptiness: `pfb_dnsbl_python_migrate()`
and `pfb_control_legacy_seed()` use `empty($dconfig)` as fresh-install discriminator,
so on install *after* fresh one they fire against seeded section and write their
(vestigial) `dnsbl_mode` / `pfb_py_block` / `pfb_control_legacy_seeded` keys. Behaviour
unchanged — `pfb_control_legacy` still only set when `pfb_control` is `'on'`, which a
seeded section is not — but write is spurious. New run-once logic uses marker, not
emptiness.

Coverage: `tests/php/RegistryPassTest.php` (mode, grandfathers, rename branch, idempotency,
hostile rows), `tests/php/CfgRegistryGrandfatherGateTest.php` (partition totality, fixpoint,
`old_name` parity), `tests/php/MigrationRegistryTest.php` (driver, raw persistence, #1907
ordering), `tests/php/LegacyKeyRenameMigrationTest.php` (row rename).

## Field vocabularies

| Adapter type | Stored vocabulary |
| ------------ | ----------------- |
| `toggle`            | write `{'on', ''}`; case-insensitive `on` read; `''`, legacy `'off'`, and junk → Off; only absence → registered default |
| `idn`               | write `{'on' (=All), 'confusable', '' (=Off)}`; legacy `'off'` → Off; unrecognised `'all'`/junk keep the Off fallback |
| `alias_delta_mode`  | `{'auto', 'delta', 'replace'}` — unknown/absent token reads as `'auto'` (ADR-40, since 4.0.0) |
| `top1m_source`      | write `{'tranco' (default), 'cisco', 'openpagerank', 'majestic', 'cloudflare'}` (majestic ADR-59 P4, cloudflare ADR-59 P5, openpagerank replaced P4's domcop in #928); legacy read `'alexa'`→Tranco (dead service, #872) and `'domcop'`→OpenPageRank (list moved hosting, #928), neither re-emitted |
| `plain`             | identity — any stored value passes through unchanged |

**Excluded fields** — none. `pfb_idn` previously excluded (`NULL`/`NULL` identity adapters);
now adopted as `PfbIdnMode` (see ADR-28 §2.2). `All` reuses legacy `'on'` token, so
adoption migration-free for supported upgrades. `top1m_source` similarly moved off plain-string
read-boundary coalesce onto `PfbTop1mSource` enum (issue #877 review) — same shape, no migration.

## Foreign-key exclusion list (use `config_*_path` directly — NOT via `PfbConfig`)

Following `installedpackages/pfblockerng*` paths **not** registered in `pfb_cfg_registry()`
and stay on direct `config_*_path`. Enforcement sniff does NOT flag them (not in
registered path set). Each annotation committed in relevant source file.

| Section / Key | Reason |
| --- | --- |
| `pfblockerngdnsbl/config/{row}/custom` | Dynamic per-row key, not in registry |
| `pfblockerngdnsbl/config/{row}/logging` | Dynamic per-row key, not in registry |
| `pfblockerngdnsbl/config/{row}/filter_top1m` | Dynamic per-row key, not in registry (renamed from `filter_alexa`, issue #1898) |
| `pfblockernglistsv4/config/{row}/custom` | Dynamic per-row key, not in registry |
| `pfblockernglistsv6/config/{row}/custom` | Dynamic per-row key, not in registry |
| `pfblockerngdnsbl` (section-level) | Dynamic per-feed list section |
| `pfblockernglistsv4` / `pfblockernglistsv6` (section-level) | Dynamic per-feed list sections |
| `pfblockerngsync/config/0/row/*` | Dynamic XMLRPC row blob, not in registry |
| `pfblockerngglobal/widget-*` | Dashboard widget keys, not in registry |
| `pfblockerngblacklist/*` | Entire section is foreign (not in registry) |
| `pfblockerngglobal/feed_*` + `feed_alt_*` | Dynamic alias-name keys, not in registry |
| `pfblockerngglobal` (section-level) | Dynamic feed-key section |
| `pfblockerng_wizard/*` | Wizard temp section, entirely foreign |
| `installedpackages` (bulk blob) | Bulk wizard init write, foreign structure |
| `pfblockerng{continent}/config/0` | Dynamic per-continent structure |
| `pfblockerngdnsblsettings/config/0/dnsbl_webpage` | Out-of-scope foreign key (ADR-29 §2.5); written directly by `pfblockerng_dnsbl.php`, read via `pfb_dnsbl_webpage()` (issue #713 removed the never-written `dnsblwebpage` registry mis-spelling) |
| `pfblockerngdnsbl` / `pfblockernglistsv4/v6` (section-level reads) | Dynamic list sections |
| `aliases/alias`, `filter/rule`, `system/*`, `interfaces`, `unbound/*` | pfSense core sections |
| `pfblockernglistsv4/v6/config/{row}/auto{addrnot,ports,addr,not}_{in,out}` | Dynamic per-row keys (issue #2123: same bare names as the registered `dnsbl/auto*` scalars; `pfblockerng_category_edit.php` writes them at `installedpackages/{$conf_type}/config/{$rowid}/…`, a path no exact-path registry entry can address). Runtime reads stay direct and normalize through `pfb_dnsbl_toggle_enabled()` (#2817). |
| `pfblockernglistsv4/v6/config/{row}/whois_convert` + `filter_top1m` | Dynamic per-row `PFB_FILTER_ON_OFF` keys, same reason |
| `pfblockerng{continent}/config/0/auto*` | Dynamic per-continent structure (issue #2123: `pfblockerng_geoip.inc` writes the same bare names per continent). Runtime reads stay direct and normalize through `pfb_dnsbl_toggle_enabled()` (#2817). |
| `pfblockerngsync/config/0/{varsynconchanges,varsynctimeout}` | Foreign siblings of the registered `sync/syncinterfaces` |
| `pfblockerngglobal/*` except `alertrefresh` | Foreign siblings of the registered `global/alertrefresh` (display prefs, `pfbextdns`, and the dynamic `feed_*`/`widget-*` keys) |

## Sniff file-scope exclusion — `pfblockerng_extra.inc` / `pfblockerng_migrate.inc`

Distinct from per-path foreign-key list above: `RequireConfigGatewaySniff` excludes these two
**whole files** from its scan (see PHPCS sniff entry in `.agents/policy/coding.md` → "Linting"),
originally because `pfblockerng_extra.inc` hosts `PfbConfig` itself (gateway can't call
through itself) and `pfblockerng_migrate.inc` predates registry. `pfblockerng_extra.inc` has
since grown well beyond gateway — also hosts real dispatch/scheduling logic (e.g.
ADR-43 due-ledger API and `pfblockerng_tick()`). That code is registered-field-adjacent (reads
`pfb_interval`/`pfb_quiet_hours` via `PfbConfig::read()` already) but sniff
cannot enforce it there — any new code landing in this file must self-police `PfbConfig` usage for
registered keys (direct `config_get_path`/`config_set_path` on one is rule violation sniff
will not catch); rely on manual review, not mechanical gate.
