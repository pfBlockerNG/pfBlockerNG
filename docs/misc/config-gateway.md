# Config gateway (PfbConfig) — reference

Scope: PfbConfig gateway contract, storage adapters, field inventory. Load when:
touching config fields, `PfbConfig`, or forward-upgrade behaviour.

Deep reference for the ADR-28/29 config-storage adapters and the `PfbConfig` gateway: the
operative gateway contract, the storage adapter rule, and the mechanics a change needs when
adding a field, preserving existing behaviour through an upgrade, or checking the foreign-key
exclusions.

## Gateway contract (ADR-29)

`PfbConfig` (`pfblockerng_extra.inc`) is the **single access point for every registered
`installedpackages/pfblockerng*` scalar field**:

- **Read/write/delete via `PfbConfig::read/write/delete($key)`** — never direct
  `config_*_path` on a registered key (enforced by the
  `PfBlockerNG.Config.RequireConfigGateway` sniff; adding a registered key ⇒ also add it to
  the sniff's `$registeredPaths`).
- Section helpers (`readSection`/`writeSection`/`deleteSection`) for whole-section,
  non-per-field access. Unregistered key → `InvalidArgumentException`.
- **No `write_config()` inside the gateway** — the caller decides when to flush. The registry
  (`pfb_cfg_registry()`) is read-only after boot.

## Write authorization (issue #1895)

Authorization is a property of the **write**, not the call site (the
`pfblockerng_hook_edit.inc` GATE 1 precedent generalised):

- Every registry entry may carry an optional `write_priv` — the page whose privilege the
  write re-asserts via `isAllowedPage()`. Absent means `PfbConfig::WRITE_PRIV_DEFAULT`
  (`pfblockerng/pfblockerng_general.php`, the package page — pfSense grants all
  pfBlockerNG pages through one privilege entry, so finer per-page defaults would be
  meaningless). The only explicit override: `pfb_software_check` →
  `pkg_mgr_installed.php` (the #485 Software-page secondary gate).
- `PfbConfig::write()` / `writeSection()` enforce it **fail-closed**: an undefined
  `isAllowedPage()` (no web session — `priv.inc` is only in the web auth include chain)
  or a FALSE return throws `RuntimeException`. `writeSection()` checks every registered
  field of the section present in `$data` before any mutation. The loud throw is
  deliberate: the silent-FALSE alternative is exactly the CLI trap #1895 documents.
- `PfbConfig::writeSystem()` / `writeSectionSystem()` skip the check — the sanctioned
  path for cron, the install/deinstall hooks, migrations, CLI, and pfSense-core hooks
  (`pfb_alias_rename_followup()` runs from the `firewall_aliases_edit` pre-write hook
  under a firewall-alias-only privilege, so enforcement there would break a supported
  path). The bypass is visible at the call site and mechanically confined:
  `RequireConfigGatewaySniff` (`SystemWriteInWww`) refuses the `*System()` variants in
  any file under `src/usr/local/www/`.
- `delete()` / `deleteSection()` carry no privilege check (out of #1895's scope).
- Coverage: `tests/php/CfgWriteAuthorizationTest.php` (deny/allow per entry point, the
  per-field override, the priv.inc-loaded CLI-trap regression, write/writeSystem
  parity) + the sniff fixtures in `tests/php/RequireConfigGatewaySniffTest.php`.

## Storage adapter rule (ADR-28 §2.2)

- **Storage is NOT frozen — forward-upgrade compatible where practical, not byte-for-byte.**
  No versioned migration routine. New options add new stored strings; read-boundary adapters
  absorb legacy tokens and writes emit a canonical token (which may differ from the legacy one
  when behaviour-equivalent). The goal is to preserve *behaviour* on upgrade, not bytes.
- **Forward-compat (upgrade) has two cases:** an existing config with the key absent reads to
  a value that **preserves that user's prior behaviour**; a brand-new config gets the new
  default. When those differ, a one-time grandfather seed sets the key for existing installs
  at upgrade (e.g. `pfb_rdns_seed_value`, `pfb_feed_filter_install_default`) so the
  absent-default never silently changes an existing user's behaviour.
- **Canonical current storage.** Read adapters accept legacy tokens needed by supported forward
  upgrades; writes emit the current canonical token. They do not constrain new storage to what an
  older package understands.
- Enums/booleans are the **internal runtime representation**; conversion at the boundary:
  stored string → enum on read; enum → canonical stored string on write.
- **The enum owns its stored-value semantics** via the `PfbStoredEnum` interface +
  `PfbStoredEnumAdapter` trait: `EnumClass::fromStored($raw)` (read) and `$enum->toStored()`
  (write). The per-field **absent default** is the registry's `$entry['default']` (applied by
  `PfbConfig::read()` *before* the adapter); the enum's `default()` is only the
  **parse-fallback** for unknown/non-scalar tokens, never the absent-default. A field's `''`
  vs `'off'` off-value is handled by its own enum.
- **Round-trip pinned by tests** (`CfgAdaptersTest`): every canonical
  token round-trips (`write(read(v)) == v`); a legacy token reads to the right runtime value
  and writes to its behaviour-equivalent canonical token.
- **Explicitly out of scope (ADR-28 §2.4):** `config.xml` versioned schema/migrations;
  `py_unbound.ini` and any manifest/serialized/wire value read by Python or shell; ADR-26
  locale prefixes; genuine boolean predicates (return `bool`, not an enum); mass realignment
  of untouched lines; `stubs/`, generated artifacts, vendored code.
- Per-field adapter inventory, field-vocabulary table, and forward-upgrade invariants: the
  sections below.

## Adapter inventory (field → enum)

- **PHP adapters / enums** (`PfbToggle`, `PfbIdnMode` + the thin `pfb_cfg_*_read/write`
  delegations) in `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc`:
  - Every ADAPTER-CARRYING checkbox field → `PfbToggle` (`'on'`/`'off'`; issue #1887 merged the former
    `PfbLenient` into it). Off is an EXPLICIT stored token; a stored `''` is the
    not-configured state and resolves to the field's registered default at the gateway,
    exactly as an absent key does. Tokens are recognised case-insensitively on read;
    writes always emit canonical lowercase. The runtime `$pfb[]` toggle mirrors carry
    the enum itself (never `->value`), so consumers compare `=== PfbToggle::On`.
    Registered checkbox fields still on `NULL`/`NULL` adapters (e.g. `pfb_regex`,
    `pfb_noaaaa`, `pfb_gp`, `pfb_cache`, `pfb_py_nolog`, `pfb_tld`, `alexa_enable`)
    keep the raw `{'on', ''}` storage until they adopt the pair — a field joining the
    adapter set moves all its consumers in the same commit (see below).
  - **`pfb_cache_flush` → `PfbToggle`**: default Off; enables the post-handshake full Unbound
    cache flush for bulk zero-downtime DNSBL data swaps.
  - **`enable_rep`/`enable_pdup`/`enable_dedup` → `PfbToggle`** (issue #1896, the Reputation
    "Max"/"pMax"/"dMax" toggles): default Off. The section
    (`pfblockerngreputation/config/0`) also holds unregistered scalars (`p24_*_var`,
    `ccwhite`/`ccblack`/`ccexclude`, `et_update`, `et_header`/`etblock`/`etmatch`) — only
    these three toggles are registered; the Reputation settings page's read/write routes
    through `PfbConfig::readSection()`/`writeSection()` so the three normalise while the
    rest pass through byte-identical (direct section-level reads elsewhere stay legal —
    the sniff gates exact key paths only).
  - **`pfb_alias_delta_mode` → `PfbAliasDeltaMode`** (ADR-40, registry adapters
    `pfb_cfg_alias_delta_mode_read/write`): tokens `'auto'` (new-install default) / `'delta'` /
    `'replace'`. Unknown or absent token reads as `Auto`. **Grandfather seed:** an already-configured
    install is pinned to `'replace'` (pre-ADR-40 full `-T replace`) at install/upgrade by
    `pfb_alias_delta_mode_install_default()` + `pfblockerng_install.inc` — run-once via its `!isset`
    guard — so only a brand-new install takes the `'auto'` absent-default; an upgrade keeps full
    replace.
    `pfb_alias_delta_batch` (plain string, `NULL`/`NULL` adapters) is the batch-size companion
    field; its stored value is a decimal integer string, clamped to `[64, 4096]` at read time by
    `pfb_alias_delta_batch_clamp()`.
  - **`pfb_idn` → `PfbIdnMode`** (registry adapters `pfb_cfg_idn_mode_read/write`): tokens
    `'on'` (= All) / `'confusable'` / `'off'`. `All` **reuses the original `'on'`** block-all
    token, so current code reading a pre-4.0.0 configuration preserves block-all with no
    migration. `PfbConfig::read('pfb_idn')` returns the enum;
    `PfbConfig::write()` and the `py_unbound.ini` build both emit `toStored()`; consumers compare
    `=== PfbIdnMode::All` / `::Confusable`. The 4.0.0-alpha-only `'all'` token is **not** carried
    (alpha compatibility is intentionally not maintained) — it reads as Off. One canonical
    vocabulary spans `config.xml`, the ini, and the Python `IdnMode` enum.
  - **`alexa_type` → `PfbTop1mSource`** (issue #877 review, registry adapters
    `pfb_cfg_top1m_source_read/write`): tokens `'tranco'` (default) / `'cisco'` /
    `'openpagerank'` (#928, replacing ADR-59 P4's `'domcop'`) /
    `'majestic'` (added ADR-59 P4) / `'cloudflare'` (added ADR-59 P5, the first
    token-authenticated provider). TWO tokens are READ-only, never re-emitted by a write —
    `'alexa'` (the dead Alexa TOP1M service, #872) coalesces to `Tranco`, and `'domcop'`
    (the DomCop TOP1M list's hosting moved to OpenPageRank, #928) coalesces to
    `OpenPageRank`; `fromLegacy()` coalesces any other unknown/absent token to `Tranco`.
    The stored config key stays `alexa_type` — no rename.
  - **`top1m_token`** (ADR-59 P5, plain string — `NULL`/`NULL` adapters): a masked,
    write-only credential (currently consumed only by the `cloudflare` `alexa_type`,
    ignored by every other provider), fed to `pfb_download()` via `pfb_top1m_auth_headers()`
    and the ADR-59 P3 header-auth plumbing (`Authorization: Bearer <token>`). Default `''`.
    Never echoed back on GET (`pfblockerng_dnsbl.php`); a blank POST preserves the
    existing stored value rather than clearing it — the field has no "off" state to
    round-trip, just identity pass-through like any other plain field. Validated on POST
    by `PFB_FILTER_TOKEN` (`pfblockerng.inc`) — a base64url/JWT charset
    (`[A-Za-z0-9._~+/=-]`), NOT `PFB_FILTER_WORD` (which would reject a real token).
- **Python** (`pfb_unbound.py`): the **`IdnMode` enum** shares that vocabulary — `All = 'on'`,
  `Confusable = 'confusable'`, `Off = 'off'` — and reads the ini `idn_mode` token directly (the
  legacy `python_idn` fallback is retained for a config predating the key). The toggle enum has
  **no Python consumer** (`config.getboolean()` reads all bool toggles), so it is a
  PHP-only adapter.

## Adding a new registered field

1. Add an entry to `pfb_cfg_registry()` with the exact `config.xml` key, its section path,
   the default stored string, and the adapter pair (or `NULL`/`NULL` for plain string).
   Giving an EXISTING field an adapter changes what `read()` returns for it (enum, not
   string), so every consumer of that field moves in the same commit — a stale string
   comparison against the enum fails silently in the always-false direction (issue #1887).
2. Verify round-trip: `write(read(v)) == v` for every canonical stored vocabulary value.
   When the field's owning page carries a secondary privilege gate (like the Software
   page), set `write_priv` on the entry (see "Write authorization" above).
3. Add a test in `tests/php/CfgGatewayTest.php` (round-trip + default-absent cases).
4. Update the `$inventory` in `testInventoryCompletenessAllKnownKeysAccountedFor()`.

When adding a registered key, also add its full path to the `$registeredPaths` property in
`tests/phpcs/PfBlockerNG/Sniffs/Config/RequireConfigGatewaySniff.php` (the enforcement sniff).

## Forward-upgrade contract

The gateway preserves existing behaviour while configurations move forward:

- **Legacy-read invariant** (old store → new code): `PfbConfig::read($key)` on any supported
  legacy stored token returns a well-formed runtime value — no crash, correct type, sane default
  for absent. `''` and absent are the SAME not-configured state (issue #1887): every gateway
  entry point (`read()`, `write()`, `writeSection()`) resolves both to the registered default
  through one shared helper, so a stored `''` can never mean different things to the read and
  the normalising write paths.
- **Grandfather invariant**: when an absent current default would change established behaviour,
  the install/upgrade path writes a one-time seed for existing installations.
- **Canonical-write invariant**: current code writes the current canonical representation.

Package downgrade is unsupported. Current normalized state is not rewritten for an older
package, and adapters need not emit old-package-compatible tokens. Before upgrading, keep a
pfSense configuration backup. If an older package cannot consume the upgraded state, restore the
pre-upgrade backup or reinstall the current package and continue forward.

### Section writes are normalised too (issue #930)

`PfbConfig::writeSection($section, $data)` applies the **same** canonical normalisation
as a single-key `PfbConfig::write()` — for every key in `$data` that is registered to the EXACT
target `$section` (a same-named key registered to a *different* section is foreign data and is
left untouched) and carries **both** a read and a write adapter, the value is round-tripped
`read_adapter()` then `write_adapter()` before the section is persisted. A key with no adapter
pair (plain string) or not present in `$data` passes through byte-identical; `writeSection()`
never calls `write_config()`.

Before this fix, `writeSection()` called `config_set_path($section, $data)` directly, bypassing
every adapter — a legacy read-only token (`alexa_type` `'domcop'`/`'alexa'`, `pfb_idn` alpha-only
`'all'`) or a hostile/junk value riding **any** section-blob write (a `www/` save handler, an
install seed, a migration) persisted raw into `config.xml` instead of being coalesced to its
canonical form. Consequently, a legacy token riding a `readSection()` → `writeSection()`
round-trip (a restored backup, an HA sync, a hand-edited `config.xml`) is coalesced to canonical
on the next save — it does not perpetually re-emit itself just because the write went through the
section-level helper instead of the per-key one.

Coverage: `tests/php/CfgGatewayTest.php` — a property test iterating `pfb_cfg_registry()` itself
(every adapter-bearing field × a canonical/legacy/junk sample set, compared against the
`PfbConfig::write()` oracle) plus targeted scenario and hostile-input tests (legacy `alexa_type`
tokens, alpha-only `pfb_idn`, a non-scalar/`NULL`/enum-instance/int value, an unadapted key,
a same-named key in a foreign section, a mixed realistic section blob).

## Field vocabularies

| Adapter type | Stored vocabulary |
| ------------ | ----------------- |
| `toggle`            | `{'on', 'off'}` (issue #1887; case-insensitive read, lowercase write; a stored `''` ≡ absent → registered default) |
| `idn`               | write `{'on' (=All), 'confusable', 'off'}`; legacy reads `'all'`→Off, `''`→Off (4.0.0-alpha `'all'` not carried) |
| `alias_delta_mode`  | `{'auto', 'delta', 'replace'}` — unknown/absent token reads as `'auto'` (ADR-40, since 4.0.0) |
| `top1m_source`      | write `{'tranco' (default), 'cisco', 'openpagerank', 'majestic', 'cloudflare'}` (majestic ADR-59 P4, cloudflare ADR-59 P5, openpagerank replaced P4's domcop in #928); legacy read `'alexa'`→Tranco (dead service, #872) and `'domcop'`→OpenPageRank (list moved hosting, #928), neither re-emitted |
| `plain`             | identity — any stored value passes through unchanged |

**Excluded fields** — none. `pfb_idn` was previously excluded (`NULL`/`NULL` identity adapters);
it is now adopted as `PfbIdnMode` (see ADR-28 §2.2). `All` reuses the legacy `'on'` token, so the
adoption is migration-free for supported upgrades. `alexa_type` similarly moved off a plain-string
read-boundary coalesce onto the `PfbTop1mSource` enum (issue #877 review) — same shape, no migration.

## Foreign-key exclusion list (use `config_*_path` directly — NOT via `PfbConfig`)

The following `installedpackages/pfblockerng*` paths are **not** registered in `pfb_cfg_registry()`
and stay on direct `config_*_path`. The enforcement sniff does NOT flag them (they are not in the
registered path set). Each annotation is committed in the relevant source file.

| Section / Key | Reason |
| --- | --- |
| `pfblockerngdnsbl/config/{row}/custom` | Dynamic per-row key, not in registry |
| `pfblockerngdnsbl/config/{row}/logging` | Dynamic per-row key, not in registry |
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

## Sniff file-scope exclusion — `pfblockerng_extra.inc` / `pfblockerng_migrate.inc`

Distinct from the per-path foreign-key list above: `RequireConfigGatewaySniff` excludes these two
**whole files** from its scan (see the PHPCS sniff entry in `.agents/policy/coding.md` → "Linting"),
originally because `pfblockerng_extra.inc` hosts `PfbConfig` itself (the gateway can't call
through itself) and `pfblockerng_migrate.inc` predates the registry. `pfblockerng_extra.inc` has
since grown well beyond the gateway — it also hosts real dispatch/scheduling logic (e.g. the
ADR-43 due-ledger API and `pfblockerng_tick()`). That code is registered-field-adjacent (it reads
`pfb_interval`/`pfb_quiet_hours`/`pfb_tick_interval` via `PfbConfig::read()` already) but the sniff
cannot enforce it there — any new code landing in this file must self-police `PfbConfig` usage for
registered keys (direct `config_get_path`/`config_set_path` on one is a rule violation the sniff
will not catch); rely on manual review, not the mechanical gate.
