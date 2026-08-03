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
- **Path addressing (issue #1931):** registry keys are `'<alias>/<config-key>'` path
  strings — `'gen/pfb_keep'`, `'ip/suppression'` — with the alias resolved through the
  `PFB_SECTIONS` map (`gen`/`dnsbl`/`ss`/`ip`/`rep`), the single home of the five real
  section paths. Same-named keys in different sections cannot collide, and bare-name
  lookups throw (`InvalidArgumentException`) — no dual addressing. Entries carry no
  `section` attribute; a key prefix outside `PFB_SECTIONS` fails `CfgGatewayTest`'s
  alias gate, and the pre-change tuple parity is pinned by
  `tests/php/fixtures/cfg_registry_pre1931_parity.json`.
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
- **`writeSection()`'s gate is delta-aware** (issue #1895 addendum, found reviewing the
  composition against `pfblockerng_general.php`'s whole-section readSection → modify one
  field → writeSection() save): a registered field present in `$data` only asserts its
  `write_priv` when its canonical incoming value differs from its canonical
  currently-stored value (both sides run through the same read/write-adapter
  round-trip); an unchanged read-modify-write pass-through (e.g. `pfb_software_check`
  riding along untouched while the General page saves an unrelated field) is not an
  authorization event and is silently skipped. `PfbConfig::write()` stays **strict** — an
  explicit single-key write is always an authorization event, changed or not, since there
  is no read-modify-write section saver behind it.
- Coverage: `tests/php/CfgWriteAuthorizationTest.php` (deny/allow per entry point, the
  per-field override, the priv.inc-loaded CLI-trap regression, write/writeSystem
  parity, the delta-aware pass-through/real-change/absent-vs-default rows) + the sniff
  fixtures in `tests/php/RequireConfigGatewaySniffTest.php`.

## Storage adapter rule (ADR-28 §2.2)

- **Storage is NOT frozen — forward-upgrade compatible where practical, not byte-for-byte.**
  No versioned migration routine. New options add new stored strings; read-boundary adapters
  absorb legacy tokens and writes emit a canonical token (which may differ from the legacy one
  when behaviour-equivalent). The goal is to preserve *behaviour* on upgrade, not bytes.
- **Forward-compat (upgrade) has two cases:** an existing config with the key absent reads to
  a value that **preserves that user's prior behaviour**; a brand-new config gets the new
  default. When those differ, the registry entry carries a `grandfather` map (issue #1921)
  that the one-pass registry reconciliation applies for existing installs at upgrade (the
  bespoke `pfb_rdns_seed_value` cross-section seed is the exception that stays hand-written),
  so the absent-default never silently changes an existing user's behaviour.
- **Canonical current storage.** Read adapters accept legacy tokens needed by supported forward
  upgrades; writes emit the current canonical token. They do not constrain new storage to what an
  older package understands.
- **Adapter presence owns empty-string semantics (issue #2120).** A genuinely absent/`NULL`
  value resolves to the registry default before every read adapter. A stored `''` reaches an
  adapter-bearing entry's read adapter, while a plain scalar still treats `''` as not configured
  and resolves it to the registry default. `PfbConfig::read()` never exposes absence. Writing
  `NULL` to an adapter-bearing entry deletes that key (and a section write omits it), so absence
  stays truthful instead of materialising a default; plain-scalar behaviour is unchanged.
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
  - Every ADAPTER-CARRYING checkbox field → `PfbToggle` (issue #1887 merged the former
    `PfbLenient` into it). Read is deliberately narrow and case-insensitive: `on` in any
    case is `On`; every other present token (`''`, legacy `'off'`, junk) is `Off`.
    Only genuine absence consults the field's registered default. Writes emit `'on'` for
    `On` and canonical `''` for `Off`; `'off'` is accepted forever but never written
    (issue #2120, deliberately reversing #1887's explicit-`'off'` writer). The enum's
    `Off = 'off'` backing value remains its internal/render identity. The runtime `$pfb[]`
    toggle mirrors carry
    the enum itself (never `->value`), so consumers compare `=== PfbToggle::On`.
    Registered checkbox fields still on `NULL`/`NULL` adapters (e.g. `pfb_regex`,
    `pfb_noaaaa`, `pfb_gp`, `pfb_py_nolog`, `tld_wildcard`, `top1m_enable`)
    keep the raw `{'on', ''}` storage until they adopt the pair — a field joining the
    adapter set moves all its consumers in the same commit (see below).
  - **Nine adapter-bearing toggles default On:** `pfb_keep`, `pfb_software_check`,
    `pfb_feed_internal_filter`, `pfb_syntax_highlight`, `pfb_cache`, `pfb_py_reply`,
    `pfb_hsts`, `pfb_idn_block_malicious`, and ip-section `suppression`. For all nine,
    absence reads On while a stored `''` reads Off. The six former `'' => 'off'`
    grandfather arms (`pfb_keep`, `pfb_cache`, `pfb_py_reply`, `pfb_hsts`,
    `pfb_idn_block_malicious`, `suppression`) were retired by #2120 because the runtime
    adapter now preserves that legacy uncheck and canonical writes use `''`; the separate
    `pfb_keep` absent → `'on'` grandfather remains. `pfb_py_reply`/`pfb_hsts`
    additionally get the `issue1907-python-gated-toggles`
    migration: a stored `'on'` beside a pre-upgrade `dnsbl_mode` that is present and not
    `'dnsbl_python'` was inert (both consumers were python-gated in 3.2) and is disabled
    before the ADR-02 python force would otherwise activate it.
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
    `'replace'`. Unknown or absent token reads as `Auto`. **Grandfather:** an already-configured
    install is pinned to `'replace'` (pre-ADR-40 full `-T replace`) by the registry entry's
    `grandfather => [PFB_GF_ABSENT => 'replace']` map, applied once by the registry pass at
    install/upgrade — so only a brand-new install takes the `'auto'` absent-default; an
    upgrade keeps full replace.
    `pfb_alias_delta_batch` (plain string, `NULL`/`NULL` adapters) is the batch-size companion
    field; its stored value is a decimal integer string, clamped to `[64, 4096]` at read time by
    `pfb_alias_delta_batch_clamp()`.
  - **`pfb_idn` → `PfbIdnMode`** (registry adapters `pfb_cfg_idn_mode_read/write`): live
    cases are `'on'` (= All), `'confusable'`, and Off. `All` **reuses the original `'on'`** block-all
    token, so current code reading a pre-4.0.0 configuration preserves block-all with no
    migration. `PfbConfig::read('dnsbl/pfb_idn')` returns the enum;
    `PfbConfig::write()` and the `py_unbound.ini` build both emit `toStored()`: Off → `''`,
    All → `'on'`, Confusable → `'confusable'`. Reads accept both `''` and legacy `'off'`
    as Off. The 4.0.0-alpha-only `'all'` token is **not** carried (alpha compatibility is
    intentionally not maintained) — like other unrecognised junk, it keeps the enum's
    existing `default()` fallback to Off. Consumers compare `=== PfbIdnMode::All` /
    `::Confusable`; form rendering uses the enum's backing `->value`, not its storage token.
  - **`top1m_source` → `PfbTop1mSource`** (issue #877 review, registry adapters
    `pfb_cfg_top1m_source_read/write`): tokens `'tranco'` (default) / `'cisco'` /
    `'openpagerank'` (#928, replacing ADR-59 P4's `'domcop'`) /
    `'majestic'` (added ADR-59 P4) / `'cloudflare'` (added ADR-59 P5, the first
    token-authenticated provider). TWO tokens are READ-only, never re-emitted by a write —
    `'alexa'` (the dead Alexa TOP1M service, #872) coalesces to `Tranco`, and `'domcop'`
    (the DomCop TOP1M list's hosting moved to OpenPageRank, #928) coalesces to
    `OpenPageRank`; `fromLegacy()` coalesces any other unknown/absent token to `Tranco`.
    The stored key was `alexa_type` until issue #1898 renamed it (see "Stored-key
    vocabulary" below); the legacy *tokens* are unaffected by that rename.
  - **`top1m_token`** (ADR-59 P5, plain string — `NULL`/`NULL` adapters): a masked,
    write-only credential (currently consumed only by the `cloudflare` `top1m_source`,
    ignored by every other provider), fed to `pfb_download()` via `pfb_top1m_auth_headers()`
    and the ADR-59 P3 header-auth plumbing (`Authorization: Bearer <token>`). Default `''`.
    Never echoed back on GET (`pfblockerng_dnsbl.php`); a blank POST preserves the
    existing stored value rather than clearing it — the field has no "off" state to
    round-trip, just identity pass-through like any other plain field. Validated on POST
    by `PFB_FILTER_TOKEN` (`pfblockerng.inc`) — a base64url/JWT charset
    (`[A-Za-z0-9._~+/=-]`), NOT `PFB_FILTER_WORD` (which would reject a real token).
- **Python** (`pfb_unbound.py`): the **`IdnMode` enum** keeps the internal cases
  `All = 'on'`, `Confusable = 'confusable'`, `Off = 'off'`. A present empty or legacy
  `'off'` ini value reads Off; absent `idn_mode` and unrecognised junk retain the legacy
  `python_idn` fallback. The toggle enum has
  **no Python consumer** (`config.getboolean()` reads all bool toggles), so it is a
  PHP-only adapter.

## Adding a new registered field

1. Add an entry to `pfb_cfg_registry()` keyed `'<alias>/<config-key>'` (alias from
   `PFB_SECTIONS`; the config-key part is the exact `config.xml` key), with the default
   stored string and the adapter pair (or `NULL`/`NULL` for plain string).
   Giving an EXISTING field an adapter changes what `read()` returns for it (enum, not
   string), so every consumer of that field moves in the same commit — a stale string
   comparison against the enum fails silently in the always-false direction (issue #1887).
2. Verify round-trip: `write(read(v)) == v` for every canonical stored vocabulary value.
   When the field's owning page carries a secondary privilege gate (like the Software
   page), set `write_priv` on the entry (see "Write authorization" above).
3. Add a test in `tests/php/CfgGatewayTest.php` (round-trip + default-absent cases).
4. Update the `$inventory` in `testInventoryCompletenessAllKnownKeysAccountedFor()`.
5. Classify the grandfathering decision on the entry itself — a `grandfather` map or a
   `no_grandfather` reason (issue #1921; the trigger question is under "Forward-upgrade
   contract"). `CfgRegistryGrandfatherGateTest` fails the suite on an unclassified entry.

When adding a registered key, also add its full path to the `$registeredPaths` property in
`tests/phpcs/PfBlockerNG/Sniffs/Config/RequireConfigGatewaySniff.php` (the enforcement sniff).

`tld_allow_sort` and `tld_allow_{gtld,cctld,itld,bgtld}` are plain registered scalars (`NULL`/
`NULL` adapters) since issue #1921 — they were previously on the foreign-key exclusion list
below. They still stay legal on `pfblockerng_dnsbl.php`'s direct section-blob read/write (the
gateway does not require every registered field to move its consumers in the same step); the
registration exists for `old_name` parity with the rest of the `pfb_pytld*` rename family.

## Forward-upgrade contract

The gateway preserves existing behaviour while configurations move forward:

- **Legacy-read invariant** (old store → new code): `PfbConfig::read($key)` on any supported
  legacy stored token returns a well-formed runtime value — no crash, correct type, sane default
  for absent. Issue #2120 deliberately reverses #1887's `''`-equals-absence identity for
  adapter-bearing entries only: genuine absence resolves to the registered default; stored
  `''` reaches the adapter. Plain scalars retain the #1887 identity. The shared normalization
  still makes `read()`, `write()`, and `writeSection()` agree on the same distinction.
- **Grandfather invariant (issue #1921)**: when an absent current default — or a raw legacy
  stored value — would change established behaviour, the registry entry carries a
  `grandfather` map: raw stored value → new value, with the dedicated `PFB_GF_ABSENT` marker
  keying genuine absence (a PHP array literal coerces a `NULL` key to `''`, so absence needs
  an explicit marker). The one-pass registry reconciliation (below) applies the map once at
  install/upgrade; unmapped values pass through unchanged. **The trigger is "did the
  behaviour this field controls change for someone upgrading?", never "did this key exist
  before?"** — a field introduced in 4.0 to make previously *hardcoded* behaviour
  configurable is the highest-risk case, not a safe one, because its new-install default is
  chosen for new installs while every upgrader was living under the old hardcoded behaviour.
  The shipped maps:

  | Field | Grandfather map | Why |
  | --- | --- | --- |
  | `gen/pfb_keep` | `[ABSENT => 'on']` | #281 upgrade keeps settings; #2120's runtime adapter owns the legacy `''` uncheck |
  | `gen/pfb_alias_delta_mode` | `[ABSENT => 'replace']` | ADR-40 — an upgrade keeps the pre-ADR-40 full replace |
  | `dnsbl/pfb_dnsbl_lenient` | `[ABSENT => 'on']` | ADR-22 — an upgrade keeps permissive parsing |

  **Every entry carries its decision.** Exactly one of a `grandfather` map or a
  `no_grandfather` reason string per registry entry, with two exceptions carrying neither:
  `gen/settings_family` (the mode instrument, recorded by `pfb_settings_family_record()`)
  and `dnsbl/pfb_control_legacy` (the PFBL-03 cross-key bespoke seed).
  `tests/php/CfgRegistryGrandfatherGateTest.php` enforces the partition **totally** — a new
  registered field with neither fails the suite — plus the **fixpoint rule** (no map output
  is also a map input; `['on'=>'off','off'=>'on']` would oscillate across reinstalls) and
  `old_name` parity. Issue #1920's one-time 103-row audit is thereby a standing gate.

  **Ordering is branch order, not pass order.** The former three-stage hazard (rename
  migration, then grandfather helpers, then the seeding pass, with their mutual order pinned
  by a test) is structurally gone: `pfb_registry_pass()` does rename → grandfather-map →
  seed as branch order inside one loop (see "The registry pass" below).
- **Canonical-write invariant**: current code writes the current canonical representation.
- **Canonical-name invariant** (issue #1898): a registered key's *name* is the current domain
  vocabulary too, not a frozen historical spelling. Renaming one ships a one-time post-install
  migration in `pfb_migration_registry()`; after it runs, current code reads and writes only the
  new name — no dual-read, no fallback, no shadow copy (see "Stored-key vocabulary" below).

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

For an adapter-bearing key, an explicit `NULL` removes that key from the section before the
section is persisted; an omitted key remains omitted. This matches single-key `write(NULL)`
deletion. Plain registered scalars retain their existing byte-preserving section behavior.

Before this fix, `writeSection()` called `config_set_path($section, $data)` directly, bypassing
every adapter — a legacy read-only token (`top1m_source` `'domcop'`/`'alexa'`, `pfb_idn` alpha-only
`'all'`) or a hostile/junk value riding **any** section-blob write (a `www/` save handler, an
install seed, a migration) persisted raw into `config.xml` instead of being coalesced to its
canonical form. Consequently, a legacy token riding a `readSection()` → `writeSection()`
round-trip (a restored backup, an HA sync, a hand-edited `config.xml`) is coalesced to canonical
on the next save — it does not perpetually re-emit itself just because the write went through the
section-level helper instead of the per-key one.

Coverage: `tests/php/CfgGatewayTest.php` — a property test iterating `pfb_cfg_registry()` itself
(every adapter-bearing field × a canonical/legacy/junk sample set, compared against the
`PfbConfig::write()` oracle) plus targeted scenario and hostile-input tests (legacy `top1m_source`
tokens, alpha-only `pfb_idn`, a non-scalar/`NULL`/enum-instance/int value, an unadapted key,
a same-named key in a foreign section, a mixed realistic section blob).

## Stored-key vocabulary (issue #1898)

ADR-29 §5 originally froze registry keys at "the EXACT existing `config.xml` keys (no renames)"
so 4.x code could share a `config.xml` with the 3.2.x package family. The owner retired that goal
on 2026-07-30 — downgrade safety now comes from the settings-family snapshots
(`pfb_settings_family_save()` / `_replace()`), not from perpetuating an obsolete spelling. Stored
keys therefore carry the **current** domain vocabulary, and an existing installation is carried
forward by one migration.

**The 15 retired names.** Four landed decisions had frozen a stored key while the runtime/UI
vocabulary moved on: the dead-Alexa TOP1M cluster (#872/#877), ADR-66 §2.1/§2.2's TLD Allow
and TLD Wildcard families, and the DNSBL whitelist blob (stored as `suppression` until
issue #1921 renamed it to its true name).

| Old stored key | Current stored key |
| --- | --- |
| `alexa_enable` · `alexa_type` · `alexa_count` · `alexa_inclusion` | `top1m_enable` · `top1m_source` · `top1m_count` · `top1m_inclusion` |
| `filter_alexa` (dynamic `pfblockerngdnsbl/config/{row}`) | `filter_top1m` |
| `pfb_pytld` · `pfb_pytld_sort` · `pfb_pytlds_{gtld,cctld,itld,bgtld}` | `tld_allow` · `tld_allow_sort` · `tld_allow_{gtld,cctld,itld,bgtld}` |
| `pfb_tld` · `tldblacklist` · `tldexclusion` | `tld_wildcard` · `tld_wildcard_blacklist` · `tld_wildcard_exclusion` |
| `suppression` (DNSBL settings section) | `whitelist` |

**Scalar renames are `old_name` slots (issue #1921).** Every retired *scalar* spelling lives
as the `old_name` slot on its registry entry; the rename is the first branch of the registry
pass (below), so no later branch can ever observe a value still under its old name. The one
per-feed **row** rename (`filter_alexa` → `filter_top1m`) stays a migration —
`PFB_LEGACY_KEY_RENAMES` + `pfb_legacy_key_rename_migrate()`, the `issue1898-legacy-key-rename`
entry in `pfb_migration_registry()` — because feed rows are not registered scalars; that
migration keeps the original #1898 semantics: per-row preflight, all-or-nothing across rows,
fail-closed on a conflicting pair with a `file_notice()` naming keys and never values.
`CfgRegistryGrandfatherGateTest`'s `old_name` parity pins the retired-spelling set.

## The registry pass (issue #1921)

`pfb_registry_pass()` (`pfblockerng.inc`) replaces the rename migration's scalar half, the
grandfather helpers, and the #1898 seeding pass with **one registry-driven loop**, called at
the end of `pfblockerng_install.inc` after `pfb_run_migrations()` and after the ADR-53
`pfBlockerNGSuppress` alias conversion (which keys on the literal absence of
`ip/v4suppression` and must observe pre-pass state). Mode is computed **per section**:
`OLDCFG` iff the section is non-empty under `pfb_gconfig_operator_view()` (the installer's
`settings_family` marker never reads as operator data — #1770/#1771/#1775). Per key:

- **NEWCFG** — seed the registry default (stabilised through the entry's own grandfather map
  so a seeded value can never be re-mapped by a later run).
- **OLDCFG** — rename (an `old_name` value moves verbatim, `''` and `'0'` included; a
  conflicting pair keeps the new name, leaves the old in place, and raises one
  `file_notice()` naming keys, never values — per-key, not all-or-nothing); then the
  grandfather map (`PFB_GF_ABSENT` covers genuine absence; unmapped values are identity;
  `''` is a stored value and moves/maps as one); then seed the default if still absent.

Idempotent by construction: a present key short-circuits everything except the conflict
warning, and the gate's fixpoint rule guarantees a map output is never a map input. The pass
returns only changed sections; the caller persists them via `PfbConfig::writeSectionSystem()`
(the pass's output riding the adapters is deliberate — it is what coalesces a renamed key's
legacy token, e.g. `top1m_source` `'alexa'` → `'tranco'`).

**Migrations persist raw.** `pfb_run_migrations()` and every legacy-reshape write earlier in
`pfblockerng_install.inc` persist via `PfbConfig::writeSectionRawSystem()` (direct
`config_set_path()`, no adapter round-trip) — an adapter-riding write-back before the pass
would canonicalise a bystander legacy token (for example `top1m_source = 'alexa'`) before
the registry pass can inspect it. Canonicalisation is the pass's job. Pinned by
`tests/php/InstallPrePassWriteOrderTest.php` (no `writeSectionSystem` before
the pass call in the installer) and the raw-bystander regression in
`MigrationRegistryTest`.

**What stays outside the loop:**

| Piece | Why | Fate |
| --- | --- | --- |
| PFBL-03 `pfb_control_legacy_seed()` | cross-key: value depends on `pfb_control`, plus its own run-once marker | migration; runs before the pass, which then sees the key present and skips |
| `issue1907-python-gated-toggles` | cross-key: stored `'on'` + pre-upgrade `dnsbl_mode` present and ≠ `'dnsbl_python'` → `'off'` | migration; MUST run before the ADR-02 python force, which overwrites the `dnsbl_mode` evidence |
| ADR-02 python-mode force | not a grandfather — forces unregistered keys regardless of value | migration, after the #1907 exception |
| Row rename `filter_alexa` → `filter_top1m` | feed rows are not registered scalars | the residual `issue1898-legacy-key-rename` migration |
| `gen/settings_family` | the mode instrument, valued by the installing package | recorded by `pfb_settings_family_record()`; the pass skips it entirely |

**Consequence for future fields:** after the pass a bare `!isset($cfg[$key])` no longer means
"an existing install that predates this setting". A new grandfather decides from the *value*
via its map, or from a dedicated one-shot marker (`pfb_control_legacy_seeded`'s shape), never
from key absence. The same applies to whole-section emptiness: `pfb_dnsbl_python_migrate()`
and `pfb_control_legacy_seed()` use `empty($dconfig)` as their fresh-install discriminator,
so on the install *after* a fresh one they fire against a seeded section and write their
(vestigial) `dnsbl_mode` / `pfb_py_block` / `pfb_control_legacy_seeded` keys. Behaviour is
unchanged — `pfb_control_legacy` is still only set when `pfb_control` is `'on'`, which a
seeded section is not — but the write is spurious. New run-once logic uses a marker, not
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

**Excluded fields** — none. `pfb_idn` was previously excluded (`NULL`/`NULL` identity adapters);
it is now adopted as `PfbIdnMode` (see ADR-28 §2.2). `All` reuses the legacy `'on'` token, so the
adoption is migration-free for supported upgrades. `top1m_source` similarly moved off a plain-string
read-boundary coalesce onto the `PfbTop1mSource` enum (issue #877 review) — same shape, no migration.

## Foreign-key exclusion list (use `config_*_path` directly — NOT via `PfbConfig`)

The following `installedpackages/pfblockerng*` paths are **not** registered in `pfb_cfg_registry()`
and stay on direct `config_*_path`. The enforcement sniff does NOT flag them (they are not in the
registered path set). Each annotation is committed in the relevant source file.

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
