# Config gateway (PfbConfig) — reference

Deep reference for the ADR-28/29 config-storage adapters and the `PfbConfig` gateway. The
**operative rules** (read/write/delete via `PfbConfig`, the enforcement sniff) live in `CLAUDE.md`
→ "Config gateway — PfbConfig". This file holds the mechanics a change needs only when adding a
field, reasoning about rollback/downgrade, or checking the foreign-key exclusions.

## Adapter inventory (field → enum)

- **PHP adapters / enums** (`PfbToggle`, `PfbLenient`, `PfbIdnMode` + the thin
  `pfb_cfg_*_read/write` delegations) in `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc`:
  - `dnsbl_lenient` / `pfb_keep` / `pfb_keep_on_upgrade` → `PfbLenient` (`'on'`/`'off'`);
    `dnsbl_vip_auto` and ~76 other `'on'`/`''` checkbox fields → `PfbToggle` (off-value `''`).
    **`pfb_keep_on_upgrade`** (#687, "Keep enabled during version upgrades") is lenient so the
    absent-default `'on'` (new install) is distinguishable from an explicit `'off'`; an
    already-configured install is grandfather-seeded to `'off'` at install/upgrade by
    `pfb_keep_on_upgrade_install_default()` + `pfblockerng_install.inc` (run-once via `!isset`), so
    an upgrade preserves its prior teardown-on-removal behaviour.
  - **`pfb_alias_delta_mode` → `PfbAliasDeltaMode`** (ADR-40, registry adapters
    `pfb_cfg_alias_delta_mode_read/write`): tokens `'auto'` (new-install default) / `'delta'` /
    `'replace'`. Unknown or absent token reads as `Auto`. **Grandfather seed:** an already-configured
    install is pinned to `'replace'` (pre-ADR-40 full `-T replace`) at install/upgrade by
    `pfb_alias_delta_mode_install_default()` + `pfblockerng_install.inc` — run-once via its `!isset`
    guard — so only a brand-new install takes the `'auto'` absent-default; an upgrade keeps full
    replace. Absent on a pre-4.0.0 (downgrade) install → feature silently absent (full replace).
    `pfb_alias_delta_batch` (plain string, `NULL`/`NULL` adapters) is the batch-size companion
    field; its stored value is a decimal integer string, clamped to `[64, 4096]` at read time by
    `pfb_alias_delta_batch_clamp()`.
  - **`pfb_idn` → `PfbIdnMode`** (registry adapters `pfb_cfg_idn_mode_read/write`): tokens
    `'on'` (= All) / `'confusable'` / `'off'`. `All` **reuses the original `'on'`** block-all
    token, so a pre-4.0.0 install round-trips with no migration *and* an older release reading
    `'on'` still blocks all IDN. `PfbConfig::read('pfb_idn')` returns the enum;
    `PfbConfig::write()` and the `py_unbound.ini` build both emit `toStored()`; consumers compare
    `=== PfbIdnMode::All` / `::Confusable`. The 4.0.0-alpha-only `'all'` token is **not** carried
    (alpha compatibility is intentionally not maintained) — it reads as Off. One canonical
    vocabulary spans `config.xml`, the ini, and the Python `IdnMode` enum.
- **Python** (`pfb_unbound.py`): the **`IdnMode` enum** shares that vocabulary — `All = 'on'`,
  `Confusable = 'confusable'`, `Off = 'off'` — and reads the ini `idn_mode` token directly (the
  legacy `python_idn` fallback is retained for a config predating the key). Toggle/lenient enums
  have **no Python consumer** (`config.getboolean()` reads all bool toggles), so they are
  PHP-only adapters.

## Adding a new registered field

1. Add an entry to `pfb_cfg_registry()` with the exact `config.xml` key, its section path,
   the default stored string, and the adapter pair (or `NULL`/`NULL` for plain string).
2. Set the `since` value to the package release that first introduced the key to `config.xml`
   (format: `'X.Y.Z'`; for legacy keys the earliest still-shipped release is acceptable).
3. Verify round-trip: `write(read(v)) == v` for every canonical stored vocabulary value.
4. Add a test in `tests/php/CfgGatewayTest.php` (round-trip + default-absent cases).
5. Update the `$inventory` in `testInventoryCompletenessAllKnownKeysAccountedFor()`.

When adding a registered key, also add its full path to the `$registeredPaths` property in
`tests/phpcs/PfBlockerNG/Sniffs/Config/RequireConfigGatewaySniff.php` (the enforcement sniff).

## Rollback / backward-compat contract (ADR-29 Phase 3)

The gateway is the enforcement mechanism for downgrade safety. Two invariants hold for every
registered field, asserted per-field by `tests/php/RollbackContractTest.php`:

- **FORWARD invariant** (old store → new code): `PfbConfig::read($key)` on any legacy stored
  token returns a well-formed runtime value — no crash, correct type, sane default for absent.
- **BACKWARD invariant** (new code → old store → old code): `PfbConfig::write($key, $v)` only
  ever emits a token from the field's **known vocabulary** — never a novel on-disk token an
  older release wouldn't understand. A write **may normalise** a legacy token to a
  behaviour-equivalent canonical one (e.g. `pfb_idn`: `All` persists as the legacy-understood
  `'on'`, and the dropped `'all'` normalises to `'off'`); the emitted token is always one an
  older release string-compares correctly. Guaranteed by construction: backed enums emit
  `toStored()` (a member of the vocabulary), and plain-string fields use identity adapters.

### Scope limit (no versioned schema)

This is *not* full backward compatibility — that needs a versioned config schema this package
deliberately lacks (ADR-28 §1.3). The invariants cover the **vocabulary of existing registered
fields** only. A genuinely **new option added in a later release** is unknown to an older one:
on rollback the old code **ignores** the key (inert, not misread or corrupting) and its value is
**preserved** in `config.xml` for roll-forward — the new feature is simply unusable on the old
version (inherent, out of scope). `since-version` bounds each field's rollback claim to releases
at/after that version; it is a per-field scope marker, not a migration.

## Field vocabularies (`pfb_cfg_field_vocab()`)

| Adapter type | Stored vocabulary |
| ------------ | ----------------- |
| `toggle`            | `{'on', ''}` |
| `lenient`           | `{'on', 'off', ''}` — `''` is a LEGACY READ token (pre-ADR-22 absent); write emits `'off'` |
| `idn`               | write `{'on' (=All), 'confusable', 'off'}`; legacy reads `'all'`→Off, `''`→Off (4.0.0-alpha `'all'` not carried) |
| `alias_delta_mode`  | `{'auto', 'delta', 'replace'}` — unknown/absent token reads as `'auto'` (ADR-40, since 4.0.0) |
| `plain`             | identity — any stored value passes through unchanged |

**Excluded fields** — none. `pfb_idn` was previously excluded (`NULL`/`NULL` identity adapters);
it is now adopted as `PfbIdnMode` (see ADR-28 §2.2). `All` reuses the legacy `'on'` token, so the
adoption is migration-free and downgrade-safe.

## Since-version convention

Every registry entry carries a `'since'` field (`'X.Y.Z'` pattern). It records the first
package release that introduced the key to `config.xml`. For legacy keys that pre-date the
registry, the earliest still-shipped release is the baseline (`'1.0.0'` for original-era keys,
`'2.0.0'` for Python-mode era, `'3.x.y'` for ADR additions). Required format verified by
`RollbackContractTest::testSinceVersionFollowsVersionPattern`.

## Off-VM downgrade gate

`tests/smoke/test_upgrade_config_stability.py::test_pkg_downgrade_preserves_config_values`
carries the `repo` marker (deselected from `-m smoke`). Install HIGHER build → write config →
downgrade to LOWER build via `pkg delete` + reinstall → assert the stored config values are
preserved (sane reads, behaviour intact) AND the DNSBL probe still returns VIP. Skips cleanly
when `SMOKE_PKG`/`repo_vm` is absent.

## Foreign-key exclusion list (use `config_*_path` directly — NOT via `PfbConfig`)

The following `installedpackages/pfblockerng*` paths are **not** registered in `pfb_cfg_registry()`
and stay on direct `config_*_path`. The enforcement sniff does NOT flag them (they are not in the
registered path set). Each annotation is committed in the relevant source file.

| Section / Key | Reason |
| --- | --- |
| `pfblockerngipsettings/config/0/v4suppression` | Foreign section — not in registry |
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
| `pfblockerngreputation/config/0` | Static display section, no registered keys |
| `pfblockerng{continent}/config/0` | Dynamic per-continent structure |
| `pfblockerngdnsblsettings/config/0/dnsbl_webpage` | Out-of-scope key (ADR-29 §2.5); the registered key is `dnsblwebpage` |
| `pfblockerngdnsbl` / `pfblockernglistsv4/v6` (section-level reads) | Dynamic list sections |
| `aliases/alias`, `filter/rule`, `system/*`, `interfaces`, `unbound/*` | pfSense core sections |
