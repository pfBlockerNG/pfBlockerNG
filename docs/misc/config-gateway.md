# Config gateway (PfbConfig) — reference

Deep reference for the ADR-28/29 config-storage adapters and the `PfbConfig` gateway. The
**operative rules** (read/write/delete via `PfbConfig`, the enforcement sniff) live in `CLAUDE.md`
→ "Config gateway — PfbConfig". This file holds the mechanics a change needs only when adding a
field, reasoning about rollback/downgrade, or checking the foreign-key exclusions.

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
| `toggle`     | `{'on', ''}` |
| `lenient`    | `{'on', 'off', ''}` — `''` is a LEGACY READ token (pre-ADR-22 absent); write emits `'off'` |
| `idn`        | write `{'on' (=All), 'confusable', 'off'}`; legacy reads `'all'`→Off, `''`→Off (4.0.0-alpha `'all'` not carried) |
| `plain`      | identity — any stored value passes through unchanged |

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
