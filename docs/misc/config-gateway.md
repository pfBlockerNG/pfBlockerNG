# Config gateway (PfbConfig) — reference

Deep reference for the ADR-28/29 config-storage adapters and the `PfbConfig` gateway. The
**operative rules** (read/write/delete via `PfbConfig`, the enforcement sniff) live in `CLAUDE.md`
→ "Config gateway — PfbConfig". This file holds the mechanics a change needs only when adding a
field, reasoning about rollback/downgrade, or checking the foreign-key exclusions.

## Adapter inventory (field → enum)

- **PHP adapters / enums** (`PfbToggle`, `PfbLenient`, `PfbIdnMode` + the thin
  `pfb_cfg_*_read/write` delegations) in `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc`:
  - `dnsbl_lenient` / `pfb_keep` → `PfbLenient` (`'on'`/`'off'`); `dnsbl_vip_auto` and ~76 other
    `'on'`/`''` checkbox fields → `PfbToggle` (off-value `''`).
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
  - **`alexa_type` → `PfbTop1mSource`** (issue #877 review, registry adapters
    `pfb_cfg_top1m_source_read/write`): tokens `'tranco'` (default) / `'cisco'` / `'openpagerank'` /
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
| `top1m_source`      | write `{'tranco' (default), 'cisco', 'openpagerank', 'majestic', 'cloudflare'}` (openpagerank/majestic ADR-59 P4, cloudflare ADR-59 P5); legacy read `'alexa'`→Tranco (dead service, #872) and `'domcop'`→OpenPageRank (list moved hosting, #928), neither re-emitted |
| `plain`             | identity — any stored value passes through unchanged |

**Excluded fields** — none. `pfb_idn` was previously excluded (`NULL`/`NULL` identity adapters);
it is now adopted as `PfbIdnMode` (see ADR-28 §2.2). `All` reuses the legacy `'on'` token, so the
adoption is migration-free and downgrade-safe. `alexa_type` similarly moved off a plain-string
read-boundary coalesce onto the `PfbTop1mSource` enum (issue #877 review) — same shape, no migration.

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

## Downgrade-preparation tool — structural reversals the config layer can't cover

The adapter/rollback contract above covers **config.xml scalar values**. A 4.0.x → pre-4.0.x
downgrade also has two **structural** (filesystem / cron) changes that a config adapter cannot
reverse and that do **not** self-heal on an older release:

1. **Relocated custom list scripts.** On upgrade, `pfblockerng_install.inc` moves a user's
   `{ip,dnsbl}_{pre,post}_*.{sh,py}` scripts from the package root into `list_scripts/`. A
   pre-4.0.x release resolves list scripts against the package **root only**, so a moved script
   silently stops running after a downgrade.
2. **The ADR-43 `tick` cron.** The `pfblockerng.php tick` entry replaced the older
   `cron`/`dcc`/`ss_refresh`/`bl` fleet; an older release has no `tick` verb, so the entry becomes
   an orphan and the update fleet is absent until the older release re-syncs.

Everything else the upgrade changed is already downgrade-safe: new-in-4.0.x config keys are
**ignored** by an older release (inert, preserved for roll-forward), and the `.md5` →
`.xxhash128` feed sidecars and the `.tar.bz2` → `.tar.zst` MFS archive **self-heal** on the next
feed update / rebuild.

**`scripts/pfb-downgrade-prep.sh`** reverses exactly those two non-self-healing changes. It is a
**dev/ops-only** POSIX-sh tool — **not shipped** in the package (release archives are `src/` only) —
that an operator copies to the appliance and runs as **root, before** the `pkg` downgrade (never
fired automatically — a normal upgrade or uninstall must not trigger it):

- Moves custom list scripts back to the package root, **skipping shipped scripts by name**
  (`ip_pre_AWS_*.sh`, `aws_region_prefixes.sh` — the only files pfBlockerNG ships in `list_scripts/`),
  so a shipped AWS wrapper is never moved. No pkg query is involved. Caveat: a user script named
  exactly like a shipped wrapper is treated as shipped and left in place — the shipped namespace is
  reserved.
- Removes the `tick` cron via `pfSsh.php` (the shipped `install_cron_job()`), so config.xml and the
  live crontab are rewritten cleanly.

It is **idempotent** (a second run restores nothing and reports the tick cron already gone) and
prints a short report of what it did.

Coverage: `tests/shell/pfb_downgrade_prep_spec.sh` (shellspec — the file-move logic, the shipped-name
gate, before/after, idempotency, skip-shipped, skip-existing, and the tick-cron output parsing via a
fake `pfSsh.php`) and `tests/smoke/test_downgrade_prepare.py` (the tool end-to-end on a live VM,
`repo` marker — real file moves + real `install_cron_job` tick removal).

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
| `pfblockerngreputation/config/0` | Static display section, no registered keys |
| `pfblockerng{continent}/config/0` | Dynamic per-continent structure |
| `pfblockerngdnsblsettings/config/0/dnsbl_webpage` | Out-of-scope foreign key (ADR-29 §2.5); written directly by `pfblockerng_dnsbl.php`, read via `pfb_dnsbl_webpage()` (issue #713 removed the never-written `dnsblwebpage` registry mis-spelling) |
| `pfblockerngdnsbl` / `pfblockernglistsv4/v6` (section-level reads) | Dynamic list sections |
| `aliases/alias`, `filter/rule`, `system/*`, `interfaces`, `unbound/*` | pfSense core sections |

## Sniff file-scope exclusion — `pfblockerng_extra.inc` / `pfblockerng_migrate.inc`

Distinct from the per-path foreign-key list above: `RequireConfigGatewaySniff` excludes these two
**whole files** from its scan (see the PHPCS sniff entry in `CLAUDE.md` → "Code standards → PHP"),
originally because `pfblockerng_extra.inc` hosts `PfbConfig` itself (the gateway can't call
through itself) and `pfblockerng_migrate.inc` predates the registry. `pfblockerng_extra.inc` has
since grown well beyond the gateway — it also hosts real dispatch/scheduling logic (e.g. the
ADR-43 due-ledger API and `pfblockerng_tick()`). That code is registered-field-adjacent (it reads
`pfb_interval`/`pfb_quiet_hours`/`pfb_tick_interval` via `PfbConfig::read()` already) but the sniff
cannot enforce it there — any new code landing in this file must self-police `PfbConfig` usage for
registered keys (direct `config_get_path`/`config_set_path` on one is a rule violation the sniff
will not catch); rely on manual review, not the mechanical gate.
