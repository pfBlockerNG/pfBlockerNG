<?php
/*
 * pfblockerng_extra.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file is used to 'include functions' not yet merged into pfSense

// ---------------------------------------------------------------------------
// ADR-28 — config field enums + the PfbStoredEnum adapter contract.
//
// Backed string enums for recurring config flags. Each enum OWNS its stored-value
// semantics (the PfbStoredEnum interface + PfbStoredEnumAdapter trait) so the
// PfbConfig gateway and the pfb_cfg_* helpers stay trivial:
//   - read : EnumClass::fromStored($raw)   — the NULL/absent default is the registry's
//             $entry['default'] (applied by PfbConfig::read() BEFORE the adapter);
//             '', legacy aliases, and junk are resolved by the enum itself.
//   - write: $enum->toStored()             — the canonical persisted token.
//
// Policy (ADR-28 §2.2, reframed): the goal is PRESERVE BEHAVIOUR ON UPGRADE, not
// byte-identical storage. A write may persist a normalised canonical token when it
// is behaviour-equivalent to the legacy one (e.g. pfb_idn All persists the legacy
// 'on' token, reproducing the prior block-all-IDN behaviour). Downgrade is tolerated:
// older releases string-compared these values, so an unknown token falls through to
// the safe default there.
//
// Tests: tests/php/CfgAdaptersTest.php, tests/php/RollbackContractTest.php.
// Naming follows pfb_* conventions (CLAUDE.md "Naming").
// ---------------------------------------------------------------------------

// PfbStoredEnum — the contract every config-backed enum implements. Keeps the
// reader/writer dumb: read = EnumClass::fromStored($raw), write = $enum->toStored().
interface PfbStoredEnum
{
	// Parse-fallback for unknown/non-scalar input. NOT the per-field absent default
	// (that is the registry's $entry['default'], applied by PfbConfig::read()).
	public static function default(): static;

	// Stored config value (string, NULL, or non-scalar) -> enum. The enum owns its
	// '' (EMPTY), legacy-alias, and junk handling.
	public static function fromStored(mixed $stored): static;

	// Enum -> the canonical token persisted to config.xml / py_unbound.ini.
	public function toStored(): string;
}

// PfbStoredEnumAdapter — shared fromStored/toStored mechanics. An enum customises
// its semantics by setting default() (fallback) and overriding fromLegacy() (aliases).
trait PfbStoredEnumAdapter
{
	public static function fromStored(mixed $stored): static
	{
		// Idempotency: a value already adapted to this enum (e.g. a PfbConfig::read()
		// result fed back through the read adapter) returns itself. Without this, the
		// non-scalar guard below would collapse a valid enum to default() — a double-apply
		// footgun that silently mis-rendered toggle checkboxes (always-unchecked) on the
		// settings pages.
		if ($stored instanceof static) {
			return $stored;
		}
		if (!is_scalar($stored) && $stored !== NULL) {
			return static::default();		// subtree / non-scalar guard
		}
		// NULL collapses to '' here — a gateway read has already applied the registry
		// per-field default, so NULL only reaches this path from direct callers.
		$raw = (string) ($stored ?? '');
		return self::tryFrom($raw) ?? static::fromLegacy($raw);
	}

	// '' (EMPTY) and any non-canonical token. Override per enum for legacy aliases.
	protected static function fromLegacy(string $raw): static
	{
		return static::default();
	}

	public function toStored(): string
	{
		return $this->value;
	}
}

// PfbToggle — checkbox fields stored as 'on' (checked) or '' (unchecked).
//   Stored vocabulary: 'on' | '' (missing/unchecked = ''). '' is the Off case, so
//   tryFrom('') resolves it directly; the per-field absent default is the registry's.
enum PfbToggle: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	case On  = 'on';
	case Off = '';

	// Parse-fallback ONLY (unknown/non-scalar -> "not On"). NOT the absent default.
	public static function default(): static
	{
		return self::Off;
	}
}

// PfbLenient — a tri-state {on, off, legacy ''} flag (the explicit 'off' token
// survives the live config round-trip where a toggle's '' off-value would not).
//
// Used by: pfb_dnsbl_lenient (pfb_dnsblconfig['pfb_dnsbl_lenient'], ADR-22 scheme-parsing
//   leniency) and pfb_keep (#484 — so a default-on keep flag can store 'off' explicitly).
//   Stored vocabulary: 'on' | 'off' | '' (legacy: a missing pre-ADR-22 / pre-#484 install).
//   pfb_global() reads pfb_dnsbl_lenient as a PfbLenient enum via PfbConfig::read()
//   (the registry wires pfb_cfg_lenient_read/write); consumers compare === PfbLenient::On.
//   Note: '' (missing key) maps to Off ('off'), NOT to the PfbToggle '' value.
//   This field's "off" stored value is 'off', distinct from PfbToggle::Off = ''.
enum PfbLenient: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	case On  = 'on';
	case Off = 'off';

	// NULL/absent -> registry default; '' (legacy missing) and junk -> Off (via fromLegacy).
	public static function default(): static
	{
		return self::Off;
	}
}

// PfbIdnMode — ADR-08 IDN-feature mode selector. Adopted into the PfbConfig gateway.
//
// Used by: pfb_idn (config key) / $pfb['dnsbl_idn'] (runtime).
//   Canonical tokens (config.xml AND py_unbound.ini AND the Python IdnMode enum, all the
//   same vocabulary): 'on' (= All), 'confusable', 'off'. '' / unknown -> Off.
//   Reusing the original 'on' token for All is the key move — pre-4.0.0 installs round-trip
//   with no migration and an older release reading 'on' still blocks all IDN (behaviour
//   preserved on downgrade). 'confusable' is the only genuinely new token; an old release
//   treats it as off (acceptable). PfbConfig::read('pfb_idn') returns the enum;
//   PfbConfig::write() persists toStored(); the ini build emits the same toStored() token.
enum PfbIdnMode: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	// All reuses the original 'on' token (pre-ADR-08 block-all-IDN) as its backing value:
	// it round-trips with ZERO migration AND is downgrade-safe — an older release reading
	// 'on' still blocks all IDN. Only Confusable is a genuinely new token (an old release
	// treats it as off, which is acceptable). The SAME token feeds config.xml, py_unbound.ini,
	// and the Python IdnMode enum — one canonical vocabulary, no per-consumer serialisation.
	case All        = 'on';
	case Confusable = 'confusable';
	case Off        = 'off';

	// Parse-fallback (unknown / '' -> Off via the trait); the per-field absent default is
	// the registry's. No legacy alias: the only other historical token was the 4.0.0-alpha
	// 'all', and breaking alpha-only compatibility is acceptable.
	public static function default(): static
	{
		return self::Off;
	}
}

// PfbAliasDeltaMode — ADR-40 alias-table apply mechanism selector.
//
// Three modes control how pfBlockerNG applies alias-table changes to the pf kernel:
//   Auto    ('auto')    — default; delta (-T add/-T delete) for small churn (< ~5%),
//                         full -T replace for initial load / boot / large churn. Safe
//                         default for all deployments.
//   Delta   ('delta')   — ALWAYS apply via forward delta (-T add/-T delete); NO
//                         large-churn replace fallback. Power-user/controlled-incremental
//                         override — can be slow on a full-table rebuild. Use 'auto' for
//                         the safe default.
//   Replace ('replace') — always full -T replace (pre-ADR-40 behaviour).
//
// Absent-default = 'auto' for a NEW install. An already-configured install is grandfathered to
// 'replace' (pre-ADR-40 full -T replace) by a one-time install/upgrade seed
// (pfb_alias_delta_mode_install_default() + pfblockerng_install.inc), so an upgrade preserves the
// operator's prior apply path instead of silently switching to delta — the absent-default 'auto'
// reaches only brand-new installs. Downgrade-safe: an older release lacking this key ignores it
// and performs its existing full replace.
enum PfbAliasDeltaMode: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	case Auto    = 'auto';
	case Delta   = 'delta';
	case Replace = 'replace';

	public static function default(): static
	{
		return self::Auto;
	}
}

/** Read a PfbAliasDeltaMode from a raw stored value. */
function pfb_cfg_alias_delta_mode_read(mixed $stored): PfbAliasDeltaMode
{
	return PfbAliasDeltaMode::fromStored($stored);
}

/** Write a PfbAliasDeltaMode back to its canonical stored token. */
function pfb_cfg_alias_delta_mode_write(PfbAliasDeltaMode|string $mode): string
{
	return ($mode instanceof PfbAliasDeltaMode ? $mode : PfbAliasDeltaMode::fromStored($mode))->toStored();
}

// Thin delegations to the enum adapters (PfbStoredEnum::fromStored / toStored).
// Kept so the registry callables + the direct www/ callers have a free-function
// handle; all semantics live on the enums.

/** Read a PfbToggle from a raw stored value. */
function pfb_cfg_toggle_read(mixed $stored): PfbToggle
{
	return PfbToggle::fromStored($stored);
}

/** Write a PfbToggle (enum or legacy string) back to its stored string. */
function pfb_cfg_toggle_write(PfbToggle|string $toggle): string
{
	return ($toggle instanceof PfbToggle ? $toggle : PfbToggle::fromStored($toggle))->toStored();
}

/** Read a PfbLenient from a raw stored value. */
function pfb_cfg_lenient_read(mixed $stored): PfbLenient
{
	return PfbLenient::fromStored($stored);
}

/** Write a PfbLenient (enum or legacy string) back to its stored string. */
function pfb_cfg_lenient_write(PfbLenient|string $lenient): string
{
	return ($lenient instanceof PfbLenient ? $lenient : PfbLenient::fromStored($lenient))->toStored();
}

/** Read a PfbIdnMode from a raw stored value (legacy 'on' -> All). */
function pfb_cfg_idn_mode_read(mixed $stored): PfbIdnMode
{
	return PfbIdnMode::fromStored($stored);
}

/**
 * Write a PfbIdnMode (enum or legacy string) back to its canonical stored token
 * ('on' | 'confusable' | 'off'). All persists as the legacy 'on' token (reproduces
 * the prior block-all-IDN behaviour); the 4.0.0-alpha 'all' token is dropped to 'off'.
 */
function pfb_cfg_idn_mode_write(PfbIdnMode|string $mode): string
{
	return ($mode instanceof PfbIdnMode ? $mode : PfbIdnMode::fromStored($mode))->toStored();
}

// ---------------------------------------------------------------------------
// ADR-29 Phase 1 — PfbConfig gateway + declarative field registry.
//
// PfbConfig is the single sanctioned gateway for all config.xml reads/writes
// of registered installedpackages/pfblockerng* keys. It wraps
// config_get_path / config_set_path / config_del_path, applying the
// registered default and the field-aware adapter (from ADR-28) at the
// boundary.
//
// Field registry shape (pfb_cfg_registry()):
//   key => [
//     'section'       => 'installedpackages/pfblockerng*/config/0',  // config.xml path prefix
//     'default'       => <stored-string default for absent/null>,
//     'read_adapter'  => callable|null,   // null = plain string (identity)
//     'write_adapter' => callable|null,   // null = plain string (identity)
//     'since'         => 'x.y.z',        // version that introduced the key
//   ]
//
// Section-level helpers (read/write/delete a whole section) allow www/ pages and
// pfb_remove_config_settings() to flow through one gateway call in later phases.
//
// CONSTRAINTS (ADR-29 §5, ADR-28 §2.2):
//   - Registry keys are the EXACT existing config.xml keys — no renames.
//   - Stored values NEVER change; adapters map to the legacy stored string on write.
//   - Round-trip identity: write(read(v)) == v for every canonical stored value.
//   - This phase adds the class + registry only; no call site changed yet.
//
// Tests: tests/php/CfgGatewayTest.php (round-trip, default, inventory).
// ---------------------------------------------------------------------------

/**
 * pfb_cfg_registry — the declarative field registry for all registered
 * installedpackages/pfblockerng* scalar keys.
 *
 * Returns a flat map of config-key => descriptor. Keys are the exact strings
 * used in config.xml, grouped loosely by config section.
 *
 * Read adapter: callable(mixed $stored): <enum|string>  — stored string -> runtime value.
 * Write adapter: callable(<enum|string> $value): string — runtime value -> stored string.
 * null adapter = plain string (identity; no conversion).
 *
 * @return array<string,array{section:string,default:string,read_adapter:callable|null,write_adapter:callable|null,since:string}>
 */
function pfb_cfg_registry(): array
{
	static $registry = NULL;
	if ($registry !== NULL) {
		return $registry;
	}

	// -----------------------------------------------------------------------
	// Section: installedpackages/pfblockerng/config/0  (general settings)
	// -----------------------------------------------------------------------
	$gen = 'installedpackages/pfblockerng/config/0';

	// -----------------------------------------------------------------------
	// Section: installedpackages/pfblockerngdnsblsettings/config/0
	// -----------------------------------------------------------------------
	$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

	// -----------------------------------------------------------------------
	// Section: installedpackages/pfblockerngsafesearch  (flat, no /config/0)
	// -----------------------------------------------------------------------
	$ss = 'installedpackages/pfblockerngsafesearch';

	// -----------------------------------------------------------------------
	// Section: installedpackages/pfblockerngipsettings/config/0
	// -----------------------------------------------------------------------
	$ip = 'installedpackages/pfblockerngipsettings/config/0';

	$registry = [

		// -------------------------------------------------------------------
		// General section (pfblockerng/config/0)
		// -------------------------------------------------------------------

		// Master enable/disable: 'on' | '' (checkbox).
		'enable_cb' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '1.0.0',
		],

		// Keep blocklists when pfBlockerNG is disabled: 'on' | 'off' | ''.
		// Default ON — the #281 canonical default; GUI and pfb_global() agree.
		// Uses the lenient adapter so an unchecked-save (off) is stored as the
		// explicit 'off' token, distinguishable from a never-configured install
		// (key absent) which the registry default returns as 'on'. The empty-string
		// '' is a LEGACY READ token for installs written before this fix; it maps
		// to Off on read, same as 'off'. Write always emits 'off' (backward-safe:
		// older releases that read 'off' for pfb_keep treat it as "disabled").
		'pfb_keep' => [
			'section'       => $gen,
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_lenient_read',
			'write_adapter' => 'pfb_cfg_lenient_write',
			'since'         => '2.1.0',
		],

		// Update interval: numeric hour string | 'Disabled'. Default '1'.
		'pfb_interval' => [
			'section'       => $gen,
			'default'       => '1',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Cron start minute ('0'|'15'|'30'|'45'). Default '0'.
		'pfb_min' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Cron start hour (0-23 as string). Default '0'.
		'pfb_hour' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Once-a-day start hour (0-23 as string). Default '0'.
		'pfb_dailystart' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Max daily download failure threshold ('0' = unlimited). Default '0'.
		'skipfeed' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// ADR-11: CSV of active aggregate alias types (e.g. 'Deny,Permit'). Default ''.
		'pfb_agg_types' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.2.0',
		],

		// Log rotation limits (all numeric strings; default '20000').
		'log_max_log' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_errlog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_extraslog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_ip_blocklog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_ip_permitlog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_ip_matchlog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_dnslog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_dnsbl_parse_err' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_dnsreplylog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_unilog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// ADR-30: per-log scheduled reset period (off|daily|weekly|monthly). Default 'off'.
		// Vocabulary: {'off','daily','weekly','monthly'}. Plain-string (identity) adapter.
		// Mirrors the log_max_<type> set exactly — one entry per managed log type.
		// 'since' = '4.0.0' — the first release that ships these fields.
	];

	$log_types = [
		'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
		'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
	];
	foreach ($log_types as $log_type) {
		$registry['log_rotate_' . $log_type] = [
			'section'       => $gen,
			'default'       => 'off',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		];
		// ADR-30 amendment: lines to keep when a scheduled reset fires (numeric string).
		// Default '0' = clear fully. Plain-string (identity) adapter; mirrors log_rotate_<type>.
		$registry['log_reset_keep_' . $log_type] = [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		];
	}

	$registry = $registry + [

		// Software update check last-seen version (string or null). Default ''.
		'pfb_software_check' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// Internal-address feed-host filter toggle: 'on'|'off'. Default 'on' (new install).
		'pfb_feed_internal_filter' => [
			'section'       => $gen,
			'default'       => 'on',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.1.0',
		],

		// Allowlist for internal-feed hosts (base64-encoded). Default ''.
		'pfb_feed_internal_allowlist' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.1.0',
		],

		// ADR-49: opt-in plain-text feed sanity scan. Checkbox 'on'|''(off).
		// Default off (absent = off = today's behaviour: the scan never runs).
		'pfb_feed_sanity' => [
			'section'       => $gen,
			'default'       => '',                       // absent -> Off (new-install default too)
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// Reuse blocklists across updates: 'on' | '' (checkbox). Default ''.
		'pfb_reuse' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '2.0.0',
		],

		// ADR-40: alias-table apply mode: 'auto' | 'delta' | 'replace'. New-install default 'auto'.
		// 'auto' = delta for small churn (< ~5%), full replace for initial load / large churn;
		// 'delta' = ALWAYS forward delta, NO large-churn replace fallback (power-user override);
		// 'replace' = always full -T replace (pre-ADR-40 behaviour).
		// Existing installs are grandfather-seeded to 'replace' at install/upgrade
		// (pfb_alias_delta_mode_install_default); only brand-new installs take the 'auto' default.
		'pfb_alias_delta_mode' => [
			'section'       => $gen,
			'default'       => 'auto',
			'read_adapter'  => 'pfb_cfg_alias_delta_mode_read',
			'write_adapter' => 'pfb_cfg_alias_delta_mode_write',
			'since'         => '4.0.0',
		],

		// ADR-40: alias-table delta batch size (integer as string). Default '512'.
		// Clamped to [64, 4096] on read. Batch=512 is optimal for sub-1M tables
		// (zero ICMP stalls at 100k/1k-churn); batch=1024+ for 1M+ tables.
		'pfb_alias_delta_batch' => [
			'section'       => $gen,
			'default'       => '512',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-43: tick-cron dispatch interval in minutes (1–60). Default '15'.
		// One cron tick fires every */pfb_tick_interval; jobs run only when due
		// per the due-ledger. Default 15 matches the tightest existing job (ss_refresh).
		'pfb_tick_interval' => [
			'section'       => $gen,
			'default'       => '15',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-43 P5: optional apply-on-change maintenance window ("HH:MM-HH:MM", local time).
		// When set: detected changes outside the window are deferred (pending); the first tick
		// inside the window applies them. Empty string (default) = apply immediately (no deferral).
		// Wrapping windows (e.g. "23:00-03:00") span midnight. Malformed = fail-safe (apply now).
		'pfb_quiet_hours' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// -------------------------------------------------------------------
		// DNSBL settings section (pfblockerngdnsblsettings/config/0)
		// -------------------------------------------------------------------

		// DNSBL master enable: 'on' | '' (checkbox).
		'pfb_dnsbl' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '1.0.0',
		],

		// ADR-13: auto-create/remove DNSBL sinkhole VIPs: 'on' | '' (checkbox).
		'pfb_dnsvip_auto' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '3.0.0',
		],

		// [ #381 ] Opt out of automatic DNSBL sinkhole NAT rule generation: 'on' | '' (checkbox).
		// Default '' = NAT generated (current behaviour); 'on' = user manages NAT manually.
		'pfb_dnsbl_nonat' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// VIP interface for DNSBL sinkhole. Default 'lo0'.
		'dnsbl_interface' => [
			'section'       => $dnsbl,
			'default'       => 'lo0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL IPv4 sinkhole VIP id string. Default ''.
		'pfb_dnsvip4' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL IPv6 sinkhole VIP id string. Default ''.
		'pfb_dnsvip6' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL lighttpd HTTP port. Default '' (system default).
		'pfb_dnsport' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL lighttpd HTTPS port. Default ''.
		'pfb_dnsport_ssl' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// TOP1M (Alexa/Tranco) whitelist enable. Default ''.
		'alexa_enable' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// TOP1M type selector ('tranco'|'alexa'|'cisco'). Default 'tranco'.
		'alexa_type' => [
			'section'       => $dnsbl,
			'default'       => 'tranco',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// TOP1M domain count (numeric string). Default '1000'.
		'alexa_count' => [
			'section'       => $dnsbl,
			'default'       => '1000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// TOP1M TLD inclusions for whitelisting. Default ''.
		'alexa_inclusion' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Resolver cache backup/restore option. Default ''.
		'pfb_cache' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Global logging/blocking mode. Default ''.
		'global_log' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// ADR-22: scheme-parsing leniency: 'on' | 'off' | ''. Default 'off'.
		// PfbLenient adapter (off-value = 'off', not '').
		'pfb_dnsbl_lenient' => [
			'section'       => $dnsbl,
			'default'       => 'off',
			'read_adapter'  => 'pfb_cfg_lenient_read',
			'write_adapter' => 'pfb_cfg_lenient_write',
			'since'         => '3.1.0',
		],

		// Python DNS reply logging. Default ''.
		'pfb_py_reply' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// HSTS null-blocking mode: 'on' | ''. Default ''.
		'pfb_hsts' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '3.0.0',
		],

		// ADR-08: IDN mode — adopted into the gateway as a PfbIdnMode enum (ADR-28
		// reframe: preserve behaviour on upgrade, not byte-identical storage). Read
		// normalises legacy 'on' -> All; write persists the canonical token
		// ('all'|'confusable'|'off'), so a stored legacy 'on'/'' migrates on next save
		// to a behaviour-equivalent value. Downgrade-safe: older releases string-compared
		// these tokens, so an unknown token falls through to their off default.
		// See ADR-28 §2.2 + CfgAdaptersTest + RollbackContractTest.
		'pfb_idn' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_idn_mode_read',
			'write_adapter' => 'pfb_cfg_idn_mode_write',
			'since'         => '3.0.0',
		],

		// Confusable: block malicious homoglyphs (default on). Default 'on'.
		'pfb_idn_block_malicious' => [
			'section'       => $dnsbl,
			'default'       => 'on',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Confusable: escalate suspicious mixed-script to block (opt-in). Default ''.
		'pfb_idn_escalate_suspicious' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Python regex: 'on' | ''. Default ''.
		'pfb_regex' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Python regex list (textarea). Default ''.
		'pfb_regex_list' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Python regex static cap ('on'|''). Default ''.
		'pfb_regex_cap' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// CNAME validation. Default ''.
		'pfb_cname' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// TLD Allow option. Default ''.
		'pfb_pytld' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Log events via DNSBL Webserver vs python. Default ''.
		'pfb_py_nolog' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// No AAAA blocking: 'on' | ''. Default ''.
		'pfb_noaaaa' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// No AAAA list (textarea). Default ''.
		'pfb_noaaaa_list' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// DNSBL bypass enable: 'on' | ''. Default ''.
		'pfb_gp' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// DNSBL bypass local IP list (textarea). Default ''.
		'pfb_gp_bypass_list' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// TLD blacklist (textarea). Default ''.
		'tldblacklist' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// TLD exclusion (textarea). Default ''.
		'tldexclusion' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL suppression/whitelist (base64). Default ''.
		'suppression' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL action for IP blocking. Default 'Disabled'.
		'action' => [
			'section'       => $dnsbl,
			'default'       => 'Disabled',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Auto-create floating pass rule. Default 'Disabled'.
		'pfb_dnsbl_rule' => [
			'section'       => $dnsbl,
			'default'       => 'Disabled',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Allow-interface for DNSBL (multi-select). Default ''.
		'dnsbl_allow_int' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Python control integration. Default ''.
		'pfb_control' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Legacy DNS-TXT control transport (deprecated). Default ''.
		'pfb_control_legacy' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Python cache max (numeric string). Default '' (unlimited).
		'pfb_py_cache_max' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// TLD blocking enable. Default ''.
		'pfb_tld' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Aliaslog (logging mode). Default ''.
		'aliaslog' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// ADR-36: NAT DNS-redirect enable: 'on' | '' (checkbox). Default '' (off).
		'dnsbl_redir' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// ADR-36: NAT DNS-redirect interface multi-select (comma-joined string). Default ''.
		'dnsbl_redir_int' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-36: NAT DNS-redirect exception alias/IP string. Default ''.
		'dnsbl_redir_exclude' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block enable: 'on' | '' (checkbox). Default '' (off).
		'dnsbl_dot_block' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block interface multi-select (comma-joined string). Default ''.
		'dnsbl_dot_block_int' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block exception alias/IP string. Default ''.
		'dnsbl_dot_block_exclude' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block rule action: 'reject' (default) | 'block'.
		// Mirrors the IP-settings inbound/outbound Rule Action selector. Reject
		// fast-fails the client (outbound LAN->WAN rule); block silently drops.
		'dnsbl_dot_block_action' => [
			'section'       => $dnsbl,
			'default'       => 'reject',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block floating mode: 'on' | '' (checkbox). Default '' (off).
		// On = a single floating rule (direction 'in') over the selected interfaces
		// instead of one rule per interface. Off preserves the per-interface default.
		'dnsbl_dot_block_floating' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// -------------------------------------------------------------------
		// ADR-38: syslog export settings (General / Log Settings section, $gen)
		// -------------------------------------------------------------------

		// Master toggle — emit security events to syslog: 'on' | '' (checkbox).
		// Default '' (off) — zero impact on existing installs.
		// ADR-38 Amendment 1: only the master toggle is configurable. The export
		// facility (LOG_LOCAL6) and severity (LOG_INFO) are fixed in
		// pfb_syslog_event() — events route to the dedicated pfblockerng_syslog.log
		// by program name, so facility never affects routing, and every event is
		// the same class of informational record, so a severity picker is moot.
		'log_syslog' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// -------------------------------------------------------------------
		// SafeSearch section (pfblockerngsafesearch — flat, no /config/0)
		// -------------------------------------------------------------------

		// SafeSearch enable mode. Default 'Disable'.
		'safesearch_enable' => [
			'section'       => $ss,
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// YouTube SafeSearch mode. Default 'Disable'.
		'safesearch_youtube' => [
			'section'       => $ss,
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// DNS-over-HTTPS blocking mode. Default 'Disable'.
		'safesearch_doh' => [
			'section'       => $ss,
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// DoH domain exclusion list (CSV). Default ''.
		'safesearch_doh_list' => [
			'section'       => $ss,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// -------------------------------------------------------------------
		// IP settings section (pfblockerngipsettings/config/0)
		// -------------------------------------------------------------------

		// ADR-53: IPv4 suppression customlist -- CIDR/host carve-outs from the
		// Deny alias set, stored as a base64-encoded newline-separated list
		// (same shape as the DNSBL 'suppression' blob above). Registered so
		// every call site routes through the gateway; this is a legacy key
		// from the original addon (mirrors the '1.0.0' vintage of the sibling
		// DNSBL blob fields). Default ''.
		'v4suppression' => [
			'section'       => $ip,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// ADR-53 P6: IPv6 suppression customlist -- the v4 blob's v6 sibling
		// (same base64/newline-separated shape). Genuinely new (no pre-registry
		// era to inherit from v4suppression's), so 'since' is the current
		// development version rather than a legacy '1.0.0'. Default ''.
		'v6suppression' => [
			'section'       => $ip,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],
	];

	return $registry;
}

// Read the configured DNSBL block-page template filename. issue #713: this is a
// FOREIGN key (ADR-29 §2.5 out-of-scope) written directly by pfblockerng_dnsbl.php
// as 'dnsbl_webpage' — NOT a gateway-registered key — so it is read here with a
// direct config_get_path(), mirroring how the DNSBL settings page stores and reads
// it ($pfb['dconfig']['dnsbl_webpage'] ?: 'dnsbl_default.php'). config_get_path()'s
// default arg only substitutes when the key is ABSENT, not when it is present but
// empty (''), so the `?:` coercion below is required to actually match that page —
// a saved-then-cleared 'dnsbl_webpage' must still report 'dnsbl_default.php', the
// same as an install that never saved DNSBL settings (and the install/upgrade
// refresh of dnsbl_active.php then fires). Fixes the dead read of the mis-spelled
// 'dnsblwebpage' registry key, which always returned '' because nothing ever
// writes that path.
function pfb_dnsbl_webpage(): string
{
	return config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_webpage', 'dnsbl_default.php') ?: 'dnsbl_default.php';
}

/**
 * PfbConfig — the centralized gateway for registered config.xml keys.
 *
 * All reads and writes of registered keys (pfb_cfg_registry()) must flow
 * through this class. Non-registered (foreign) keys continue to use
 * config_get_path / config_set_path / config_del_path directly.
 *
 * API:
 *   PfbConfig::read($key)                          — read one field
 *   PfbConfig::write($key, $value)                 — write one field
 *   PfbConfig::delete($key)                        — delete one field
 *   PfbConfig::readSection($section)               — read a whole section array
 *   PfbConfig::writeSection($section, $data)       — write a whole section array
 *   PfbConfig::deleteSection($section)             — delete a whole section
 *
 * @see pfb_cfg_registry()
 */
final class PfbConfig
{
	/**
	 * Read a single registered field.
	 *
	 * Returns the registered default when the key is absent/null; applies
	 * the registered read adapter (stored string -> runtime enum/string).
	 *
	 * @param  string $key  The exact config.xml field key (e.g. 'pfb_keep').
	 * @return mixed        Runtime value (enum or string).
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	public static function read(string $key): mixed
	{
		$entry   = self::entry($key);
		$path    = $entry['section'] . '/' . $key;
		$raw     = config_get_path($path, NULL);
		$stored  = ($raw === NULL) ? $entry['default'] : (string) $raw;
		$adapter = $entry['read_adapter'];
		return ($adapter !== NULL) ? $adapter($stored) : $stored;
	}

	/**
	 * Write a single registered field.
	 *
	 * Applies the registered write adapter (runtime value -> exact legacy
	 * stored string) before calling config_set_path. Does NOT call
	 * write_config() — callers must persist when appropriate.
	 *
	 * @param  string $key   The exact config.xml field key.
	 * @param  mixed  $value Runtime value (enum or string).
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	public static function write(string $key, mixed $value): void
	{
		$entry   = self::entry($key);
		$path    = $entry['section'] . '/' . $key;
		$adapter = $entry['write_adapter'];
		$stored  = ($adapter !== NULL) ? $adapter($value) : (string) $value;
		config_set_path($path, $stored);
	}

	/**
	 * Delete a single registered field.
	 *
	 * @param  string $key  The exact config.xml field key.
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	public static function delete(string $key): void
	{
		$entry = self::entry($key);
		$path  = $entry['section'] . '/' . $key;
		config_del_path($path);
	}

	/**
	 * Read a whole section as a raw array (no per-key adapters applied).
	 *
	 * This is the equivalent of config_get_path($section, []) for callers
	 * (www/ pages, pfb_global) that load an entire section blob at once
	 * and access keys individually. Phase 1 exposes this seam without
	 * changing existing call sites; later phases route per-key reads through
	 * it.
	 *
	 * @param  string $section  The full config.xml section path (e.g.
	 *                          'installedpackages/pfblockerng/config/0').
	 * @return array            Raw config array (empty when absent).
	 */
	public static function readSection(string $section): array
	{
		$raw = config_get_path($section, []);
		return is_array($raw) ? $raw : [];
	}

	/**
	 * Write a whole section array (no per-key adapters applied).
	 *
	 * Equivalent to config_set_path($section, $data) for callers that
	 * manipulate the section blob directly (www/ save handlers). Does NOT
	 * call write_config() — callers persist.
	 *
	 * @param string $section  The full config.xml section path.
	 * @param array  $data     Section data to persist.
	 */
	public static function writeSection(string $section, array $data): void
	{
		config_set_path($section, $data);
	}

	/**
	 * Delete a whole section (e.g. during package removal / wipe).
	 *
	 * Equivalent to config_del_path($section).
	 *
	 * @param string $section  The full config.xml section path.
	 */
	public static function deleteSection(string $section): void
	{
		config_del_path($section);
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	/**
	 * Look up a registry entry, throwing on an unregistered key.
	 *
	 * @param  string $key
	 * @return array{section:string,default:string,read_adapter:callable|null,write_adapter:callable|null,since:string}
	 * @throws InvalidArgumentException
	 */
	private static function entry(string $key): array
	{
		$registry = pfb_cfg_registry();
		if (!array_key_exists($key, $registry)) {
			throw new InvalidArgumentException(
				"PfbConfig: key '{$key}' is not in the field registry. "
				. 'Use config_get_path() directly for foreign/unregistered keys.'
			);
		}
		return $registry[$key];
	}
}

// ---------------------------------------------------------------------------
// ADR-29 Phase 2 — Migration registry + driver.
//
// pfb_migration_registry() is the ordered, idempotent, since-version-gated
// inventory of every upgrade migration. Each entry delegates to an existing
// *_migrate / *_seed helper (from pfblockerng.inc) and carries the exact
// write_config() message that appeared in the original install.inc block.
//
// Registry shape:
//   'id'       => string — unique, stable identifier for the migration
//   'section'  => string — full config.xml section path to read/write
//   'apply'    => callable($cfg: array): ?array
//                   returns the updated section array to persist,
//                   or NULL for a no-op (already migrated / fresh install)
//   'message'  => string — write_config() description when the migration writes
//   'since'    => string — version that introduced the migration
//
// The driver in pfblockerng_install.inc calls pfb_run_migrations() to execute
// all entries in registry order. The helper bodies are UNCHANGED; this registry
// only wraps/calls them so the install.inc is one loop instead of four blocks.
//
// Tests: tests/php/MigrationRegistryTest.php
// ---------------------------------------------------------------------------

/**
 * pfb_migration_registry — the ordered list of upgrade migrations.
 *
 * Returns an array of migration descriptor maps, in the order they must run.
 * Each entry's 'apply' callable wraps an existing *_migrate / *_seed helper.
 *
 * @return list<array{id:string,section:string,apply:callable,message:string,since:string}>
 */
function pfb_migration_registry(): array
{
	$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
	$gen   = 'installedpackages/pfblockerng/config/0';

	return [
		// 1. ADR-02: force DNSBL to python-only mode.
		[
			'id'      => 'adr02-dnsbl-python-mode',
			'section' => $dnsbl,
			'apply'   => 'pfb_dnsbl_python_migrate',
			'message' => 'pfBlockerNG: migrated DNSBL to Python-only mode',
			'since'   => '2.0.0',
		],
		// 2. PFBL-03: one-time seed of the deprecated legacy DNS-TXT control toggle.
		[
			'id'      => 'pfbl03-control-legacy-seed',
			'section' => $dnsbl,
			'apply'   => 'pfb_control_legacy_seed',
			'message' => 'pfBlockerNG: seeded legacy DNSBL control toggle (PFBL-03)',
			'since'   => '3.2.0',
		],
		// 3. ADR-22: preserve permissive DNSBL scheme parsing for existing installs.
		[
			'id'      => 'adr22-dnsbl-lenient',
			'section' => $dnsbl,
			'apply'   => 'pfb_dnsbl_lenient_migrate',
			'message' => 'pfBlockerNG: preserve permissive DNSBL parsing for existing install (ADR-22 migration)',
			'since'   => '3.2.0',
		],
		// 4. Issue #281: seed pfb_keep to preserve settings across pkg upgrade.
		[
			'id'      => 'issue281-pfb-keep-seed',
			'section' => $gen,
			'apply'   => 'pfb_keep_migrate',
			'message' => 'pfBlockerNG: preserve settings across upgrade (seed Keep flag, issue #281)',
			'since'   => '3.2.0',
		],
	];
}

/**
 * pfb_run_migrations — execute all registered upgrade migrations in order.
 *
 * Iterates pfb_migration_registry(). For each entry: reads the registered
 * section, calls apply($cfg), and when the result is non-NULL writes it back
 * and calls write_config() with the entry's message. Each migration's own
 * apply() is responsible for run-once / idempotency (NULL = already done).
 */
function pfb_run_migrations(): void
{
	foreach (pfb_migration_registry() as $migration) {
		$cfg    = PfbConfig::readSection($migration['section']);
		$result = ($migration['apply'])($cfg);
		if ($result !== NULL) {
			PfbConfig::writeSection($migration['section'], $result);
			write_config($migration['message']);
		}
	}
}

// ---------------------------------------------------------------------------
// ADR-29 Phase 3 — Rollback / backward-compat contract helpers.
//
// pfb_cfg_field_vocab() documents the FULL STORED VOCABULARY for every
// registered field adapter type. The tests (RollbackContractTest.php) use
// this to assert the FORWARD invariant (every legacy stored token yields a
// sane runtime value) and the BACKWARD invariant (every write emits ONLY a
// token in the legacy vocabulary — never a novel on-disk token an older
// release would not recognise).
//
// ROLLBACK CONTRACT (ADR-29 §2.3):
//   - A field PASSES the backward invariant iff, for every possible runtime
//     value R, write_adapter(R) returns a string that is a member of the
//     field's legacy stored vocabulary.  The gateway always writes legacy
//     tokens, so downgrades leave older code reading values it already
//     understands.
//   - At the PfbConfig level no field is excluded: every write adapter emits a
//     token from the field's known vocabulary. A write may NORMALISE a legacy
//     token to a behaviour-equivalent canonical one (e.g. pfb_idn: All persists
//     the legacy 'on' token, and the dropped 4.0.0-alpha 'all' normalises to
//     'off') — the emitted token is always one an older release understands.
//
// SINCE-VERSION CONVENTION:
//   The 'since' field in pfb_cfg_registry() records the package release that
//   INTRODUCED the key to config.xml. For keys that pre-date the registry
//   (i.e. existed before ADR-29 Phase 1), 'since' is set to the earliest
//   release that still ships the pfBlockerNG line that uses the key — using
//   the legacy release series as a conservative baseline (e.g. '1.0.0' for
//   original-era keys, '2.0.0' for the Python-mode era, '3.x.y' for ADR-xx
//   additions).  The current shipped devel version is always an acceptable
//   baseline for any key whose introduction predates the registry (there is
//   no config-version migration routine, so any installed config.xml may
//   contain any subset of these keys).
// ---------------------------------------------------------------------------

/**
 * pfb_cfg_field_vocab — the legacy stored vocabulary for each adapter type.
 *
 * Returns a map of adapter-type label => array of ALL strings a pre-ADR-29
 * release might have persisted for a field of that type.  Tests iterate over
 * each registered field's adapter to select the matching vocabulary, then
 * assert:
 *
 *   FORWARD: read_adapter($stored) does not crash and returns a well-formed
 *            runtime value for EVERY token in the vocabulary.
 *   BACKWARD: write_adapter(read_adapter($stored)) ∈ vocabulary for every
 *             canonical stored token (i.e. the gateway never emits a novel
 *             on-disk string an older release would not recognise).
 *
 * Adapter types:
 *   'toggle'  — PfbToggle fields: 'on' | '' (checked/unchecked checkbox).
 *   'lenient' — PfbLenient fields: 'on' | 'off' | '' ('' = pre-ADR-22 absent).
 *   'plain'   — null/null adapters: any string; identity through (no novel token).
 *
 * The idn-mode adapter (pfb_cfg_idn_mode_read/write) IS wired at PfbConfig level
 * for pfb_idn. All canonicalises to the legacy 'on' token, so writes only emit the
 * idn vocabulary ('on'|'confusable'|'off'); the dropped 4.0.0-alpha 'all' token is
 * read as Off and never written.
 *
 * @return array<string,list<string>>
 */
function pfb_cfg_field_vocab(): array
{
	return [
		// Toggle checkbox: 'on' (enabled) | '' (disabled / absent). No novel tokens.
		'toggle'  => ['on', ''],

		// Lenient flag: 'on' (enabled) | 'off' (disabled) | '' (pre-ADR-22 absent).
		// '' is a legacy stored value that maps to Off on read; write emits 'off'.
		// 'off' is a legacy token (predates ADR-22 — the migration only runs when
		// the key is entirely absent, not when it is 'off'). Backward-safe: any
		// older release that reads 'off' treats it as "disabled", which is correct.
		'lenient' => ['on', 'off', ''],

		// IDN mode (PfbIdnMode): the tokens a write can emit. 'on' = All (reuses the
		// pre-4.0.0 block-all token, so it round-trips and an older release still blocks
		// all IDN), 'confusable', 'off'. Legacy reads '' / 'all' (4.0.0-alpha) -> Off, but
		// neither is ever WRITTEN, so they are not in the backward (write) vocabulary.
		'idn'     => ['on', 'confusable', 'off'],

		// Alias-table apply mode (PfbAliasDeltaMode, ADR-40): tokens a write can emit.
		// 'auto' (default), 'delta', 'replace'. Unknown tokens read as 'auto' (default()).
		// An older release (pre-4.0.0) has no knowledge of these fields; they simply
		// do not exist in config.xml, and the feature falls back to full replace.
		'alias_delta_mode' => ['auto', 'delta', 'replace'],

		// Plain string (null/null adapters): identity. Backward-safe by construction.
		// The 'plain' vocabulary contains the sentinel empty string; individual
		// field values are arbitrary strings (numeric, named option, etc.) but the
		// contract only requires that no novel token is INTRODUCED by the adapter.
		'plain'   => [''],
	];
}

/**
 * pfb_cfg_field_adapter_type — return the adapter type label for a registry entry.
 *
 * Returns 'toggle', 'lenient', or 'plain' — matching the keys in pfb_cfg_field_vocab().
 * Used by RollbackContractTest to look up the vocabulary for each registered field.
 *
 * @param  array $entry  A registry entry from pfb_cfg_registry().
 * @return string        Adapter type label.
 */
function pfb_cfg_field_adapter_type(array $entry): string
{
	$read = $entry['read_adapter'];
	if ($read === NULL) {
		return 'plain';
	}
	if ($read === 'pfb_cfg_lenient_read') {
		return 'lenient';
	}
	if ($read === 'pfb_cfg_idn_mode_read') {
		return 'idn';
	}
	if ($read === 'pfb_cfg_alias_delta_mode_read') {
		return 'alias_delta_mode';
	}
	// All other adapters are toggle (pfb_cfg_toggle_read).
	return 'toggle';
}

// ---------------------------------------------------------------------------
// Issue #357 — alias-rename follow-up helper.
//
// pfSense's alias-rename path (saveAlias() in alias-utils.inc) calls
// update_alias_name() to rewrite core config sections (aliases, filter,
// nat, …) but does NOT touch installedpackages/*.  The four per-row
// Advanced Inbound/Outbound alias keys (aliasports_in / aliasports_out /
// aliasaddr_in / aliasaddr_out) stored in our list sections go stale after
// a rename.  pfb_alias_rename_followup() rewrites them in-memory via the
// PfbConfig section gateway; the caller (the pre_write_config shim or any
// other save path) is responsible for persisting via write_config().
// ---------------------------------------------------------------------------

/**
 * pfb_alias_rename_followup — follow a firewall-alias rename into
 * pfBlockerNG's stored Advanced Inbound/Outbound references.
 *
 * pfSense's alias rename does not update installedpackages/*, so rewrite
 * the four alias keys everywhere pfBlockerNG stores them: the multi-row IP/
 * DNSBL feed list sections AND the single-config DNSBL-settings and GeoIP
 * continent sections (config/0), through the PfbConfig section gateway. Does
 * NOT persist (write_config is the caller's job). Returns TRUE if anything
 * changed.
 *
 * @param  string $old_name  The alias name before the rename.
 * @param  string $new_name  The alias name after the rename.
 * @return bool              TRUE when at least one key was rewritten.
 */
function pfb_alias_rename_followup(string $old_name, string $new_name): bool
{
	if ($old_name === '' || $new_name === '' || $old_name === $new_name) {
		return FALSE;
	}

	$changed = FALSE;
	$keys    = ['aliasports_in', 'aliasports_out', 'aliasaddr_in', 'aliasaddr_out'];

	// Multi-row list sections: each feed row can carry the four alias keys.
	$list_sections = ['pfblockernglistsv4', 'pfblockernglistsv6', 'pfblockerngdnsbl'];

	foreach ($list_sections as $section) {
		$path = "installedpackages/{$section}/config";
		$rows = PfbConfig::readSection($path);
		if (empty($rows)) {
			continue;
		}

		$section_dirty = FALSE;
		foreach ($rows as $i => $row) {
			foreach ($keys as $key) {
				if (($rows[$i][$key] ?? '') === $old_name) {
					$rows[$i][$key] = $new_name;
					$section_dirty  = TRUE;
					$changed        = TRUE;
				}
			}
		}

		if ($section_dirty) {
			PfbConfig::writeSection($path, $rows);
		}
	}

	// Single-config sections store the same four keys on config/0: the DNSBL
	// settings tab (pfblockerng_dnsbl.php) and every GeoIP continent tab
	// (pfblockerng.php). pfSense's alias rename skips installedpackages/* here
	// too, so the built DNSBL/GeoIP rule stops matching the stale name and
	// silently drops its In/Out restriction (#708). The continent section names
	// are 'pfblockerng' + the continent name lowercased with spaces removed
	// (the $conf_type the GeoIP page derives from $pfb['continents']).
	$cfg0_sections = [
		'pfblockerngdnsblsettings',
		'pfblockerngtopspammers',
		'pfblockerngafrica',
		'pfblockerngantarctica',
		'pfblockerngasia',
		'pfblockerngeurope',
		'pfblockerngnorthamerica',
		'pfblockerngoceania',
		'pfblockerngsouthamerica',
		'pfblockerngproxyandsatellite',
	];

	foreach ($cfg0_sections as $section) {
		$path = "installedpackages/{$section}/config/0";
		$cfg  = PfbConfig::readSection($path);
		if (empty($cfg)) {
			continue;
		}

		$section_dirty = FALSE;
		foreach ($keys as $key) {
			if (($cfg[$key] ?? '') === $old_name) {
				$cfg[$key]     = $new_name;
				$section_dirty = TRUE;
				$changed       = TRUE;
			}
		}

		if ($section_dirty) {
			PfbConfig::writeSection($path, $cfg);
		}
	}

	return $changed;
}

// ---------------------------------------------------------------------------
// Issue #356 — per-field alias-type validation helper.
//
// The four Advanced Inbound/Outbound alias fields accept different alias
// types: port fields (aliasports_*) require a pfSense 'port' alias; address
// fields (aliasaddr_*) require a 'network' or 'host' alias.  This helper
// encodes that rule in one testable place so the category-edit validation
// loop and any future caller stay in sync.
// ---------------------------------------------------------------------------

/**
 * pfb_alias_field_type_ok — check whether an alias type is valid for a
 * given Advanced Inbound/Outbound field.
 *
 * Port fields (aliasports_*) require a 'port' alias; address fields
 * (aliasaddr_*) require a 'network' or 'host' alias.
 * Unknown field names return FALSE (fail closed).
 *
 * @param  string $field       One of aliasports_in, aliasports_out,
 *                             aliasaddr_in, aliasaddr_out.
 * @param  string $alias_type  The type string returned by alias_get_type().
 * @return bool                TRUE when the alias type is allowed for this field.
 */
function pfb_alias_field_type_ok(string $field, string $alias_type): bool
{
	if ($field === 'aliasports_in' || $field === 'aliasports_out') {
		return $alias_type === 'port';
	}
	if ($field === 'aliasaddr_in' || $field === 'aliasaddr_out') {
		return $alias_type === 'network' || $alias_type === 'host';
	}
	return FALSE;
}

/**
 * pfb_adv_alias_field_errors — validate the Advanced Inbound/Outbound alias
 * fields of a category-edit POST (issue #356, #636).
 *
 * Each non-empty field must name an EXISTING firewall alias whose type the field
 * accepts (port fields -> a port alias; address fields -> a network or host alias).
 *
 * Existence AND type are resolved from alias_get_type(), which reads the
 * 'aliases/alias' configuration directly (returning '' for an unknown name) —
 * the same source the page builds its alias dropdowns/autocomplete from. This
 * deliberately replaces is_alias(): is_alias() consults the in-memory $aliastable
 * cache, populated only by alias_make_table() during filter generation, so on the
 * category-edit page that cache is empty and is_alias() reports every existing
 * alias as missing — rejecting valid aliases with "Must use an existing Alias" (#636).
 *
 * @param  array $post           The submitted form ($_POST).
 * @return array<int, string>    Human-readable input-error strings (empty when valid).
 */
function pfb_adv_alias_field_errors(array $post): array
{
	$adv_alias_fields = [
		'aliasports_in'  => ['dir' => 'Port In',         'type_label' => 'Port-type'],
		'aliasports_out' => ['dir' => 'Port Out',        'type_label' => 'Port-type'],
		'aliasaddr_in'   => ['dir' => 'Destination In',  'type_label' => 'Network or Host-type'],
		'aliasaddr_out'  => ['dir' => 'Source Out',      'type_label' => 'Network or Host-type'],
	];

	$errors = [];
	foreach ($adv_alias_fields as $field => $meta) {
		if (empty($post[$field])) {
			continue;
		}
		$alias_type = alias_get_type($post[$field]);
		if ($alias_type === '') {
			$errors[] = "Settings: Advanced {$meta['dir']}bound Alias error - Must use an existing Alias";
		} elseif (!pfb_alias_field_type_ok($field, $alias_type)) {
			$errors[] = "Settings: Advanced {$meta['dir']}bound Alias error - Must use a {$meta['type_label']} alias";
		}
	}
	return $errors;
}

// ---------------------------------------------------------------------------
// ADR-30 Phase 1 — Pure schedule-period deciders for log rotation.
//
// Two pure helper functions — no I/O, no globals, no config access.
// The caller passes all inputs explicitly; this is the testable seam.
//
// Period-key format (what gets stored in the state file per log type):
//   'off' or ''           -> '' (schedule disabled; no key)
//   'daily'               -> 'YYYY-MM-DD'    (date('Y-m-d', $ts))
//   'weekly'              -> 'YYYY-Www'       (date('o-\WW', $ts) — ISO week-year)
//   'monthly'             -> 'YYYY-MM'        (date('Y-m', $ts))
//   any unrecognised      -> '' (off-default; defensive)
//
// ISO week-year note: date('o') returns the ISO 8601 week-YEAR (not the
// calendar year), so 2027-01-01 (calendar year 2027) yields '2026-W53'
// (ISO year 2026, week 53) rather than the wrong '2027-W01'. This is the
// correct behaviour — use date('o'), never date('Y'), for the week key.
//
// Tests: tests/php/LogRotateScheduleTest.php
// ---------------------------------------------------------------------------

/**
 * pfb_log_rotate_period — compute the period key for a given schedule and time.
 *
 * Returns a string period key representing the calendar window that $ts falls
 * in, given $schedule. Returns '' when the schedule is off/empty/unrecognised.
 * The key is compared with the stored last-reset key to decide whether to reset.
 *
 * PURE — no I/O, no globals, no side effects.
 *
 * @param string $schedule  Schedule value: 'off'|''|'daily'|'weekly'|'monthly'.
 *                          Any unrecognised value is treated as 'off'.
 * @param int    $ts        Unix timestamp to compute the period key for.
 * @return string           Period key, or '' when the schedule is off/unrecognised.
 */
function pfb_log_rotate_period(string $schedule, int $ts): string
{
	return match ($schedule) {
		'daily'   => date('Y-m-d', $ts),
		'weekly'  => date('o-\WW', $ts),
		'monthly' => date('Y-m',   $ts),
		default   => '',
	};
}

/**
 * pfb_log_should_reset — decide whether a log should be reset at $now_ts.
 *
 * Returns TRUE when the calendar period has rolled over since the last reset
 * (i.e. the current period key differs from $last_key), or when $last_key is
 * empty (the log has never been reset and a reset is overdue).
 * Always returns FALSE when the schedule is 'off' / '' / unrecognised.
 *
 * PURE — no I/O, no globals, no side effects. Idempotent: within the same
 * period, pfb_log_rotate_period($schedule, $now_ts) === $last_key, so this
 * returns FALSE on every tick after the first reset in that period.
 *
 * @param string $schedule  Schedule value: 'off'|''|'daily'|'weekly'|'monthly'.
 * @param string $last_key  The period key stored after the last reset, or '' if
 *                          the log has never been reset (triggers reset).
 * @param int    $now_ts    Current Unix timestamp.
 * @return bool             TRUE iff the log should be truncated now.
 */
function pfb_log_should_reset(string $schedule, string $last_key, int $now_ts): bool
{
	$period = pfb_log_rotate_period($schedule, $now_ts);
	if ($period === '') {
		// Schedule is off or unrecognised — never reset.
		return FALSE;
	}
	// Reset when the period has changed (or when the log has never been reset).
	return $period !== $last_key;
}

// ---------------------------------------------------------------------------
// ADR-38 Phase 1 — Pure key=value syslog event formatters.
//
// pfb_syslog_format_ip(array $fields): string
//   Maps the already-computed IP Block/Permit/Match event fields to a single
//   space-separated "key=value ..." string suitable for emission as a syslog
//   message body.  The key order is fixed and documented below; this is the
//   stable contract that later phases wire to syslog(3) and that tests pin.
//
// Key vocabulary (fixed order):
//   act   — action:   'block'|'pass'|'match'
//   dir   — direction: 'in'|'out'
//   if    — friendly interface name (e.g. 'em0', 'LAN')
//   proto — protocol string (e.g. 'TCP', 'UDP', 'TCP-SA')
//   src   — source IP address
//   dst   — destination IP address
//   sport — source port (omitted when empty)
//   dport — destination port (omitted when empty)
//   ipver — IP version: '4' or '6'
//   geoip — GeoIP ISO country code (omitted when empty or 'Unk'/'Unknown')
//   alias — pfBlockerNG alias name (omitted when empty or 'Unknown')
//   feed  — feed name (omitted when empty or 'Unknown')
//   host  — resolved hostname of the external IP (omitted when empty/'Unknown')
//   asn   — ASN string (omitted when empty or 'Unknown'/'null')
//
// Empty-value convention:
//   Required fields (act/dir/if/proto/src/dst/ipver) are always present.
//   Optional fields (sport/dport/geoip/alias/feed/host/asn) are OMITTED
//   entirely when the value is empty, 'Unknown', 'Unk', or 'null'.
//
// Escaping rule:
//   A value containing a space, '=', or '"' is double-quoted; internal '"'
//   characters are backslash-escaped (\").  Newlines (\n, \r) are replaced
//   with a space before quoting to keep the message single-line.
//   Other punctuation (e.g. '|', ':', '/') is not quoted.
//
// PURE — no globals, no I/O, no config reads.
// ---------------------------------------------------------------------------

/**
 * pfb_syslog_escape — escape a single value for syslog key=value emission:
 * strip newlines, then quote if needed. Shared by pfb_syslog_format_ip() and
 * pfb_syslog_format_dnsbl() (ADR-38).
 *
 * @param string $v  Raw value.
 * @return string    Escaped/quoted value.
 */
function pfb_syslog_escape(string $v): string
{
	// Strip embedded newlines to keep the message single-line.
	$v = str_replace(["\r\n", "\r", "\n"], ' ', $v);
	// Quote if the value contains space, '=', or '"'.
	if (strpos($v, ' ') !== FALSE || strpos($v, '=') !== FALSE || strpos($v, '"') !== FALSE) {
		$v = '"' . str_replace('"', '\\"', $v) . '"';
	}
	return $v;
}

/**
 * pfb_syslog_format_ip — format an IP security event as a key=value string.
 *
 * @param array<string,string> $fields  Associative array of event fields.
 *                                      Keys: act, dir, if, proto, src, dst,
 *                                      sport, dport, ipver, geoip, alias,
 *                                      feed, host, asn.
 * @return string  Space-separated "k=v ..." body; never multi-line.
 */
function pfb_syslog_format_ip(array $fields): string
{
	// Sentinels treated as "absent" for optional fields.
	static $absent_sentinels = ['', 'Unknown', 'Unk', 'null'];

	$parts = [];

	// Required fields — always emitted. Cast to string: a caller may pass a
	// non-string scalar (e.g. FALSE), and pfb_syslog_escape()'s string param
	// would silently coerce it at the call boundary anyway — cast here too
	// for uniformity with the optional-field sites below.
	$parts[] = 'act='   . pfb_syslog_escape((string) ($fields['act'] ?? ''));
	$parts[] = 'dir='   . pfb_syslog_escape((string) ($fields['dir'] ?? ''));
	$parts[] = 'if='    . pfb_syslog_escape((string) ($fields['if'] ?? ''));
	$parts[] = 'proto=' . pfb_syslog_escape((string) ($fields['proto'] ?? ''));
	$parts[] = 'src='   . pfb_syslog_escape((string) ($fields['src'] ?? ''));
	$parts[] = 'dst='   . pfb_syslog_escape((string) ($fields['dst'] ?? ''));

	// Optional integer-ish fields — omit when empty. Cast BEFORE the '' check
	// so a non-string scalar (e.g. FALSE) compares/escapes as its coerced
	// string form, not its raw type.
	$sport = (string) ($fields['sport'] ?? '');
	if ($sport !== '') {
		$parts[] = 'sport=' . pfb_syslog_escape($sport);
	}
	$dport = (string) ($fields['dport'] ?? '');
	if ($dport !== '') {
		$parts[] = 'dport=' . pfb_syslog_escape($dport);
	}

	// Required IP version.
	$parts[] = 'ipver=' . pfb_syslog_escape((string) ($fields['ipver'] ?? ''));

	// Optional enrichment fields — omit when empty or a known absent-sentinel.
	// Cast BEFORE the in_array() sentinel check: a non-string scalar (e.g.
	// FALSE) must coerce to '' first so it matches the '' sentinel, exactly
	// as the retired $get() closure's `: string` return type did.
	foreach (['geoip', 'alias', 'feed', 'host', 'asn'] as $key) {
		$val = (string) ($fields[$key] ?? '');
		if (!in_array($val, $absent_sentinels, TRUE)) {
			$parts[] = $key . '=' . pfb_syslog_escape($val);
		}
	}

	return implode(' ', $parts);
}

// ---------------------------------------------------------------------------
// ADR-38 Amendment 1 — DNSBL syslog + unified.log formatters.
//
// pfb_syslog_format_dnsbl(array $fields): string
//   PHP port of the (retired) Python syslog_format_dnsbl().  Formats a DNSBL
//   block event as a space-separated key=value string for syslog emission.
//   Fixed key order: act qname qip qtype [group] [feed] btype eval.
//   group and feed are OPTIONAL — omitted entirely when the value is ''.
//   Escaping rule is identical to pfb_syslog_format_ip (see above).
//
// pfb_unified_format_ip(array $fields): string
//   Renders a unified.log IP row as a comma-joined string from 4 named fields:
//   l_type, log, details, dup.  No escaping — raw passthrough join.
//
// pfb_unified_format_dnsbl(array $fields): string
//   Renders a dnsbl.log CSV line as a comma-joined string from 11 named fields
//   in the FIXED column order that dnsbl.log defines.  No escaping.
//
// pfb_unified_format_dnsreply(array $fields): string
//   Renders a DNS-reply row for unified.log as a comma-joined string from 10
//   named fields in fixed column order.  No escaping.
//
// All four are PURE — no globals, no I/O, no config reads.
// ---------------------------------------------------------------------------

/**
 * pfb_syslog_format_dnsbl — format a DNSBL block event as a key=value string.
 *
 * PHP port of the retired Python syslog_format_dnsbl().  The escaping rule is
 * identical to pfb_syslog_format_ip: values containing a space, '=', or '"'
 * are double-quoted; internal '"' chars are backslash-escaped; newlines are
 * replaced with a space.
 *
 * Fixed key order: act qname qip qtype [group] [feed] btype eval.
 * group/feed are omitted entirely when their value is ''.
 *
 * @param array<string,string> $fields  Keys: q_name, q_ip, q_type, group,
 *                                      feed, b_type, b_eval.  Missing => ''.
 * @return string  Space-separated "k=v ..." body; never multi-line.
 */
function pfb_syslog_format_dnsbl(array $fields): string
{
	// Cast every extraction to string: a caller may pass a non-string scalar
	// (e.g. FALSE), and the '' emptiness check below must see its coerced
	// string form — exactly as the retired $get() closure's `: string`
	// return type did.
	$parts   = [];
	$parts[] = 'act=dnsbl';
	$parts[] = 'qname='  . pfb_syslog_escape((string) ($fields['q_name'] ?? ''));
	$parts[] = 'qip='    . pfb_syslog_escape((string) ($fields['q_ip'] ?? ''));
	$parts[] = 'qtype='  . pfb_syslog_escape((string) ($fields['q_type'] ?? ''));

	// Optional fields — omit the token entirely when the value is ''.
	$group = (string) ($fields['group'] ?? '');
	if ($group !== '') {
		$parts[] = 'group=' . pfb_syslog_escape($group);
	}
	$feed = (string) ($fields['feed'] ?? '');
	if ($feed !== '') {
		$parts[] = 'feed=' . pfb_syslog_escape($feed);
	}

	$parts[] = 'btype=' . pfb_syslog_escape((string) ($fields['b_type'] ?? ''));
	$parts[] = 'eval='  . pfb_syslog_escape((string) ($fields['b_eval'] ?? ''));

	return implode(' ', $parts);
}

/**
 * pfb_unified_format_ip — render an IP unified.log row as a comma-joined string.
 *
 * Owns the column schema for IP rows in unified.log.  Raw passthrough — no
 * escaping applied; the caller appends "\n".
 *
 * @param array<string,string> $fields  Keys (in column order): l_type, log,
 *                                      details, dup.  Missing => ''.
 * @return string  Comma-joined, no trailing newline.
 */
function pfb_unified_format_ip(array $fields): string
{
	return implode(',', [
		$fields['l_type']   ?? '',
		$fields['log']      ?? '',
		$fields['details']  ?? '',
		$fields['dup']      ?? '',
	]);
}

/**
 * pfb_unified_format_dnsbl — render a dnsbl.log CSV line as a comma-joined string.
 *
 * Owns the 11-column schema for DNSBL rows in unified.log (mirrors dnsbl.log
 * exactly).  Raw passthrough — no escaping; the caller appends "\n".
 *
 * Column order: l_type, datetime, q_name, q_ip, p_type, b_type, group,
 *               b_eval, feed, dup, q_type.
 *
 * @param array<string,string> $fields  Keys matching the column names above.
 *                                      Missing => ''.
 * @return string  Comma-joined, no trailing newline.
 */
function pfb_unified_format_dnsbl(array $fields): string
{
	return implode(',', [
		$fields['l_type']    ?? '',
		$fields['datetime']  ?? '',
		$fields['q_name']    ?? '',
		$fields['q_ip']      ?? '',
		$fields['p_type']    ?? '',
		$fields['b_type']    ?? '',
		$fields['group']     ?? '',
		$fields['b_eval']    ?? '',
		$fields['feed']      ?? '',
		$fields['dup']       ?? '',
		$fields['q_type']    ?? '',
	]);
}

/**
 * pfb_unified_format_dnsreply — render a DNS-reply unified.log row as a comma-joined string.
 *
 * Owns the 10-column schema for DNS-reply rows in unified.log.  Raw
 * passthrough — no escaping; the caller appends "\n".
 *
 * Column order: l_type, datetime, m_type, o_type, q_type, ttl, q_name,
 *               q_ip, r_addr, iso_code.
 *
 * @param array<string,string> $fields  Keys matching the column names above.
 *                                      Missing => ''.
 * @return string  Comma-joined, no trailing newline.
 */
function pfb_unified_format_dnsreply(array $fields): string
{
	return implode(',', [
		$fields['l_type']    ?? '',
		$fields['datetime']  ?? '',
		$fields['m_type']    ?? '',
		$fields['o_type']    ?? '',
		$fields['q_type']    ?? '',
		$fields['ttl']       ?? '',
		$fields['q_name']    ?? '',
		$fields['q_ip']      ?? '',
		$fields['r_addr']    ?? '',
		$fields['iso_code']  ?? '',
	]);
}

// ---------------------------------------------------------------------------
// ADR-38 — PHP syslog event emitter.
//
// pfb_syslog_event(string $body): void
//   Emits ONE syslog record with the syslog ident (program name) 'pfblockerng'
//   at a FIXED facility (LOG_LOCAL6) and severity (LOG_INFO).
//
//   Facility/severity are NOT user-configurable (ADR-38 Amendment 1): the events
//   are routed to the dedicated pfblockerng_syslog.log by the package <logging>
//   block's PROGRAM-name filter (!pfblockerng), so the facility never affects
//   where they land; and every exported event is the same class of record, so a
//   severity picker would only ever set one fixed level. They are all
//   informational security events -> LOG_INFO. The only user control is the
//   log_syslog master toggle.
//
//   Behaviour:
//     - Reads log_syslog FRESH on every call (no per-process cache). The
//       long-running pfb_filter daemon is the sole caller and the user can
//       toggle log_syslog live; a cached value would keep emitting (or stay
//       silent) until a daemon restart. This fires only on block events (the
//       caller gates on the event class), not per packet, so the PfbConfig
//       array read is cheap. The daemon keeps $config current via
//       pfb_filterlog_refresh_config() so PfbConfig sees the live value.
//     - No-op when log_syslog is off (PfbToggle::Off / '').
//     - openlog() sets ident + facility; syslog() emits at LOG_INFO; closelog()
//       releases the connection.
// ---------------------------------------------------------------------------

/**
 * pfb_syslog_event — emit a single syslog record for one security event.
 *
 * Reads log_syslog FRESH from PfbConfig on every call. Fixed facility LOG_LOCAL6
 * and severity LOG_INFO. No-op when the toggle is off.
 *
 * TEST SEAM: when $GLOBALS['pfb_test_syslog_spy'] is set (to any non-null value),
 * the call is recorded in $GLOBALS['pfb_test_syslog_calls'] instead of hitting
 * the real built-ins. The legacy $GLOBALS['pfb_test_syslog_reset'] flag is
 * accepted but inert (there is no longer a cache to reset).
 *
 * @param  string $body  The key=value message body (output of pfb_syslog_format_ip()).
 * @return void
 */
function pfb_syslog_event(string $body): void
{
	// Legacy reset flag is a no-op now (no cache) — clear it so it cannot leak.
	unset($GLOBALS['pfb_test_syslog_reset']);

	// Fresh gate: read the current toggle on every call.
	if (PfbConfig::read('log_syslog') !== PfbToggle::On) {
		return;
	}

	// Production path: openlog / syslog / closelog via PHP built-ins.
	// Test spy path: record the call in $GLOBALS['pfb_test_syslog_calls'] when a
	// spy is installed (never calls the real built-ins in test mode).
	if (isset($GLOBALS['pfb_test_syslog_spy'])) {
		$GLOBALS['pfb_test_syslog_calls'][] = [
			'ident'    => 'pfblockerng',
			'facility' => LOG_LOCAL6,
			'severity' => LOG_INFO,
			'body'     => $body,
		];
		return;
	}

	openlog('pfblockerng', LOG_PID, LOG_LOCAL6);
	syslog(LOG_INFO, $body);
	closelog();
}

// ---------------------------------------------------------------------------
// ADR-43 Phase 2 — Due-ledger library (pure core + I/O helpers).
//
// A persisted per-job next-due ledger stored as a single JSON file
// (pfb_due_ledger.json) under $pfb['dbdir']. This evolves the existing
// .update/.last sentinel pattern: instead of flag files that only record
// "needs update", each entry records {last_run, next_due, jitter} so a
// single tick can decide what is due without reading the clock per-job.
//
// Design invariants (ADR-43 §2.C):
//   - Absent entry (new install or wiped RAM-disk) ⇒ is_due returns TRUE.
//     The stable seeded jitter is applied on mark_ran, spreading next_due.
//   - next_due in the past                         ⇒ is_due returns TRUE (catch-up).
//   - next_due in the future                       ⇒ is_due returns FALSE.
//   - mark_ran sets next_due = now + interval + seeded_jitter(job, seed, max).
//   - Corrupt or absent ledger file                ⇒ treated as absent (fail-safe).
//
// #468 persist/restore integration:
//   pfb_due_ledger.json lives in $pfb['dbdir'] (= /var/db/pfblockerng on MFS).
//   Phase 4 adds it to the earlyshellcmd archive set (alongside IP aliastables)
//   so a clean reboot restores the schedule and avoids the boot stampede that the
//   absent-entry rule guards against. Until Phase 4 wires this, the absent-⇒-due
//   rule is the sole boot-stampede defence (jobs spread by their seeded jitter
//   after the first post-boot mark_ran).
//
// On-disk layout (pfb_due_ledger.json under ledger_dir):
//   {
//     "dcc":  {"last_run": 1234567890, "next_due": 1234567890, "jitter": 35079},
//     "bl":   {"last_run": 1234567890, "next_due": 1234567890, "jitter": 79870}
//   }
//   Writes are atomic: content assembled, written to .tmp with LOCK_EX, then
//   renamed to the target (atomic on POSIX / FreeBSD same-filesystem rename).
//
// Clock and seed are INJECTABLE (passed as arguments to every function that needs
// them) so PHPUnit can pin the date math without wall-clock or rand() flakiness.
// Only a thin outer wrapper (Phase 4's tick) reads time() and the install seed.
//
// Tests: tests/php/DueLedgerTest.php
// ---------------------------------------------------------------------------

/**
 * pfb_due_ledger_seeded_jitter — deterministic jitter offset for a job/seed pair.
 *
 * Returns a stable offset in [1, $max] for $max > 0, or 0 for $max === 0.
 * The result is identical for the same ($job_key, $seed, $max) triple on every
 * call, so the schedule is stable across reboots once the ledger is restored.
 * Different $job_key values with the same $seed produce different offsets (with
 * high probability for typical $max values), spreading concurrent jobs across
 * time and preventing upstream stampedes that today's rand(0,23) jitter prevents.
 *
 * PURE — no I/O, no globals, never calls rand() or time().
 *
 * @param string $job_key  Job identifier (e.g. 'dcc', 'bl').
 * @param string $seed     Per-install seed (e.g. derived from hostname or config).
 * @param int    $max      Maximum jitter (seconds or any unit). 0 disables jitter.
 * @return int             Jitter in [1, $max] when $max > 0; else 0.
 */
function pfb_due_ledger_seeded_jitter(string $job_key, string $seed, int $max): int
{
	if ($max <= 0) {
		return 0;
	}
	// crc32() returns a signed 32-bit int stored as 64-bit on PHP 8 / 64-bit FreeBSD.
	// abs() maps to [0, 2^31-1]; % $max gives [0, max-1]; +1 shifts to [1, max].
	// Guarantees non-zero: every job gets a spread offset, preventing stampedes.
	return (abs(crc32($seed . ':' . $job_key)) % $max) + 1;
}

/**
 * pfb_due_ledger_is_due_from_entry — decide due/not-due from a pre-read entry.
 *
 * Separating the I/O from the decision enables deterministic unit tests:
 * the caller reads the entry (or passes null for absent), this function decides.
 *
 * PURE — no I/O, no globals, no side effects.
 *
 * @param array|null $entry  {last_run: int, next_due: int, jitter: int} or NULL.
 * @param int        $now    Current epoch timestamp (injectable in tests).
 * @return bool              TRUE iff the job is due or the entry is absent.
 */
function pfb_due_ledger_is_due_from_entry(?array $entry, int $now): bool
{
	if ($entry === NULL) {
		// Absent (new install, wiped RAM-disk) ⇒ due now; jitter applied on mark_ran.
		return TRUE;
	}
	return $entry['next_due'] <= $now;
}

/**
 * pfb_due_ledger_read_entry — read one job entry from the on-disk ledger.
 *
 * Returns NULL on absent file, I/O error, or any corruption (fail-safe: absent
 * is always treated as "due now" by pfb_due_ledger_is_due_from_entry).
 *
 * @param string $job_key     Job identifier (e.g. 'dcc', 'bl').
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return array|null         {last_run: int, next_due: int, jitter: int} or NULL.
 */
function pfb_due_ledger_read_entry(string $job_key, string $ledger_dir): ?array
{
	$path = $ledger_dir . '/pfb_due_ledger.json';
	if (!is_file($path)) {
		return NULL;
	}
	$fp = @fopen($path, 'r');
	if ($fp === FALSE) {
		return NULL;
	}
	if (!flock($fp, LOCK_SH)) {
		fclose($fp);
		return NULL;
	}
	$raw = stream_get_contents($fp);
	flock($fp, LOCK_UN);
	fclose($fp);
	if ($raw === FALSE || $raw === '') {
		return NULL;
	}
	$data = json_decode($raw, TRUE);
	if (!is_array($data)) {
		return NULL;	// corrupt or not a JSON object
	}
	$entry = $data[$job_key] ?? NULL;
	if (!is_array($entry)) {
		return NULL;	// key absent
	}
	// Validate structure: all three integer fields must be present.
	if (!isset($entry['last_run'], $entry['next_due'], $entry['jitter'])
		|| !is_int($entry['last_run'])
		|| !is_int($entry['next_due'])
		|| !is_int($entry['jitter'])) {
		return NULL;	// malformed entry — fail-safe
	}
	return $entry;
}

/**
 * pfb_due_ledger_write_entry — atomically persist one job entry to the ledger.
 *
 * Reads the existing ledger (to preserve other jobs' entries), merges $entry
 * under $job_key, then writes to a .tmp file with LOCK_EX and renames to the
 * target (atomic on POSIX / FreeBSD same-filesystem rename).
 *
 * @param string $job_key     Job identifier.
 * @param array  $entry       {last_run: int, next_due: int, jitter: int}.
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return void
 */
function pfb_due_ledger_write_entry(string $job_key, array $entry, string $ledger_dir): void
{
	$path = $ledger_dir . '/pfb_due_ledger.json';
	$tmp  = $path . '.tmp';

	// Merge with existing data (tolerate absent/corrupt: start with empty object).
	$data = [];
	if (is_file($path)) {
		$raw = @file_get_contents($path);
		if ($raw !== FALSE && $raw !== '') {
			$decoded = json_decode($raw, TRUE);
			if (is_array($decoded)) {
				$data = $decoded;
			}
		}
	}
	$data[$job_key] = $entry;
	file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
	rename($tmp, $path);
}

/**
 * pfb_due_ledger_is_due — is the named job due to run on this tick?
 *
 * Reads the persisted entry for $job_key and applies the due rule. The $interval,
 * $seed, and $jitter_max parameters are accepted for API parity with mark_ran but
 * do not affect the is_due decision (the decision is based solely on next_due vs now).
 *
 * Absent or corrupt entry ⇒ TRUE (fail-safe: run now, jitter applied on mark_ran).
 * next_due ≤ $now         ⇒ TRUE (catch-up: missed window runs on the next tick).
 * next_due >  $now        ⇒ FALSE (not yet due).
 *
 * @param string $job_key     Job identifier (e.g. 'dcc', 'bl_weekly').
 * @param int    $interval    Job cadence in seconds (for API parity; not used here).
 * @param int    $now         Current epoch timestamp (injectable in tests).
 * @param string $seed        Per-install seed (for API parity; not used here).
 * @param int    $jitter_max  Max jitter in seconds (for API parity; not used here).
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return bool               TRUE iff the job should run this tick.
 */
function pfb_due_ledger_is_due(
	string $job_key,
	int    $interval,
	int    $now,
	string $seed,
	int    $jitter_max,
	string $ledger_dir
): bool {
	return pfb_due_ledger_is_due_from_entry(
		pfb_due_ledger_read_entry($job_key, $ledger_dir),
		$now
	);
}

/**
 * pfb_due_ledger_mark_ran — record that the job ran and schedule the next run.
 *
 * Persists {last_run: $now, next_due: $now+$interval+jitter, jitter: jitter}
 * where jitter = pfb_due_ledger_seeded_jitter($job_key, $seed, $jitter_max).
 * The same (job_key, seed, max) triple always produces the same jitter, so the
 * per-job schedule spread is stable across reboots (given a stable install seed).
 *
 * @param string $job_key     Job identifier (e.g. 'dcc', 'bl').
 * @param int    $interval    Job cadence in seconds.
 * @param int    $now         Current epoch timestamp (injectable in tests).
 * @param string $seed        Per-install seed.
 * @param int    $jitter_max  Max jitter in seconds (0 = no jitter).
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return void
 */
function pfb_due_ledger_mark_ran(
	string $job_key,
	int    $interval,
	int    $now,
	string $seed,
	int    $jitter_max,
	string $ledger_dir
): void {
	$jitter = pfb_due_ledger_seeded_jitter($job_key, $seed, $jitter_max);
	pfb_due_ledger_write_entry($job_key, [
		'last_run' => $now,
		'next_due' => $now + $interval + $jitter,
		'jitter'   => $jitter,
	], $ledger_dir);
}

/**
 * pfb_due_ledger_mark_ran_anchored — record a run and schedule the next occurrence,
 * anchored to the PREVIOUS next_due instead of "now" (issue #573: cron phase creep).
 *
 * pfb_due_ledger_mark_ran() anchors on $now (tick-start wall clock), so
 * next_due = tick_start + interval. Whenever the NEXT tick happens to start even a
 * fraction of a second faster than the previous one did, next_due misses it by that
 * fraction and the pass slips a full tick interval late. Repeated across ticks the
 * phase creeps monotonically forward; once it crosses a calendar-hour boundary, any
 * per-feed EveryDay/Weekly schedule whose configured hour lands on the now-skipped
 * hour silently misses its window (their gates in pfblockerng_sync_cron() are
 * hour-equality checks, so a skipped hour is a skipped run, not a late one).
 *
 * This variant re-anchors on the entry's PREVIOUS next_due instead of $now whenever
 * that base represents an on-time (or barely-missed) occurrence, so the cadence
 * locks to its original phase with zero cumulative slip. Falls back to plain
 * catch-up-from-now in every other case:
 *   - entry NULL (no prior run), or next_due == 0 (a set_pending placeholder with
 *     nothing meaningful to anchor to)             ⇒ base = $now.
 *   - next_due in the future relative to $now (clock skew, or an already-pending
 *     future entry)                                ⇒ base = $now (never anchor
 *     forward).
 *   - next_due more than one $interval in the past (a real catch-up: offline box,
 *     or the schedule was gated off for a long stretch) ⇒ base = $now, so the
 *     schedule re-phases from this catch-up run rather than firing every tick
 *     until a stale anchor drags current.
 *   - otherwise — 0 ≤ ($now - next_due) < $interval, the ordinary "missed the
 *     boundary by a fraction of a tick" case this fix targets ⇒ base = the entry's
 *     next_due, so the new next_due advances by exactly $interval every cycle.
 *
 * @param string $job_key     Job identifier (e.g. 'cron').
 * @param int    $interval    Job cadence in seconds.
 * @param int    $now         Current epoch timestamp (injectable in tests).
 * @param string $seed        Per-install seed.
 * @param int    $jitter_max  Max jitter in seconds (0 = no jitter).
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return void
 */
function pfb_due_ledger_mark_ran_anchored(
	string $job_key,
	int    $interval,
	int    $now,
	string $seed,
	int    $jitter_max,
	string $ledger_dir
): void {
	$entry = pfb_due_ledger_read_entry($job_key, $ledger_dir);

	$base = $now;
	if ($entry !== NULL
		&& $entry['next_due'] > 0
		&& $now >= $entry['next_due']
		&& ($now - $entry['next_due']) < $interval) {
		$base = $entry['next_due'];
	}

	$jitter = pfb_due_ledger_seeded_jitter($job_key, $seed, $jitter_max);
	pfb_due_ledger_write_entry($job_key, [
		'last_run' => $now,
		'next_due' => $base + $interval + $jitter,
		'jitter'   => $jitter,
	], $ledger_dir);
}

/**
 * pfb_tick_interval_clamp — clamp a raw pfb_tick_interval config value to a valid cron minute.
 *
 * Accepts the raw string from PfbConfig::read('pfb_tick_interval') and returns an int
 * suitable for use as the cron minute field (1–60). Non-numeric or out-of-range values
 * are clamped: 0 → 1, >60 → 60, non-int (e.g. 'abc') → 1.
 *
 * @param string $raw   Raw config value (e.g. '15', '0', '100', 'abc').
 * @return int          Clamped interval in [1, 60].
 */
function pfb_tick_interval_clamp(string $raw): int
{
	return max(1, min(60, (int) $raw));
}

/**
 * pfb_next_tick_boundary — when does the next cron tick fire?
 *
 * The ADR-43 scheduler is one cron tick that fires every $tick_min minutes (the cron minute
 * field is "star-slash-N"), so it runs at each minute-of-hour that is a multiple of $tick_min,
 * rolling to :00 of the next hour. Given the current wall-clock, returns the next boundary so
 * the Update page can show "next run at" and "time remaining" for the actual scheduled cron
 * (not the legacy per-feed interval cadence).
 *
 * @param int $tick_min  Clamped tick interval in minutes (see pfb_tick_interval_clamp).
 * @param int $cur_hour  Current hour (0–23).
 * @param int $cur_min   Current minute (0–59).
 * @param int $cur_sec   Current second (0–59).
 * @return array{0:int,1:int,2:int}  [next_hour (0–23), next_min (0–59), seconds_remaining].
 */
function pfb_next_tick_boundary(int $tick_min, int $cur_hour, int $cur_min, int $cur_sec): array
{
	$tick_min = max(1, $tick_min);
	$cur_hour_sec = ($cur_min * 60) + $cur_sec;

	$next_min = (intdiv($cur_min, $tick_min) + 1) * $tick_min;
	if ($next_min >= 60) {
		// The minute field never fires past :59, so it rolls to :00 of the next hour.
		return [($cur_hour + 1) % 24, 0, 3600 - $cur_hour_sec];
	}
	return [$cur_hour, $next_min, ($next_min * 60) - $cur_hour_sec];
}

/**
 * pfb_tick_seed — stable per-install seed for the due-ledger jitter.
 *
 * Uses the system hostname (stable across reboots unless the admin changes it).
 *
 * @return string  Non-empty seed string.
 */
function pfb_tick_seed(): string
{
	$h = php_uname('n');
	return ($h !== '') ? $h : 'pfblockerng';
}

/**
 * pfb_tick_due_jobs — which scheduled jobs are due this tick?
 *
 * Delegates to the Phase-2 due-ledger API for each job. The $now, $seed, and
 * $dbdir are injectable so PHPUnit can verify cadence without filesystem or
 * wall-clock dependencies. ss_refresh is not returned — it runs every tick
 * unconditionally (called directly by pfblockerng_tick()).
 *
 * @param int    $now            Current epoch timestamp.
 * @param string $seed           Per-install seed for seeded_jitter.
 * @param string $dbdir          Ledger directory (live = $pfb['dbdir']).
 * @param int    $cron_interval  Feed cron interval in seconds.
 * @param int    $bl_interval    Blacklist interval in seconds (86400 or 604800).
 * @return array<string,bool>    Map: job_key => TRUE when due.
 */
function pfb_tick_due_jobs(
	int    $now,
	string $seed,
	string $dbdir,
	int    $cron_interval,
	int    $bl_interval
): array {
	$jitter_max = 23 * 3600;	// 82800 s mirrors the old rand(0,23)*3600 spread

	return [
		'cron' => pfb_due_ledger_is_due('cron', $cron_interval, $now, $seed, 0,           $dbdir),
		'dcc'  => pfb_due_ledger_is_due('dcc',  86400,          $now, $seed, $jitter_max,  $dbdir),
		'bl'   => pfb_due_ledger_is_due('bl',   $bl_interval,   $now, $seed, $jitter_max,  $dbdir),
	];
}

// ---------------------------------------------------------------------------
// ADR-43 P5 — apply-on-change maintenance window + pending helpers
// ---------------------------------------------------------------------------

/**
 * pfb_quiet_hours_in_window — is $now inside the configured apply-on-change window?
 *
 * When set, detected changes are only applied INSIDE the window; outside they are
 * deferred (pending) until the next tick inside the window. Format: "HH:MM-HH:MM"
 * in local time (e.g. "02:00-06:00"). Wrapping midnight is supported ("23:00-03:00").
 *
 * Empty string ⇒ TRUE (apply immediately, no deferral — the default).
 * Malformed string ⇒ TRUE (fail-safe: apply immediately rather than defer forever).
 * Zero-width window (start == end) ⇒ TRUE (no meaningful deferral, apply immediately).
 *
 * @param int    $now    Current epoch timestamp (injectable for tests).
 * @param string $window "HH:MM-HH:MM" (local time) or '' (no window, apply immediately).
 * @return bool          TRUE = apply now; FALSE = outside window, defer.
 */
function pfb_quiet_hours_in_window(int $now, string $window): bool
{
	if ($window === '') {
		return TRUE;
	}
	if (!preg_match('/^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$/', $window, $m)) {
		return TRUE;	// malformed → fail-safe: apply immediately
	}
	// Validate hour ≤ 23 and minute ≤ 59 for both endpoints; the regex allows h=25/m=99.
	// Out-of-range → fail-safe: apply immediately (defers forever otherwise).
	if ((int)$m[1] > 23 || (int)$m[2] > 59 || (int)$m[3] > 23 || (int)$m[4] > 59) {
		return TRUE;	// out-of-range → fail-safe: apply immediately
	}
	$start = (int)$m[1] * 60 + (int)$m[2];
	$end   = (int)$m[3] * 60 + (int)$m[4];
	$cur   = (int)date('G', $now) * 60 + (int)date('i', $now);

	if ($start === $end) {
		return TRUE;	// zero-width window = no deferral
	}
	if ($start < $end) {
		return $cur >= $start && $cur < $end;	// normal window e.g. 02:00–06:00
	}
	return $cur >= $start || $cur < $end;		// wraps midnight e.g. 23:00–03:00
}

/**
 * pfb_due_ledger_set_pending — mark a job as pending-apply (deferred by quiet-hours window).
 *
 * Reads the existing ledger entry and sets pending_apply=TRUE, then writes back atomically.
 * If no entry exists, creates a "due-now" placeholder with pending_apply=TRUE.
 *
 * The pending flag is cleared implicitly when pfb_due_ledger_mark_ran() writes a clean
 * {last_run, next_due, jitter} entry (no pending_apply key).
 *
 * @param string $job_key    Job identifier (e.g. 'cron', 'dcc', 'bl').
 * @param string $ledger_dir Directory that contains pfb_due_ledger.json.
 * @return void
 */
function pfb_due_ledger_set_pending(string $job_key, string $ledger_dir): void
{
	$entry = pfb_due_ledger_read_entry($job_key, $ledger_dir);
	if ($entry === NULL) {
		$entry = ['last_run' => 0, 'next_due' => 0, 'jitter' => 0];
	}
	$entry['pending_apply'] = TRUE;
	pfb_due_ledger_write_entry($job_key, $entry, $ledger_dir);
}

/**
 * pfb_due_ledger_is_pending — is there a deferred apply pending for this job?
 *
 * Returns TRUE iff pfb_due_ledger_set_pending() has been called for this job and
 * pfb_due_ledger_mark_ran() has not yet cleared it.
 *
 * @param string $job_key    Job identifier (e.g. 'cron', 'dcc', 'bl').
 * @param string $ledger_dir Directory that contains pfb_due_ledger.json.
 * @return bool              TRUE when pending_apply is set and not yet cleared.
 */
function pfb_due_ledger_is_pending(string $job_key, string $ledger_dir): bool
{
	$entry = pfb_due_ledger_read_entry($job_key, $ledger_dir);
	return $entry !== NULL && !empty($entry['pending_apply']);
}

/**
 * pfblockerng_tick — ADR-43 P5: apply-on-change due-ledger tick dispatcher.
 *
 * Reads the ledger, dispatches each job that is due (feeds, dcc, bl) via exec() as a
 * separate process, then marks each as ran. ss_refresh runs every tick; the scheduled
 * log maintenance (pfb_log_mgmt/pfb_log_reset) runs only on an idle tick (see below).
 *
 * Lives here (not in the www/ dispatcher script) rather than the reverse so the
 * PHPUnit bootstrap can load and call the real entrypoint off-appliance: the www
 * script is never require()'d by the test suite, so before this move the tick had
 * zero off-box coverage (review finding ADR43-5). The www dispatch
 * (`pfblockerng.php tick`) still just calls this function.
 *
 * Apply-on-change (ADR-40 IP / ADR-10 DNSBL): a due job dispatches pfb_trigger, which
 * calls sync_package_pfblockerng() — ADR-40 gates alias apply on pfb_alias_set_different()
 * and ADR-10 uses zero-downtime swap for DNSBL; no apply happens when nothing changed.
 *
 * Optional quiet-hours window (pfb_quiet_hours): when set and the current time is OUTSIDE
 * the window, a due job is deferred (pending_apply recorded in the ledger); the next tick
 * inside the window applies it. Default '' = apply immediately on every due tick.
 *
 * Cadence seeding from legacy knobs (§2.G — no config.xml migration):
 *   feed cron : PfbConfig::read('pfb_interval') hours; skip when 'Disabled'.
 *   dcc       : 86400 s daily, jitter = seeded_jitter (stable per install).
 *   bl        : 86400 or 604800 s, jitter = seeded_jitter (stable per install).
 *
 * Scheduled log maintenance (pfb_log_mgmt/pfb_log_reset) runs at the end of every tick,
 * independent of the feed-cron cadence above (issue #573: with pfb_interval='Disabled'
 * the feed cron never dispatches, so log maintenance can no longer ride its tail the way
 * it used to inside pfblockerng_sync_cron()) -- but ONLY on an IDLE tick: skipped when
 * this tick just dispatched an update pass (cron/dcc/bl) or one from an earlier tick is
 * still running (pfb_update_pass_running()). Both dispatch and a backgrounded pass append
 * to $pfb['log']/$pfb['extraslog'] for potentially minutes; pfb_log_mgmt()'s
 * tail-to-temp-then-cat-over trim is a read/truncate/rewrite window that would lose any
 * lines the concurrent writer appends during it.
 */
function pfblockerng_tick(): void
{
	global $pfb;

	$now   = time();
	$seed  = pfb_tick_seed();
	$dbdir = $pfb['dbdir'];
	// Set TRUE by any branch below that actually dispatches (exec()s) an update pass
	// this tick -- gates the log-maintenance race guard at the tail of this function.
	$dispatched = FALSE;

	// --- Cadence from legacy knobs ---
	$raw_interval  = PfbConfig::read('pfb_interval');
	$cron_disabled = ($raw_interval === 'Disabled');
	$cron_secs     = $cron_disabled ? 0 : (max(1, (int)$raw_interval) * 3600);

	$bl_secs = 86400;
	if (!empty($pfb['blconfig']['blacklist_freq']) && $pfb['blconfig']['blacklist_freq'] === 'Weekly') {
		$bl_secs = 604800;
	}

	// --- Due check ---
	$due = pfb_tick_due_jobs($now, $seed, $dbdir, $cron_secs, $bl_secs);

	// --- Apply-on-change window (ADR-43 P5) ---
	// Empty window = apply immediately (default). Non-empty = defer outside window.
	$window = (string) PfbConfig::read('pfb_quiet_hours');
	$in_win = pfb_quiet_hours_in_window($now, $window);

	// --- Dispatch due (or pending) jobs; defer when outside the apply window ---

	// Feed cron: dispatch the `cron` verb (-> pfblockerng_sync_cron), NOT pfb_trigger
	// directly.  pfblockerng_sync_cron applies each feed's per-list Update Frequency
	// ($list['cron']: EveryDay/Weekly/NNhour) before its final sync_package_pfblockerng('cron'),
	// and runs the ADR-19 software-update check at the end -- both of which a bare
	// `pfb_trigger scope=both` skips (it would poll every feed every tick and never
	// run the once-per-pass update check). Apply-on-change still happens via ADR-40
	// (IP) + ADR-10 (DNSBL) inside that final sync. Backgrounded so the tick stays
	// fast. The scheduled log trim + reset no longer ride this dispatch (issue
	// #573) -- see pfb_log_mgmt()/pfb_log_reset() at the end of this function.
	if (!$cron_disabled && ($due['cron'] || pfb_due_ledger_is_pending('cron', $dbdir))) {
		if ($in_win) {
			logger(LOG_NOTICE, localize_text('Tick: dispatching feed cron.'), LOG_PREFIX_PKG_PFBLOCKERNG);
			exec("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron >> {$pfb['runlog']} 2>&1 &");
			pfb_due_ledger_mark_ran_anchored('cron', $cron_secs, $now, $seed, 0, $dbdir);
			$dispatched = TRUE;
		} else {
			logger(LOG_INFO, localize_text('Tick: feed cron deferred (outside apply window).'), LOG_PREFIX_PKG_PFBLOCKERNG);
			pfb_due_ledger_set_pending('cron', $dbdir);
		}
	}

	// MaxMind/TOP1M/ASN: daily, jittered.
	if ($due['dcc'] || pfb_due_ledger_is_pending('dcc', $dbdir)) {
		if ($in_win) {
			logger(LOG_NOTICE, localize_text('Tick: dispatching dcc.'), LOG_PREFIX_PKG_PFBLOCKERNG);
			exec("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php dcc >> {$pfb['extraslog']} 2>&1 &");
			pfb_due_ledger_mark_ran('dcc', 86400, $now, $seed, 23 * 3600, $dbdir);
			$dispatched = TRUE;
		} else {
			logger(LOG_INFO, localize_text('Tick: dcc deferred (outside apply window).'), LOG_PREFIX_PKG_PFBLOCKERNG);
			pfb_due_ledger_set_pending('dcc', $dbdir);
		}
	}

	// Blacklist: daily or weekly, jittered. Build bl_string from blconfig.
	if (($due['bl'] || pfb_due_ledger_is_pending('bl', $dbdir)) && $pfb['enable'] == 'on' &&
	    !empty($pfb['blconfig']) &&
	    !empty($pfb['blconfig']['blacklist_enable']) && $pfb['blconfig']['blacklist_enable'] != 'Disable' &&
	    !empty($pfb['blconfig']['blacklist_selected']) && isset($pfb['blconfig']['item'])) {

		if ($in_win) {
			$bl_str = '';
			$bl_sel = array_flip(explode(',', $pfb['blconfig']['blacklist_selected'])) ?: [];
			foreach ($pfb['blconfig']['item'] as $bl_item) {
				if (isset($bl_sel[$bl_item['xml']]) && !empty($bl_item['selected'])) {
					$bl_str .= ",{$bl_item['xml']}";
				}
			}
			$bl_str = pfb_filter(ltrim($bl_str, ','), PFB_FILTER_CSV, 'Tick bl dispatch');

			if (!empty($bl_str)) {
				logger(LOG_NOTICE, localize_text('Tick: dispatching bl.'), LOG_PREFIX_PKG_PFBLOCKERNG);
				exec("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php bl " . escapeshellarg($bl_str) . " >> {$pfb['extraslog']} 2>&1 &");
				pfb_due_ledger_mark_ran('bl', $bl_secs, $now, $seed, 23 * 3600, $dbdir);
				$dispatched = TRUE;
			}
		} else {
			logger(LOG_INFO, localize_text('Tick: bl deferred (outside apply window).'), LOG_PREFIX_PKG_PFBLOCKERNG);
			pfb_due_ledger_set_pending('bl', $dbdir);
		}
	}

	// SafeSearch CNAME freshness: every tick (cheap DNS re-resolution).
	pfblockerng_ss_refresh();

	// Scheduled log maintenance (issue #573): runs on every IDLE tick, independent of
	// the feed-cron gate above -- pfb_interval='Disabled' must not silently stop log
	// upkeep. Both self-gate by their own configured schedule/caps (per-log line cap
	// for pfb_log_mgmt, per-log calendar boundary for pfb_log_reset), so calling them
	// on every idle tick is safe: most calls are a no-op. Trim (line-cap) runs before
	// reset (calendar boundary), same ordering as the prior sync_cron tail. Skipped
	// when THIS tick dispatched an update pass ($dispatched) or an earlier one is
	// still running (pfb_update_pass_running()) -- both append to the same log files
	// pfb_log_mgmt()'s tail-to-temp-then-cat-over trim reads/truncates/rewrites, and
	// racing that window against a live writer loses whatever it appends meanwhile.
	if (!$dispatched && !pfb_update_pass_running()) {
		pfb_log_mgmt();
		pfb_log_reset();
	}
}

// ---------------------------------------------------------------------------
// ADR-53 P4 — pure suppression-line validator (v4 mask lift /8-/32)
// ---------------------------------------------------------------------------

/**
 * pfb_validate_suppression_line — validate one line of a v4/v6 suppression textarea.
 *
 * Mirrors the tolerant textarea shape the page already accepts: a line starting
 * with '#', or blank, is a no-op (skip, no error); an inline comment introduced
 * by '#' (e.g. "10.0.0.1/32 # example.com") is stripped before validating the
 * address/mask. IPv4 accepts masks /8-/32 (ADR-53 §2.3 fork 1 — the /8 floor is
 * a fail-open-typo guard; the carve engine itself is mask-agnostic since Phase
 * 3's iprange --except swap). IPv6 accepts masks /32-/128 (ADR-53 Phase 6 — the
 * /32 floor is the same fail-open-typo guard; the Phase 5 pure-PHP set-diff
 * engine is likewise mask-agnostic).
 *
 * PURE — no config access, no I/O; only the pfSense is_subnetv4()/is_subnetv6()
 * predicates.
 *
 * @param  string $line   One raw textarea line (as split on "\r\n"), untrimmed.
 * @param  string $family 'ipv4' or 'ipv6'.
 * @return string|null    NULL when the line is valid (or a comment/blank no-op);
 *                         otherwise the input_errors message for this line.
 */
function pfb_validate_suppression_line(string $line, string $family): ?string
{
	if (str_starts_with($line, '#') || trim($line) === '') {
		return NULL;
	}

	$host  = array_map('trim', preg_split('/(?=#)/', $line));
	$entry = $host[0];

	if ($family === 'ipv6') {
		// Mask-range check runs BEFORE the general subnet-shape check so an
		// out-of-range-but-otherwise-well-formed mask (/31, /129) gets the message
		// naming the accepted range, rather than the generic malformed-input one.
		$mask = strstr($entry, '/', FALSE);
		if ($mask !== FALSE && ctype_digit(substr($mask, 1))) {
			$mask_num = (int) substr($mask, 1);
			if ($mask_num < 32 || $mask_num > 128) {
				return "IPv6 Suppression: Invalid mask [ {$entry} ]. Mask must be between /32 and /128.";
			}
		}

		if (!is_subnetv6($entry)) {
			return "IPv6 Suppression: Invalid IPv6 subnet address defined [ {$entry} ]";
		}

		return NULL;
	}

	// Mask-range check runs BEFORE the general subnet-shape check so an
	// out-of-range-but-otherwise-well-formed mask (/7, /33) gets the message
	// naming the accepted range, rather than the generic malformed-input one.
	$mask = strstr($entry, '/', FALSE);
	if ($mask !== FALSE && ctype_digit(substr($mask, 1))) {
		$mask_num = (int) substr($mask, 1);
		if ($mask_num < 8 || $mask_num > 32) {
			return "IPv4 Suppression: Invalid mask [ {$entry} ]. Mask must be between /8 and /32.";
		}
	}

	if (!is_subnetv4($entry)) {
		return "IPv4 Suppression: Invalid IPv4 subnet address defined [ {$entry} ]";
	}

	return NULL;
}

// ---------------------------------------------------------------------------
// ADR-53 P5 — pure IPv6 CIDR set-subtraction engine
// ---------------------------------------------------------------------------
//
// IPv6 suppression can't carve by host enumeration (a /64 minus a /128 hole is
// 2^64 hosts -- ADR-53 §1.2) and `iprange` mangles v6 input outright (it parses
// a v6 literal as a hostname). Unlike the v4 engine (Phase 3's `iprange
// --except`), this is a pure-PHP set subtraction over fixed-width 128-bit
// binary-string ranges, emitting the minimal covering-CIDR remainder via
// pfSense's own ip_range_to_subnet_array() -- the REAL on-appliance function
// (never redefined here; a faithful double stands in for it under PHPUnit,
// see tests/php/pfsense_doubles.php).
//
// Every binary-string comparison below goes through strcmp(), NEVER the bare
// <, >, <=, >=, min(), max() operators: a 128-char string of '0'/'1' digits is
// a PHP "numeric string", and comparing two of those the normal way risks a
// silent (lossy, float-precision) numeric coercion for a string this long.
// strcmp() is the only byte-exact comparison for a fixed-width digit string.

/**
 * pfb_v6_cidr_to_range — parse one IPv6 CIDR token ('addr/bits') into its
 * [start, end] 128-bit binary-string range (fixed-width '0'/'1' strings,
 * lexically ordered exactly like the address's numeric value).
 *
 * A blank line or a '#'-led comment (the same tolerance
 * pfb_validate_suppression_line() applies to the persisted suppression file)
 * parses to NULL with $is_blank = TRUE -- a silent no-op, never an error. Any
 * other syntactically invalid token (no '/', out-of-range mask, unparseable
 * address) also returns NULL, but with $is_blank = FALSE so the caller
 * reports it.
 *
 * PURE.
 *
 * @param  string     $token     One raw CIDR line, untrimmed.
 * @param  bool|null &$is_blank  Set TRUE for a comment/blank no-op, FALSE otherwise.
 * @return array{0:string,1:string}|null [start_bin, end_bin], or NULL when unparseable.
 */
function pfb_v6_cidr_to_range(string $token, ?bool &$is_blank = null): ?array
{
	$is_blank = FALSE;
	$token = trim($token);
	if ($token === '' || str_starts_with($token, '#')) {
		$is_blank = TRUE;
		return NULL;
	}

	// A bare address (no /mask) is the dominant member-file shape a feed
	// emits -- treat it as its own /128, never as a malformed token (dropping
	// it would silently UNBLOCK the host; caught live by the ADR-53 v6 smoke).
	if (strpos($token, '/') === FALSE) {
		if (!is_ipaddrv6($token)) {
			return NULL;
		}
		$addr = $token;
		$bits = 128;
	} elseif (!is_subnetv6($token)) {
		return NULL;
	} else {
		[$addr, $bits_raw] = explode('/', $token, 2);
		$bits = (int) $bits_raw;
	}

	$packed = @inet_pton($addr);
	if ($packed === FALSE || strlen($packed) !== 16) {
		return NULL;
	}
	$addr_bin = '';
	foreach (str_split($packed) as $byte) {
		$addr_bin .= sprintf('%08b', ord($byte));
	}

	$host_len = 128 - $bits;
	$start    = substr($addr_bin, 0, $bits) . str_repeat('0', $host_len);
	$end      = substr($addr_bin, 0, $bits) . str_repeat('1', $host_len);

	return [$start, $end];
}

/**
 * pfb_v6_bin_inc — increment a 128-bit binary string by one address.
 *
 * PURE.
 *
 * @return string|null The incremented string, or NULL on overflow (input was
 *                      all '1's -- ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff).
 */
function pfb_v6_bin_inc(string $bin): ?string
{
	$pos = strrpos($bin, '0');
	if ($pos === FALSE) {
		return NULL;
	}
	return substr($bin, 0, $pos) . '1' . str_repeat('0', strlen($bin) - $pos - 1);
}

/**
 * pfb_v6_bin_dec — decrement a 128-bit binary string by one address.
 *
 * PURE.
 *
 * @return string|null The decremented string, or NULL on underflow (input was
 *                      all '0's -- ::).
 */
function pfb_v6_bin_dec(string $bin): ?string
{
	$pos = strrpos($bin, '1');
	if ($pos === FALSE) {
		return NULL;
	}
	return substr($bin, 0, $pos) . '0' . str_repeat('1', strlen($bin) - $pos - 1);
}

/**
 * pfb_v6_bin_to_addr — pack a 128-bit binary string back into a textual IPv6
 * address. Any valid textual form works: ip_range_to_subnet_array() re-derives
 * its own binary representation from whatever is passed in, so the specific
 * notation returned here is not load-bearing.
 *
 * PURE.
 */
function pfb_v6_bin_to_addr(string $bin): string
{
	$bin    = str_pad($bin, 128, '0', STR_PAD_LEFT);
	$packed = '';
	foreach (str_split($bin, 8) as $byte_bin) {
		$packed .= chr(bindec($byte_bin));
	}
	return inet_ntop($packed);
}

/**
 * pfb_v6_emit_covering_cidrs — the minimal covering-CIDR set for one
 * [start, end] binary-string range, via pfSense's ip_range_to_subnet_array().
 *
 * @return string[] CIDR strings ('addr/bits').
 */
function pfb_v6_emit_covering_cidrs(string $start_bin, string $end_bin): array
{
	return ip_range_to_subnet_array(pfb_v6_bin_to_addr($start_bin), pfb_v6_bin_to_addr($end_bin));
}

/**
 * pfb_cidr_subtract_v6 — set-subtract $holes from $cidrs (both IPv6 CIDR
 * arrays), returning the minimal covering-CIDR remainder (ADR-53 §2.1 v6
 * engine).
 *
 * Each entry in $cidrs is carved independently: every hole that intersects it
 * is removed (fully, partially, or not at all), so a hole spanning multiple
 * entries subtracts from each in turn; a hole containing an entry removes it
 * entirely; an entry with no intersecting hole re-emits unchanged (still
 * routed through ip_range_to_subnet_array() so notation/merging stays
 * consistent with the carved path -- ADR-53 §2.3 fork 4). An
 * entirely-suppressed input legitimately returns [] (ADR-53 §2.2
 * empty-is-legit).
 *
 * A malformed token in EITHER array is skipped -- never a throw that aborts
 * the whole file -- and appended to $errors verbatim; a blank/'#'-comment
 * line is a silent no-op and never reported.
 *
 * PURE -- no config access, no I/O.
 *
 * @param  string[]       $cidrs    Feed/member CIDR lines to carve.
 * @param  string[]       $holes    Suppression CIDR lines to carve out.
 * @param  string[]|null &$errors   By-ref out param: the raw malformed tokens
 *                                  skipped from either array (both sides pooled).
 * @return string[] The covering-CIDR remainder (no particular guaranteed order).
 */
function pfb_cidr_subtract_v6(array $cidrs, array $holes, ?array &$errors = null): array
{
	$errors = [];

	$entries = [];
	foreach ($cidrs as $token) {
		$is_blank = FALSE;
		$range    = pfb_v6_cidr_to_range((string) $token, $is_blank);
		if ($range === NULL) {
			if (!$is_blank) {
				$errors[] = (string) $token;
			}
			continue;
		}
		$entries[] = $range;
	}

	$hole_ranges = [];
	foreach ($holes as $token) {
		$is_blank = FALSE;
		$range    = pfb_v6_cidr_to_range((string) $token, $is_blank);
		if ($range === NULL) {
			if (!$is_blank) {
				$errors[] = (string) $token;
			}
			continue;
		}
		$hole_ranges[] = $range;
	}

	// Sort once, up front (not per entry): the per-entry filter below preserves
	// this order, so no repeated sort is needed.
	usort($hole_ranges, static function (array $a, array $b): int {
		return strcmp($a[0], $b[0]);
	});

	$out = [];
	foreach ($entries as [$estart, $eend]) {
		// Clip every hole that intersects this entry to the entry's own bounds.
		$intersecting = [];
		foreach ($hole_ranges as [$hstart, $hend]) {
			if (strcmp($hstart, $eend) > 0 || strcmp($hend, $estart) < 0) {
				continue; // no overlap with this entry
			}
			$intersecting[] = [
				strcmp($hstart, $estart) > 0 ? $hstart : $estart, // clipped start
				strcmp($hend, $eend) < 0 ? $hend : $eend,         // clipped end
			];
		}

		if (empty($intersecting)) {
			// array_push(...$x) appends in place (amortised O(k) for k new
			// elements) -- NEVER `$out = array_merge($out, $x)` here, which would
			// recopy the whole accumulated $out on every one of up to ~100k
			// entries (an O(n^2) blowup measured at 22s for a 100k-line file;
			// this form measured well under a second for the same input).
			array_push($out, ...pfb_v6_emit_covering_cidrs($estart, $eend));
			continue;
		}

		// Walk the (already sorted) intersecting holes, emitting the gap before
		// each one, then advancing the cursor past it; a final gap after the
		// last hole (if any) closes out the entry.
		$cursor = $estart;
		foreach ($intersecting as [$hstart, $hend]) {
			if ($cursor === NULL) {
				break; // already carved to the top of the address space
			}
			if (strcmp($hstart, $cursor) > 0) {
				$gap_end = pfb_v6_bin_dec($hstart);
				if ($gap_end !== NULL) {
					array_push($out, ...pfb_v6_emit_covering_cidrs($cursor, $gap_end));
				}
			}
			if (strcmp($hend, $cursor) >= 0) {
				$cursor = pfb_v6_bin_inc($hend);
			}
		}
		if ($cursor !== NULL && strcmp($cursor, $eend) <= 0) {
			array_push($out, ...pfb_v6_emit_covering_cidrs($cursor, $eend));
		}
	}

	return $out;
}

/**
 * pfb_suppress_file_v6 — set-subtract $suppfile's IPv6 suppression entries
 * from $file's member-list CIDR lines and publish the covering-CIDR
 * remainder, atomically.
 *
 * Fail-safe (ADR-53 §2.2): either input missing/unreadable -> FALSE, $file is
 * left untouched -- never a truncated publish on error. On success, publishes
 * via a same-directory tmp+rename (an atomic POSIX rename, so no reader ever
 * observes a partial file); a legitimately-empty remainder (everything
 * suppressed) still publishes an empty file, never a stale one. A non-CIDR
 * line in either input is dropped and logged (pfb_logger), never fatal.
 *
 * PURE aside from the single target-file write (+ its companion log lines).
 *
 * @param  string $file     Member/deny CIDR list to carve (rewritten in place).
 * @param  string $suppfile Suppression CIDR list (the holes).
 * @return bool TRUE on a successful publish (including an empty one), FALSE
 *              on any fail-safe path (previous $file left intact).
 */
function pfb_suppress_file_v6(string $file, string $suppfile): bool
{
	if (!is_readable($file) || !is_readable($suppfile)) {
		return FALSE;
	}

	$cidrs = @file($file, FILE_IGNORE_NEW_LINES);
	$holes = @file($suppfile, FILE_IGNORE_NEW_LINES);
	if ($cidrs === FALSE || $holes === FALSE) {
		return FALSE;
	}

	$errors = [];
	$result = pfb_cidr_subtract_v6($cidrs, $holes, $errors);

	foreach ($errors as $bad_token) {
		pfb_logger("IPv6 Suppression: dropping malformed entry [ {$bad_token} ]", 2);
	}

	$tmp  = $file . '.tmp';
	$body = empty($result) ? '' : implode(PHP_EOL, $result) . PHP_EOL;
	if (@file_put_contents($tmp, $body, LOCK_EX) === FALSE) {
		// ADR-53 review finding H1: a failed write can still leave a stray
		// (empty/partial, or pre-existing debris from a prior crashed run) file
		// at $tmp -- unlink it on this branch too, matching the rename-failure
		// branch below.
		@unlink($tmp);
		return FALSE;
	}
	if (!@rename($tmp, $file)) {
		@unlink($tmp);
		return FALSE;
	}

	return TRUE;
}

// ---------------------------------------------------------------------------
// ADR-53 P7 — prefix-aware killstates suppression exclusion
// ---------------------------------------------------------------------------

/**
 * pfb_ip_suppressed — TRUE iff $ip falls inside any suppression CIDR in
 * $entries (ADR-53 §2.2 killstates contract).
 *
 * Replaces the old exact-IP hashmap + subnetv4_expand() '/24' materialisation
 * in pfb_remove_states(), which could only express a bare host or an exact
 * '/24' entry -- any other containing mask (e.g. a v4 '/16', or any v6 mask)
 * silently stayed unsuppressed (ADR-53 §1.2). Uses the same ip_in_subnet()
 * loop shape pfb_local_ip() already applies to local subnets, so any mask is
 * honoured natively -- no materialisation, no per-family branching needed
 * here (ip_in_subnet() itself returns FALSE on a family mismatch).
 *
 * $entries are raw suppression-textarea lines (untrimmed; may carry a
 * trailing '#' comment or be entirely blank/comment) -- the same tolerance
 * pfb_validate_suppression_line() applies. A malformed entry (no '/', bad
 * address) is silently skipped, never fatal.
 *
 * PURE -- no config reads; the caller passes the already-decoded suppression
 * list(s).
 *
 * Cost: a linear scan of $entries per call. Suppression lists are small and
 * user-authored, so this is fine at this scale.
 * ponytail: an interval tree would be overkill here — revisit only if a
 * suppression list ever grows into the thousands of entries.
 *
 * @param  string   $ip      The firewall-state IP to test (v4 or v6).
 * @param  string[] $entries Decoded suppression lines (one family or mixed).
 * @return bool TRUE when $ip is covered by any entry.
 */
function pfb_ip_suppressed(string $ip, array $entries): bool
{
	return pfb_ip_suppressed_match($ip, $entries) !== NULL;
}

/**
 * pfb_ip_suppressed_match — same coverage test as pfb_ip_suppressed(), but
 * returns the MOST SPECIFIC (longest-prefix) covering entry instead of a
 * bool (issue #422, follow-up to ADR-53 P7/P8). Feeds two Alerts surfaces
 * that need to act on the actual customlist line, not just a yes/no: the
 * un-suppress ('delete_ip') handler (which entry to remove + re-add) and the
 * suppressed-row icon detection in the Alerts render loop.
 *
 * Skip/strip rules are identical to the pre-#422 pfb_ip_suppressed() (that
 * function is now a one-line wrapper around this one). One deliberate
 * tolerance on top: a bare host (no '/') is normalised to /32 (v4) or /128
 * (v6) before the ip_in_subnet() containment test -- ip_in_subnet() itself
 * requires a mask (a bare token never matches anything), while BOTH carve
 * engines treat a bare suppression hole as a single host (iprange for v4;
 * pfb_v6_cidr_to_range() for v6), so without the normalisation a hand-edited
 * bare entry would suppress at update time yet read as "not suppressed"
 * here (killstates would keep cutting the host's states; the Alerts
 * un-suppress could never resolve it). When both a host-exact and a broader
 * containing CIDR cover $ip, the host-specific entry wins (mirrors the old
 * /32-before-/24 precedence); a tie in prefix length keeps the first-seen
 * entry.
 *
 * PURE -- no config access, no I/O.
 *
 * @param  string   $ip      The IP to test (v4 or v6).
 * @param  string[] $entries Decoded suppression lines (one family or mixed).
 * @return string|null The RAW entry (as passed in $entries, comment intact)
 *                      with the longest prefix, or NULL when none covers $ip.
 */
function pfb_ip_suppressed_match(string $ip, array $entries): ?string
{
	$best      = NULL;
	$best_bits = -1;

	foreach ($entries as $raw) {
		$entry = trim((string) $raw);
		if ($entry === '' || str_starts_with($entry, '#')) {
			continue;
		}
		// Strip a trailing inline '#' comment, same as pfbng_text_area_decode().
		$stripped = trim(strstr($entry, '#', TRUE) ?: $entry);

		// Bare host -> exact single-host CIDR BEFORE the containment test:
		// ip_in_subnet() requires a mask, but the carve engines suppress a
		// bare hole as a single host -- the predicate must agree with them.
		if (!str_contains($stripped, '/')) {
			$stripped .= str_contains($stripped, ':') ? '/128' : '/32';
		}

		if (!ip_in_subnet($ip, $stripped)) {
			continue;
		}

		$bits = (int) substr(strrchr($stripped, '/'), 1);

		if ($bits > $best_bits) {
			$best      = $raw;
			$best_bits = $bits;
		}
	}

	return $best;
}

// ---------------------------------------------------------------------------
// ADR-53 P8 -- Alerts "+" / widget live-punch plan (any mask + v6)
// ---------------------------------------------------------------------------
//
// The Alerts "+" button (and the dashboard widget, which shares its stats
// read of the same suppression config) used to punch a hole in a live pf
// table by deleting an exact '/24' and re-adding 254 sibling hosts, refusing
// anything "blocked by a CIDR other than /24" (ADR-53 §1.2). This replaces
// that with the same covering-CIDR set-subtraction already proven for the
// persisted engines (P3's v4 `iprange --except` pass, P5's v6 PHP pass):
// locate the table entr(y/ies) that actually contain the host, delete them,
// and re-add only the covering-CIDR remainder -- any mask, both families.

/**
 * pfb_v4_carve_single -- the covering-CIDR remainder of one IPv4 CIDR (or
 * bare host, normalised to '/32') with a single host removed. The IPv4
 * sibling of pfb_cidr_subtract_v6(), scoped to the one-entry/one-hole shape
 * the live punch actually needs -- pfb_cidr_subtract_v6() stays the only
 * general multi-hole engine (the v4 persisted engine already has its own for
 * that, P3's `iprange --except`). A v4 range fits a plain PHP int (32 bits,
 * ip2long32() already returns it unsigned on 64-bit PHP), so no
 * binary-string arithmetic is needed here.
 *
 * PURE.
 *
 * @param  string $cidr    The containing table entry ('addr/bits' or bare host).
 * @param  string $host_ip The single IPv4 host to carve out (assumed to fall
 *                          inside $cidr -- the caller establishes containment
 *                          via ip_in_subnet() before calling).
 * @return string[] Covering CIDRs for $cidr minus $host_ip (empty when $cidr
 *                    IS $host_ip -- an exact host match, nothing left to add back).
 */
function pfb_v4_carve_single(string $cidr, string $host_ip): array
{
	$cidr  = str_contains($cidr, '/') ? $cidr : "{$cidr}/32";
	[$addr, $bits] = explode('/', $cidr, 2);
	$bits  = (int) $bits;
	$mask  = $bits === 0 ? 0 : ((0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF);
	$start = ip2long32($addr) & $mask;
	$end   = $start | ((~$mask) & 0xFFFFFFFF);
	$hole  = ip2long32($host_ip);

	$out = [];
	if ($hole > $start) {
		array_push($out, ...ip_range_to_subnet_array(long2ip32($start), long2ip32($hole - 1)));
	}
	if ($hole < $end) {
		array_push($out, ...ip_range_to_subnet_array(long2ip32($hole + 1), long2ip32($end)));
	}
	return $out;
}

/**
 * pfb_live_punch_plan -- compute the live pf-table punch for the Alerts "+"
 * / widget suppression action (ADR-53 §2.1 fork 3): which existing table
 * entries contain $ip (to `pfctl -T delete`) and which covering CIDRs
 * replace them (to `pfctl -T add`) -- a genuine set-subtraction, replacing
 * the retired /24-only 254-host re-add loop.
 *
 * $table_entries are raw lines from the table's membership snapshot (the
 * ADR-40 mirror file, or a `pfctl -T show` fallback) -- bare host tokens
 * ("1.2.3.4") or CIDR tokens ("1.2.3.0/24"), either family; blank/'#'-comment
 * lines are tolerated (skipped). A bare host token is treated as an exact
 * /32 or /128 -- containing ONLY itself, so punching it needs no
 * covering-CIDR add (delete only, same as the old exact-/32-match case).
 *
 * PURE -- no pfctl/pf-table access; the caller supplies the already-read
 * membership snapshot (streamed, never slurped whole -- see the alerts page
 * call site) and applies the returned plan.
 *
 * @param  string   $ip             The host to carve out (v4 or v6).
 * @param  string[] $table_entries  Raw table membership lines.
 * @return array{delete: string[], add: string[]} 'delete' = every containing
 *         entry to remove; 'add' = the covering-CIDR remainder to re-add
 *         (empty when every containing entry was an exact host match).
 */
function pfb_live_punch_plan(string $ip, array $table_entries): array
{
	$delete    = [];
	$add       = [];
	$is_v6     = str_contains($ip, ':');
	$host_cidr = $ip . ($is_v6 ? '/128' : '/32');

	foreach ($table_entries as $entry) {
		$entry = trim((string) $entry);
		if ($entry === '' || str_starts_with($entry, '#')) {
			continue;
		}
		$cidr = str_contains($entry, '/') ? $entry : $entry . ($is_v6 ? '/128' : '/32');

		if (!ip_in_subnet($ip, $cidr)) {
			continue;
		}

		$delete[] = $entry;

		if ($cidr === $host_cidr) {
			continue; // exact host match -- nothing to re-add
		}

		if ($is_v6) {
			array_push($add, ...pfb_cidr_subtract_v6([$cidr], [$host_cidr]));
		} else {
			array_push($add, ...pfb_v4_carve_single($cidr, $ip));
		}
	}

	return ['delete' => $delete, 'add' => $add];
}

// logger() and localize_text() are pfSense-core helpers (src/etc/inc/util.inc)
// on pfSense Plus / master, but absent from released pfSense CE <= 2.8.1. Define
// fallbacks ONLY when core does not provide them, so this package runs on both:
// where core has them (Plus/master) these definitions are skipped and core wins
// unchanged; on CE 2.8.1 they fill the gap. Behaviour mirrors the core versions.
if (!function_exists('localize_text')) {
	function localize_text(...$args) {
		$arg0_len = strlen($args[0]);
		if (($arg0_len > 0) && ($arg0_len < 4096)) {
			$args[0] = gettext($args[0]);
		}
		return (count($args) == 1) ? $args[0] : sprintf(...$args);
	}
}

if (!function_exists('logger')) {
	function logger(int $priority, mixed $message, ?string $prefix = null, ?int $facilities = null): void {
		$log_prefix = match ($priority) {
			LOG_EMERG	=> 'EMERGENCY',
			LOG_ALERT	=> 'ALERT',
			LOG_CRIT	=> 'CRITICAL',
			LOG_ERR		=> 'ERROR',
			LOG_WARNING	=> 'WARNING',
			LOG_NOTICE	=> 'NOTICE',
			LOG_INFO	=> 'INFO',
			LOG_DEBUG	=> 'DEBUG',
			default		=> 'DEBUG'
		};
		if (isset($prefix)) {
			$log_prefix .= ' [' . gettext($prefix) . ']';
		}
		$pri = isset($facilities) ? ($priority | $facilities) : $priority;
		if (is_string($message)) {
			$message = str_replace(PHP_EOL, '', $message);
			$log_string = (strlen($message) > 0) ? "{$log_prefix} {$message}" : $log_prefix;
		} else {
			$log_string = $log_prefix . ' ' . str_replace(PHP_EOL, '', var_export($message, TRUE));
		}
		syslog($pri, $log_string);
	}
}
?>
