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
// ADR-28 Phase 1 — field-aware config adapters.
//
// Internal backed enums for recurring config flags + field-aware read/write
// adapter helpers.  Rule (ADR-28 §2.2):
//   - config.xml stored values NEVER change (no migration routine exists).
//   - Enums are an INTERNAL runtime representation only.
//   - read adapter: Enum::tryFrom($stored) ?? Enum::default()
//   - write adapter: $enum->value  (equals the exact legacy stored string)
//   - A field whose "off" is '' for one field and 'off' for another uses a
//     FIELD-SPECIFIC default — there is no single global toggle.
//
// Round-trip tests: tests/php/CfgAdaptersTest.php.
// Naming follows pfb_* conventions (CLAUDE.md "Naming").
// ---------------------------------------------------------------------------

// PfbToggle — checkbox fields stored as 'on' (checked) or '' (unchecked).
//
// Used by: pfb_dnsvip_auto (pfb_dnsblconfig['pfb_dnsvip_auto']).
//   Stored vocabulary: 'on' | '' (missing/unchecked = '').
//   pfb_global() normalisation at :1334:
//     pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_dnsvip_auto'] ?? '')->value
enum PfbToggle: string
{
	case On  = 'on';
	case Off = '';

	public static function default(): self
	{
		return self::Off;
	}
}

// PfbLenient — the ADR-22 scheme-parsing leniency flag.
//
// Used by: pfb_dnsbl_lenient (pfb_dnsblconfig['pfb_dnsbl_lenient']).
//   Stored vocabulary: 'on' | 'off' | '' (missing pre-ADR-22 install).
//   pfb_global() normalisation at :1364:
//     pfb_cfg_lenient_read($pfb['dnsblconfig']['pfb_dnsbl_lenient'] ?? '')->value
//   Note: '' (missing key) maps to Off ('off'), NOT to the PfbToggle '' value.
//   This field's "off" stored value is 'off', distinct from PfbToggle::Off = ''.
enum PfbLenient: string
{
	case On  = 'on';
	case Off = 'off';

	public static function default(): self
	{
		return self::Off;
	}
}

// PfbIdnMode — ADR-08 IDN-feature mode selector.
//
// Used by: dnsbl_idn (pfb_dnsblconfig['pfb_idn']).
//   Stored vocabulary: 'all' | 'confusable' | 'off' | '' | 'on' (legacy).
//   pfb_global() :1372-1373 passes the raw value through unchanged EXCEPT
//   for the legacy 'on' -> 'all' migration.  Because '' passes through as ''
//   (not 'off'), the seam for dnsbl_idn is kept as-is (excluded from adapter
//   adoption); PfbIdnMode is still used via the adapter at call sites that
//   need the normalised canonical value — see ADR-28 Phase 4 handoff.
//   IMPORTANT: 'on' is a LEGACY stored value — new saves always write 'all'.
//   The adapter read fn below replicates the pfb_global() normalisation so
//   downstream code sees the canonical value ('all'/'off'/'confusable').
//   The write fn returns the canonical stored string (never 'on').
//   Round-trip note: read('on') -> All -> write -> 'all' != 'on'.
//   This is the INTENDED behaviour: the legacy value is normalised on read
//   and the canonical value is stored on write (a one-way migration for 'on').
//   This field is therefore EXCLUDED from write(read(v))==v for v='on' only;
//   all other values round-trip losslessly.  Documented in 01_Results.txt.
enum PfbIdnMode: string
{
	case All        = 'all';
	case Confusable = 'confusable';
	case Off        = 'off';

	public static function default(): self
	{
		return self::Off;
	}
}

/**
 * pfb_cfg_toggle_read — read a PfbToggle from a raw stored value.
 *
 * Maps 'on' -> On, anything else -> Off (matches pfb_global() :1334 logic).
 *
 * @param mixed $stored  Raw value from config_get_path / $pfb['dnsblconfig'][...].
 */
function pfb_cfg_toggle_read(mixed $stored): PfbToggle
{
	if (!is_scalar($stored) && $stored !== null) {
		return PfbToggle::default();
	}
	return PfbToggle::tryFrom((string) ($stored ?? '')) ?? PfbToggle::default();
}

/**
 * pfb_cfg_toggle_write — write a PfbToggle back to its stored string.
 *
 * Returns the exact legacy stored string ('on' or '').  Accepts either the
 * runtime enum or a raw legacy string (normalised through the read adapter),
 * matching the PfbConfig::write() "enum or string" contract.
 *
 * @param PfbToggle|string $toggle  Runtime enum or raw stored string.
 */
function pfb_cfg_toggle_write(PfbToggle|string $toggle): string
{
	if (is_string($toggle)) {
		$toggle = pfb_cfg_toggle_read($toggle);
	}
	return $toggle->value;
}

/**
 * pfb_cfg_lenient_read — read a PfbLenient from a raw stored value.
 *
 * Maps 'on' -> On, anything else (incl. '', missing, 'off') -> Off.
 * Replicates pfb_global() :1364 normalisation.
 *
 * @param mixed $stored  Raw value from config_get_path / $pfb['dnsblconfig'][...].
 */
function pfb_cfg_lenient_read(mixed $stored): PfbLenient
{
	if (!is_scalar($stored) && $stored !== null) {
		return PfbLenient::default();
	}
	if ((string) ($stored ?? '') === 'on') {
		return PfbLenient::On;
	}
	return PfbLenient::default();
}

/**
 * pfb_cfg_lenient_write — write a PfbLenient back to its stored string.
 *
 * Returns 'on' or 'off' (never '').  Accepts either the runtime enum or a raw
 * legacy string (normalised through the read adapter), matching the
 * PfbConfig::write() "enum or string" contract.
 *
 * @param PfbLenient|string $lenient  Runtime enum or raw stored string.
 */
function pfb_cfg_lenient_write(PfbLenient|string $lenient): string
{
	if (is_string($lenient)) {
		$lenient = pfb_cfg_lenient_read($lenient);
	}
	return $lenient->value;
}

/**
 * pfb_cfg_idn_mode_read — read a PfbIdnMode from a raw stored value.
 *
 * Replicates pfb_global() :1372-1373 normalisation:
 *   'on'         -> All (legacy migration — new saves write 'all')
 *   'all'        -> All
 *   'confusable' -> Confusable
 *   anything else (incl. '', 'off', missing) -> Off
 *
 * @param mixed $stored  Raw value from config_get_path / $pfb['dnsblconfig'][...].
 */
function pfb_cfg_idn_mode_read(mixed $stored): PfbIdnMode
{
	if (!is_scalar($stored) && $stored !== null) {
		return PfbIdnMode::default();
	}
	$raw = (string) ($stored ?? '');
	if ($raw === 'on') {
		// Legacy: 'on' migrates to All at runtime; canonical stored value is 'all'.
		return PfbIdnMode::All;
	}
	return PfbIdnMode::tryFrom($raw) ?? PfbIdnMode::default();
}

/**
 * pfb_cfg_idn_mode_write — write a PfbIdnMode back to its stored string.
 *
 * Returns the canonical stored string ('all', 'confusable', or 'off').
 * NOTE: 'on' (legacy) is never re-emitted; it normalises to 'all' on read
 * and is stored as 'all' on write.  This is the intended one-way migration.
 *
 * Accepts either the runtime enum or a raw legacy string (normalised through
 * the read adapter), matching the PfbConfig::write() "enum or string" contract.
 *
 * @param PfbIdnMode|string $mode  Runtime enum or raw stored string.
 */
function pfb_cfg_idn_mode_write(PfbIdnMode|string $mode): string
{
	if (is_string($mode)) {
		$mode = pfb_cfg_idn_mode_read($mode);
	}
	return $mode->value;
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

		// Keep blocklists when pfBlockerNG is disabled: 'on' | '' (checkbox).
		// Default ON — the #281 canonical default; GUI and pfb_global() agree.
		'pfb_keep' => [
			'section'       => $gen,
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
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

		// Reuse blocklists across updates: 'on' | '' (checkbox). Default ''.
		'pfb_reuse' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '2.0.0',
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

		// ADR-08: IDN mode — EXCLUDED from adapter adoption (legacy 'on' cannot
		// round-trip; write(read('on')) == 'all' != 'on'). Kept as plain string.
		// The pfb_cfg_idn_mode_read/write adapters exist but are NOT wired here.
		// See ADR-28 §2.2 + CfgAdaptersTest testIdnModeLegacyOnNormalisesToAll.
		'pfb_idn' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
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

		// Webpage template. Default ''.
		'dnsblwebpage' => [
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

		// -------------------------------------------------------------------
		// ADR-38: syslog export settings (General / Log Settings section, $gen)
		// -------------------------------------------------------------------

		// Master toggle — emit security events to syslog: 'on' | '' (checkbox).
		// Default '' (off) — zero impact on existing installs.
		'log_syslog' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// syslog facility (Snort-style token string). Default 'log_local6'.
		// Vocabulary: 'log_local0'..'log_local7', 'log_daemon', 'log_user',
		// 'log_auth', 'log_kern', 'log_lpr', 'log_mail', 'log_news',
		// 'log_syslog', 'log_uucp', 'log_cron'. Plain-string identity adapter.
		'log_syslog_facility' => [
			'section'       => $gen,
			'default'       => 'log_local6',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// syslog severity / priority (Snort-style token string). Default 'log_notice'.
		// Vocabulary: 'log_emerg', 'log_alert', 'log_crit', 'log_err',
		// 'log_warning', 'log_notice', 'log_info', 'log_debug'. Plain-string identity adapter.
		'log_syslog_priority' => [
			'section'       => $gen,
			'default'       => 'log_notice',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
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
	];

	return $registry;
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
//   - A field EXCLUDED from backward-safety testing is one where write()
//     CANNOT guarantee a legacy token — those are excluded from adapter
//     adoption entirely (like pfb_idn's 'on'→'all' normalisation at the
//     pfb_global() seam, which bypasses PfbConfig).  At the PfbConfig level,
//     no field is excluded because all write adapters emit legacy tokens.
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
 * The idn-mode adapter (pfb_cfg_idn_mode_read/write) is NOT wired at PfbConfig
 * level for pfb_idn (excluded; legacy 'on' cannot round-trip through the adapter
 * without normalisation — pfb_idn uses null adapters and is backward-safe as-is).
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
 * the four per-row alias keys across the IP/DNSBL list sections, through
 * the PfbConfig section gateway. Does NOT persist (write_config is the
 * caller's job). Returns TRUE if anything changed.
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

	$changed  = FALSE;
	$sections = ['pfblockernglistsv4', 'pfblockernglistsv6', 'pfblockerngdnsbl'];
	$keys     = ['aliasports_in', 'aliasports_out', 'aliasaddr_in', 'aliasaddr_out'];

	foreach ($sections as $section) {
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
// ADR-38 Phase 2 — syslog facility / severity token → PHP constant maps.
//
// pfb_syslog_facility_constant(string $token): int
//   Maps a stored Snort-style facility token (e.g. 'log_local6') to the
//   corresponding PHP LOG_* integer constant.  Unknown tokens → LOG_LOCAL6
//   (the safe default).  The full vocabulary is the Snort-style set:
//     'log_kern'   → LOG_KERN    'log_user'   → LOG_USER
//     'log_mail'   → LOG_MAIL    'log_daemon' → LOG_DAEMON
//     'log_auth'   → LOG_AUTH    'log_syslog' → LOG_SYSLOG
//     'log_lpr'    → LOG_LPR     'log_news'   → LOG_NEWS
//     'log_uucp'   → LOG_UUCP   'log_cron'   → LOG_CRON
//     'log_local0' → LOG_LOCAL0  'log_local1' → LOG_LOCAL1
//     'log_local2' → LOG_LOCAL2  'log_local3' → LOG_LOCAL3
//     'log_local4' → LOG_LOCAL4  'log_local5' → LOG_LOCAL5
//     'log_local6' → LOG_LOCAL6  'log_local7' → LOG_LOCAL7
//   Default (unknown) → LOG_LOCAL6.
//
// pfb_syslog_priority_constant(string $token): int
//   Maps a stored Snort-style severity token (e.g. 'log_notice') to the
//   corresponding PHP LOG_* integer constant.  Unknown tokens → LOG_NOTICE
//   (the safe default).  The full vocabulary:
//     'log_emerg'   → LOG_EMERG   'log_alert'  → LOG_ALERT
//     'log_crit'    → LOG_CRIT    'log_err'    → LOG_ERR
//     'log_warning' → LOG_WARNING 'log_notice' → LOG_NOTICE
//     'log_info'    → LOG_INFO    'log_debug'  → LOG_DEBUG
//   Default (unknown) → LOG_NOTICE.
//
// Both functions are PURE (no globals, no I/O, no side effects) and DORMANT
// (uncalled from production code this phase).
// ---------------------------------------------------------------------------

/**
 * pfb_syslog_facility_constant — map a stored Snort-style facility token to a PHP constant.
 *
 * @param  string $token  Stored token (e.g. 'log_local6').
 * @return int            PHP LOG_* constant; LOG_LOCAL6 for unknown tokens.
 */
function pfb_syslog_facility_constant(string $token): int
{
	static $map = [
		'log_kern'   => LOG_KERN,
		'log_user'   => LOG_USER,
		'log_mail'   => LOG_MAIL,
		'log_daemon' => LOG_DAEMON,
		'log_auth'   => LOG_AUTH,
		'log_syslog' => LOG_SYSLOG,
		'log_lpr'    => LOG_LPR,
		'log_news'   => LOG_NEWS,
		'log_uucp'   => LOG_UUCP,
		'log_cron'   => LOG_CRON,
		'log_local0' => LOG_LOCAL0,
		'log_local1' => LOG_LOCAL1,
		'log_local2' => LOG_LOCAL2,
		'log_local3' => LOG_LOCAL3,
		'log_local4' => LOG_LOCAL4,
		'log_local5' => LOG_LOCAL5,
		'log_local6' => LOG_LOCAL6,
		'log_local7' => LOG_LOCAL7,
	];

	return $map[$token] ?? LOG_LOCAL6;
}

/**
 * pfb_syslog_priority_constant — map a stored Snort-style severity token to a PHP constant.
 *
 * @param  string $token  Stored token (e.g. 'log_notice').
 * @return int            PHP LOG_* constant; LOG_NOTICE for unknown tokens.
 */
function pfb_syslog_priority_constant(string $token): int
{
	static $map = [
		'log_emerg'   => LOG_EMERG,
		'log_alert'   => LOG_ALERT,
		'log_crit'    => LOG_CRIT,
		'log_err'     => LOG_ERR,
		'log_warning' => LOG_WARNING,
		'log_notice'  => LOG_NOTICE,
		'log_info'    => LOG_INFO,
		'log_debug'   => LOG_DEBUG,
	];

	return $map[$token] ?? LOG_NOTICE;
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

	/**
	 * Escape a single value: strip newlines, then quote if needed.
	 *
	 * @param string $v  Raw value.
	 * @return string    Escaped/quoted value.
	 */
	$escape = static function (string $v): string {
		// Strip embedded newlines to keep the message single-line.
		$v = str_replace(["\r\n", "\r", "\n"], ' ', $v);
		// Quote if the value contains space, '=', or '"'.
		if (strpos($v, ' ') !== FALSE || strpos($v, '=') !== FALSE || strpos($v, '"') !== FALSE) {
			$v = '"' . str_replace('"', '\\"', $v) . '"';
		}
		return $v;
	};

	$get = static function (string $key) use ($fields): string {
		return $fields[$key] ?? '';
	};

	$parts = [];

	// Required fields — always emitted.
	$parts[] = 'act='   . $escape($get('act'));
	$parts[] = 'dir='   . $escape($get('dir'));
	$parts[] = 'if='    . $escape($get('if'));
	$parts[] = 'proto=' . $escape($get('proto'));
	$parts[] = 'src='   . $escape($get('src'));
	$parts[] = 'dst='   . $escape($get('dst'));

	// Optional integer-ish fields — omit when empty.
	$sport = $get('sport');
	if ($sport !== '') {
		$parts[] = 'sport=' . $escape($sport);
	}
	$dport = $get('dport');
	if ($dport !== '') {
		$parts[] = 'dport=' . $escape($dport);
	}

	// Required IP version.
	$parts[] = 'ipver=' . $escape($get('ipver'));

	// Optional enrichment fields — omit when empty or a known absent-sentinel.
	foreach (['geoip', 'alias', 'feed', 'host', 'asn'] as $key) {
		$val = $get($key);
		if (!in_array($val, $absent_sentinels, TRUE)) {
			$parts[] = $key . '=' . $escape($val);
		}
	}

	return implode(' ', $parts);
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
