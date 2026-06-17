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
	return PfbToggle::tryFrom((string) ($stored ?? '')) ?? PfbToggle::default();
}

/**
 * pfb_cfg_toggle_write — write a PfbToggle back to its stored string.
 *
 * Returns the exact legacy stored string ('on' or '').
 */
function pfb_cfg_toggle_write(PfbToggle $toggle): string
{
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
	if ((string) ($stored ?? '') === 'on') {
		return PfbLenient::On;
	}
	return PfbLenient::default();
}

/**
 * pfb_cfg_lenient_write — write a PfbLenient back to its stored string.
 *
 * Returns 'on' or 'off' (never '').
 */
function pfb_cfg_lenient_write(PfbLenient $lenient): string
{
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
 */
function pfb_cfg_idn_mode_write(PfbIdnMode $mode): string
{
	return $mode->value;
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
