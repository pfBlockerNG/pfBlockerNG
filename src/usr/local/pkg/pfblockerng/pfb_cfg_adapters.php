<?php
/*
 * pfb_cfg_adapters.php — ADR-28 Phase 1
 *
 * Internal backed enums for recurring config flags + field-aware read/write
 * adapter helpers.  BEHAVIOUR-PRESERVING: nothing in production includes this
 * file yet.  Every adapter is exhaustively round-trip tested in
 * tests/php/CfgAdaptersTest.php.
 *
 * Rule (ADR-28 §2.2):
 *   - config.xml stored values NEVER change (no migration routine exists).
 *   - Enums are an INTERNAL runtime representation only.
 *   - read adapter: Enum::tryFrom($stored) ?? Enum::default()
 *   - write adapter: $enum->value  (equals the exact legacy stored string)
 *   - A field whose "off" is '' for one field and 'off' for another uses a
 *     FIELD-SPECIFIC default — there is no single global toggle.
 *
 * Naming follows pfb_* conventions (CLAUDE.md "Naming").
 */

declare(strict_types=1);

// ---------------------------------------------------------------------------
// PfbToggle — checkbox fields stored as 'on' (checked) or '' (unchecked).
//
// Used by: pfb_dnsvip_auto (pfb_dnsblconfig['pfb_dnsvip_auto']).
//   Stored vocabulary: 'on' | '' (missing/unchecked = '').
//   pfb_global() normalisation at :1334:
//     ($pfb['dnsblconfig']['pfb_dnsvip_auto'] ?? '') == 'on' ? 'on' : ''
// ---------------------------------------------------------------------------
enum PfbToggle: string
{
	case On  = 'on';
	case Off = '';

	public static function default(): self
	{
		return self::Off;
	}
}

// ---------------------------------------------------------------------------
// PfbLenient — the ADR-22 scheme-parsing leniency flag.
//
// Used by: pfb_dnsbl_lenient (pfb_dnsblconfig['pfb_dnsbl_lenient']).
//   Stored vocabulary: 'on' | 'off' | '' (missing pre-ADR-22 install).
//   pfb_global() normalisation at :1364:
//     (($pfb['dnsblconfig']['pfb_dnsbl_lenient'] ?? '') === 'on') ? 'on' : 'off'
//   Note: '' (missing key) maps to Off ('off'), NOT to the PfbToggle '' value.
//   This field's "off" stored value is 'off', distinct from PfbToggle::Off = ''.
// ---------------------------------------------------------------------------
enum PfbLenient: string
{
	case On  = 'on';
	case Off = 'off';

	public static function default(): self
	{
		return self::Off;
	}
}

// ---------------------------------------------------------------------------
// PfbIdnMode — ADR-08 IDN-feature mode selector.
//
// Used by: dnsbl_idn (pfb_dnsblconfig['pfb_idn']).
//   Stored vocabulary: 'all' | 'confusable' | 'off' | '' | 'on' (legacy).
//   pfb_global() normalisation at :1372-1373:
//     $pfb_idn_raw = $pfb['dnsblconfig']['pfb_idn'] ?? '';
//     $pfb['dnsbl_idn'] = ($pfb_idn_raw === 'on') ? 'all' : $pfb_idn_raw;
//   The legacy 'on' value migrates to 'all' at runtime; '' migrates to 'off'.
//   IMPORTANT: 'on' is a LEGACY stored value — new saves always write 'all'.
//   The adapter read fn below replicates the pfb_global() normalisation so
//   downstream code sees the canonical value ('all'/'off'/'confusable').
//   The write fn returns the canonical stored string (never 'on').
//   Round-trip note: read('on') -> All -> write -> 'all' != 'on'.
//   This is the INTENDED behaviour: the legacy value is normalised on read
//   and the canonical value is stored on write (a one-way migration for 'on').
//   This field is therefore EXCLUDED from write(read(v))==v for v='on' only;
//   all other values round-trip losslessly.  Documented in 01_Results.txt.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Field-aware adapter helpers (pfb_cfg_* naming per CLAUDE.md).
// ---------------------------------------------------------------------------

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
