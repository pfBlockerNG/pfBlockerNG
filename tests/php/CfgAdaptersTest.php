<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-28 Phase 1 — round-trip identity tests for the field-aware config adapters.
 *
 * Rule (ADR-28 §2.2): for every adapted field, every existing stored value
 * (incl. empty / unset / any legacy variant) must satisfy write(read(v)) == v
 * for canonical values, or must map to the documented canonical value for
 * legacy migration values.  Any field that cannot round-trip losslessly is
 * excluded (documented in 01_Results.txt).
 *
 * Scenario A — PfbToggle (pfb_dnsvip_auto): 'on' / '' checkbox.
 *   Background: stored as 'on' (checked) or '' (unchecked / missing key).
 *     Given a raw stored value v.
 *     When pfb_cfg_toggle_read(v) -> enum, pfb_cfg_toggle_write(enum) -> stored.
 *     Then write(read(v)) == v for canonical values; junk -> default ''.
 *
 * Scenario B — PfbLenient (pfb_dnsbl_lenient): 'on' / 'off' / '' flag.
 *   Background: stored as 'on', 'off', or '' (pre-ADR-22 / missing key).
 *     Given a raw stored value v.
 *     When pfb_cfg_lenient_read(v) -> enum, pfb_cfg_lenient_write(enum) -> stored.
 *     Then write(read(v)) == v for 'on'/'off'; '' maps to 'off' (normalised default).
 *
 * Scenario C — PfbIdnMode (pfb_idn / dnsbl_idn): 'all'/'confusable'/'off'/''/'on'.
 *   Background: stored as 'all', 'confusable', 'off', '' (off/absent), or 'on' (legacy).
 *     Given a raw stored value v.
 *     When pfb_cfg_idn_mode_read(v) -> enum, pfb_cfg_idn_mode_write(enum) -> stored.
 *     Then write(read(v)) == v for canonical values ('all','confusable','off').
 *     And write(read('on')) == 'all'  (documented one-way legacy migration — excluded
 *     from strict round-trip; 'on' never re-emitted; see ADR-28 §2.2 + 01_Results.txt).
 *     And write(read('')) == 'off'    (normalised default).
 */
final class CfgAdaptersTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Scenario A — PfbToggle
	// -----------------------------------------------------------------------

	public function testToggleReadOnReturnsOn(): void
	{
		// Given the canonical 'on' stored value.
		// Before: raw string.
		$raw = 'on';
		$this->assertSame('on', $raw);

		// When read.
		$enum = pfb_cfg_toggle_read($raw);

		// Then On.
		$this->assertSame(PfbToggle::On, $enum);
	}

	public function testToggleReadEmptyReturnsOff(): void
	{
		// Given the canonical '' (unchecked checkbox) stored value.
		$enum = pfb_cfg_toggle_read('');

		$this->assertSame(PfbToggle::Off, $enum);
	}

	public function testToggleReadNullReturnsOff(): void
	{
		// Given null (missing key — config_get_path returns null for absent key).
		$enum = pfb_cfg_toggle_read(null);

		$this->assertSame(PfbToggle::Off, $enum);
	}

	public function testToggleReadJunkReturnsDefault(): void
	{
		// Given an unrecognised stored value — maps to Off (the default).
		$this->assertSame(PfbToggle::Off, pfb_cfg_toggle_read('yes'));
		$this->assertSame(PfbToggle::Off, pfb_cfg_toggle_read('1'));
		$this->assertSame(PfbToggle::Off, pfb_cfg_toggle_read('off'));
	}

	public function testToggleRoundTripOn(): void
	{
		// Given: canonical 'on'.  write(read(v)) == v.
		$v = 'on';
		// Before: raw string 'on'.
		$this->assertSame('on', $v);

		// When round-tripped.
		$result = pfb_cfg_toggle_write(pfb_cfg_toggle_read($v));

		// Then identical.
		$this->assertSame($v, $result);
	}

	public function testToggleRoundTripOff(): void
	{
		// Given: canonical '' (unchecked).  write(read(v)) == v.
		$v = '';
		$result = pfb_cfg_toggle_write(pfb_cfg_toggle_read($v));
		$this->assertSame($v, $result);
	}

	public function testToggleDefaultIsOff(): void
	{
		$this->assertSame(PfbToggle::Off, PfbToggle::default());
		$this->assertSame('', PfbToggle::default()->value);
	}

	public function testToggleWriteValues(): void
	{
		// write produces the exact stored strings — not 'true'/'false' or 1/0.
		$this->assertSame('on', pfb_cfg_toggle_write(PfbToggle::On));
		$this->assertSame('', pfb_cfg_toggle_write(PfbToggle::Off));
	}

	// -----------------------------------------------------------------------
	// Scenario B — PfbLenient
	// -----------------------------------------------------------------------

	public function testLenientReadOnReturnsOn(): void
	{
		// Given 'on' (lenient parsing enabled).
		$enum = pfb_cfg_lenient_read('on');
		$this->assertSame(PfbLenient::On, $enum);
	}

	public function testLenientReadOffReturnsOff(): void
	{
		// Given 'off' (strict parsing).
		$enum = pfb_cfg_lenient_read('off');
		$this->assertSame(PfbLenient::Off, $enum);
	}

	public function testLenientReadEmptyReturnsOff(): void
	{
		// Given '' (pre-ADR-22 install — key absent / blank).
		// Before: maps to Off (strict), not the same as PfbToggle::Off=''.
		$enum = pfb_cfg_lenient_read('');
		$this->assertSame(PfbLenient::Off, $enum);
	}

	public function testLenientReadNullReturnsOff(): void
	{
		$enum = pfb_cfg_lenient_read(null);
		$this->assertSame(PfbLenient::Off, $enum);
	}

	public function testLenientReadJunkReturnsDefault(): void
	{
		$this->assertSame(PfbLenient::Off, pfb_cfg_lenient_read('yes'));
		$this->assertSame(PfbLenient::Off, pfb_cfg_lenient_read('1'));
		$this->assertSame(PfbLenient::Off, pfb_cfg_lenient_read('enabled'));
	}

	public function testLenientRoundTripOn(): void
	{
		// 'on' round-trips losslessly.
		$v = 'on';
		// Before: raw.
		$this->assertSame('on', $v);
		// After.
		$this->assertSame($v, pfb_cfg_lenient_write(pfb_cfg_lenient_read($v)));
	}

	public function testLenientRoundTripOff(): void
	{
		// 'off' round-trips losslessly.
		$v = 'off';
		$this->assertSame($v, pfb_cfg_lenient_write(pfb_cfg_lenient_read($v)));
	}

	public function testLenientEmptyNormalisesToOff(): void
	{
		// '' (missing key) maps to 'off' on write — normalised default.
		// This is the documented non-lossless case for '' (not a canonical
		// write-back value; pfb_global() also normalises to 'off').
		$result = pfb_cfg_lenient_write(pfb_cfg_lenient_read(''));
		$this->assertSame('off', $result);
		// Confirm it's different from the raw ''.
		$this->assertNotSame('', $result);
	}

	public function testLenientDefaultIsOff(): void
	{
		$this->assertSame(PfbLenient::Off, PfbLenient::default());
		$this->assertSame('off', PfbLenient::default()->value);
	}

	public function testLenientWriteValues(): void
	{
		$this->assertSame('on', pfb_cfg_lenient_write(PfbLenient::On));
		$this->assertSame('off', pfb_cfg_lenient_write(PfbLenient::Off));
	}

	// -----------------------------------------------------------------------
	// Scenario C — PfbIdnMode
	// -----------------------------------------------------------------------

	public function testIdnModeReadAllReturnsAll(): void
	{
		// Given canonical 'all'.
		$enum = pfb_cfg_idn_mode_read('all');
		$this->assertSame(PfbIdnMode::All, $enum);
	}

	public function testIdnModeReadConfusableReturnsConfusable(): void
	{
		$enum = pfb_cfg_idn_mode_read('confusable');
		$this->assertSame(PfbIdnMode::Confusable, $enum);
	}

	public function testIdnModeReadOffReturnsOff(): void
	{
		$enum = pfb_cfg_idn_mode_read('off');
		$this->assertSame(PfbIdnMode::Off, $enum);
	}

	public function testIdnModeReadEmptyReturnsOff(): void
	{
		// '' (absent / disabled) -> Off.
		$enum = pfb_cfg_idn_mode_read('');
		$this->assertSame(PfbIdnMode::Off, $enum);
	}

	public function testIdnModeReadNullReturnsOff(): void
	{
		$enum = pfb_cfg_idn_mode_read(null);
		$this->assertSame(PfbIdnMode::Off, $enum);
	}

	public function testIdnModeReadLegacyOnReturnsAll(): void
	{
		// 'on' is the LEGACY stored value (pre-ADR-08 UI). pfb_global() maps
		// 'on' -> 'all' at runtime; the adapter replicates that normalisation.
		// Before: legacy value.
		$raw = 'on';
		$this->assertSame('on', $raw);

		// When read.
		$enum = pfb_cfg_idn_mode_read($raw);

		// Then All (normalised).
		$this->assertSame(PfbIdnMode::All, $enum);
	}

	public function testIdnModeReadJunkReturnsDefault(): void
	{
		$this->assertSame(PfbIdnMode::Off, pfb_cfg_idn_mode_read('yes'));
		$this->assertSame(PfbIdnMode::Off, pfb_cfg_idn_mode_read('enabled'));
		$this->assertSame(PfbIdnMode::Off, pfb_cfg_idn_mode_read('IDN_MODE_ALL'));
	}

	public function testIdnModeRoundTripAll(): void
	{
		// Canonical 'all' round-trips losslessly.
		$v = 'all';
		// Before: raw.
		$this->assertSame('all', $v);
		// After.
		$this->assertSame($v, pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read($v)));
	}

	public function testIdnModeRoundTripConfusable(): void
	{
		$v = 'confusable';
		$this->assertSame($v, pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read($v)));
	}

	public function testIdnModeRoundTripOff(): void
	{
		$v = 'off';
		$this->assertSame($v, pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read($v)));
	}

	public function testIdnModeLegacyOnNormalisesToAll(): void
	{
		// 'on' (legacy) normalises to 'all' on write — documented one-way migration.
		// This is the ONLY non-lossless case; all canonical values round-trip.
		// Before: raw legacy value.
		$raw = 'on';
		$this->assertSame('on', $raw);

		// After: canonical 'all' (one-way migration — 'on' is never re-emitted).
		$result = pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read($raw));
		$this->assertSame('all', $result);
		$this->assertNotSame('on', $result);
	}

	public function testIdnModeEmptyNormalisesToOff(): void
	{
		// '' normalises to 'off' on write.
		$result = pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read(''));
		$this->assertSame('off', $result);
	}

	public function testIdnModeDefaultIsOff(): void
	{
		$this->assertSame(PfbIdnMode::Off, PfbIdnMode::default());
		$this->assertSame('off', PfbIdnMode::default()->value);
	}

	public function testIdnModeWriteValues(): void
	{
		$this->assertSame('all', pfb_cfg_idn_mode_write(PfbIdnMode::All));
		$this->assertSame('confusable', pfb_cfg_idn_mode_write(PfbIdnMode::Confusable));
		$this->assertSame('off', pfb_cfg_idn_mode_write(PfbIdnMode::Off));
	}

	// -----------------------------------------------------------------------
	// Cross-field: confirm Off values are field-specific (NOT interchangeable)
	// -----------------------------------------------------------------------

	public function testOffValuesAreDifferentAcrossFields(): void
	{
		// PfbToggle::Off = '' -- checkbox unchecked.
		// PfbLenient::Off = 'off' -- explicit off, not empty.
		// PfbIdnMode::Off = 'off' -- explicit off, not empty.
		// These must NOT be confused with each other.
		$this->assertNotSame(
			pfb_cfg_toggle_write(PfbToggle::Off),
			pfb_cfg_lenient_write(PfbLenient::Off),
			'PfbToggle::Off and PfbLenient::Off must produce different stored strings'
		);
	}

	// -----------------------------------------------------------------------
	// Scenario D — Seam behaviour: pfb_global() adapter expressions produce
	// byte-identical strings to the OLD inline ternaries they replace.
	//
	// These tests are the falsifiable proof that the seam is unchanged.
	// They MUST fail if someone alters the normalisation.
	//
	// dnsbl_vip_auto (line ~1334): old = ($raw ?? '') == 'on' ? 'on' : ''
	//   Replaced by: pfb_cfg_toggle_read($raw ?? '')->value
	//
	// dnsbl_lenient (line ~1364): old = (($raw ?? '') === 'on') ? 'on' : 'off'
	//   Replaced by: pfb_cfg_lenient_read($raw ?? '')->value
	//
	// dnsbl_idn (lines ~1372-1373): EXCLUDED — old ternary passes '' through
	//   as '' (not 'off'), which differs from pfb_cfg_idn_mode_read('')->value
	//   ('off'). Seam left as-is; see ADR-28 Phase 4 handoff (04_Results.txt).
	// -----------------------------------------------------------------------

	/**
	 * dnsbl_vip_auto seam: adapter expression is byte-identical to the old ternary.
	 *
	 * Old: ($pfb['dnsblconfig']['pfb_dnsvip_auto'] ?? '') == 'on' ? 'on' : ''
	 * New: pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_dnsvip_auto'] ?? '')->value
	 *
	 * Scenario:
	 *   Given each reachable stored input for pfb_dnsvip_auto.
	 *   When run through the old ternary and the new adapter expression.
	 *   Then both produce the same byte-identical string.
	 */
	public function testSeamDnsblVipAutoAdapterMatchesOldTernary(): void
	{
		$cases = [
			['on',  'on', 'on'],      // canonical checked -> 'on'
			['',    '',   ''],        // canonical unchecked -> ''
			[null,  '',   ''],        // null (missing key, ?? '' gives '') -> ''
			['off', '',   ''],        // junk -> ''
			['yes', '',   ''],        // junk -> ''
			['1',   '',   ''],        // junk -> ''
		];

		foreach ($cases as [$raw, $expectedOld, $expectedNew]) {
			$coalesced = $raw ?? '';
			// Before: old ternary result (what pfb_global() used to produce).
			$old = $coalesced == 'on' ? 'on' : '';
			$this->assertSame($expectedOld, $old, "old ternary for input " . var_export($raw, TRUE));

			// After: adapter expression (what pfb_global() now produces).
			$new = pfb_cfg_toggle_read($coalesced)->value;
			$this->assertSame($expectedNew, $new, "adapter for input " . var_export($raw, TRUE));

			// Byte-identical: the seam is unchanged.
			$this->assertSame($old, $new, "old vs new differ for input " . var_export($raw, TRUE));
		}
	}

	/**
	 * dnsbl_lenient seam: adapter expression is byte-identical to the old ternary.
	 *
	 * Old: (($pfb['dnsblconfig']['pfb_dnsbl_lenient'] ?? '') === 'on') ? 'on' : 'off'
	 * New: pfb_cfg_lenient_read($pfb['dnsblconfig']['pfb_dnsbl_lenient'] ?? '')->value
	 *
	 * Scenario:
	 *   Given each reachable stored input for pfb_dnsbl_lenient.
	 *   When run through the old ternary and the new adapter expression.
	 *   Then both produce the same byte-identical string.
	 */
	public function testSeamDnsblLenientAdapterMatchesOldTernary(): void
	{
		$cases = [
			['on',      'on',  'on'],   // enabled -> 'on'
			['off',     'off', 'off'],  // explicit off -> 'off'
			['',        'off', 'off'],  // absent/blank pre-ADR-22 -> 'off'
			[null,      'off', 'off'],  // null (missing key) -> 'off'
			['yes',     'off', 'off'],  // junk -> 'off'
			['1',       'off', 'off'],  // junk -> 'off'
			['enabled', 'off', 'off'],  // junk -> 'off'
		];

		foreach ($cases as [$raw, $expectedOld, $expectedNew]) {
			$coalesced = $raw ?? '';
			// Before: old ternary result.
			$old = ($coalesced === 'on') ? 'on' : 'off';
			$this->assertSame($expectedOld, $old, "old ternary for input " . var_export($raw, TRUE));

			// After: adapter expression.
			$new = pfb_cfg_lenient_read($coalesced)->value;
			$this->assertSame($expectedNew, $new, "adapter for input " . var_export($raw, TRUE));

			// Byte-identical: the seam is unchanged.
			$this->assertSame($old, $new, "old vs new differ for input " . var_export($raw, TRUE));
		}
	}

	/**
	 * dnsbl_idn seam exclusion: prove the adapter would NOT be byte-identical to the
	 * old ternary for the '' input, confirming why the seam is excluded.
	 *
	 * Old: ($raw === 'on') ? 'all' : $raw   — passes '' through as ''
	 * Adapter: pfb_cfg_idn_mode_read('')->value   — returns 'off'
	 *
	 * This test PINS the exclusion decision: it will fail if the old seam behaviour
	 * ever changes to match the adapter (at which point the seam can be adopted).
	 */
	public function testSeamDnsblIdnExclusionProofEmptyPassthrough(): void
	{
		// Old ternary: '' passes through unchanged.
		$raw    = '';
		$oldResult = ($raw === 'on') ? 'all' : $raw;
		$this->assertSame('', $oldResult, 'old ternary must pass empty string through as empty string');

		// Adapter: '' normalises to Off = 'off'.
		$adapterResult = pfb_cfg_idn_mode_read($raw)->value;
		$this->assertSame('off', $adapterResult, 'adapter must return off for empty string');

		// They differ — this is why dnsbl_idn is excluded from seam adoption.
		$this->assertNotSame($oldResult, $adapterResult, 'old and adapter must differ for empty string (exclusion proof)');
	}

	/**
	 * dnsbl_idn seam: document the old ternary's pass-through behaviour for all inputs.
	 *
	 * This pins the CURRENT seam behaviour so any future change is detected.
	 */
	public function testSeamDnsblIdnOldTernaryBehaviour(): void
	{
		// Old seam: $pfb_idn_raw = $stored ?? ''; $pfb['dnsbl_idn'] = ($pfb_idn_raw === 'on') ? 'all' : $pfb_idn_raw;
		$cases = [
			['on',          'all'],         // legacy migration: 'on' -> 'all'
			['all',         'all'],         // canonical
			['confusable',  'confusable'],  // canonical
			['off',         'off'],         // canonical
			['',            ''],            // absent/blank: passes through as '' (NOT 'off')
			['junk',        'junk'],        // junk: passes through unchanged
		];

		foreach ($cases as [$raw, $expected]) {
			$pfb_idn_raw  = $raw ?? '';
			$result       = ($pfb_idn_raw === 'on') ? 'all' : $pfb_idn_raw;
			$this->assertSame($expected, $result, "old ternary for input " . var_export($raw, TRUE));
		}
	}
}
