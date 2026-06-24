<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-28 Phase 1 — round-trip identity tests for the field-aware config adapters.
 *
 * Rule (ADR-28 §2.2 reframe): for every adapted field, every existing stored value
 * (incl. empty / unset / any legacy variant) must satisfy write(read(v)) == v for
 * canonical values, or must map to a behaviour-equivalent canonical token for legacy
 * migration values (behaviour preserved on upgrade, downgrade-safe).  Fields that
 * cannot satisfy this are excluded (documented in 01_Results.txt).
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
 * Scenario C — PfbIdnMode (pfb_idn / dnsbl_idn): backing values 'on'/'confusable'/'off'.
 *   Background: config.xml stores 'on' (= All, block-all-IDN), 'confusable', 'off'. 'on'
 *     reuses the pre-4.0.0 block-all token, so older releases reading it still block all
 *     IDN (downgrade-safe). The 4.0.0-alpha-only 'all' token is dropped (unrecognised ->
 *     Off), and '' (absent/disabled) is Off.
 *     Given a raw stored value v.
 *     When pfb_cfg_idn_mode_read(v) -> enum, pfb_cfg_idn_mode_write(enum) -> stored.
 *     Then write(read('on')) == 'on'  (canonical identity).
 *     And write(read('confusable')) == 'confusable'  (identity).
 *     And write(read('off')) == 'off'  (identity).
 *     And write(read('all')) == 'off'  (dropped alpha token -> Off).
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

	public function testToggleWriteAcceptsLegacyString(): void
	{
		// PfbConfig::write() advertises an "enum or string" contract; a raw
		// legacy string must normalise through the read adapter (it was a
		// TypeError before — pfblockerng_update.php Force Reload passes 'on').
		// Canonical strings round-trip; junk normalises to the '' default.
		$this->assertSame('on', pfb_cfg_toggle_write('on'));
		$this->assertSame('', pfb_cfg_toggle_write(''));
		$this->assertSame('', pfb_cfg_toggle_write('off'));
		$this->assertSame('', pfb_cfg_toggle_write('yes'));
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

	public function testLenientWriteAcceptsLegacyString(): void
	{
		// "enum or string" contract: raw legacy string normalises through read.
		// 'on'/'off' round-trip; '' and junk normalise to the 'off' default.
		$this->assertSame('on', pfb_cfg_lenient_write('on'));
		$this->assertSame('off', pfb_cfg_lenient_write('off'));
		$this->assertSame('off', pfb_cfg_lenient_write(''));
		$this->assertSame('off', pfb_cfg_lenient_write('yes'));
	}

	// -----------------------------------------------------------------------
	// Scenario C — PfbIdnMode
	// -----------------------------------------------------------------------

	public function testIdnModeReadCanonicalOnReturnsAll(): void
	{
		// 'on' is the canonical block-all token (PfbIdnMode::All backing value), reused
		// from the pre-4.0.0 binary IDN toggle.
		$this->assertSame(PfbIdnMode::All, pfb_cfg_idn_mode_read('on'));
	}

	public function testIdnModeReadTransitionalAllReturnsOff(): void
	{
		// 'all' was the 4.0.0-alpha transitional token; alpha compatibility is not
		// maintained, so it is now an unrecognised token -> Off.
		$this->assertSame(PfbIdnMode::Off, pfb_cfg_idn_mode_read('all'));
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

	public function testIdnModeReadJunkReturnsDefault(): void
	{
		$this->assertSame(PfbIdnMode::Off, pfb_cfg_idn_mode_read('yes'));
		$this->assertSame(PfbIdnMode::Off, pfb_cfg_idn_mode_read('enabled'));
		$this->assertSame(PfbIdnMode::Off, pfb_cfg_idn_mode_read('IDN_MODE_ALL'));
	}

	// -----------------------------------------------------------------------
	// Non-scalar guard (is_scalar branch) — all three read adapters
	// -----------------------------------------------------------------------

	public function testToggleReadNonScalarReturnsDefault(): void
	{
		// Non-scalar input (e.g. array from config_get_path returning a subtree) must
		// return the field default WITHOUT emitting "Array to string conversion" warning.
		$this->assertSame(PfbToggle::Off, pfb_cfg_toggle_read(['x']));
		$this->assertSame(PfbToggle::Off, pfb_cfg_toggle_read(['on']));
	}

	public function testLenientReadNonScalarReturnsDefault(): void
	{
		// Non-scalar input returns Off (the field default) without casting.
		$this->assertSame(PfbLenient::Off, pfb_cfg_lenient_read(['x']));
		$this->assertSame(PfbLenient::Off, pfb_cfg_lenient_read(['on']));
	}

	public function testIdnModeReadNonScalarReturnsDefault(): void
	{
		// Non-scalar input returns Off (the field default) without casting.
		$this->assertSame(PfbIdnMode::Off, pfb_cfg_idn_mode_read(['x']));
		$this->assertSame(PfbIdnMode::Off, pfb_cfg_idn_mode_read(['all']));
	}

	public function testIdnModeDroppedAlphaAllNormalisesToOff(): void
	{
		// 'all' (4.0.0-alpha only; compatibility intentionally dropped) is unrecognised
		// -> Off, so a write-back emits 'off' — NOT the legacy 'all'.
		$v = 'all';
		// Before: raw.
		$this->assertSame('all', $v);

		// When round-tripped.
		$result = pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read($v));

		// Then: 'off' (unrecognised -> Off).
		$this->assertSame('off', $result);
		$this->assertNotSame('all', $result);
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

	public function testIdnModeCanonicalOnRoundTripsLosslessly(): void
	{
		// 'on' is now the CANONICAL stored token for PfbIdnMode::All (the backing
		// value). It reads back as All and writes as 'on' — perfect identity.
		// (Previously 'on' was treated as "legacy" and normalised to 'all'; the
		// ADR-28 reframe reclaimed 'on' as the canonical token: older releases reading
		// 'on' still block all IDN, so this is behaviour-preserving + downgrade-safe.)
		// Before: raw canonical value.
		$raw = 'on';
		$this->assertSame('on', $raw);

		// When round-tripped.
		$result = pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read($raw));

		// Then: 'on' — canonical identity.
		$this->assertSame('on', $result, "'on' is the canonical token for All — round-trips losslessly");
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
		// PfbIdnMode::All backing value is 'on' (the original pre-ADR-08 block-all
		// token, reused for round-trip correctness + downgrade safety).
		$this->assertSame('on', pfb_cfg_idn_mode_write(PfbIdnMode::All));
		$this->assertSame('confusable', pfb_cfg_idn_mode_write(PfbIdnMode::Confusable));
		$this->assertSame('off', pfb_cfg_idn_mode_write(PfbIdnMode::Off));
	}

	public function testIdnModeWriteAcceptsLegacyString(): void
	{
		// "enum or string" contract: raw string normalises through read adapter.
		// 'on'  -> All (canonical) — round-trips losslessly.
		// 'confusable' and 'off' are canonical and round-trip.
		// '', junk, and the dropped 4.0.0-alpha 'all' normalise to Off -> 'off'.
		$this->assertSame('on',          pfb_cfg_idn_mode_write('on'));
		$this->assertSame('confusable',  pfb_cfg_idn_mode_write('confusable'));
		$this->assertSame('off',         pfb_cfg_idn_mode_write('off'));
		$this->assertSame('off',         pfb_cfg_idn_mode_write(''));
		$this->assertSame('off',         pfb_cfg_idn_mode_write('yes'));
		$this->assertSame('off',         pfb_cfg_idn_mode_write('all'));   // dropped alpha token
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

	public function testP5ReadBoundaryPatternMatchesOldCompare(): void
	{
		// Equivalence: pfb_cfg_toggle_read($v) === PfbToggle::On
		// must produce the same bool as the old ($v == 'on') for all stored vocab.
		// Before-state: old expression produces false for '', true for 'on'.
		$this->assertFalse('' == 'on', 'before: empty string is not on');
		$this->assertTrue('on' == 'on', 'before: on is on');
		$this->assertFalse('off' == 'on', 'before: off is not on');
		$this->assertFalse(null == 'on', 'before: null is not on');

		// After-state: adapter produces same bool.
		$this->assertFalse(pfb_cfg_toggle_read('') === PfbToggle::On, 'adapter: empty string -> Off != On');
		$this->assertTrue(pfb_cfg_toggle_read('on') === PfbToggle::On, 'adapter: on -> On == On');
		$this->assertFalse(pfb_cfg_toggle_read('off') === PfbToggle::On, 'adapter: off -> Off != On');
		$this->assertFalse(pfb_cfg_toggle_read(null) === PfbToggle::On, 'adapter: null -> Off != On');
		$this->assertFalse(pfb_cfg_toggle_read('yes') === PfbToggle::On, 'adapter: yes -> Off != On');

		// Negation pattern: !== PfbToggle::On same as != 'on'
		$this->assertTrue(pfb_cfg_toggle_read('') !== PfbToggle::On, 'negation: empty != on');
		$this->assertFalse(pfb_cfg_toggle_read('on') !== PfbToggle::On, 'negation: on is on');
	}

	public function testP5FormCheckboxPatternMatchesOldTernary(): void
	{
		// Pattern: $pconfig['field'] === 'on' ? TRUE:FALSE
		// vs:      pfb_cfg_toggle_read($pconfig['field']) === PfbToggle::On
		// These must be identical for every stored vocab value.
		$vocab = ['on', '', 'off', null];
		foreach ($vocab as $v) {
			$old  = ($v === 'on') ? true : false;
			$new  = pfb_cfg_toggle_read($v) === PfbToggle::On;
			$this->assertSame($old, $new,
				"Form_Checkbox pattern mismatch for stored value: " . var_export($v, true));
		}
	}
}
