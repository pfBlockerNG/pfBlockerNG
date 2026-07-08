<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-60 §1.8: dnsbl_alias_update() stamped its "last updated" stat with
 * date('M j H:i:s', time()) -- no year -- for both its 'update' and 'disabled'
 * branches. The widget reads that value back through pfb_iso_timestamp(), which
 * strtotime()-guesses a year for any no-year string; a value written in December
 * and read in a LATER year renders with the WRONG year (the real write year is
 * unrecoverable). Both branches now write date('Y-m-d H:i:s', time()) instead.
 *
 * pfb_iso_timestamp() itself is unchanged (kept -- see the handoff for why): the
 * characterization tests below prove it is STILL the only thing standing between
 * an old, already-stored no-year SQLite row and a wrong display, which is exactly
 * why it stays until every pre-existing row has been overwritten by this fix.
 */
#[CoversFunction('dnsbl_alias_update')]
#[CoversFunction('pfb_iso_timestamp')]
final class DnsblAliasUpdateTimestampFormatTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['pfb']['dnsbl_info_stats'] = array();
	}

	/**
	 * Red -> green proof (write side): the REAL function, called for real (real
	 * clock), must store a YEAR-bearing ISO timestamp for the 'update' branch.
	 * Pre-fix this stored 'Jul  8 ...' (no year) and the regex failed; post-fix it
	 * stores '2026-07-08 ...' and passes.
	 */
	public function testUpdateModeStoresYearBearingIsoTimestamp(): void
	{
		global $pfb;

		dnsbl_alias_update('update', 'PFB_TS_FMT_TEST', '', '', 3);

		$this->assertNotEmpty($pfb['dnsbl_info_stats'], 'expected a stat row to be recorded');
		$stamp = $pfb['dnsbl_info_stats'][0]['timestamp'];
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			$stamp,
			"dnsbl_alias_update('update', ...) must store a year-bearing ISO timestamp now; got: {$stamp}"
		);

		// A FRESH value round-trips through pfb_iso_timestamp() unchanged -- no more
		// guessing needed once the write side carries a real year.
		$this->assertSame($stamp, pfb_iso_timestamp($stamp), 'a fresh ISO-with-year value must round-trip unchanged');
	}

	/**
	 * Same proof for the 'disabled' branch -- the second, separate call site.
	 */
	public function testDisabledModeStoresYearBearingIsoTimestamp(): void
	{
		global $pfb;

		dnsbl_alias_update('disabled', 'PFB_TS_FMT_TEST_DISABLED', '', '', '');

		$this->assertNotEmpty($pfb['dnsbl_info_stats'], 'expected a disabled-alias stat row to be recorded');
		$stamp = $pfb['dnsbl_info_stats'][0]['timestamp'];
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			$stamp,
			"dnsbl_alias_update('disabled', ...) must store a year-bearing ISO timestamp now; got: {$stamp}"
		);
	}

	/**
	 * Characterization (the residual upgrade-window risk pfb_iso_timestamp() still
	 * covers): a value stamped the OLD way (no year) at a December instant in a
	 * definite past year (2024) permanently loses that year on readback -- the
	 * reformatter can only guess the CURRENT year, never the actual write year.
	 * This is the exact "December-updated/January-viewed" bug from the ADR, made
	 * deterministic by using a fixed past write-year instead of real wall-clock time
	 * (which cannot be frozen here without mocking strtotime()/date()).
	 */
	public function testOldNoYearFormatLosesTheRealWriteYearOnReadback(): void
	{
		$writeYear = 2024;
		// Exactly what the OLD (pre-fix) dnsbl_alias_update() line produced for a
		// December 31 instant in $writeYear: date('M j H:i:s', $epoch).
		$oldStoredValue = date('M j H:i:s', mktime(23, 0, 0, 12, 31, $writeYear));
		$this->assertSame('Dec 31 23:00:00', $oldStoredValue, 'fixture sanity: the OLD no-year write format');

		$result = pfb_iso_timestamp($oldStoredValue);

		$this->assertStringNotContainsString(
			(string) $writeYear,
			$result,
			"BUG: the actual write year ({$writeYear}) must be lost by the no-year format -- got: {$result}"
		);
	}

	/**
	 * Green pairing: the SAME December 2024 instant, stored the NEW way (a real
	 * year), round-trips through pfb_iso_timestamp() with the CORRECT year --
	 * regardless of what year it is actually read back in.
	 */
	public function testNewYearBearingFormatPreservesTheRealWriteYearOnReadback(): void
	{
		$writeYear = 2024;
		// Exactly what the FIXED dnsbl_alias_update() line now produces for the same instant.
		$newStoredValue = date('Y-m-d H:i:s', mktime(23, 0, 0, 12, 31, $writeYear));
		$this->assertSame('2024-12-31 23:00:00', $newStoredValue, 'fixture sanity: the NEW year-bearing write format');

		$result = pfb_iso_timestamp($newStoredValue);

		$this->assertSame(
			$newStoredValue,
			$result,
			"the year-bearing value must round-trip unchanged, preserving the real write year ({$writeYear})"
		);
	}
}
