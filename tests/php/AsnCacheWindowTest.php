<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_asn_cache_window() — the pure mapping from the ASN Reporting
 * setting to the SQLite relative-time expiry window (issue #713, bug 13).
 *
 * pfb_daemon_filterlog()'s cache-eviction DELETE runs whenever
 * ($pfb['asn_reporting'] != 'disabled' || !empty($pfb['asn_token'])) -- a
 * WIDER guard than the old $asn_cache-assigning switch, which only ran when
 * asn_reporting wasn't 'disabled'. So a config with reporting disabled but an
 * ASN token set reached the DELETE with $asn_cache undefined/NULL, binding NULL
 * and never expiring anything -- an unbounded cache. This mapping is
 * unconditional and defaults 'disabled' (and any unknown token) to the same
 * '-24 hours' safety window used for an unrecognised value, so the DELETE
 * always has a real bound.
 *
 * Scenario A-E: each configured reporting interval maps to its SQLite window.
 * Scenario F: 'disabled' -> the safe '-24 hours' default (the regression).
 * Scenario G: an unrecognised token -> the same safe default.
 */
#[CoversFunction('pfb_asn_cache_window')]
final class AsnCacheWindowTest extends TestCase
{
	public function testOneHour_MapsToMinusOneHour(): void
	{
		$this->assertSame('-1 hour', pfb_asn_cache_window('1hour'));
	}

	public function testFourHour_MapsToMinusFourHours(): void
	{
		$this->assertSame('-4 hours', pfb_asn_cache_window('4hour'));
	}

	public function testTwelveHour_MapsToMinusTwelveHours(): void
	{
		$this->assertSame('-12 hours', pfb_asn_cache_window('12hour'));
	}

	public function testTwentyFourHour_MapsToMinusTwentyFourHours(): void
	{
		$this->assertSame('-24 hours', pfb_asn_cache_window('24hour'));
	}

	public function testWeek_MapsToMinusOneWeek(): void
	{
		$this->assertSame('-1 week', pfb_asn_cache_window('week'));
	}

	// ---------- Scenario F — the regression: 'disabled' must still be defined ----------

	/**
	 * The regression this bug fixes: 'disabled' (reporting off, but the cache
	 * eviction still runs when an ASN token is configured) must map to the safe
	 * default, never to an empty/undefined value that would bind NULL and defeat
	 * the DELETE's expiry.
	 */
	public function testDisabled_MapsToSafeTwentyFourHourDefault(): void
	{
		$window = pfb_asn_cache_window('disabled');

		$this->assertSame('-24 hours', $window,
			"expected: 'disabled' still yields a real SQLite window so the cache "
			. "always expires;\nactual: '{$window}'");
	}

	// ---------- Scenario G — unknown token falls back to the same safe default ----------

	public function testUnknownToken_MapsToSafeTwentyFourHourDefault(): void
	{
		$window = pfb_asn_cache_window('not_a_real_value');

		$this->assertSame('-24 hours', $window,
			"expected: an unrecognised token falls back to '-24 hours';\n"
			. "actual: '{$window}'");
	}
}
