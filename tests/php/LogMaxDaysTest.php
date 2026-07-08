<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_log_max_days() — resolves a stored 'log_max_days_<type>' config value to
 * the age-cutoff day count pfb_log_mgmt() applies (ADR-60 S2.2).
 *
 * Mirrors pfb_log_max_lines()'s fallback shape (LogMaxLinesTest.php): the raw
 * config value is untrusted (an operator's typo, or an absent/never-written
 * key on a fresh install) and must never crash pfb_log_mgmt() -- anything that
 * isn't a plain non-negative integer string resolves to '0' (off), the same
 * as the registered default.
 *
 * Branch coverage: all input classes pfb_log_mgmt() can see for a
 * 'log_max_days_<type>' field (S2.6 hostile-input row: "non-numeric/garbage
 * config value treated as off").
 */
#[CoversFunction('pfb_log_max_days')]
final class LogMaxDaysTest extends TestCase
{
	/**
	 * A digit-string config value resolves to that same int day count.
	 */
	public function testNumericRawResolvesToThatIntDayCount(): void
	{
		$this->assertSame(30, pfb_log_max_days('30'), "'30' must resolve to 30 days");
		$this->assertSame(365, pfb_log_max_days('365'), "'365' must resolve to 365 days");
	}

	/**
	 * The explicit '0' (registered default) resolves to 0 -- the age cap is off.
	 */
	public function testZeroResolvesToOffZero(): void
	{
		$this->assertSame(0, pfb_log_max_days('0'), "'0' must resolve to 0 (off)");
	}

	/**
	 * Anything that is not a plain digit string (empty, garbage, absent/null,
	 * or a negative number -- the '-' character fails the digit-only regex)
	 * falls back to 0 (off) -- an operator's malformed value must never trim
	 * a log against a garbage cutoff.
	 */
	public function testInvalidOrEmptyRawFallsBackToZero(): void
	{
		$this->assertSame(0, pfb_log_max_days(''), "empty raw value must fall back to 0 (off)");
		$this->assertSame(0, pfb_log_max_days('not-a-number'), "non-numeric raw value must fall back to 0 (off)");
		$this->assertSame(0, pfb_log_max_days(null), "absent (null) raw value must fall back to 0 (off)");
		$this->assertSame(0, pfb_log_max_days('-5'), "a negative numeric string must fall back to 0 (off)");
		$this->assertSame(0, pfb_log_max_days('nolimit'), "'nolimit' is not a valid day count -- must fall back to 0 (off)");
	}
}
