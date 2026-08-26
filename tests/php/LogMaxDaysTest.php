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

	/**
	 * Adversarial review finding (PR #1005): an oversized-but-all-digit value passes
	 * the /^[0-9]+$/ guard and (int) casts to PHP_INT_MAX. pfb_log_age_trim_temp()
	 * then computes 'days * 86400', which overflows int into a float and throws a
	 * TypeError against pfb_log_age_cutoff()'s typed 'int $cutoff_ts' parameter --
	 * crashing pfb_log_mgmt() entirely instead of the promised never-crash fallback.
	 * The result must be clamped well below PHP_INT_MAX / 86400 so the multiplication
	 * can never overflow.
	 */
	public function testOversizedAllDigitRawIsClampedNotPhpIntMax(): void
	{
		$result = pfb_log_max_days('99999999999999999999999999999999');

		$this->assertLessThan(
			(int) (PHP_INT_MAX / 86400),
			$result,
			'an oversized value must be clamped well under PHP_INT_MAX/86400, or the *86400 step overflows int to float'
		);
		$this->assertIsInt($result);

		// The clamped value, multiplied out, must itself never overflow.
		$product = $result * 86400;
		$this->assertIsInt($product, "days*86400 must stay a native int (not overflow to float); got: " . var_export($product, TRUE));
	}
}
