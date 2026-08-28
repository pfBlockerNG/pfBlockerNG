<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_log_trim_margin_pct() -- issue #1109: resolves the stored global
 * 'pfb_log_trim_margin_pct' config value to the hysteresis margin percent
 * pfb_log_trim_needed() applies. Mirrors pfb_log_max_days()'s fallback shape
 * (LogMaxDaysTest.php): non-numeric/garbage/absent/non-scalar -> 0 (off).
 *
 * Branch coverage: every hostile-input row for a global percent knob,
 * including the #1143 TypeError class (an array config value reaching a
 * string-typed sink) -- the is_scalar() guard is what stops it.
 */
#[CoversFunction('pfb_log_trim_margin_pct')]
final class LogTrimMarginPctTest extends TestCase
{
	public function testEmptyStringResolvesToZero(): void
	{
		$this->assertSame(0, pfb_log_trim_margin_pct(''), "'' must resolve to 0 (off)");
	}

	public function testExplicitZeroResolvesToZero(): void
	{
		$this->assertSame(0, pfb_log_trim_margin_pct('0'), "'0' must resolve to 0 (off)");
	}

	public function testMidRangeValueResolvesToItself(): void
	{
		$this->assertSame(50, pfb_log_trim_margin_pct('50'), "'50' must resolve to 50");
	}

	public function testClampBoundaryValueResolvesToItself(): void
	{
		$this->assertSame(1000, pfb_log_trim_margin_pct('1000'), "'1000' (clamp boundary) must resolve to 1000");
	}

	public function testOversizedValueIsClampedToBoundary(): void
	{
		$this->assertSame(1000, pfb_log_trim_margin_pct('2000'), "'2000' must clamp down to 1000");
	}

	public function testHugeOversizedValueIsClampedToBoundary(): void
	{
		$this->assertSame(1000, pfb_log_trim_margin_pct('999999999'), "'999999999' must clamp down to 1000");
	}

	public function testNonNumericValueFallsBackToZero(): void
	{
		$this->assertSame(0, pfb_log_trim_margin_pct('abc'), "'abc' must fall back to 0");
	}

	public function testNegativeValueFallsBackToZero(): void
	{
		$this->assertSame(0, pfb_log_trim_margin_pct('-5'), "'-5' must fall back to 0");
	}

	public function testDecimalValueFallsBackToZero(): void
	{
		$this->assertSame(0, pfb_log_trim_margin_pct('1.5'), "'1.5' must fall back to 0");
	}

	public function testWhitespacePaddedValueFallsBackToZero(): void
	{
		$this->assertSame(0, pfb_log_trim_margin_pct('  50 '), "'  50 ' must fall back to 0 (not trimmed)");
	}

	public function testArrayValueFallsBackToZeroNotTypeError(): void
	{
		// #1143 TypeError class: an array config value reaching a string-typed
		// sink. is_scalar() is what stops it here (see also #1109 integration
		// coverage: LogMgmtAgeCutoffTest::testMarginConfigValueAsArrayDoesNotCrash).
		$this->assertSame(0, pfb_log_trim_margin_pct(['50']), "an array raw value must fall back to 0, not TypeError");
	}

	public function testNullValueFallsBackToZero(): void
	{
		$this->assertSame(0, pfb_log_trim_margin_pct(NULL), 'NULL must fall back to 0');
	}

	/**
	 * TRUE parses to 1 -- parity with pfb_log_max_days(TRUE), NOT a special
	 * case: is_scalar(TRUE) is TRUE and (string) TRUE === '1', so both
	 * siblings inherit the same behaviour by construction.
	 */
	public function testBooleanTrueParityWithSiblingParser(): void
	{
		$this->assertSame(1, pfb_log_trim_margin_pct(TRUE), 'TRUE must resolve to 1 (is_scalar+string-cast quirk)');
		$this->assertSame(
			pfb_log_max_days(TRUE),
			pfb_log_trim_margin_pct(TRUE),
			"must match pfb_log_max_days(TRUE)'s behaviour exactly (both share the is_scalar guard shape)"
		);
	}
}
