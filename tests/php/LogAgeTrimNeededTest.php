<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_log_age_trim_needed() -- issue #1052/#1109: probe-before-copy for the
 * age-cap pass, renamed+generalised from the original #1052 'nolimit'-only
 * probe to also gate the numeric-cap branch via pfb_log_trim_needed().
 * $margin_pct widens the cutoff window; margin=0 is byte-identical to the
 * pre-#1109 formula, so every #1052 case is re-pinned here at margin=0.
 *
 * issue #1258: the margin parameter is now a RAW value, parsed internally via
 * pfb_log_trim_margin_pct() -- an out-of-range/hostile margin is no longer
 * constructible. The hostile rows below prove no caller, present or future,
 * can hand this guard an unclamped margin.
 */
#[CoversFunction('pfb_log_age_trim_needed')]
final class LogAgeTrimNeededTest extends TestCase
{
	private string $tmpFile;

	protected function setUp(): void
	{
		$this->tmpFile = (string) tempnam(sys_get_temp_dir(), 'pfb_age_trim_needed_');
	}

	protected function tearDown(): void
	{
		if (is_file($this->tmpFile)) {
			unlink($this->tmpFile);
		}
	}

	private function daysAgo(int $days): string
	{
		return date('Y-m-d H:i:s', time() - ($days * 86400));
	}

	private function secondsAgo(int $seconds): string
	{
		return date('Y-m-d H:i:s', time() - $seconds);
	}

	/** Runs $fn under a handler that records E_WARNING instead of printing it; fails the test if any fired. */
	private function assertNoPhpWarning(callable $fn): mixed
	{
		$warnings = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
			$warnings[] = $errstr;
			return TRUE;
		}, E_WARNING);
		try {
			$result = $fn();
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $warnings, 'must not trigger a PHP warning: ' . implode('; ', $warnings));
		return $result;
	}

	/** margin=0, oldest line NOT expired -- identical to #1052 today. */
	public function testMarginZeroOldestUnexpiredReturnsFalse(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(5) . " fresh-enough\n");
		$this->assertFalse(
			pfb_log_age_trim_needed($this->tmpFile, 10, 'log', 0),
			'margin=0: a 5-day-old first line under a 10-day cap must not need a pass'
		);
	}

	/** margin=0, oldest line expired -- identical to #1052 today. */
	public function testMarginZeroOldestExpiredReturnsTrue(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(15) . " too-old\n");
		$this->assertTrue(
			pfb_log_age_trim_needed($this->tmpFile, 10, 'log', 0),
			'margin=0: a 15-day-old first line past a 10-day cap must need a pass'
		);
	}

	/** margin=50, oldest past the cap but inside the 1.5x window -- the new hysteresis. */
	public function testMarginFiftyWithinHighWaterWindowReturnsFalse(): void
	{
		// cap=10 days, margin=50 -> window=15 days; 12 days old is past the cap
		// but still inside the widened window.
		file_put_contents($this->tmpFile, $this->daysAgo(12) . " past-cap-in-window\n");
		$this->assertFalse(
			pfb_log_age_trim_needed($this->tmpFile, 10, 'log', 50),
			'margin=50: a 12-day-old first line (cap=10, window=15) must not need a pass'
		);
	}

	/** margin=50, oldest past the 1.5x window -- must fire. */
	public function testMarginFiftyBeyondHighWaterWindowReturnsTrue(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(20) . " past-window\n");
		$this->assertTrue(
			pfb_log_age_trim_needed($this->tmpFile, 10, 'log', 50),
			'margin=50: a 20-day-old first line (cap=10, window=15) must need a pass'
		);
	}

	/** empty file -- fallthrough preserved regardless of margin. */
	public function testEmptyFileReturnsTrueRegardlessOfMargin(): void
	{
		file_put_contents($this->tmpFile, '');
		$this->assertTrue(
			pfb_log_age_trim_needed($this->tmpFile, 10, 'log', 50),
			'an empty file must fall through to TRUE (let the no-op pass run)'
		);
	}

	/** unparseable/legacy first line -- fallthrough preserved regardless of margin. */
	public function testUnparseableFirstLineReturnsTrueRegardlessOfMargin(): void
	{
		file_put_contents($this->tmpFile, "pre-ADR-60 legacy line, no timestamp\n");
		$this->assertTrue(
			pfb_log_age_trim_needed($this->tmpFile, 10, 'log', 50),
			'an unparseable/legacy first line must fall through to TRUE'
		);
	}

	/** unopenable path -- fallthrough preserved regardless of margin. */
	public function testUnopenablePathReturnsTrueRegardlessOfMargin(): void
	{
		$missing = $this->tmpFile . '-does-not-exist';
		$this->assertTrue(
			pfb_log_age_trim_needed($missing, 10, 'log', 50),
			'an unopenable path must fall through to TRUE'
		);
	}

	// -----------------------------------------------------------------------
	// issue #1258 hostile rows -- an out-of-range/hostile raw margin must be
	// unconstructible: no warning, no TypeError, resolves via the ONE clamp.
	// -----------------------------------------------------------------------

	/**
	 * At pfb_log_max_days()'s own 3650000-day clamp, an unclamped PHP_INT_MAX
	 * margin overflows the window arithmetic to a float, and (int) of an
	 * unrepresentable float is 0 -- a same-second cutoff that wipes the log.
	 * Must instead clamp to 1000%, giving a huge (never-expiring) window.
	 */
	public function testHostilePhpIntMaxRawMarginNeverCollapsesWindowToZero(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(100) . " x\n");
		$result = $this->assertNoPhpWarning(
			fn () => pfb_log_age_trim_needed($this->tmpFile, 3650000, 'log', PHP_INT_MAX)
		);
		$this->assertFalse($result, 'PHP_INT_MAX margin must clamp to 1000%, never collapse the window to 0');
	}

	public static function hostileOversizedMarginRows(): array
	{
		// agedays=10, margin clamps to 1000% -> window = 10*86400*11 = 110 days.
		return [
			'within clamped 110-day window (109d)' => [109 * 86400, FALSE],
			'beyond clamped 110-day window (111d)'  => [111 * 86400, TRUE],
		];
	}

	/** A huge-but-numeric string margin must clamp to the SAME 1000% boundary as the literal. */
	#[DataProvider('hostileOversizedMarginRows')]
	public function testHostileOversizedStringRawMarginClampsToBoundary(int $secondsAgo, bool $expected): void
	{
		file_put_contents($this->tmpFile, $this->secondsAgo($secondsAgo) . " x\n");
		$this->assertSame($expected, pfb_log_age_trim_needed($this->tmpFile, 10, 'log', '999999999'));
	}

	/**
	 * -5 must resolve to margin=0 (10-day exact window), not a literal
	 * negative margin (window=820800s/~9.5d) that would shrink the window
	 * and put a false-expired verdict on a line that is genuinely in range.
	 */
	public function testHostileNegativeRawMarginResolvesToZeroNotLiteralNegativeMargin(): void
	{
		file_put_contents($this->tmpFile, $this->secondsAgo(850000) . " x\n");
		$this->assertFalse(
			pfb_log_age_trim_needed($this->tmpFile, 10, 'log', -5),
			'-5 must resolve to margin=0, not a literal negative margin that shrinks the window'
		);
	}

	/** #1143 TypeError class: an array raw margin must fall back to 0 (is_scalar guard), never TypeError. */
	public function testHostileArrayRawMarginFallsBackToZeroNotTypeError(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(15) . " x\n");
		$this->assertTrue(
			pfb_log_age_trim_needed($this->tmpFile, 10, 'log', ['50']),
			'an array raw margin must fall back to 0, not TypeError'
		);
	}
}
