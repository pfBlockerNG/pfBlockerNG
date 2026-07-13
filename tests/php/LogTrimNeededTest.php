<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_log_trim_needed() -- issue #1109: the ONE unified high-water guard for
 * BOTH pfb_log_mgmt() branches, replacing the two duplicated #1052 skip
 * lines. Line-cap x age-cap x margin matrix (issue #1109's own table):
 * numeric-cap-only, nolimit-only, and combined rows, each at margin 0 and 50.
 *
 * Float math throughout (never intdiv()): pfb_log_max_lines() applies no
 * clamp, so $logmax can be an absurd int -- intdiv() throws TypeError on a
 * float argument, and integer overflow promotes to float in PHP. The
 * mandatory hostile row below pins that this never crashes.
 *
 * issue #1258: the margin parameter is now a RAW value, parsed internally via
 * pfb_log_trim_margin_pct() -- an out-of-range/hostile margin is no longer
 * constructible, including via the internal call to pfb_log_age_trim_needed().
 */
#[CoversFunction('pfb_log_trim_needed')]
final class LogTrimNeededTest extends TestCase
{
	private string $tmpFile;

	protected function setUp(): void
	{
		$this->tmpFile = (string) tempnam(sys_get_temp_dir(), 'pfb_trim_needed_');
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

	private function seedLines(int $count): void
	{
		$lines = [];
		for ($i = 0; $i < $count; $i++) {
			$lines[] = "l{$i}";
		}
		file_put_contents($this->tmpFile, implode("\n", $lines) . "\n");
	}

	/** $oldCount old (chronologically first) lines at $oldDays, then $freshCount lines dated today. */
	private function seedAgedLines(int $oldCount, int $oldDays, int $freshCount): void
	{
		$lines = [];
		for ($i = 0; $i < $oldCount; $i++) {
			$lines[] = $this->daysAgo($oldDays) . " old{$i}";
		}
		for ($i = 0; $i < $freshCount; $i++) {
			$lines[] = date('Y-m-d H:i:s') . " fresh{$i}";
		}
		file_put_contents($this->tmpFile, implode("\n", $lines) . "\n");
	}

	// -----------------------------------------------------------------------
	// Row 1/2 -- numeric cap, age off, margin 0.
	// -----------------------------------------------------------------------

	public function testNumericCapAgeOffMarginZeroUnderCapDoesNotFire(): void
	{
		$this->seedLines(8);
		$this->assertFalse(
			pfb_log_trim_needed(10, 0, $this->tmpFile, 'log', 0),
			'8 lines under a 10-line cap must not need a trim -- the redundant-rewrite elision'
		);
	}

	public function testNumericCapAgeOffMarginZeroOverCapFires(): void
	{
		$this->seedLines(12);
		$this->assertTrue(
			pfb_log_trim_needed(10, 0, $this->tmpFile, 'log', 0),
			'12 lines over a 10-line cap must need a trim'
		);
	}

	// -----------------------------------------------------------------------
	// Row 3/4 -- numeric cap, age off, margin 50 (high-water = 1.5x cap).
	// -----------------------------------------------------------------------

	public function testNumericCapAgeOffMarginFiftyUnderHighWaterDoesNotFire(): void
	{
		$this->seedLines(12); // 1.2x of 10
		$this->assertFalse(
			pfb_log_trim_needed(10, 0, $this->tmpFile, 'log', 50),
			'12 lines (1.2x cap) under the 1.5x high-water must not need a trim'
		);
	}

	public function testNumericCapAgeOffMarginFiftyOverHighWaterFires(): void
	{
		$this->seedLines(16); // 1.6x of 10
		$this->assertTrue(
			pfb_log_trim_needed(10, 0, $this->tmpFile, 'log', 50),
			'16 lines (1.6x cap) over the 1.5x high-water must need a trim'
		);
	}

	// -----------------------------------------------------------------------
	// Row 5 -- nolimit, age set, margin 0 (identical to #1052 today).
	// -----------------------------------------------------------------------

	public function testNolimitAgeSetMarginZeroHeadUnexpiredDoesNotFire(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(5) . " a\n");
		$this->assertFalse(
			pfb_log_trim_needed('nolimit', 10, $this->tmpFile, 'log', 0),
			'margin=0: unexpired head must not need a trim (identical to #1052)'
		);
	}

	public function testNolimitAgeSetMarginZeroHeadExpiredFires(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(15) . " a\n");
		$this->assertTrue(
			pfb_log_trim_needed('nolimit', 10, $this->tmpFile, 'log', 0),
			'margin=0: expired head must need a trim (identical to #1052)'
		);
	}

	// -----------------------------------------------------------------------
	// Row 6 -- nolimit, age set, margin 50 (window = 1.5x cap days).
	// -----------------------------------------------------------------------

	public function testNolimitAgeSetMarginFiftyHeadInWindowDoesNotFire(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(12) . " a\n"); // cap=10, window=15
		$this->assertFalse(
			pfb_log_trim_needed('nolimit', 10, $this->tmpFile, 'log', 50),
			'margin=50: a 12-day head under the 15-day window must not need a trim'
		);
	}

	public function testNolimitAgeSetMarginFiftyHeadBeyondWindowFires(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(20) . " a\n"); // cap=10, window=15
		$this->assertTrue(
			pfb_log_trim_needed('nolimit', 10, $this->tmpFile, 'log', 50),
			'margin=50: a 20-day head over the 15-day window must need a trim'
		);
	}

	// -----------------------------------------------------------------------
	// Row 7 -- numeric cap AND age set, margin 0: fires iff lines>cap OR head expired.
	// -----------------------------------------------------------------------

	public function testNumericAndAgeMarginZeroNeitherExceedsDoesNotFire(): void
	{
		$this->seedAgedLines(0, 0, 5); // 5 fresh lines; cap=10, age-cap=10 days
		$this->assertFalse(
			pfb_log_trim_needed(10, 10, $this->tmpFile, 'log', 0),
			'5 fresh lines under a 10-line cap with an unexpired head must not fire'
		);
	}

	public function testNumericAndAgeMarginZeroLineExceedsFires(): void
	{
		// All FRESH timestamps (not merely unparseable) -- isolates the
		// line-cap trigger: if the short-circuit broke, the age check alone
		// would return FALSE (unexpired), not accidentally TRUE via the
		// unparseable-first-line fallthrough.
		$this->seedAgedLines(0, 0, 12); // 12 fresh lines > 10-line cap
		$this->assertTrue(
			pfb_log_trim_needed(10, 10, $this->tmpFile, 'log', 0),
			'line cap alone exceeding must fire regardless of a fresh (unexpired) age head'
		);
	}

	public function testNumericAndAgeMarginZeroAgeExceedsFires(): void
	{
		$this->seedAgedLines(1, 15, 2); // 3 total lines (well under cap); head 15d old > 10d age-cap
		$this->assertTrue(
			pfb_log_trim_needed(10, 10, $this->tmpFile, 'log', 0),
			'age cap alone exceeding must fire regardless of line count'
		);
	}

	// -----------------------------------------------------------------------
	// Row 8 -- numeric cap AND age set, margin 50: fires iff EITHER cap is
	// over ITS OWN high-water.
	// -----------------------------------------------------------------------

	public function testNumericAndAgeMarginFiftyNeitherExceedsOwnHighWaterDoesNotFire(): void
	{
		// line: 11 total (1 old head + 10 fresh) < 1.5x10=15 high-water.
		// age: head 12d old, cap=10d -> window=15d; 12<15, not expired.
		$this->seedAgedLines(1, 12, 10);
		$this->assertFalse(
			pfb_log_trim_needed(10, 10, $this->tmpFile, 'log', 50),
			'neither the 1.2x-cap line count nor the 12d/15d-window age head must fire'
		);
	}

	public function testNumericAndAgeMarginFiftyLineExceedsOwnHighWaterFiresEvenIfAgeWithinWindow(): void
	{
		$this->seedAgedLines(0, 0, 17); // 17 lines > 1.5x10=15; head is TODAY (well within any age window)
		$this->assertTrue(
			pfb_log_trim_needed(10, 10, $this->tmpFile, 'log', 50),
			'the line cap exceeding its own 1.5x high-water must fire even with a fresh age head'
		);
	}

	public function testNumericAndAgeMarginFiftyAgeExceedsOwnWindowFiresEvenIfLineWithinHighWater(): void
	{
		$this->seedAgedLines(1, 20, 4); // 5 total lines, well under 15 high-water; head 20d > 15d window
		$this->assertTrue(
			pfb_log_trim_needed(10, 10, $this->tmpFile, 'log', 50),
			'the age head exceeding its own 15-day window must fire even with a small line count'
		);
	}

	// -----------------------------------------------------------------------
	// Mandatory hostile row: an unclamped absurd numeric cap must not crash
	// (the intdiv()-on-a-float TypeError trap this float-math design avoids).
	// -----------------------------------------------------------------------

	public function testAbsurdLogMaxDoesNotCrashAndReturnsFalseForNormalFile(): void
	{
		$this->seedLines(5);
		$result = pfb_log_trim_needed(PHP_INT_MAX, 0, $this->tmpFile, 'log', 50);
		$this->assertFalse($result, 'an absurd cap must never fire for a normal-sized file, and must not throw');
	}

	// -----------------------------------------------------------------------
	// issue #1257 C1: an unopenable path must fail HIGH (guard fires), never
	// silently skip a needed trim.
	// -----------------------------------------------------------------------

	public function testUnopenableLogPathWithLineCapActiveFires(): void
	{
		$missing = $this->tmpFile . '-does-not-exist';
		$this->assertTrue(
			pfb_log_trim_needed(10, 0, $missing, 'log', 0),
			'an unopenable log path with a line cap active must fire the trim guard, never skip it'
		);
	}

	// -----------------------------------------------------------------------
	// issue #1258 hostile rows -- an out-of-range/hostile raw margin must be
	// unconstructible: no warning, no TypeError, resolves via the ONE clamp.
	// -----------------------------------------------------------------------

	/**
	 * PHP_INT_MAX must clamp through the internal pfb_log_age_trim_needed()
	 * call too -- 'nolimit' isolates the age branch so the line-cap branch
	 * never short-circuits the propagation.
	 */
	public function testHostilePhpIntMaxRawMarginPropagatesClampIntoInternalAgeCall(): void
	{
		file_put_contents($this->tmpFile, $this->daysAgo(100) . " x\n");
		$result = $this->assertNoPhpWarning(
			fn () => pfb_log_trim_needed('nolimit', 3650000, $this->tmpFile, 'log', PHP_INT_MAX)
		);
		$this->assertFalse($result, 'PHP_INT_MAX margin must clamp to 1000% inside the internal age call too');
	}

	/**
	 * -5 must resolve to margin=0 (exact high-water=cap), not a literal
	 * negative margin (high_water=9.5) that fires the guard early.
	 */
	public function testHostileNegativeRawMarginResolvesToZeroNotLiteralNegativeMargin(): void
	{
		$this->seedLines(10); // exactly at cap
		$this->assertFalse(
			pfb_log_trim_needed(10, 0, $this->tmpFile, 'log', -5),
			'-5 must resolve to margin=0, not a literal negative margin that lowers the high-water'
		);
	}

	/** #1143 TypeError class: an array raw margin must fall back to 0 (is_scalar guard), never TypeError. */
	public function testHostileArrayRawMarginFallsBackToZeroNotTypeError(): void
	{
		$this->seedLines(12); // over a 10-line cap even at margin=0
		$this->assertTrue(
			pfb_log_trim_needed(10, 0, $this->tmpFile, 'log', ['50']),
			'an array raw margin must fall back to 0, not TypeError'
		);
	}

	public static function hostileOversizedMarginHighWaterRows(): array
	{
		// logmax=10, margin clamps to 1000% -> high_water = 10*11 = 110.
		return [
			'within clamped 110 high-water (109 lines)' => [109, FALSE],
			'beyond clamped 110 high-water (111 lines)'  => [111, TRUE],
		];
	}

	/** A huge-but-numeric string margin must clamp to the SAME 1000% boundary as the literal. */
	#[DataProvider('hostileOversizedMarginHighWaterRows')]
	public function testHostileOversizedStringRawMarginClampsHighWaterToBoundary(int $lineCount, bool $expected): void
	{
		$this->seedLines($lineCount);
		$this->assertSame($expected, pfb_log_trim_needed(10, 0, $this->tmpFile, 'log', '999999999'));
	}
}
