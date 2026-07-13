<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_log_age_trim_needed() -- issue #1052/#1109: probe-before-copy for the
 * age-cap pass, renamed+generalised from pfb_log_age_nolimit_pass_needed
 * (which only ever gated the 'nolimit' branch) to also gate the numeric-cap
 * branch via pfb_log_trim_needed(). $margin_pct widens the cutoff window;
 * margin=0 is byte-identical to the pre-#1109 pfb_log_age_nolimit_pass_needed
 * formula, so every #1052 case is re-pinned here at margin=0.
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
}
