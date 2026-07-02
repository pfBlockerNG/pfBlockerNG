<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_filterlog_skip_count() — the pure parser for
 * `grep -c ^ /var/log/filter.log`'s raw exec() output (issue #713, bug 14).
 *
 * The old call site computed `max(exec(...) - 1, 0)` with no cast: when
 * filter.log is momentarily absent (log rotation racing the daemon restart),
 * the merged 2>&1 output is a grep error STRING, and PHP 8 throws
 * "Unsupported operand types: string - int" out of the daemon -- a crash loop.
 * (int) casting the exec() output first makes any non-numeric string coerce to
 * 0 instead of throwing.
 *
 * Scenario A: a normal numeric count -> count - 1
 * Scenario B: a zero count -> 0 (never negative)
 * Scenario C: empty output -> 0
 * Scenario D: the grep error string (filter.log absent) -> 0, no exception
 */
#[CoversFunction('pfb_filterlog_skip_count')]
final class FilterlogSkipCountTest extends TestCase
{
	// ---------- Scenario A — normal numeric grep count ----------

	public function testNumericCount_ReturnsCountMinusOne(): void
	{
		// Given: grep -c reports 1234 matching lines (includes the trailing
		// blank-line artifact the call site's "-1" already accounted for).
		$grepOutput = '1234';

		// When
		$skip = pfb_filterlog_skip_count($grepOutput);

		// Then
		$this->assertSame(1233, $skip,
			"expected: 1233 (1234 - 1);\nactual: {$skip}");
	}

	// ---------- Scenario B — zero count never goes negative ----------

	public function testZeroCount_ReturnsZeroNotNegative(): void
	{
		// Given
		$grepOutput = '0';

		// When
		$skip = pfb_filterlog_skip_count($grepOutput);

		// Then: max(0 - 1, 0) = 0, never -1.
		$this->assertSame(0, $skip,
			"expected: 0 (clamped, never negative);\nactual: {$skip}");
	}

	// ---------- Scenario C — empty output ----------

	public function testEmptyOutput_ReturnsZero(): void
	{
		// Given
		$grepOutput = '';

		// When
		$skip = pfb_filterlog_skip_count($grepOutput);

		// Then
		$this->assertSame(0, $skip,
			"expected: 0 (empty output);\nactual: {$skip}");
	}

	// ---------- Scenario D — the regression: grep's error string must not throw ----------

	/**
	 * The regression this bug fixes: when filter.log is momentarily absent,
	 * exec()'s merged 2>&1 output is grep's error text, not a number. The old
	 * un-cast `$output - 1` threw a PHP 8 TypeError for this exact input,
	 * crash-looping the daemon. This must return 0 with no exception.
	 */
	public function testGrepErrorString_ReturnsZeroWithoutThrowing(): void
	{
		// Given: filter.log does not exist, so grep -c wrote its error to stderr,
		// merged into $output by the caller's 2>&1.
		$grepOutput = 'grep: /var/log/filter.log: No such file or directory';

		// When / Then: must not throw (the old bare `$output - 1` did).
		$skip = pfb_filterlog_skip_count($grepOutput);

		$this->assertSame(0, $skip,
			"expected: 0, and no TypeError, for a non-numeric grep error string;\n"
			. "actual: {$skip}");
	}
}
