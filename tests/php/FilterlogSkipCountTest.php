<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_filterlog_skip_count() -- the pure "lines to skip on daemon
 * (re)start" derivation (issue #713, bug 14; issue #1261: input is now
 * pfb_count_lines()'s ?int, not exec()'s raw string).
 *
 * pfb_count_lines() returns NULL when it cannot read filter.log (e.g. a
 * TOCTOU race between the caller's file_exists() guard and the read). NULL
 * must skip nothing -- the daemon reprocesses the whole log rather than
 * silently dropping lines it never actually parsed.
 *
 * Scenario A: a normal numeric count -> count - 1
 * Scenario B: a zero count -> 0 (never negative)
 * Scenario C: NULL (pfb_count_lines() read failure) -> 0, no exception
 */
#[CoversFunction('pfb_filterlog_skip_count')]
final class FilterlogSkipCountTest extends TestCase
{
	// ---------- Scenario A — normal numeric count ----------

	public function testNumericCount_ReturnsCountMinusOne(): void
	{
		// Given: pfb_count_lines() read 1234 matching lines.
		$count = 1234;

		// When
		$skip = pfb_filterlog_skip_count($count);

		// Then
		$this->assertSame(1233, $skip,
			"expected: 1233 (1234 - 1);\nactual: {$skip}");
	}

	// ---------- Scenario B — zero count never goes negative ----------

	public function testZeroCount_ReturnsZeroNotNegative(): void
	{
		// Given
		$count = 0;

		// When
		$skip = pfb_filterlog_skip_count($count);

		// Then: max(0 - 1, 0) = 0, never -1.
		$this->assertSame(0, $skip,
			"expected: 0 (clamped, never negative);\nactual: {$skip}");
	}

	// ---------- Scenario C — the regression: a read failure must not throw ----------

	/**
	 * The regression this bug fixes: when filter.log is momentarily absent,
	 * pfb_count_lines() returns NULL. The old string-typed signature could
	 * only represent that as a magic string (or, called with NULL under
	 * strict_types, a TypeError) -- this must return 0 with no exception.
	 */
	public function testNullCount_ReturnsZeroWithoutThrowing(): void
	{
		// Given: pfb_count_lines('/var/log/filter.log') could not read the file.
		$count = NULL;

		// When / Then: must not throw.
		$skip = pfb_filterlog_skip_count($count);

		$this->assertSame(0, $skip,
			"expected: 0, and no TypeError, for a NULL (unreadable file) count;\n"
			. "actual: {$skip}");
	}
}
