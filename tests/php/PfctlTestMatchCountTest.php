<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_pfctl_test_match_count() — the pure parser for `pfctl -t <table>
 * -T test <ip> 2>&1` output (issue #713, bug 9).
 *
 * pfctl prints "N/1 addresses match." on a normal run. Because the call sites
 * merge stderr via 2>&1, a MISSING table instead prints an error string such as
 * "pfctl: Table does not exist." The old call sites took
 * `substr($output, 0, 1) > 0` as their truthiness test: PHP 8's string/int
 * comparison rules turn a leading letter ('p' in "pfctl: ...") into a match
 * ('p' > '0' as a string compare), so an absent table was falsely reported as a
 * match — a false IDS-block / false "states killed" (issue #713).
 *
 * Scenario A: a real match ("1/1 addresses match.") -> 1
 * Scenario B: no match ("0/1 addresses match.") -> 0
 * Scenario C: table absent (pfctl error string via 2>&1) -> 0, NOT a false match
 * Scenario D: empty output -> 0
 */
#[CoversFunction('pfb_pfctl_test_match_count')]
final class PfctlTestMatchCountTest extends TestCase
{
	// ---------- Scenario A — a real match ----------

	public function testMatchOutput_ReturnsOne(): void
	{
		// Given: pfctl reports one address matching the table.
		$output = '1/1 addresses match.';

		// When
		$count = pfb_pfctl_test_match_count($output);

		// Then
		$this->assertSame(1, $count,
			"expected: 1 (a real match);\nactual: {$count}");
	}

	// ---------- Scenario B — no match ----------

	public function testNoMatchOutput_ReturnsZero(): void
	{
		// Given: pfctl reports the address is not in the table.
		$output = '0/1 addresses match.';

		// When
		$count = pfb_pfctl_test_match_count($output);

		// Then
		$this->assertSame(0, $count,
			"expected: 0 (no match);\nactual: {$count}");
	}

	// ---------- Scenario C — absent table must NOT read as a match ----------

	/**
	 * The regression this bug fixes: an absent table's pfctl error text (merged
	 * via 2>&1) must parse to 0, never a positive match count.
	 */
	public function testTableDoesNotExist_ReturnsZeroNotAFalseMatch(): void
	{
		// Given: the table does not exist, so pfctl writes an error to stderr,
		// merged into $output by the caller's 2>&1.
		$output = 'pfctl: Table does not exist.';

		// When
		$count = pfb_pfctl_test_match_count($output);

		// Then: 0 -- a missing table must never be treated as a positive match.
		$this->assertSame(0, $count,
			"expected: 0 (absent table is not a match);\nactual: {$count}");
	}

	// ---------- Scenario D — empty output ----------

	public function testEmptyOutput_ReturnsZero(): void
	{
		// Given: exec() returned no output at all.
		$output = '';

		// When
		$count = pfb_pfctl_test_match_count($output);

		// Then
		$this->assertSame(0, $count,
			"expected: 0 (empty output);\nactual: {$count}");
	}
}
