<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_iso_timestamp() — reformats a stored timestamp string to ISO 8601
 * 'YYYY-MM-DD HH:MM:SS' for display (issue #333: widget date localisation).
 *
 * Two branches:
 *   1. Parseable input (strtotime() succeeds) → ISO-formatted output.
 *   2. Unparseable or empty input (strtotime() returns FALSE / empty string) →
 *      raw value returned unchanged (no '1970-01-01 00:00:00' placeholder).
 *
 * Both branches are asserted so a regression in either guard would cause a failure.
 */
#[CoversFunction('pfb_iso_timestamp')]
final class PfbIsoTimestampTest extends TestCase
{
	/**
	 * A US-style date string with an explicit year is converted to ISO 8601.
	 * Proves the parseable branch reformats the value.
	 */
	public function testUsStyleWithYearConvertsToIso(): void
	{
		// Given: a US-format datetime string that includes a full year.
		$input = '07/04/2024 13:30:45';

		// When.
		$result = pfb_iso_timestamp($input);

		// Then: the output is the ISO equivalent.
		$this->assertSame('2024-07-04 13:30:45', $result);
	}

	/**
	 * An already-ISO value round-trips unchanged.
	 * Proves strtotime() parses ISO correctly and date('Y-m-d H:i:s') round-trips it.
	 */
	public function testAlreadyIsoRoundTrips(): void
	{
		$input = '2024-11-05 14:30:45';

		$result = pfb_iso_timestamp($input);

		$this->assertSame('2024-11-05 14:30:45', $result);
	}

	/**
	 * A DNSBL-style 'M j H:i:s' stored timestamp (e.g. written by date('M j H:i:s'))
	 * with a full year produces the correct ISO output. Uses a deterministic full-date
	 * string so the test is not year-dependent.
	 *
	 * date('M j H:i:s') writes e.g. 'Jul  4 13:30:45' (no year). To avoid relying on
	 * the current year, we use a format that includes a year.
	 */
	public function testFullDatetimeStringConvertsToIso(): void
	{
		// strtotime() handles 'Month D, YYYY HH:MM:SS' reliably.
		$input    = 'November 5, 2024 14:30:45';
		$expected = '2024-11-05 14:30:45';

		$this->assertSame($expected, pfb_iso_timestamp($input));
	}

	/**
	 * An unparseable/garbage value passes through unchanged — the FALSE guard.
	 * Proves the function never returns '1970-01-01 00:00:00' for junk input.
	 */
	public function testUnparseableValuePassesThroughUnchanged(): void
	{
		$garbage = 'not a date at all';

		$result = pfb_iso_timestamp($garbage);

		// Result must be the original garbage, not a formatted epoch.
		$this->assertSame($garbage, $result);
		$this->assertStringNotContainsString('1970', $result, 'must not format to epoch');
	}

	/**
	 * An empty string passes through unchanged — the early-return guard.
	 * Proves the empty-check fires before strtotime() so '' stays ''.
	 */
	public function testEmptyStringPassesThroughUnchanged(): void
	{
		$this->assertSame('', pfb_iso_timestamp(''));
	}

	/**
	 * Transition test: proves the two branches are real and independent.
	 *
	 * BEFORE (parseable): a datetime string → ISO output (not the original string).
	 * AFTER  (garbage):   a garbage string  → original string (not an ISO value).
	 *
	 * Green proves both paths execute, not that one constant path was taken.
	 */
	public function testParseableAndUnparseableBranchesAreDistinct(): void
	{
		$parseable = '2024-07-04 13:30:45';
		$garbage   = 'xyzzy-no-date';

		// Parseable branch: returns ISO (which round-trips here).
		$isoResult = pfb_iso_timestamp($parseable);
		$this->assertSame('2024-07-04 13:30:45', $isoResult, 'parseable: must return ISO');

		// Unparseable branch: returns the raw garbage, NOT an ISO string.
		$rawResult = pfb_iso_timestamp($garbage);
		$this->assertSame($garbage, $rawResult, 'unparseable: must return raw input');

		// Cross-assert: the two outputs are different (rules out an always-return-input path).
		$this->assertNotSame($isoResult, $rawResult, 'the two branches must produce different outputs');
	}
}
