<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-60 §1.8's remaining lower-priority sites -- cosmetic ISO-8601 normalization
 * outside the two genuine wrong-year bugs (DnsblAliasUpdateTimestampFormatTest /
 * ClearSqliteTimestampFormatTest cover those). Each site here already carried a
 * year (or, for the debug filename, has zero external consumer); the changes are
 * pure format polish, verified with a source tripwire (so this oracle goes red the
 * moment the format string drifts again) plus a reproduction of the exact new
 * behaviour.
 */
final class TimestampCosmeticNormalizationTest extends TestCase
{
	private const PFBLOCKERNG_INC    = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';
	private const PFBLOCKERNG_PHP    = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng.php';
	private const INDEX_PHP          = __DIR__ . '/../../src/usr/local/www/pfblockerng/www/index.php';

	private string $savedTz;

	protected function setUp(): void
	{
		require_once __DIR__ . '/UpdatePageLoader.php';
		pfb_test_load_update_page_functions();
		$this->savedTz = date_default_timezone_get();
		date_default_timezone_set('UTC');
	}

	protected function tearDown(): void
	{
		date_default_timezone_set($this->savedTz);
	}

	// -----------------------------------------------------------------------
	// pfblockerng.inc:16486 -- the /tmp debug-snapshot filename ('M_j' -> 'Y-m-d')
	// -----------------------------------------------------------------------

	public function testDebugFilenameSourceUsesFixedWidthFormat(): void
	{
		$source = (string) file_get_contents(self::PFBLOCKERNG_INC);
		$this->assertStringContainsString(
			"\$ts = date('Y-m-d', time());",
			$source,
			'the /tmp debug-snapshot filename format changed -- update this oracle'
		);
		$this->assertStringNotContainsString("date('M_j', time());", $source, 'the OLD variable-width format must be gone');
	}

	/**
	 * The OLD 'M_j' format was variable-width (single-vs-double-digit day, e.g.
	 * 'Mar_4' is 5 chars, 'Mar_14' is 6) -- not lexically sortable across a month.
	 * The NEW 'Y-m-d' is always exactly 10 characters, for ANY day of any month.
	 */
	public function testDebugFilenameNewFormatIsFixedWidthForAnyDay(): void
	{
		$singleDigitDay = date('Y-m-d', mktime(0, 0, 0, 3, 4, 2026));
		$doubleDigitDay = date('Y-m-d', mktime(0, 0, 0, 3, 14, 2026));

		$this->assertSame('2026-03-04', $singleDigitDay);
		$this->assertSame('2026-03-14', $doubleDigitDay);
		$this->assertSame(10, strlen($singleDigitDay), 'single-digit-day filename stamp must be fixed-width');
		$this->assertSame(10, strlen($doubleDigitDay), 'double-digit-day filename stamp must be the SAME width');

		// Red proof (characterization of the OLD bug): the OLD 'M_j' format was NOT
		// fixed-width across single vs double-digit days.
		$oldSingle = date('M_j', mktime(0, 0, 0, 3, 4, 2026));
		$oldDouble = date('M_j', mktime(0, 0, 0, 3, 14, 2026));
		$this->assertNotSame(strlen($oldSingle), strlen($oldDouble), 'sanity: the OLD format really was variable-width');
	}

	// -----------------------------------------------------------------------
	// pfblockerng.php:843 -- MaxMind version file gmdate ('D, j M Y H:i:s T' -> 'Y-m-d H:i:s')
	// -----------------------------------------------------------------------

	public function testMaxmindGmdateSourceUsesIsoFormat(): void
	{
		$source = (string) file_get_contents(self::PFBLOCKERNG_PHP);
		$this->assertStringContainsString(
			"@gmdate('Y-m-d H:i:s', pfb_file_mtime(\$maxmind_cont));",
			$source,
			'the MaxMind version-file gmdate format changed -- update this oracle'
		);
		$this->assertStringNotContainsString("gmdate('D, j M Y H:i:s T'", $source, 'the OLD RFC-2822-ish format must be gone');
	}

	/**
	 * widget.php:524's `grep -o 'Last-.*' maxmind_ver` extracts the WHOLE rest of
	 * the "Last-Modified: ..." line regardless of the date's exact shape -- confirms
	 * the ISO reformat is genuinely display-only, no downstream parser to break.
	 */
	public function testMaxmindWidgetGrepStillCapturesTheWholeIsoLine(): void
	{
		$epoch = mktime(9, 5, 3, 3, 4, 2026);
		$newTds = gmdate('Y-m-d H:i:s', $epoch);
		$this->assertSame('2026-03-04 09:05:03', $newTds);

		$verFile = tempnam(sys_get_temp_dir(), 'pfb_maxmind_ver_');
		$this->assertNotFalse($verFile);
		file_put_contents($verFile, "MaxMind GeoLite2 Date/Time Stamp\nLast-Modified: {$newTds}\n");

		$out = [];
		exec('grep -o ' . escapeshellarg('Last-.*') . ' ' . escapeshellarg($verFile), $out, $retval);
		unlink($verFile);

		$this->assertSame(0, $retval, 'the grep pipeline must exit 0');
		$this->assertSame("Last-Modified: {$newTds}", $out[0] ?? null, 'the widget must still capture the whole ISO-dated line');
	}

	// -----------------------------------------------------------------------
	// pfblockerng_update.php:291-292 -- Schedule Last/Next display (add seconds)
	// -----------------------------------------------------------------------

	/**
	 * Red -> green proof (real function call): a ledger entry with a deliberately
	 * non-zero seconds component (':45') must render those seconds. Pre-fix (the
	 * OLD 'Y-m-d H:i' format) truncated them; post-fix they show.
	 */
	public function testScheduleDisplayIncludesSecondsForBothLastAndNext(): void
	{
		$lastRun = mktime(9, 0, 45, 1, 1, 2025);
		$nextDue = $lastRun + 900; // +15 minutes, still :45s

		$html = pfb_ledger_entry_html(['last_run' => $lastRun, 'next_due' => $nextDue]);

		$this->assertStringContainsString(
			'Last: <strong>2025-01-01 09:00:45</strong>',
			$html,
			"the Schedule 'Last' timestamp must include seconds now; got: {$html}"
		);
		$this->assertStringContainsString(
			'Next: <strong>2025-01-01 09:15:45</strong>',
			$html,
			"the Schedule 'Next' timestamp must include seconds now; got: {$html}"
		);
	}

	/**
	 * Branch coverage: the "never run" (NULL entry) path is untouched by this
	 * phase's change -- still the plain placeholder, no timestamp involved at all.
	 */
	public function testScheduleDisplayNullEntryStillShowsNotYetRun(): void
	{
		$this->assertSame('<em>Not yet run</em>', pfb_ledger_entry_html(null));
	}

	// -----------------------------------------------------------------------
	// www/index.php:101 -- HTTP Expires header, explicitly OUT OF SCOPE (§1.8)
	// -----------------------------------------------------------------------

	/**
	 * Confirms the RFC 7231/2822-mandated Expires header is left byte-for-byte
	 * unchanged -- this phase's ISO sweep deliberately does NOT touch it.
	 */
	public function testExpiresHttpHeaderIsByteForByteUnchanged(): void
	{
		$source = (string) file_get_contents(self::INDEX_PHP);
		$this->assertStringContainsString(
			'header("Expires: Sat, 26 Jul 2014 05:00:00 GMT");',
			$source,
			'www/index.php\'s Expires header changed -- it must stay byte-for-byte (RFC 7231/2822-mandated, out of scope for ADR-60 §1.8)'
		);
	}
}
