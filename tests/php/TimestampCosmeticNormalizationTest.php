<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-60 §1.8's remaining lower-priority sites -- cosmetic ISO-8601 normalization
 * outside the two genuine wrong-year bugs (DnsblAliasUpdateTimestampFormatTest /
 * ClearSqliteTimestampFormatTest cover those). Each site here already carried a
 * year; the changes are
 * pure format polish. Top-level producers have no off-appliance callable seam, so
 * retained pins use php_strip_whitespace() and never production comments.
 */
final class TimestampCosmeticNormalizationTest extends TestCase
{
	private const PFBLOCKERNG_PHP    = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng.php';

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

	private function codeSource(string $path): string
	{
		$source = php_strip_whitespace($path);
		$this->assertNotSame('', $source, "could not read comment-free source: {$path}");
		return $source;
	}

	// -----------------------------------------------------------------------
	// pfblockerng.php:843 -- MaxMind version file gmdate ('D, j M Y H:i:s T' -> 'Y-m-d H:i:s')
	// -----------------------------------------------------------------------

	public function testMaxmindGmdateSourceUsesIsoFormat(): void
	{
		$source = $this->codeSource(self::PFBLOCKERNG_PHP);
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

	// -----------------------------------------------------------------------
	// www/index.php:101 -- HTTP Expires header, explicitly OUT OF SCOPE (§1.8)
	// -----------------------------------------------------------------------

}
