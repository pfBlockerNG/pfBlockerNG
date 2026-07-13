<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * $networks / $total / $lastline -- the per-ISO "Total Networks" line counts
 * in pfblockerng.php's continent-file rebuild (issue #1261).
 *
 * $networks (line ~1414) is NOT display-only: it is written into a header
 * line that is later re-parsed, and "Total Networks: 0" or "...: NA" trips a
 * placeholder branch that BLANKS the country's IP list (transient read
 * failure treated as "genuinely empty" is silent data loss). $total (line
 * ~1574) only ever renders as "(N)" in a dropdown -- display-only, so its
 * `?? 0` NULL fallback is the safe, correct direction and needs no fix, only
 * a mirror test (house precedent: tests/php/AliasCntGrepCountGuardTest.php).
 *
 * The file carries top-level execution and cannot be require()d
 * off-appliance. The $networks header block is eval-extracted verbatim
 * (PfbReflectorGuardTest.php precedent) into an oracle driven by REAL
 * pfb_count_lines() calls against real fixtures -- a directory path (exists,
 * unreadable as a file -> NULL) and a real empty file (exists, 0 lines) --
 * so the same test file proves red on the pre-fix `?? 0` and green after,
 * with zero mocking of pfb_count_lines() itself. The placeholder-blank
 * condition is likewise eval-extracted, not hardcoded, so a change to that
 * condition is caught too.
 *
 * Feature: a country's IP list is blanked only for a genuinely-zero or
 *          NA network count, never for a count that could not be read
 *
 *   Scenario: pfb_count_lines() read failure (NULL) -> placeholder must NOT fire
 *   Scenario: a genuinely empty ISO file (0)        -> placeholder MUST fire
 */
final class CountryNetworksCountGuardTest extends TestCase
{
	private static string $src;
	private static string $tmpDir;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php';
		$src = file_get_contents($path);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.php');
		}
		self::$src = $src;

		self::$tmpDir = sys_get_temp_dir() . '/pfb_country_networks_' . getmypid();
		@mkdir(self::$tmpDir, 0777, TRUE);

		// Oracle 1: the $iso_file header-building block, anchored on text
		// stable across both the pre-fix `?? 0` and the fixed fallback.
		if (!function_exists('pfb_networks_header_oracle')) {
			if (!preg_match(
				'/(if \(file_exists\(\$iso_file\)\) \{.*?\$iso_header \.= "# Total Networks: \{\$networks\}\\\\n";)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('oracle extraction failed: the $iso_file header block was not found in pfblockerng.php');
			}
			eval(
				'function pfb_networks_header_oracle(string $iso_file): string {'
				. ' $geoip = ["name" => "Testland"]; $geoip_id = ""; $iso = "TL"; $iso_header = "";'
				. $m[1]
				// close the extracted block's own opening "if (file_exists(...)) {"
				. ' } return $iso_header; }'
			);
		}

		// Oracle 2: the placeholder-blank condition itself -- untouched by
		// this fix, pinned so a future change to it is still caught.
		if (!function_exists('pfb_placeholder_branch_fires_oracle')) {
			if (!preg_match(
				'/strpos\(\$line, \'Total Networks: 0\'\) !== FALSE \|\| strpos\(\$line, \'Total Networks: NA\'\) !== FALSE/',
				$src,
				$m2
			)) {
				throw new RuntimeException('oracle extraction failed: the placeholder-blank condition was not found in pfblockerng.php');
			}
			eval('function pfb_placeholder_branch_fires_oracle(string $line): bool { return (' . $m2[0] . '); }');
		}
	}

	public static function tearDownAfterClass(): void
	{
		foreach (glob(self::$tmpDir . '/*') ?: [] as $f) {
			is_dir($f) ? @rmdir($f) : @unlink($f);
		}
		@rmdir(self::$tmpDir);
	}

	private function totalNetworksLine(string $header): string
	{
		$lines = explode("\n", trim($header));
		return end($lines);
	}

	// -----------------------------------------------------------------------
	// Rows 1+2: the point is both together -- a fix that merely disables the
	// placeholder branch would pass row 1 alone without proving anything.
	// -----------------------------------------------------------------------

	public function testReadFailureDoesNotTripZeroNetworksPlaceholder(): void
	{
		// A directory: file_exists() is TRUE, but pfb_count_lines()'s fopen('rb')
		// fails -- a real, unmocked read failure (NULL), not chmod-based (chmod
		// denial tests are meaningless under root; a directory fails everywhere).
		$dir = self::$tmpDir . '/unreadable_dir_v4';
		@mkdir($dir, 0777, TRUE);
		$this->assertNull(pfb_count_lines($dir), 'fixture must reproduce a real pfb_count_lines() read failure');

		$line = $this->totalNetworksLine(pfb_networks_header_oracle($dir));
		$this->assertStringStartsWith('# Total Networks: ', $line, 'header must still carry a Total Networks line on a read failure');
		$this->assertFalse(
			pfb_placeholder_branch_fires_oracle($line),
			"a read failure must not render as '{$line}' -- it must not match the 0/NA placeholder-blank branch and silently empty the country's list"
		);
	}

	public function testGenuinelyEmptyIsoFileStillTripsZeroNetworksPlaceholder(): void
	{
		$empty = self::$tmpDir . '/empty_v4.txt';
		touch($empty);
		$this->assertSame(0, pfb_count_lines($empty), 'fixture must reproduce a real genuinely-empty file');

		$line = $this->totalNetworksLine(pfb_networks_header_oracle($empty));
		$this->assertSame('# Total Networks: 0', $line);
		$this->assertTrue(
			pfb_placeholder_branch_fires_oracle($line),
			'a genuinely empty ISO file must still trip the placeholder-blank branch -- this is the intended behaviour'
		);
	}

	// -----------------------------------------------------------------------
	// Source-inspection: no exec() grep fork survives, and the fallback is
	// never bare `?? 0` again (that shape is exactly the reintroduced bug).
	// -----------------------------------------------------------------------

	public function testNetworksNeverFallsBackToBareZero(): void
	{
		$this->assertDoesNotMatchRegularExpression(
			'/\$networks\s*=\s*pfb_count_lines\(\$iso_file\)\s*\?\?\s*0\s*;/',
			self::$src,
			'$networks must not fall back to a bare 0 on NULL -- that string collides with the placeholder-blank branch (issue #1261)'
		);
	}

	public function testNoExecGrepForkSurvivesForNetworks(): void
	{
		$this->assertDoesNotMatchRegularExpression(
			'/\$networks\s*=\s*exec\(/',
			self::$src,
			'a $networks = exec(...) fork survives -- issue #1261 must replace it with pfb_count_lines()'
		);
	}

	// -----------------------------------------------------------------------
	// Rows 3+4: $total (line ~1574) -- display-only, `?? 0` is correct as-is.
	// -----------------------------------------------------------------------

	public function testTotalAssignedFromPfbCountLinesWithZeroFallback(): void
	{
		$this->assertMatchesRegularExpression(
			'/\$total\s*=\s*pfb_count_lines\([^;]*\)\s*\?\?\s*0\s*;/',
			self::$src,
			'$total must be assigned from pfb_count_lines(...) ?? 0 (display-only, issue #1261)'
		);
	}

	public function testNoExecGrepForkSurvivesForTotal(): void
	{
		$this->assertDoesNotMatchRegularExpression(
			'/\$total\s*=\s*exec\(/',
			self::$src,
			'a $total = exec(...) fork survives -- issue #1261 must replace it with pfb_count_lines()'
		);
	}

	// -----------------------------------------------------------------------
	// Rows 5+6: $lastline (line ~1514) -- the EOF-flush trigger
	// (`$linenum == $lastline`). `?? 0` preserves the exec()-era `?: 0`: a
	// failed count yields 0, which $linenum (starts at 1) can never equal, so
	// the flush stays unreachable -- and the fopen() of the same file fails
	// too, so the loop never runs.
	// -----------------------------------------------------------------------

	public function testLastlineAssignedFromPfbCountLinesWithZeroFallback(): void
	{
		$this->assertMatchesRegularExpression(
			'/\$lastline\s*=\s*pfb_count_lines\(\$file\)\s*\?\?\s*0\s*;/',
			self::$src,
			'$lastline must be assigned from pfb_count_lines($file) ?? 0 (EOF-flush trigger, issue #1261)'
		);
	}

	public function testNoExecGrepForkSurvivesForLastline(): void
	{
		$this->assertDoesNotMatchRegularExpression(
			'/\$lastline\s*=\s*exec\(/',
			self::$src,
			'a $lastline = exec(...) fork survives -- issue #1261 must replace it with pfb_count_lines()'
		);
	}

	/** A real, unmocked read failure (a directory) must fall back to 0, never
	 *  NULL/error text reaching the `$linenum == $lastline` comparison. */
	public function testLastlineReadFailureFallsBackToZero(): void
	{
		$dir = self::$tmpDir . '/unreadable_dir_lastline';
		@mkdir($dir, 0777, TRUE);
		$this->assertNull(pfb_count_lines($dir), 'fixture must reproduce a real pfb_count_lines() read failure');

		$lastline = pfb_count_lines($dir) ?? 0;
		$this->assertSame(0, $lastline, 'a failed count must fall back to 0 (the exec()-era behaviour): the EOF flush stays unreachable');
	}

	public static function totalRenderRows(): array
	{
		return [
			'NULL count (pfb_count_lines() read failure)' => [NULL, '(0)'],
			'happy path count'                             => [5, '(5)'],
		];
	}

	/** Mirror of the coptions dropdown render: "{$country} {$isocode} ({$total})". */
	#[DataProvider('totalRenderRows')]
	public function testTotalRendersAsParenthesisedCount(?int $pfbCountLinesResult, string $expectRendered): void
	{
		$total = $pfbCountLinesResult ?? 0;
		$this->assertSame($expectRendered, "({$total})");
	}
}
