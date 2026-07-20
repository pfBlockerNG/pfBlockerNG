<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1299: the continent-file ISO-append `exec("cat ... 2>&1")` in
 * pfblockerng.php's pfblockerng_uc_countries() (line ~1423) merges cat's
 * stderr into the continent `.txt` data file. A cat failure (any cause --
 * a TOCTOU race, permission denial, etc.) writes stderr text (e.g.
 * "cat: <path>: Is a directory") into the file as if it were feed data;
 * the package-owned pfblockerng_get_countries() reparse
 * (`elseif (!str_starts_with($line, '#'))`) then treats that line as real network data and
 * persists it verbatim. This is the corruption sibling of issue
 * #1261/PR #1268, which fixed only the "blanking" half (`?? 0` ->
 * `?? 'ERROR'`), not this half.
 *
 * The file carries top-level execution and cannot be require()d
 * off-appliance (house precedent: CountryNetworksCountGuardTest.php). The
 * exec() call is eval-extracted verbatim from the real source into an
 * oracle driven by the REAL /bin/cat binary against a real fixture -- a
 * directory used as $iso_file (file_exists() TRUE, cat fails) -- so the
 * same test proves red on the pre-fix `2>&1` and green after its removal,
 * with zero mocking of exec()/cat itself.
 *
 * Feature: a cat failure while building the continent file must never
 *          write bogus stderr text into that data file
 *
 *   Scenario: $iso_file is a directory (file_exists() TRUE, cat fails)
 *             -> the continent file must stay untouched by the append
 */
final class GeoipContinentCatStderrGuardTest extends TestCase
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

		self::$tmpDir = sys_get_temp_dir() . '/pfb_geoip_cat_stderr_' . getmypid();
		if (!@mkdir(self::$tmpDir, 0777, TRUE) && !is_dir(self::$tmpDir)) {
			throw new RuntimeException('test bootstrap: failed to create tmp dir ' . self::$tmpDir);
		}

		// Oracle: the ISO-append status-handling block, extracted verbatim so
		// the real command and its failure cleanup execute in this test.
		if (!function_exists('pfb_cat_append_oracle')) {
			if (!preg_match(
				'/(?:\$cat_output\s*=\s*array\(\);\s*\$cat_status\s*=\s*0;\s*)?'
				. 'exec\("\{\$pfb\[\'cat\'\]\} \{\$iso_file_esc\} >> \{\$pfb_file_esc\}( 2>&1)?"'
				. '(?:,\s*\$cat_output,\s*\$cat_status)?\);'
				. '(?:\s*if \(\$cat_status !== 0\) \{.*?return FALSE;\s*\})?/s',
				$src,
				$m
			)) {
				throw new RuntimeException('oracle extraction failed: the cat-append status block was not found in pfblockerng.php');
			}
			$block = str_replace(
				['pfb_logger(', 'rmdir_recursive('],
				['pfb_geoip_test_logger(', 'pfb_geoip_test_rmdir_recursive('],
				$m[0]
			);
			eval(
				'function pfb_cat_append_oracle('
				. 'string $iso_file, string $pfb_file, string $cat = "/bin/cat", string $iso = "US", string $type = "4"'
				. '): bool {'
				. ' $pfb = ["cat" => $cat, "ccdir_tmp" => dirname($pfb_file) . "/build_tmp"];'
				. ' $iso_file_esc = escapeshellarg($iso_file);'
				. ' $pfb_file_esc = escapeshellarg($pfb_file);'
				. ' ' . $block
				. ' return TRUE;'
				. ' }'
			);
		}
	}

	public static function tearDownAfterClass(): void
	{
		foreach (glob(self::$tmpDir . '/*') ?: [] as $f) {
			is_dir($f) ? @rmdir($f) : @unlink($f);
		}
		@rmdir(self::$tmpDir);
	}

	private function makeCatFixture(string $name, string $body): string
	{
		$path = self::$tmpDir . '/' . $name;
		file_put_contents($path, "#!/bin/sh\n{$body}");
		chmod($path, 0755);
		return $path;
	}

	public function testPartialStdoutFailureIsDiscardedAndReported(): void
	{
		$cat = $this->makeCatFixture('partial-cat', "printf 'partial-network\\n'\nexit 7\n");
		$isoFile = self::$tmpDir . '/US_v4.txt';
		$pfbFile = self::$tmpDir . '/continent_partial_v4.txt';
		$buildTmp = self::$tmpDir . '/build_tmp';
		pfb_geoip_test_rmdir_recursive($buildTmp);
		mkdir($buildTmp);
		file_put_contents($buildTmp . '/working', 'temporary');
		file_put_contents($isoFile, "ignored\n");
		file_put_contents($pfbFile, "# header\n");
		$GLOBALS['pfb_geoip_test_logs'] = [];

		$result = pfb_cat_append_oracle($isoFile, $pfbFile, $cat, 'US', '4');

		$this->assertFalse($result);
		$this->assertFileDoesNotExist($pfbFile, 'failed append must discard header plus partial stdout');
		$this->assertDirectoryDoesNotExist($buildTmp, 'failed build must clean temporary state');
		$this->assertSame([["\n Failed to append ISO data [ US IPv4 ] (cat status 7)\n", 4]], $GLOBALS['pfb_geoip_test_logs']);
	}

	public function testFailureWithoutStdoutIsDiscardedAndReported(): void
	{
		$cat = $this->makeCatFixture('silent-cat', "exit 9\n");
		$isoFile = self::$tmpDir . '/CA_v6.txt';
		$pfbFile = self::$tmpDir . '/continent_silent_v6.txt';
		$buildTmp = self::$tmpDir . '/build_tmp';
		pfb_geoip_test_rmdir_recursive($buildTmp);
		mkdir($buildTmp);
		file_put_contents($isoFile, "ignored\n");
		file_put_contents($pfbFile, "# header\n");
		$GLOBALS['pfb_geoip_test_logs'] = [];

		$result = pfb_cat_append_oracle($isoFile, $pfbFile, $cat, 'CA', '6');

		$this->assertFalse($result);
		$this->assertFileDoesNotExist($pfbFile);
		$this->assertDirectoryDoesNotExist($buildTmp);
		$this->assertSame([["\n Failed to append ISO data [ CA IPv6 ] (cat status 9)\n", 4]], $GLOBALS['pfb_geoip_test_logs']);
	}

	public function testCatFailureOnUnreadableIsoDoesNotCorruptContinentFile(): void
	{
		// A directory: file_exists() is TRUE (passes the guard at line 1412
		// unchanged), but cat fails to read it -- a real, unmocked failure,
		// not chmod-based (chmod denial is meaningless under root; a
		// directory fails identically root or not).
		$isoDir = self::$tmpDir . '/unreadable_iso_v4';
		@mkdir($isoDir, 0777, TRUE);
		$this->assertTrue(is_dir($isoDir), 'fixture must be a real directory to reproduce "cat: ...: Is a directory"');
		$this->assertTrue(file_exists($isoDir), 'fixture must pass the file_exists() guard at line 1412 unchanged');

		$pfbFile = self::$tmpDir . '/continent_v4.txt';
		file_put_contents($pfbFile, "# partial continent output\n");

		$result = pfb_cat_append_oracle($isoDir, $pfbFile);

		$this->assertFalse($result, 'cat failure must be reported to the conversion caller');
		$this->assertFileDoesNotExist($pfbFile, 'failed conversion must discard partial continent output');
	}

	public function testCatAppendExecDoesNotMergeStderrIntoDataFile(): void
	{
		// Assert against the single extracted exec() line, not the whole
		// source string -- keeps the failure diff readable (the whole-source
		// form dumps ~2700 lines on failure).
		if (!preg_match(
			'/exec\("\{\$pfb\[\'cat\'\]\} \{\$iso_file_esc\} >> \{\$pfb_file_esc\}( 2>&1)?"'
			. '(?:,\s*\$cat_output,\s*\$cat_status)?\);/',
			self::$src,
			$m
		)) {
			$this->fail('the cat-append exec() call was not found in pfblockerng.php');
		}
		$this->assertStringNotContainsString(
			'2>&1',
			$m[0],
			"issue #1299: the continent-file cat append must not redirect cat's stderr (2>&1) into the data file -- got: {$m[0]}"
		);
	}

	/** @return array<string, array{string}> */
	public static function ipVersionProvider(): array
	{
		return [
			'IPv4' => ['v4'],
			'IPv6' => ['v6'],
		];
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('ipVersionProvider')]
	public function testCatSuccessAppendsNetworksAndReportsTrue(string $type): void
	{
		$isoFile = self::$tmpDir . "/US_{$type}.txt";
		$pfbFile = self::$tmpDir . "/continent_{$type}_success.txt";
		file_put_contents($isoFile, "network-{$type}\n");
		file_put_contents($pfbFile, "# header {$type}\n");

		$this->assertTrue(pfb_cat_append_oracle($isoFile, $pfbFile));
		$this->assertSame("# header {$type}\nnetwork-{$type}\n", file_get_contents($pfbFile));
	}

	public function testBuilderReportsSuccessAfterAllContinentRows(): void
	{
		$this->assertMatchesRegularExpression(
			'/rmdir_recursive\("\{\$pfb\[\'ccdir_tmp\'\]\}"\);\s*return TRUE;\s*}/',
			self::$src,
			'pfblockerng_uc_countries() must report successful completion to paired callers'
		);
	}

	public function testDcAndDccGateCountryGenerationOnConversionSuccess(): void
	{
		$this->assertMatchesRegularExpression(
			'/case \'dc\':.*?case \'dcc\':.*?if \(pfblockerng_uc_countries\(\)\) \{\s*pfblockerng_get_countries\(\);\s*}/s',
			self::$src
		);
	}

	public function testUgcGatesCountryGenerationOnConversionSuccess(): void
	{
		$this->assertMatchesRegularExpression(
			'/case \'ugc\':\s*if \(pfblockerng_uc_countries\(\)\) \{\s*pfblockerng_get_countries\(\);\s*}/s',
			self::$src
		);
	}

	public function testStandaloneUcAndGcDispatchRemainIndependent(): void
	{
		$this->assertMatchesRegularExpression(
			'/case \'uc\':.*?pfblockerng_uc_countries\(\);\s*break;\s*case \'gc\':.*?pfblockerng_get_countries\(\);\s*break;/s',
			self::$src
		);
	}

	public function testCountryBuildUsesSameAppendGuardForIpv4AndIpv6(): void
	{
		$this->assertMatchesRegularExpression(
			'/foreach \(array\(\'4\', \'6\'\) as \$type\).*?' . preg_quote('exec("{$pfb[\'cat\']} {$iso_file_esc} >> {$pfb_file_esc}"', '/') . '/s',
			self::$src
		);
	}
}

function pfb_geoip_test_logger(string $message, int $level): void
{
	$GLOBALS['pfb_geoip_test_logs'][] = [$message, $level];
}

function pfb_geoip_test_rmdir_recursive(string $path): void
{
	foreach (glob($path . '/*') ?: [] as $entry) {
		is_dir($entry) ? pfb_geoip_test_rmdir_recursive($entry) : unlink($entry);
	}
	@rmdir($path);
}
