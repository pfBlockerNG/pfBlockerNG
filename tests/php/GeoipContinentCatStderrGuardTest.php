<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1299: the continent-file ISO-append `exec("cat ... 2>&1")` in
 * pfblockerng.php's pfblockerng_uc_countries() (line ~1423) merges cat's
 * stderr into the continent `.txt` data file. A cat failure (any cause --
 * a TOCTOU race, permission denial, etc.) writes stderr text (e.g.
 * "cat: <path>: Is a directory") into the file as if it were feed data;
 * pfblockerng_get_countries()'s reparse (`elseif (!str_starts_with($line,
 * '#'))`, line ~1572) then treats that line as real network data and
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

		// Oracle: the ISO-append exec() call itself, extracted verbatim so it
		// tracks whichever form is actually in source -- with or without the
		// trailing " 2>&1" -- proving red pre-fix, green post-fix.
		if (!function_exists('pfb_cat_append_oracle')) {
			if (!preg_match(
				'/exec\("\{\$pfb\[\'cat\'\]\} \{\$iso_file_esc\} >> \{\$pfb_file_esc\}( 2>&1)?"\);/',
				$src,
				$m
			)) {
				throw new RuntimeException('oracle extraction failed: the cat-append exec() call was not found in pfblockerng.php');
			}
			eval(
				'function pfb_cat_append_oracle(string $iso_file, string $pfb_file): void {'
				. ' $pfb = ["cat" => "/bin/cat"];'
				. ' $iso_file_esc = escapeshellarg($iso_file);'
				. ' $pfb_file_esc = escapeshellarg($pfb_file);'
				. ' ' . $m[0]
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
		touch($pfbFile);
		$this->assertSame('', file_get_contents($pfbFile), 'fixture must start empty');

		pfb_cat_append_oracle($isoDir, $pfbFile);

		$content = file_get_contents($pfbFile);
		$this->assertNotFalse($content, 'destination file must remain readable after the exec() call');
		$this->assertSame(
			'',
			$content,
			"issue #1299: cat's stderr leaked into the continent data file -- expected '' but got " . var_export($content, TRUE)
		);
	}

	public function testCatAppendExecDoesNotMergeStderrIntoDataFile(): void
	{
		// Assert against the single extracted exec() line, not the whole
		// source string -- keeps the failure diff readable (the whole-source
		// form dumps ~2700 lines on failure).
		if (!preg_match(
			'/exec\("\{\$pfb\[\'cat\'\]\} \{\$iso_file_esc\} >> \{\$pfb_file_esc\}( 2>&1)?"\);/',
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
}
