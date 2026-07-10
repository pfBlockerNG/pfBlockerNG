<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfblockerng_log.php AJAX 'load' handler line-count guard (issue #1156).
 *
 * `exec("{$pfb['grep']} -c ^ ... 2>&1")` puts a grep error string into
 * $linecnt on failure (removed-file race, unreadable path). PHP 8 then
 * compares that string to an int as strings ($linecnt > $maxcnt can be
 * TRUE for non-numeric text) and a subsequent $linecnt - $maxcnt on a
 * non-numeric string is a fatal TypeError.
 *
 * The file executes top-level code on include (needs a live pfSense
 * session — $pfb, $_REQUEST routing, real file I/O) and cannot be
 * require()d or invoked off-appliance, so this test pins the SOURCE
 * SHAPE of the guard (regex over the real file contents) rather than
 * driving the handler behaviourally; see PfbReflectorGuardTest.php for
 * the sibling technique of testing a top-level www script off-appliance.
 */
final class LogLinecountGuardTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_log.php';
		$src = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_log.php');
		}
		self::$src = $src;
	}

	public function testGrepLineCountExecCallExistsExactlyOnce(): void
	{
		$count = preg_match_all('/\$linecnt\s*=\s*exec\(.*-c\s+\^.*\);/', self::$src);
		$this->assertSame(
			1,
			$count,
			'expected exactly one grep -c line-count exec() call in the AJAX load handler'
		);
	}

	public function testLinecntMaxcntSubtractionStillPresent(): void
	{
		$this->assertMatchesRegularExpression(
			'/\$linecnt\s*-\s*\$maxcnt/',
			self::$src,
			'the tail-window subtraction this guard protects must still exist'
		);
	}

	/**
	 * The red row: on unpatched code this regex does not match (no
	 * is_numeric() guards the comparison), so this assertion FAILS.
	 */
	public function testLinecntComparisonIsNumericGuardedBeforeSubtraction(): void
	{
		$this->assertMatchesRegularExpression(
			'/if\s*\(\s*is_numeric\(\s*\$linecnt\s*\)\s*&&\s*\$linecnt\s*>\s*\$maxcnt\s*\)/',
			self::$src,
			'the $linecnt > $maxcnt comparison gating the subtraction must be is_numeric()-guarded'
		);
	}

	/**
	 * Documentation test pinning the PHP 8 language semantics the guard
	 * exists to work around: a non-numeric string compares numerically
	 * false-true against an int, but the same string minus an int is a
	 * fatal TypeError.
	 */
	public function testGrepErrorStringSemanticsMotivatingTheGuard(): void
	{
		$this->assertTrue(
			'grep: no such file' > 10000,
			'PHP 8 must still compare a non-numeric string > int as TRUE here'
		);

		$this->expectException(TypeError::class);
		(function () {
			return 'grep: no such file' - 10000;
		})();
	}
}
