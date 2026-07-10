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
 * non-numeric string is a fatal TypeError. Silently skipping the cap
 * would be worse than the fatal: the fgets() loop would stream the
 * WHOLE file unbounded, defeating the 10k-line cap exactly when grep
 * cannot be trusted — so a non-numeric count must answer with the
 * handler's own '|2|' error convention and stop.
 *
 * The file executes top-level code on include (needs a live pfSense
 * session — $pfb, $_REQUEST routing, real file I/O) and cannot be
 * require()d off-appliance. Per the PfbReflectorGuardTest.php eval-oracle
 * precedent, the guard + cap block is extracted verbatim from the real
 * source into a callable oracle (exec output injected as the argument;
 * print captured; exit becomes an early return), so the branch logic is
 * exercised behaviourally, not just shape-matched.
 *
 * Feature: a non-numeric grep count fails loudly instead of fatal or
 *          unbounded streaming; numeric counts keep the 10k tail window
 *
 *   Scenario: numeric under/at the cap  -> no window, no error
 *   Scenario: numeric over the cap      -> window armed, skip count exact
 *   Scenario: non-numeric (grep error)  -> '|2|' error response, no window,
 *             no TypeError
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

		// Oracle: the block from the non-numeric guard through the cap window,
		// exactly as committed. print -> capture, exit -> early return, gettext
		// stripped (plain PHP string stays). If extraction fails the guard block
		// changed shape — fail loudly rather than skip.
		if (!function_exists('pfb_log_linecount_oracle')
			&& preg_match('/(if \(!is_numeric\(\$linecnt\)\).*?Displaying last.*?\n\t{3}\})\n/s', $src, $m)) {
			$block = strtr($m[1], [
				'print ('  => '$out .= (',
				'exit;'    => 'return array($out, NULL, NULL, NULL);',
				'gettext(' => '(',
			]);
			eval(
				'function pfb_log_linecount_oracle($linecnt) {'
				. ' $out = \'\'; $maxcnt = 0; $validate = NULL; $line_limit = NULL; $skipcnt = NULL;'
				. $block
				. ' return array($out, $validate, $skipcnt, $line_limit); }'
			);
		}
	}

	private function oracle(string $linecnt): array
	{
		if (!function_exists('pfb_log_linecount_oracle')) {
			$this->fail('oracle extraction failed: the is_numeric guard block was not found in pfblockerng_log.php — see testNonNumericGuardAnswersWithErrorConvention\'s source assertion');
		}
		return pfb_log_linecount_oracle($linecnt);
	}

	// --------------------------------------------------------------------------
	// Source-shape vacuity guards (the oracle depends on these constructs)
	// --------------------------------------------------------------------------

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
	 * The red row for the loud-failure behaviour: on code that silently
	 * skips the cap for a non-numeric count, this shape is absent.
	 */
	public function testNonNumericGuardAnswersWithErrorConvention(): void
	{
		$this->assertMatchesRegularExpression(
			'/if\s*\(\s*!is_numeric\(\s*\$linecnt\s*\)\s*\)\s*\{\s*\n\s*print \("\|2\|"/',
			self::$src,
			'a non-numeric $linecnt must answer with the handler\'s |2| error convention before any cap math'
		);
	}

	// --------------------------------------------------------------------------
	// Behavioural rows through the extracted oracle
	// --------------------------------------------------------------------------

	public function testNumericUnderCapKeepsFullView(): void
	{
		[$out, $validate, $skipcnt, $line_limit] = $this->oracle('500');

		$this->assertSame('', $out, 'no error response expected for a numeric under-cap count');
		$this->assertFalse($validate, 'the tail window must stay disarmed under the cap');
		$this->assertNull($skipcnt, 'no skip count expected under the cap');
		$this->assertSame('', $line_limit, 'no truncation notice expected under the cap');
	}

	public function testNumericAtCapBoundaryKeepsFullView(): void
	{
		// Pins the comparison operator: exactly-at-cap is NOT over the cap.
		[$out, $validate] = $this->oracle('10000');

		$this->assertSame('', $out, 'no error response expected at the cap boundary');
		$this->assertFalse($validate, 'exactly-at-cap must not arm the tail window (> not >=)');
	}

	public function testNumericOverCapArmsTailWindowWithExactSkipCount(): void
	{
		[$out, $validate, $skipcnt, $line_limit] = $this->oracle('10500');

		$this->assertSame('', $out, 'no error response expected for a numeric over-cap count');
		$this->assertTrue($validate, 'an over-cap count must arm the tail window');
		$this->assertSame(500, $skipcnt, 'skip count must be linecnt - maxcnt');
		$this->assertStringContainsString(
			'Displaying last 10000 lines only',
			(string) $line_limit,
			'the truncation notice must name the cap'
		);
	}

	public function testNonNumericGrepErrorFailsLoudlyWithoutTypeErrorOrStreaming(): void
	{
		try {
			[$out, $validate] = $this->oracle('grep: no such file or directory');
		} catch (\TypeError $e) {
			$this->fail('a non-numeric grep count must not reach the subtraction: ' . $e->getMessage());
		}

		$this->assertStringStartsWith(
			'|2|',
			$out,
			'a non-numeric grep count must produce the |2| error response, got ' . var_export($out, true)
		);
		$this->assertNull(
			$validate,
			'the handler must stop at the error response — reaching the cap logic means the unbounded-stream path is open'
		);
	}

	/**
	 * Documentation test pinning the PHP 8 language semantics the guard
	 * defends against — NOT a substitute for the rows above.
	 */
	public function testGrepErrorStringSemanticsMotivatingTheGuard(): void
	{
		$this->assertTrue(
			'grep: no such file' > 10000,
			'PHP 8 compares int vs non-numeric string as strings — the old comparison let error text through'
		);

		$this->expectException(\TypeError::class);
		(static fn () => 'grep: no such file' - 10000)();
	}
}
