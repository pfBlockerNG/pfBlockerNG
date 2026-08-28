<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfblockerng_log.php AJAX 'load' handler line-count guard (issue #1156;
 * issue #1261: exec("grep -c ^ ... 2>&1") is replaced by pfb_count_lines()).
 *
 * Before #1261, a removed-file race or unreadable path put grep's error
 * string into $linecnt, and PHP 8 comparing/subtracting that string against
 * an int was a TypeError hazard -- an `is_numeric($linecnt)` guard caught it.
 * pfb_count_lines() now returns ?int directly: no shell, no error string, so
 * the guard is a plain `$linecnt === NULL` check. Silently skipping the cap
 * would still be worse than failing: the fgets() loop would stream the WHOLE
 * file unbounded, defeating the 10k-line cap exactly when the count is
 * unknown -- so a NULL count must still answer with the handler's own '|2|'
 * error convention and stop.
 *
 * The file executes top-level code on include (needs a live pfSense
 * session -- $pfb, $_REQUEST routing, real file I/O) and cannot be
 * require()d off-appliance. The guard + cap block is extracted verbatim from
 * comment-free source into a callable oracle (the count injected as the argument, print
 * captured, exit becomes an early return), so the branch logic is exercised
 * behaviourally, not just shape-matched.
 *
 * Feature: a NULL line count fails loudly instead of fatal or unbounded
 *          streaming; numeric counts keep the 10k tail window
 *
 *   Scenario: numeric under/at the cap  -> no window, no error
 *   Scenario: numeric over the cap      -> window armed, skip count exact
 *   Scenario: NULL (read failure)       -> '|2|' error response, no window,
 *             no TypeError
 */
final class LogLinecountGuardTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_log.php';
		$src = php_strip_whitespace($path);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free pfblockerng_log.php');
		}
		self::$src = $src;

		// Oracle: the block from the NULL guard through the cap window, exactly
		// as committed. print -> capture, exit -> early return, gettext
		// stripped (plain PHP string stays). If extraction fails the guard block
		// changed shape -- fail loudly rather than skip.
		$start = strpos($src, 'if ($linecnt === NULL)');
		$end = strpos($src, '$data =', $start === FALSE ? 0 : $start);
		if (!function_exists('pfb_log_linecount_oracle') && $start !== FALSE && $end !== FALSE && $end > $start) {
			$block = substr($src, $start, $end - $start);
			$block = strtr($block, [
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

	private function oracle(?int $linecnt): array
	{
		if (!function_exists('pfb_log_linecount_oracle')) {
			$this->fail('oracle extraction failed: the $linecnt === NULL guard block was not found in pfblockerng_log.php — see testNullGuardAnswersWithErrorConvention\'s source assertion');
		}
		return pfb_log_linecount_oracle($linecnt);
	}

	// --------------------------------------------------------------------------
	// Source-shape vacuity guards (the oracle depends on these constructs)
	// --------------------------------------------------------------------------

	public function testLinecntAssignedFromPfbCountLinesExactlyOnce(): void
	{
		$count = preg_match_all('/\$linecnt\s*=\s*pfb_count_lines\(.*\);/', self::$src);
		$this->assertSame(
			1,
			$count,
			'expected exactly one pfb_count_lines() assignment in the AJAX load handler (issue #1261)'
		);
	}

	public function testNoExecGrepForkSurvivesForLinecnt(): void
	{
		$this->assertDoesNotMatchRegularExpression(
			'/\$linecnt\s*=\s*exec\(/',
			self::$src,
			'a $linecnt = exec(...) fork survives -- issue #1261 must replace it with pfb_count_lines()'
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
	 * skips the cap for a NULL count, this shape is absent.
	 */
	public function testNullGuardAnswersWithErrorConvention(): void
	{
		$this->assertStringContainsString(
			'if ($linecnt === NULL) { print ("|2|',
			self::$src,
			'a NULL $linecnt must answer with the handler\'s |2| error convention before any cap math'
		);
	}

	// --------------------------------------------------------------------------
	// Behavioural rows through the extracted oracle
	// --------------------------------------------------------------------------

	public function testNumericUnderCapKeepsFullView(): void
	{
		[$out, $validate, $skipcnt, $line_limit] = $this->oracle(500);

		$this->assertSame('', $out, 'no error response expected for a numeric under-cap count');
		$this->assertFalse($validate, 'the tail window must stay disarmed under the cap');
		$this->assertNull($skipcnt, 'no skip count expected under the cap');
		$this->assertSame('', $line_limit, 'no truncation notice expected under the cap');
	}

	public function testNumericAtCapBoundaryKeepsFullView(): void
	{
		// Pins the comparison operator: exactly-at-cap is NOT over the cap.
		[$out, $validate] = $this->oracle(10000);

		$this->assertSame('', $out, 'no error response expected at the cap boundary');
		$this->assertFalse($validate, 'exactly-at-cap must not arm the tail window (> not >=)');
	}

	public function testNumericOverCapArmsTailWindowWithExactSkipCount(): void
	{
		[$out, $validate, $skipcnt, $line_limit] = $this->oracle(10500);

		$this->assertSame('', $out, 'no error response expected for a numeric over-cap count');
		$this->assertTrue($validate, 'an over-cap count must arm the tail window');
		$this->assertSame(500, $skipcnt, 'skip count must be linecnt - maxcnt');
		$this->assertStringContainsString(
			'Displaying last 10000 lines only',
			(string) $line_limit,
			'the truncation notice must name the cap'
		);
	}

	public function testNullReadFailureFailsLoudlyWithoutTypeErrorOrStreaming(): void
	{
		try {
			[$out, $validate] = $this->oracle(NULL);
		} catch (\TypeError $e) {
			$this->fail('a NULL line count must not reach the subtraction: ' . $e->getMessage());
		}

		$this->assertStringStartsWith(
			'|2|',
			$out,
			'a NULL line count must produce the |2| error response, got ' . var_export($out, true)
		);
		$this->assertNull(
			$validate,
			'the handler must stop at the error response — reaching the cap logic means the unbounded-stream path is open'
		);
	}
}
