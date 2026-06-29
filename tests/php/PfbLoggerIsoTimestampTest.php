<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_logger() stamps log lines in ISO-8601 'YYYY-MM-DD HH:MM:SS', not the old
 * ambiguous US 'm/j/y H:i:s' (issue: American-style dates in user-facing logs).
 *
 * The '[ NOW ]' token in a log message is substituted with the current timestamp; this
 * pins that substitution's FORMAT. The shipped pfb_logger() is exercised against a temp
 * log file so the on-disk side-effect is asserted (not coverage theater). The shared
 * $GLOBALS['pfb'] 'log'/'errlog'/'pnow' are saved/restored so the suite stays
 * order-independent, and 'pnow' is cleared so the first call substitutes the timestamp
 * (rather than the same-second dedup path stripping it).
 */
#[CoversFunction('pfb_logger')]
#[CoversFunction('pfb_failures')]
final class PfbLoggerIsoTimestampTest extends TestCase
{
	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['log', 'errlog', 'pnow', 'grep', 'failed'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	public function testLogTimestampIsIso8601NotUsStyle(): void
	{
		// Given: a temp log target and a cleared 'pnow' so the '[ NOW ]' token is substituted
		// (not stripped by the same-second dedup branch).
		$log = tempnam(sys_get_temp_dir(), 'pfb_logtest_');
		$this->assertNotFalse($log, 'could not create temp log file');
		$this->tmpfiles[] = $log;
		$GLOBALS['pfb']['log'] = $log;
		unset($GLOBALS['pfb']['pnow']);

		// When: a message carrying the '[ NOW ]' token is logged to the main log (logtype 1).
		pfb_logger("pfb-iso-timestamp-test [ NOW ]\n", 1);

		// Then: the written timestamp is ISO-8601, and never the old US m/j/y form.
		$written = (string) file_get_contents($log);
		$this->assertMatchesRegularExpression(
			'/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/',
			$written,
			"log line should carry an ISO-8601 'YYYY-MM-DD HH:MM:SS' timestamp; got: {$written}"
		);
		$this->assertDoesNotMatchRegularExpression(
			'#\b\d{2}/\d{1,2}/\d{2}\b#',
			$written,
			"log line must not carry an ambiguous US 'm/j/y' date; got: {$written}"
		);
	}

	/**
	 * pfb_failures() greps the error log for TODAY's failures by date — so its date format
	 * MUST match what pfb_logger() writes. This pins the producer↔consumer coupling: a FAIL
	 * line stamped with today's ISO date is found (if the grep reverted to m/j/y while the
	 * log is ISO, it would silently find nothing and this fails).
	 */
	public function testFailuresGrepMatchesIsoLogTimestamp(): void
	{
		// Given: an error log holding a FAIL line stamped with today's date in the SAME ISO
		// format pfb_logger() now writes ('Y-m-d ...'), plus enough tokens for pfb_failures()'s
		// explode(' ')[4] alias field.
		$errlog = tempnam(sys_get_temp_dir(), 'pfb_errlogtest_');
		$this->assertNotFalse($errlog, 'could not create temp errlog file');
		$this->tmpfiles[] = $errlog;
		$stamp = date('Y-m-d H:i:s', time());
		$this->assertNotFalse(
			file_put_contents($errlog, "{$stamp} [ FAIL pfbtestalias ] download error\n"),
			'could not seed the temp errlog'
		);
		$GLOBALS['pfb']['errlog'] = $errlog;
		$GLOBALS['pfb']['grep']   = 'grep';	// resolved via PATH on the test host
		unset($GLOBALS['pfb']['failed']);

		// When.
		pfb_failures();

		// Then: today's FAIL line was matched by the date grep and tallied.
		$this->assertArrayHasKey(
			'pfbtestalias',
			$GLOBALS['pfb']['failed'] ?? [],
			"pfb_failures() did not find today's FAIL line — the grep date format is out of sync "
			. 'with pfb_logger()'
		);
	}
}
