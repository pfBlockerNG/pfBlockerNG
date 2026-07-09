<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_logger() stamps log lines in ISO-8601 'YYYY-MM-DD HH:MM:SS', not the old
 * ambiguous US 'm/j/y H:i:s' (issue: American-style dates in user-facing logs).
 *
 * ADR-60 P2: every write is now unconditionally stamped -- the legacy opt-in
 * '[ NOW ]' token + same-second '$pfb[pnow]' dedup is retired. issue #1008 deleted
 * every pfblockerng.inc caller's literal '[ NOW ]' token and the scrub itself
 * (LogTimestampBaselineTest::testLogMessageContainingNowSubstringIsPreservedVerbatim
 * pins that a message containing 'NOW' is no longer mangled); issue #1047 found the
 * token still live in 9 pfblockerng.php (www UI) call sites and deleted those too --
 * LogNowTokenRetiredTest now tripwires the WHOLE tracked src/ tree, not just one file.
 * The shipped pfb_logger() is exercised against a temp log file so the on-disk
 * side-effect is asserted (not coverage theater). The shared $GLOBALS['pfb'] keys
 * are saved/restored so the suite stays order-independent.
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
		foreach (['log', 'errlog', 'grep', 'failed'] as $k) {
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
		// Given: a temp log target.
		$log = tempnam(sys_get_temp_dir(), 'pfb_logtest_');
		$this->assertNotFalse($log, 'could not create temp log file');
		$this->tmpfiles[] = $log;
		$GLOBALS['pfb']['log'] = $log;

		// When: logged to the main log (logtype 1).
		pfb_logger("pfb-iso-timestamp-test\n", 1);

		// Then: the written line is unconditionally ISO-8601-stamped, never the old US
		// m/j/y form.
		$written = (string) file_get_contents($log);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} pfb-iso-timestamp-test\n$/',
			$written,
			"log line should carry a leading ISO-8601 'YYYY-MM-DD HH:MM:SS' timestamp; got: {$written}"
		);
		$this->assertDoesNotMatchRegularExpression(
			'#\b\d{2}/\d{1,2}/\d{2}\b#',
			$written,
			"log line must not carry an ambiguous US 'm/j/y' date; got: {$written}"
		);
	}

	/**
	 * pfb_failures() greps the error log for TODAY's failures by date, then extracts the
	 * failed feed via explode(' ')[4]. ADR-60 P2 prepends pfb_logger()'s ISO-8601 stamp to
	 * the FRONT of every errlog line, shifting that index unless pfb_failures() strips the
	 * new prefix first — this test drives the REAL production write path
	 * (pfb_logger(), pfblockerng.inc's real "Download FAIL" call-site shape, verbatim) end
	 * to end into the real pfb_failures(), so a header[4]-index regression fails here.
	 */
	public function testFailuresGrepMatchesIsoLogTimestamp(): void
	{
		// Given: a real errlog line written via pfb_logger(), mirroring pfb_download_failure()'s
		// actual call site verbatim: "\n\n [ {$alias} - {$header} ] Download FAIL [ NOW ]\n", logtype 2.
		$log    = tempnam(sys_get_temp_dir(), 'pfb_logtest_');
		$errlog = tempnam(sys_get_temp_dir(), 'pfb_errlogtest_');
		$this->assertNotFalse($log, 'could not create temp log file');
		$this->assertNotFalse($errlog, 'could not create temp errlog file');
		$this->tmpfiles[] = $log;
		$this->tmpfiles[] = $errlog;
		$GLOBALS['pfb']['log']    = $log;
		$GLOBALS['pfb']['errlog'] = $errlog;
		$GLOBALS['pfb']['grep']   = 'grep';	// resolved via PATH on the test host
		unset($GLOBALS['pfb']['failed']);

		// When: the real write path, then the real tally.
		pfb_logger("\n\n [ pfB_TestAlias - pfbtestheader ] Download FAIL [ NOW ]\n", 2);
		pfb_failures();

		// Then: today's FAIL line was matched and tallied under the FEED header -- the SAME
		// key pfb_failures() extracted before this rework, not the alias (the regression).
		$this->assertArrayHasKey(
			'pfbtestheader',
			$GLOBALS['pfb']['failed'] ?? [],
			'pfb_failures() did not extract the feed header at explode(\' \')[4] -- got: '
			. var_export($GLOBALS['pfb']['failed'] ?? [], true)
		);
	}

	/**
	 * Issue #1054 (ADR-60's stamped-unit contract amended to the physical LINE,
	 * not the write): a full line, then two sub-line progress fragments ('.',
	 * ' completed .'), then a line break followed by another full line -- only
	 * the writes that actually START a new physical line get a stamp; the
	 * fragments continuing mid-line must carry NONE. RED on pre-fix code: every
	 * write got its own stamp, so the fragments would each carry one too.
	 */
	public function testMidLineFragmentsCarryNoStampOnlyLineStartsDo(): void
	{
		$log = tempnam(sys_get_temp_dir(), 'pfb_logtest_');
		$this->assertNotFalse($log, 'could not create temp log file');
		$this->tmpfiles[] = $log;
		$GLOBALS['pfb']['log'] = $log;

		pfb_logger("Downloading feed", 1);
		pfb_logger('.', 1);
		pfb_logger(' completed .', 1);
		pfb_logger("\nNext [ x ]\n", 1);

		$written = (string) file_get_contents($log);
		$isoRe   = '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}';
		$this->assertMatchesRegularExpression(
			"/^{$isoRe} Downloading feed\\. completed \\.\n{$isoRe} Next \\[ x \\]\n\$/",
			$written,
			"stamps must land exactly at line starts, never mid-line on a progress fragment; got: {$written}"
		);
		// Explicit negative check on the fragments themselves (vacuity guard): neither
		// sub-line write ('.', ' completed .') may carry its own embedded stamp --
		// exactly one stamp per physical line (2 lines here), never a 3rd mid-line one.
		$this->assertSame(2, preg_match_all("/{$isoRe}/", $written),
			"exactly one stamp per physical line (2 lines here) -- got: {$written}"
		);
	}

	/**
	 * Issue #1054, coverage row "fragment at BOL is stamped": a sub-line
	 * progress fragment written as the VERY FIRST write to a fresh (absent)
	 * target file starts a new physical line by definition, so it IS stamped --
	 * proving the BOL tracker's lazy-init (file absent/empty => TRUE), not just
	 * the leading-newline special case.
	 */
	public function testFragmentWrittenFirstToAFreshFileIsStamped(): void
	{
		$log = tempnam(sys_get_temp_dir(), 'pfb_logtest_');
		$this->assertNotFalse($log, 'could not create temp log file');
		unlink($log); // tempnam() creates it -- start truly absent, per the BOL contract's "absent" case.
		$this->tmpfiles[] = $log;
		$GLOBALS['pfb']['log'] = $log;

		pfb_logger('.', 1);

		$written = (string) file_get_contents($log);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \.$/',
			$written,
			"a fragment written first to an absent/fresh target must be stamped (it starts a new line); got: {$written}"
		);
	}
}
