<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-60 Phase 1 — pins TODAY's inconsistent, sometimes-absent, sometimes
 * year-less log timestamp behaviour (ADR.md §1.3) as the "before" oracle for
 * Phases 2-4's red→green proofs. No production output changes in this phase.
 *
 * pfb_daemon_filterlog() reads php://stdin in an unbounded daemon loop and is
 * not directly callable from a unit test; its 'BSD'/'syslog' timestamp branch
 * (§1.3's ip_blocklog/ip_permitlog/ip_matchlog row) is pinned via (a) a
 * grep tripwire on the exact current source line, so this oracle goes red the
 * moment Phase 3 changes it, and (b) a reproduction of that exact formula
 * against synthetic fixtures.
 */
#[CoversFunction('pfb_logger')]
#[CoversFunction('pfb_parsed_fail')]
#[CoversFunction('pfb_log_iso_timestamp')]
final class LogTimestampBaselineTest extends TestCase
{
	private const PFBLOCKERNG_INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	private string $savedTz;

	protected function setUp(): void
	{
		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		// The syslog-branch reproduction below reformats a fixed instant -- pin the
		// timezone so the expected wall-clock string is environment-independent.
		$this->savedTz = date_default_timezone_get();
		date_default_timezone_set('UTC');
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
		date_default_timezone_set($this->savedTz);
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	private function tempFile(string $prefix): string {
		$f = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($f, "could not create temp file ({$prefix})");
		$this->tmpfiles[] = $f;
		return $f;
	}

	private const NO_TIMESTAMP_PATTERN = '/\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{2}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/';

	// -----------------------------------------------------------------------
	// §1.3 row: log/extraslog -- opt-in NOW token, process-global same-second dedup
	// -----------------------------------------------------------------------

	public function testLogWithoutNowTokenWritesNoTimestamp(): void
	{
		$log = $this->tempFile('pfb_log_notoken_');
		$GLOBALS['pfb']['log'] = $log;

		pfb_logger("pfb-baseline no-token line\n", 1);

		$written = (string) file_get_contents($log);
		$this->assertSame(
			"pfb-baseline no-token line\n",
			$written,
			"a pfb_logger() call with no 'NOW' token must write the line unchanged, no timestamp"
		);
		$this->assertDoesNotMatchRegularExpression(self::NO_TIMESTAMP_PATTERN, $written);
	}

	public function testExtrasLogWithoutNowTokenWritesNoTimestamp(): void
	{
		$extraslog = $this->tempFile('pfb_extraslog_notoken_');
		$GLOBALS['pfb']['extraslog'] = $extraslog;

		pfb_logger("pfb-baseline extraslog no-token line\n", 3);

		$written = (string) file_get_contents($extraslog);
		$this->assertSame(
			"pfb-baseline extraslog no-token line\n",
			$written,
			'extraslog shares log\'s opt-in NOW-token mechanics -- no token means no timestamp'
		);
		$this->assertDoesNotMatchRegularExpression(self::NO_TIMESTAMP_PATTERN, $written);
	}

	public function testLogWithNowTokenSubstitutesIsoTimestampWhenPnowCleared(): void
	{
		$log = $this->tempFile('pfb_log_now_');
		$GLOBALS['pfb']['log'] = $log;
		unset($GLOBALS['pfb']['pnow']);

		pfb_logger("pfb-baseline now-token line [ NOW ]\n", 1);

		$written = (string) file_get_contents($log);
		$this->assertMatchesRegularExpression(
			'/^pfb-baseline now-token line \[ \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \]\n$/',
			$written,
			"a fresh (cleared 'pnow') NOW-token call must substitute an ISO-8601 timestamp"
		);
	}

	/**
	 * The dedup bug (ADR.md §1.4): a same-second repeat call with the identical
	 * 'pnow' strips the '[ NOW ]' bracket to NOTHING -- reproduced on purpose,
	 * this is the "before" proof Phase 2 flips to "always stamped".
	 *
	 * Bounded retry: the premise ($now === preset pnow) only holds if the
	 * wall-clock second does not roll over between presetting 'pnow' and
	 * pfb_logger()'s own date() call: an inherent race with no injectable
	 * clock in production code today.
	 */
	public function testLogNowTokenStrippedToNothingWhenPnowAlreadySetSameSecond(): void
	{
		$log = $this->tempFile('pfb_log_dedup_');
		$GLOBALS['pfb']['log'] = $log;

		[$before, $after] = $this->runWithinSameSecond(function (string $before) use ($log) {
			file_put_contents($log, '');
			$GLOBALS['pfb']['pnow'] = $before;
			pfb_logger("pfb-baseline dedup line [ NOW ]\n", 1);
		});
		$this->assertSame($before, $after, 'wall-clock second rolled over on every retry attempt (flaky env)');

		$written = (string) file_get_contents($log);
		$this->assertSame(
			"pfb-baseline dedup line\n",
			$written,
			"same-second dedup must strip ' [ NOW ]' to nothing, not substitute a timestamp"
		);
	}

	/**
	 * ADR.md §1.4: 'pnow' is a single process-global shared across every
	 * logtype -- a log (logtype 1) call's timestamp poisons a LATER,
	 * same-second extraslog (logtype 3) call too.
	 */
	public function testPnowDedupContaminatesAcrossLogAndExtrasLog(): void
	{
		$log = $this->tempFile('pfb_log_cross_');
		$extraslog = $this->tempFile('pfb_extraslog_cross_');
		$GLOBALS['pfb']['log'] = $log;
		$GLOBALS['pfb']['extraslog'] = $extraslog;
		unset($GLOBALS['pfb']['pnow']);

		// Note: no external 'pnow' preset here -- the FIRST call (logtype 1) sets
		// $pfb['pnow'] itself; the second call (logtype 3) is poisoned by THAT,
		// proving the contamination flows from pfb_logger() itself, not the harness.
		[$before, $after] = $this->runWithinSameSecond(function (string $before) use ($log, $extraslog) {
			file_put_contents($log, '');
			file_put_contents($extraslog, '');
			unset($GLOBALS['pfb']['pnow']);
			pfb_logger("pfb-cross-a [ NOW ]\n", 1);        // sets $pfb['pnow']
			pfb_logger("pfb-cross-b [ NOW ]\n", 3);         // extraslog, same second
		});
		$this->assertSame($before, $after, 'wall-clock second rolled over on every retry attempt (flaky env)');

		$extrasWritten = (string) file_get_contents($extraslog);
		$this->assertSame(
			"pfb-cross-b\n",
			$extrasWritten,
			"the log (logtype 1) call's 'pnow' must poison the LATER extraslog (logtype 3) call's bracket too"
		);
	}

	// -----------------------------------------------------------------------
	// §1.3 row: errlog -- always stamped via pfb_logger()'s $elog; the
	// pfb_open_sqlite() bypass writes directly, with no timestamp at all.
	// -----------------------------------------------------------------------

	public function testErrlogAlwaysStampedEvenWhenMainLogDedupStripsTimestamp(): void
	{
		$log = $this->tempFile('pfb_log_errdedup_');
		$errlog = $this->tempFile('pfb_errlog_errdedup_');
		$GLOBALS['pfb']['log'] = $log;
		$GLOBALS['pfb']['errlog'] = $errlog;

		[$before, $after] = $this->runWithinSameSecond(function (string $before) use ($log, $errlog) {
			file_put_contents($log, '');
			file_put_contents($errlog, '');
			$GLOBALS['pfb']['pnow'] = $before;
			pfb_logger("pfb-errlog-dedup line [ NOW ]\n", 2);
		});
		$this->assertSame($before, $after, 'wall-clock second rolled over on every retry attempt (flaky env)');

		$mainWritten = (string) file_get_contents($log);
		$errWritten  = (string) file_get_contents($errlog);

		$this->assertSame("pfb-errlog-dedup line\n", $mainWritten, 'main log: dedup strips the bracket');
		$this->assertMatchesRegularExpression(
			'/^pfb-errlog-dedup line \[ \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \]\n$/',
			$errWritten,
			'errlog must always carry the ISO timestamp, even when the main log dedup fired'
		);
	}

	public function testErrlogBypassWriteHasNoTimestamp(): void
	{
		// Tripwire: pin the exact bypass shape from pfb_open_sqlite() so this
		// oracle goes red if that call site's format ever changes.
		$source = (string) file_get_contents(self::PFBLOCKERNG_INC);
		$this->assertStringContainsString(
			'@file_put_contents($pfb[\'errlog\'], "\nDNSBL_SQL: Failed to open DB - {$message}", FILE_APPEND | LOCK_EX);',
			$source,
			'pfb_open_sqlite() bypass write shape changed -- update this baseline oracle'
		);

		$errlog = $this->tempFile('pfb_errlog_bypass_');
		// Reproduces that exact write: a direct file_put_contents(), no pfb_logger(),
		// no timestamp of any kind.
		file_put_contents($errlog, "\nDNSBL_SQL: Failed to open DB - Query ip cache", FILE_APPEND | LOCK_EX);

		$written = (string) file_get_contents($errlog);
		$this->assertSame("\nDNSBL_SQL: Failed to open DB - Query ip cache", $written);
		$this->assertDoesNotMatchRegularExpression(self::NO_TIMESTAMP_PATTERN, $written);
	}

	// -----------------------------------------------------------------------
	// §1.3 row: ip_blocklog/ip_permitlog/ip_matchlog -- pfb_daemon_filterlog()'s
	// 'BSD' raw passthrough (no year available) vs 'syslog' lossy reformat
	// (year discarded). Not directly callable (stdin daemon loop); pinned via
	// a source tripwire + a reproduction of the exact formula.
	// -----------------------------------------------------------------------

	public function testFilterlogBsdBranchRawPassthroughHasNoYear(): void
	{
		$source = (string) file_get_contents(self::PFBLOCKERNG_INC);
		$this->assertStringContainsString(
			'$log = "{$f[0]} {$f[1]} {$f[2]},{$d[3]},{$d[4]},{$int},{$d[6]},{$d[8]},";',
			$source,
			"pfb_daemon_filterlog()'s 'BSD' branch formula changed -- update this baseline oracle"
		);

		// A classic BSD syslog triple has no year field at all.
		$f = ['Jul', '4', '13:30:45'];
		$bsdPassthrough = "{$f[0]} {$f[1]} {$f[2]}";

		$this->assertSame('Jul 4 13:30:45', $bsdPassthrough);
		$this->assertDoesNotMatchRegularExpression('/\d{4}/', $bsdPassthrough, 'BSD raw passthrough must carry no year');
	}

	public function testFilterlogSyslogBranchLossyReformatDropsYear(): void
	{
		$source = (string) file_get_contents(self::PFBLOCKERNG_INC);
		$this->assertStringContainsString(
			"\$ts = date('M j H:i:s', strtotime(\$f[1]));",
			$source,
			"pfb_daemon_filterlog()'s 'syslog' branch formula changed -- update this baseline oracle"
		);

		// A synthetic RFC-5424 timestamp field -- it DOES carry a year.
		$f = [1 => '2024-11-05T13:30:45+00:00'];
		$this->assertStringContainsString('2024', $f[1], 'fixture sanity: the RFC-5424 source must carry a year');

		$ts = date('M j H:i:s', strtotime($f[1]));

		$this->assertSame('Nov 5 13:30:45', $ts);
		$this->assertDoesNotMatchRegularExpression(
			'/\d{4}/',
			$ts,
			"the 'syslog' branch's date('M j H:i:s', ...) reformat must drop the year, even though the source had one"
		);
	}

	// -----------------------------------------------------------------------
	// §1.3 row: dnsbl_parse_err -- pfb_parsed_fail()'s ambiguous 2-digit-year format
	// -----------------------------------------------------------------------

	public function testParsedFailPinsAmbiguousTwoDigitYearFormat(): void
	{
		$logfile = $this->tempFile('pfb_parsedfail_');

		pfb_parsed_fail('pfbtestheader', 'some parse line', 'orig line', $logfile);

		$written = (string) file_get_contents($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{1,2}\/\d{1,2}\/\d{2} \d{2}:\d{2}:\d{2},pfbtestheader,some parse line,orig line$/',
			$written,
			"pfb_parsed_fail() must write the ambiguous 'm/j/y H:i:s' 2-digit-year format; got: {$written}"
		);
	}

	// -----------------------------------------------------------------------
	// The new (unwired) ISO-8601 helper Phases 2-4 will call.
	// -----------------------------------------------------------------------

	public function testPfbLogIsoTimestampMatchesIso8601Format(): void
	{
		$result = pfb_log_iso_timestamp();

		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			$result,
			"pfb_log_iso_timestamp() must return 'YYYY-MM-DD HH:MM:SS'; got: {$result}"
		);
	}

	/**
	 * Runs $work($before) with a best-effort guarantee that no wall-clock
	 * second boundary was crossed during it, retrying up to 5 times. $work()
	 * itself decides whether/how to use $before (e.g. presetting
	 * $GLOBALS['pfb']['pnow']) -- this helper has no side effects of its own.
	 *
	 * @return array{0:string,1:string} [$before, $after] -- equal on success.
	 */
	private function runWithinSameSecond(callable $work): array {
		$before = $after = '';
		for ($attempt = 0; $attempt < 5; $attempt++) {
			$before = date('Y-m-d H:i:s', time());
			$work($before);
			$after = date('Y-m-d H:i:s', time());
			if ($before === $after) {
				break;
			}
		}
		return [$before, $after];
	}
}
