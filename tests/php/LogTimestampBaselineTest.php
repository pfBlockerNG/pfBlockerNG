<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-60 Phase 1 pinned TODAY's inconsistent, sometimes-absent, sometimes
 * year-less log timestamp behaviour (ADR.md §1.3) as the "before" oracle for
 * Phases 2-4's red→green proofs. Phase 2 flips the log/extraslog/errlog rows
 * (below) to pin the FIXED, always-on behaviour instead: the legacy opt-in
 * '[ NOW ]' token + same-second '$pfb[pnow]' dedup (ADR.md §1.4) is retired.
 *
 * pfb_daemon_filterlog() reads php://stdin in an unbounded daemon loop and is
 * not directly callable from a unit test; its 'BSD'/'syslog' timestamp branch
 * (§1.3's ip_blocklog/ip_permitlog/ip_matchlog row, Phase 3's row, untouched
 * here) is pinned via (a) a grep tripwire on the exact current source line, so
 * this oracle goes red the moment Phase 3 changes it, and (b) a reproduction
 * of that exact formula against synthetic fixtures.
 */
#[CoversFunction('pfb_logger')]
#[CoversFunction('pfb_parsed_fail')]
#[CoversFunction('pfb_log_iso_timestamp')]
#[CoversFunction('pfb_open_sqlite')]
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
		foreach (['log', 'errlog', 'extraslog', 'runlog', 'runlog_active'] as $k) {
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

	// -----------------------------------------------------------------------
	// §1.3 row: log/extraslog -- ADR-60 P2: always stamped now, no opt-in
	// token, no same-second dedup. Fixture messages carry no '[ NOW ]' token
	// at all (that opt-in mechanic no longer exists), proving the timestamp
	// is unconditional, not substitution-triggered.
	// -----------------------------------------------------------------------

	public function testLogAlwaysStampedWithIsoTimestamp(): void
	{
		$log = $this->tempFile('pfb_log_notoken_');
		$GLOBALS['pfb']['log'] = $log;

		pfb_logger("pfb-baseline no-token line\n", 1);

		$written = (string) file_get_contents($log);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} pfb-baseline no-token line\n$/',
			$written,
			"pfb_logger() must ALWAYS prefix an ISO-8601 timestamp, even with no legacy 'NOW' token; got: {$written}"
		);
	}

	public function testExtrasLogAlwaysStampedWithIsoTimestamp(): void
	{
		$extraslog = $this->tempFile('pfb_extraslog_notoken_');
		$GLOBALS['pfb']['extraslog'] = $extraslog;

		pfb_logger("pfb-baseline extraslog no-token line\n", 3);

		$written = (string) file_get_contents($extraslog);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} pfb-baseline extraslog no-token line\n$/',
			$written,
			"extraslog must ALWAYS be stamped now too; got: {$written}"
		);
	}

	/**
	 * A caller still embedding the legacy '[ NOW ]' token gets it defensively
	 * scrubbed to nothing -- never substituted, never left as dead text --
	 * while the unconditional prefix still lands.
	 */
	public function testLogLegacyNowTokenScrubbedNotSubstituted(): void
	{
		$log = $this->tempFile('pfb_log_now_');
		$GLOBALS['pfb']['log'] = $log;

		pfb_logger("pfb-baseline now-token line [ NOW ]\n", 1);

		$written = (string) file_get_contents($log);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} pfb-baseline now-token line\n$/',
			$written,
			"the legacy '[ NOW ]' token must be scrubbed, and the real prefix used instead; got: {$written}"
		);
	}

	/**
	 * The dedup bug (ADR.md §1.4) is retired: two calls landing in the SAME
	 * wall-clock second must BOTH carry a real, non-blank ISO timestamp --
	 * neither strips the other's.
	 *
	 * Bounded retry: only proves the same-second premise if the wall-clock
	 * second does not roll over between the two calls -- an inherent race
	 * with no injectable clock in production code today.
	 */
	public function testLogRepeatedSameSecondCallsBothStamped(): void
	{
		$log = $this->tempFile('pfb_log_dedup_');
		$GLOBALS['pfb']['log'] = $log;

		[$before, $after] = $this->runWithinSameSecond(function () use ($log) {
			file_put_contents($log, '');
			pfb_logger("pfb-baseline dedup line\n", 1);
			pfb_logger("pfb-baseline dedup line\n", 1);
		});
		$this->assertSame($before, $after, 'wall-clock second rolled over on every retry attempt (flaky env)');

		$lines = explode("\n", rtrim((string) file_get_contents($log), "\n"));
		$this->assertCount(2, $lines, 'expected two independently-stamped lines');
		foreach ($lines as $i => $line) {
			$this->assertMatchesRegularExpression(
				'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} pfb-baseline dedup line$/',
				$line,
				"line {$i} must carry its own real ISO timestamp even though both calls landed in the same second; got: {$line}"
			);
		}
	}

	/**
	 * ADR.md §1.4's 'pnow' was a single process-global shared across every
	 * logtype; it is deleted, so a log (logtype 1) call can no longer poison
	 * a LATER, same-second extraslog (logtype 3) call -- each is now stamped
	 * independently.
	 */
	public function testLogAndExtrasLogCallsAreIndependent(): void
	{
		$log = $this->tempFile('pfb_log_cross_');
		$extraslog = $this->tempFile('pfb_extraslog_cross_');
		$GLOBALS['pfb']['log'] = $log;
		$GLOBALS['pfb']['extraslog'] = $extraslog;

		[$before, $after] = $this->runWithinSameSecond(function () use ($log, $extraslog) {
			file_put_contents($log, '');
			file_put_contents($extraslog, '');
			pfb_logger("pfb-cross-a\n", 1);
			pfb_logger("pfb-cross-b\n", 3);
		});
		$this->assertSame($before, $after, 'wall-clock second rolled over on every retry attempt (flaky env)');

		$logWritten    = (string) file_get_contents($log);
		$extrasWritten = (string) file_get_contents($extraslog);

		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} pfb-cross-a\n$/',
			$logWritten,
			"log's own stamp must be unaffected by the LATER extraslog call; got: {$logWritten}"
		);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} pfb-cross-b\n$/',
			$extrasWritten,
			"extraslog must carry its OWN real timestamp -- no shared global state left to contaminate it with; got: {$extrasWritten}"
		);
	}

	// -----------------------------------------------------------------------
	// §1.3 row: errlog -- ADR-60 P2: both writers (pfb_logger()'s $elog and
	// the pfb_open_sqlite() bypass) are always stamped now.
	// -----------------------------------------------------------------------

	public function testErrlogAndMainLogBothStampedSameFormat(): void
	{
		$log = $this->tempFile('pfb_log_errdedup_');
		$errlog = $this->tempFile('pfb_errlog_errdedup_');
		$GLOBALS['pfb']['log'] = $log;
		$GLOBALS['pfb']['errlog'] = $errlog;

		pfb_logger("pfb-errlog-dedup line\n", 2);

		$mainWritten = (string) file_get_contents($log);
		$errWritten  = (string) file_get_contents($errlog);

		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} pfb-errlog-dedup line\n$/',
			$mainWritten,
			"main log must always carry the ISO timestamp now; got: {$mainWritten}"
		);
		$this->assertSame(
			$mainWritten,
			$errWritten,
			'a logtype-2 write must land the IDENTICAL stamped line in both log and errlog'
		);
	}

	public function testErrlogBypassWriteAlwaysStamped(): void
	{
		// Tripwire: pin the exact (now-stamped) bypass shape from pfb_open_sqlite() so
		// this oracle goes red if that call site's format ever changes.
		$source = (string) file_get_contents(self::PFBLOCKERNG_INC);
		$this->assertStringContainsString(
			'@file_put_contents($pfb[\'errlog\'], "\n{$now} DNSBL_SQL: Failed to open DB - {$message}", FILE_APPEND | LOCK_EX);',
			$source,
			'pfb_open_sqlite() bypass write shape changed -- update this baseline oracle'
		);

		$errlog = $this->tempFile('pfb_errlog_bypass_');
		$now = date('Y-m-d H:i:s', time());
		// Reproduces that exact (now-stamped) write: a direct file_put_contents(), no pfb_logger().
		file_put_contents($errlog, "\n{$now} DNSBL_SQL: Failed to open DB - Query ip cache", FILE_APPEND | LOCK_EX);

		$written = (string) file_get_contents($errlog);
		$this->assertMatchesRegularExpression(
			'/^\n\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} DNSBL_SQL: Failed to open DB - Query ip cache$/',
			$written,
			"the pfb_open_sqlite() bypass write must always carry a real ISO timestamp now; got: {$written}"
		);
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
	 * Runs $work() with a best-effort guarantee that no wall-clock second
	 * boundary was crossed during it, retrying up to 5 times.
	 *
	 * @return array{0:string,1:string} [$before, $after] -- equal on success.
	 */
	private function runWithinSameSecond(callable $work): array {
		$before = $after = '';
		for ($attempt = 0; $attempt < 5; $attempt++) {
			$before = date('Y-m-d H:i:s', time());
			$work();
			$after = date('Y-m-d H:i:s', time());
			if ($before === $after) {
				break;
			}
		}
		return [$before, $after];
	}
}
