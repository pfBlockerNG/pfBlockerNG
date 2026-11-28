<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-60 Phase 1 pinned TODAY's inconsistent, sometimes-absent, sometimes
 * year-less log timestamp behaviour (ADR.md §1.3) as the "before" oracle for
 * Phases 2-4's red→green proofs. Phases 2-4 have since flipped every row
 * (below) to pin the FIXED, always-on ISO-8601 behaviour instead: all 10 log
 * types now share the same 'Y-m-d H:i:s' shape.
 *
 * SyslogEventTest exercises the daemon's DNSBL stdin branch in a bounded child
 * process. This file keeps the 'BSD'/'syslog' timestamp branch (§1.3's
 * ip_blocklog/ip_permitlog/ip_matchlog row) on its smaller pure seam,
 * pfb_filterlog_timestamp(). Issue #4053 removed pfb_log_event(), the block page's dnsbl.log writer.
 */
#[CoversFunction('pfb_logger')]
#[CoversFunction('pfb_log_iso_timestamp')]
#[CoversFunction('pfb_filterlog_timestamp')]
#[CoversFunction('pfb_open_sqlite')]
final class LogTimestampBaselineTest extends TestCase
{
	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	private string $savedTz;

	protected function setUp(): void
	{
		foreach (['log', 'errlog', 'extraslog', 'pnow', 'runlog', 'runlog_active'] as $k) {
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
			elseif (is_dir($f)) {
				rmdir_recursive($f);
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
	 * issue #1008: the legacy '[ NOW ]' scrub is retired (every caller's literal token
	 * was deleted in the same change) -- pfb_logger() no longer special-cases message
	 * content at all, so a message that happens to contain the substring 'NOW'
	 * (bracketed or bare) is preserved byte-for-byte, not silently mangled.
	 */
	public function testLogMessageContainingNowSubstringIsPreservedVerbatim(): void
	{
		$log = $this->tempFile('pfb_log_now_');
		$GLOBALS['pfb']['log'] = $log;
		unset($GLOBALS['pfb']['pnow']);

		pfb_logger("SNOWSHOE feed KNOWN issue [ NOW ]\n", 1);

		$written = (string) file_get_contents($log);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} SNOWSHOE feed KNOWN issue \[ NOW \]\n$/',
			$written,
			"a message containing 'NOW' must be preserved verbatim (no scrub) after the prefix; got: {$written}"
		);
		$this->assertArrayNotHasKey('pnow', $GLOBALS['pfb'], 'pfb_logger() must not recreate retired same-second global state');
	}

	/**
	 * The dedup bug (ADR.md §1.4) is retired: repeated calls must each carry
	 * a real, non-blank ISO timestamp -- neither strips the other's.
	 */
	public function testLogRepeatedCallsAreIndependentlyStamped(): void
	{
		$log = $this->tempFile('pfb_log_dedup_');
		$GLOBALS['pfb']['log'] = $log;

		pfb_logger("pfb-baseline dedup line\n", 1);
		pfb_logger("pfb-baseline dedup line\n", 1);

		$lines = explode("\n", rtrim((string) file_get_contents($log), "\n"));
		$this->assertCount(2, $lines, 'expected two independently-stamped lines');
		foreach ($lines as $i => $line) {
			$this->assertMatchesRegularExpression(
				'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} pfb-baseline dedup line$/',
				$line,
				"line {$i} must carry its own real ISO timestamp; got: {$line}"
			);
		}
	}

	/**
	 * ADR.md §1.4's 'pnow' was a single process-global shared across every
	 * logtype; it is deleted, so a log (logtype 1) call can no longer poison
	 * a later extraslog (logtype 3) call -- each is now stamped independently.
	 */
	public function testLogAndExtrasLogCallsAreIndependent(): void
	{
		$log = $this->tempFile('pfb_log_cross_');
		$extraslog = $this->tempFile('pfb_extraslog_cross_');
		$GLOBALS['pfb']['log'] = $log;
		$GLOBALS['pfb']['extraslog'] = $extraslog;

		pfb_logger("pfb-cross-a\n", 1);
		pfb_logger("pfb-cross-b\n", 3);

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
		$errlog = $this->tempFile('pfb_errlog_bypass_');
		$dir = $this->tempFile('pfb_sqlite_dir_');
		unlink($dir);
		mkdir($dir);
		$this->saved['dnsbl_info'] = array_key_exists('dnsbl_info', $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb']['dnsbl_info'] : FALSE;
		$this->saved['sqlite_timeout'] = array_key_exists('sqlite_timeout', $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb']['sqlite_timeout'] : FALSE;
		$this->saved['errlog'] = array_key_exists('errlog', $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb']['errlog'] : FALSE;
		$GLOBALS['pfb']['dnsbl_info'] = $dir;
		$GLOBALS['pfb']['sqlite_timeout'] = 1;
		$GLOBALS['pfb']['errlog'] = $errlog;

		try {
			$this->assertFalse(pfb_open_sqlite(1, 'Query ip cache'), 'an SQLite directory path must fail open and exercise the errlog bypass');
		} finally {
			rmdir($dir);
		}

		$written = (string) file_get_contents($errlog);
		$lines = array_values(array_filter(explode("\n", $written), static fn (string $line): bool => $line !== ''));
		$this->assertCount(2, $lines, "the failed first and second SQLite opens must both log a stamped line; got: {$written}");
		foreach ($lines as $line) {
			$this->assertMatchesRegularExpression(
				'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} DNSBL_SQL: Failed to open DB(?: 2nd attempt)? - Query ip cache$/',
				$line,
				"the pfb_open_sqlite() bypass write must carry a real ISO timestamp now; got: {$line}"
			);
		}
	}

	// -----------------------------------------------------------------------
	// §1.3 row: ip_blocklog/ip_permitlog/ip_matchlog -- pfb_filterlog_timestamp()'s
	// 'BSD' branch year-infers, 'syslog' keeps its already-real year.
	// -----------------------------------------------------------------------

	public function testFilterlogBsdBranchYearInfersFromNow(): void
	{
		// A classic BSD syslog triple has no year field at all -- infer it from $now.
		// A line timestamped for "today" (a few hours before $now, the live-tailing
		// daemon's normal case) must pick $now's own year, no rollback.
		$now = strtotime('2026-07-08 10:00:00 UTC');
		$f = ['Jul', '8', '07:00:00'];

		$ts_formatted = pfb_filterlog_timestamp($f, 'BSD', $now);

		$this->assertSame('2026-07-08 07:00:00', $ts_formatted, 'BSD triple must year-infer against $now, unrolled');
	}

	public function testFilterlogSyslogBranchKeepsRealYear(): void
	{
		// A synthetic RFC-5424 timestamp field -- it DOES carry a year, verbatim.
		$f = [1 => '2024-11-05T13:30:45+00:00'];
		$this->assertStringContainsString('2024', $f[1], 'fixture sanity: the RFC-5424 source must carry a year');

		$ts_formatted = pfb_filterlog_timestamp($f, 'syslog', time());

		$this->assertSame('2024-11-05 13:30:45', $ts_formatted, "the 'syslog' branch must keep \$f[1]'s real year verbatim, not discard it");
	}

	/**
	 * issue #1006: a malformed RFC-5424 $f[1] must fall back to
	 * pfb_log_iso_timestamp()'s "now", never stamp 1970 -- an unguarded
	 * strtotime()===FALSE previously fed date() a FALSE (=> 0) timestamp,
	 * which the age-cutoff (Phase 6) would then treat as always-expired,
	 * silently dropping a genuinely recent line.
	 */
	public function testFilterlogSyslogBranchUnparseableFallsBackToIsoNow(): void
	{
		$f = [1 => 'not-a-valid-rfc5424-timestamp'];
		$this->assertFalse(strtotime($f[1]), 'fixture sanity: the garbage $f[1] must fail to parse (FALSE)');

		$ts_formatted = pfb_filterlog_timestamp($f, 'syslog', time());

		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			$ts_formatted,
			"the FALSE-parse fallback must be pfb_log_iso_timestamp()'s ISO-8601 \"now\" shape"
		);
		$this->assertStringStartsNotWith('1970-01-01', $ts_formatted, 'must never silently stamp the Unix epoch on a parse failure');
	}

	/**
	 * Hostile-input row (a): a real RFC-5424 timestamp spanning a year
	 * boundary must parse to EXACTLY that year -- never inferred.
	 */
	public function testFilterlogSyslogBranchPreservesYearAcrossBoundary(): void
	{
		$f = [1 => '2025-12-31T23:59:59+00:00'];

		$ts_formatted = pfb_filterlog_timestamp($f, 'syslog', time());

		$this->assertSame(
			'2025-12-31 23:59:59',
			$ts_formatted,
			'a syslog line spanning a year boundary must keep its verbatim source year, never year-inferred'
		);
	}

	/**
	 * Hostile-input row (c): a December BSD line read in January (the classic
	 * yearless-BSD-syslog case) must roll back exactly one year.
	 */
	public function testFilterlogBsdBranchDecemberReadInJanuaryRollsBackYear(): void
	{
		$now = strtotime('2026-01-05 10:00:00 UTC');
		$f = ['Dec', '31', '23:00:00'];

		$naiveTs = strtotime("{$f[0]} {$f[1]} {$f[2]}", $now);
		$this->assertGreaterThan($now + 6 * 3600, $naiveTs, 'fixture sanity: the naive same-year parse must land in the future');

		$ts_formatted = pfb_filterlog_timestamp($f, 'BSD', $now);

		$this->assertSame('2025-12-31 23:00:00', $ts_formatted, 'a December BSD line read in January must roll back exactly one year');
	}

	/**
	 * Adversarial review nitpick (PR #1005): the '6*3600' skew-tolerance boundary
	 * itself (a value beyond the ADR's literal "roll back if in the future" text,
	 * added to avoid misreading a same-day line near midnight/DST as "next year")
	 * had no test pinning its exact edge. Reproduces the full production formula
	 * on both sides of the threshold, same $bsd_now, only the BSD line's time
	 * differing by +/- 1 minute around exactly 6 hours ahead.
	 */
	public function testFilterlogBsdBranchSixHourSkewToleranceBoundary(): void
	{
		$bsdNow = strtotime('2026-07-08 12:00:00 UTC');

		// 5h59m ahead: AT/under tolerance -- no rollback, current year kept.
		$this->assertSame(
			'2026-07-08 17:59:00',
			pfb_filterlog_timestamp(['Jul', '8', '17:59:00'], 'BSD', $bsdNow),
			'just under the 6h tolerance must NOT roll back the year'
		);

		// 6h01m ahead: OVER tolerance -- the guard fires and rolls back a year
		// (the heuristic applies uniformly, not only at a literal Dec/Jan boundary --
		// a documented, already-shipped characteristic, pinned here, not redesigned).
		$this->assertSame(
			'2025-07-08 18:01:00',
			pfb_filterlog_timestamp(['Jul', '8', '18:01:00'], 'BSD', $bsdNow),
			'just over the 6h tolerance must roll back the year'
		);
	}

	/**
	 * Hostile-input row (d): unparseable BSD fields must never raise a PHP
	 * warning/fatal -- the daemon falls back to pfb_log_iso_timestamp()'s "now".
	 */
	public function testFilterlogBsdBranchUnparseableFallsBackToIsoNow(): void
	{
		$warnings = [];
		set_error_handler(function ($errno, $errstr) use (&$warnings) {
			$warnings[] = $errstr;
			return true;
		});
		$f = ['Foo', '99', '99:99:99'];
		$ts_formatted = pfb_filterlog_timestamp($f, 'BSD', time());
		restore_error_handler();

		$this->assertSame([], $warnings, 'pfb_filterlog_timestamp() on garbage BSD fields must never raise a PHP warning');
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			$ts_formatted,
			"the FALSE-parse fallback must be pfb_log_iso_timestamp()'s ISO-8601 \"now\" shape"
		);
		$this->assertStringStartsNotWith('1970-01-01', $ts_formatted, 'must never silently stamp the Unix epoch on a parse failure');
	}

	// -----------------------------------------------------------------------
	// The shared ISO-8601 helper -- wired in by Phases 2-4 (every log-timestamp
	// call site, PHP and python, now shares this same 'Y-m-d H:i:s' shape).
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

}
