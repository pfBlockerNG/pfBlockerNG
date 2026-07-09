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
 * pfb_daemon_filterlog() reads php://stdin in an unbounded daemon loop and is
 * not directly callable from a unit test; its 'BSD'/'syslog' timestamp branch
 * (§1.3's ip_blocklog/ip_permitlog/ip_matchlog row) was extracted into the
 * pure, directly-callable pfb_filterlog_timestamp() and is exercised for real
 * below. Only the REST of pfb_daemon_filterlog() -- the stdin daemon loop
 * itself -- remains untestable directly. pfb_log_event() (§1.8's dnsbl.log
 * twin writer) IS directly callable and is exercised for real below too.
 */
#[CoversFunction('pfb_logger')]
#[CoversFunction('pfb_parsed_fail')]
#[CoversFunction('pfb_log_iso_timestamp')]
#[CoversFunction('pfb_filterlog_timestamp')]
#[CoversFunction('pfb_open_sqlite')]
#[CoversFunction('pfb_log_event')]
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
	 * issue #1008: the legacy '[ NOW ]' scrub is retired (every caller's literal token
	 * was deleted in the same change) -- pfb_logger() no longer special-cases message
	 * content at all, so a message that happens to contain the substring 'NOW'
	 * (bracketed or bare) is preserved byte-for-byte, not silently mangled.
	 */
	public function testLogMessageContainingNowSubstringIsPreservedVerbatim(): void
	{
		$log = $this->tempFile('pfb_log_now_');
		$GLOBALS['pfb']['log'] = $log;

		pfb_logger("SNOWSHOE feed KNOWN issue [ NOW ]\n", 1);

		$written = (string) file_get_contents($log);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} SNOWSHOE feed KNOWN issue \[ NOW \]\n$/',
			$written,
			"a message containing 'NOW' must be preserved verbatim (no scrub) after the prefix; got: {$written}"
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
	// §1.3 row: dnsbl_parse_err -- ADR-60 P3: pfb_parsed_fail() now writes the
	// same unambiguous ISO-8601 format as every other log type.
	// -----------------------------------------------------------------------

	public function testParsedFailWritesIsoTimestampFormat(): void
	{
		$logfile = $this->tempFile('pfb_parsedfail_');

		// issue #1004: trailing $lineno column added -- pinned explicitly (5) here.
		pfb_parsed_fail('pfbtestheader', 'some parse line', 'orig line', $logfile, 5);

		$written = (string) file_get_contents($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},pfbtestheader,some parse line,orig line,5$/',
			$written,
			"pfb_parsed_fail() must write the unambiguous 'Y-m-d H:i:s' format now; got: {$written}"
		);
	}

	/**
	 * Hostile-input row (e): the new ISO timestamp's ':' characters must not
	 * introduce an extra comma that would shift dnsbl_parse_err's CSV columns.
	 */
	public function testParsedFailIsoTimestampHasNoExtraCommaFields(): void
	{
		$logfile = $this->tempFile('pfb_parsedfail_csv_');

		// issue #1004: 5 columns now (timestamp,header,line,oline,lineno) -- field0 unmoved.
		pfb_parsed_fail('pfbtestheader', 'some parse line', 'orig line', $logfile, 5);

		$written = (string) file_get_contents($logfile);
		$fields = explode(',', $written);
		$this->assertCount(5, $fields, "the ISO timestamp must not shift dnsbl_parse_err's CSV columns; got: {$written}");
	}

	// -----------------------------------------------------------------------
	// §1.3 row: dnslog -- ADR-60 P4: pfb_log_event() (the Unbound-native-mode
	// twin writer to the SAME dnsbl.log file pfb_unbound.py's python-mode
	// writer targets, ADR.md §1.8) now stamps 'Y-m-d H:i:s' too. Unlike
	// pfb_daemon_filterlog()/pfb_parsed_fail(), pfb_log_event() takes plain
	// scalar args and IS directly callable -- exercised for real below.
	// -----------------------------------------------------------------------

	/**
	 * Seeds a minimal-but-real $pfb sandbox for pfb_log_event(): a temp dnsbl.log
	 * plus two temp SQLite3 DB files for its 'dnsbl' (table 1) and 'lastevent'
	 * (table 2) opens, with the SAME lastevent row pre-seeded so pfb_log_event()
	 * takes its "duplicate entry" branch -- skipping pfb_dnsbl_parse() (a real-DNS
	 * lookup + on-disk grep dependency unrelated to this phase's timestamp-only
	 * change) entirely, without stubbing or touching pfb_log_event() itself.
	 *
	 * @return array{0:string,1:string} [$dnslog path, $lastevent groupname/details string]
	 */
	private function seedLogEventSandbox(string $domain, string $src_ip): array
	{
		$dnslog = $this->tempFile('pfb_log_event_dnslog_');
		$resolverDb = $this->tempFile('pfb_log_event_resolver_');
		$infoDb = $this->tempFile('pfb_log_event_info_');
		$GLOBALS['pfb']['dnslog'] = $dnslog;
		$GLOBALS['pfb']['dnsbl_resolver'] = $resolverDb;
		$GLOBALS['pfb']['dnsbl_info'] = $infoDb;
		$GLOBALS['pfb']['sqlite_timeout'] = 2000;
		$GLOBALS['pfb']['errlog'] = $this->tempFile('pfb_log_event_errlog_');

		$db = new SQLite3($resolverDb);
		$db->exec('CREATE TABLE IF NOT EXISTS lastevent ( row INTEGER, groupname TEXT, entry TEXT, details TEXT )');
		$stmt = $db->prepare('INSERT INTO lastevent (row, groupname, entry, details) VALUES (0, :g, :e, :d)');
		$stmt->bindValue(':g', 'PreGroup', SQLITE3_TEXT);
		$stmt->bindValue(':e', "{$domain}{$src_ip}", SQLITE3_TEXT);
		$stmt->bindValue(':d', 'predetails', SQLITE3_TEXT);
		$stmt->execute();
		$db->close();

		return [$dnslog, 'predetails'];
	}

	/**
	 * Calls $work() with every raised PHP warning/notice captured (not printed),
	 * then returns those messages MINUS pfb_open_sqlite()'s @chown/@chgrp-to-
	 * 'unbound' noise (the 'unbound' OS user is absent on a dev/CI box -- same
	 * harness-noise filter as DnsblParseComputeMetacharTest).
	 *
	 * @return string[] unexpected warning messages (empty = none)
	 */
	private function callCapturingUnexpectedWarnings(callable $work): array
	{
		$caught = [];
		set_error_handler(function (int $errno, string $errstr) use (&$caught): bool {
			$caught[] = $errstr;
			return true;
		});
		try {
			$work();
		} finally {
			restore_error_handler();
		}

		return array_values(array_filter($caught, static function (string $msg): bool {
			return !str_contains($msg, 'Unable to find uid for unbound')
				&& !str_contains($msg, 'Unable to find gid for unbound');
		}));
	}

	public function testPfbLogEventWritesIsoTimestamp(): void
	{
		[$dnslog] = $this->seedLogEventSandbox('uuid-logevent-iso.example.com', '203.0.113.77');

		$unexpected = $this->callCapturingUnexpectedWarnings(function () {
			pfb_log_event('DNSBL-HTTPS', 'uuid-logevent-iso.example.com', '203.0.113.77', 'Unknown');
		});
		$this->assertSame([], $unexpected, 'expected no unrelated PHP warning from pfb_log_event(); got: ' . var_export($unexpected, true));

		$written = (string) file_get_contents($dnslog);
		$this->assertMatchesRegularExpression(
			'/^DNSBL-HTTPS,\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},predetails,-\n$/',
			$written,
			"pfb_log_event() (Unbound-native-mode DNSBL logging) must write an ISO-8601 timestamp now, like the python-mode writer; got: {$written}"
		);
	}

	/**
	 * The concrete §1.8 "mixed-format" failure mode this phase closes: dnsbl.log
	 * accumulates lines from BOTH writers (pfb_log_event() here; pfb_unbound.py's
	 * make_timestamp() simulated as a synthetic python-shaped CSV row, since
	 * Python is not callable from PHPUnit) -- after this phase, every line's
	 * timestamp field (index 1 in both writers' CSV shapes) is uniformly ISO,
	 * regardless of which DNSBL mode wrote it.
	 */
	public function testDnsblLogUniformAcrossBothWritersAfterFix(): void
	{
		$pySource = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfb_unbound.py');
		$this->assertStringContainsString(
			'datetime.now().strftime("%Y-%m-%d %H:%M:%S")',
			$pySource,
			"pfb_unbound.py's make_timestamp() format changed -- update this synthetic python-writer line to match"
		);

		[$dnslog] = $this->seedLogEventSandbox('uuid-logevent-mixed.example.com', '203.0.113.78');

		$unexpected = $this->callCapturingUnexpectedWarnings(function () {
			pfb_log_event('DNSBL-Full', 'uuid-logevent-mixed.example.com', '203.0.113.78', 'Unknown');
		});
		$this->assertSame([], $unexpected, 'expected no unrelated PHP warning from pfb_log_event(); got: ' . var_export($unexpected, true));

		// Synthetic python-mode line -- same 'Y-m-d H:i:s' shape make_timestamp()
		// now produces (pinned by the source tripwire above), same file.
		$pyLine = 'DNSBL-python,' . date('Y-m-d H:i:s', time())
			. ',uuid-pyrow.example.com,203.0.113.79,Python,VIP,TestGroup,uuid-pyrow.example.com,TestFeed,+,A';
		file_put_contents($dnslog, "{$pyLine}\n", FILE_APPEND | LOCK_EX);

		$lines = array_values(array_filter(explode("\n", (string) file_get_contents($dnslog)), static fn (string $l): bool => $l !== ''));
		$this->assertCount(2, $lines, "expected exactly the PHP-writer line + the synthetic python-writer line; got: " . var_export($lines, true));

		foreach ($lines as $line) {
			$fields = explode(',', $line);
			$this->assertMatchesRegularExpression(
				'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
				$fields[1],
				"every dnsbl.log line's timestamp field must be ISO-8601 regardless of writer; got line: {$line}"
			);
		}
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
