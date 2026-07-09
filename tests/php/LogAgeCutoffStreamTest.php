<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1012: pfb_log_age_trim_temp()'s 'nolimit' candidate has no
 * line-count cap, so @file()-ing it into a PHP array (ADR-60 S2.2's
 * assumption of "an already line-capped (small) candidate") can materialize
 * the whole unbounded log in memory. These pin the streaming
 * (fgets/fwrite-to-scratch) replacement's memory boundedness and its own
 * I/O failure gating; functional/field-mode coverage for the streaming path
 * lives in LogMgmtAgeCutoffTest.php.
 */
final class LogAgeCutoffStreamTest extends TestCase
{
	/** Mirrors LogMgmtAgeCutoffTest::seedMinimalConfig() -- see there for why each key is needed. */
	private function seedMinimalConfig(): void
	{
		$GLOBALS['config'] = [];
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		config_set_path("{$gen}/pfb_min",        '0');
		config_set_path("{$gen}/pfb_hour",       '0');
		config_set_path("{$gen}/pfb_dailystart", '0');
		config_set_path("{$gen}/skipfeed",       '0');

		config_set_path("{$ip}/suppression",     '');
		config_set_path("{$ip}/database_cc",     '');
		config_set_path("{$ip}/maxmind_locale",  'en');
		config_set_path("{$ip}/asn_reporting",   'disabled');
		config_set_path("{$ip}/asn_token",       '');
		config_set_path("{$ip}/maxmind_account", '');
		config_set_path("{$ip}/maxmind_key",     '');

		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');

		config_set_path("{$dnsbl}/pfb_dnsvip4",     '');
		config_set_path("{$dnsbl}/pfb_dnsvip6",     '');
		config_set_path("{$dnsbl}/pfb_dnsport",     '8081');
		config_set_path("{$dnsbl}/pfb_dnsport_ssl", '8443');
		config_set_path("{$dnsbl}/alexa_enable",    '');
		config_set_path("{$dnsbl}/pfb_cache",       '');
		config_set_path("{$dnsbl}/pfb_py_reply",    '');
		config_set_path("{$dnsbl}/pfb_regex",       '');
		config_set_path("{$dnsbl}/pfb_regex_list",  '');
		config_set_path("{$dnsbl}/pfb_cname",       '');
		config_set_path("{$dnsbl}/pfb_pytld",       '');
		config_set_path("{$dnsbl}/pfb_py_nolog",    '');
		config_set_path("{$dnsbl}/pfb_noaaaa",      '');
		config_set_path("{$dnsbl}/pfb_noaaaa_list", '');
		config_set_path("{$dnsbl}/pfb_gp",          '');
		config_set_path("{$dnsbl}/pfb_gp_bypass_list", '');

		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}
	}

	private function ensureLogDir(): void
	{
		$logdir = $GLOBALS['pfb']['logdir'];
		if (!is_dir($logdir)) {
			@mkdir($logdir, 0755, TRUE);
		}
	}

	/**
	 * Writes $expiredCount lines timestamped $expiredDaysAgo days ago,
	 * followed by $freshCount lines timestamped now, directly to $path via
	 * fwrite() (never held as one in-memory array/string) -- mirrors the
	 * 'prefix' field-mode shape ('log' type). Returns the fresh lines, in
	 * order, for the post-trim assertion.
	 *
	 * @return string[]
	 */
	private function writeLargeLogFixture(string $path, int $expiredCount, int $freshCount, int $expiredDaysAgo): array
	{
		$fh = fopen($path, 'w');
		$expiredTs = date('Y-m-d H:i:s', time() - ($expiredDaysAgo * 86400));
		for ($i = 0; $i < $expiredCount; $i++) {
			fwrite($fh, $expiredTs . ' expired-line-' . $i . "\n");
		}
		$nowTs = date('Y-m-d H:i:s');
		$freshLines = [];
		for ($i = 0; $i < $freshCount; $i++) {
			$line = $nowTs . ' fresh-line-' . $i;
			fwrite($fh, $line . "\n");
			$freshLines[] = $line;
		}
		fclose($fh);
		return $freshLines;
	}

	/**
	 * THE pinning test for issue #1012. A 200,000-line / several-MB 'log'
	 * file, all but 5 lines 40 days old (expired), 'log_max_log'='nolimit' +
	 * 'log_max_days_log' set -- the age-cutoff candidate is the WHOLE file,
	 * no line-count cap exists to shrink it first. Also covers the
	 * all-expired-leading-run case (ADR.md S2.6): the entire 199,995-line
	 * expired run must be dropped via the streaming path.
	 *
	 * Bound justification (measured this session on this machine): the old
	 * @file()-array approach costs a +24,690,688 byte (~23.5 MiB)
	 * memory_get_peak_usage(true) delta on this exact fixture; the streaming
	 * fgets()/fwrite() approach costs 0 bytes. 5 MiB sits an order of
	 * magnitude below the old cost and comfortably above the streaming
	 * overhead, cleanly separating old-code-fails from new-code-passes.
	 *
	 * Scenario:
	 *   Given log_max_log='nolimit'; log_max_days_log='30'.
	 *   And   199,995 lines 40 days old + 5 fresh lines (today).
	 *   Before: 200,000 lines.
	 *   When  pfb_log_age_trim_temp() is called with $unbounded_candidate=TRUE.
	 *   Then  only the 5 fresh lines survive AND the memory_get_peak_usage(true)
	 *         delta across the call stays under 5 MiB.
	 */
	#[RunInSeparateProcess]
	public function testStreamingTrimStaysMemoryBoundedOnLargeMostlyExpiredFile(): void
	{
		$this->seedMinimalConfig();
		$this->ensureLogDir();
		pfb_global();

		$logPath = $GLOBALS['pfb']['log'];
		// 199,995 expired + 5 fresh = 200,000 lines (>= the 150,000-line floor).
		$freshLines = $this->writeLargeLogFixture($logPath, 199995, 5, 40);

		clearstatcache(TRUE, $logPath);
		$this->assertGreaterThan(1_000_000, filesize($logPath), 'Before: fixture must be several MB');

		gc_collect_cycles();
		$memBefore = memory_get_peak_usage(TRUE);

		$ok = pfb_log_age_trim_temp($logPath, 30, 'log', TRUE);

		$memDelta = memory_get_peak_usage(TRUE) - $memBefore;

		$this->assertTrue($ok, 'the streaming trim must succeed');

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame($freshLines, $linesAfter,
			'only the 5 fresh lines must survive (the whole 199,995-line expired run dropped), got '
			. count($linesAfter) . ' lines'
		);

		$this->assertLessThan(5 * 1024 * 1024, $memDelta,
			"streaming trim's memory_get_peak_usage(true) delta must stay under 5 MiB on a 200k-line file, got {$memDelta} bytes"
		);
	}

	/**
	 * Streaming I/O failure gating, branch 1: $temp does not exist at all --
	 * fopen($temp, 'r') fails -- the streaming helper must return FALSE
	 * without touching anything (there is nothing to touch).
	 */
	public function testStreamingHelperFailsWhenTempFileMissing(): void
	{
		$this->seedMinimalConfig();
		$this->ensureLogDir();
		pfb_global();

		$missing = $GLOBALS['pfb']['logdir'] . '/does-not-exist-' . uniqid() . '.log';
		$this->assertFileDoesNotExist($missing, 'Before: the path must not exist');

		$ok = pfb_log_age_trim_temp($missing, 30, 'log', TRUE);

		$this->assertFalse($ok, 'a missing $temp must make the streaming trim return FALSE');
		$this->assertFileDoesNotExist($missing, 'a failed trim must never create $temp');
	}

	/**
	 * Streaming I/O failure gating, branch 2: $temp's directory is read-only.
	 * Probed this session: tempnam()/fopen($scratch,'w') do NOT fail here --
	 * tempnam() silently falls back to the system temp dir -- so the failure
	 * actually surfaces at the final rename($scratch, $temp) (destination dir
	 * not writable). Still proves the same contract: FALSE returned, $temp
	 * byte-for-byte untouched, and the now-orphaned-directory scratch file
	 * cleaned up. Root bypasses directory permissions, so this cannot be
	 * simulated there (mirrors testFailedCatNeverCorruptsLiveLogEvenWithAgeCutoffActive).
	 */
	public function testStreamingHelperFailsAndLeavesTempUntouchedWhenDestinationDirReadOnly(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses directory permissions; cannot simulate an unwritable scratch dir');
		}

		$this->seedMinimalConfig();
		$this->ensureLogDir();
		pfb_global();

		$roDir = $GLOBALS['pfb']['logdir'] . '/ro-' . uniqid();
		mkdir($roDir, 0755);
		$temp = $roDir . '/candidate.log';
		$content = date('Y-m-d H:i:s') . " fresh line\n";
		file_put_contents($temp, $content);
		chmod($roDir, 0555);

		try {
			$ok = pfb_log_age_trim_temp($temp, 30, 'log', TRUE);

			$this->assertFalse($ok, 'a read-only destination dir must make the streaming trim return FALSE');
			clearstatcache(TRUE, $temp);
			$this->assertSame($content, file_get_contents($temp),
				'a failed rename() back onto $temp must leave it byte-for-byte untouched'
			);
		} finally {
			chmod($roDir, 0755);
		}
	}
}
