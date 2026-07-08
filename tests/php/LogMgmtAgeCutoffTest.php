<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-60 Phase 6 -- pfb_log_mgmt()'s age-based retention cap (log_max_days_<type>).
 *
 * Drives the REAL pfb_log_mgmt() against real temp files under the bootstrap
 * sandbox ($pfb[$logtype] paths, set once at pfblockerng.inc load time from
 * $g['varlog_path'] -- see tests/php/bootstrap.php), mirroring
 * LogRotateResetTest.php's established Part B pattern: no setUp()/tearDown(),
 * each test seeds $GLOBALS['config'] fresh and writes its OWN full file
 * content before acting, so tests are self-encapsulated despite sharing the
 * same on-disk paths (PHPUnit runs sequentially).
 *
 * Coverage (ADR.md S2.5 "log_max_<type> x log_max_days_<type>" + S2.6 hostile
 * rows, all against the 'log' type (prefix field-mode) unless noted):
 *
 *   Matrix (S2.5) -- log_max_<type> is either left at its registry default
 *   (20000 -- "off": no effective line-count reduction on these small
 *   fixtures) or explicitly 'nolimit' or a small numeric cap ("set"):
 *     - testDefaultsOnBothCapsIsByteIdenticalNoOp            (off  x off)
 *     - testAgeOnlyTrimEngagesWhenLineCapIsEffectivelyOff    (off  x set)
 *     - testNolimitWithAgeOffLeavesFileEntirelyUntouched     (nolimit x off)
 *     - testNolimitWithAgeSetStillTrimsByAge                 (nolimit x set -- the independence fix)
 *     - testSetLineCapOnlyTrimUnaffectedByNonTimestampedLines(set  x off)
 *     - testSetSetAgeCutoffTighterThanLineCount               (set x set, age wins)
 *     - testSetSetLineCountTighterThanAgeCutoff               (set x set, line-count wins)
 *
 *   Hostile-input rows (S2.6), integration-level (pure-parser-level coverage
 *   lives in LogAgeCutoffTest.php):
 *     - testEmptyFileStaysEmpty
 *     - testRealisticUpgradeMixedLegacyAndNewFormatLines
 *     - testNonNumericLogMaxDaysConfigValueIsTreatedAsOff
 *     - testOversizedLogMaxDaysConfigValueDoesNotCrash
 *
 *   Per-type field-position wiring (at least one per DISTINCT field mode --
 *   'log' above covers 'prefix'; these cover the other two):
 *     - testFieldZeroModeAgeCutoffTrimsIpBlocklog             (field0)
 *     - testFieldOneModeAgeCutoffTrimsDnslog                  (field1, also
 *       exercises the chroot-branch code path -- chroot dir absent on this
 *       runner, so it falls back to the host path per LogRotateResetTest's
 *       established note)
 *
 *   Inode + ownership: fileinode() before/after in the tail-based path (the
 *   'set x set' tests above) AND the 'nolimit'-with-age copy()-based path
 *   (testNolimitWithAgeSetStillTrimsByAge) -- both code paths that write the
 *   live log must preserve the inode.
 *
 *   Failure gating: testFailedCatNeverCorruptsLiveLogEvenWithAgeCutoffActive.
 */
final class LogMgmtAgeCutoffTest extends TestCase
{
	/**
	 * Seed the minimum config keys pfb_global() reads (mirrors
	 * LogRotateResetTest::seedConfigForReset() -- avoids undefined-array-key
	 * warnings against a near-empty test config). Resets $GLOBALS['config']
	 * so each test starts from a clean slate regardless of run order.
	 */
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

	/** Set BOTH caps for one log type (leave unset for the registry default). */
	private function setLogCaps(string $logtype, string $maxLines, string $maxDays): void
	{
		$gen = 'installedpackages/pfblockerng/config/0';
		config_set_path("{$gen}/log_max_{$logtype}", $maxLines);
		config_set_path("{$gen}/log_max_days_{$logtype}", $maxDays);
	}

	private function logPath(string $logtype): string
	{
		return $GLOBALS['pfb'][$logtype];
	}

	private function ensureLogDir(): void
	{
		$logdir = $GLOBALS['pfb']['logdir'];
		if (!is_dir($logdir)) {
			@mkdir($logdir, 0755, TRUE);
		}
	}

	private function daysAgo(int $days): string
	{
		return date('Y-m-d H:i:s', time() - ($days * 86400));
	}

	private function now(): string
	{
		return date('Y-m-d H:i:s', time());
	}

	// -----------------------------------------------------------------------
	// S2.5 coverage matrix -- log_max_log x log_max_days_log (type 'log', prefix mode)
	// -----------------------------------------------------------------------

	/**
	 * off x off: neither cap configured (registry defaults: log_max_log=20000,
	 * log_max_days_log='0'). Must be BYTE-IDENTICAL to pre-ADR-60 behaviour --
	 * asserts full file content equality, not just line count.
	 *
	 * Scenario:
	 *   Given neither log_max_log nor log_max_days_log is configured.
	 *   And   a 3-line 'log' file (non-timestamped content -- proves the age
	 *         path never even attempts to parse these when off).
	 *   Before: file has its 3 original lines.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  the file content is BYTE-IDENTICAL to before.
	 */
	public function testDefaultsOnBothCapsIsByteIdenticalNoOp(): void
	{
		$this->seedMinimalConfig();
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$content = "l1\nl2\nl3\n";
		file_put_contents($logPath, $content);

		$before = file_get_contents($logPath);
		$this->assertSame($content, $before, 'Before: seeded content must match exactly');

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$after = file_get_contents($logPath);
		$this->assertSame($content, $after,
			'off x off must be byte-identical to the pre-ADR-60 no-op: got ' . var_export($after, TRUE)
		);
	}

	/**
	 * off x set: log_max_log left at its default (no effective line-count
	 * reduction on this 4-line fixture); log_max_days_log='30' -- the
	 * age-only trim engages independently.
	 *
	 * RED->GREEN PROOF TEST (see handoff): fails against pre-Phase-6
	 * pfb_log_mgmt() (no age concept at all -- all 4 lines would survive).
	 *
	 * Scenario:
	 *   Given log_max_days_log='30'; log_max_log unset (default 20000).
	 *   And   2 lines 40 days old + 2 lines from today.
	 *   Before: 4 lines present.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  only the 2 fresh lines survive (both 40-day-old lines dropped).
	 */
	public function testAgeOnlyTrimEngagesWhenLineCapIsEffectivelyOff(): void
	{
		$this->seedMinimalConfig();
		$gen = 'installedpackages/pfblockerng/config/0';
		config_set_path("{$gen}/log_max_days_log", '30');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$old1 = $this->daysAgo(40) . ' old-one';
		$old2 = $this->daysAgo(40) . ' old-two';
		$new1 = $this->now() . ' new-one';
		$new2 = $this->now() . ' new-two';
		file_put_contents($logPath, implode("\n", [$old1, $old2, $new1, $new2]) . "\n");

		$linesBefore = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertCount(4, $linesBefore, 'Before: must have 4 lines');

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame([$new1, $new2], $linesAfter,
			'After: only the 2 fresh lines must survive the age-only trim, got ' . var_export($linesAfter, TRUE)
		);
	}

	/**
	 * nolimit x off: today's opt-out, unchanged -- the file is left ENTIRELY
	 * untouched (matches the early-continue guard: neither cap is active).
	 *
	 * Scenario:
	 *   Given log_max_log='nolimit'; log_max_days_log='0'.
	 *   And   a 5-line file (mixed ages, irrelevant since nothing should run).
	 *   Before: 5 lines, mtime M.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  content AND mtime are unchanged (file never touched).
	 */
	public function testNolimitWithAgeOffLeavesFileEntirelyUntouched(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', 'nolimit', '0');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$content = implode("\n", [
			$this->daysAgo(40) . ' a',
			$this->daysAgo(1)  . ' b',
			$this->now()       . ' c',
			$this->now()       . ' d',
			$this->now()       . ' e',
		]) . "\n";
		file_put_contents($logPath, $content);
		$mtimeBefore = filemtime($logPath);

		// A real filesystem mtime tick so an accidental touch would be visible.
		usleep(1_100_000);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			'nolimit x off must leave content byte-identical (today\'s unchanged opt-out)'
		);
		$this->assertSame($mtimeBefore, filemtime($logPath),
			'nolimit x off must not even rewrite the file (mtime unchanged)'
		);
	}

	/**
	 * nolimit x set -- THE INDEPENDENCE FIX: 'nolimit' opts out of the
	 * LINE-COUNT step only; the age cap still trims. Exercises the
	 * copy()-based whole-file candidate path (no tail(1) step at all).
	 *
	 * Scenario:
	 *   Given log_max_log='nolimit'; log_max_days_log='30'.
	 *   And   2 lines 40 days old + 2 lines from today (well under any
	 *         conceivable line cap, proving 'nolimit' truly means no
	 *         line-count limit while age still applies).
	 *   Before: 4 lines; inode = I.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  only the 2 fresh lines survive AND inode is unchanged.
	 */
	public function testNolimitWithAgeSetStillTrimsByAge(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', 'nolimit', '30');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$old1 = $this->daysAgo(40) . ' old-one';
		$old2 = $this->daysAgo(40) . ' old-two';
		$new1 = $this->now() . ' new-one';
		$new2 = $this->now() . ' new-two';
		file_put_contents($logPath, implode("\n", [$old1, $old2, $new1, $new2]) . "\n");

		$inodeBefore = fileinode($logPath);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame([$new1, $new2], $linesAfter,
			"'nolimit' must still respect the age cap (independence fix), got " . var_export($linesAfter, TRUE)
		);
		$this->assertSame($inodeBefore, fileinode($logPath),
			'the copy()-based nolimit+age path must preserve the inode (in-place cat-over)'
		);
	}

	/**
	 * set x off: line-count-only trim, unchanged from pre-ADR-60 behaviour.
	 * Uses NON-timestamped content ('l1'..'l5') to prove the age-cutoff parser
	 * is never even invoked when log_max_days_log='0' -- if the '0'-is-off
	 * guard were broken, these unparseable lines would ALL be dropped as
	 * "expired", which would fail this test immediately.
	 *
	 * Scenario:
	 *   Given log_max_log='3'; log_max_days_log='0'.
	 *   And   a 5-line file with no timestamps at all.
	 *   Before: 5 lines.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  the last 3 lines survive (line-count trim only).
	 */
	public function testSetLineCapOnlyTrimUnaffectedByNonTimestampedLines(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '3', '0');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
			'set x off must trim by line-count only, ignoring the (unparseable) content entirely'
		);
	}

	/**
	 * set x set, AGE TIGHTER: tail -n 4 alone would keep 4 lines, but the
	 * 10-day age cutoff further drops 2 of those 4 (they are 20 days old) --
	 * proving age wins when it is the more restrictive cap.
	 *
	 * Scenario:
	 *   Given log_max_log='4'; log_max_days_log='10'.
	 *   And   6 lines: 2 at 40 days, 2 at 20 days, 2 fresh (today).
	 *   Before: 6 lines; inode = I.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  tail -n 4 would keep [20d,20d,fresh,fresh] (4 lines) but the
	 *         10-day age cutoff further drops the two 20-day-old lines --
	 *         only the 2 fresh lines survive. Inode unchanged.
	 */
	public function testSetSetAgeCutoffTighterThanLineCount(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '4', '10');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$veryOld1 = $this->daysAgo(40) . ' very-old-one';
		$veryOld2 = $this->daysAgo(40) . ' very-old-two';
		$mid1     = $this->daysAgo(20) . ' mid-one';
		$mid2     = $this->daysAgo(20) . ' mid-two';
		$new1     = $this->now()       . ' new-one';
		$new2     = $this->now()       . ' new-two';
		file_put_contents($logPath, implode("\n", [$veryOld1, $veryOld2, $mid1, $mid2, $new1, $new2]) . "\n");

		$inodeBefore = fileinode($logPath);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame([$new1, $new2], $linesAfter,
			'age cutoff must drop the 20-day-old lines the line-count cap alone would have kept, got '
			. var_export($linesAfter, TRUE)
		);
		$this->assertSame($inodeBefore, fileinode($logPath), 'inode must be unchanged (in-place)');
	}

	/**
	 * set x set, LINE-COUNT TIGHTER: tail -n 2 keeps the last 2 lines, both
	 * of which are already well within the 30-day age window -- the age
	 * cutoff removes nothing further, proving line-count wins when IT is the
	 * more restrictive cap.
	 *
	 * Scenario:
	 *   Given log_max_log='2'; log_max_days_log='30'.
	 *   And   4 fresh (today) lines.
	 *   Before: 4 lines.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  exactly the last 2 lines survive (age removes nothing further).
	 */
	public function testSetSetLineCountTighterThanAgeCutoff(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '2', '30');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$a = $this->now() . ' a';
		$b = $this->now() . ' b';
		$c = $this->now() . ' c';
		$d = $this->now() . ' d';
		file_put_contents($logPath, implode("\n", [$a, $b, $c, $d]) . "\n");

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame([$c, $d], $linesAfter,
			'line-count cap must win (all tail-kept lines are within the age window), got '
			. var_export($linesAfter, TRUE)
		);
	}

	// -----------------------------------------------------------------------
	// S2.6 hostile-input rows (integration level)
	// -----------------------------------------------------------------------

	/**
	 * Empty file stays empty (age cutoff active).
	 */
	public function testEmptyFileStaysEmpty(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '20000', '30');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		file_put_contents($logPath, '');

		$this->assertSame(0, filesize($logPath), 'Before: file must be empty');

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame(0, filesize($logPath), 'an empty file must stay empty, not error or grow');
	}

	/**
	 * Realistic upgrade scenario: a file with legacy (pre-ADR-60, unparseable)
	 * lines from before the operator opted in, followed by new-format ISO
	 * lines. Only the legacy lines are dropped (S2.2 "unparseable = expired").
	 *
	 * Scenario:
	 *   Given log_max_days_log='30'; log_max_log unset (default, no line effect).
	 *   And   2 legacy lines (no leading timestamp) + 2 fresh ISO lines.
	 *   Before: 4 lines.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  only the 2 fresh lines survive.
	 */
	public function testRealisticUpgradeMixedLegacyAndNewFormatLines(): void
	{
		$this->seedMinimalConfig();
		$gen = 'installedpackages/pfblockerng/config/0';
		config_set_path("{$gen}/log_max_days_log", '30');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$legacy1 = 'pre-ADR-60 legacy line one, no timestamp';
		$legacy2 = 'pre-ADR-60 legacy line two, no timestamp';
		$fresh1  = $this->now() . ' fresh-one';
		$fresh2  = $this->now() . ' fresh-two';
		file_put_contents($logPath, implode("\n", [$legacy1, $legacy2, $fresh1, $fresh2]) . "\n");

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame([$fresh1, $fresh2], $linesAfter,
			'a realistic upgrade must drop only the legacy lines, got ' . var_export($linesAfter, TRUE)
		);
	}

	/**
	 * A non-numeric log_max_days_log config value (operator typo / corrupted
	 * config.xml) is treated as off -- the line-count trim (if any) still
	 * applies, but no age trim happens.
	 *
	 * Scenario:
	 *   Given log_max_log='3'; log_max_days_log='garbage'.
	 *   And   5 lines, all fresh (today).
	 *   Before: 5 lines.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  the last 3 lines survive (line-count only; garbage age value ignored).
	 */
	public function testNonNumericLogMaxDaysConfigValueIsTreatedAsOff(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '3', 'garbage');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$lines = [
			$this->now() . ' l1', $this->now() . ' l2', $this->now() . ' l3',
			$this->now() . ' l4', $this->now() . ' l5',
		];
		file_put_contents($logPath, implode("\n", $lines) . "\n");

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(array_slice($lines, 2), $linesAfter,
			"a non-numeric log_max_days_log value must be treated as off (line-count only), got "
			. var_export($linesAfter, TRUE)
		);
	}

	/**
	 * Adversarial review finding (PR #1005): an oversized-but-all-digit
	 * log_max_days_<type> value used to crash pfb_log_mgmt() with an uncaught
	 * TypeError (days*86400 overflowing int into a float, rejected by
	 * pfb_log_age_cutoff()'s typed int parameter) -- aborting the whole
	 * foreach loop and leaving every subsequent log type untrimmed. Red-proof:
	 * this test crashed with "TypeError: pfb_log_age_cutoff(): Argument #2
	 * ($cutoff_ts) must be of type int, float given" against the pre-fix
	 * pfb_log_max_days() (no clamp); it must run to completion now.
	 */
	public function testOversizedLogMaxDaysConfigValueDoesNotCrash(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '3', '99999999999999999999999999999999');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$lines = [
			$this->now() . ' l1', $this->now() . ' l2', $this->now() . ' l3',
			$this->now() . ' l4', $this->now() . ' l5',
		];
		file_put_contents($logPath, implode("\n", $lines) . "\n");

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(array_slice($lines, 2), $linesAfter,
			"an oversized log_max_days_log value must not crash pfb_log_mgmt() -- line-count trim must still apply, got "
			. var_export($linesAfter, TRUE)
		);
	}

	// -----------------------------------------------------------------------
	// Per-type field-position wiring -- field0 and field1 (prefix already
	// covered by every 'log' test above).
	// -----------------------------------------------------------------------

	/**
	 * field0 mode ('ip_blocklog'): the timestamp is CSV column 0. Age cutoff
	 * must correctly parse and trim by it.
	 *
	 * Scenario:
	 *   Given log_max_days_ip_blocklog='10'; log_max_ip_blocklog unset (no
	 *         line-count effect).
	 *   And   1 CSV row 40 days old + 1 CSV row from today (field 0 = ts).
	 *   Before: 2 rows.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  only the fresh row survives.
	 */
	public function testFieldZeroModeAgeCutoffTrimsIpBlocklog(): void
	{
		$this->seedMinimalConfig();
		$gen = 'installedpackages/pfblockerng/config/0';
		config_set_path("{$gen}/log_max_days_ip_blocklog", '10');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('ip_blocklog');
		$old   = $this->daysAgo(40) . ',1,em0,WAN,block,4,17,UDP,10.0.0.1,10.0.0.2,1234,53,in,US,-,-,-,-,-,+';
		$fresh = $this->now()       . ',2,em0,WAN,block,4,17,UDP,10.0.0.3,10.0.0.4,1235,53,in,US,-,-,-,-,-,+';
		file_put_contents($logPath, $old . "\n" . $fresh . "\n");

		$inodeBefore = fileinode($logPath);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame([$fresh], $linesAfter,
			'field0 age cutoff must drop the 40-day-old CSV row, got ' . var_export($linesAfter, TRUE)
		);
		$this->assertSame($inodeBefore, fileinode($logPath), 'inode must be unchanged (in-place)');
	}

	/**
	 * field1 mode ('dnslog'): field 0 is a type label ('DNSBL-python'), the
	 * timestamp is CSV column 1. Also exercises the chroot-branch code path
	 * (dnslog/dnsreplylog/unilog) -- the chroot dir is absent on this runner,
	 * so it falls back to the host path (LogRotateResetTest's established note).
	 *
	 * Scenario:
	 *   Given log_max_days_dnslog='10'; log_max_dnslog unset (no line-count effect).
	 *   And   1 row 40 days old + 1 row from today (field 0 = label, field 1 = ts).
	 *   Before: 2 rows; inode = I.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  only the fresh row survives; inode unchanged.
	 */
	public function testFieldOneModeAgeCutoffTrimsDnslog(): void
	{
		$this->seedMinimalConfig();
		$gen = 'installedpackages/pfblockerng/config/0';
		config_set_path("{$gen}/log_max_days_dnslog", '10');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('dnslog');
		$old   = 'DNSBL-python,' . $this->daysAgo(40) . ',old.example.com,127.0.0.1,Python,Block,Feed,eval,feed,+,A';
		$fresh = 'DNSBL-python,' . $this->now()       . ',new.example.com,127.0.0.1,Python,Block,Feed,eval,feed,+,A';
		file_put_contents($logPath, $old . "\n" . $fresh . "\n");

		$inodeBefore = fileinode($logPath);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame([$fresh], $linesAfter,
			'field1 age cutoff must drop the 40-day-old row, got ' . var_export($linesAfter, TRUE)
		);
		$this->assertSame($inodeBefore, fileinode($logPath), 'inode must be unchanged (in-place)');
	}

	// -----------------------------------------------------------------------
	// Failure gating -- a failed exec must never blank/corrupt the live log.
	// -----------------------------------------------------------------------

	/**
	 * A failed final cat-over-the-live-log step (permission denied) must
	 * leave the original log file byte-for-byte untouched, even with the
	 * age cutoff active (both the line-count and age steps having already
	 * "succeeded" into the temp file). Uses 'extraslog' to avoid stepping on
	 * the shared 'log' path other tests in this suite use.
	 *
	 * Root bypasses file permissions (chmod is a no-op enforcement-wise for
	 * root), so this test cannot simulate the denial there -- skipped, same
	 * guard CLAUDE.md documents for the existing chmod-based PHPUnit tests.
	 */
	public function testFailedCatNeverCorruptsLiveLogEvenWithAgeCutoffActive(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses file permissions; cannot simulate a permission-denied write');
		}

		$this->seedMinimalConfig();
		$this->setLogCaps('extraslog', '4', '10');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('extraslog');
		$content = implode("\n", [
			$this->daysAgo(40) . ' old',
			$this->now()       . ' fresh',
		]) . "\n";
		file_put_contents($logPath, $content);
		chmod($logPath, 0444);

		try {
			pfb_log_mgmt();

			clearstatcache(TRUE, $logPath);
			$this->assertSame($content, file_get_contents($logPath),
				'a failed cat-over-the-live-log step must never blank/corrupt the original content'
			);
		} finally {
			chmod($logPath, 0644);
		}
	}
}
