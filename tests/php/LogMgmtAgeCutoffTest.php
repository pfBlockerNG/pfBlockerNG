<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
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
 *     - testFieldZeroModeNolimitAgeCutoffTrimsIpBlocklog      (field0, streaming)
 *     - testFieldOneModeAgeCutoffTrimsDnslog                  (field1, also
 *       exercises the chroot-branch code path -- chroot dir absent on this
 *       runner, so it falls back to the host path per LogRotateResetTest's
 *       established note)
 *     - testFieldOneModeNolimitAgeCutoffTrimsDnslog           (field1, streaming)
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
		config_set_path("{$dnsbl}/top1m_enable",    '');
		config_set_path("{$dnsbl}/pfb_cache",       '');
		config_set_path("{$dnsbl}/pfb_py_reply",    '');
		config_set_path("{$dnsbl}/pfb_regex",       '');
		config_set_path("{$dnsbl}/pfb_regex_list",  '');
		config_set_path("{$dnsbl}/pfb_cname",       '');
		config_set_path("{$dnsbl}/tld_allow",       '');
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

	/** Set the GLOBAL hysteresis margin percent (issue #1109; applies to every log type). */
	private function setMarginPct(string $pct): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct', $pct);
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
		$mtimeBefore = time() - 3600;
		touch($logPath, $mtimeBefore);
		clearstatcache(TRUE, $logPath);
		$this->assertSame($mtimeBefore, filemtime($logPath), 'before: forced mtime must take');

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
	 * Issue #1052 coverage row "first-line expired (run)": the first line
	 * ($old1) is expired, so the pass must still run -- the sibling pin for
	 * testNolimitWithAgeSetSkipsPassWhenFirstLineIsFresh below.
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
	 * Issue #1052, coverage row "first-line fresh (skip)": lines are
	 * chronologically appended, so an unexpired FIRST line means nothing in
	 * the file can be expired -- the whole copy()+age-trim pass must be
	 * SKIPPED this tick, not just a no-op trim of an untouched candidate.
	 * RED-PROVABLE: pre-fix code @copy()s + cat-overwrites the live log
	 * every idle tick regardless, which rewrites (and would bump) the mtime.
	 *
	 * Scenario:
	 *   Given log_max_log='nolimit'; log_max_days_log='30'.
	 *   And   5 lines, ALL fresh (today) -- the first line is nowhere near
	 *         expired.
	 *   Before: 5 lines; mtime M.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  content AND mtime are BOTH unchanged (the pass never ran).
	 */
	public function testNolimitWithAgeSetSkipsPassWhenFirstLineIsFresh(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', 'nolimit', '30');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$content = implode("\n", [
			$this->now() . ' a',
			$this->now() . ' b',
			$this->now() . ' c',
			$this->now() . ' d',
			$this->now() . ' e',
		]) . "\n";
		file_put_contents($logPath, $content);
		$mtimeBefore = time() - 3600;
		touch($logPath, $mtimeBefore);
		clearstatcache(TRUE, $logPath);
		$this->assertSame($mtimeBefore, filemtime($logPath), 'before: forced mtime must take');

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			'a fresh-first-line nolimit+age-cap file must be byte-identical (whole pass skipped)'
		);
		$this->assertSame($mtimeBefore, filemtime($logPath),
			'a fresh-first-line nolimit+age-cap file must not even be rewritten (mtime unchanged) -- '
			. 'the copy()+cat pass must be skipped entirely, not run as a no-op'
		);
	}

	/**
	 * Issue #1052, coverage row "first-line unparseable-legacy (run)": an
	 * unparseable FIRST line must NOT trigger the skip -- the probe falls
	 * through to "pass needed" so the legacy line is still correctly dropped
	 * (S2.2 "unparseable = expired"), matching pre-#1052 behaviour exactly.
	 *
	 * Scenario:
	 *   Given log_max_log='nolimit'; log_max_days_log='30'.
	 *   And   1 legacy line (no timestamp) + 2 fresh ISO lines.
	 *   Before: 3 lines.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  only the 2 fresh lines survive (the pass ran, dropping the legacy line).
	 */
	public function testNolimitWithAgeSetStillRunsWhenFirstLineIsUnparseableLegacy(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', 'nolimit', '30');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$legacy = 'pre-ADR-60 legacy line, no timestamp';
		$fresh1 = $this->now() . ' fresh-one';
		$fresh2 = $this->now() . ' fresh-two';
		file_put_contents($logPath, implode("\n", [$legacy, $fresh1, $fresh2]) . "\n");

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame([$fresh1, $fresh2], $linesAfter,
			'an unparseable legacy first line must not skip the pass -- only it gets dropped, got '
			. var_export($linesAfter, TRUE)
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
	 * Empty file, NOLIMIT (issue #1012): testEmptyFileStaysEmpty above only
	 * exercises the DEFAULT/bounded '20000' line-cap path -- this pins the
	 * streaming trim's empty-input case (fopen($temp,'r') on a 0-byte file,
	 * no fgets() iterations, rename empty scratch over $temp).
	 */
	public function testEmptyFileStaysEmptyUnderNolimit(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', 'nolimit', '30');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		file_put_contents($logPath, '');

		$this->assertSame(0, filesize($logPath), 'Before: file must be empty');

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame(0, filesize($logPath), 'an empty file under nolimit must stay empty, not error or grow');
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
	 * field0 mode, NOLIMIT (issue #1012): same as
	 * testFieldZeroModeAgeCutoffTrimsIpBlocklog but log_max_ip_blocklog is
	 * also 'nolimit' -- exercises the streaming trim path with field0 CSV
	 * timestamps instead of the array/@file() path.
	 */
	public function testFieldZeroModeNolimitAgeCutoffTrimsIpBlocklog(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('ip_blocklog', 'nolimit', '10');
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
			'field0 nolimit streaming trim must drop the 40-day-old CSV row, got ' . var_export($linesAfter, TRUE)
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

	/**
	 * field1 mode, NOLIMIT (issue #1012): same as
	 * testFieldOneModeAgeCutoffTrimsDnslog but log_max_dnslog is also
	 * 'nolimit' -- exercises the streaming trim path with field1 CSV
	 * timestamps, also under the chroot-branch code path.
	 */
	public function testFieldOneModeNolimitAgeCutoffTrimsDnslog(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('dnslog', 'nolimit', '10');
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
			'field1 nolimit streaming trim must drop the 40-day-old row, got ' . var_export($linesAfter, TRUE)
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

	/**
	 * Issue #1053: pfb_log_age_trim_temp()'s array path must treat a SHORT
	 * (partial, non-FALSE) file_put_contents() write as failure, not success --
	 * a genuine disk-full short write cannot be forced deterministically/
	 * portably in a unit test (same constraint documented at
	 * IpPrefetchTest's write-outcome predicate tests),
	 * so this pins the extracted write-outcome predicate directly with
	 * fabricated byte counts -- the "testable shape" fallback for an
	 * unforceable OS failure. The predicate is new code: it does not exist
	 * pre-fix (calling it errors on the old source), so red<->green here is
	 * "did not exist" -> "exists and rules correctly" for every input shape.
	 */
	public function testAgeTrimWriteOkFlagsAShortWriteAsIncomplete(): void
	{
		$content = "line-one\nline-two\n";

		$short = pfb_log_age_trim_write_ok(strlen($content) - 3, $content);
		$this->assertFalse($short, 'expected a short byte count to be flagged as an incomplete write');

		$failed = pfb_log_age_trim_write_ok(FALSE, $content);
		$this->assertFalse($failed, 'expected FALSE to be flagged as an incomplete write');

		$complete = pfb_log_age_trim_write_ok(strlen($content), $content);
		$this->assertTrue($complete, 'expected an exact full-length write to be flagged as complete');
	}

	// -----------------------------------------------------------------------
	// issue #1109 -- pfb_log_trim_margin_pct hysteresis, wired through the
	// real pfb_log_mgmt() on both the plain and chroot-fallback branches.
	// -----------------------------------------------------------------------

	/**
	 * RED->GREEN PROOF (line-cap hysteresis, plain branch): a file at 1.2x its
	 * numeric line cap, margin=50 (high-water=1.5x), must be left untouched.
	 *
	 * Fails pre-#1109: today's code has no margin concept and always
	 * tail -n's a numeric cap unconditionally -- 12 lines would be cut to 10.
	 *
	 * Scenario:
	 *   Given log_max_log='10'; pfb_log_trim_margin_pct='50'.
	 *   And   12 lines (1.2x cap, under the 1.5x high-water).
	 *   Before: 12 lines; inode = I.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  content is BYTE-IDENTICAL (still 12 lines) and inode is unchanged.
	 */
	public function testMarginHysteresisSkipsLineCapTrimWithinHighWaterPlainBranch(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '10', '0');
		$this->setMarginPct('50');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$lines = [];
		for ($i = 0; $i < 12; $i++) {
			$lines[] = "l{$i}";
		}
		$content = implode("\n", $lines) . "\n";
		file_put_contents($logPath, $content);
		$inodeBefore = fileinode($logPath);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			'12 lines (1.2x a 10-line cap) under the 1.5x margin high-water must be left byte-identical'
		);
		$this->assertSame($inodeBefore, fileinode($logPath), 'inode must be unchanged when the pass is skipped');
	}

	/**
	 * Same proof as above on the CHROOT-fallback branch ('dnslog') -- Matrix
	 * row E: every behavioural row exercised through both pfb_log_mgmt()
	 * branches (chroot dir absent off-appliance -> falls back to the host
	 * path, per LogRotateResetTest's established note).
	 */
	public function testMarginHysteresisSkipsLineCapTrimWithinHighWaterChrootBranch(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('dnslog', '10', '0');
		$this->setMarginPct('50');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('dnslog');
		$lines = [];
		for ($i = 0; $i < 12; $i++) {
			$lines[] = 'DNSBL-python,' . $this->now() . ",d{$i}.example.com,127.0.0.1,Python,Block,Feed,eval,feed,+,A";
		}
		$content = implode("\n", $lines) . "\n";
		file_put_contents($logPath, $content);
		$inodeBefore = fileinode($logPath);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			'chroot branch: 12 rows (1.2x a 10-row cap) under the 1.5x margin high-water must be byte-identical'
		);
		$this->assertSame($inodeBefore, fileinode($logPath), 'inode must be unchanged when the pass is skipped');
	}

	/**
	 * Pinning companion (NOT a red proof -- pre-#1109 code already tails a
	 * numeric cap to the exact count unconditionally, so this result is
	 * unchanged before/after): once the high-water fires, the LOW-WATER cut
	 * is still exact -- 16 lines (1.6x cap, over the 1.5x high-water) trim
	 * down to precisely the 10-line cap, not to 15.
	 */
	public function testMarginHysteresisFiresLineCapTrimOverHighWaterCutsToExactCapPlainBranch(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '10', '0');
		$this->setMarginPct('50');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$lines = [];
		for ($i = 0; $i < 16; $i++) {
			$lines[] = "l{$i}";
		}
		file_put_contents($logPath, implode("\n", $lines) . "\n");

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(array_slice($lines, 6), $linesAfter,
			'16 lines over the 1.5x high-water must cut to EXACTLY the 10-line cap (low-water), got '
			. var_export($linesAfter, TRUE)
		);
	}

	/**
	 * RED->GREEN PROOF (age-cap hysteresis, plain branch): 'nolimit' + an age
	 * cap, head past the cap but inside the margin-widened window, must be
	 * left untouched.
	 *
	 * Fails pre-#1109: the pre-rename #1052 probe ignores margin -- a
	 * 12-day-old head past a 10-day cap is judged expired, the pass runs,
	 * and the old line is dropped.
	 *
	 * Scenario:
	 *   Given log_max_log='nolimit'; log_max_days_log='10'; margin='50' (window=15d).
	 *   And   1 line 12 days old (past cap, inside window) + 1 fresh line.
	 *   Before: 2 lines.
	 *   When  pfb_log_mgmt() is called.
	 *   Then  content is BYTE-IDENTICAL (both lines survive).
	 */
	public function testMarginHysteresisSkipsAgeCapTrimWithinWindowPlainBranch(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', 'nolimit', '10');
		$this->setMarginPct('50');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$old = $this->daysAgo(12) . ' still-in-window';
		$new = $this->now() . ' fresh';
		$content = $old . "\n" . $new . "\n";
		file_put_contents($logPath, $content);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			'a 12-day-old head (age-cap=10d, margin=50 -> window=15d) must be left byte-identical'
		);
	}

	/** Same proof as above on the CHROOT-fallback branch ('dnslog'). */
	public function testMarginHysteresisSkipsAgeCapTrimWithinWindowChrootBranch(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('dnslog', 'nolimit', '10');
		$this->setMarginPct('50');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('dnslog');
		$old = 'DNSBL-python,' . $this->daysAgo(12) . ',old.example.com,127.0.0.1,Python,Block,Feed,eval,feed,+,A';
		$new = 'DNSBL-python,' . $this->now()       . ',new.example.com,127.0.0.1,Python,Block,Feed,eval,feed,+,A';
		$content = $old . "\n" . $new . "\n";
		file_put_contents($logPath, $content);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			'chroot branch: a 12-day-old head within the margin window must be left byte-identical'
		);
	}

	/**
	 * Pinning companion (NOT a red proof -- pre-#1109 code already drops a
	 * head past the exact cap; a head past the WIDENED window is past the
	 * exact cap too, so this result is unchanged before/after): a head
	 * beyond the 1.5x window still fires and is dropped.
	 */
	public function testMarginHysteresisFiresAgeCapTrimBeyondWindowPlainBranch(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', 'nolimit', '10');
		$this->setMarginPct('50');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$old = $this->daysAgo(20) . ' past-window';
		$new = $this->now() . ' fresh';
		file_put_contents($logPath, $old . "\n" . $new . "\n");

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame([$new], $linesAfter,
			'a 20-day-old head beyond the 15-day window must still be dropped, got ' . var_export($linesAfter, TRUE)
		);
	}

	/**
	 * RED->GREEN PROOF (the elision itself -- headline row): a file already
	 * within its numeric cap, margin='0', no age cap, must not even be
	 * REWRITTEN this tick -- asserted via mtime (a rewrite bumps it to now)
	 * so the proof cannot pass on today's code (unconditional rewrite) and
	 * cannot flake on sub-second timing (an old, force-set mtime is compared
	 * for exact equality, never a "did it change recently" window).
	 *
	 * Scenario:
	 *   Given log_max_log='10'; log_max_days_log unset (0, off); margin='0'.
	 *   And   5 lines (under cap); mtime forced to 1 hour ago.
	 *   Before: mtime = M (1h ago).
	 *   When  pfb_log_mgmt() is called.
	 *   Then  mtime is STILL M and content is byte-identical (pass never ran).
	 */
	public function testMarginElisionLeavesFileUntouchedIncludingMtime(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '10', '0');
		$this->setMarginPct('0');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$content = "l0\nl1\nl2\nl3\nl4\n";
		file_put_contents($logPath, $content);
		$forcedMtime = time() - 3600;
		touch($logPath, $forcedMtime);
		clearstatcache(TRUE, $logPath);
		$this->assertSame($forcedMtime, filemtime($logPath), 'before: forced mtime must take');

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath), 'content must be byte-identical (pass never ran)');
		$this->assertSame($forcedMtime, filemtime($logPath),
			'a file already within its cap must not even be rewritten (mtime unchanged) -- '
			. 'today\'s code rewrites unconditionally and would bump this to "now"'
		);
	}

	/**
	 * Scenario: a log left ending mid-line still gets the trim it is owed.
	 *
	 * Given a log whose last line is unterminated (no trailing newline) -- the state
	 *   pfb_logger('.', 1)'s sub-line progress fragments leave behind, and exactly what
	 *   pfb_logger_target_starts_at_bol() exists to detect,
	 * When  it sits one line over its line cap at margin=0,
	 * Then  the trim FIRES and cuts to the same content tail(1) itself would keep.
	 *
	 * The high-water guard gates a tail(1) rewrite, so it must count lines the way
	 * tail does: an unterminated trailing chunk IS a line. Counting bare "\n" bytes
	 * undercounts by one, the guard reads "at cap" instead of "over cap", and the
	 * needed trim is silently skipped -- the log overshoots its cap (#1109).
	 */
	public function testDanglingLastLineStillTrimsToTailsOwnResult(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '5', '0');
		$this->setMarginPct('0');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		// 5 newline-terminated lines + a 6th, unterminated -- tail(1) sees SIX lines.
		file_put_contents($logPath, "l1\nl2\nl3\nl4\nl5\nDANGLING");

		// The oracle is the real write path: whatever `tail -n 5` keeps is what the
		// trim must leave behind. Captured BEFORE the trim overwrites the file.
		$expected = shell_exec('/usr/bin/tail -n 5 ' . escapeshellarg($logPath));
		$this->assertStringNotContainsString('l1', (string) $expected,
			'before: tail -n 5 must already be dropping l1 -- else this fixture proves nothing'
		);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$after = file_get_contents($logPath);
		$this->assertSame($expected, $after,
			'a log ending mid-line must be trimmed to exactly what tail(1) keeps -- '
			. 'counting only "\n" bytes undercounts the dangling line and skips the trim'
		);
		$this->assertStringNotContainsString('l1', (string) $after, 'the over-cap head line must be gone');
		$this->assertStringContainsString('DANGLING', (string) $after, 'the unterminated tail line must survive');
	}

	/**
	 * Mandatory hostile row: an unclamped absurd log_max_log value (numeric
	 * but saturates pfb_log_max_lines() to PHP_INT_MAX) combined with a
	 * margin must never crash pfb_log_mgmt() (the intdiv()-on-float TypeError
	 * trap the float-math design in pfb_log_trim_needed() avoids) and must
	 * leave a normal-sized file untouched.
	 */
	public function testOversizedLogMaxWithMarginDoesNotCrash(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '99999999999999999999999999999999', '0');
		$this->setMarginPct('50');
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$content = "l0\nl1\nl2\nl3\nl4\n";
		file_put_contents($logPath, $content);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			'an absurd log_max_log value with a margin set must not crash, and must not touch a normal file'
		);
	}

	/**
	 * #1143 TypeError-class hostile row: an array raw config value for
	 * pfb_log_trim_margin_pct (a crafted/corrupted config.xml) must parse to
	 * 0 (is_scalar() guard) and must not crash pfb_log_mgmt() with a
	 * TypeError. Bypasses the normal string-write path to inject the array
	 * directly at the raw config path, as a hostile config.xml would.
	 */
	public function testMarginConfigValueAsArrayDoesNotCrash(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '10', '0');
		config_set_path('installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct', ['50']);
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$content = "l0\nl1\nl2\nl3\nl4\n";
		file_put_contents($logPath, $content);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			'an array pfb_log_trim_margin_pct value must parse to 0 and must not crash pfb_log_mgmt()'
		);
	}

	// -----------------------------------------------------------------------
	// issue #1258 -- end-to-end proof that a hostile pfb_log_trim_margin_pct
	// config value can no longer reach the guards unclamped, on BOTH
	// pfb_log_mgmt() branches. Age cap left OFF (0) so only the line-cap
	// guard's own high-water math is in play; content stays well under cap.
	// -----------------------------------------------------------------------

	public static function hostileMarginConfigValues(): array
	{
		return [
			'oversized numeric (PHP_INT_MAX)' => [(string) PHP_INT_MAX],
			'oversized numeric (999999999)'   => ['999999999'],
			'negative'                        => ['-5'],
		];
	}

	#[DataProvider('hostileMarginConfigValues')]
	public function testHostileMarginConfigValueDoesNotCrashPlainBranch(string $marginRaw): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('log', '10', '0');
		$this->setMarginPct($marginRaw);
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('log');
		$content = "l0\nl1\nl2\nl3\nl4\n"; // 5 lines, well under the 10-line cap
		file_put_contents($logPath, $content);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			"a hostile pfb_log_trim_margin_pct ('{$marginRaw}') must not crash pfb_log_mgmt() and must not wipe a within-cap log"
		);
	}

	#[DataProvider('hostileMarginConfigValues')]
	public function testHostileMarginConfigValueDoesNotCrashChrootBranch(string $marginRaw): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('dnslog', '10', '0');
		$this->setMarginPct($marginRaw);
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('dnslog');
		$lines = [];
		for ($i = 0; $i < 3; $i++) {
			$lines[] = 'DNSBL-python,' . $this->now() . ",d{$i}.example.com,127.0.0.1,Python,Block,Feed,eval,feed,+,A";
		}
		$content = implode("\n", $lines) . "\n"; // 3 rows, well under the 10-row cap
		file_put_contents($logPath, $content);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			"chroot branch: a hostile pfb_log_trim_margin_pct ('{$marginRaw}') must not crash and must not wipe a within-cap log"
		);
	}

	/** Chroot-branch companion to testMarginConfigValueAsArrayDoesNotCrash() (plain branch only). */
	public function testHostileArrayMarginConfigValueDoesNotCrashChrootBranch(): void
	{
		$this->seedMinimalConfig();
		$this->setLogCaps('dnslog', '10', '0');
		config_set_path('installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct', ['50']);
		$this->ensureLogDir();
		pfb_global();

		$logPath = $this->logPath('dnslog');
		$lines = [];
		for ($i = 0; $i < 3; $i++) {
			$lines[] = 'DNSBL-python,' . $this->now() . ",d{$i}.example.com,127.0.0.1,Python,Block,Feed,eval,feed,+,A";
		}
		$content = implode("\n", $lines) . "\n";
		file_put_contents($logPath, $content);

		pfb_log_mgmt();

		clearstatcache(TRUE, $logPath);
		$this->assertSame($content, file_get_contents($logPath),
			'chroot branch: an array pfb_log_trim_margin_pct value must parse to 0 and must not crash pfb_log_mgmt()'
		);
	}
}
