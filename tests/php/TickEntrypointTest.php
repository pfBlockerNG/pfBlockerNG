<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #573 — scheduled log maintenance must survive pfb_interval='Disabled'.
 *
 * pfblockerng_tick() is the ONLY scheduled path to pfb_log_mgmt()/pfb_log_reset()
 * (ADR30-1). Before this change those two calls lived at the tail of
 * pfblockerng_sync_cron(), reachable only through the tick's feed-cron dispatch,
 * itself gated on `!$cron_disabled` (pfb_interval !== 'Disabled'). A user who set
 * Update Frequency to 'Disabled' therefore silently stopped ALL scheduled log
 * trim/reset, with no warning.
 *
 * This suite drives the REAL pfblockerng_tick() entrypoint -- relocated here
 * (from the www/ dispatcher script, which is never require()'d off-appliance)
 * so it is loadable by the PHPUnit bootstrap, per ADR43-5 -- and pins that log
 * maintenance is no longer gated behind the feed-cron cadence (Cases A/B), while
 * (PR #790 review) it also stays gated OFF on a tick that itself just dispatched
 * an update pass (Case D) -- see pfb_update_pass_running() in pfblockerng.inc.
 *
 * Red→green: before this change pfblockerng_tick() existed only in
 * src/usr/local/www/pfblockerng/pfblockerng.php, a script the PHPUnit bootstrap
 * never loads -- every test below failed against the pre-change worktree with
 * "Call to undefined function pfblockerng_tick()".
 *
 * Branch coverage:
 *   Case A — pfb_interval='Disabled' (the bug): log maintenance still runs.
 *   Case B — pfb_interval numeric + feed cron NOT due (future ledger entry):
 *            log maintenance still runs -- proving it is unconditional on the
 *            feed-cron cadence, not merely re-homed behind the same due-job gate.
 *   Case C — issue #573 phase 2: the feed-cron next_due anchors to its own
 *            previous next_due (via pfb_due_ledger_mark_ran_anchored), not to
 *            wall-clock time(), so a tick that fires a fraction of a second
 *            early does not slip the schedule a full tick interval late.
 *   Case D — PR #790 review: a tick that DISPATCHES an update pass this cycle
 *            (testDispatchingTickSkipsLogMaintenanceThisTick) must skip log
 *            maintenance THAT tick -- pfb_log_mgmt()'s tail-to-temp-then-cat-over
 *            trim would otherwise race the backgrounded pass it just exec()'d.
 */
final class TickEntrypointTest extends TestCase
{
	/** Per-test private sandbox for $pfb['dbdir'] -- see setUp(). */
	private string $dbdir = '';

	/** Whether $GLOBALS['pfb']['dbdir'] was set before this test, and its value. */
	private bool $hadDbdir = FALSE;
	private mixed $originalDbdir = NULL;

	/** Whether $GLOBALS['pfb']['runlog']/['extraslog'] were set before this test, and their values. */
	private bool $hadRunlog = FALSE;
	private mixed $originalRunlog = NULL;
	private bool $hadExtraslog = FALSE;
	private mixed $originalExtraslog = NULL;

	/**
	 * Self-encapsulated (CLAUDE.md mandate): pfblockerng_tick() reads/writes the
	 * due-ledger + log-rotate marker at $pfb['dbdir'] (not injectable), a path a
	 * sibling suite (SoftwareUpdateCheckTest) also repoints at its own sandbox
	 * WITHOUT restoring the original on teardown -- so $pfb['dbdir'] cannot be
	 * trusted to reflect the bootstrap value by the time this suite runs. Give
	 * this suite its OWN private, guaranteed-empty dbdir per test instead of
	 * depending on (or wiping) whatever the shared one currently holds; restore
	 * the prior value afterwards so later suites see no side effect from this one.
	 *
	 * $pfb['runlog']/['extraslog'] get the SAME treatment (PR #790 review): a
	 * dispatching case below (a due, in-window cron/dcc/bl job) triggers a REAL
	 * exec("... >> {$pfb['runlog']|extraslog} 2>&1 &") -- the shell opens that
	 * redirect target regardless of whether /usr/local/bin/php exists on this
	 * box, so an un-repointed path would write stray content into the SHARED
	 * bootstrap sandbox log other test classes also read/write. Point both at
	 * this test's own private dbdir instead.
	 */
	protected function setUp(): void
	{
		$this->hadDbdir      = array_key_exists('dbdir', $GLOBALS['pfb'] ?? []);
		$this->originalDbdir = $GLOBALS['pfb']['dbdir'] ?? NULL;

		$this->hadRunlog      = array_key_exists('runlog', $GLOBALS['pfb'] ?? []);
		$this->originalRunlog = $GLOBALS['pfb']['runlog'] ?? NULL;

		$this->hadExtraslog      = array_key_exists('extraslog', $GLOBALS['pfb'] ?? []);
		$this->originalExtraslog = $GLOBALS['pfb']['extraslog'] ?? NULL;

		$this->dbdir = sys_get_temp_dir() . '/pfb_tick_entrypoint_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir']     = $this->dbdir;
		$GLOBALS['pfb']['runlog']    = "{$this->dbdir}/pfblockerng_run.log";
		$GLOBALS['pfb']['extraslog'] = "{$this->dbdir}/extras.log";

		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		if ($this->hadDbdir) {
			$GLOBALS['pfb']['dbdir'] = $this->originalDbdir;
		} else {
			unset($GLOBALS['pfb']['dbdir']);
		}
		if ($this->hadRunlog) {
			$GLOBALS['pfb']['runlog'] = $this->originalRunlog;
		} else {
			unset($GLOBALS['pfb']['runlog']);
		}
		if ($this->hadExtraslog) {
			$GLOBALS['pfb']['extraslog'] = $this->originalExtraslog;
		} else {
			unset($GLOBALS['pfb']['extraslog']);
		}
		$this->rrmdir($this->dbdir);
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = "{$dir}/{$entry}";
			is_dir($path) ? $this->rrmdir($path) : @unlink($path);
		}
		@rmdir($dir);
	}

	// -----------------------------------------------------------------------
	// Seeding helpers (mirrors LogRotateResetTest::seedConfigForReset() -- the
	// established minimum pfb_global() needs to run warning-free off-box).
	// -----------------------------------------------------------------------

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

	/**
	 * Seed the minimum config keys pfb_global() reads (avoids undefined-array-key
	 * warnings against a near-empty test config), the tick cadence knob under
	 * test ($rawInterval), an always-apply quiet-hours window, and a scheduled
	 * line-cap ('log') + calendar reset ('errlog') so a real tick call exercises
	 * BOTH log-maintenance functions distinguishably.
	 */
	private function seedTickPrereqs(string $rawInterval): void
	{
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

		// Tick cadence knobs under test (issue #573: 'Disabled' must not gate
		// log maintenance -- see pfblockerng_tick()).
		config_set_path("{$gen}/pfb_interval",    $rawInterval);
		config_set_path("{$gen}/pfb_quiet_hours", ''); // apply immediately, no deferral

		// pfb_log_mgmt(): cap 'log' to 3 lines; every other type stays at the
		// registry default (20000) -> no-op trim, keeping the test single-purpose.
		config_set_path("{$gen}/log_max_log", '3');

		// pfb_log_reset(): 'errlog' has a daily reset schedule; every other type
		// stays 'off' (registry default) -> no-op reset except for 'errlog'.
		config_set_path("{$gen}/log_rotate_errlog",     'daily');
		config_set_path("{$gen}/log_reset_keep_errlog", '0');
	}

	/**
	 * Write a stale (yesterday) log_rotate.last marker entry for $logtype, so
	 * pfb_log_reset() finds its daily schedule "due" (period rolled over).
	 */
	private function writeStaleMarker(string $logtype): void
	{
		$markerPath = $GLOBALS['pfb']['dbdir'] . '/log_rotate.last';
		$yesterday  = date('Y-m-d', strtotime('-1 day'));
		file_put_contents($markerPath, "{$logtype}={$yesterday}\n");
	}

	/**
	 * Seed a future (not-yet-due), non-pending ledger entry so pfblockerng_tick()
	 * does not dispatch a real exec() for $jobKey.
	 */
	private function seedFutureLedgerEntry(string $jobKey, int $now): void
	{
		pfb_due_ledger_write_entry($jobKey, [
			'last_run' => $now - 3600,
			'next_due' => $now + 3600,
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);
	}

	// -----------------------------------------------------------------------
	// Case A — the bug: pfb_interval='Disabled' must not silently stop log
	// maintenance.
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given pfb_interval='Disabled' (the feed cron is entirely gated off).
	 *   And   a 5-line 'log' file with log_max_log=3 (pfb_log_mgmt should trim it).
	 *   And   a non-empty 'errlog' file with a stale daily marker (pfb_log_reset
	 *         should clear it).
	 *   Before: 'log' has 5 lines; 'errlog' is non-empty.
	 *   When  pfblockerng_tick() is called.
	 *   Then  'log' is trimmed to its last 3 lines (pfb_log_mgmt ran).
	 *   And   'errlog' is fully cleared and its marker advanced to today
	 *         (pfb_log_reset ran) -- log maintenance survives a Disabled
	 *         Update Frequency (issue #573).
	 */
	public function testDisabledIntervalStillRunsLogMaintenance(): void
	{
		$this->seedTickPrereqs('Disabled');
		// Mirrors src/usr/local/www/pfblockerng/pfblockerng.php:63 -- the real
		// dispatcher always calls pfb_global() once before routing to any verb
		// (including 'tick'), which is what populates $pfb['enable']/['blconfig']
		// and creates $pfb['dbdir']/['logdir'] on disk.
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		// Prevent a real exec() dispatch for dcc/bl (both fail-safe "due" when
		// their ledger entry is absent); 'cron' needs no seeding here because
		// $cron_disabled short-circuits its dispatch regardless of due state.
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		$logPath    = $this->logPath('log');
		$errlogPath = $this->logPath('errlog');

		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");
		file_put_contents($errlogPath, "some error\n");
		$this->writeStaleMarker('errlog');

		// Before.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesBefore,
			"Before: expected 'log' to have 5 lines, got {$linesBefore};\n"
			. '  content=' . var_export(file_get_contents($logPath), TRUE));
		$this->assertGreaterThan(0, filesize($errlogPath),
			"Before: expected 'errlog' non-empty, got " . filesize($errlogPath) . ' bytes');

		// Act.
		pfblockerng_tick();

		// After: pfb_log_mgmt() trimmed 'log' to its last 3 lines.
		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
			"After tick with pfb_interval='Disabled': expected 'log' trimmed to [l3,l4,l5], got "
			. var_export($linesAfter, TRUE)
			. ' -- pfb_log_mgmt() must run every tick, not only when the feed cron is enabled');

		// After: pfb_log_reset() cleared 'errlog' and advanced its marker.
		clearstatcache(TRUE, $errlogPath);
		$this->assertSame(0, filesize($errlogPath),
			"After tick with pfb_interval='Disabled': expected 'errlog' fully cleared, got "
			. filesize($errlogPath) . ' bytes -- pfb_log_reset() must run every tick');

		$markerContents = (string) file_get_contents($GLOBALS['pfb']['dbdir'] . '/log_rotate.last');
		$entries        = pfb_log_rotate_marker_parse($markerContents);
		$this->assertSame(date('Y-m-d'), $entries['errlog'] ?? NULL,
			"After tick: expected 'errlog' marker advanced to today (" . date('Y-m-d') . '), got '
			. var_export($entries['errlog'] ?? NULL, TRUE));
	}

	// -----------------------------------------------------------------------
	// Case B — branch coverage: the feed cron NOT being due must not gate log
	// maintenance either (proves it is unconditional, not merely re-homed
	// behind the due-ledger check that used to gate pfblockerng_sync_cron()).
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given pfb_interval='24' (a normal numeric cadence, NOT disabled).
	 *   And   the 'cron' ledger entry is NOT due (next_due 1h in the future).
	 *   And   the same 'log'/'errlog' seeding as Case A.
	 *   Before: 'log' has 5 lines; 'errlog' is non-empty; 'cron' next_due is
	 *           1h in the future.
	 *   When  pfblockerng_tick() is called.
	 *   Then  the feed cron is NOT dispatched (its ledger entry is untouched --
	 *         no mark_ran).
	 *   And   'log' is STILL trimmed and 'errlog' STILL cleared -- log
	 *         maintenance runs regardless of whether the feed cron itself was
	 *         due this tick.
	 */
	public function testLogMaintenanceRunsEvenWhenFeedCronNotDue(): void
	{
		$this->seedTickPrereqs('24');
		// Mirrors src/usr/local/www/pfblockerng/pfblockerng.php:63 -- see the
		// sibling Case A test for why this must run before any ledger/log I/O.
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		$this->seedFutureLedgerEntry('cron', $now);
		$this->seedFutureLedgerEntry('dcc',  $now);
		$this->seedFutureLedgerEntry('bl',   $now);

		$logPath    = $this->logPath('log');
		$errlogPath = $this->logPath('errlog');

		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");
		file_put_contents($errlogPath, "some error\n");
		$this->writeStaleMarker('errlog');

		// Before.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesBefore,
			"Before: expected 'log' to have 5 lines, got {$linesBefore}");
		$this->assertGreaterThan(0, filesize($errlogPath),
			"Before: expected 'errlog' non-empty, got " . filesize($errlogPath) . ' bytes');

		// Act.
		pfblockerng_tick();

		// The feed cron ledger entry must be unchanged (no mark_ran) -- confirms
		// the tick genuinely treated 'cron' as not-due this pass.
		$cronEntry = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($cronEntry, 'cron ledger entry must still exist after the tick');
		$this->assertSame($now + 3600, $cronEntry['next_due'],
			'cron next_due must be unchanged (not marked ran): expected ' . ($now + 3600)
			. " got {$cronEntry['next_due']} -- the feed cron must NOT have dispatched this tick");

		// After: log maintenance ran anyway.
		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
			"After tick with feed cron NOT due: expected 'log' still trimmed to [l3,l4,l5], got "
			. var_export($linesAfter, TRUE)
			. ' -- log maintenance must be unconditional, not gated behind the feed-cron due check');

		clearstatcache(TRUE, $errlogPath);
		$this->assertSame(0, filesize($errlogPath),
			"After tick with feed cron NOT due: expected 'errlog' still fully cleared, got "
			. filesize($errlogPath) . ' bytes');
	}

	// -----------------------------------------------------------------------
	// issue #573 (phase 2) -- the feed-cron next_due must anchor to its own
	// PREVIOUS next_due, not to wall-clock $now, so a tick that starts a hair
	// earlier than its predecessor does not push the whole schedule one full
	// tick interval late (cron phase creep).
	// -----------------------------------------------------------------------

	/**
	 * Red->green: before pfblockerng_tick() dispatched the feed cron via
	 * pfb_due_ledger_mark_ran_anchored(), a due job's next_due was always
	 * tick_start + interval -- so a ledger entry missed by a few seconds (a
	 * completely ordinary boundary fluctuation, not a real catch-up) produced
	 * a next_due that was ALSO a few seconds late, repeating every cycle
	 * (issue #573's monotonic phase creep -- eventually crossing a
	 * calendar-hour boundary and silently skipping an EveryDay/Weekly
	 * per-feed schedule gated on that hour). This test drives the REAL
	 * pfblockerng_tick() entrypoint and pins that the cron next_due instead
	 * advances by EXACTLY $interval from its OWN previous value, never from
	 * $now.
	 *
	 * Scenario:
	 *   Given pfb_interval='24' (interval = 86400 s) and a 'cron' ledger entry
	 *   whose next_due is 10 s in the past (missed the boundary by a few
	 *   seconds -- the ordinary case, not a real catch-up); dcc/bl are NOT due.
	 *   When  pfblockerng_tick() runs (the real entrypoint, not the pure
	 *         helper covered elsewhere).
	 *   Then  the new cron next_due = the OLD next_due + 86400 EXACTLY --
	 *         not time() + 86400 (which would land seconds later and, over
	 *         many cycles, eventually cross a calendar-hour boundary).
	 */
	public function testCronNextDueAnchorsToPreviousNextDueNotWallClock(): void
	{
		$this->seedTickPrereqs('24');
		// Mirrors src/usr/local/www/pfblockerng/pfblockerng.php:63 -- see Case A.
		pfb_global();
		$this->ensureLogDir();

		$now         = time();
		$interval    = 86400;	// pfb_interval='24' hours
		$oldNextDue  = $now - 10;	// missed the boundary by 10 s -- the ordinary case

		pfb_due_ledger_write_entry('cron', [
			'last_run' => $oldNextDue - $interval,
			'next_due' => $oldNextDue,
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);

		// Prevent a real exec() dispatch for dcc/bl.
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		// Act.
		pfblockerng_tick();

		$cronEntry = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$expected  = $oldNextDue + $interval;

		$this->assertNotNull($cronEntry, 'cron ledger entry must exist after the tick');
		$this->assertSame($expected, $cronEntry['next_due'],
			"cron next_due: expected old_next_due + interval ({$expected} = {$oldNextDue} + {$interval}), "
			. "got {$cronEntry['next_due']} -- pfblockerng_tick() must anchor the feed-cron next_due to "
			. 'its own previous schedule, not to wall-clock time() (issue #573 phase creep)');
	}

	// -----------------------------------------------------------------------
	// PR #790 review — a tick that DISPATCHES an update pass this cycle must
	// NOT also run log maintenance in the same call: pfb_log_mgmt()'s
	// tail-to-temp-then-cat-over trim (pfblockerng.inc) is a read/truncate/
	// rewrite window that races the backgrounded pass it just exec()'d, which
	// appends to the SAME log files ($pfb['runlog']/['extraslog']) for
	// potentially minutes -- a lost-append hazard, not merely a stale read.
	// -----------------------------------------------------------------------

	/**
	 * Red->green: before this fix pfblockerng_tick() called pfb_log_mgmt()/
	 * pfb_log_reset() unconditionally at its tail, even on a tick that itself
	 * just dispatched the feed cron. This test drives a tick that DOES
	 * dispatch (a due, in-window 'cron' job) and pins that log maintenance is
	 * SKIPPED that tick (the $dispatched flag path -- deterministic, does not
	 * depend on `ps`, unlike the pfb_update_pass_running() branch covered by
	 * Cases A/B staying idle).
	 *
	 * Scenario:
	 *   Given pfb_interval='24' and a 'cron' ledger entry 10 s past due
	 *   (dispatches this tick); the same 5-line 'log' + stale-marker 'errlog'
	 *   seeding as Case A.
	 *   Before: 'log' has 5 lines; 'errlog' is non-empty with a stale marker.
	 *   When  pfblockerng_tick() is called.
	 *   Then  the feed cron IS dispatched (mark_ran_anchored advances 'cron').
	 *   And   'log' is STILL 5 lines and 'errlog' is STILL non-empty with its
	 *         stale marker unchanged -- pfb_log_mgmt()/pfb_log_reset() must be
	 *         skipped on a tick that itself just dispatched an update pass.
	 */
	public function testDispatchingTickSkipsLogMaintenanceThisTick(): void
	{
		$this->seedTickPrereqs('24');
		// Mirrors src/usr/local/www/pfblockerng/pfblockerng.php:63 -- see Case A.
		pfb_global();
		$this->ensureLogDir();

		$now      = time();
		$interval = 86400;	// pfb_interval='24' hours

		pfb_due_ledger_write_entry('cron', [
			'last_run' => $now - $interval - 10,
			'next_due' => $now - 10,	// 10 s past due -- dispatches this tick
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);

		// Prevent a real exec() dispatch for dcc/bl -- isolate to the cron dispatch.
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		$logPath    = $this->logPath('log');
		$errlogPath = $this->logPath('errlog');
		$yesterday  = date('Y-m-d', strtotime('-1 day'));

		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");
		file_put_contents($errlogPath, "some error\n");
		$this->writeStaleMarker('errlog');

		// Before.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesBefore,
			"Before: expected 'log' to have 5 lines, got {$linesBefore}");
		$this->assertGreaterThan(0, filesize($errlogPath),
			"Before: expected 'errlog' non-empty, got " . filesize($errlogPath) . ' bytes');

		// Act.
		pfblockerng_tick();

		// The feed cron WAS dispatched -- mark_ran_anchored advanced 'cron' past its
		// pre-tick next_due, proving this tick genuinely took the dispatch branch.
		$cronEntry = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($cronEntry, 'cron ledger entry must exist after the tick');
		$this->assertGreaterThan($now - 10, $cronEntry['next_due'],
			'cron next_due must have advanced (dispatched this tick): expected > ' . ($now - 10)
			. " got {$cronEntry['next_due']} -- test setup did not actually dispatch the cron");

		// After: log maintenance must NOT have run -- the dispatch this tick holds
		// pfblockerng_tick()'s $dispatched race guard closed.
		clearstatcache(TRUE, $logPath);
		$linesAfter = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesAfter,
			"After a tick that DISPATCHED the feed cron: expected 'log' UNTRIMMED at 5 lines, got "
			. "{$linesAfter} -- pfb_log_mgmt() must be skipped on a tick that just dispatched an "
			. 'update pass (race against the backgrounded pass appending to the same log)');

		clearstatcache(TRUE, $errlogPath);
		$this->assertGreaterThan(0, filesize($errlogPath),
			"After a tick that DISPATCHED the feed cron: expected 'errlog' STILL non-empty, got "
			. filesize($errlogPath) . ' bytes -- pfb_log_reset() must be skipped on a tick that just '
			. 'dispatched an update pass');

		$markerContents = (string) file_get_contents($GLOBALS['pfb']['dbdir'] . '/log_rotate.last');
		$entries        = pfb_log_rotate_marker_parse($markerContents);
		$this->assertSame($yesterday, $entries['errlog'] ?? NULL,
			"After a tick that DISPATCHED the feed cron: expected 'errlog' marker still yesterday's key "
			. "({$yesterday}), got " . var_export($entries['errlog'] ?? NULL, TRUE)
			. ' -- pfb_log_reset() must not have advanced it');
	}
}
