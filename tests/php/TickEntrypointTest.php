<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #573 — scheduled log maintenance must survive pfb_interval='Disabled'.
 *
 * pfblockerng_tick() is the ONLY scheduled path to pfb_log_mgmt() (ADR30-1). Before
 * this change that call lived at the tail of pfblockerng_sync_cron(), reachable only
 * through the tick's feed-cron dispatch, itself gated on `!$cron_disabled`
 * (pfb_interval !== 'Disabled'). A user who set Update Frequency to 'Disabled'
 * therefore silently stopped ALL scheduled log trim, with no warning.
 *
 * This suite drives the REAL pfblockerng_tick() entrypoint -- relocated here
 * (from the www/ dispatcher script, which is never require()'d off-appliance)
 * so it is loadable by the PHPUnit bootstrap, per ADR43-5 -- and pins that log
 * maintenance is no longer gated behind the legacy feed-cron cadence (Cases A/B).
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
 *   Case E — issue #1769: the pfb_update_pass_running() half of the gate's skip
 *            must be observable, not silent (testTickLogsDeferredMaintenanceWhenAPassIsRunning).
 *   Case G — issue #1769 root cause: a PENDING 'cron' entry (pfb_due_ledger_set_pending)
 *            bypasses $cron_disabled even with pfb_interval='Disabled', dispatches, and
 *            skips log maintenance via $dispatched, NOT pfb_update_pass_running() --
 *            (testPendingCronApplyBypassesDisabledIntervalAndSkipsLogMaintenance) with its
 *            converse, a plain future-seeded 'cron' entry staying genuinely idle
 *            (testDisabledIntervalWithFutureSeededCronStaysIdleAndRunsLogMaintenance) --
 *            the ADR-60 smoke fixture's oracle (tests/smoke/test_log_age_retention.py).
 */
final class TickEntrypointTest extends TestCase
{
	/** Per-test private sandbox for $pfb['dbdir'] -- see setUp(). */
	private string $dbdir = '';

	/** Whether $GLOBALS['pfb']['dbdir'] was set before this test, and its value. */
	private bool $hadDbdir = FALSE;
	private mixed $originalDbdir = NULL;
	private bool $hadStateDir = FALSE;
	private mixed $originalStateDir = NULL;

	/** Whether $GLOBALS['pfb']['runlog']/['extraslog'] were set before this test, and their values. */
	private bool $hadRunlog = FALSE;
	private mixed $originalRunlog = NULL;
	private bool $hadExtraslog = FALSE;
	private mixed $originalExtraslog = NULL;

	/**
	 * issue #1666: $GLOBALS['pfb']['log']/['logdir']/['errlog'] are set ONCE at
	 * pfblockerng.inc include time (never recomputed by pfb_global()) -- so
	 * without a per-test sandbox here, 'log' rode whatever value a PRIOR test
	 * class last left it at, including a path a leaked-teardown suite had
	 * already deleted. Same treatment as dbdir/runlog/extraslog above.
	 */
	private bool $hadLog = FALSE;
	private mixed $originalLog = NULL;
	private bool $hadLogdir = FALSE;
	private mixed $originalLogdir = NULL;
	private bool $hadErrlog = FALSE;
	private mixed $originalErrlog = NULL;

	/** issue #1666: neuter $pfb['php'] so Cases C/D's real dispatch branches exec()
	 *  a harmless recording stub instead of a REAL "pfblockerng.php <verb>" shell
	 *  a sibling suite's pfb_update_pass_running() `ps` scan could then see. */
	private bool $hadPhp = FALSE;
	private mixed $originalPhp = NULL;

	/** issue #1666: $GLOBALS['config'] was overwritten unconditionally below with
	 *  no restore; save/restore it like every other process-global this suite
	 *  touches. */
	private bool $hadConfig = FALSE;
	private mixed $originalConfig = NULL;

	/** issue #1666: seedTickPrereqs() sets this once, guarded by isset(), and it is
	 *  never restored -- the first test to run in the whole suite leaves it set for
	 *  every later test/class. Save/restore it explicitly instead. */
	private bool $hadUnboundChroot = FALSE;
	private mixed $originalUnboundChroot = NULL;

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
		$this->hadStateDir      = array_key_exists('schedule_state_dir', $GLOBALS['pfb'] ?? []);
		$this->originalStateDir = $GLOBALS['pfb']['schedule_state_dir'] ?? NULL;

		$this->hadRunlog      = array_key_exists('runlog', $GLOBALS['pfb'] ?? []);
		$this->originalRunlog = $GLOBALS['pfb']['runlog'] ?? NULL;

		$this->hadExtraslog      = array_key_exists('extraslog', $GLOBALS['pfb'] ?? []);
		$this->originalExtraslog = $GLOBALS['pfb']['extraslog'] ?? NULL;

		$this->hadLog      = array_key_exists('log', $GLOBALS['pfb'] ?? []);
		$this->originalLog = $GLOBALS['pfb']['log'] ?? NULL;

		$this->hadLogdir      = array_key_exists('logdir', $GLOBALS['pfb'] ?? []);
		$this->originalLogdir = $GLOBALS['pfb']['logdir'] ?? NULL;

		$this->hadErrlog      = array_key_exists('errlog', $GLOBALS['pfb'] ?? []);
		$this->originalErrlog = $GLOBALS['pfb']['errlog'] ?? NULL;

		$this->hadPhp      = array_key_exists('php', $GLOBALS['pfb'] ?? []);
		$this->originalPhp = $GLOBALS['pfb']['php'] ?? NULL;

		$this->hadConfig      = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? NULL;

		$this->hadUnboundChroot      = array_key_exists('unbound_chroot_path', $GLOBALS['g'] ?? []);
		$this->originalUnboundChroot = $GLOBALS['g']['unbound_chroot_path'] ?? NULL;

		$this->dbdir = $this->dbdirPrefix() . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		mkdir("{$this->dbdir}/state", 0755, TRUE);
		$GLOBALS['pfb']['dbdir']     = $this->dbdir;
		$GLOBALS['pfb']['schedule_state_dir'] = "{$this->dbdir}/state";
		$GLOBALS['pfb']['runlog']    = "{$this->dbdir}/pfblockerng_run.log";
		$GLOBALS['pfb']['extraslog'] = "{$this->dbdir}/extras.log";
		$GLOBALS['pfb']['logdir']    = $this->dbdir;
		$GLOBALS['pfb']['log']       = "{$this->dbdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']    = "{$this->dbdir}/error.log";
		$GLOBALS['pfb']['php']       = $this->installPhpArgvRecorder();

		$GLOBALS['config'] = [];

		// issue #1769: pfsense_doubles.php's logger() double records every call here
		// (real syslog() has no portable off-appliance read-back) -- fresh per test.
		$GLOBALS['pfb_test_logger_calls'] = [];

		// issue #1769 B3/B4: both log-maintenance skip arms emit via
		// pfb_syslog_emit(); the shared syslog spy records those calls.
		$GLOBALS['pfb_test_syslog_spy']   = TRUE;
		$GLOBALS['pfb_test_syslog_calls'] = [];
	}

	protected function tearDown(): void
	{
		if ($this->hadDbdir) {
			$GLOBALS['pfb']['dbdir'] = $this->originalDbdir;
		} else {
			unset($GLOBALS['pfb']['dbdir']);
		}
		if ($this->hadStateDir) {
			$GLOBALS['pfb']['schedule_state_dir'] = $this->originalStateDir;
		} else {
			unset($GLOBALS['pfb']['schedule_state_dir']);
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
		if ($this->hadLog) {
			$GLOBALS['pfb']['log'] = $this->originalLog;
		} else {
			unset($GLOBALS['pfb']['log']);
		}
		if ($this->hadLogdir) {
			$GLOBALS['pfb']['logdir'] = $this->originalLogdir;
		} else {
			unset($GLOBALS['pfb']['logdir']);
		}
		if ($this->hadErrlog) {
			$GLOBALS['pfb']['errlog'] = $this->originalErrlog;
		} else {
			unset($GLOBALS['pfb']['errlog']);
		}
		if ($this->hadPhp) {
			$GLOBALS['pfb']['php'] = $this->originalPhp;
		} else {
			unset($GLOBALS['pfb']['php']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
		if ($this->hadUnboundChroot) {
			$GLOBALS['g']['unbound_chroot_path'] = $this->originalUnboundChroot;
		} else {
			unset($GLOBALS['g']['unbound_chroot_path']);
		}
		unset($GLOBALS['pfb_test_logger_calls']);
		unset($GLOBALS['pfb_test_syslog_spy'], $GLOBALS['pfb_test_syslog_calls']);
		$this->rrmdir($this->dbdir);
	}

	/**
	 * issue #1666: point $pfb['php'] at a harmless recording stub instead of the
	 * real interpreter -- Cases C/D genuinely dispatch (a due 'cron' job), so
	 * this is the only lever available to keep that dispatch from forking a REAL
	 * "pfblockerng.php cron" background process. Mirrors
	 * TickFeedPassDeferralTest::installPhpArgvRecorder().
	 *
	 * issue #2006: suite process-table checks retain only this PHPUnit process's
	 * sandbox prefix, so another checkout's recorder cannot cross-trip them.
	 */
	private function installPhpArgvRecorder(): string
	{
		$path = "{$this->dbdir}/pfb_php_recorder";
		$log  = escapeshellarg("{$this->dbdir}/pfb_php_calls.log");
		file_put_contents($path, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> {$log}\n");
		chmod($path, 0755);
		return $path;
	}

	private function dbdirPrefix(): string
	{
		$pid = getmypid();
		if (!is_int($pid)) {
			throw new RuntimeException('PHPUnit process PID is unavailable');
		}
		return sys_get_temp_dir() . '/pfb_tick_entrypoint_' . $pid . '_';
	}

	private function hostPsLines(): array
	{
		$psLines = [];
		exec('/bin/ps -wax', $psLines, $rc);
		if ($rc !== 0) {
			throw new RuntimeException('/bin/ps -wax failed while inspecting test workers');
		}
		return $psLines;
	}

	private function monotonicTime(): int
	{
		$now = hrtime(TRUE);
		if (!is_int($now)) {
			throw new RuntimeException('monotonic clock is unavailable');
		}
		return $now;
	}

	/** Return only worker command lines carrying this PHPUnit process's sandbox prefix. */
	private function suiteWorkerPsLines(): array
	{
		$prefix = $this->dbdirPrefix();
		return array_values(array_filter(
			$this->hostPsLines(),
			static fn (string $line): bool => str_contains($line, $prefix)
		));
	}

	private function workerPsLines(int $pid): array
	{
		$pidPattern = '/^\s*' . preg_quote((string) $pid, '/') . '\s/';
		return array_values(array_filter(
			$this->hostPsLines(),
			static fn (string $line): bool => preg_match($pidPattern, $line) === 1
		));
	}

	/**
	 * Allow a background recorder one second to exit; persistent workers remain visible.
	 *
	 * @param null|callable(): int $clock
	 * @param null|list<string> $psLinesOverride
	 */
	private function settledSuiteWorkerPsLines(?callable $clock = NULL, ?array $psLinesOverride = NULL): array
	{
		$clock ??= fn (): int => $this->monotonicTime();
		$psLines = [];
		$deadline = $clock() + 1_000_000_000;
		for ($attempt = 0; $attempt < 50; $attempt++) {
			$psLines = $psLinesOverride ?? $this->suiteWorkerPsLines();
			if (!pfb_update_pass_running($psLines)) {
				return $psLines;
			}
			$now = $clock();
			if ($attempt === 49 || $now >= $deadline) {
				break;
			}
			usleep((int) min(20000, intdiv($deadline - $now, 1000)));
		}
		return $psLines;
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
	 * line-cap ('log') so a real tick call exercises pfb_log_mgmt().
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

		// Tick cadence knobs under test (issue #573: 'Disabled' must not gate
		// log maintenance -- see pfblockerng_tick()).
		config_set_path("{$gen}/pfb_interval",    $rawInterval);
		config_set_path("{$gen}/pfb_quiet_hours", ''); // apply immediately, no deferral

		// pfb_log_mgmt(): cap 'log' to 3 lines; every other type stays at the
		// registry default (20000) -> no-op trim, keeping the test single-purpose.
		config_set_path("{$gen}/log_max_log", '3');
		// Apply reconciliation has an independent cadence; keep it idle unless a
		// test explicitly seeds that job due.
		$this->seedFutureLedgerEntry('apply_reconcile', time());
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

	/** Seed an idle tick with only the SafeSearch ledger state under test due. */
	private function prepareSafeSearchTick(): int
	{
		$this->seedTickPrereqs('Disabled');
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		$this->seedFutureLedgerEntry('cron', $now);
		$this->seedFutureLedgerEntry('dcc',  $now);
		$this->seedFutureLedgerEntry('bl',   $now);

		return $now;
	}

	// -----------------------------------------------------------------------
	// Case A — the bug: pfb_interval='Disabled' must not silently stop log
	// maintenance.
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given pfb_interval='Disabled' (the feed cron is entirely gated off).
	 *   And   a 5-line 'log' file with log_max_log=3 (pfb_log_mgmt should trim it).
	 *   Before: 'log' has 5 lines.
	 *   When  pfblockerng_tick() is called.
	 *   Then  'log' is trimmed to its last 3 lines (pfb_log_mgmt ran) -- log
	 *         maintenance survives a Disabled Update Frequency (issue #573).
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

		$logPath = $this->logPath('log');

		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");

		// Before.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesBefore,
			"Before: expected 'log' to have 5 lines, got {$linesBefore};\n"
			. '  content=' . var_export(file_get_contents($logPath), TRUE));

		$psLines = $this->settledSuiteWorkerPsLines();
		$this->assertFalse(pfb_update_pass_running($psLines),
			'a pfblockerng.php worker owned by this PHPUnit run leaked from an earlier test');

		// Act.
		pfblockerng_tick($psLines);

		// After: pfb_log_mgmt() trimmed 'log' to its last 3 lines.
		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
			"After tick with pfb_interval='Disabled': expected 'log' trimmed to [l3,l4,l5], got "
			. var_export($linesAfter, TRUE)
			. ' -- pfb_log_mgmt() must run every tick, not only when the feed cron is enabled');
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
	 *   And   the same 'log' seeding as Case A.
	 *   Before: 'log' has 5 lines; no pending manual apply exists.
	 *   When  pfblockerng_tick() is called.
	 *   Then  'log' is trimmed, proving no manual pass dispatched and log
	 *         maintenance runs regardless of
	 *         whether the feed cron itself was due this tick.
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

		$logPath = $this->logPath('log');

		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");

		// Before.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesBefore,
			"Before: expected 'log' to have 5 lines, got {$linesBefore}");

		// Ordering-regression tripwire (issue #1666/#2006): reject workers leaked
		// by this PHPUnit run without consulting unrelated host workers.
		$psLines = $this->settledSuiteWorkerPsLines();
		$this->assertFalse(pfb_update_pass_running($psLines),
			'a pfblockerng.php worker owned by this PHPUnit run leaked from an earlier test');

		// Act.
		$manualRuns = 0;
		pfblockerng_tick(
			ps_lines: $psLines,
			manual_runner: static function () use (&$manualRuns): bool {
				$manualRuns++;
				return TRUE;
			}
		);
		$this->assertSame(0, $manualRuns, 'future non-pending cron entry must not dispatch');

		// After: log maintenance ran anyway.
		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
			"After tick with feed cron NOT due: expected 'log' still trimmed to [l3,l4,l5], got "
			. var_export($linesAfter, TRUE)
			. ' -- log maintenance must be unconditional, not gated behind the feed-cron due check');
	}

	/** issue #2006: an injected empty process snapshot isolates an idle tick from host workers. */
	public function testIdleTickIgnoresUnrelatedHostWorker(): void
	{
		$this->seedTickPrereqs('Disabled');
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		$this->seedFutureLedgerEntry('cron', $now);
		$this->seedFutureLedgerEntry('dcc',  $now);
		$this->seedFutureLedgerEntry('bl',   $now);

		$logPath = $this->logPath('log');
		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");

		[$proc, $pid, $stdin] = $this->spawnStrayUpdatePassProcess();
		try {
			$this->assertTrue(pfb_update_pass_running(), 'fixture worker must be visible in the host process table');
			pfblockerng_tick([]);

			$linesAfter = array_values(array_filter(
				explode("\n", (string) file_get_contents($logPath)),
				'strlen'
			));
			$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
				'an injected empty process snapshot must keep an unrelated host worker out of the idle tick');
		} finally {
			$this->killStrayUpdatePassProcess($proc, $pid, $stdin);
		}
	}

	/** issue #2006: the suite snapshot excludes matching workers from another run. */
	public function testSuiteSnapshotExcludesForeignHostWorker(): void
	{
		$this->seedTickPrereqs('Disabled');
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		$this->seedFutureLedgerEntry('cron', $now);
		$this->seedFutureLedgerEntry('dcc',  $now);
		$this->seedFutureLedgerEntry('bl',   $now);

		$logPath = $this->logPath('log');
		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");

		$foreignDir = sys_get_temp_dir() . '/pfb_tick_foreign_' . uniqid('', TRUE);
		[$proc, $pid, $stdin] = $this->spawnStrayUpdatePassProcess($foreignDir);
		try {
			$this->assertTrue(pfb_update_pass_running($this->workerPsLines($pid)),
				'foreign fixture worker must match pfb_update_pass_running()');
			$psLines = $this->suiteWorkerPsLines();
			$this->assertFalse(pfb_update_pass_running($psLines),
				'this PHPUnit run snapshot must exclude the foreign fixture worker');
			pfblockerng_tick($psLines);

			$linesAfter = array_values(array_filter(
				explode("\n", (string) file_get_contents($logPath)),
				'strlen'
			));
			$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
				'a foreign host worker must not close this PHPUnit run idle-tick gate');
		} finally {
			$this->killStrayUpdatePassProcess($proc, $pid, $stdin);
			$this->rrmdir($foreignDir);
		}
	}

	public function testPersistentSuiteWorkerSettlingHonorsDeadlineAndIterationCap(): void
	{
		$workerLines = ['  1234  -  Ss  0:00 /usr/local/www/pfblockerng/pfblockerng.php cron'];

		$deadlineReads = 0;
		$deadlineClock = static function () use (&$deadlineReads): int {
			return $deadlineReads++ === 0 ? 0 : 1_000_000_000;
		};
		$psLines = $this->settledSuiteWorkerPsLines($deadlineClock, $workerLines);
		$this->assertSame(2, $deadlineReads, 'deadline arm must stop after its second clock read');
		$this->assertTrue(pfb_update_pass_running($psLines),
			'a persistent worker must remain visible after the settling deadline');

		$capReads = 0;
		$fixedClock = static function () use (&$capReads): int {
			$capReads++;
			return 0;
		};
		$psLines = $this->settledSuiteWorkerPsLines($fixedClock, $workerLines);
		$this->assertSame(51, $capReads, 'iteration-cap arm must stop after 50 observations');
		$this->assertTrue(pfb_update_pass_running($psLines),
			'a persistent worker must remain visible after the iteration cap');
	}

	// -----------------------------------------------------------------------
	// issue #2089 — SafeSearch refresh is its own zero-jitter 900-second job.
	// -----------------------------------------------------------------------

	/** An absent SafeSearch entry runs once and seeds a zero-jitter 900-second slot. */
	public function testSafeSearchAbsentEntryRunsOnceAndSeedsCadence(): void
	{
		$now = $this->prepareSafeSearchTick();
		$calls = 0;
		$refresh = static function () use (&$calls): void {
			$calls++;
		};

		pfblockerng_tick($this->suiteWorkerPsLines(), $refresh);

		$this->assertSame(1, $calls, 'absent ss_refresh entry must invoke SafeSearch exactly once');
		$entry = pfb_due_ledger_read_entry('ss_refresh', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($entry, 'due SafeSearch tick must create its ledger entry');
		$this->assertSame(0, $entry['jitter'], 'ss_refresh cadence must have zero jitter');
		$this->assertSame(900, $entry['next_due'] - $entry['last_run'],
			'ss_refresh next_due must be exactly 900 seconds after last_run');
		$this->assertGreaterThan($now, $entry['next_due'],
			'ss_refresh next_due must be in the future after its first run');
	}

	/** A future SafeSearch entry does not call or rewrite the observer/ledger. */
	public function testSafeSearchFutureEntryDoesNotRunOrChangeLedger(): void
	{
		$now = $this->prepareSafeSearchTick();
		$this->seedFutureLedgerEntry('ss_refresh', $now);
		$before = pfb_due_ledger_read_entry('ss_refresh', $GLOBALS['pfb']['dbdir']);
		$calls = 0;
		$refresh = static function () use (&$calls): void {
			$calls++;
		};

		pfblockerng_tick($this->suiteWorkerPsLines(), $refresh);

		$this->assertSame(0, $calls, 'future ss_refresh entry must not invoke SafeSearch');
		$after = pfb_due_ledger_read_entry('ss_refresh', $GLOBALS['pfb']['dbdir']);
		$this->assertSame($before, $after, 'future ss_refresh entry must remain unchanged');
	}

	/** A slightly overdue SafeSearch entry advances from its prior slot, not wall clock. */
	public function testSafeSearchSlightlyOverdueEntryReanchorsFromPriorSlot(): void
	{
		$now = $this->prepareSafeSearchTick();
		$oldNextDue = $now - 10;
		pfb_due_ledger_write_entry('ss_refresh', [
			'last_run' => $oldNextDue - 900,
			'next_due' => $oldNextDue,
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);
		$calls = 0;
		$refresh = static function () use (&$calls): void {
			$calls++;
		};

		pfblockerng_tick($this->suiteWorkerPsLines(), $refresh);

		$this->assertSame(1, $calls, 'overdue ss_refresh entry must invoke SafeSearch once');
		$entry = pfb_due_ledger_read_entry('ss_refresh', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($entry, 'overdue ss_refresh entry must remain present');
		$this->assertSame($oldNextDue + 900, $entry['next_due'],
			'slightly overdue ss_refresh must advance from prior next_due exactly 900 seconds');
	}

	/** A multi-interval overdue SafeSearch entry runs once and catches up past now. */
	public function testSafeSearchMultiIntervalOverdueEntryDoesNotBurst(): void
	{
		$now = $this->prepareSafeSearchTick();
		$oldNextDue = $now - 1800;
		pfb_due_ledger_write_entry('ss_refresh', [
			'last_run' => $oldNextDue - 900,
			'next_due' => $oldNextDue,
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);
		$calls = 0;
		$refresh = static function () use (&$calls): void {
			$calls++;
		};

		pfblockerng_tick($this->suiteWorkerPsLines(), $refresh);

		$this->assertSame(1, $calls, 'multi-interval overdue ss_refresh must not replay missed slots');
		$entry = pfb_due_ledger_read_entry('ss_refresh', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($entry, 'overdue ss_refresh entry must remain present');
		$this->assertSame(900, $entry['next_due'] - $entry['last_run'],
			'multi-interval catch-up must write one 900-second cadence slot');
		$this->assertGreaterThan($now, $entry['next_due'],
			'multi-interval catch-up must advance ss_refresh next_due past now');
	}

	// -----------------------------------------------------------------------
	// issue #1769 — the pfb_update_pass_running() half of the log-maintenance
	// gate was SILENT on skip: a stray process matching the ps-scan regex closed the
	// gate with zero trace, which cost a live-tier diagnosis (the smoke suite's
	// seeded log rode this same unsynchronized gate). This test drives a REAL
	// background process through a REAL, suite-scoped `ps` snapshot
	// (PfbUpdatePassRunningTest covers the regex itself via synthetic arrays) and
	// asserts BOTH halves of the fix: the
	// skip still holds (log untrimmed) AND it is no longer silent (a
	// deferred-maintenance line lands in the log).
	// -----------------------------------------------------------------------

	/**
	 * Red->green: before this fix the tail gate's elseif branch did not exist --
	 * the skip happened with no trace. Assertion (b) below is the one that fails
	 * RED against the pre-fix worktree (no deferred-maintenance line ever
	 * reaches the log); assertion (a) pins the pre-existing skip stays put.
	 *
	 * Scenario:
	 *   Given a REAL background process whose /bin/ps -wax command line matches
	 *   pfb_update_pass_running()'s regex (a tiny `/bin/sh <sandbox>/pfblockerng.php
	 *   dcc` sleeper -- proven live via the ps scan itself, not an injected array).
	 *   And   the same 5-line 'log' / log_max_log=3 seeding as Case A.
	 *   And   the runtime schedule cache is future-dated (no real dispatch of
	 *         pfblockerng_tick()'s own jobs this tick -- isolates to the stray
	 *         process's effect on the gate).
	 *   When  pfblockerng_tick() is called.
	 *   Then  (a) 'log' is NOT trimmed -- the ORIGINAL 5 lines are still present,
	 *         untouched by pfb_log_mgmt().
	 *   And   (b) a "log maintenance deferred" line IS appended -- the skip is
	 *         no longer silent.
	 *
	 * issue #1769 review: this branch is deliberately KEPT on pfb_logger()/$pfb['log'];
	 * this test and the ADR-60 smoke suite's self-diagnosing failure output assert this exact
	 * surface. Tradeoff stated explicitly, not silently kept: a long-lived stray/leaked
	 * update pass would make this line accumulate in the very file it's deferring
	 * maintenance on, bounded by how long that pass survives (transient in practice).
	 */
	public function testTickLogsDeferredMaintenanceWhenAPassIsRunning(): void
	{
		$this->seedTickPrereqs('24');
		// Mirrors src/usr/local/www/pfblockerng/pfblockerng.php:63 -- see Case A.
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		$this->seedFutureLedgerEntry('cron', $now);
		$this->seedFutureLedgerEntry('dcc',  $now);
		$this->seedFutureLedgerEntry('bl',   $now);

		$logPath = $this->logPath('log');
		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");

		[$proc, $pid, $stdin] = $this->spawnStrayUpdatePassProcess();
		try {
			// Prove this PHPUnit run's filtered process snapshot sees its fixture.
			$psLines = $this->suiteWorkerPsLines();
			$this->assertTrue(pfb_update_pass_running($psLines),
				'fixture process does not satisfy pfb_update_pass_running() -- ps line does not '
				. 'match; see spawnStrayUpdatePassProcess()');

			// Before.
			$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
			$this->assertSame(5, $linesBefore, "Before: expected 'log' to have 5 lines, got {$linesBefore}");

			// Act.
			pfblockerng_tick($psLines);

			// (a) 'log' was NOT trimmed -- the original 5 lines are all still present
			// (pfb_log_mgmt()'s tail-to-3 trim never ran).
			clearstatcache(TRUE, $logPath);
			$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
			$this->assertSame(['l1', 'l2', 'l3', 'l4', 'l5'], array_slice($linesAfter, 0, 5),
				"After tick with a running update pass: expected 'log' UNTRIMMED (original 5 lines "
				. 'intact), got ' . var_export($linesAfter, TRUE)
				. ' -- pfb_log_mgmt() must still be skipped while pfb_update_pass_running() is TRUE');

			// (b) the skip is no longer silent -- and (issue #1769 B4) it says so on
			// the SYSLOG surface, leaving 'log' byte-identical: the old pfb_logger()
			// line grew the very file whose trim it was deferring.
			$this->assertSame(['l1', 'l2', 'l3', 'l4', 'l5'], $linesAfter,
				"After tick with a running update pass: 'log' must be byte-identical (no deferred "
				. 'line appended to the starved file itself), got ' . var_export($linesAfter, TRUE));
			$deferred = array_values(array_filter(
				$GLOBALS['pfb_test_syslog_calls'] ?? [],
				static fn (array $c) => str_contains($c['body'], 'log maintenance deferred')
			));
			$this->assertNotEmpty($deferred,
				'expected a "log maintenance deferred" pfb_syslog_emit() call, got '
				. var_export($GLOBALS['pfb_test_syslog_calls'] ?? [], TRUE)
				. ' -- the skip must be observable, not silent (issue #1769)');
		} finally {
			$this->killStrayUpdatePassProcess($proc, $pid, $stdin);
		}
	}

	/**
	 * Spawn a REAL background process whose /bin/ps -wax command line matches
	 * pfb_update_pass_running()'s regex: a tiny sleeper script invoked as
	 * "/bin/sh <sandbox>/pfblockerng.php dcc" -- the literal substring
	 * "pfblockerng.php" followed by whitespace then "dcc" (not followed by a
	 * word char) is exactly what the regex scans `ps -wax` for. Array-form
	 * proc_open (no shell wrapper) so the tracked pid IS the /bin/sh process
	 * `ps` actually reports, not an intermediary.
	 *
	 * issue #1769 review: the sleeper blocks on `read x` (a shell BUILTIN, no
	 * forked child) reading from its own stdin -- a piped descriptor the caller
	 * holds open and never writes to -- instead of `sleep 30` (a SEPARATE forked
	 * process). `sleep 30`'s fork meant killStrayUpdatePassProcess()'s
	 * proc_terminate() SIGKILL only killed the /bin/sh parent, orphaning the
	 * `sleep` grandchild (confirmed live via `pgrep -fl "sleep 30"` finding it
	 * still alive after the suite). SIGKILL to the shell now ends the whole
	 * fixture -- nothing left behind -- and the `ps` line the regex scans is
	 * unchanged (still "/bin/sh <script> dcc").
	 *
	 * @return array{0:resource,1:int,2:resource} [$proc, $pid, $stdin] -- $stdin is
	 *         the write end of the piped stdin descriptor; the caller must fclose()
	 *         it (see killStrayUpdatePassProcess()).
	 */
	private function spawnStrayUpdatePassProcess(?string $dir = NULL): array
	{
		$dir ??= $this->dbdir;
		if (!is_dir($dir)) {
			mkdir($dir, 0755, TRUE);
		}
		$script = "{$dir}/pfblockerng.php";
		file_put_contents($script, "#!/bin/sh\nread x\n");

		$descriptors = [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
		$proc = proc_open(['/bin/sh', $script, 'dcc'], $descriptors, $pipes);
		$this->assertIsResource($proc, 'failed to spawn the stray update-pass fixture process');

		$status = proc_get_status($proc);
		$pid    = $status['pid'];

		// Give the ps table a moment to pick the new process up before the caller trusts it.
		$deadline = $this->monotonicTime() + 1_000_000_000;
		for ($i = 0; $i < 50; $i++) {
			if (pfb_update_pass_running($this->workerPsLines($pid))) {
				break;
			}
			$now = $this->monotonicTime();
			if ($i === 49 || $now >= $deadline) {
				break;
			}
			usleep((int) min(20000, intdiv($deadline - $now, 1000)));
		}

		return [$proc, $pid, $pipes[0]];
	}

	/**
	 * @param resource $proc
	 * @param resource $stdin
	 */
	private function killStrayUpdatePassProcess($proc, int $pid, $stdin): void
	{
		if (is_resource($stdin)) {
			fclose($stdin);
		}
		$reaped = FALSE;
		if (is_resource($proc)) {
			proc_terminate($proc, 9);	// SIGKILL: no cleanup path runs in the child
			// proc_close() BLOCKS until the process changes state (waitpid()
			// under the hood) and reaps it -- must happen before any liveness
			// probe below, or a not-yet-reaped zombie reads as "still alive"
			// (kill(pid, 0) succeeds against a zombie; bit this fix once).
			proc_close($proc);
			$reaped = TRUE;
		}
		// Assert it is actually gone. posix_kill(pid, 0) is the standard "is this
		// pid alive" probe (no signal sent, just an existence check) -- guarded by
		// function_exists(): posix is NOT in CI's installed extension list
		// (.github/workflows/test.yml ~:511 installs curl/intl/mbstring/ctype/filter
		// only), so this was an implicit dependency, not a guaranteed one. Without
		// it, trust proc_close()'s own blocking wait above as the liveness proof --
		// its resource is invalid now, so there is nothing left to poll.
		if (function_exists('posix_kill')) {
			for ($i = 0; $i < 50; $i++) {
				if (!@posix_kill($pid, 0)) {
					break;
				}
				usleep(20000);
			}
			$this->assertFalse(@posix_kill($pid, 0),
				"stray fixture process {$pid} is still alive after kill -- see spawnStrayUpdatePassProcess()");
		} else {
			$this->assertTrue($reaped,
				'expected the fixture process to have been terminated and reaped via proc_close()');
		}
	}

	// -----------------------------------------------------------------------
	// issue #1769 root cause (Cases G/H) -- the ADR-60 smoke suite's
	// log-age-retention module starved pfb_log_mgmt() on its FIRST tick after a
	// fresh deploy through the $dispatched half of this SAME gate, not the
	// pfb_update_pass_running() half Cases A-F cover: h.deploy()'s package
	// reinstall loses the pfb_feed_pass_begin() race, pfblockerng_cron.inc calls
	// pfb_due_ledger_set_pending('cron'), and the smoke fixture (before this fix)
	// never cleared it for 'cron' (only 'dcc'/'bl') -- so even with
	// pfb_interval='Disabled' (the module's whole "every tick is idle" premise),
	// the dispatch condition `(!$cron_disabled && $due['cron']) || $cron_pending`
	// (pfblockerng_extra.inc) still fires via $cron_pending, bypassing
	// $cron_disabled entirely.
	// -----------------------------------------------------------------------

	/**
	 * Documents the real cause in-suite (live smoke cannot run in this
	 * environment): pins that a PENDING 'cron' entry dispatches even with
	 * pfb_interval='Disabled', and that pfb_update_pass_running() is FALSE at
	 * that moment -- ruling out the OTHER half of the gate as the cause of the
	 * skip.
	 *
	 * Scenario:
	 *   Given pfb_interval='Disabled' and a PENDING 'cron' ledger entry
	 *   (pfb_due_ledger_set_pending -- e.g. left behind by an install-time feed
	 *   pass that lost the pfb_feed_pass_begin() race); dcc/bl future-seeded; no
	 *   worker owned by this PHPUnit run.
	 *   When  pfblockerng_tick() is called.
	 *   Then  the pending 'cron' entry IS dispatched despite $cron_disabled (its
	 *         pending_apply flag is cleared by the dispatch branch).
	 *   And   'log' is NOT trimmed -- log maintenance was skipped this tick, caused
	 *         by $dispatched (pfb_update_pass_running() was FALSE going in, per the
	 *         precondition below).
	 */
	public function testPendingCronApplyBypassesDisabledIntervalAndSkipsLogMaintenance(): void
	{
		$this->seedTickPrereqs('Disabled');
		// Mirrors src/usr/local/www/pfblockerng/pfblockerng.php:63 -- see Case A.
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		pfb_due_ledger_set_pending('cron', $GLOBALS['pfb']['dbdir']);
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		$psLines = $this->settledSuiteWorkerPsLines();
		$this->assertFalse(pfb_update_pass_running($psLines),
			'precondition: no stray/leaked process may satisfy pfb_update_pass_running() -- '
			. 'this test isolates to the $dispatched half of the gate (issue #1769)');

		$logPath = $this->logPath('log');
		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");

		// Before.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesBefore, "Before: expected 'log' to have 5 lines, got {$linesBefore}");

		// Act.
		$manualRuns = 0;
		pfblockerng_tick(
			$psLines,
			NULL,
			NULL,
			5.0,
			NULL,
			NULL,
			5.0,
			NULL,
			NULL,
			static function () use (&$manualRuns): bool {
				$manualRuns++;
				return TRUE;
			}
		);
		$this->assertSame(1, $manualRuns, 'pending manual apply must run exactly once');

		// The pending cron entry WAS dispatched despite pfb_interval='Disabled' --
		// pending_apply bypasses $cron_disabled (pfblockerng_extra.inc).
		$this->assertFalse(pfb_due_ledger_is_pending('cron', $GLOBALS['pfb']['dbdir']),
			'pending_apply must have been cleared by the dispatch branch');

		// The precondition above proves this test entered through the $dispatched half.
		// After: log maintenance was skipped -- 'log' still has its original 5 lines.
		clearstatcache(TRUE, $logPath);
		$linesAfter = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesAfter,
			"After a Disabled-interval tick with a PENDING 'cron' entry: expected 'log' UNTRIMMED "
			. "at 5 lines (log maintenance skipped via \$dispatched, not pfb_update_pass_running()), "
			. "got {$linesAfter} -- issue #1769 root cause");
	}

	/**
	 * The converse / oracle for the ADR-60 smoke fixture's fix
	 * (tests/smoke/test_log_age_retention.py): a plain FUTURE-seeded
	 * (non-pending) 'cron' ledger entry does NOT bypass $cron_disabled, so a
	 * pfb_interval='Disabled' tick stays genuinely idle and DOES run log
	 * maintenance -- exactly what the fixed smoke fixture's deployed_vm now
	 * seeds for 'cron' (mirroring the existing dcc/bl seeds).
	 *
	 * Scenario:
	 *   Given pfb_interval='Disabled' and a FUTURE-seeded (non-pending) 'cron'
	 *   ledger entry; dcc/bl future-seeded too; no stray process.
	 *   When  pfblockerng_tick() is called.
	 *   Then  'log' IS trimmed, proving the tick remained idle.
	 */
	public function testDisabledIntervalWithFutureSeededCronStaysIdleAndRunsLogMaintenance(): void
	{
		$this->seedTickPrereqs('Disabled');
		// Mirrors src/usr/local/www/pfblockerng/pfblockerng.php:63 -- see Case A.
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		$this->seedFutureLedgerEntry('cron', $now);
		$this->seedFutureLedgerEntry('dcc',  $now);
		$this->seedFutureLedgerEntry('bl',   $now);

		$logPath = $this->logPath('log');
		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");

		$psLines = $this->settledSuiteWorkerPsLines();
		$this->assertFalse(pfb_update_pass_running($psLines),
			'a pfblockerng.php worker owned by this PHPUnit run leaked from an earlier test');

		// Act.
		pfblockerng_tick($psLines);

		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
			"After a Disabled-interval tick with a FUTURE-seeded (non-pending) 'cron' entry: "
			. 'expected \'log\' trimmed to [l3,l4,l5] (genuinely idle tick), got '
			. var_export($linesAfter, TRUE));
	}
}
