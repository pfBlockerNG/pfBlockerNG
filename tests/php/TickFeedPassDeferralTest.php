<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Fixed-job and manual-apply regressions for the real pfblockerng_tick() entrypoint.
 *
 * Drives the REAL pfblockerng_tick() entrypoint (TickEntrypointTest's sandbox
 * pattern: a private $pfb['dbdir']/runlog/extraslog per test, restored on
 * teardown -- see that suite's setUp() comment for why: pfblockerng_tick()
 * reads/writes the due-ledger at $pfb['dbdir'] (not injectable), and a
 * dispatching branch's exec() redirect opens $pfb['runlog']/['extraslog'] for
 * real regardless of whether /usr/local/bin/php exists on this dev box).
 *
 * Feed-pass contention and scheduled reservation behavior are pinned by
 * TickScheduleRuntimeTest; this suite keeps fixed cadence and manual apply paths.
 */
final class TickFeedPassDeferralTest extends TestCase
{
	/**
	 * Reaper for a stuck run, never a deadline the dispatch contract is judged against
	 * (#2024, tracker #1517). Its expiry says STUCK/ENVIRONMENT and nothing about tick.
	 */
	private const SALVAGE_CAP_S = 30.0;

	/** Per-test private sandbox for $pfb['dbdir'] -- see TickEntrypointTest::setUp(). */
	private string $dbdir = '';

	/** The argv recorder and spawn log used by fixed-job/manual-apply regressions. */
	private string $recorderPath = '';

	private string $spawnLog = '';

	private bool $hadDbdir = FALSE;
	private mixed $originalDbdir = NULL;
	private bool $hadRunlog = FALSE;
	private mixed $originalRunlog = NULL;
	private bool $hadExtraslog = FALSE;
	private mixed $originalExtraslog = NULL;
	private bool $hadStateDir = FALSE;
	private mixed $originalStateDir = NULL;
	private bool $hadPhp = FALSE;
	private mixed $originalPhp = NULL;

	/** Raw fd simulating another process holding the feed-pass lock. */
	private $lockFp = NULL;

	protected function setUp(): void
	{
		$this->hadDbdir      = array_key_exists('dbdir', $GLOBALS['pfb'] ?? []);
		$this->originalDbdir = $GLOBALS['pfb']['dbdir'] ?? NULL;

		$this->hadRunlog      = array_key_exists('runlog', $GLOBALS['pfb'] ?? []);
		$this->originalRunlog = $GLOBALS['pfb']['runlog'] ?? NULL;

		$this->hadExtraslog      = array_key_exists('extraslog', $GLOBALS['pfb'] ?? []);
		$this->originalExtraslog = $GLOBALS['pfb']['extraslog'] ?? NULL;
		$this->hadStateDir      = array_key_exists('schedule_state_dir', $GLOBALS['pfb'] ?? []);
		$this->originalStateDir = $GLOBALS['pfb']['schedule_state_dir'] ?? NULL;

		$this->hadPhp      = array_key_exists('php', $GLOBALS['pfb'] ?? []);
		$this->originalPhp = $GLOBALS['pfb']['php'] ?? NULL;

		$this->dbdir = sys_get_temp_dir() . '/pfb_tick_feedpass_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir']     = $this->dbdir;
		$GLOBALS['pfb']['runlog']    = "{$this->dbdir}/pfblockerng_run.log";
		$GLOBALS['pfb']['extraslog'] = "{$this->dbdir}/extras.log";
		$GLOBALS['pfb']['schedule_state_dir'] = "{$this->dbdir}/state";
		mkdir($GLOBALS['pfb']['schedule_state_dir'], 0755, TRUE);

		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		if (is_resource($this->lockFp)) {
			@flock($this->lockFp, LOCK_UN);
			@fclose($this->lockFp);
			$this->lockFp = NULL;
		}
		// Reset this process's own hold, if the fix under test acquired one --
		// self-encapsulation: a leaked hold would wedge every later test's probe.
		if (function_exists('pfb_feed_pass_release')) {
			pfb_feed_pass_release();
		}

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
		if ($this->hadStateDir) {
			$GLOBALS['pfb']['schedule_state_dir'] = $this->originalStateDir;
		} else {
			unset($GLOBALS['pfb']['schedule_state_dir']);
		}
		if ($this->hadPhp) {
			$GLOBALS['pfb']['php'] = $this->originalPhp;
		} else {
			unset($GLOBALS['pfb']['php']);
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

	/** Mirrors TickEntrypointTest::seedTickPrereqs() -- the minimum pfb_global() needs. */
	private function seedTickPrereqs(string $rawInterval, string $quietHours = ''): void
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

		config_set_path("{$gen}/pfb_interval",    $rawInterval);
		config_set_path("{$gen}/pfb_quiet_hours", $quietHours);

		config_set_path("{$gen}/log_max_log", '3');
	}

	private function seedFutureLedgerEntry(string $jobKey, int $now): void
	{
		pfb_due_ledger_write_entry($jobKey, [
			'last_run' => $now - 3600,
			'next_due' => $now + 3600,
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);
	}

	private function seedDueLedgerEntry(string $jobKey, int $now): void
	{
		pfb_due_ledger_write_entry($jobKey, [
			'last_run' => $now - 86410,
			'next_due' => $now - 10,
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);
	}

	/**
	 * Install the argv recorder and return the $pfb['php'] value that drives it.
	 *
	 * The value is a `<spawn counter>; <recorder>` pair, not a bare path: $pfb['php'] is
	 * interpolated into exec("{$pfb['php']} <script> <args> ... &"), so the counter runs
	 * in the FOREGROUND of that exec() -- the shape installLedgerRequeueCommand() already
	 * relies on -- and only the recorder is backgrounded. exec() returns once the
	 * foreground segment has run, so the moment pfblockerng_tick() returns the spawn log
	 * holds exactly one byte per dispatch: the dispatch COUNT is an observed fact rather
	 * than something awaitRecordedInvocations() has to infer from how long nothing else
	 * showed up (#2024).
	 */
	private function installPhpArgvRecorder(): string
	{
		$this->recorderPath = "{$this->dbdir}/php-recorder";
		$this->spawnLog     = "{$this->dbdir}/php-spawns";
		// Created empty up front so an empty spawn log reads as "tick dispatched nothing"
		// rather than as "the counter never got the chance to run".
		file_put_contents($this->spawnLog, '');
		// The argv file is published by rename, so a *.done.* path is never a partial read.
		$script = <<<'SH'
#!/bin/sh
tmp="${0}.tmp.$$"
printf '%s\0' "$@" > "$tmp"
mv "$tmp" "${0}.done.$$"
SH;
		file_put_contents($this->recorderPath, $script . "\n");
		chmod($this->recorderPath, 0755);
		return 'printf x >> ' . escapeshellarg($this->spawnLog)
			. '; ' . escapeshellarg($this->recorderPath);
	}

	/**
	 * Block until every dispatch this tick spawned has published its argv.
	 *
	 * The wait ends on the event -- one *.done.* marker per counted spawn -- so a tick
	 * that dispatched nothing returns [] immediately and a tick that dispatched twice is
	 * reported as two invocations, both without consulting the clock. The cap below only
	 * reaps a run whose recorder never finished; its expiry is an environment verdict.
	 *
	 * @return list<list<string>>
	 */
	private function awaitRecordedInvocations(): array
	{
		$spawned   = strlen((string) @file_get_contents($this->spawnLog));
		$deadline  = microtime(TRUE) + self::SALVAGE_CAP_S;
		$donePaths = [];
		while (TRUE) {
			$donePaths = glob("{$this->recorderPath}.done.*") ?: [];
			if (count($donePaths) >= $spawned || microtime(TRUE) >= $deadline) {
				break;
			}
			usleep(1000);
		}
		sort($donePaths);
		$this->assertCount($spawned, $donePaths, sprintf(
			'STUCK/ENVIRONMENT: %d of the %d recorder(s) tick spawned published argv within the '
			. '%ss salvage cap -- the run is stuck or the environment is broken, not a '
			. 'behavioural failure', count($donePaths), $spawned, self::SALVAGE_CAP_S));

		$recorded = [];
		foreach ($donePaths as $donePath) {
			$raw = file_get_contents($donePath);
			$this->assertNotFalse($raw, 'PHP argv recorder output must be readable');
			$args = explode("\0", $raw);
			array_pop($args);
			$recorded[] = $args;
		}
		return $recorded;
	}

	private function installLedgerRequeueCommand(): string
	{
		$ledgerPath = "{$this->dbdir}/pfb_due_ledger.json";
		$sourcePath = "{$ledgerPath}.requeued";
		$scriptPath = "{$this->dbdir}/requeue-ledger";
		copy($ledgerPath, $sourcePath);
		file_put_contents($scriptPath, "#!/bin/sh\n/bin/cp "
			. escapeshellarg($sourcePath) . ' ' . escapeshellarg($ledgerPath) . "\n");
		chmod($scriptPath, 0755);
		return $scriptPath;
	}

	/** Hold the feed-pass lock as ANOTHER process would -- a second, independent fd. */
	private function holdLockAsAnotherProcess(): void
	{
		$this->lockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertNotFalse($this->lockFp, 'test setup: failed to open the lock file');
		$this->assertTrue(flock($this->lockFp, LOCK_EX), 'test setup: failed to flock the lock file');
	}

	/**
	 * A "HH:MM-HH:MM" window guaranteed to exclude the CURRENT wall-clock minute
	 * (needed because pfblockerng_tick() calls time() internally -- $now is not
	 * injectable): starts 2 minutes from now, ends 4 minutes from now, so "now"
	 * is always strictly before the window regardless of hour/day wrap.
	 */
	private function outsideWindowNow(): string
	{
		$cur   = ((int) date('G') * 60) + (int) date('i');
		$start = ($cur + 2) % 1440;
		$end   = ($cur + 4) % 1440;
		return sprintf('%02d:%02d-%02d:%02d', intdiv($start, 60), $start % 60, intdiv($end, 60), $end % 60);
	}

	/**
	 * Scenario:
	 *   Given pfb_interval='Disabled' and a future cron ledger entry whose manual
	 *         GUI apply was deferred with pending_apply=TRUE.
	 *   And   the apply window is open and the feed-pass lock is free.
	 *   When  pfblockerng_tick() runs.
	 *   Then  the pending manual apply dispatches once, clears only pending_apply,
	 *         preserves cadence fields, and suppresses same-tick log maintenance.
	 */
	public function testDisabledIntervalDispatchesPendingManualApplyWithoutMovingCadence(): void
	{
		$this->seedTickPrereqs('Disabled');
		pfb_global();
		$GLOBALS['pfb']['php'] = $this->installPhpArgvRecorder();
		if (!is_dir($GLOBALS['pfb']['logdir'])) {
			@mkdir($GLOBALS['pfb']['logdir'], 0755, TRUE);
		}

		$now = time();
		$expected = [
			'last_run'      => $now - 7200,
			'next_due'      => $now + 7200,
			'jitter'        => 37,
			'pending_apply' => TRUE,
		];
		pfb_due_ledger_write_entry('cron', $expected, $GLOBALS['pfb']['dbdir']);
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		$logPath = $GLOBALS['pfb']['log'];
		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");
		$this->assertSame($expected,
			pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']),
			'test setup: disabled cron must start future, pending, and byte-for-byte known');

		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, NULL, NULL, $this->manualRunner());

		$this->assertContains(
			['/usr/local/www/pfblockerng/pfblockerng.php', 'pfb_trigger', 'scope=both', 'force=false', 'trigger=manual'],
			$this->awaitRecordedInvocations(),
			'disabled pending apply must dispatch exactly once with the manual trigger argv');
		$after = json_decode((string) file_get_contents($GLOBALS['pfb']['dbdir'] . '/pfb_due_ledger.json'), TRUE);
		$this->assertArrayNotHasKey('pending_apply', $after['cron'] ?? [],
			'disabled pending apply must clear its manual marker after the synchronous pass');
		$lines = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(['l1', 'l2', 'l3', 'l4', 'l5'], $lines,
			'dispatching the pending manual apply must suppress same-tick log maintenance');
	}

	/**
	 * Scenario:
	 *   Given pfb_interval='Disabled' with pending_apply=TRUE inside the window.
	 *   And   another feed pass holds the lock.
	 *   When  pfblockerng_tick() runs.
	 *   Then  the whole ledger entry remains pending and unchanged for retry.
	 */
	public function testDisabledIntervalRetainsPendingManualApplyWhileFeedPassIsBusy(): void
	{
		$this->seedTickPrereqs('Disabled');
		pfb_global();
		$now = time();
		$expected = [
			'last_run'      => $now - 3600,
			'next_due'      => $now + 3600,
			'jitter'        => 19,
			'pending_apply' => TRUE,
		];
		pfb_due_ledger_write_entry('cron', $expected, $GLOBALS['pfb']['dbdir']);
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);
		$this->holdLockAsAnotherProcess();

		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, NULL, NULL, $this->manualRunner());

		$this->assertSame($expected,
			pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']),
			'busy feed pass must retain disabled pending apply and every cadence field unchanged');
	}

	/**
	 * Scenario:
	 *   Given pfb_interval='Disabled' with pending_apply=TRUE outside the window.
	 *   When  pfblockerng_tick() runs.
	 *   Then  the whole ledger entry remains pending and unchanged for retry.
	 */
	public function testDisabledIntervalRetainsPendingManualApplyOutsideQuietHours(): void
	{
		$this->seedTickPrereqs('Disabled', $this->outsideWindowNow());
		pfb_global();
		$now = time();
		$expected = [
			'last_run'      => $now - 1800,
			'next_due'      => $now + 1800,
			'jitter'        => 11,
			'pending_apply' => TRUE,
		];
		pfb_due_ledger_write_entry('cron', $expected, $GLOBALS['pfb']['dbdir']);
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		pfblockerng_tick();

		$this->assertSame($expected,
			pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']),
			'closed quiet-hours window must retain disabled pending apply and every cadence field unchanged');
	}


	public function testDisabledManualChildRequeueSurvivesDispatch(): void
	{
		$this->seedTickPrereqs('Disabled');
		pfb_global();
		$now = time();
		$expected = [
			'last_run'      => $now - 7200,
			'next_due'      => $now + 7200,
			'jitter'        => 37,
			'pending_apply' => TRUE,
		];
		pfb_due_ledger_write_entry('cron', $expected, $GLOBALS['pfb']['dbdir']);
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl', $now);
		$recorderCmd = $this->installPhpArgvRecorder();
		$requeue     = $this->installLedgerRequeueCommand();
		// Another foreground segment ahead of the recorder's own -- both run inside the
		// dispatching exec(), only the recorder is backgrounded.
		$GLOBALS['pfb']['php'] = escapeshellarg($requeue) . '; ' . $recorderCmd;

		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, NULL, NULL, $this->manualRunner());

		$this->assertContains(
			['/usr/local/www/pfblockerng/pfblockerng.php', 'pfb_trigger', 'scope=both', 'force=false', 'trigger=manual'],
			$this->awaitRecordedInvocations());
		$this->assertSame($expected,
			pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']),
			'a child lock-loss requeue must survive the parent dispatch path');
	}

	public function testPendingManualApplyRunsSynchronouslyInsideDispatcherLock(): void
	{
		$this->seedTickPrereqs('Disabled');
		pfb_global();
		$now = time();
		pfb_due_ledger_write_entry('cron', [
			'last_run' => $now - 60, 'next_due' => $now + 60, 'jitter' => 0, 'pending_apply' => TRUE,
		], $GLOBALS['pfb']['dbdir']);
		$ran = 0;
		$locked = FALSE;
		$runner = function () use (&$ran, &$locked): bool {
			$ran++;
			$probe = fopen($GLOBALS['pfb']['schedule_state_dir'] . '/pfb_schedule_dispatch.lock', 'c');
			$this->assertNotFalse($probe);
			$locked = !flock($probe, LOCK_EX | LOCK_NB);
			fclose($probe);
			return TRUE;
		};

		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, NULL, NULL, $runner);

		$this->assertSame(1, $ran);
		$this->assertTrue($locked);
	}

	private function manualRunner(): callable
	{
		return static function (): bool {
			global $pfb;
			$status = 1;
			exec("{$pfb['php']} /usr/local/www/pfblockerng/pfblockerng.php pfb_trigger scope=both force=false trigger=manual >> {$pfb['runlog']} 2>&1", $output, $status);
			return $status === 0;
		};
	}

	public function testDefaultPhpExecutableIsProductionPhp(): void
	{
		$this->assertSame('/usr/local/bin/php', $GLOBALS['pfb']['php']);
	}
}
