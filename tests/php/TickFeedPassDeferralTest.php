<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1175 — pfblockerng_tick() must DEFER its feed-cron dispatch when a feed
 * pass is already running, instead of dispatching a second overlapping pass that
 * races the shared recompute staging files (masterfile.new etc.).
 *
 * Drives the REAL pfblockerng_tick() entrypoint (TickEntrypointTest's sandbox
 * pattern: a private $pfb['dbdir']/runlog/extraslog per test, restored on
 * teardown -- see that suite's setUp() comment for why: pfblockerng_tick()
 * reads/writes the due-ledger at $pfb['dbdir'] (not injectable), and a
 * dispatching branch's exec() redirect opens $pfb['runlog']/['extraslog'] for
 * real regardless of whether /usr/local/bin/php exists on this dev box).
 *
 * The running pass is simulated WITHOUT the pfb_feed_pass_* helpers under test
 * in the deferral cases below (they must hold across the RED run, where they do
 * not exist yet): this suite fopen()s the lock file itself and flock(LOCK_EX)s
 * it on its OWN handle -- a second, independent open file description
 * contending for the SAME file. flock(2) locks belong to the open file
 * description, not the process, so two handles in one process genuinely
 * contend, and the kernel drops the lock on process death (a crashed pass can
 * never wedge the system).
 *
 * Red->green: before this change pfblockerng_tick()'s feed-cron dispatch branch
 * had no running-pass check -- it always exec()'d and mark_ran_anchored()'d the
 * ledger, even while another pass held the lock. testDueCronDefersWhenFeedPassLockIsHeld
 * drives that branch with a due 'cron' job while the lock is held and pins (a)
 * the ledger entry's next_due is untouched (no dispatch) and (b) pending_apply
 * is set so the next tick retries.
 */
final class TickFeedPassDeferralTest extends TestCase
{
	/** Per-test private sandbox for $pfb['dbdir'] -- see TickEntrypointTest::setUp(). */
	private string $dbdir = '';

	private bool $hadDbdir = FALSE;
	private mixed $originalDbdir = NULL;
	private bool $hadRunlog = FALSE;
	private mixed $originalRunlog = NULL;
	private bool $hadExtraslog = FALSE;
	private mixed $originalExtraslog = NULL;
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

		$this->hadPhp      = array_key_exists('php', $GLOBALS['pfb'] ?? []);
		$this->originalPhp = $GLOBALS['pfb']['php'] ?? NULL;

		$this->dbdir = sys_get_temp_dir() . '/pfb_tick_feedpass_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir']     = $this->dbdir;
		$GLOBALS['pfb']['runlog']    = "{$this->dbdir}/pfblockerng_run.log";
		$GLOBALS['pfb']['extraslog'] = "{$this->dbdir}/extras.log";

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

	private function installPhpArgvRecorder(): string
	{
		$phpPath = "{$this->dbdir}/php-recorder";
		$script   = <<<'SH'
#!/bin/sh
active="${0}.active.$$"
done="${0}.done.$$"
tmp="${done}.tmp"
: > "$active"
trap 'rm -f "$active" "$tmp"' EXIT HUP INT TERM
printf '%s\0' "$@" > "$tmp"
mv "$tmp" "$done"
SH;
		file_put_contents($phpPath, $script . "\n");
		chmod($phpPath, 0755);
		return $phpPath;
	}

	/** @return list<list<string>> */
	private function awaitRecordedInvocations(string $phpPath): array
	{
		$deadline    = hrtime(TRUE) + 2_000_000_000;
		$stableSince = NULL;
		$donePaths   = [];
		while (hrtime(TRUE) < $deadline) {
			$now         = hrtime(TRUE);
			$currentDone = glob("{$phpPath}.done.*") ?: [];
			$activePaths = glob("{$phpPath}.active.*") ?: [];
			sort($currentDone);
			if ($currentDone !== [] && $activePaths === []) {
				if ($currentDone !== $donePaths) {
					$donePaths   = $currentDone;
					$stableSince = $now;
				} elseif ($stableSince !== NULL && $now - $stableSince >= 200_000_000) {
					break;
				}
			} else {
				$stableSince = NULL;
			}
			usleep(1000);
		}
		$this->assertNotEmpty($donePaths,
			'tick dispatch must complete at the configured PHP executable within 2 seconds');
		$this->assertSame([], glob("{$phpPath}.active.*") ?: [],
			'all configured PHP invocations must finish before argv is asserted');

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

	// -----------------------------------------------------------------------
	// Row 11 (coverage matrix) -- the RED->GREEN pinning test.
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given a due 'cron' ledger entry (10s past due) and pfb_interval='24'.
	 *   And   ANOTHER process holds the feed-pass lock (simulated raw flock).
	 *   Before: the 'cron' entry's next_due is 10s in the past (due).
	 *   When  pfblockerng_tick() runs.
	 *   Then  the feed cron is NOT dispatched -- next_due is UNCHANGED (no
	 *         mark_ran/mark_ran_anchored) -- AND pending_apply is set so the
	 *         next tick retries the deferred dispatch.
	 */
	public function testDueCronDefersWhenFeedPassLockIsHeld(): void
	{
		$this->seedTickPrereqs('24');
		pfb_global();
		if (!is_dir($GLOBALS['pfb']['logdir'])) {
			@mkdir($GLOBALS['pfb']['logdir'], 0755, TRUE);
		}

		$now      = time();
		$interval = 86400;

		pfb_due_ledger_write_entry('cron', [
			'last_run' => $now - $interval - 10,
			'next_due' => $now - 10,	// 10s past due -- would dispatch this tick
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);

		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		$this->holdLockAsAnotherProcess();

		$before = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($before, 'test setup: cron ledger entry must exist before the tick');
		$this->assertSame($now - 10, $before['next_due'], 'test setup sanity: cron ledger entry pre-seeded due');

		// Act.
		pfblockerng_tick();

		$after = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($after, 'cron ledger entry must still exist after the tick');
		$this->assertSame($now - 10, $after['next_due'],
			'cron next_due must be UNCHANGED (no dispatch while a feed pass is running): expected '
			. ($now - 10) . " got {$after['next_due']}");
		$this->assertTrue(!empty($after['pending_apply']),
			'cron ledger entry must be marked pending_apply so the NEXT tick retries the deferred dispatch');
	}

	// -----------------------------------------------------------------------
	// Row 12 -- regression pin: a due cron dispatches normally when the lock
	// is free (the new check must not block legitimate work).
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given a due 'cron' ledger entry and pfb_interval='24'; NO other process
	 *   holds the feed-pass lock.
	 *   When  pfblockerng_tick() runs.
	 *   Then  the feed cron IS dispatched -- next_due advances by exactly the
	 *         interval from its own previous next_due (mark_ran_anchored), and
	 *         no pending_apply flag is left set.
	 */
	public function testDueCronDispatchesWhenFeedPassLockIsFree(): void
	{
		$this->seedTickPrereqs('24');
		pfb_global();
		if (!is_dir($GLOBALS['pfb']['logdir'])) {
			@mkdir($GLOBALS['pfb']['logdir'], 0755, TRUE);
		}

		$now      = time();
		$interval = 86400;
		$oldNextDue = $now - 10;

		pfb_due_ledger_write_entry('cron', [
			'last_run' => $oldNextDue - $interval,
			'next_due' => $oldNextDue,
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);

		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		// Act -- no lock held anywhere.
		pfblockerng_tick();

		$after = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($after, 'cron ledger entry must exist after the tick');
		$this->assertSame($oldNextDue + $interval, $after['next_due'],
			'cron next_due must advance by exactly the interval when the lock is free: expected '
			. ($oldNextDue + $interval) . " got {$after['next_due']}");
		$this->assertTrue(empty($after['pending_apply']),
			'a dispatched cron must not be left pending_apply');
	}

	// -----------------------------------------------------------------------
	// Row 13 -- retry: a job deferred by a prior tick's busy lock dispatches
	// on the NEXT tick once the lock has freed.
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given a 'cron' ledger entry left pending_apply=TRUE by a prior deferred
	 *   tick (next_due still in the past, untouched by that deferral).
	 *   And   the feed-pass lock is now FREE.
	 *   When  pfblockerng_tick() runs.
	 *   Then  the feed cron IS dispatched this time -- next_due advances and
	 *         pending_apply is cleared (mark_ran_anchored writes a clean entry).
	 */
	public function testPendingFromPriorDeferralDispatchesOnceLockFrees(): void
	{
		$this->seedTickPrereqs('24');
		pfb_global();
		if (!is_dir($GLOBALS['pfb']['logdir'])) {
			@mkdir($GLOBALS['pfb']['logdir'], 0755, TRUE);
		}

		$now      = time();
		$interval = 86400;
		$oldNextDue = $now - 10;

		// Simulates the Row-11 outcome: still due, left pending by a prior tick.
		pfb_due_ledger_write_entry('cron', [
			'last_run'      => $oldNextDue - $interval,
			'next_due'      => $oldNextDue,
			'jitter'        => 0,
			'pending_apply' => TRUE,
		], $GLOBALS['pfb']['dbdir']);

		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		// Act -- lock is free this time.
		pfblockerng_tick();

		$after = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($after, 'cron ledger entry must exist after the retry tick');
		$this->assertSame($oldNextDue + $interval, $after['next_due'],
			'the retried cron must dispatch and advance next_due by the interval: expected '
			. ($oldNextDue + $interval) . " got {$after['next_due']}");
		$this->assertTrue(empty($after['pending_apply']),
			'a successfully retried dispatch must clear pending_apply');
	}

	// -----------------------------------------------------------------------
	// Row 14 -- quiet-hours interaction: outside the apply window, the
	// existing quiet-hours defer path wins regardless of lock state.
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given a due 'cron' entry, pfb_quiet_hours set to a window that excludes
	 *   "now", AND another process holds the feed-pass lock.
	 *   When  pfblockerng_tick() runs.
	 *   Then  no exception -- the tick defers via the quiet-hours branch (the
	 *         lock check is inside the in-window arm, never reached here) and
	 *         pending_apply is set exactly once.
	 */
	public function testDueCronOutsideQuietHoursDefersRegardlessOfLockState(): void
	{
		$window = $this->outsideWindowNow();
		$this->seedTickPrereqs('24', $window);
		pfb_global();
		if (!is_dir($GLOBALS['pfb']['logdir'])) {
			@mkdir($GLOBALS['pfb']['logdir'], 0755, TRUE);
		}

		$now      = time();
		$interval = 86400;

		pfb_due_ledger_write_entry('cron', [
			'last_run' => $now - $interval - 10,
			'next_due' => $now - 10,
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);

		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		$this->holdLockAsAnotherProcess();

		// Act -- must not throw.
		pfblockerng_tick();

		$after = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($after, 'cron ledger entry must exist after the tick');
		$this->assertTrue(!empty($after['pending_apply']),
			'outside the quiet-hours window the tick must defer via pending_apply, whether or not '
			. 'a feed pass is running');
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
		$fakePhp = $this->installPhpArgvRecorder();
		$GLOBALS['pfb']['php'] = $fakePhp;
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

		pfblockerng_tick();

		$this->assertSame([
			['/usr/local/www/pfblockerng/pfblockerng.php', 'pfb_trigger', 'scope=both', 'force=false', 'trigger=manual'],
		], $this->awaitRecordedInvocations($fakePhp),
			'disabled pending apply must dispatch exactly once with the manual trigger argv');
		$after = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$this->assertSame([
			'last_run' => $expected['last_run'],
			'next_due' => $expected['next_due'],
			'jitter'   => $expected['jitter'],
		], $after,
			'disabled pending apply must clear only pending_apply; cadence fields must remain unchanged');
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

		pfblockerng_tick();

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

	public function testScheduledCronUsesConfiguredPhpExactlyOnce(): void
	{
		$this->seedTickPrereqs('24');
		pfb_global();
		$fakePhp = $this->installPhpArgvRecorder();
		$GLOBALS['pfb']['php'] = $fakePhp;
		$now = time();
		$this->seedDueLedgerEntry('cron', $now);
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl', $now);

		pfblockerng_tick();

		$this->assertSame([
			['/usr/local/www/pfblockerng/pfblockerng.php', 'cron'],
		], $this->awaitRecordedInvocations($fakePhp));
	}

	public function testDccUsesConfiguredPhpExactlyOnce(): void
	{
		$this->seedTickPrereqs('24');
		pfb_global();
		$fakePhp = $this->installPhpArgvRecorder();
		$GLOBALS['pfb']['php'] = $fakePhp;
		$now = time();
		$this->seedFutureLedgerEntry('cron', $now);
		$this->seedDueLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl', $now);

		pfblockerng_tick();

		$this->assertSame([
			['/usr/local/www/pfblockerng/pfblockerng.php', 'dcc'],
		], $this->awaitRecordedInvocations($fakePhp));
	}

	public function testBlUsesConfiguredPhpExactlyOnce(): void
	{
		$this->seedTickPrereqs('24');
		pfb_global();
		$fakePhp = $this->installPhpArgvRecorder();
		$GLOBALS['pfb']['php'] = $fakePhp;
		$GLOBALS['pfb']['enable'] = 'on';
		$GLOBALS['pfb']['blconfig'] = [
			'blacklist_enable'   => 'Enable',
			'blacklist_selected' => 'test-list',
			'item'               => [[
				'xml'      => 'test-list',
				'selected' => 'on',
			]],
		];
		$now = time();
		$this->seedFutureLedgerEntry('cron', $now);
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedDueLedgerEntry('bl', $now);

		pfblockerng_tick();

		$this->assertSame([
			['/usr/local/www/pfblockerng/pfblockerng.php', 'bl', 'test-list'],
		], $this->awaitRecordedInvocations($fakePhp));
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
		$fakePhp = $this->installPhpArgvRecorder();
		$requeue = $this->installLedgerRequeueCommand();
		$GLOBALS['pfb']['php'] = escapeshellarg($requeue) . '; ' . escapeshellarg($fakePhp);

		pfblockerng_tick();

		$this->assertSame([
			['/usr/local/www/pfblockerng/pfblockerng.php', 'pfb_trigger', 'scope=both', 'force=false', 'trigger=manual'],
		], $this->awaitRecordedInvocations($fakePhp));
		$this->assertSame($expected,
			pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']),
			'a child lock-loss requeue must survive the parent dispatch path');
	}

	public function testDefaultPhpExecutableIsProductionPhp(): void
	{
		$this->assertSame('/usr/local/bin/php', $GLOBALS['pfb']['php']);
	}
}
