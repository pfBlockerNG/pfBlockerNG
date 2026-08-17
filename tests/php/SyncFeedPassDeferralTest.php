<?php

declare(strict_types=1);

require_once __DIR__ . '/SyncPrereqSeedTrait.php';

use PHPUnit\Framework\TestCase;

/**
 * issue #1277 -- a GUI Save/Force (sync_package_pfblockerng(), the funnel both
 * pfblockerng_general.php's Save and pfblockerng_update.php's Force/Run Now
 * call) must schedule a retry when it loses the cross-process feed-pass lock
 * race, mirroring pfblockerng_tick()'s existing 'cron' pending_apply deferral
 * (TickFeedPassDeferralTest::testDueCronDefersWhenFeedPassLockIsHeld) instead
 * of silently dropping the requested change.
 *
 * Lock-hold technique: FeedPassLockTest's -- a second, independent fopen()
 * handle flock(LOCK_EX)s the SAME lock path; flock is per open-file-
 * description, so this genuinely contends even within one PHP process.
 *
 * Red->green: before this change the lock-loss branch was a bare `return;`
 * with no due-ledger write, so `pfb_due_ledger_read_entry('cron', $dbdir)`
 * stayed NULL after a lost race -- nothing ever scheduled a retry.
 */
final class SyncFeedPassDeferralTest extends TestCase
{
	use SyncPrereqSeedTrait;

	private string $dbdir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];
	private bool $hadConfig = FALSE;
	private mixed $originalConfig = NULL;
	private bool $hadChrootPath = FALSE;
	private mixed $originalChrootPath = NULL;

	/** Raw fd simulating another process holding the feed-pass lock. */
	private $lockFp = NULL;
	private $dispatchLockFp = NULL;

	protected function setUp(): void
	{
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->hadConfig      = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->hadChrootPath      = array_key_exists('unbound_chroot_path', $GLOBALS['g'] ?? []);
		$this->originalChrootPath = $GLOBALS['g']['unbound_chroot_path'] ?? NULL;

		$this->dbdir = sys_get_temp_dir() . '/pfb_sync_feedpass_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir'             => $this->dbdir,
			'schedule_state_dir' => $this->dbdir,
			'log'               => "{$this->dbdir}/pfblockerng.log",
			'errlog'            => "{$this->dbdir}/error.log",
			'runlog'            => "{$this->dbdir}/run.log",
			'pending_marker'     => "{$this->dbdir}/pfb_pending_changes",
		]);

		$GLOBALS['config'] = [];
		$this->seedSyncPrereqs();
	}

	protected function tearDown(): void
	{
		if (is_resource($this->lockFp)) {
			@flock($this->lockFp, LOCK_UN);
			@fclose($this->lockFp);
			$this->lockFp = NULL;
		}
		if (is_resource($this->dispatchLockFp)) {
			@flock($this->dispatchLockFp, LOCK_UN);
			@fclose($this->dispatchLockFp);
			$this->dispatchLockFp = NULL;
		}
		// Self-encapsulation: never leave this process holding the lock across tests.
		pfb_feed_pass_release();

		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		// issue #1277 review: setUp() mutates these two shared globals too --
		// restore them so a later test never inherits this fixture's state.
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
		if ($this->hadChrootPath) {
			$GLOBALS['g']['unbound_chroot_path'] = $this->originalChrootPath;
		} else {
			unset($GLOBALS['g']['unbound_chroot_path']);
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


	/** Hold the feed-pass lock as ANOTHER process would -- a second, independent fd. */
	private function holdLockAsAnotherProcess(): void
	{
		$this->lockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertNotFalse($this->lockFp, 'test setup: failed to open the lock file');
		$this->assertTrue(flock($this->lockFp, LOCK_EX), 'test setup: failed to flock the lock file');
	}

	// -----------------------------------------------------------------------
	// The RED->GREEN pinning test.
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given a 'cron' due-ledger entry with next_due far in the future (proves
	 *   the deferral does NOT go through mark_ran/mark_ran_anchored).
	 *   And   ANOTHER process holds the feed-pass lock (simulated raw flock).
	 *   Before: the entry's next_due is the seeded future timestamp.
	 *   When  sync_package_pfblockerng() (the GUI Save/Force funnel) runs and
	 *         loses the lock race.
	 *   Then  next_due is UNCHANGED (no dispatch happened) AND pending_apply is
	 *         set, so the next cron tick retries the dropped change -- mirrors
	 *         TickFeedPassDeferralTest::testDueCronDefersWhenFeedPassLockIsHeld's
	 *         assertion shape.
	 */
	public function testLockLossSetsPendingApplyWithoutAdvancingNextDue(): void
	{
		$now = time();

		pfb_due_ledger_write_entry('cron', [
			'last_run' => $now - 3600,
			'next_due' => $now + 3600,
			'jitter'   => 0,
		], $this->dbdir);

		$this->holdLockAsAnotherProcess();

		$before = pfb_due_ledger_read_entry('cron', $this->dbdir);
		$this->assertNotNull($before, 'test setup: cron ledger entry must exist before the call');
		$this->assertSame($now + 3600, $before['next_due'], 'test setup sanity: seeded future next_due');

		// Act -- a GUI Save/Force loses the feed-pass lock race.
		$this->assertFalse(sync_package_pfblockerng(), 'lock deferral must be observable by CLI/manual callers');

		$after = pfb_due_ledger_read_entry('cron', $this->dbdir);
		$this->assertNotNull($after, 'cron ledger entry must still exist after the lost race');
		$this->assertSame($now + 3600, $after['next_due'],
			'cron next_due must be UNCHANGED (no dispatch happened -- mark_ran/mark_ran_anchored never ran): '
			. "expected {$now}+3600 got {$after['next_due']}");
		$this->assertTrue(!empty($after['pending_apply']),
			'cron ledger entry must be marked pending_apply so the next tick retries the dropped GUI change');
	}

	public function testUpdateDefersBeforeFeedWorkWhenDispatcherLockIsHeld(): void
	{
		$now = time();
		$this->assertTrue(pfb_due_ledger_write_entry('cron', [
			'last_run' => $now - 3600,
			'next_due' => $now + 3600,
			'jitter'   => 0,
		], $this->dbdir));
		$this->dispatchLockFp = fopen("{$this->dbdir}/pfb_schedule_dispatch.lock", 'c');
		$this->assertNotFalse($this->dispatchLockFp);
		$this->assertTrue(flock($this->dispatchLockFp, LOCK_EX));
		$before = file_get_contents("{$this->dbdir}/pfb_due_ledger.json");
		$this->assertIsString($before);

		$GLOBALS['g']['pfblockerng_install'] = TRUE;
		try {
			$this->assertFalse(sync_package_pfblockerng(), 'dispatcher deferral must be observable by callers');
		} finally {
			unset($GLOBALS['g']['pfblockerng_install']);
		}

		$this->assertSame($before, file_get_contents("{$this->dbdir}/pfb_due_ledger.json"),
			'Lock contention must not mutate the active cache or its markers.');
		$this->assertTrue(pfb_pending_changes(),
			'The durable request marker must preserve an update deferred before feed work starts.');
	}
}
