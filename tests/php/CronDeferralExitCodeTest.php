<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';

/**
 * Issue #2491: a DEFERRED scheduled feed pass is a benign skip, not a failure.
 *
 * `pfblockerng.php:255` is `exit(pfblockerng_sync_cron() ? 0 : 1)`, and the tick
 * consumer (`pfblockerng_extra.inc:5988`) discards the return value entirely, so this
 * boolean's only meaning is the cron process's exit code.
 *
 * Three paths return FALSE today, and they are not the same kind of event:
 *
 *   cron.inc:266  dispatcher lock unavailable  -> deferred, occurrences retained
 *   cron.inc:277  feed lock unavailable        -> deferred, occurrences retained
 *   cron.inc:306  runtime model/state missing  -> genuine failure (logged as logtype 2)
 *                   (inside `if (\$scheduled_runtime)`, so cron-path only —
 *                    unreachable under Force Check)
 *
 * The first two mean another pass is already doing the work and the run stood down with
 * its durable pending occurrence intact — the next tick retries. The code's own wording
 * says as much: "deferred ... durable pending occurrences retained".
 *
 * SCOPE, precisely: the installed crontab entry is `pfblockerng.php cron-tick`
 * (pfblockerng.inc:7665), which always exits 0 and whose feed dispatch discards this
 * boolean — and pfblockerng.inc:7685 actively REMOVES any legacy `pfblockerng.php cron`
 * entry on every sync pass. So no scheduled job has surfaced this exit code. What
 * changes is the `cron` verb run by hand at the CLI or by a third-party wrapper: it no
 * longer reports failure for a benign deferral, which also makes production agree with
 * tests/smoke/test_feed_pass_lock.py:127 for the first time.
 *
 * The third is a real failure and must keep exiting non-zero, otherwise this change
 * would trade false alarms for silent breakage.
 *
 * The benign reading applies ONLY to the unattended cron verb. Force Check
 * (`pfblockerng.php:304`, `$force_all = TRUE`) means an operator asked for an update NOW
 * and did not get one — that stays observable, as `SyncCronFeedPassDeferralTest` pins.
 *
 * Rows 1-2 are RED before the fix (they return FALSE); row 3 is the before-state guard
 * that keeps the fix honest and passes both before and after.
 */
final class CronDeferralExitCodeTest extends TestCase
{
	private string $dbdir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];
	private bool $hadConfig = FALSE;
	private mixed $originalConfig = NULL;

	/** Raw fds simulating ANOTHER process holding a lock. */
	private $feedLockFp = NULL;
	private $dispatchLockFp = NULL;

	protected function setUp(): void
	{
		$this->hadPfb         = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb    = $GLOBALS['pfb'] ?? [];
		$this->hadConfig      = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? NULL;

		$this->dbdir = sys_get_temp_dir() . '/pfb_cron_defer_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir'              => $this->dbdir,
			'schedule_state_dir' => $this->dbdir,
			'log'                => "{$this->dbdir}/pfblockerng.log",
			'errlog'             => "{$this->dbdir}/error.log",
			'runlog'             => "{$this->dbdir}/run.log",
			'pending_marker'     => "{$this->dbdir}/pfb_pending_changes",
		]);
		$GLOBALS['config'] = [];

		// No inherited locks: a leaked handle would make a deferral row pass vacuously
		// (the reentrancy short-circuit returns TRUE without ever reaching the guard).
		unset($GLOBALS['pfb_schedule_dispatch_lock'], $GLOBALS['pfb_feed_pass_lock']);
	}

	protected function tearDown(): void
	{
		foreach ([$this->feedLockFp, $this->dispatchLockFp] as $fp) {
			if (is_resource($fp)) {
				@flock($fp, LOCK_UN);
				@fclose($fp);
			}
		}
		$this->feedLockFp = $this->dispatchLockFp = NULL;

		pfb_feed_pass_release();
		if (isset($GLOBALS['pfb_schedule_dispatch_lock']) && is_resource($GLOBALS['pfb_schedule_dispatch_lock'])) {
			@flock($GLOBALS['pfb_schedule_dispatch_lock'], LOCK_UN);
			@fclose($GLOBALS['pfb_schedule_dispatch_lock']);
		}
		unset($GLOBALS['pfb_schedule_dispatch_lock'], $GLOBALS['pfb_feed_pass_lock']);

		foreach (glob("{$this->dbdir}/*") ?: [] as $path) {
			is_dir($path) ? @rmdir($path) : @unlink($path);
		}
		@rmdir($this->dbdir);

		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	private function mainLog(): string
	{
		$log = $GLOBALS['pfb']['log'];
		return is_file($log) ? (string) file_get_contents($log) : '';
	}

	public function testDispatcherLockHeldExitsCleanly(): void
	{
		$this->dispatchLockFp = fopen("{$this->dbdir}/pfb_schedule_dispatch.lock", 'c');
		$this->assertIsResource($this->dispatchLockFp, 'test setup: could not open the dispatcher lock');
		$this->assertTrue(flock($this->dispatchLockFp, LOCK_EX), 'test setup: could not hold the dispatcher lock');

		$result = pfblockerng_sync_cron();

		$this->assertStringContainsString('dispatcher lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the dispatcher-deferral path');
		$this->assertTrue($result,
			'a deferred pass retains its occurrences and retries next tick — cron must exit 0 (issue #2491)');
	}

	public function testFeedPassLockHeldExitsCleanly(): void
	{
		$this->feedLockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertIsResource($this->feedLockFp, 'test setup: could not open the feed-pass lock');
		$this->assertTrue(flock($this->feedLockFp, LOCK_EX), 'test setup: could not hold the feed-pass lock');

		$result = pfblockerng_sync_cron();

		$this->assertStringContainsString('feed lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the feed-pass deferral path');
		$this->assertTrue($result,
			'a deferred pass retains its occurrences and retries next tick — cron must exit 0 (issue #2491)');
	}

	public function testForceCheckDeferralStaysObservable(): void
	{
		$this->feedLockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertIsResource($this->feedLockFp, 'test setup: could not open the feed-pass lock');
		$this->assertTrue(flock($this->feedLockFp, LOCK_EX), 'test setup: could not hold the feed-pass lock');

		// $force_all = TRUE is the Force Check caller (pfblockerng.php:304).
		$result = pfblockerng_sync_cron(TRUE);

		$this->assertStringContainsString('feed lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the feed-pass deferral path');
		$this->assertFalse($result,
			'an operator-initiated Force Check that was deferred must still report failure — '
			. 'the benign reading is for the unattended cron verb only (issue #2491)');
	}

	public function testForceCheckDispatcherDeferralStaysObservable(): void
	{
		// Without this row, reverting the dispatcher guard to a bare `return TRUE`
		// fails nothing: the feed-lock row below covers only that one guard.
		$this->dispatchLockFp = fopen("{$this->dbdir}/pfb_schedule_dispatch.lock", 'c');
		$this->assertIsResource($this->dispatchLockFp, 'test setup: could not open the dispatcher lock');
		$this->assertTrue(flock($this->dispatchLockFp, LOCK_EX), 'test setup: could not hold the dispatcher lock');

		$result = pfblockerng_sync_cron(TRUE);

		$this->assertStringContainsString('dispatcher lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the dispatcher-deferral path');
		$this->assertFalse($result,
			'Force Check deferred at the dispatcher lock must still report failure (issue #2491)');
	}

	public function testRuntimeUnavailableStillFails(): void
	{
		// Reach the genuine-failure guard with BOTH LOCKS HEALTHY. Do not do this by
		// pointing schedule_state_dir at a missing directory: the dispatcher lock file
		// lives there too, so the run would take the DEFERRAL path instead and this row
		// would pass for the wrong reason (it did, before this was corrected).
		// An unparseable state file makes pfb_schedule_state_read() return NULL
		// (pfblockerng_extra.inc) while both locks acquire normally.
		file_put_contents("{$this->dbdir}/pfb_schedule_state.json", 'not json at all');

		$result = pfblockerng_sync_cron();

		$log = $this->mainLog();
		$this->assertStringContainsString('runtime unavailable', $log,
			'before-state: the run must actually have reached the genuine-failure guard');
		$this->assertStringNotContainsString('lock unavailable', $log,
			'this row must not be taking a deferral path — that would pass for the wrong reason');
		$this->assertFalse($result,
			'a genuine runtime failure must KEEP exiting non-zero — this fix must not trade '
			. 'false alarms for silent breakage (issue #2491)');
	}
}
