<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';
require_once __DIR__ . '/support/FailingFlockStream.php';

/**
 * Issue #2591: pfblockerng_sync_cron() keeps its established bool while exposing
 * lock identity through an optional by-reference result.
 *
 * Scheduled deferrals retain TRUE, Force Check deferrals retain FALSE, and genuine
 * failures leave the reason NULL. The CLI maps either lock reason to EX_TEMPFAIL.
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

	public function testDispatcherLockPreservesScheduledTrueAndNamesLock(): void
	{
		$this->dispatchLockFp = fopen("{$this->dbdir}/pfb_schedule_dispatch.lock", 'c');
		$this->assertIsResource($this->dispatchLockFp, 'test setup: could not open the dispatcher lock');
		$this->assertTrue(flock($this->dispatchLockFp, LOCK_EX), 'test setup: could not hold the dispatcher lock');
		$deferredBy = NULL;

		$result = pfblockerng_sync_cron(FALSE, 'both', FALSE, FALSE, $deferredBy);

		$this->assertStringContainsString('dispatcher lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the dispatcher-deferral path');
		$this->assertTrue($result, 'scheduled deferral must retain the established TRUE internal return');
		$this->assertSame('dispatcher-lock', $deferredBy);
	}

	public function testFeedPassLockPreservesScheduledTrueAndNamesLock(): void
	{
		$this->feedLockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertIsResource($this->feedLockFp, 'test setup: could not open the feed-pass lock');
		$this->assertTrue(flock($this->feedLockFp, LOCK_EX), 'test setup: could not hold the feed-pass lock');
		$deferredBy = NULL;

		$result = pfblockerng_sync_cron(FALSE, 'both', FALSE, FALSE, $deferredBy);

		$this->assertStringContainsString('feed lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the feed-pass deferral path');
		$this->assertTrue($result, 'scheduled deferral must retain the established TRUE internal return');
		$this->assertSame('feed-pass-lock', $deferredBy);
	}

	public function testForceCheckFeedPassDeferralPreservesFalseAndNamesLock(): void
	{
		$this->feedLockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertIsResource($this->feedLockFp, 'test setup: could not open the feed-pass lock');
		$this->assertTrue(flock($this->feedLockFp, LOCK_EX), 'test setup: could not hold the feed-pass lock');
		$deferredBy = NULL;

		$result = pfblockerng_sync_cron(TRUE, 'both', FALSE, FALSE, $deferredBy);

		$this->assertStringContainsString('feed lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the feed-pass deferral path');
		$this->assertFalse($result, 'Force Check must retain the established FALSE internal return');
		$this->assertSame('feed-pass-lock', $deferredBy);
	}

	public function testForceCheckDispatcherDeferralPreservesFalseAndNamesLock(): void
	{
		$this->dispatchLockFp = fopen("{$this->dbdir}/pfb_schedule_dispatch.lock", 'c');
		$this->assertIsResource($this->dispatchLockFp, 'test setup: could not open the dispatcher lock');
		$this->assertTrue(flock($this->dispatchLockFp, LOCK_EX), 'test setup: could not hold the dispatcher lock');
		$deferredBy = NULL;

		$result = pfblockerng_sync_cron(TRUE, 'both', FALSE, FALSE, $deferredBy);

		$this->assertStringContainsString('dispatcher lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the dispatcher-deferral path');
		$this->assertFalse($result, 'Force Check must retain the established FALSE internal return');
		$this->assertSame('dispatcher-lock', $deferredBy);
	}

	public function testDispatcherOpenErrorFailsWithoutDeferralReason(): void
	{
		$GLOBALS['pfb']['schedule_state_dir'] = "{$this->dbdir}/missing/child";
		$deferredBy = NULL;

		$result = pfblockerng_sync_cron(FALSE, 'both', FALSE, FALSE, $deferredBy);

		$this->assertFalse($result, 'dispatcher open error must remain a real failure');
		$this->assertNull($deferredBy, 'dispatcher open error must map to CLI rc=1, not lock-deferral rc=75');
	}

	public function testDispatcherFlockErrorFailsWithoutDeferralReason(): void
	{
		$this->assertTrue(stream_wrapper_register('pfbcrondispatcherror', PfbFailingFlockStream::class));
		try {
			$GLOBALS['pfb']['schedule_state_dir'] = 'pfbcrondispatcherror://state';
			$deferredBy = NULL;

			$result = pfblockerng_sync_cron(FALSE, 'both', FALSE, FALSE, $deferredBy);

			$this->assertFalse($result, 'dispatcher flock error must remain a real failure');
			$this->assertNull($deferredBy, 'dispatcher flock error must map to CLI rc=1, not lock-deferral rc=75');
		} finally {
			stream_wrapper_unregister('pfbcrondispatcherror');
		}
	}

	public function testFeedPassFlockErrorFailsWithoutDeferralReason(): void
	{
		$this->assertTrue(stream_wrapper_register('pfbcronfeederror', PfbFailingFlockStream::class));
		try {
			$GLOBALS['pfb']['schedule_state_dir'] = $this->dbdir;
			$GLOBALS['pfb']['dbdir'] = 'pfbcronfeederror://state';
			$deferredBy = NULL;

			$result = pfblockerng_sync_cron(FALSE, 'both', FALSE, FALSE, $deferredBy);

			$this->assertFalse($result, 'feed-pass flock error must remain a real failure');
			$this->assertNull($deferredBy, 'feed-pass flock error must map to CLI rc=1, not lock-deferral rc=75');
		} finally {
			stream_wrapper_unregister('pfbcronfeederror');
		}
	}

	public function testRuntimeUnavailableStillFailsWithoutDeferralReason(): void
	{
		file_put_contents("{$this->dbdir}/pfb_schedule_state.json", 'not json at all');
		$deferredBy = NULL;

		$result = pfblockerng_sync_cron(FALSE, 'both', FALSE, FALSE, $deferredBy);

		$log = $this->mainLog();
		$this->assertStringContainsString('runtime unavailable', $log,
			'before-state: the run must actually have reached the genuine-failure guard');
		$this->assertStringNotContainsString('lock unavailable', $log,
			'this row must not be taking a deferral path — that would pass for the wrong reason');
		$this->assertFalse($result, 'a genuine runtime failure must retain its FALSE internal return');
		$this->assertNull($deferredBy, 'a real failure must map to rc=1, not lock-deferral rc=75');
	}
}
