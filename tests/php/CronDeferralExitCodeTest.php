<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';
require_once __DIR__ . '/support/FailingFlockStream.php';
require_once __DIR__ . '/DeferralLockHarnessTrait.php';

/**
 * Issue #2591: pfblockerng_sync_cron() keeps its established bool while exposing
 * lock identity through an optional by-reference result.
 *
 * Scheduled deferrals retain TRUE, Force Check deferrals retain FALSE, and genuine
 * failures leave the reason NULL. The CLI maps either lock reason to EX_TEMPFAIL.
 */
final class CronDeferralExitCodeTest extends TestCase
{
	use DeferralLockHarnessTrait;

	private string $dbdir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];
	private bool $hadConfig = FALSE;
	private mixed $originalConfig = NULL;

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

		$this->resetDeferralLocks();
	}

	protected function tearDown(): void
	{
		$this->releaseDeferralLocks();

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

	public function testDispatcherLockPreservesScheduledTrueAndNamesLock(): void
	{
		$this->holdDispatcherLock();
		$deferredBy = NULL;

		$result = pfblockerng_sync_cron(FALSE, 'both', FALSE, FALSE, $deferredBy);

		$this->assertStringContainsString('dispatcher lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the dispatcher-deferral path');
		$this->assertTrue($result, 'scheduled deferral must retain the established TRUE internal return');
		$this->assertSame('dispatcher-lock', $deferredBy);
	}

	public function testFeedPassLockPreservesScheduledTrueAndNamesLock(): void
	{
		$this->holdFeedPassLock();
		$deferredBy = NULL;

		$result = pfblockerng_sync_cron(FALSE, 'both', FALSE, FALSE, $deferredBy);

		$this->assertStringContainsString('feed lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the feed-pass deferral path');
		$this->assertTrue($result, 'scheduled deferral must retain the established TRUE internal return');
		$this->assertSame('feed-pass-lock', $deferredBy);
	}

	public function testForceCheckFeedPassDeferralPreservesFalseAndNamesLock(): void
	{
		$this->holdFeedPassLock();
		$deferredBy = NULL;

		$result = pfblockerng_sync_cron(TRUE, 'both', FALSE, FALSE, $deferredBy);

		$this->assertStringContainsString('feed lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the feed-pass deferral path');
		$this->assertFalse($result, 'Force Check must retain the established FALSE internal return');
		$this->assertSame('feed-pass-lock', $deferredBy);
	}

	public function testForceCheckDispatcherDeferralPreservesFalseAndNamesLock(): void
	{
		$this->holdDispatcherLock();
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
