<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2496: sync_package_pfblockerng()'s silent precondition guards must log.
 *
 * pfblockerng.php:255 is `exit(pfblockerng_sync_cron() ? 0 : 1)`, so a FALSE from
 * sync_package_pfblockerng() surfaces as rc=1 with empty stdout AND stderr. Three of
 * its four early guards return FALSE without writing anything anywhere, which made a
 * 13-test smoke failure undiagnosable until the guards were hand-instrumented:
 *
 *   pfblockerng_apply.inc  pfb_schedule_dispatch_begin() FALSE   — silent
 *   pfblockerng_apply.inc  pfb_stage_publish_dir_recover() FALSE — silent
 *   pfblockerng_apply.inc  pfb_geoip_generation_ready() FALSE    — silent
 *
 * (The fourth, pfb_feed_pass_begin(), logs its own skip inside the callee — pinned by
 * FeedPassLockTest row 11 — so it is deliberately NOT covered here: a call-site line
 * would double-log.)
 *
 * Each row forces exactly one guard to fire, asserts sync_package_pfblockerng()
 * returns FALSE (the before-state, already true), and asserts the main log names the
 * failed precondition (the change under test — RED before the fix).
 *
 * Environment recipe mirrors FeedPassLockTest: temp dbdir/state dir, $pfb['log'] at a
 * temp path, locks held via raw fds where a guard needs contention.
 */
final class SyncGuardLoggingTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const EXTRA = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';

	private string $dir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];
	/** @var array<int, resource> */
	private array $rawFps = [];

	public static function setUpBeforeClass(): void
	{
		require_once self::EXTRA;
		require_once self::APPLY;
	}

	protected function setUp(): void
	{
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->dir = sys_get_temp_dir() . '/pfb_sync_guard_' . uniqid('', TRUE);
		mkdir("{$this->dir}/db", 0755, TRUE);
		mkdir("{$this->dir}/state", 0755, TRUE);
		mkdir("{$this->dir}/cc", 0755, TRUE);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir'              => "{$this->dir}/db",
			'schedule_state_dir' => "{$this->dir}/state",
			'ccdir'              => "{$this->dir}/cc",
			'log'                => "{$this->dir}/pfblockerng.log",
			'errlog'             => "{$this->dir}/error.log",
		]);
		// A previous test (or a reentrant caller) must not lend us its locks.
		unset($GLOBALS['pfb_schedule_dispatch_lock'], $GLOBALS['pfb_feed_pass_lock']);
	}

	protected function tearDown(): void
	{
		foreach ($this->rawFps as $fp) {
			if (is_resource($fp)) {
				@flock($fp, LOCK_UN);
				@fclose($fp);
			}
		}
		$this->rawFps = [];
		// Release anything the function under test acquired before its guard fired.
		if (isset($GLOBALS['pfb_feed_pass_lock']) && is_resource($GLOBALS['pfb_feed_pass_lock'])) {
			@flock($GLOBALS['pfb_feed_pass_lock'], LOCK_UN);
			@fclose($GLOBALS['pfb_feed_pass_lock']);
		}
		if (isset($GLOBALS['pfb_schedule_dispatch_lock']) && is_resource($GLOBALS['pfb_schedule_dispatch_lock'])) {
			@flock($GLOBALS['pfb_schedule_dispatch_lock'], LOCK_UN);
			@fclose($GLOBALS['pfb_schedule_dispatch_lock']);
		}
		unset($GLOBALS['pfb_schedule_dispatch_lock'], $GLOBALS['pfb_feed_pass_lock']);

		$paths = array_merge(
			glob("{$this->dir}/db/*") ?: [],
			glob("{$this->dir}/state/*") ?: [],
			glob("{$this->dir}/cc/*") ?: [],
			glob("{$this->dir}/cc/.*") ?: [],
			glob("{$this->dir}/*") ?: [],
		);
		foreach ($paths as $path) {
			if (basename($path) === '.' || basename($path) === '..') {
				continue;
			}
			is_dir($path) ? @rmdir($path) : @unlink($path);
		}
		@rmdir($this->dir);

		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	private function mainLog(): string
	{
		$log = $GLOBALS['pfb']['log'];
		return is_file($log) ? (string) file_get_contents($log) : '';
	}

	public function testDispatchLockUnavailableLogsThePrecondition(): void
	{
		$holder = fopen("{$this->dir}/state/pfb_schedule_dispatch.lock", 'c');
		$this->assertIsResource($holder, 'test setup: could not open the dispatch lock');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: could not hold the dispatch lock');

		$this->assertFalse(sync_package_pfblockerng('noupdates'),
			'before-state: a held dispatcher lock must abort the sync');
		$this->assertStringContainsString('dispatcher lock', $this->mainLog(),
			'the aborted sync must log WHICH precondition failed (issue #2496): dispatcher lock');
	}

	public function testStagePublishRecoverFailureLogsThePrecondition(): void
	{
		// scandir(FALSE) path: dbdir vanished out from under the run.
		$GLOBALS['pfb']['dbdir'] = "{$this->dir}/db-nonexistent";

		$this->assertFalse(sync_package_pfblockerng('noupdates'),
			'before-state: an unrecoverable stage/publish dir must abort the sync');
		$this->assertStringContainsString('stage/publish', $this->mainLog(),
			'the aborted sync must log WHICH precondition failed (issue #2496): stage/publish recovery');
	}

	public function testGeoipGenerationSwapLogsThePrecondition(): void
	{
		touch("{$this->dir}/cc/.pfb_generation_swapping");

		$this->assertFalse(sync_package_pfblockerng('noupdates'),
			'before-state: an in-flight GeoIP generation swap must abort the sync');
		$this->assertStringContainsString('GeoIP generation', $this->mainLog(),
			'the aborted sync must log WHICH precondition failed (issue #2496): GeoIP generation swap');
	}
}
