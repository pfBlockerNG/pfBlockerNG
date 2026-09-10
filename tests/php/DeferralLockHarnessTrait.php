<?php

declare(strict_types=1);

use PHPUnit\Framework\Assert;

/** Shared lock contention and log readers; consuming suites own paths and fixture lifecycle. */
trait DeferralLockHarnessTrait
{
	/** @var array<int, resource> Raw holds simulate another process; never publish them in lock globals. */
	private array $rawFps = [];

	private function mainLog(): string
	{
		$log = $GLOBALS['pfb']['log'];
		return is_file($log) ? (string) file_get_contents($log) : '';
	}

	private function syslogMessages(): string
	{
		return implode("\n", array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
	}

	private function holdDispatcherLock(): void
	{
		$fp = fopen("{$GLOBALS['pfb']['schedule_state_dir']}/pfb_schedule_dispatch.lock", 'c');
		Assert::assertIsResource($fp, 'test setup: could not open the dispatcher lock');
		$this->rawFps[] = $fp;
		Assert::assertTrue(flock($fp, LOCK_EX), 'test setup: could not hold the dispatcher lock');
	}

	private function holdFeedPassLock(): void
	{
		$fp = fopen("{$GLOBALS['pfb']['dbdir']}/pfb_feed_pass.lock", 'c');
		Assert::assertIsResource($fp, 'test setup: could not open the feed-pass lock');
		$this->rawFps[] = $fp;
		Assert::assertTrue(flock($fp, LOCK_EX), 'test setup: could not hold the feed-pass lock');
	}

	private function resetDeferralLocks(): void
	{
		// Inherited handles would bypass the guards through the reentrancy short-circuit.
		unset($GLOBALS['pfb_schedule_dispatch_lock'], $GLOBALS['pfb_feed_pass_lock']);
	}

	private function releaseDeferralLocks(): void
	{
		foreach ($this->rawFps as $fp) {
			if (is_resource($fp)) {
				@flock($fp, LOCK_UN);
				@fclose($fp);
			}
		}
		$this->rawFps = [];
		pfb_feed_pass_release();
		pfb_schedule_dispatch_release();
		$this->resetDeferralLocks();
	}
}
