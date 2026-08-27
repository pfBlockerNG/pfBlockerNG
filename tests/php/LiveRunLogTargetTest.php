<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin pfb_run_log_target() -- the file a run's RAW output (dispatched-process stdout and hook
 * script output) is appended to (issue #680). The AJAX live tail reads the per-run log, but a run
 * also emits plenty that never goes through pfb_logger(): the hook scripts' own output and system
 * command stdout. Before this, the hook runner appended to the cumulative log ($pfb['log']), which
 * the #671 tail no longer reads -- so hook output and the trailing run block went missing from the
 * live view.
 *
 * The target must be the per-run log WHILE a run is active (runlog_active), so that raw output
 * interleaves with pfb_logger()'s mirror in the file the tail reads; outside a run it falls back to
 * the cumulative log.
 */
#[CoversFunction('pfb_run_log_target')]
final class LiveRunLogTargetTest extends TestCase
{
	protected function tearDown(): void
	{
		global $pfb;
		unset($pfb['runlog_active']);
	}

	public function testActiveRunTargetsThePerRunLog(): void
	{
		global $pfb;
		$pfb['runlog_active'] = TRUE;

		$this->assertSame(
			$pfb['runlog'],
			pfb_run_log_target(),
			'while a run is active, raw output must go to the per-run log the live tail reads'
		);
	}

	public function testOutsideARunFallsBackToTheCumulativeLog(): void
	{
		global $pfb;
		unset($pfb['runlog_active']);

		$this->assertSame(
			$pfb['log'],
			pfb_run_log_target(),
			'outside a run there is nothing tailing, so raw output goes to the cumulative log'
		);
	}

	public function testMissingRunLogPathFallsBackToCumulative(): void
	{
		global $pfb;
		$pfb['runlog_active'] = TRUE;
		$saved = $pfb['runlog'];
		$pfb['runlog'] = '';
		try {
			$this->assertSame($pfb['log'], pfb_run_log_target(), 'no run-log path -> cumulative log');
		} finally {
			$pfb['runlog'] = $saved;
		}
	}
}
