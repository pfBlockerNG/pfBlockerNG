<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #2122: every update-pass entrypoint has an explicit fail-closed lock verdict. */
final class UpdateLockCallerWiringTest extends TestCase
{
	private function source(string $relative): string
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/' . $relative);
		$this->assertNotFalse($source, "failed to read {$relative}");
		return $source;
	}

	private function functionBody(string $source, string $startNeedle, string $endNeedle): string
	{
		$start = strpos($source, $startNeedle);
		$this->assertNotFalse($start, "function start missing: {$startNeedle}");
		if ($endNeedle === '') {
			return substr($source, $start);
		}
		$end = strpos($source, $endNeedle, $start);
		$this->assertNotFalse($end, "function end marker missing: {$endNeedle}");
		return substr($source, $start, $end - $start);
	}

	public function testSyncPassWaitsAndNeverWritesPendingWhenAcquireTimesOut(): void
	{
		$source = $this->source('src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$head = $this->functionBody($source, 'function sync_package_pfblockerng', 'pfb_runlog_begin();');

		$this->assertStringContainsString('pfb_feed_pass_begin(\'sync\',TRUE,$pfb_manual_progress)', $head,
			'sync pass must wait up to the shared 45-second budget and expose manual progress');
		$this->assertStringNotContainsString('pfb_due_ledger_set_pending', $head,
			'a pass that never acquired the update lock must not write the ledger');
	}

	public function testCronPassWaitsAndNeverWritesPendingWhenAcquireTimesOut(): void
	{
		$source = $this->source('src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc');
		$head = $this->functionBody($source, 'function pfblockerng_sync_cron', 'pfb_runlog_begin();');

		$this->assertStringContainsString('pfb_feed_pass_begin(\'cron\',TRUE,$manual)', $head,
			'cron/forcecheck child must wait for the shared update lock');
		$this->assertStringNotContainsString('pfb_due_ledger_set_pending', $head,
			'a child that never acquired the update lock must not write the ledger');
	}

	public function testManualCadenceWriteRunsInsideTheSuccessfulChild(): void
	{
		$source = $this->source('src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$body = $this->functionBody($source, 'function sync_package_pfblockerng', '');
		$mark = strpos($body, "pfb_due_ledger_mark_ran('cron'");
		$release = strrpos($body, 'pfb_feed_pass_release();');

		$this->assertNotFalse($mark, 'successful full manual child must advance cron cadence');
		$this->assertNotFalse($release, 'sync pass release missing');
		$this->assertLessThan($release, $mark,
			'manual cadence must be written before releasing the update lock');
	}

	public function testUpdatePageDispatchesManualChildWithoutWritingLedgerOrBarging(): void
	{
		$source = $this->source('src/usr/local/www/pfblockerng/pfblockerng_update.php');
		$run = $this->functionBody($source, 'function pfb_runnow(', 'function pfb_runnow_forcecheck(');
		$force = $this->functionBody($source, 'function pfb_runnow_forcecheck(', '$pgtitle =');

		foreach (['pfb_runnow' => $run, 'pfb_runnow_forcecheck' => $force] as $name => $body) {
			$this->assertStringNotContainsString('pfb_active_task_running()', $body,
				"{$name} must dispatch a waiting child instead of refusing an active pass");
			$this->assertStringNotContainsString('pfb_due_ledger_mark_ran', $body,
				"{$name} parent must not claim success before the child acquires/completes");
		}
		$this->assertStringContainsString('mode={$force_mode_esc}', $force,
			'forcecheck must pass its sidecar-clear mode into the lock-owning child');
	}
}
