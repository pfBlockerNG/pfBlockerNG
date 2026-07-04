<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_update_pass_running — the tick's "is an update pass dispatching/running right now"
 * guard (issue #573 review finding, PR #790). Deliberately narrower than the sibling
 * pfb_feed_task_running(): it EXCLUDES 'tick' (the only caller IS the tick, which would
 * always see itself in `ps` and permanently close its own gate) and INCLUDES 'dcc'/'bl'
 * (both append to $pfb['extraslog'] for potentially minutes, so a dispatched/running dcc
 * or bl pass must also hold pfblockerng_tick()'s log-maintenance gate closed).
 *
 * $ps_lines is injected (bypassing exec()) so every branch is asserted deterministically,
 * off-appliance, with no live `ps` dependency.
 *
 * Branch coverage: every verb pfb_update_pass_running() must recognise as an update pass
 * (cron/update/updateip/updatednsbl/pfb_trigger/forcecheck/dcc/bl) gets its own TRUE case;
 * 'tick' (deliberately excluded) and an unrelated/empty ps snapshot get FALSE cases.
 */
#[CoversFunction('pfb_update_pass_running')]
final class PfbUpdatePassRunningTest extends TestCase
{
	private function psLine(string $verb): array
	{
		return ["  1234  -  Ss    0:00.12 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php {$verb}"];
	}

	public function testCronLineIsRunning(): void
	{
		$this->assertTrue(pfb_update_pass_running($this->psLine('cron')));
	}

	public function testUpdateLineIsRunning(): void
	{
		$this->assertTrue(pfb_update_pass_running($this->psLine('update')));
	}

	public function testUpdateipLineIsRunning(): void
	{
		$this->assertTrue(pfb_update_pass_running($this->psLine('updateip')));
	}

	public function testUpdatednsblLineIsRunning(): void
	{
		$this->assertTrue(pfb_update_pass_running($this->psLine('updatednsbl')));
	}

	public function testPfbTriggerLineIsRunning(): void
	{
		$this->assertTrue(pfb_update_pass_running($this->psLine('pfb_trigger')));
	}

	public function testForcecheckLineIsRunning(): void
	{
		$this->assertTrue(pfb_update_pass_running($this->psLine('forcecheck')));
	}

	/** dcc appends to $pfb['extraslog'] -- must hold the log-maintenance gate closed. */
	public function testDccLineIsRunning(): void
	{
		$this->assertTrue(pfb_update_pass_running($this->psLine('dcc')));
	}

	/** bl appends to $pfb['extraslog'] -- must hold the log-maintenance gate closed. */
	public function testBlLineIsRunning(): void
	{
		$this->assertTrue(pfb_update_pass_running($this->psLine('bl')));
	}

	/**
	 * 'tick' is deliberately EXCLUDED: the only caller is pfblockerng_tick() itself, so
	 * a ps snapshot always contains the running tick's own line -- including 'tick' here
	 * would make the log-maintenance gate permanently closed.
	 */
	public function testTickOnlyLineIsNotRunning(): void
	{
		$this->assertFalse(pfb_update_pass_running($this->psLine('tick')));
	}

	public function testUnrelatedProcessLineIsNotRunning(): void
	{
		$this->assertFalse(pfb_update_pass_running(['  999  -  Ss    0:00.01 /usr/sbin/cron -s']));
	}

	public function testEmptyPsSnapshotIsNotRunning(): void
	{
		$this->assertFalse(pfb_update_pass_running([]));
	}
}
