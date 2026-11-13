<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Durable scheduled-feed facts and selection remain per source row. */
final class ScheduledFeedStateTest extends TestCase
{
	private array $originalPfb = [];
	private string $dir = '';

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_schedule_feed_state_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0755, TRUE);
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		foreach (glob($this->dir . '/*') ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	public function testTerminalOutcomesAreReportedToTheRunningUpdateAndTheFirstOneStands(): void
	{
		unset($GLOBALS['pfb']['scheduled_outcomes']);

		pfb_schedule_outcome_record('ipv4:feed_v4', PfbScheduleTerminalResult::RetryCapReached);
		pfb_schedule_outcome_record('ipv4:feed_v4', PfbScheduleTerminalResult::Success);
		pfb_schedule_outcome_record('dnsbl:other', PfbScheduleTerminalResult::Success);

		$this->assertSame(
			['ipv4:feed_v4' => 'retry-cap-reached', 'dnsbl:other' => 'success'],
			$GLOBALS['pfb']['scheduled_outcomes'],
			'the check that closed the occurrence stands, as the first terminal outcome did in the state file'
		);
		$this->assertSame([], glob($this->dir . '/*') ?: [], 'nothing is written: Core records the outcomes from the Update result');
	}

	public function testFeedIdentityAndScheduledSelectionCoverEveryFamily(): void
	{
		$this->assertSame('ipv4:a_v4', pfb_schedule_feed_id('ipv4', 'a_v4'));
		$this->assertSame('ipv6:b_v6', pfb_schedule_feed_id('ipv6', 'b_v6'));
		$this->assertSame('dnsbl:c', pfb_schedule_feed_id('dnsbl', 'c'));
		$this->assertNull(pfb_schedule_feed_id('ipv4', 'a'));

		$GLOBALS['pfb']['scheduled_runtime_cron'] = TRUE;
		$GLOBALS['pfb']['scheduled_selected_ids'] = ['ipv4:a_v4' => TRUE];
		$this->assertTrue(pfb_schedule_feed_selected('ipv4', 'a_v4'));
		$this->assertFalse(pfb_schedule_feed_selected('ipv6', 'b_v6'));
		$GLOBALS['pfb']['scheduled_runtime_cron'] = FALSE;
		$this->assertTrue(pfb_schedule_feed_selected('ipv6', 'b_v6'));
	}
}
