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

	public function testTerminalOutcomeUpdatesOnlyReservedCompletion(): void
	{
		$pending = 1_700_000_000;
		$this->assertTrue(pfb_schedule_state_set_pending(['ipv4:feed_v4' => $pending], $this->dir));
		$this->assertTrue(pfb_schedule_state_record_outcome(
			'ipv4:feed_v4', PfbScheduleTerminalResult::Success, $this->dir, $pending + 20
		));
		$this->assertTrue(pfb_schedule_state_record_outcome(
			'dnsbl:unreserved', PfbScheduleTerminalResult::Success, $this->dir, $pending + 30
		));

		$state = pfb_schedule_state_read($this->dir);
		$this->assertSame($pending, $state['items']['ipv4:feed_v4']['last_completed_occurrence']);
		$this->assertSame('success', $state['items']['ipv4:feed_v4']['completion_outcome']);
		$this->assertSame($pending + 20, $state['items']['ipv4:feed_v4']['last_successful_check']);
		$this->assertSame(
			['last_successful_check' => $pending + 30],
			$state['items']['dnsbl:unreserved'],
			'an unreserved success is a check fact, not a fabricated occurrence completion'
		);
	}

	public function testRetryCapWithoutReservationCreatesNoStateItem(): void
	{
		$this->assertTrue(pfb_schedule_state_record_outcome(
			'ipv6:capped_v6', PfbScheduleTerminalResult::RetryCapReached, $this->dir, 1_700_000_000
		));
		$this->assertSame([], pfb_schedule_state_read($this->dir)['items']);
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
