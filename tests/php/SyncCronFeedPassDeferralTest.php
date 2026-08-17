<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1315 -- the cron/Force Check funnel must defer when its atomic
 * feed-pass acquisition loses after the tick's advisory busy probe.
 */
final class SyncCronFeedPassDeferralTest extends TestCase
{
	private string $dbdir = '';
	private array $originalPfb = [];
	private mixed $originalConfig = NULL;
	private $lockFp = NULL;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->dbdir = sys_get_temp_dir() . '/pfb_sync_cron_feedpass_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dbdir;
		$GLOBALS['pfb']['log'] = "{$this->dbdir}/pfblockerng.log";

		$this->lockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertNotFalse($this->lockFp, 'test setup: failed to open feed-pass lock');
		$this->assertTrue(flock($this->lockFp, LOCK_EX), 'test setup: failed to hold feed-pass lock');
	}

	protected function tearDown(): void
	{
		if (is_resource($this->lockFp)) {
			flock($this->lockFp, LOCK_UN);
			fclose($this->lockFp);
		}
		pfb_feed_pass_release();
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		unset($GLOBALS['g']['pfblockerng_install']);
		foreach (glob("{$this->dbdir}/state/*") ?: [] as $path) {
			unlink($path);
		}
		@rmdir("{$this->dbdir}/state");
		foreach (glob("{$this->dbdir}/*") ?: [] as $path) {
			unlink($path);
		}
		rmdir($this->dbdir);
	}

	public function testLockLossLeavesScheduleStateAndCacheUntouched(): void
	{
		$stateDir = "{$this->dbdir}/state";
		mkdir($stateDir, 0755, TRUE);
		$GLOBALS['pfb']['schedule_state_dir'] = $stateDir;
		$state = [
			'schema' => 1,
			'items' => ['ipv4:feed_v4' => ['pending_occurrence' => 123]],
		];
		$this->assertTrue(pfb_schedule_state_write($state, $stateDir));

		$nextDue = time() + 3600;
		pfb_due_ledger_write_entry('cron', [
			'last_run' => time() - 3600,
			'next_due' => $nextDue,
			'jitter'   => 0,
		], $this->dbdir);

		$beforeLedger = file_get_contents("{$this->dbdir}/pfb_due_ledger.json");
		$beforeState = file_get_contents("{$stateDir}/pfb_schedule_state.json");

		// issue #2491: this row's no-args call is the ORIGINAL deliberate intent (#1315:
		// the tick's advisory busy probe, i.e. the $force_all = FALSE path); the
		// "Force Check" wording was a later addition and is the half that was wrong.
		// The cron path now reports a deferral as success, so the expectation flips —
		// but the call stays on the cron path, because the state/cache assertions below
		// are this file's reason to exist and they must keep covering it.
		// Force Check's own return contract is pinned in CronDeferralExitCodeTest.
		$this->assertTrue(pfblockerng_sync_cron(),
			'a deferred scheduled pass reports success, and must still preserve state');

		$this->assertSame($beforeLedger, file_get_contents("{$this->dbdir}/pfb_due_ledger.json"),
			'lost feed-pass lock must not mutate the runtime cache');
		$this->assertSame($beforeState, file_get_contents("{$stateDir}/pfb_schedule_state.json"),
			'lost feed-pass lock must leave the durable occurrence reserved for the next tick');
	}

	public function testPendingTop1mChangeDoesNotApplyOutsideWindowOnNoUpdatePass(): void
	{
		flock($this->lockFp, LOCK_UN);
		fclose($this->lockFp);
		$this->lockFp = NULL;
		$GLOBALS['pfb']['schedule_state_dir'] = $this->dbdir;
		$GLOBALS['pfb']['continents'] = [];
		$GLOBALS['config'] = [];
		$start = ((int) date('G') + 12) % 24;
		config_set_path('installedpackages/pfblockerng/config/0', [
			'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '0',
			'pfb_schedule_minute' => '0',
			'pfb_quiet_hours' => sprintf('%02d:00-%02d:01', $start, $start),
		]);
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_selected' => '', 'blacklist_freq' => 'Never', 'item' => [],
		]);
		$this->assertTrue(pfb_schedule_state_write(['schema' => 1, 'items' => []], $this->dbdir));

		$this->assertTrue(pfblockerng_sync_cron(FALSE, 'both', TRUE));
		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dbdir),
			'A TOP1M change must stay pending when the no-update feed tail runs outside the apply window.');
	}
}
