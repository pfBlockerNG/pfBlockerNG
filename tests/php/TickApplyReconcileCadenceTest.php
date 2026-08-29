<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Regression reproduction for issue #2100: apply retries must obey their own ledger. */
final class TickApplyReconcileCadenceTest extends TestCase
{
	private string $dir;
	private array $originalPfb;
	private array $originalConfig;
	private array $tmpfiles = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_tick_apply_cadence_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0755, TRUE);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$GLOBALS['pfb'] = [
			'dbdir' => $this->dir,
			'aliasdir' => $this->dir,
			'log' => "{$this->dir}/pfblockerng.log",
			'errlog' => "{$this->dir}/error.log",
			'runlog' => "{$this->dir}/run.log",
			'extraslog' => "{$this->dir}/extras.log",
		];
		$GLOBALS['config'] = [];
		$gen = 'installedpackages/pfblockerng/config/0';
		config_set_path("{$gen}/pfb_interval", 'Disabled');
		config_set_path("{$gen}/pfb_quiet_hours", '');
		$now = time();
		foreach (['cron', 'dcc', 'bl', 'ss_refresh'] as $job) {
			pfb_due_ledger_write_entry($job, [
				'last_run' => $now - 3600,
				'next_due' => $now + 3600,
				'jitter' => 0,
			], $this->dir);
		}
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		foreach ($this->tmpfiles as $file) {
			@unlink($file);
		}
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	public function testFutureApplyReconcileEntrySuppressesRetry(): void
	{
		$counter = tempnam(sys_get_temp_dir(), 'pfb_tick_apply_counter_');
		$this->tmpfiles[] = $counter;
		@unlink($counter);
		$mock = tempnam(sys_get_temp_dir(), 'pfb_tick_apply_mock_');
		$this->tmpfiles[] = $mock;
		$counterArg = escapeshellarg($counter);
		file_put_contents($mock, "#!/bin/sh\necho x >> {$counterArg}\nexit 1\n");
		chmod($mock, 0755);
		$GLOBALS['pfb']['pfctl'] = $mock;
		file_put_contents("{$this->dir}/pfB_Test_v4.txt", "10.0.0.1\n");
		pfb_sync_status_open('ip', 'pfB_Test_v4', 'apply', 'seeded failure', $this->dir);
		$now = time();
		pfb_due_ledger_write_entry('apply_reconcile', [
			'last_run' => $now - 900,
			'next_due' => $now + 3600,
			'jitter' => 0,
		], $this->dir);

		pfblockerng_tick();

		$this->assertFileDoesNotExist($counter, 'future apply_reconcile entry must suppress the retry');
		$entry = pfb_due_ledger_read_entry('apply_reconcile', $this->dir);
		$this->assertSame($now + 3600, $entry['next_due']);
	}
}
