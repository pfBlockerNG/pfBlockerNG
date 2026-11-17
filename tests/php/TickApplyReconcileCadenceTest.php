<?php

declare(strict_types=1);

require_once __DIR__ . '/SyncPrereqSeedTrait.php';

use PHPUnit\Framework\TestCase;

/** Issues #2100, #3996: every tick retries open apply failures; Core, not an Outpost ledger, decides how often the tick runs. */
final class TickApplyReconcileCadenceTest extends TestCase
{
	use SyncPrereqSeedTrait;

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
			'pending_marker' => "{$this->dir}/pfb_pending_changes",
			'schedule_state_dir' => $this->dir,
			'aliasdir' => $this->dir,
			'log' => "{$this->dir}/pfblockerng.log",
			'errlog' => "{$this->dir}/error.log",
			'runlog' => "{$this->dir}/run.log",
			'extraslog' => "{$this->dir}/extras.log",
			// What the apply's pfb_global(), pfb_log_mgmt() and certificate refresh read: kept inside the scratch directory
			'folder_array' => [],
			'dns_proxy_cert' => "{$this->dir}/tls.pem",
			'dns_proxy_cert_legacy' => "{$this->dir}/legacy_cert.pem",
		] + array_fill_keys(['ip_blocklog', 'ip_permitlog', 'ip_matchlog', 'ip_parse_err', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog'], "{$this->dir}/absent.log");
		$GLOBALS['config'] = [];
		$this->seedSyncPrereqs();
		$gen = 'installedpackages/pfblockerng/config/0';
		config_set_path("{$gen}/pfb_interval", 'Disabled');
		config_set_path("{$gen}/pfb_quiet_hours", '');
		$now = time();
		foreach (['cron', 'dcc', 'bl'] as $job) {
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

	public function testTwoTicksLessThan900SecondsApartBothRetryAndKeepNoLedgerEntry(): void
	{
		$counter = tempnam(sys_get_temp_dir(), 'pfb_tick_apply_counter_');
		$this->tmpfiles[] = $counter;
		@unlink($counter);
		$mock = tempnam(sys_get_temp_dir(), 'pfb_tick_apply_mock_');
		$this->tmpfiles[] = $mock;
		$counterArg = escapeshellarg($counter);
		file_put_contents($mock, "#!/bin/sh
echo x >> {$counterArg}
exit 1
");
		chmod($mock, 0755);
		$GLOBALS['pfb']['pfctl'] = $mock;
		file_put_contents("{$this->dir}/pfB_Test_v4.txt", "10.0.0.1
");
		pfb_sync_status_open('ip', 'pfB_Test_v4', 'apply', 'seeded failure', $this->dir);
		$next = time() + 3600;
		pfb_due_ledger_write_entry('apply_reconcile', ['last_run' => $next - 900, 'next_due' => $next, 'jitter' => 0], $this->dir);
		$tick = static fn () => pfblockerng_tick(core_settings: static fn(): ?string => NULL, core_call: static fn(): array => ['status' => 0, 'body' => NULL, 'error' => 'no Core in this test']);

		$tick();
		$tick();

		$this->assertSame(2, count(file($counter, FILE_IGNORE_NEW_LINES)), 'each tick retries the open apply failure, a leftover future entry notwithstanding');
		$this->assertSame($next, pfb_due_ledger_read_entry('apply_reconcile', $this->dir)['next_due'], 'the leftover entry is not rewritten');
	}
}
