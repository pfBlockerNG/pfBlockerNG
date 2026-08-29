<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #2100: apply_reconcile failures stay due and overlapping ticks run once. */
final class TickApplyReconcileFailureTest extends TestCase
{
	private string $dir;
	private array $originalPfb;
	private array $originalConfig;
	private bool $hadG = FALSE;
	private array $originalG = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_tick_apply_failure_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0755, TRUE);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$this->hadG = array_key_exists('g', $GLOBALS);
		$this->originalG = $GLOBALS['g'] ?? [];
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir' => $this->dir,
			'log' => "{$this->dir}/pfblockerng.log",
			'errlog' => "{$this->dir}/error.log",
			'runlog' => "{$this->dir}/run.log",
			'extraslog' => "{$this->dir}/extras.log",
		]);
		$GLOBALS['config'] = [];
		$gen = 'installedpackages/pfblockerng/config/0';
		config_set_path("{$gen}/pfb_interval", 'Disabled');
		config_set_path("{$gen}/pfb_quiet_hours", '');
		foreach (['pfb_min', 'pfb_hour', 'pfb_dailystart', 'skipfeed'] as $key) {
			config_set_path("{$gen}/{$key}", '0');
		}
		$ip = 'installedpackages/pfblockerngipsettings/config/0';
		foreach (['suppression', 'database_cc', 'asn_token', 'maxmind_account', 'maxmind_key'] as $key) {
			config_set_path("{$ip}/{$key}", '');
		}
		config_set_path("{$ip}/maxmind_locale", 'en');
		config_set_path("{$ip}/asn_reporting", 'disabled');
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		foreach (['pfb_dnsvip4', 'pfb_dnsvip6', 'top1m_enable', 'pfb_cache', 'pfb_py_reply', 'pfb_regex',
			'pfb_regex_list', 'pfb_cname', 'tld_allow', 'pfb_py_nolog', 'pfb_noaaaa', 'pfb_noaaaa_list',
			'pfb_gp', 'pfb_gp_bypass_list'] as $key) {
			config_set_path("{$dnsbl}/{$key}", '');
		}
		config_set_path("{$dnsbl}/pfb_dnsport", '8081');
		config_set_path("{$dnsbl}/pfb_dnsport_ssl", '8443');
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
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
		if ($this->hadG) {
			$GLOBALS['g'] = $this->originalG;
		} else {
			unset($GLOBALS['g']);
		}
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private function seedApply(int $nextDue): void
	{
		pfb_due_ledger_write_entry('apply_reconcile', [
			'last_run' => $nextDue - 900,
			'next_due' => $nextDue,
			'jitter' => 0,
		], $this->dir);
	}

	private function tick(?callable $worker = NULL, ?callable $opener = NULL, float $timeout = 5.0): void
	{
		pfblockerng_tick(NULL, NULL, NULL, 5.0, $worker, $opener, $timeout);
	}

	public function testDueAttemptMarksAnchoredFutureSlotAndRunsOnce(): void
	{
		$priorDue = time() - 100;
		$this->seedApply($priorDue);
		$calls = 0;
		$this->tick(static function () use (&$calls): void {
			$calls++;
		});

		$this->assertSame(1, $calls);
		$entry = pfb_due_ledger_read_entry('apply_reconcile', $this->dir);
		$this->assertSame($priorDue + 900, $entry['next_due'], 'apply_reconcile must use anchored 900-second cadence');
		$this->tick(static function () use (&$calls): void {
			$calls++;
		});
		$this->assertSame(1, $calls, 'future reservation must suppress the next tick');
	}

	public function testCompletedProductionScanWithNoOpenEntriesAdvancesLedger(): void
	{
		$this->assertSame([], pfb_sync_status_list_open($this->dir), 'production scan precondition must have no open status rows');
		$this->seedApply(time() - 2700);
		$this->tick();
		$entry = pfb_due_ledger_read_entry('apply_reconcile', $this->dir);
		$this->assertNotNull($entry, 'completed production scan must reserve apply_reconcile');
		$this->assertSame(0, $entry['jitter'], 'apply_reconcile must have zero jitter');
		$this->assertSame(900, $entry['next_due'] - $entry['last_run'], 'apply_reconcile cadence must be exactly 900 seconds');
		$this->assertGreaterThan(time(), $entry['next_due'], 'completed production scan must reserve a future slot');
	}

	public function testMultiIntervalOverdueRunsOnceAndCatchesUpFromNow(): void
	{
		$this->seedApply(time() - 2700);
		$calls = 0;
		$this->tick(static function () use (&$calls): void {
			$calls++;
		});
		$entry = pfb_due_ledger_read_entry('apply_reconcile', $this->dir);
		$this->assertSame(1, $calls, 'multiple missed intervals must not burst');
		$this->assertGreaterThan(time(), $entry['next_due'], 'catch-up reservation must be future-dated');
		$this->assertSame(900, $entry['next_due'] - $entry['last_run'], 'apply cadence remains exactly 900 seconds');
	}

	public function testLockOpenFalseAndNonResourceLeaveDueAndRetryable(): void
	{
		$priorDue = time() - 1;
		$this->seedApply($priorDue);
		$calls = 0;
		$this->tick(static function () use (&$calls): void {
			$calls++;
		}, static fn(string $path): mixed => FALSE);
		$this->assertSame(0, $calls);
		$this->assertSame($priorDue, pfb_due_ledger_read_entry('apply_reconcile', $this->dir)['next_due']);

		$this->tick(static function () use (&$calls): void {
			$calls++;
		}, static fn(string $path): mixed => 'not-a-resource');
		$this->assertSame(0, $calls);
		$this->assertSame($priorDue, pfb_due_ledger_read_entry('apply_reconcile', $this->dir)['next_due']);

		$this->tick(static function () use (&$calls): void {
			$calls++;
		});
		$this->assertSame(1, $calls, 'a cleared opener failure must retry on the next tick');
	}

	public function testAcquireFailureDoesNotCloseInjectedHandleOrAdvance(): void
	{
		$priorDue = time() - 1;
		$this->seedApply($priorDue);
		$handle = NULL;
		$opener = static function () use (&$handle): mixed {
			$handle = fopen('php://memory', 'r+');
			return $handle;
		};
		$calls = 0;
		$this->tick(static function () use (&$calls): void {
			$calls++;
		}, $opener, 0.0);
		$this->assertSame(0, $calls);
		$this->assertSame($priorDue, pfb_due_ledger_read_entry('apply_reconcile', $this->dir)['next_due']);
		$this->assertIsResource($handle);
		$this->assertSame(1, fwrite($handle, 'x'), 'caller-owned handle must remain open');
		fclose($handle);
	}

	public function testLockContentionTimeoutLeavesDueAndRetriesAfterRelease(): void
	{
		if (!function_exists('pcntl_fork')) {
			$this->markTestSkipped('pcntl_fork() unavailable; timeout proof needs a lock holder process.');
		}
		$priorDue = time() - 1;
		$this->seedApply($priorDue);
		$lockPath = "{$this->dir}/pfb_apply_reconcile.lock";
		$marker = "{$this->dir}/holder-ready";
		$release = "{$this->dir}/holder-release";
		$pid = pcntl_fork();
		if ($pid === -1) {
			$this->fail('pcntl_fork() failed while creating apply lock holder');
		}
		if ($pid === 0) {
			$holder = fopen($lockPath, 'c');
			if ($holder === FALSE || !flock($holder, LOCK_EX)) {
				exit(2);
			}
			touch($marker);
			$deadline = microtime(TRUE) + 3.0;
			while (!is_file($release) && microtime(TRUE) < $deadline) {
				usleep(1000);
			}
			flock($holder, LOCK_UN);
			fclose($holder);
			exit(is_file($release) ? 0 : 3);
		}

		$handle = NULL;
		$opener = static function (string $path) use (&$handle): mixed {
			$handle = fopen($path, 'c');
			return $handle;
		};
		$calls = 0;
		$status = NULL;
		try {
			$this->waitForPath($marker, 3.0);
			$this->tick(static function () use (&$calls): void {
				$calls++;
			}, $opener, 0.01);
			$this->assertSame(0, $calls, 'contention timeout must not run reconciliation');
			$this->assertSame($priorDue, pfb_due_ledger_read_entry('apply_reconcile', $this->dir)['next_due']);
			$this->assertStringContainsString('apply reconciliation lock timed out',
				(string) @file_get_contents($GLOBALS['pfb']['errlog']));
		} finally {
			if (is_resource($handle)) {
				fclose($handle);
			}
			touch($release);
			pcntl_waitpid($pid, $status);
		}
		$this->assertTrue(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0,
			'lock holder must exit cleanly before retry');

		$this->tick(static function () use (&$calls): void {
			$calls++;
		});
		$this->assertSame(1, $calls, 'released lock must allow one retry');
		$this->assertGreaterThan(time(), pfb_due_ledger_read_entry('apply_reconcile', $this->dir)['next_due']);
	}

	public function testThrownWorkerStaysDueAndNextTickRetries(): void
	{
		$priorDue = time() - 1;
		$this->seedApply($priorDue);
		$calls = 0;
		$this->tick(static function () use (&$calls): void {
			$calls++;
			throw new RuntimeException('reconcile failed');
		});
		$this->assertSame(1, $calls);
		$this->assertSame($priorDue, pfb_due_ledger_read_entry('apply_reconcile', $this->dir)['next_due']);
		$this->tick(static function () use (&$calls): void {
			$calls++;
		});
		$this->assertSame(2, $calls);
	}

	public function testOverlappingTicksRunOneApplyReconciliation(): void
	{
		if (!function_exists('pcntl_fork')) {
			$this->markTestSkipped('pcntl_fork() unavailable; overlap proof needs separate processes.');
		}
		$this->seedApply(time() - 1);
		$ready = "{$this->dir}/ready";
		$go = "{$this->dir}/go";
		$openerStarted = "{$this->dir}/opener-started";
		$openersRelease = "{$this->dir}/openers-release";
		$calls = "{$this->dir}/calls";
		$pids = [];
		$workerFailures = [];
		try {
			for ($i = 0; $i < 2; $i++) {
				$pid = pcntl_fork();
				if ($pid === -1) {
					$this->fail('pcntl_fork() failed');
				}
				if ($pid === 0) {
					try {
						file_put_contents($ready, "1\n", FILE_APPEND | LOCK_EX);
						$this->waitForPath($go, 3.0);
						$opener = static function (string $path) use ($openerStarted, $openersRelease): mixed {
							file_put_contents($openerStarted, "1\n", FILE_APPEND | LOCK_EX);
							$deadline = microtime(TRUE) + 3.0;
							while (!is_file($openersRelease) && microtime(TRUE) < $deadline) {
								usleep(1000);
							}
							if (!is_file($openersRelease)) {
								throw new RuntimeException('timed out waiting for opener release');
							}
							return fopen($path, 'c');
						};
						$this->tick(static function () use ($calls): void {
							file_put_contents($calls, "1\n", FILE_APPEND | LOCK_EX);
						}, $opener);
						exit(0);
					} catch (Throwable $e) {
						file_put_contents("{$this->dir}/worker-error", $e::class . ': ' . $e->getMessage());
						exit(1);
					}
				}
				$pids[] = $pid;
			}
			$this->assertTrue($this->waitForLineCount($ready, 2, 3.0),
				'overlap workers did not reach ready barrier; lines=' . $this->lineCount($ready));
			touch($go);
			$this->assertTrue($this->waitForLineCount($openerStarted, 2, 3.0),
				'both workers must pass the outer due check and reach opener; lines=' . $this->lineCount($openerStarted));
			touch($openersRelease);
		} finally {
			touch($go);
			touch($openersRelease);
			foreach ($pids as $pid) {
				pcntl_waitpid($pid, $status);
				if (!pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 0) {
					$workerFailures[] = "overlap worker {$pid} failed: " . (string) @file_get_contents("{$this->dir}/worker-error");
				}
			}
		}
		$this->assertSame([], $workerFailures, implode("\n", $workerFailures));
		$lines = is_file($calls) ? array_values(array_filter(explode("\n", (string) file_get_contents($calls)), 'strlen')) : [];
		$this->assertCount(1, $lines, 'in-lock due recheck must allow one overlapping reconciliation');
	}

	private function waitForPath(string $path, float $timeout): void
	{
		$deadline = microtime(TRUE) + $timeout;
		while (!is_file($path) && microtime(TRUE) < $deadline) {
			usleep(1000);
		}
		if (!is_file($path)) {
			throw new RuntimeException("timed out waiting for {$path}");
		}
	}

	private function waitForLineCount(string $path, int $expected, float $timeout): bool
	{
		$deadline = microtime(TRUE) + $timeout;
		while (microtime(TRUE) < $deadline) {
			if ($this->lineCount($path) >= $expected) {
				return TRUE;
			}
			usleep(1000);
		}
		return $this->lineCount($path) >= $expected;
	}

	private function lineCount(string $path): int
	{
		$lines = is_file($path)
			? array_values(array_filter(explode("\n", (string) file_get_contents($path)), 'strlen'))
			: [];
		return count($lines);
	}
}
