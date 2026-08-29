<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #2089: SafeSearch lock failures must fail closed and remain retryable. */
final class TickSafeSearchFailureTest extends TestCase
{
	private string $dir;
	private mixed $originalPfb;
	private mixed $originalConfig;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_tick_ss_failure_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0755, TRUE);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$GLOBALS['pfb'] = [
			'dbdir'     => $this->dir,
			'log'       => "{$this->dir}/pfblockerng.log",
			'errlog'    => "{$this->dir}/error.log",
			'runlog'    => "{$this->dir}/run.log",
			'extraslog' => "{$this->dir}/extras.log",
		];
		$GLOBALS['config'] = [];

		$gen = 'installedpackages/pfblockerng/config/0';
		config_set_path("{$gen}/pfb_interval", 'Disabled');
		config_set_path("{$gen}/pfb_quiet_hours", '');
		$now = time();
		foreach (['cron', 'dcc', 'bl'] as $job) {
			pfb_due_ledger_write_entry($job, [
				'last_run' => $now - 3600,
				'next_due' => $now + 3600,
				'jitter'   => 0,
			], $this->dir);
		}
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	public function testLockOpenFailureLogsAndRetries(): void
	{
		$calls = 0;
		$refresh = static function () use (&$calls): void {
			$calls++;
		};
		$opener = static fn(string $path): mixed => FALSE;

		pfblockerng_tick(['pfblockerng.php dcc'], $refresh, $opener, 5.0);

		$this->assertSame(0, $calls, 'lock-open failure must not call SafeSearch');
		$this->assertNull(pfb_due_ledger_read_entry('ss_refresh', $this->dir),
			'lock-open failure must not advance ss_refresh ledger');
		$this->assertStringContainsString('SafeSearch lock open failed', $this->errorLog());

		pfblockerng_tick(['pfblockerng.php dcc'], $refresh);

		$this->assertSame(1, $calls, 'SafeSearch must retry after lock-open failure');
		$this->assertFutureReservation();
	}

	public function testLockTimeoutLogsAndRetriesAfterRelease(): void
	{
		if (!function_exists('pcntl_fork')) {
			$this->markTestSkipped('pcntl_fork() unavailable; timeout reproduction needs a real lock holder.');
		}

		$lockPath = "{$this->dir}/pfb_ss_refresh.lock";
		$marker = "{$this->dir}/holder.ready";
		$holderReleasePath = "{$this->dir}/holder.release";
		$pid = pcntl_fork();
		if ($pid === -1) {
			$this->fail('pcntl_fork() failed while creating the lock holder');
		}
		if ($pid === 0) {
			$holder = fopen($lockPath, 'c');
			if ($holder === FALSE || !flock($holder, LOCK_EX)) {
				exit(2);
			}
			touch($marker);
			$deadline = microtime(TRUE) + 3.0;
			while (!is_file($holderReleasePath) && microtime(TRUE) < $deadline) {
				usleep(1000);
			}
			flock($holder, LOCK_UN);
			fclose($holder);
			exit(is_file($holderReleasePath) ? 0 : 3);
		}

		$calls = 0;
		$refresh = static function () use (&$calls): void {
			$calls++;
		};
		$opener = static fn(string $path): mixed => fopen($path, 'c');
		$waitResult = NULL;
		$status = NULL;
		try {
			$this->waitForPath($marker, 2.0);
			pfblockerng_tick(['pfblockerng.php dcc'], $refresh, $opener, 0.01);

			$this->assertSame(0, $calls, 'lock timeout must not call SafeSearch');
			$this->assertNull(pfb_due_ledger_read_entry('ss_refresh', $this->dir),
				'lock timeout must not advance ss_refresh ledger');
			$this->assertStringContainsString('SafeSearch lock timed out', $this->errorLog());
		} finally {
			// Always release and reap the holder, including when any post-fork
			// assertion or tick call throws.
			touch($holderReleasePath);
			$waitResult = pcntl_waitpid($pid, $status);
		}

		$this->assertSame($pid, $waitResult, 'lock holder must be reaped after timeout attempt');
		$this->assertTrue(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0,
			'lock holder must exit cleanly before retry');
		pfblockerng_tick(['pfblockerng.php dcc'], $refresh);

		$this->assertSame(1, $calls, 'SafeSearch must retry after the lock is released');
		$this->assertFutureReservation();
	}

	public function testNonTimeoutAcquireFailureLeavesMemoryHandleReusable(): void
	{
		$handle = NULL;
		$calls = 0;
		$refresh = static function () use (&$calls): void {
			$calls++;
		};
		$opener = static function () use (&$handle): mixed {
			$handle = fopen('php://memory', 'r+');
			return $handle;
		};

		pfblockerng_tick(['pfblockerng.php dcc'], $refresh, $opener, 5.0);

		$this->assertSame(0, $calls, 'non-timeout acquire failure must not call SafeSearch');
		$this->assertNull(pfb_due_ledger_read_entry('ss_refresh', $this->dir),
			'non-timeout acquire failure must not advance ss_refresh ledger');
		$this->assertStringContainsString('SafeSearch lock acquire failed', $this->errorLog());
		$this->assertIsResource($handle, 'lock opener handle must remain owned by the caller');
		$this->assertSame(1, fwrite($handle, 'x'), 'failed acquire must not close the opener handle');
		fclose($handle);

		pfblockerng_tick(['pfblockerng.php dcc'], $refresh);

		$this->assertSame(1, $calls, 'SafeSearch must retry after non-timeout acquire failure');
		$this->assertFutureReservation();
	}

	public function testRefreshThrowLeavesDueAndNextTickRunsOnce(): void
	{
		$thrown = FALSE;
		$refresh = static function () use (&$thrown): void {
			if (!$thrown) {
				$thrown = TRUE;
				throw new RuntimeException('refresh failed');
			}
		};

		try {
			pfblockerng_tick(['pfblockerng.php dcc'], $refresh);
		} catch (RuntimeException $e) {
			$this->assertSame('refresh failed', $e->getMessage());
		}

		$this->assertTrue($thrown, 'first SafeSearch refresh must throw in this scenario');
		$this->assertNull(pfb_due_ledger_read_entry('ss_refresh', $this->dir),
			'a failed SafeSearch refresh must remain due for retry');
		$successes = 0;
		$retry = static function () use (&$successes): void {
			$successes++;
		};
		pfblockerng_tick(['pfblockerng.php dcc'], $retry);

		$this->assertSame(1, $successes, 'next tick must run exactly one retry after a thrown refresh');
		$this->assertFutureReservation();
	}

	private function errorLog(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['errlog']);
	}

	private function assertFutureReservation(): void
	{
		$entry = pfb_due_ledger_read_entry('ss_refresh', $this->dir);
		$this->assertNotNull($entry, 'successful SafeSearch refresh must write its ledger entry');
		$this->assertGreaterThan(time(), $entry['next_due'], 'successful SafeSearch refresh must schedule a future slot');
	}

	private function waitForPath(string $path, float $timeout): void
	{
		$deadline = microtime(TRUE) + $timeout;
		while (!is_file($path) && microtime(TRUE) < $deadline) {
			usleep(1000);
		}
		$this->assertFileExists($path, "timed out waiting for {$path}");
	}
}
