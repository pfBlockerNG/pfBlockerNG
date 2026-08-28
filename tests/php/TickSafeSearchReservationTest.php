<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #2089: overlapping ticks must serialize SafeSearch refresh work. */
final class TickSafeSearchReservationTest extends TestCase
{
	private string $dir;
	private mixed $originalPfb;
	private mixed $originalConfig;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_tick_ss_reservation_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0755, TRUE);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$GLOBALS['pfb'] = ['dbdir' => $this->dir];
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

	/**
	 * Two real tick processes overlap their refresh callbacks. Before the lock/recheck,
	 * both callbacks run; after it, only the winner runs and the loser observes not-due.
	 */
	public function testOverlappingTicksRunOneSafeSearchRefresh(): void
	{
		if (!function_exists('pcntl_fork')) {
			$this->markTestSkipped('pcntl_fork() unavailable; overlapping tick reproduction requires real processes.');
		}

		$readyPath   = "{$this->dir}/ready.log";
		$startedPath = "{$this->dir}/started.log";
		$callsPath   = "{$this->dir}/calls.log";
		$goPath      = "{$this->dir}/go";
		$openersReleasePath = "{$this->dir}/openers-release";
		$releasePath = "{$this->dir}/release";
		$pids = [];

		for ($i = 0; $i < 2; $i++) {
			$pid = pcntl_fork();
			if ($pid === -1) {
				$this->fail('pcntl_fork() failed while creating overlapping tick workers');
			}
			if ($pid === 0) {
				try {
					file_put_contents($readyPath, getmypid() . "\n", FILE_APPEND | LOCK_EX);
					$this->waitForPath($goPath, 3.0);
					$opener = static function (string $lockPath) use ($startedPath, $openersReleasePath): mixed {
						file_put_contents($startedPath, getmypid() . "\n", FILE_APPEND | LOCK_EX);
						$deadline = microtime(TRUE) + 3.0;
						while (!is_file($openersReleasePath) && microtime(TRUE) < $deadline) {
							usleep(1000);
						}
						if (!is_file($openersReleasePath)) {
							throw new RuntimeException('timed out waiting for opener release');
						}
						$handle = fopen($lockPath, 'c');
						return $handle;
					};
					$refresh = static function () use ($callsPath, $releasePath): void {
						file_put_contents($callsPath, getmypid() . "\n", FILE_APPEND | LOCK_EX);
						$deadline = microtime(TRUE) + 3.0;
						while (!is_file($releasePath) && microtime(TRUE) < $deadline) {
							usleep(1000);
						}
					};
					pfblockerng_tick(['pfblockerng.php dcc'], $refresh, $opener);
					exit(0);
				} catch (Throwable $e) {
					file_put_contents("{$this->dir}/worker-error.log", $e::class . ': ' . $e->getMessage());
					exit(1);
				}
			}
			$pids[] = $pid;
		}

		$statuses = [];
		try {
			$this->assertTrue($this->waitForLineCount($readyPath, 2, 3.0),
				'overlap workers did not both reach ready barrier; lines=' . $this->lineCount($readyPath));
			touch($goPath);
			$this->assertTrue($this->waitForLineCount($startedPath, 2, 3.0),
				'overlap workers did not both reach started barrier; lines=' . $this->lineCount($startedPath));
			touch($openersReleasePath);
			// Both workers reached the overlap barrier. One callback is the expected
			// winner; the second worker either waits on the lock or races the old code.
			$this->assertTrue($this->waitForLineCount($callsPath, 1, 3.0),
				'no SafeSearch callback reached overlap; lines=' . $this->lineCount($callsPath));
		} finally {
			// Release every worker even when a milestone assertion fails, then reap
			// the children so a timed-out assertion cannot orphan processes.
			touch($goPath);
			touch($openersReleasePath);
			touch($releasePath);
			foreach ($pids as $pid) {
				pcntl_waitpid($pid, $status);
				$statuses[$pid] = $status;
			}
		}

		foreach ($statuses as $pid => $status) {
			$this->assertTrue(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0,
				"tick worker {$pid} failed: " . (string) @file_get_contents("{$this->dir}/worker-error.log"));
		}

		$calls = is_file($callsPath)
			? array_values(array_filter(explode("\n", (string) file_get_contents($callsPath)), 'strlen'))
			: [];
		$this->assertCount(1, $calls,
			'overlapping ticks must invoke SafeSearch once after the in-lock due recheck; calls=' . var_export($calls, TRUE));
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
			$lines = is_file($path)
				? array_values(array_filter(explode("\n", (string) file_get_contents($path)), 'strlen'))
				: [];
			if (count($lines) >= $expected) {
				return TRUE;
			}
			usleep(1000);
		}
		return FALSE;
	}

	private function lineCount(string $path): int
	{
		$lines = is_file($path)
			? array_values(array_filter(explode("\n", (string) file_get_contents($path)), 'strlen'))
			: [];
		return count($lines);
	}
}
