<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #2122: concurrent due-ledger writers must preserve both reservations. */
final class DueLedgerConcurrentWriterTest extends TestCase
{
	private const ITERATIONS = 20;
	private string $dir = '';
	private array $originalPfb = [];

	protected function setUp(): void
	{
		if (!function_exists('pcntl_fork')) {
			$this->markTestSkipped('pcntl_fork() required for concurrent-writer proof.');
		}
		$this->originalPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_due_writer_' . getmypid() . '_' . uniqid('', TRUE);
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
	}

	protected function tearDown(): void
	{
		pfb_feed_pass_release();
		$GLOBALS['pfb'] = $this->originalPfb;
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	/** @return array{0:mixed,1:mixed} */
	private function signalPair(): array
	{
		$pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
		$this->assertNotFalse($pair, 'test setup: stream_socket_pair failed');
		stream_set_timeout($pair[0], 5);
		stream_set_timeout($pair[1], 5);
		return $pair;
	}

	/** @return array{0:int,1:mixed} */
	private function forkWriter(string $job, int $iteration): array
	{
		[$parent, $child] = $this->signalPair();
		$pid = pcntl_fork();
		$this->assertNotSame(-1, $pid, 'test setup: pcntl_fork failed');
		if ($pid === 0) {
			fclose($parent);
			$warnings = [];
			set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
				$warnings[] = "{$severity}:{$message}";
				return TRUE;
			});
			fwrite($child, "READY\n");
			$go = fgets($child);
			if ($go !== "GO\n") {
				exit(2);
			}
			pfb_due_ledger_write_entry($job, [
				'last_run' => $iteration,
				'next_due' => $iteration + 60,
				'jitter'   => 0,
			], $this->dir);
			restore_error_handler();
			file_put_contents(
				"{$this->dir}/writer-{$job}-{$iteration}.json",
				json_encode(['warnings' => $warnings], JSON_THROW_ON_ERROR)
			);
			fclose($child);
			exit(0);
		}
		fclose($child);
		return [$pid, $parent];
	}

	private function readEvent(mixed $stream, string $expected): void
	{
		$actual = fgets($stream);
		if ($actual === FALSE) {
			$meta = stream_get_meta_data($stream);
			$this->fail('salvage cap expired / stuck or environment awaiting ' . trim($expected)
				. '; stream=' . json_encode($meta));
		}
		$this->assertSame($expected, $actual, 'concurrent-writer barrier event mismatch');
	}

	public function testConcurrentDifferentKeysRemainValidAndWarningFree(): void
	{
		for ($iteration = 1; $iteration <= self::ITERATIONS; $iteration++) {
			@unlink("{$this->dir}/pfb_due_ledger.json");
			[$cronPid, $cron] = $this->forkWriter('cron', $iteration);
			[$applyPid, $apply] = $this->forkWriter('apply_reconcile', $iteration);

			$this->readEvent($cron, "READY\n");
			$this->readEvent($apply, "READY\n");
			fwrite($cron, "GO\n");
			fwrite($apply, "GO\n");
			fclose($cron);
			fclose($apply);

			$this->assertSame($cronPid, pcntl_waitpid($cronPid, $cronStatus));
			$this->assertSame($applyPid, pcntl_waitpid($applyPid, $applyStatus));
			$this->assertTrue(pcntl_wifexited($cronStatus) && pcntl_wexitstatus($cronStatus) === 0,
				"cron writer failed in iteration {$iteration}");
			$this->assertTrue(pcntl_wifexited($applyStatus) && pcntl_wexitstatus($applyStatus) === 0,
				"apply writer failed in iteration {$iteration}");

			$raw = file_get_contents("{$this->dir}/pfb_due_ledger.json");
			$this->assertNotFalse($raw, "ledger missing after iteration {$iteration}");
			$ledger = json_decode($raw, TRUE);
			$this->assertIsArray($ledger, "invalid JSON after iteration {$iteration}: {$raw}");
			$this->assertSame(
				['apply_reconcile', 'cron'],
				array_values(array_intersect(['apply_reconcile', 'cron'], array_keys($ledger))),
				"concurrent writers lost a job in iteration {$iteration}: {$raw}"
			);

			foreach (['cron', 'apply_reconcile'] as $job) {
				$report = json_decode(
					(string) file_get_contents("{$this->dir}/writer-{$job}-{$iteration}.json"),
					TRUE
				);
				$this->assertSame([], $report['warnings'] ?? NULL,
					"{$job} writer emitted warnings in iteration {$iteration}: " . json_encode($report));
			}
		}
	}
}
