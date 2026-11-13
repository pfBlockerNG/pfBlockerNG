<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ScheduleStateStoreTest extends TestCase
{
	private const HASH = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_schedule_state_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	public function testEntryUpdateRejectsMalformedSiblingAndPreservesCache(): void
	{
		$path = $this->dir . '/pfb_due_ledger.json';
		$documents = [
			['good' => ['last_run' => 1, 'next_due' => 2, 'jitter' => 0], 'bad' => ['last_run' => '1']],
			['_meta' => ['schema' => 1, 'config_hash' => self::HASH], 'bad' => ['last_run' => '1']],
		];
		foreach ($documents as $document) {
			file_put_contents($path, json_encode($document));
			$before = file_get_contents($path);

			$this->assertFalse(pfb_due_ledger_write_entry(
				'dcc',
				['last_run' => 3, 'next_due' => 4, 'jitter' => 0],
				$this->dir
			));
			$this->assertSame($before, file_get_contents($path));
		}
	}

	public function testPendingUpdateUsesLatestEntryInsideExclusiveTransaction(): void
	{
		$path = $this->dir . '/pfb_due_ledger.json';
		$this->assertTrue(pfb_due_ledger_write_entry(
			'cron',
			['last_run' => 1, 'next_due' => 2, 'jitter' => 0],
			$this->dir
		));
		$newer = ['last_run' => 100, 'next_due' => 200, 'jitter' => 0];
		$competing_lock_blocked = FALSE;

		pfb_due_ledger_set_pending('cron', $this->dir, 5.0, [
			'before_document' => static function () use ($path, $newer, &$competing_lock_blocked): void {
				$competitor = fopen($path . '.lock', 'c');
				$would_block = 0;
				$competing_lock_blocked = !flock($competitor, LOCK_EX | LOCK_NB, $would_block) && $would_block === 1;
				fclose($competitor);
				file_put_contents($path, json_encode(['cron' => $newer]));
			},
		]);

		$this->assertTrue($competing_lock_blocked, 'the whole entry update must hold the sidecar lock');
		$this->assertSame($newer + ['pending_apply' => TRUE], pfb_due_ledger_read_entry('cron', $this->dir));
	}

}
