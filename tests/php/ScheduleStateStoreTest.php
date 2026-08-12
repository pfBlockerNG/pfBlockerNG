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

	public function testCacheRoundTripAllowsNoCronAndRejectsStaleOrMalformedDocuments(): void
	{
		$this->assertTrue(pfb_due_ledger_write_cache([], self::HASH, $this->dir));
		$this->assertSame(
			['_meta' => ['schema' => 1, 'config_hash' => self::HASH]],
			pfb_due_ledger_read_cache($this->dir, self::HASH)
		);
		$this->assertNull(pfb_due_ledger_read_cache($this->dir, str_repeat('b', 64)));
		file_put_contents($this->dir . '/pfb_due_ledger.json', '[]');
		$this->assertNull(pfb_due_ledger_read_cache($this->dir, self::HASH));
		file_put_contents($this->dir . '/pfb_due_ledger.json', '{"_meta":{"schema":1,"config_hash":"' . strtoupper(self::HASH) . '"}}');
		$this->assertNull(pfb_due_ledger_read_cache($this->dir, self::HASH));
	}

	public function testCachePreservesBothEntryShapesAndRejectsInvalidInputs(): void
	{
		$entries = [
			'cron' => ['last_run' => 0, 'next_due' => 0, 'jitter' => 0],
			'dcc' => ['last_run' => 1, 'next_due' => 2, 'jitter' => 0, 'pending_apply' => TRUE],
		];
		$this->assertTrue(pfb_due_ledger_write_cache($entries, self::HASH, $this->dir));
		$this->assertSame($entries, array_diff_key(pfb_due_ledger_read_cache($this->dir, self::HASH), ['_meta' => TRUE]));
		$this->assertFalse(pfb_due_ledger_write_cache(['bad' => ['last_run' => '1']], self::HASH, $this->dir));
		$this->assertFalse(pfb_due_ledger_write_cache([], strtoupper(self::HASH), $this->dir));
		$this->assertFalse(pfb_due_ledger_write_cache([], 'short', $this->dir));
	}

	public function testCacheFailureBoundariesPreservePreviousBytes(): void
	{
		$this->assertTrue(pfb_due_ledger_write_cache([], self::HASH, $this->dir));
		$path = $this->dir . '/pfb_due_ledger.json';
		$before = file_get_contents($path);
		foreach (['fail_temp', 'fail_write', 'fail_read', 'fail_validate', 'fail_rename'] as $failure) {
			$this->assertFalse(pfb_due_ledger_write_cache(
				['cron' => ['last_run' => 1, 'next_due' => 2, 'jitter' => 0]],
				self::HASH,
				$this->dir,
				[$failure => TRUE]
			), $failure);
			$this->assertSame($before, file_get_contents($path), $failure . ' must preserve target');
		}
	}

	public function testStateAbsentIsCanonicalEmptyAndFullItemRoundTrips(): void
	{
		$this->assertSame(['schema' => 1, 'items' => []], pfb_schedule_state_read($this->dir));
		$state = ['schema' => 1, 'items' => [
			'opaque-feed' => [
				'last_successful_check' => 0,
				'last_completed_occurrence' => 0,
				'completion_outcome' => 'success',
				'pending_occurrence' => 0,
			],
		]];
		$this->assertTrue(pfb_schedule_state_write($state, $this->dir));
		$this->assertSame($state, pfb_schedule_state_read($this->dir));
	}

	public function testStateRejectsHostileShapesAndPreservesBytesOnFailures(): void
	{
		$valid = ['schema' => 1, 'items' => ['feed' => ['pending_occurrence' => 0]]];
		$this->assertTrue(pfb_schedule_state_write($valid, $this->dir));
		$path = $this->dir . '/pfb_schedule_state.json';
		$before = file_get_contents($path);
		$invalid = [
			['schema' => 2, 'items' => []],
			['schema' => 1, 'items' => ['' => ['pending_occurrence' => 0]]],
			['schema' => 1, 'items' => ['1' => ['pending_occurrence' => 0]]],
			['schema' => 1, 'items' => ['feed' => ['pending_occurrence' => -1]]],
			['schema' => 1, 'items' => ['feed' => ['pending_occurrence' => 1.5]]],
			['schema' => 1, 'items' => ['feed' => ['last_completed_occurrence' => 1]]],
			['schema' => 1, 'items' => ['feed' => ['last_completed_occurrence' => 1, 'completion_outcome' => 'bad']]],
			['schema' => 1, 'items' => ['feed' => ['pending_occurrence' => 0, 'unknown' => 1]]],
		];
		foreach ($invalid as $state) {
			$this->assertFalse(pfb_schedule_state_write($state, $this->dir));
			$this->assertSame($before, file_get_contents($path));
		}
		file_put_contents($path, '{"schema":1,"items":null}');
		$this->assertNull(pfb_schedule_state_read($this->dir));
		foreach (['fail_temp', 'fail_write', 'fail_read', 'fail_validate', 'fail_rename'] as $failure) {
			$this->assertFalse(pfb_schedule_state_write($valid, $this->dir, [$failure => TRUE]), $failure);
		}
	}
}
