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
			$this->assertSame([], glob($this->dir . '/.pfb_schedule.*') ?: [], $failure . ' must remove staging files');
		}
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

	public function testStateAbsentIsCanonicalEmptyAndFullItemRoundTrips(): void
	{
		$this->assertSame(['schema' => 1, 'items' => []], pfb_schedule_state_read($this->dir));
		$state = ['schema' => 1, 'items' => [
			'opaque-feed' => [
				'last_successful_check' => 0,
				'last_completed_occurrence' => 0,
				'completion_outcome' => 'success',
				'pending_occurrence' => 1,
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
			['schema' => 1, 'items' => ['feed' => ['last_completed_occurrence' => 1, 'completion_outcome' => 'success', 'pending_occurrence' => 1]]],
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
			$this->assertSame([], glob($this->dir . '/.pfb_schedule.*') ?: [], $failure . ' must remove staging files');
		}
	}

	public function testStateRejectsEveryNumericLookingOpaqueId(): void
	{
		foreach (['01', '1.5', '1e3', '+1', ' 1 '] as $id) {
			$this->assertFalse(pfb_schedule_state_write(
				['schema' => 1, 'items' => [$id => ['pending_occurrence' => 0]]],
				$this->dir
			), 'numeric-looking id must be rejected: ' . var_export($id, TRUE));
		}
	}

	public function testStateUpdateStartsEmptyMergesLatestFactsAndPendingOccurrences(): void
	{
		$this->assertTrue(pfb_schedule_state_update(
			static function (array $state): array {
				$state['items']['feed'] = ['last_successful_check' => 10];
				return $state;
			},
			$this->dir
		));
		$this->assertTrue(pfb_schedule_state_set_pending(['feed' => 20, 'new-feed' => 30], $this->dir));
		$this->assertSame([
			'schema' => 1,
			'items' => [
				'feed' => ['last_successful_check' => 10, 'pending_occurrence' => 20],
				'new-feed' => ['pending_occurrence' => 30],
			],
		], pfb_schedule_state_read($this->dir));
	}

	public function testStateUpdateRejectsMalformedExistingCallbackResultsAndPreservesBytes(): void
	{
		$path = $this->dir . '/pfb_schedule_state.json';
		file_put_contents($path, '{"schema":1,"items":null}');
		$before = file_get_contents($path);
		$this->assertFalse(pfb_schedule_state_update(static fn (array $state): array => $state, $this->dir));
		$this->assertSame($before, file_get_contents($path));

		$this->assertTrue(pfb_schedule_state_write(['schema' => 1, 'items' => ['feed' => ['pending_occurrence' => 1]]], $this->dir));
		$before = file_get_contents($path);
		foreach ([
			static fn (array $state): array => ['schema' => 2, 'items' => []],
			static fn (array $state): array => ['schema' => 1, 'items' => ['feed' => []]],
			static function (array $state): array { throw new RuntimeException('callback failed'); },
		] as $update) {
			$this->assertFalse(pfb_schedule_state_update($update, $this->dir));
			$this->assertSame($before, file_get_contents($path));
		}
	}

	public function testPendingValidationIsAtomicAndEmptyMapIsNoOp(): void
	{
		$this->assertTrue(pfb_schedule_state_set_pending([], $this->dir));
		$this->assertFileDoesNotExist($this->dir . '/pfb_schedule_state.json');
		foreach ([
			['', 1], ['1', 1], ['feed', -1], ['feed', 1.5], ['feed', '1'],
		] as [$id, $occurrence]) {
			$this->assertFalse(pfb_schedule_state_set_pending([$id => $occurrence], $this->dir));
		}
		$this->assertFileDoesNotExist($this->dir . '/pfb_schedule_state.json');
	}

	public function testPendingOccurrenceRemainsStableUntilTerminalOutcome(): void
	{
		$state = ['schema' => 1, 'items' => ['feed' => ['pending_occurrence' => 1]]];
		$this->assertTrue(pfb_schedule_state_write($state, $this->dir));
		$this->assertTrue(pfb_schedule_state_set_pending(['feed' => 3], $this->dir));
		$this->assertSame(
			['pending_occurrence' => 1],
			pfb_schedule_state_read($this->dir)['items']['feed'],
			'a late worker must never complete an occurrence that replaced the one it was dispatched for'
		);
	}

	public function testCompletedOccurrenceCannotBeReservedFromAStaleTickSnapshot(): void
	{
		$state = [
			'schema' => 1,
			'items' => ['feed' => ['last_completed_occurrence' => 3, 'completion_outcome' => 'success']],
		];
		$this->assertTrue(pfb_schedule_state_set_pending(['feed' => 3], $this->dir, [
			'before_document' => function () use ($state): void {
				file_put_contents($this->dir . '/pfb_schedule_state.json', json_encode($state));
			},
		]));
		$this->assertSame($state['items']['feed'], pfb_schedule_state_read($this->dir)['items']['feed']);
	}

	public function testStateUpdateReadsAfterExclusiveLockCallbackMutation(): void
	{
		$path = $this->dir . '/pfb_schedule_state.json';
		$this->assertTrue(pfb_schedule_state_write(['schema' => 1, 'items' => ['feed' => ['pending_occurrence' => 1]]], $this->dir));
		$newer = ['schema' => 1, 'items' => ['feed' => ['last_successful_check' => 9]]];
		$blocked = FALSE;
		$this->assertTrue(pfb_schedule_state_update(
			static function (array $state) use ($newer): array {
				return ['schema' => 1, 'items' => $state['items'] + $newer['items']];
			},
			$this->dir,
			['before_document' => static function () use ($path, $newer, &$blocked): void {
				$lock = fopen($path . '.lock', 'c');
				$would_block = 0;
				$blocked = !flock($lock, LOCK_EX | LOCK_NB, $would_block) && $would_block === 1;
				fclose($lock);
				file_put_contents($path, json_encode($newer));
			}],
		));
		$this->assertTrue($blocked);
		$this->assertSame($newer, pfb_schedule_state_read($this->dir));
	}
}
