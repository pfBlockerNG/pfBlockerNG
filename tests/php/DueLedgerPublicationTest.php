<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DueLedgerPublicationTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_due_publication_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	public function testValidEntryPublishesAndReturnsTrue(): void
	{
		$result = pfb_due_ledger_write_entry('dcc', [
			'last_run' => 100,
			'next_due' => 200,
			'jitter' => 0,
		], $this->dir);

		$this->assertTrue($result, 'a valid ledger entry must report successful publication');
		$model = pfb_schedule_runtime_config();
		$this->assertIsArray($model,
			'harness: the writer needs a resolvable config generation to stamp against');
		$this->assertSame(
			[
				'_meta' => ['schema' => 1, 'config_hash' => $model['config_hash']],
				'dcc' => ['last_run' => 100, 'next_due' => 200, 'jitter' => 0],
			],
			json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE),
			'the published document must carry the row plus the stamp its own cache reader requires'
		);
	}

	public function testMalformedEntryReturnsFalseAndPreservesPriorBytes(): void
	{
		$path = $this->dir . '/pfb_due_ledger.json';
		file_put_contents($path, '{"keep":{"last_run":1,"next_due":2,"jitter":0}}');
		$before = file_get_contents($path);

		$result = pfb_due_ledger_write_entry('dcc', ['last_run' => 'bad'], $this->dir);

		$this->assertFalse($result, 'malformed entry must reject publication');
		$this->assertSame($before, file_get_contents($path), 'rejected entry must preserve prior bytes');
	}

	public function testInjectedPublicationFailuresReturnFalseAndPreservePriorBytes(): void
	{
		foreach (['fail_temp', 'fail_write', 'fail_read', 'fail_validate', 'fail_rename'] as $failure) {
			$path = $this->dir . '/pfb_due_ledger.json';
			file_put_contents($path, '{"keep":{"last_run":1,"next_due":2,"jitter":0}}');
			$before = file_get_contents($path);

			$result = pfb_due_ledger_write_entry('dcc', [
				'last_run' => 100,
				'next_due' => 200,
				'jitter' => 0,
			], $this->dir, [$failure => TRUE]);

			$this->assertFalse($result, $failure . ' must reject publication');
			$this->assertSame($before, file_get_contents($path), $failure . ' must preserve prior bytes');
			$this->assertFileDoesNotExist($path . '.tmp', $failure . ' must remove staging file');
		}
	}

	public function testPendingPublicationReportsWhetherTheDurableMarkerWasWritten(): void
	{
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));
		$this->assertTrue(pfb_due_ledger_read_entry('cron', $this->dir)['pending_apply'] ?? FALSE);
		$before = file_get_contents($this->dir . '/pfb_due_ledger.json');

		$this->assertFalse(pfb_due_ledger_set_pending('cron', $this->dir, 5.0, ['fail_rename' => TRUE]));
		$this->assertSame($before, file_get_contents($this->dir . '/pfb_due_ledger.json'));
	}
}
