<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941 (cutover review): pfb_due_ledger_retire_schedule() drops the PHP scheduler's entries from the due ledger once, on
 * every install and upgrade, and the Outpost's own entries stay: `ss_refresh`, `apply_reconcile` and the `cron` entry as the
 * pending-apply flag. The ledger is shared with the writers of those entries (the tick, a page save, an HA receive), which take
 * the ledger's lock; so the read that decides what to keep happens under that same lock, or a `pending_apply` set between the
 * read and the publish is published away.
 *
 * The seam is the publisher's `before_document` hook: it runs under the lock, where the writer that won the lock first has just
 * committed. PfbCoreServiceTest pins the rest (what goes, what stays, a ledger with nothing to drop is not rewritten).
 */
#[CoversFunction('pfb_due_ledger_retire_schedule')]
final class DueLedgerRetireScheduleTest extends TestCase
{
	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_ledger_retire_' . getmypid() . '_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	/** @return array<string, mixed> */
	private function ledger(): array
	{
		return json_decode((string) file_get_contents("{$this->dir}/pfb_due_ledger.json"), TRUE, 16, JSON_THROW_ON_ERROR);
	}

	/** @param array<string, mixed> $document */
	private function write(array $document): void
	{
		file_put_contents("{$this->dir}/pfb_due_ledger.json", json_encode($document, JSON_THROW_ON_ERROR));
	}

	private static function entry(array $more = []): array
	{
		return ['last_run' => 5, 'next_due' => 9, 'jitter' => 0] + $more;
	}

	public function testAPendingApplySetWhileTheRetirementWaitsForTheLockIsNotLost(): void
	{
		// Given a ledger whose `cron` entry carries no pending apply when the retirement starts
		$this->write(['_meta' => ['schema' => 1, 'config_hash' => str_repeat('a', 64)], 'cron' => self::entry(), 'extra:dcc' => self::entry(), 'ss_refresh' => self::entry()]);
		$fired = 0;

		// When the tick marks a pending apply just before the retirement holds the lock (its commit is what the hook plays)
		$ok = pfb_due_ledger_retire_schedule($this->dir, [
			'before_document' => function () use (&$fired): void {
				$fired++;
				$this->write(['_meta' => ['schema' => 1, 'config_hash' => str_repeat('a', 64)], 'cron' => self::entry(['pending_apply' => TRUE]),
					'extra:dcc' => self::entry(), 'ss_refresh' => self::entry()]);
			},
		]);

		// Then the retirement decided on what was in the file under the lock: the pending apply survives, the schedule entries go
		$this->assertTrue($ok);
		$this->assertSame(1, $fired, 'the publisher ran the hook once, under the lock');
		$this->assertSame(
			['cron' => ['last_run' => 0, 'next_due' => 0, 'jitter' => 0, 'pending_apply' => TRUE], 'ss_refresh' => self::entry()],
			$this->ledger(),
			'the pending apply set under the lock must survive, and the schedule entries and the stamp must go'
		);
	}

	public function testAnEntryTheOutpostAddedWhileTheRetirementWaitsForTheLockIsNotLost(): void
	{
		$this->write(['extra:dcc' => self::entry(), 'ss_refresh' => self::entry()]);

		$ok = pfb_due_ledger_retire_schedule($this->dir, [
			'before_document' => function (): void {
				$this->write(['extra:dcc' => self::entry(), 'ss_refresh' => self::entry(), 'apply_reconcile' => self::entry(['next_due' => 99])]);
			},
		]);

		$this->assertTrue($ok);
		$this->assertSame(['ss_refresh' => self::entry(), 'apply_reconcile' => self::entry(['next_due' => 99])], $this->ledger());
	}

	public function testALedgerThatWentCleanWhileTheRetirementWaitedIsLeftAsItIs(): void
	{
		// Given a ledger with a schedule entry the retirement would drop, which another run retires first
		$this->write(['extra:dcc' => self::entry(), 'ss_refresh' => self::entry()]);

		$ok = pfb_due_ledger_retire_schedule($this->dir, [
			'before_document' => function (): void {
				$this->write(['ss_refresh' => self::entry()]);
			},
		]);

		$this->assertTrue($ok, 'nothing to drop is a success');
		$this->assertSame(['ss_refresh' => self::entry()], $this->ledger());
	}

	public function testALedgerThatIsNotJsonIsLeftAsItIsAndIsNotAFailure(): void
	{
		file_put_contents("{$this->dir}/pfb_due_ledger.json", 'not json');

		$this->assertTrue(pfb_due_ledger_retire_schedule($this->dir));
		$this->assertSame('not json', file_get_contents("{$this->dir}/pfb_due_ledger.json"));
	}

	public function testNoLedgerIsNoWork(): void
	{
		$this->assertTrue(pfb_due_ledger_retire_schedule($this->dir));
		$this->assertFileDoesNotExist("{$this->dir}/pfb_due_ledger.json");
	}
}
