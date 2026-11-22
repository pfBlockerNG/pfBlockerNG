<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4037: the settlement the update pass and the version 2 apply share, the clear of the due-ledger flag, and the check
 * that a pf table is empty. Each runs in this process against a due ledger, an apply record and a pfctl double in the test's
 * own folder.
 */
#[CoversFunction('pfb_apply_settle')]
#[CoversFunction('pfb_core_update_clear_pending_apply')]
#[CoversFunction('pfb_pfctl_table_empty')]
final class OutpostApplySettleTest extends TestCase
{
	private string $dir;

	/** @var array<string, mixed> */
	private array $saved;

	protected function setUp(): void
	{
		global $pfb;
		$this->saved = $pfb;
		$this->dir = sys_get_temp_dir() . '/pfb_settle_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700, TRUE);
		$pfb['dbdir'] = $this->dir;
		$pfb['save'] = FALSE;
		$pfb['filter_configure'] = FALSE;
	}

	protected function tearDown(): void
	{
		global $pfb;
		$pfb = $this->saved;
		rmdir_recursive($this->dir);
	}

	/** An apply record waiting for the next apply, as a received policy leaves it. */
	private function openRecord(): void
	{
		$time = time() - 100;
		file_put_contents("{$this->dir}/pfb_sync_receive.json", json_encode(['accepted_digest' => NULL,
			'last' => ['time' => $time, 'outcome' => 'changed'], 'apply' => ['time' => $time, 'outcome' => 'waiting']]));
	}

	/** @return array{0: ?string, 1: ?string} the apply record's outcome and reason */
	private function record(): array
	{
		$apply = json_decode((string) file_get_contents("{$this->dir}/pfb_sync_receive.json"), TRUE)['apply'] ?? [];
		return [$apply['outcome'] ?? NULL, $apply['reason'] ?? NULL];
	}

	/** @return array<string, array{0: bool, 1: ?string, 2: bool, 3: string}> reload unknown, failure, the flag kept, the reason recorded */
	public static function settlementsThatDoNotComplete(): array
	{
		$failed = 'a resource was not applied; pending changes kept';
		return [
			'version 2: a resource failed'           => [FALSE, $failed, TRUE, $failed],
			'version 1: the reload was not launched' => [TRUE, NULL, FALSE, 'firewall reload not confirmed; pending changes kept'],
		];
	}

	/**
	 * WHEN the apply did not complete THEN the settlement records the failure and returns FALSE. A failure it is given keeps the
	 * due flag, so nothing has to write it back; version 1's unlaunched reload clears it, as the update pass always has.
	 */
	#[DataProvider('settlementsThatDoNotComplete')]
	public function testASettlementThatDoesNotCompleteRecordsTheFailure(bool $reloadUnknown, ?string $failure, bool $kept, string $reason): void
	{
		$this->openRecord();
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir), 'before: the due flag is set');

		$settled = pfb_apply_settle(FALSE, $reloadUnknown, NULL, time() - 10, $failure);

		$this->assertSame($kept, pfb_due_ledger_is_pending('cron', $this->dir), 'the due flag');
		$this->assertSame(['failed', $reason], $this->record());
		$this->assertFalse($settled);
	}

	/** WHEN the due flag cannot be cleared THEN the settlement records a failed apply and returns FALSE. */
	public function testASettlementThatCannotClearTheDueFlagReturnsFalse(): void
	{
		$this->openRecord();
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));
		unlink("{$this->dir}/pfb_due_ledger.json.lock");
		mkdir("{$this->dir}/pfb_due_ledger.json.lock");	// a folder at the ledger's lock: no ledger write succeeds

		$settled = pfb_apply_settle(FALSE, FALSE, NULL, time() - 10);

		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dir), 'before: the flag could not be cleared');
		$this->assertFalse($settled);
		$this->assertSame('failed', $this->record()[0]);
	}

	/** WHEN everything was applied THEN the settlement clears the due flag, records the apply and returns TRUE. */
	public function testASettlementThatCompletesReturnsTrue(): void
	{
		$this->openRecord();
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));

		$this->assertTrue(pfb_apply_settle(FALSE, FALSE, NULL, time() - 10));
		$this->assertFalse(pfb_due_ledger_is_pending('cron', $this->dir));
		$this->assertSame('applied', $this->record()[0]);
	}

	/** WHEN the due ledger cannot be read (another process holds it) THEN clearing the flag fails: an unreadable flag is not a clear one. */
	public function testClearingAnUnreadableDueFlagFails(): void
	{
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));
		$held = fopen("{$this->dir}/pfb_due_ledger.json", 'r');
		$this->assertTrue(flock($held, LOCK_EX | LOCK_NB), 'before: the test holds the ledger');
		try {
			$cleared = pfb_core_update_clear_pending_apply(0.0);
		} finally {
			flock($held, LOCK_UN);
			fclose($held);
		}

		$this->assertFalse($cleared);
		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dir), 'the flag is still set');
	}

	/** WHEN the ledger holds no flag THEN the clear succeeds and writes no ledger. */
	public function testClearingAnAbsentDueFlagWritesNothing(): void
	{
		$this->assertTrue(pfb_core_update_clear_pending_apply(0.0));
		$this->assertFileDoesNotExist("{$this->dir}/pfb_due_ledger.json");
	}

	/** A pfctl double that runs $script. */
	private function pfctl(string $script): string
	{
		$path = "{$this->dir}/pfctl";
		file_put_contents($path, "#!/bin/sh\n{$script}\n");
		chmod($path, 0755);
		return $path;
	}

	/** @return array<string, array{0: string, 1: bool}> what `pfctl -T show` does => the table is empty */
	public static function tableShows(): array
	{
		return [
			'it prints nothing'                => ['exit 0', TRUE],
			'the table does not exist'         => ["echo 'pfctl: Table does not exist.' >&2; exit 1", TRUE],
			'it prints one member'             => ["echo '   192.0.2.1'", FALSE],
		];
	}

	/** A table is empty when `pfctl -T show` prints no member, a table that does not exist included. */
	#[DataProvider('tableShows')]
	public function testATableIsEmptyWhenPfctlShowsNoMember(string $script, bool $empty): void
	{
		global $pfb;
		$pfb['pfctl'] = $this->pfctl($script);

		$this->assertSame($empty, pfb_pfctl_table_empty('pfB_Abuse_v4'));
	}

	/** The check reads one line of `pfctl -T show`: a table of 500,000 members costs it no more memory than a table of one. */
	public function testTheEmptinessCheckReadsOneLineWhateverTheTableSize(): void
	{
		global $pfb;
		$pfb['pfctl'] = $this->pfctl("exec seq -f '10.0.%g.0/24' 1 500000");
		$this->assertSame('10.0.1.0/24', exec("{$pfb['pfctl']} | head -n 1"), 'before: the double prints the table');

		memory_reset_peak_usage();
		$before = memory_get_usage();
		$empty = pfb_pfctl_table_empty('pfB_Abuse_v4');
		$grown = memory_get_peak_usage() - $before;

		$this->assertFalse($empty);
		$this->assertLessThan(256 * 1024, $grown, "the check held {$grown} bytes of the table's listing");
	}
}
