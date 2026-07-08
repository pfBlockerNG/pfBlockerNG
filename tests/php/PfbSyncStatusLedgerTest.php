<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 — Pure sync-status ledger library.
 *
 * Tests the clock-injectable pfb_sync_status_* helpers defined in
 * pfblockerng_extra.inc, mirroring DueLedgerTest's shape. The library is
 * unreferenced by production code this phase — a later phase wires writers/
 * clearers into the download/apply/parse pipeline.
 *
 * Functions under test:
 *   pfb_sync_status_open(string $facility, string $item, string $stage,
 *                          string $message, string $ledger_dir, ?callable $clock_fn = null): void
 *   pfb_sync_status_close(string $facility, string $item, string $stage, string $ledger_dir): void
 *   pfb_sync_status_list_open(string $ledger_dir, ?string $facility = null): array
 *
 * Coverage mandate (CLAUDE.md "Test coverage") — every branch:
 *   open:  new key creates an entry; an already-open key refreshes message/
 *          last_seen and preserves first_seen (no duplicate); clock is injectable.
 *   close: existing key removed; absent key is a safe no-op (no write, no throw).
 *   list_open: filters by facility; NULL facility returns every facility.
 *   read:  absent file, corrupt (non-JSON) file, and corrupt (non-object JSON)
 *          file all read as an empty ledger — never throw.
 *   write: an unwritable ledger dir fails silently (no uncaught exception) —
 *          this suite's chosen contract; see testUnwritableLedgerDirFailsSafely().
 */
#[CoversFunction('pfb_sync_status_open')]
#[CoversFunction('pfb_sync_status_close')]
#[CoversFunction('pfb_sync_status_list_open')]
#[CoversFunction('pfb_sync_status_read_all')]
#[CoversFunction('pfb_sync_status_write_all')]
final class PfbSyncStatusLedgerTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_sync_status_test_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		// Restore a writable mode in case testUnwritableLedgerDirFailsSafely ran
		// (chmod 0555), so the recursive cleanup below can actually delete it.
		@chmod($this->dir, 0777);
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private static function clockAt(int $ts): callable
	{
		return static fn (): int => $ts;
	}

	// -----------------------------------------------------------------------
	// open() — new key, refresh-in-place, injectable clock.
	// -----------------------------------------------------------------------

	public function testOpenNewKeyCreatesOneEntry(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open, 'a brand-new key must create exactly one entry');
		$this->assertSame('ip', $open[0]['facility']);
		$this->assertSame('pfB_Example_v4', $open[0]['item']);
		$this->assertSame('download', $open[0]['stage']);
		$this->assertSame('HTTP 404', $open[0]['message']);
		$this->assertSame(1000, $open[0]['first_seen']);
		$this->assertSame(1000, $open[0]['last_seen']);
	}

	public function testOpenExistingKeyRefreshesWithoutDuplicating(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 500', $this->dir, self::clockAt(2000));

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open, 'reopening the SAME key must refresh, never duplicate');
		$this->assertSame('HTTP 500', $open[0]['message'], 'message must be the LATEST refresh');
		$this->assertSame(1000, $open[0]['first_seen'], 'first_seen must be preserved from the original open');
		$this->assertSame(2000, $open[0]['last_seen'], 'last_seen must advance to the refresh time');
	}

	public function testOpenDefaultsToRealClockWhenNoneInjected(): void
	{
		$before = time();
		pfb_sync_status_open('dnsbl', 'SomeGroup', 'apply', 'stuck', $this->dir);
		$after = time();

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open);
		$this->assertGreaterThanOrEqual($before, $open[0]['first_seen']);
		$this->assertLessThanOrEqual($after, $open[0]['first_seen']);
	}

	// -----------------------------------------------------------------------
	// close() — existing key removed; absent key is a safe no-op.
	// -----------------------------------------------------------------------

	public function testCloseExistingKeyRemovesEntry(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		// Before-state: the entry is genuinely open first, so close() closing it
		// is a real transition, not a no-op that happens to leave zero entries.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir));

		pfb_sync_status_close('ip', 'pfB_Example_v4', 'download', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir), 'closing the open key must remove it');
	}

	public function testCloseAbsentKeyIsSafeNoOp(): void
	{
		// No exception, no warning, no ledger file created at all.
		pfb_sync_status_close('ip', 'never_opened', 'download', $this->dir);

		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_status.json', 'close on an absent key must not write a file');
		$this->assertSame([], pfb_sync_status_list_open($this->dir));
	}

	public function testCloseAbsentKeyAmongOthersLeavesOthersIntact(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));

		// Close a DIFFERENT stage under the same facility/item — must be a no-op.
		pfb_sync_status_close('ip', 'pfB_Example_v4', 'apply', $this->dir);

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open, 'closing an unrelated stage must not touch the real entry');
		$this->assertSame('download', $open[0]['stage']);
	}

	// -----------------------------------------------------------------------
	// list_open() — facility filter.
	// -----------------------------------------------------------------------

	public function testListOpenFiltersByFacility(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'ip fail', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('dnsbl', 'SomeGroup', 'apply', 'dnsbl fail', $this->dir, self::clockAt(2000));

		$ip_only = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $ip_only);
		$this->assertSame('ip', $ip_only[0]['facility']);

		$dnsbl_only = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $dnsbl_only);
		$this->assertSame('dnsbl', $dnsbl_only[0]['facility']);

		$all = pfb_sync_status_list_open($this->dir);
		$this->assertCount(2, $all, 'NULL facility must return every facility');
	}

	// -----------------------------------------------------------------------
	// Downgrade-safe reads: absent / corrupt file -> empty ledger, never throw.
	// -----------------------------------------------------------------------

	public function testAbsentFileReadsAsEmpty(): void
	{
		$this->assertSame([], pfb_sync_status_list_open($this->dir));
	}

	public function testCorruptNonJsonFileReadsAsEmpty(): void
	{
		file_put_contents($this->dir . '/pfb_sync_status.json', 'this is not json{{{');

		$this->assertSame([], pfb_sync_status_list_open($this->dir));
	}

	public function testCorruptNonObjectJsonReadsAsEmpty(): void
	{
		// Valid JSON, but a scalar, not the expected facility->item->stage object.
		file_put_contents($this->dir . '/pfb_sync_status.json', '"just a string"');

		$this->assertSame([], pfb_sync_status_list_open($this->dir));
	}

	// -----------------------------------------------------------------------
	// Unwritable ledger dir — chosen contract: silent no-op, never an uncaught
	// exception. Root bypasses directory permissions entirely (a root run can't
	// simulate the denial — CLAUDE.md "Running tests"), so this is skipped there,
	// matching the repo's established chmod-0555 permission-test convention.
	// -----------------------------------------------------------------------

	public function testUnwritableLedgerDirFailsSafely(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses directory permissions -- cannot simulate the denial.');
		}

		chmod($this->dir, 0555);

		// Must not throw / must not emit an uncaught error up to the caller.
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));

		// The chosen contract is a silent no-op: nothing observable changed.
		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_status.json', 'an unwritable dir must not produce a ledger file');
	}
}
