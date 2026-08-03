<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1315 -- the cron/Force Check funnel must defer when its atomic
 * feed-pass acquisition loses after the tick's advisory busy probe.
 */
final class SyncCronFeedPassDeferralTest extends TestCase
{
	private string $dbdir = '';
	private array $originalPfb = [];
	private $lockFp = NULL;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->dbdir = sys_get_temp_dir() . '/pfb_sync_cron_feedpass_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dbdir;
		$GLOBALS['pfb']['log'] = "{$this->dbdir}/pfblockerng.log";

	}

	protected function tearDown(): void
	{
		if (is_resource($this->lockFp)) {
			flock($this->lockFp, LOCK_UN);
			fclose($this->lockFp);
		}
		pfb_feed_pass_release();
		$GLOBALS['pfb'] = $this->originalPfb;
		foreach (glob("{$this->dbdir}/*") ?: [] as $path) {
			unlink($path);
		}
		rmdir($this->dbdir);
	}

	public function testLockTimeoutLeavesLedgerUntouched(): void
	{
		$nextDue = time() + 3600;
		pfb_due_ledger_write_entry('cron', [
			'last_run' => time() - 3600,
			'next_due' => $nextDue,
			'jitter'   => 0,
		], $this->dbdir);

		$before = pfb_due_ledger_read_entry('cron', $this->dbdir);
		$this->assertSame($nextDue, $before['next_due'], 'test setup: future next_due must be seeded');
		$this->lockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertNotFalse($this->lockFp, 'test setup: failed to open feed-pass lock');
		$this->assertTrue(flock($this->lockFp, LOCK_EX), 'test setup: failed to hold feed-pass lock');

		$this->assertFalse(pfb_feed_pass_wait(FALSE, 0.0, NULL, NULL, $this->dbdir));

		$after = pfb_due_ledger_read_entry('cron', $this->dbdir);
		$this->assertSame($nextDue, $after['next_due'], 'lost lock must preserve next_due');
		$this->assertArrayNotHasKey('pending_apply', $after, 'a non-owner must not mutate the ledger');
	}
}
