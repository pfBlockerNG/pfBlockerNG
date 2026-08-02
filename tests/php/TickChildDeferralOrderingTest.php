<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1315 review -- a child cron pass that loses the feed-pass lock may
 * finish before the backgrounding tick resumes after exec(). The parent must
 * advance its cadence before launch so it cannot erase the child's deferral.
 */
final class TickChildDeferralOrderingTest extends TestCase
{
	private string $dbdir = '';
	private array $originalPfb = [];
	private $lockFp = NULL;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->dbdir = sys_get_temp_dir() . '/pfb_tick_child_order_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dbdir;
		$GLOBALS['pfb']['log'] = "{$this->dbdir}/pfblockerng.log";

		$this->lockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertNotFalse($this->lockFp, 'test setup: failed to open feed-pass lock');
		$this->assertTrue(flock($this->lockFp, LOCK_EX), 'test setup: failed to hold feed-pass lock');
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

	public function testChildLockLossAfterLaunchKeepsPendingRetry(): void
	{
		// Scheduling is off-limits for #2103 and the background child cannot be made
		// deterministic off-appliance. Keep the ordering pin against comment-free PHP.
		// PRODUCTION COMMENTS AND DOCBLOCKS MUST NEVER BE LOAD-BEARING FOR A TEST.
		$src = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc'
		);
		$this->assertNotFalse($src, 'test oracle: failed to read pfblockerng_extra.inc');

		$branchStart = strpos($src, "logger(LOG_NOTICE, localize_text('Tick: dispatching feed cron.')");
		$this->assertNotFalse($branchStart, 'test oracle: numeric feed-cron dispatch branch not found');
		$branchEnd = strpos($src, '$dispatched = TRUE;', $branchStart);
		$this->assertNotFalse($branchEnd, 'test oracle: feed-cron dispatch branch end not found');
		$branch = substr($src, $branchStart, $branchEnd - $branchStart);

		$launchPos = strpos($branch, 'exec("{$pfb[\'php\']} /usr/local/www/pfblockerng/pfblockerng.php cron');
		$markPos = strpos($branch, "pfb_due_ledger_mark_ran_anchored('cron'");
		$this->assertNotFalse($launchPos, 'test oracle: exact cron background launch not found');
		$this->assertNotFalse($markPos, 'test oracle: anchored cadence update not found');

		$now = time();
		$interval = 86400;
		$oldNextDue = $now - 10;
		pfb_due_ledger_write_entry('cron', [
			'last_run' => $oldNextDue - $interval,
			'next_due' => $oldNextDue,
			'jitter'   => 0,
		], $this->dbdir);

		$operations = [
			$launchPos => static function (): void {
				pfblockerng_sync_cron();
			},
			$markPos => function () use ($interval, $now): void {
				pfb_due_ledger_mark_ran_anchored('cron', $interval, $now, 'test-seed', 0, $this->dbdir);
			},
		];
		ksort($operations);
		foreach ($operations as $operation) {
			$operation();
		}

		$after = pfb_due_ledger_read_entry('cron', $this->dbdir);
		$this->assertSame($oldNextDue + $interval, $after['next_due'],
			'numeric cadence must still advance from the previous anchored due time');
		$this->assertTrue(!empty($after['pending_apply']),
			'child lock loss after launch must remain pending for the next enabled tick');
	}
}
