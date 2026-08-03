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

	public function testParentCommitsCadenceAndReleasesBeforeLaunchingChild(): void
	{
		$src = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc'
		);
		$this->assertNotFalse($src, 'test oracle: failed to read pfblockerng_extra.inc');

		$start = strpos($src, 'function pfblockerng_tick(');
		$end = strpos($src, 'function pfb_sync_status_read_all(', $start);
		$this->assertNotFalse($start);
		$this->assertNotFalse($end);
		$body = substr($src, $start, $end - $start);
		$mark = strpos($body, 'pfb_due_ledger_mark_entry_anchored($ledger, \'cron\'');
		$release = strrpos($body, 'pfb_feed_pass_release();');
		$launch = strpos($body, 'exec($command);');
		$this->assertNotFalse($mark);
		$this->assertNotFalse($release);
		$this->assertNotFalse($launch);
		$this->assertLessThan($release, $mark, 'cadence is committed while parent owns the lock');
		$this->assertLessThan($launch, $release, 'parent releases before any async child launch');
	}
}
