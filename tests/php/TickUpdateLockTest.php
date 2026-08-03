<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #2122: the scheduled tick owns one bounded update-lock transaction. */
final class TickUpdateLockTest extends TestCase
{
	private string $dbdir = '';

	protected function setUp(): void
	{
		$this->dbdir = sys_get_temp_dir() . '/pfb_tick_update_lock_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		pfb_feed_pass_release();
		foreach (glob("{$this->dbdir}/*") ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dbdir);
		unset($GLOBALS['pfb_test_file_notices']);
	}

	public function testScheduledTimeoutCounterRaisesOnlyOnFifteenthConsecutiveFailure(): void
	{
		$this->assertTrue(function_exists('pfb_tick_lock_timeout_record'));
		for ($attempt = 1; $attempt <= 14; $attempt++) {
			pfb_tick_lock_timeout_record($this->dbdir);
		}
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'attempts 1-14 must raise no notice');
		$this->assertSame('14', trim((string) file_get_contents("{$this->dbdir}/pfb_tick_lock_timeouts")));

		pfb_tick_lock_timeout_record($this->dbdir);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'attempt 15 must raise exactly one notice');
		$this->assertStringContainsString('15 consecutive scheduled ticks',
			$GLOBALS['pfb_test_file_notices'][0]['notice']);

		pfb_tick_lock_timeout_record($this->dbdir);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'attempt 16 must not repeat the notice');
		$this->assertSame('15', trim((string) file_get_contents("{$this->dbdir}/pfb_tick_lock_timeouts")));
	}

	public function testOnlyScheduledSuccessResetsPersistentFailureSequence(): void
	{
		$this->assertTrue(function_exists('pfb_tick_lock_timeout_record'));
		$this->assertTrue(function_exists('pfb_tick_lock_timeout_reset'));
		file_put_contents("{$this->dbdir}/pfb_tick_lock_timeouts", '14');

		$this->assertTrue(pfb_feed_pass_acquire($this->dbdir), 'manual pass test setup must acquire');
		pfb_feed_pass_release();
		$this->assertSame('14', trim((string) file_get_contents("{$this->dbdir}/pfb_tick_lock_timeouts")),
			'manual success must not reset scheduled failure state');

		pfb_tick_lock_timeout_record($this->dbdir);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		pfb_tick_lock_timeout_reset($this->dbdir);
		$this->assertFileDoesNotExist("{$this->dbdir}/pfb_tick_lock_timeouts",
			'a scheduled tick lock success resets the sequence');

		$GLOBALS['pfb_test_file_notices'] = [];
		for ($attempt = 1; $attempt <= 14; $attempt++) {
			pfb_tick_lock_timeout_record($this->dbdir);
		}
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'reset starts a new 15-failure sequence');
	}

	public function testTickReadsLedgerOnceUnderLockAndDispatchesAfterRelease(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc'
		);
		$this->assertNotFalse($source);
		$start = strpos($source, 'function pfblockerng_tick(');
		$end = strpos($source, 'function pfb_sync_status_read_all(', $start);
		$this->assertNotFalse($start);
		$this->assertNotFalse($end);
		$body = substr($source, $start, $end - $start);

		$acquire = strpos($body,
			'pfb_feed_pass_wait(FALSE,$update_lock_timeout,$update_lock_clock,$update_lock_sleep,$dbdir)');
		$read = strpos($body, 'pfb_due_ledger_read_all($dbdir)');
		$release = strrpos($body, 'pfb_feed_pass_release();');
		$dispatch = strpos($body, 'foreach ($commands as $command)');

		$this->assertNotFalse($acquire, 'tick must wait on the shared update lock');
		$this->assertNotFalse($read, 'tick must read the ledger after acquiring');
		$this->assertSame(1, substr_count($body, 'pfb_due_ledger_read_all($dbdir)'),
			'tick must use exactly one ledger snapshot');
		$this->assertGreaterThan($acquire, $read, 'ledger read must occur after lock acquisition');
		$this->assertNotFalse($release);
		$this->assertNotFalse($dispatch);
		$this->assertGreaterThan($release, $dispatch,
			'background children must be dispatched only after the parent releases the update lock');
	}
}
