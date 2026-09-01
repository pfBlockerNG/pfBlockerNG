<?php

declare(strict_types=1);

require_once __DIR__ . '/support/FailingFlockStream.php';

use PHPUnit\Framework\TestCase;

/**
 * Issue #2592: pfb_extras_process_begin()'s dispatcher-lock guard must name itself.
 *
 * The Extras verbs are wired as `if (!$scheduled && !pfb_extras_process_begin())
 * { exit(1); }` (pfblockerng.php, the shared `case 'dc': case 'dcc':` label), so a
 * FALSE from that guard surfaces as rc=1 with empty stdout AND stderr. Before this
 * change the lost-dispatcher-lock branch returned FALSE writing nothing anywhere --
 * a probe against the untouched guard produced rc=1 with a 0-byte delta on
 * $pfb['log'], $pfb['errlog'] AND $pfb['extraslog'] and zero logger() calls -- so a
 * live wedged lock holder was undiagnosable. Same class as issue #2496 ("every guard
 * must name itself or the failure is undiagnosable") on a third dispatcher-lock site.
 *
 * The deferral must be visible in BOTH sinks the sibling guards use, and the
 * exit-code semantics must not move (a deferred Extras run got no work, so the verbs
 * keep reporting it):
 *
 *   pfblockerng.inc:18608-18610   pfb_feed_pass_begin()  pfb_logger(1) + logger(LOG_NOTICE)
 *   pfblockerng_apply.inc:722-726 (issue #2505)          pfb_logger(1) + logger(LOG_NOTICE)
 *   pfblockerng_cron.inc:266-270  (issue #2505)          pfb_logger(1) + logger(LOG_NOTICE)
 *
 * Rows 1-2 and 6 are RED before the fix. Rows 3-5 are before-state guards that pass
 * on both sides: row 3 pins the FALSE that drives the verbs' rc=1, rows 4-5 pin that
 * nothing new is logged when the dispatcher lock was actually acquired.
 *
 * Contention is provoked the way FeedPassLockTest's rows do it -- see its docblock for
 * the flock(2) open-file-description semantics that make it work within one process.
 */
final class ExtrasDispatcherDeferralLoggingTest extends TestCase
{
	/** The syslog wording the sibling guards use, with this guard's label. */
	private const NOTICE = 'Feed pass [ extras ] deferred - the scheduler dispatcher lock is unavailable.';

	private string $dir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];

	/** Raw fds simulating ANOTHER process holding a lock -- closed in tearDown. */
	private array $rawFps = [];

	protected function setUp(): void
	{
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->dir = sys_get_temp_dir() . '/pfb_extras_defer_' . uniqid('', TRUE);
		mkdir($this->dir, 0755, TRUE);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir'              => $this->dir,
			'schedule_state_dir' => $this->dir,
			'log'                => "{$this->dir}/pfblockerng.log",
			'errlog'             => "{$this->dir}/error.log",
			'extraslog'          => "{$this->dir}/extras.log",
		]);

		// No inherited locks: a leaked handle makes pfb_schedule_dispatch_begin()
		// short-circuit on its reentrancy check, so the guard under test is never
		// reached and a deferral row would pass vacuously.
		unset($GLOBALS['pfb_schedule_dispatch_lock'], $GLOBALS['pfb_feed_pass_lock']);

		// Fresh syslog capture (pfsense_doubles.php logger() double).
		$GLOBALS['pfb_test_logger_calls'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->rawFps as $fp) {
			if (is_resource($fp)) {
				@flock($fp, LOCK_UN);
				@fclose($fp);
			}
		}
		$this->rawFps = [];

		// Never leave this process holding a lock across tests (self-encapsulation).
		pfb_feed_pass_release();
		pfb_schedule_dispatch_release();
		unset($GLOBALS['pfb_schedule_dispatch_lock'], $GLOBALS['pfb_feed_pass_lock']);
		unset($GLOBALS['pfb_test_logger_calls']);

		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			is_dir($path) ? @rmdir($path) : @unlink($path);
		}
		@rmdir($this->dir);

		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	private function mainLog(): string
	{
		$log = $GLOBALS['pfb']['log'];
		return is_file($log) ? (string) file_get_contents($log) : '';
	}

	/** The syslog messages captured by the logger() double, one per line. */
	private function syslogMessages(): string
	{
		return implode("\n", array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
	}

	/** ANOTHER process wedges the scheduler dispatcher lock. */
	private function holdDispatcherLock(): void
	{
		$fp = fopen("{$this->dir}/pfb_schedule_dispatch.lock", 'c');
		$this->assertIsResource($fp, 'test setup: could not open the dispatcher lock');
		$this->rawFps[] = $fp;
		$this->assertTrue(flock($fp, LOCK_EX), 'test setup: could not hold the dispatcher lock');
	}

	/** ANOTHER process wedges the feed-pass lock. */
	private function holdFeedPassLock(): void
	{
		$fp = fopen("{$this->dir}/pfb_feed_pass.lock", 'c');
		$this->assertIsResource($fp, 'test setup: could not open the feed-pass lock');
		$this->rawFps[] = $fp;
		$this->assertTrue(flock($fp, LOCK_EX), 'test setup: could not hold the feed-pass lock');
	}

	// -----------------------------------------------------------------------
	// RED rows: a lost dispatcher lock must name itself in both sinks.
	// -----------------------------------------------------------------------

	/**
	 * Scenario: an Extras run (`pfblockerng.php dc` / `dcc`) loses the dispatcher race.
	 *   Given another process holds the scheduler dispatcher lock
	 *   When  pfb_extras_process_begin() runs
	 *   Then  it still reports the deferral (FALSE -> the verb's exit 1)
	 *   And   /var/log/pfblockerng/pfblockerng.log names THIS guard, not just "deferred"
	 */
	public function testDispatcherDeferralNamesTheGuardInTheMainLog(): void
	{
		$this->holdDispatcherLock();

		$this->assertFalse(pfb_extras_process_begin(),
			'before-state: a wedged dispatcher lock must keep reporting the deferral');
		$this->assertStringContainsString('Extras process deferred: dispatcher lock unavailable', $this->mainLog(),
			'the deferred Extras run must name WHICH guard stood it down (issue #2592)');
	}

	/**
	 * Scenario: the same deferral must escape /var/log/pfblockerng.
	 *   Given another process holds the scheduler dispatcher lock
	 *   When  pfb_extras_process_begin() runs
	 *   Then  exactly one syslog notice carries the sibling guards' wording,
	 *         at LOG_NOTICE, under the pfBlockerNG prefix
	 *
	 * All three attributes are asserted, not just the text: feed-pass parity is
	 * specifically LOG_NOTICE (pfb_feed_pass_begin()), and without the prefix the
	 * line is not attributable to this package in syslog.
	 */
	public function testDispatcherDeferralRaisesLogNoticeSyslogLine(): void
	{
		$this->holdDispatcherLock();

		pfb_extras_process_begin();

		$notices = array_values(array_filter(
			$GLOBALS['pfb_test_logger_calls'],
			static fn (array $call): bool => str_contains($call['message'], 'dispatcher lock')
		));
		$this->assertCount(1, $notices,
			'a wedged dispatcher-lock holder must raise exactly one syslog notice (issue #2592) -- captured: '
			. var_export($GLOBALS['pfb_test_logger_calls'], TRUE));
		$this->assertSame(self::NOTICE, $notices[0]['message'],
			"the notice must keep the sibling guards' wording (pfblockerng_apply.inc:725)");
		$this->assertSame(LOG_NOTICE, $notices[0]['priority'],
			'the deferral notice must be LOG_NOTICE (feed-pass parity)');
		$this->assertSame(LOG_PREFIX_PKG_PFBLOCKERNG, $notices[0]['prefix'],
			'the notice must be attributable to pfBlockerNG in syslog');
	}

	/**
	 * Issue #3012: the FEED-pass guard must name itself too.
	 *
	 * pfb_feed_pass_begin() logs its own skip line only when the lock is
	 * CONTENDED. An acquisition error leaves $contended FALSE, so before #3012
	 * this arm released the dispatcher lock and returned FALSE with nothing in
	 * the main log naming what was skipped or why -- the operator saw a verb
	 * silently do nothing.
	 */
	public function testFeedPassAcquisitionErrorNamesTheGuardInTheMainLog(): void
	{
		$this->assertTrue(stream_wrapper_register('pfbextrasfeedlockerror', PfbFailingFlockStream::class));
		$dbdir = $GLOBALS['pfb']['dbdir'];
		try {
			// Only the feed-pass lock lives under dbdir; the dispatcher lock uses
			// schedule_state_dir, so it still acquires and this reaches the guard.
			$GLOBALS['pfb']['dbdir'] = 'pfbextrasfeedlockerror://state';

			$this->assertFalse(pfb_extras_process_begin(),
				'an unacquirable feed-pass lock must still refuse the extras run');
			$this->assertStringContainsString('feed pass lock could not be acquired', $this->mainLog(),
				'an acquisition error must name itself in the main log; contention is the only case '
				. 'pfb_feed_pass_begin() logs on its own behalf');
		} finally {
			$GLOBALS['pfb']['dbdir'] = $dbdir;
			stream_wrapper_unregister('pfbextrasfeedlockerror');
		}
	}

	public function testScheduleCacheAcquisitionErrorNamesTheGuardInTheMainLog(): void
	{
		$this->assertTrue(stream_wrapper_register('pfbschedulecachelockerror', PfbFailingFlockStream::class));
		$dbdir = $GLOBALS['pfb']['dbdir'];
		try {
			$GLOBALS['pfb']['dbdir'] = 'pfbschedulecachelockerror://state';

			$this->assertFalse(pfb_schedule_cache_regenerate(),
				'an unacquirable feed-pass lock must refuse schedule cache regeneration');
			$this->assertStringContainsString(
				'Schedule cache regeneration skipped: the feed pass lock could not be acquired.',
				$this->mainLog(),
				'the acquisition error must name schedule cache regeneration in the main log'
			);
			$this->assertStringNotContainsString('another pfBlockerNG feed pass is running', $this->mainLog(),
				'an acquisition error must not claim another pass is running');
			$this->assertFalse(is_resource($GLOBALS['pfb_schedule_dispatch_lock'] ?? NULL),
				'the refused regeneration must release its dispatcher lock');
			$this->assertFalse(is_resource($GLOBALS['pfb_feed_pass_lock'] ?? NULL),
				'the refused regeneration must not leave a feed-pass lock');
		} finally {
			$GLOBALS['pfb']['dbdir'] = $dbdir;
			stream_wrapper_unregister('pfbschedulecachelockerror');
		}
	}

	/**
	 * Scenario: the deferral line must not graft onto a half-written log line.
	 *   Given the main log ends mid-line (a previous writer's partial write)
	 *   When  the dispatcher-lock deferral logs
	 *   Then  the new line starts on a fresh line carrying its own ISO timestamp
	 *
	 * pfb_logger() inserts the stamp AFTER any leading newlines and only when the
	 * target is at BOL (pfb_logger_format_for_target()), so dropping the message's
	 * leading "\n" would append unstamped text to whatever was written last.
	 */
	public function testDeferralLineStartsOnItsOwnStampedLogLine(): void
	{
		file_put_contents($GLOBALS['pfb']['log'], 'unterminated line from the lock holder');
		$this->holdDispatcherLock();

		pfb_extras_process_begin();

		$this->assertMatchesRegularExpression(
			'/^unterminated line from the lock holder\n'
			. '\d{4}-\d\d-\d\d \d\d:\d\d:\d\d  Extras process deferred: dispatcher lock unavailable\.\n$/',
			$this->mainLog(),
			'the deferral must begin its own stamped line, not extend the previous partial write');
	}

	// -----------------------------------------------------------------------
	// Guard rows (green before AND after the fix).
	// -----------------------------------------------------------------------

	/**
	 * Scenario: logging the deferral must not change what the verbs report.
	 *   Given another process holds the scheduler dispatcher lock
	 *   Then  pfb_extras_process_begin() returns FALSE, which is what the Extras verbs
	 *         turn into exit(1)
	 *
	 * Only the executable half is pinned here. That `dc`/`dcc` stay WIRED as
	 * `if (!$scheduled && !pfb_extras_process_begin()) { exit(1); }` is guaranteed by
	 * pfblockerng.php being outside this change's diff, not by re-deriving an
	 * unmodified file's text -- and nothing pinned that exit code before this change
	 * either. Asserting it for real needs the appliance tier: issue #2832.
	 */
	public function testDcAndDccVerbsKeepExitingOneOnDispatcherDeferral(): void
	{
		$this->holdDispatcherLock();
		$this->assertFalse(pfb_extras_process_begin(),
			'the Extras guard must keep returning FALSE -- that FALSE IS the verbs rc=1');
	}

	/**
	 * Scenario: the granted path stays quiet -- the new lines are deferral-only.
	 *   Given nothing holds either lock
	 *   When  pfb_extras_process_begin() runs
	 *   Then  it returns TRUE
	 *   And   nothing new reaches pfblockerng.log or syslog
	 */
	public function testGrantedExtrasProcessLogsNothingNew(): void
	{
		$this->assertTrue(pfb_extras_process_begin(),
			'before-state: an uncontended Extras run must get both locks');

		$this->assertStringNotContainsString('deferred', $this->mainLog(),
			'a granted Extras run must not log a deferral');
		$this->assertSame([], $GLOBALS['pfb_test_logger_calls'],
			'a granted Extras run must raise no syslog line');
	}

	/**
	 * Scenario: the OTHER failure branch must not borrow the dispatcher's message.
	 *   Given nothing holds the dispatcher lock but another process holds the feed-pass lock
	 *   When  pfb_extras_process_begin() runs
	 *   Then  it reports the deferral
	 *   And   pfb_feed_pass_begin()'s own skip line is what names it
	 *   And   nothing claims the dispatcher lock was unavailable (it was acquired)
	 */
	public function testFeedPassDeferralDoesNotClaimTheDispatcherLockWasUnavailable(): void
	{
		$this->holdFeedPassLock();

		$this->assertFalse(pfb_extras_process_begin(),
			'before-state: a wedged feed-pass lock must keep reporting the deferral');
		$this->assertStringContainsString('Feed pass [ extras ] skipped', $this->mainLog(),
			'before-state: the run must actually have taken the feed-pass deferral path');
		$this->assertStringNotContainsString('dispatcher lock unavailable', $this->mainLog(),
			'the dispatcher lock WAS acquired on this path');
		$this->assertStringNotContainsString('dispatcher lock', $this->syslogMessages(),
			'the dispatcher lock WAS acquired on this path');
	}
}
