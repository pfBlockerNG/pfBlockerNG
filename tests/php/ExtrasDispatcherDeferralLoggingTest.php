<?php

declare(strict_types=1);

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
 * The deferral must be visible in BOTH places the sibling guards use, and the
 * exit-code semantics must not move (a deferred Extras run got no work, so the verb
 * keeps reporting it):
 *
 *   pfblockerng.inc  pfb_feed_pass_begin()  pfb_logger(logtype 1) + logger(LOG_NOTICE)
 *   pfblockerng_apply.inc:722-726 (#2505)   pfb_logger(logtype 1) + logger(LOG_NOTICE)
 *   pfblockerng_cron.inc:266-270  (#2505)   pfb_logger(logtype 1) + logger(LOG_NOTICE)
 *
 * Rows 1-2 are RED before the fix (the branch is silent). Rows 3-5 are the
 * before-state guards that keep the fix honest and pass on both sides: row 3 pins the
 * unchanged rc=1 wiring shared by `dc` and `dcc`, rows 4-5 pin that nothing new is
 * logged when the dispatcher lock was actually acquired.
 *
 * flock(2) belongs to the open file description, not the process, so the raw fd held
 * here conflicts with the guard's own fopen() inside this one process -- the same
 * mechanism FeedPassLockTest relies on for its contention rows.
 */
final class ExtrasDispatcherDeferralLoggingTest extends TestCase
{
	/** The verb dispatcher whose rc=1 wiring row 3 pins (not loadable off-appliance). */
	private const PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng.php';

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
	// RED rows: a lost dispatcher lock must name itself in both places.
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
			'the deferred Extras run must name WHICH guard stood it down (issue #2592) -- '
			. 'pfblockerng.log held: ' . var_export($this->mainLog(), TRUE));
	}

	/**
	 * Scenario: the same deferral must escape /var/log/pfblockerng.
	 *   Given another process holds the scheduler dispatcher lock
	 *   When  pfb_extras_process_begin() runs
	 *   Then  a LOG_NOTICE syslog line names the Extras feed pass and the dispatcher lock
	 *
	 * Priority is asserted, not just the text: feed-pass parity is specifically
	 * LOG_NOTICE (pfb_feed_pass_begin()), so a LOG_INFO downgrade must fail here.
	 */
	public function testDispatcherDeferralRaisesLogNoticeSyslogLine(): void
	{
		$this->holdDispatcherLock();

		pfb_extras_process_begin();

		$this->assertStringContainsString('Feed pass [ extras ] deferred', $this->syslogMessages(),
			'a wedged dispatcher-lock holder must be visible on syslog, not only in pfblockerng.log '
			. '(issue #2592) -- captured: ' . var_export($GLOBALS['pfb_test_logger_calls'], TRUE));
		$this->assertStringContainsString('dispatcher lock', $this->syslogMessages(),
			'the syslog notice must name the dispatcher lock as the cause');
		$priorities = [];
		foreach ($GLOBALS['pfb_test_logger_calls'] ?? [] as $call) {
			if (str_contains($call['message'], 'dispatcher lock')) {
				$priorities[] = $call['priority'];
			}
		}
		$this->assertContains(LOG_NOTICE, $priorities,
			'the dispatcher-lock deferral notice must be LOG_NOTICE (feed-pass parity) -- got priorities: '
			. var_export($priorities, TRUE));
	}

	// -----------------------------------------------------------------------
	// Guard rows (green before AND after the fix).
	// -----------------------------------------------------------------------

	/**
	 * Scenario: logging the deferral must not change what the verbs report.
	 *   Given another process holds the scheduler dispatcher lock
	 *   Then  pfb_extras_process_begin() returns FALSE
	 *   And   the shared `dc`/`dcc` label still turns that FALSE into exit(1)
	 *
	 * The verb wiring is asserted against the dispatcher's source because
	 * pfblockerng.php is not loadable off-appliance (absolute /usr/local requires
	 * plus pfb_global()'s real /var writes), the same reason
	 * GeoipSwapConsumerGuardTest reads it as text. Both verbs share ONE guard
	 * statement, so this pins the rc for `dc` and `dcc` together.
	 */
	public function testDcAndDccVerbsKeepExitingOneOnDispatcherDeferral(): void
	{
		$this->holdDispatcherLock();
		$this->assertFalse(pfb_extras_process_begin(),
			'the Extras guard must keep returning FALSE -- that FALSE IS the verbs rc=1');

		$source = file_get_contents(self::PHP);
		$this->assertIsString($source, 'test setup: could not read the verb dispatcher');
		$start = strpos($source, "case 'dc':");
		$this->assertIsInt($start, "the `dc` verb label is gone from pfblockerng.php");
		$end = strpos($source, "case 'bu':", $start);
		$this->assertIsInt($end, "the `bu` verb label that bounds the dc/dcc case is gone");
		$region = substr($source, $start, $end - $start);

		$this->assertStringContainsString("case 'dcc':", $region,
			'`dcc` must keep sharing the `dc` label, so one guard covers both verbs');
		$this->assertMatchesRegularExpression(
			'/if \(!\$scheduled && !pfb_extras_process_begin\(\)\) \{\s*exit\(1\);\s*\}/',
			$region,
			'issue #2592 changes observability only: a deferred dc/dcc run got no work, '
			. 'so the verbs must keep exiting 1');
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
			'a granted Extras run must not log a deferral -- pfblockerng.log held: '
			. var_export($this->mainLog(), TRUE));
		$this->assertSame([], $GLOBALS['pfb_test_logger_calls'],
			'a granted Extras run must raise no syslog line -- captured: '
			. var_export($GLOBALS['pfb_test_logger_calls'], TRUE));
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
			'the dispatcher lock WAS acquired on this path -- pfblockerng.log held: '
			. var_export($this->mainLog(), TRUE));
		$this->assertStringNotContainsString('dispatcher lock', $this->syslogMessages(),
			'the dispatcher lock WAS acquired on this path -- captured: '
			. var_export($GLOBALS['pfb_test_logger_calls'], TRUE));
	}
}
