<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-43 Phase 5 — Apply-on-change + optional quiet-hours window.
 *
 * Tests the pure helpers added in Phase 5:
 *   pfb_quiet_hours_in_window(int $now, string $window): bool
 *   pfb_due_ledger_set_pending(string $job_key, string $ledger_dir): void
 *   pfb_due_ledger_is_pending(string $job_key, string $ledger_dir): bool
 *
 * All functions are defined in pfblockerng_extra.inc. The window-check is
 * clock-injectable via $now; the pending helpers are ledger-backed (filesystem
 * temp dir, cleaned up in tearDown).
 *
 * Coverage mandate (every branch):
 *   pfb_quiet_hours_in_window: no window → TRUE; inside window → TRUE; outside → FALSE;
 *     boundary just-before / at-start / just-before-end / at-end; midnight-wrap;
 *     malformed → TRUE (fail-safe).
 *   pfb_due_ledger_set_pending: sets pending_apply=TRUE; absent entry → created.
 *   pfb_due_ledger_is_pending:  absent = FALSE; after set_pending = TRUE; after
 *     mark_ran (which writes a clean entry) = FALSE.
 *   Interaction: due-outside-window → pending recorded; next tick in-window → pending
 *     cleared by mark_ran; no-change / not-due-and-no-pending → nothing dispatched.
 *
 * Red→green evidence (before Phase 5):
 *   pfb_quiet_hours_in_window()  → "Call to undefined function pfb_quiet_hours_in_window()"
 *   pfb_due_ledger_set_pending() → "Call to undefined function pfb_due_ledger_set_pending()"
 *   pfb_due_ledger_is_pending()  → "Call to undefined function pfb_due_ledger_is_pending()"
 *   PfbConfig::read('gen/pfb_quiet_hours') → InvalidArgumentException (key not registered)
 */
final class QuietHoursApplyTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Constants
	// -----------------------------------------------------------------------

	/**
	 * Epoch for a known local time used across boundary tests.
	 * mktime(2, 30, 0) = local 02:30:00 today (when tests run).
	 * Tests that need a fixed minute (e.g. "just-before 02:00") compute their own.
	 */
	private int $t0230;	// 02:30 local time
	private int $t0200;	// 02:00 local time (window start)
	private int $t0600;	// 06:00 local time (window end)
	private int $t0159;	// 01:59 local time (just before window)
	private int $t0559;	// 05:59 local time (just before window end)
	private int $t1000;	// 10:00 local time (outside window)

	private string $dir;

	protected function setUp(): void
	{
		// Compute fixed epochs for today's date in the local timezone.
		$this->t0230 = mktime(2, 30, 0);
		$this->t0200 = mktime(2,  0, 0);
		$this->t0600 = mktime(6,  0, 0);
		$this->t0159 = mktime(1, 59, 0);
		$this->t0559 = mktime(5, 59, 0);
		$this->t1000 = mktime(10, 0, 0);

		$this->dir = sys_get_temp_dir() . '/pfb_qh_test_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	// -----------------------------------------------------------------------
	// pfb_quiet_hours_in_window — no window
	// -----------------------------------------------------------------------

	/**
	 * Empty window string returns TRUE (apply immediately — the default).
	 *
	 * Scenario:
	 *   Given pfb_quiet_hours = '' (no window configured).
	 *   When pfb_quiet_hours_in_window($now, '').
	 *   Then TRUE (apply immediately; no deferral).
	 *
	 * Red→green: before Phase 5, function did not exist.
	 */
	public function testNoWindowAlwaysInWindow(): void
	{
		$this->assertTrue(
			pfb_quiet_hours_in_window($this->t1000, ''),
			'empty window must always return TRUE (apply immediately)'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_quiet_hours_in_window — inside window
	// -----------------------------------------------------------------------

	/**
	 * Time inside "02:00-06:00" returns TRUE (apply now).
	 *
	 * Scenario:
	 *   Given window = "02:00-06:00", now = 02:30.
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then TRUE (inside window — apply).
	 */
	public function testInsideWindowReturnsTrue(): void
	{
		$this->assertTrue(
			pfb_quiet_hours_in_window($this->t0230, '02:00-06:00'),
			'02:30 must be inside "02:00-06:00" window (apply now)'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_quiet_hours_in_window — outside window
	// -----------------------------------------------------------------------

	/**
	 * Time outside "02:00-06:00" returns FALSE (defer).
	 *
	 * Scenario:
	 *   Given window = "02:00-06:00", now = 10:00.
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then FALSE (outside window — defer).
	 *
	 * Red→green: before Phase 5, function did not exist.
	 */
	public function testOutsideWindowReturnsFalse(): void
	{
		$this->assertFalse(
			pfb_quiet_hours_in_window($this->t1000, '02:00-06:00'),
			'10:00 must be outside "02:00-06:00" window (defer)'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_quiet_hours_in_window — boundary: just before start
	// -----------------------------------------------------------------------

	/**
	 * Time at 01:59 (just before "02:00-06:00" start) returns FALSE.
	 *
	 * Scenario:
	 *   Given window = "02:00-06:00", now = 01:59.
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then FALSE (one minute before window opens).
	 */
	public function testBoundaryJustBeforeStartReturnsFalse(): void
	{
		$this->assertFalse(
			pfb_quiet_hours_in_window($this->t0159, '02:00-06:00'),
			'01:59 must be outside "02:00-06:00" (just before window start)'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_quiet_hours_in_window — boundary: at start
	// -----------------------------------------------------------------------

	/**
	 * Time at exactly 02:00 (window start) returns TRUE.
	 *
	 * Scenario:
	 *   Given window = "02:00-06:00", now = 02:00.
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then TRUE (exactly at the window start edge — inclusive).
	 */
	public function testBoundaryAtStartReturnsTrue(): void
	{
		$this->assertTrue(
			pfb_quiet_hours_in_window($this->t0200, '02:00-06:00'),
			'02:00 must be inside "02:00-06:00" (window start is inclusive)'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_quiet_hours_in_window — boundary: just before end
	// -----------------------------------------------------------------------

	/**
	 * Time at 05:59 (just before "02:00-06:00" end) returns TRUE.
	 *
	 * Scenario:
	 *   Given window = "02:00-06:00", now = 05:59.
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then TRUE (one minute before window closes — still inside).
	 */
	public function testBoundaryJustBeforeEndReturnsTrue(): void
	{
		$this->assertTrue(
			pfb_quiet_hours_in_window($this->t0559, '02:00-06:00'),
			'05:59 must be inside "02:00-06:00" (just before window end)'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_quiet_hours_in_window — boundary: at end (exclusive)
	// -----------------------------------------------------------------------

	/**
	 * Time at exactly 06:00 (window end) returns FALSE (end is exclusive).
	 *
	 * Scenario:
	 *   Given window = "02:00-06:00", now = 06:00.
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then FALSE (exactly at the window end — exclusive).
	 */
	public function testBoundaryAtEndReturnsFalse(): void
	{
		$this->assertFalse(
			pfb_quiet_hours_in_window($this->t0600, '02:00-06:00'),
			'06:00 must be outside "02:00-06:00" (window end is exclusive)'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_quiet_hours_in_window — midnight-wrapping window
	// -----------------------------------------------------------------------

	/**
	 * Time inside a midnight-wrapping window ("23:00-03:00") at 23:30 returns TRUE.
	 *
	 * Scenario:
	 *   Given window = "23:00-03:00", now = 23:30.
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then TRUE (inside the portion of the window that starts before midnight).
	 */
	public function testMidnightWrapInsideBeforeMidnight(): void
	{
		$t2330 = mktime(23, 30, 0);
		$this->assertTrue(
			pfb_quiet_hours_in_window($t2330, '23:00-03:00'),
			'23:30 must be inside "23:00-03:00" wrapping window (pre-midnight portion)'
		);
	}

	/**
	 * Time inside a midnight-wrapping window ("23:00-03:00") at 01:00 returns TRUE.
	 *
	 * Scenario:
	 *   Given window = "23:00-03:00", now = 01:00.
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then TRUE (inside the portion after midnight).
	 */
	public function testMidnightWrapInsideAfterMidnight(): void
	{
		$t0100 = mktime(1, 0, 0);
		$this->assertTrue(
			pfb_quiet_hours_in_window($t0100, '23:00-03:00'),
			'01:00 must be inside "23:00-03:00" wrapping window (post-midnight portion)'
		);
	}

	/**
	 * Time outside a midnight-wrapping window ("23:00-03:00") at 12:00 returns FALSE.
	 *
	 * Scenario:
	 *   Given window = "23:00-03:00", now = 12:00.
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then FALSE (outside both portions of the wrapping window).
	 */
	public function testMidnightWrapOutsideReturnsFalse(): void
	{
		$t1200 = mktime(12, 0, 0);
		$this->assertFalse(
			pfb_quiet_hours_in_window($t1200, '23:00-03:00'),
			'12:00 must be outside "23:00-03:00" wrapping window'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_quiet_hours_in_window — malformed input (fail-safe)
	// -----------------------------------------------------------------------

	/**
	 * Malformed window string returns TRUE (fail-safe: apply immediately).
	 *
	 * Scenario:
	 *   Given window = "not-a-window".
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then TRUE (fail-safe: prefer applying over deferring forever on bad config).
	 */
	public function testMalformedWindowReturnsTrueFailSafe(): void
	{
		$this->assertTrue(
			pfb_quiet_hours_in_window($this->t1000, 'not-a-window'),
			'malformed window must return TRUE (fail-safe: apply immediately)'
		);
	}

	/**
	 * Out-of-range hour (e.g. "25:00-03:00") returns TRUE (fail-safe).
	 *
	 * The regex accepts \d{1,2} for hours, so h=25 passes the pattern but is not a valid
	 * clock hour. Without the bounds check, the function would parse start=1500 (25*60)
	 * which can never match cur (max 1439), deferring applies forever.
	 *
	 * Scenario:
	 *   Given window = "25:00-03:00" (hour 25 is out of range).
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then TRUE (fail-safe: apply immediately, not defer forever).
	 *
	 * Red→green: before the bounds check, the function returned FALSE (start=1500, never matches).
	 */
	public function testOutOfRangeHourReturnsTrueFailSafe(): void
	{
		$this->assertTrue(
			pfb_quiet_hours_in_window($this->t1000, '25:00-03:00'),
			'out-of-range hour (25) must return TRUE (fail-safe: apply immediately, not defer forever)'
		);
	}

	/**
	 * Out-of-range minute (e.g. "10:60-11:00") returns TRUE (fail-safe).
	 *
	 * The regex accepts \d{2} for minutes, so m=60 passes the pattern but is not a valid
	 * minute. Without the bounds check, start=660 (10*60+60) = 11:00 which could produce
	 * a window equal to "11:00-11:00" (zero-width) or silently mis-match.
	 *
	 * Scenario:
	 *   Given window = "10:60-11:00" (minute 60 is out of range).
	 *   When pfb_quiet_hours_in_window($now, $window).
	 *   Then TRUE (fail-safe: apply immediately).
	 *
	 * Red→green: before the bounds check, the function silently mis-calculated the window.
	 */
	public function testOutOfRangeMinuteReturnsTrueFailSafe(): void
	{
		$this->assertTrue(
			pfb_quiet_hours_in_window($this->t1000, '10:60-11:00'),
			'out-of-range minute (60) must return TRUE (fail-safe: apply immediately)'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_due_ledger_set_pending + pfb_due_ledger_is_pending
	// -----------------------------------------------------------------------

	/**
	 * is_pending returns FALSE when no entry exists (nothing deferred yet).
	 *
	 * Scenario:
	 *   Background: ledger absent.
	 *     Given no ledger file exists for 'cron'.
	 *     When pfb_due_ledger_is_pending('cron', $dir).
	 *     Then FALSE (no pending flag).
	 *
	 * Red→green: before Phase 5, pfb_due_ledger_is_pending() did not exist.
	 */
	public function testIsPendingFalseWhenAbsent(): void
	{
		$result = pfb_due_ledger_is_pending('cron', $this->dir);

		$this->assertFalse($result,
			'is_pending must return FALSE when no ledger entry exists'
		);
	}

	/**
	 * set_pending writes pending_apply=TRUE; is_pending returns TRUE.
	 *
	 * Scenario:
	 *   Background: a due job detected outside the apply window.
	 *     Given no prior ledger entry for 'cron'.
	 *     When pfb_due_ledger_set_pending('cron', $dir) is called (deferred).
	 *     Then pfb_due_ledger_is_pending('cron', $dir) returns TRUE.
	 *
	 * Red→green: before Phase 5, pfb_due_ledger_set_pending() did not exist.
	 */
	public function testSetPendingMakesIsPendingTrue(): void
	{
		// Before: not pending.
		$before = pfb_due_ledger_is_pending('cron', $this->dir);
		$this->assertFalse($before, 'before set_pending: is_pending must be FALSE');

		// When: defer the job.
		pfb_due_ledger_set_pending('cron', $this->dir);

		// Then: pending is set.
		$after = pfb_due_ledger_is_pending('cron', $this->dir);
		$this->assertTrue($after,
			'after set_pending: is_pending must be TRUE;\n'
			. '  ledger=' . (file_exists($this->dir . '/pfb_due_ledger.json')
				? file_get_contents($this->dir . '/pfb_due_ledger.json')
				: '<absent>')
		);
	}

	/**
	 * mark_ran clears the pending flag (writes a clean entry without pending_apply).
	 *
	 * Scenario:
	 *   Background: job was deferred (pending=TRUE), then the window opens.
	 *     Given pfb_due_ledger_set_pending('cron', $dir) was called.
	 *     When pfb_due_ledger_mark_ran('cron', 86400, $now, 'seed', 0, $dir) is called
	 *          (job dispatched inside the window).
	 *     Then pfb_due_ledger_is_pending('cron', $dir) returns FALSE (pending cleared).
	 */
	public function testMarkRanClearsPendingFlag(): void
	{
		$now = mktime(3, 0, 0);	// inside any reasonable window

		// Given: pending.
		pfb_due_ledger_set_pending('cron', $this->dir);
		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dir),
			'precondition: pending must be TRUE before mark_ran'
		);

		// When: job dispatches (mark_ran writes a clean entry).
		pfb_due_ledger_mark_ran('cron', 86400, $now, 'test-seed', 0, $this->dir);

		// Then: pending is cleared.
		$cleared = pfb_due_ledger_is_pending('cron', $this->dir);
		$this->assertFalse($cleared,
			'after mark_ran: is_pending must be FALSE (clean entry has no pending_apply);\n'
			. '  ledger=' . (file_exists($this->dir . '/pfb_due_ledger.json')
				? file_get_contents($this->dir . '/pfb_due_ledger.json')
				: '<absent>')
		);
	}

	// -----------------------------------------------------------------------
	// Interaction: due outside window → pending; next tick inside → dispatched
	// -----------------------------------------------------------------------

	/**
	 * Simulates the full defer → apply lifecycle:
	 *   tick 1 (outside window): job is due + outside window → set_pending, no dispatch.
	 *   tick 2 (inside window):  job is pending + inside window → dispatch + mark_ran.
	 *
	 * This is the integration test that proves the apply-on-change contract (#9):
	 *   "A detected change is deferred (pending recorded); the first tick inside
	 *    the window applies it."
	 *
	 * Scenario:
	 *   Background: window = "02:00-06:00".
	 *     Given a due job (cron) with no prior ledger entry.
	 *     And now = 10:00 (outside window).
	 *   When tick 1 evaluates the job:
	 *     Then pending_apply is recorded (is_pending = TRUE).
	 *     And mark_ran is NOT called (next_due unchanged = past, still due).
	 *   When tick 2 evaluates at now = 03:00 (inside window):
	 *     Then is_pending was TRUE before mark_ran.
	 *     And mark_ran IS called (next_due advances to future).
	 *     And is_pending = FALSE after mark_ran.
	 *
	 * Red→green: before Phase 5, set_pending/is_pending didn't exist.
	 */
	public function testDeferredOutsideWindowThenAppliedInsideWindow(): void
	{
		$window   = '02:00-06:00';
		$t_out    = mktime(10, 0, 0);	// outside window
		$t_in     = mktime(3,  0, 0);	// inside window

		// --- Tick 1: outside window, job is due ---
		$in_win_1 = pfb_quiet_hours_in_window($t_out, $window);
		$this->assertFalse($in_win_1,
			'tick 1: 10:00 must be outside "02:00-06:00" (deferred path)'
		);

		// Simulate tick logic: job is due (ledger absent → due), outside window → set_pending.
		$due_1 = pfb_due_ledger_is_due('cron', 86400, $t_out, 'seed', 0, $this->dir);
		$this->assertTrue($due_1, 'tick 1: absent ledger → job is due');

		if (!$in_win_1) {
			pfb_due_ledger_set_pending('cron', $this->dir);
			// No mark_ran: job remains due on the next tick.
		}

		$pending_after_tick1 = pfb_due_ledger_is_pending('cron', $this->dir);
		$this->assertTrue($pending_after_tick1,
			'after tick 1 (deferred): pending_apply must be TRUE;\n'
			. '  ledger=' . (file_exists($this->dir . '/pfb_due_ledger.json')
				? file_get_contents($this->dir . '/pfb_due_ledger.json')
				: '<absent>')
		);

		// --- Tick 2: inside window ---
		$in_win_2 = pfb_quiet_hours_in_window($t_in, $window);
		$this->assertTrue($in_win_2,
			'tick 2: 03:00 must be inside "02:00-06:00" (apply path)'
		);

		// Job is still due (mark_ran wasn't called in tick 1).
		$due_2 = pfb_due_ledger_is_due('cron', 86400, $t_in, 'seed', 0, $this->dir);
		$this->assertTrue($due_2, 'tick 2: job must still be due (mark_ran not called in tick 1)');

		$pending_before_dispatch = pfb_due_ledger_is_pending('cron', $this->dir);
		$this->assertTrue($pending_before_dispatch,
			'tick 2 before dispatch: pending must still be TRUE'
		);

		// Simulate dispatch: mark_ran (clears pending).
		pfb_due_ledger_mark_ran('cron', 86400, $t_in, 'seed', 0, $this->dir);

		$pending_after_dispatch = pfb_due_ledger_is_pending('cron', $this->dir);
		$this->assertFalse($pending_after_dispatch,
			'after tick 2 dispatch: pending must be FALSE (cleared by mark_ran);\n'
			. '  ledger=' . (file_exists($this->dir . '/pfb_due_ledger.json')
				? file_get_contents($this->dir . '/pfb_due_ledger.json')
				: '<absent>')
		);

		// Job is no longer due (next_due now in the future).
		$due_3 = pfb_due_ledger_is_due('cron', 86400, $t_in, 'seed', 0, $this->dir);
		$this->assertFalse($due_3,
			'after tick 2 dispatch: job must not be due again (next_due in future)'
		);
	}

	/**
	 * A job NOT due and NOT pending does nothing (no-change / no-apply).
	 *
	 * Scenario:
	 *   Background: job has next_due in the future (already ran recently).
	 *     Given a ledger entry with next_due = now + 1 hour.
	 *     And now = inside window.
	 *   When the tick evaluates (due=FALSE, pending=FALSE).
	 *   Then neither pending is set nor mark_ran called.
	 *
	 * This is the regression guard: no change ⇒ no apply.
	 */
	public function testNotDueNotPendingNoApply(): void
	{
		$t_in = mktime(3, 0, 0);

		// Pre-seed: job ran recently, next_due in the future.
		pfb_due_ledger_write_entry('cron', [
			'last_run' => $t_in - 3600,
			'next_due' => $t_in + 3600,
			'jitter'   => 0,
		], $this->dir);

		$due     = pfb_due_ledger_is_due('cron', 86400, $t_in, 'seed', 0, $this->dir);
		$pending = pfb_due_ledger_is_pending('cron', $this->dir);
		$in_win  = pfb_quiet_hours_in_window($t_in, '02:00-06:00');

		$this->assertFalse($due,
			'not-due-not-pending: job must not be due (next_due in future)'
		);
		$this->assertFalse($pending,
			'not-due-not-pending: pending must be FALSE (no set_pending called)'
		);

		// Neither condition met → no dispatch (verified by asserting no ledger change).
		if (!$due && !$pending) {
			// Tick takes no action for this job.
			$no_action = TRUE;
		}

		$this->assertTrue($no_action ?? FALSE,
			'not-due-not-pending: tick must take no action for this job'
		);

		$entry_after = pfb_due_ledger_read_entry('cron', $this->dir);
		$this->assertNotNull($entry_after);
		$this->assertSame($t_in + 3600, $entry_after['next_due'],
			'not-due-not-pending: ledger entry must be unchanged (no dispatch, no pending set)'
		);
	}
}
