<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_livetail_force_done — the Run-Now livetail terminator decision (pfb_livetail's
 * non-'view' 'force' mode, used by every Update-page run + the Force-check).
 *
 * The Update-page live tail now ends when the dispatched feed PROCESS exits, not when
 * an 'UPDATE PROCESS ENDED' log line appears: a crash/abort that never wrote that marker
 * used to loop the tail forever. The loop streams the log every cycle regardless of this
 * decision (output is never delayed); the startup grace bounds ONLY the silent dead-launch
 * case (never seen running AND no output), never a run that produced output. This pins the
 * decision across every branch.
 *
 * Red→green: pfb_livetail_force_done() does not exist before the change, so every case
 * fatals with "undefined function"; green after.
 */
#[CoversFunction('pfb_livetail_force_done')]
final class LivetailForceDoneTest extends TestCase
{
	/**
	 * While the dispatched task is running, keep tailing AND latch that we saw it.
	 */
	public function testRunningKeepsTailingAndLatchesSeen(): void
	{
		// Given a fresh tail that has not yet seen the task
		$seen   = FALSE;
		$cycles = 0;

		// When the task is observed running (no output yet)
		$done = pfb_livetail_force_done(TRUE, FALSE, $seen, $cycles, 33);

		// Then the tail continues, the "seen" latch is set, and the grace counter is untouched
		$this->assertFalse($done, 'tail must continue while the task is running');
		$this->assertTrue($seen, 'observing the task running must latch $seen');
		$this->assertSame(0, $cycles, 'the startup-grace counter must not advance once the task is running');
	}

	/**
	 * Once the task has been seen running and is now gone, the tail stops — the normal
	 * completion path (the dispatched process exited).
	 */
	public function testSeenThenGoneStops(): void
	{
		// Given a tail that has already seen the task running
		$seen   = TRUE;
		$cycles = 0;

		// When the task is no longer running (output state is irrelevant once seen)
		$done = pfb_livetail_force_done(FALSE, FALSE, $seen, $cycles, 33);

		// Then the tail stops at once, independent of the grace counter
		$this->assertTrue($done, 'tail must stop once a previously-running task has exited');
		$this->assertSame(0, $cycles, 'a seen->gone stop must not consume the startup-grace counter');
	}

	/**
	 * A task we never sampled in ps but that HAS produced output has clearly finished once
	 * it is gone — stop immediately, do NOT wait out the grace (so a fast pass that wrote
	 * output is never held for ~10s before the tail ends).
	 */
	public function testOutputSeenStopsImmediatelyEvenIfNeverSampledRunning(): void
	{
		// Given a tail that never sampled the task as running
		$seen   = FALSE;
		$cycles = 0;

		// When the task is not running but output has already registered
		$done = pfb_livetail_force_done(FALSE, TRUE, $seen, $cycles, 33);

		// Then the tail stops at once without consuming the grace
		$this->assertTrue($done, 'output already registered + task gone must end the tail immediately');
		$this->assertSame(0, $cycles, 'an output-driven stop must not consume the startup-grace counter');
	}

	/**
	 * Before the task is ever seen AND with no output yet, the tail keeps waiting (within
	 * the grace) so the mwexec_bg launch lag never stops the tail prematurely.
	 */
	public function testNeverSeenNoOutputWithinGraceKeepsWaiting(): void
	{
		// Given a tail that has not seen the task, no output, grace of 3 cycles
		$seen   = FALSE;
		$cycles = 0;
		$grace  = 3;

		// When the task is not (yet) running and nothing has been written on the sub-grace cycles
		$this->assertFalse(pfb_livetail_force_done(FALSE, FALSE, $seen, $cycles, $grace), 'cycle 1 within grace must keep waiting');
		$this->assertSame(1, $cycles);
		$this->assertFalse(pfb_livetail_force_done(FALSE, FALSE, $seen, $cycles, $grace), 'cycle 2 within grace must keep waiting');
		$this->assertSame(2, $cycles);

		// Then it has not stopped and has not falsely latched "seen"
		$this->assertFalse($seen, 'never observing the task must not latch $seen');
	}

	/**
	 * If the task never appears AND never writes anything within the grace (a failed
	 * mwexec_bg launch), the tail gives up rather than looping forever.
	 */
	public function testNeverSeenNoOutputGraceExhaustedStops(): void
	{
		// Given a tail with a 3-cycle grace that never sees the task and gets no output
		$seen   = FALSE;
		$cycles = 0;
		$grace  = 3;

		// When the grace is consumed cycle by cycle
		$this->assertFalse(pfb_livetail_force_done(FALSE, FALSE, $seen, $cycles, $grace)); // cycles -> 1
		$this->assertFalse(pfb_livetail_force_done(FALSE, FALSE, $seen, $cycles, $grace)); // cycles -> 2

		// Then the cycle that reaches the grace bound stops the tail
		$this->assertTrue(
			pfb_livetail_force_done(FALSE, FALSE, $seen, $cycles, $grace), // cycles -> 3 >= 3
			'reaching the startup grace on a silent dead launch must stop the tail'
		);
		$this->assertSame(3, $cycles);
	}
}
