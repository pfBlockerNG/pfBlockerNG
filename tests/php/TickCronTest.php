<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-43 Phase 4 — due-ledger writers and the quarter-hour boundary helper. Core decides when the tick runs (issue #3996), so the
 * tick keeps no due-ledger entry of its own; the ledger library stays for the feed cron's pending-apply flag and the extras.
 *
 * Fixed constants (pre-computed, stable across all runs):
 *   seed='test-seed', job='dcc', jitter_max=82800 (23*3600) ⇒ 78279
 *   seed='test-seed', job='bl',  jitter_max=82800            ⇒ 51070
 */
final class TickCronTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Fixed test constants.
	// -----------------------------------------------------------------------

	/** Per-test seed value — stable across all runs. */
	private const SEED = 'test-seed';

	/** Arbitrary fixed "now" epoch (2025-07-15 00:00:00 UTC). */
	private const NOW = 1752537600;

	/** Daily interval in seconds. */
	private const DAILY = 86400;

	/** 23-hour jitter_max for dcc/bl. */
	private const JITTER_MAX = 82800;

	/** Pre-computed seeded_jitter('dcc', SEED, 82800) = 78279. */
	private const JITTER_DCC = 78279;

	/** Pre-computed seeded_jitter('bl', SEED, 82800) = 51070. */
	private const JITTER_BL = 51070;

	// -----------------------------------------------------------------------
	// Filesystem sandbox for ledger I/O tests.
	// -----------------------------------------------------------------------

	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_tick_test_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	// -----------------------------------------------------------------------
	// Jitter: mark_ran produces non-zero stable jitter for dcc/bl.
	// -----------------------------------------------------------------------

	/**
	 * mark_ran uses non-zero seeded jitter for dcc (23*3600 = 82800 max).
	 *
	 * Ensures the tick never collapses dcc onto one fixed minute: the
	 * ledger entry written by mark_ran must contain a non-zero jitter and
	 * the same jitter on every call (deterministic per install).
	 *
	 * Scenario:
	 *   Background: jitter_max=82800 for dcc.
	 *     Given mark_ran('dcc', 86400, NOW, SEED, 82800) called once.
	 *     When the ledger entry for 'dcc' is read back.
	 *     Then jitter == JITTER_DCC (=78279) > 0 and next_due = NOW + 86400 + JITTER_DCC.
	 */
	public function testDccMarkRanWritesNonZeroJitter(): void
	{
		pfb_due_ledger_mark_ran('dcc', self::DAILY, self::NOW, self::SEED, self::JITTER_MAX, $this->dir);

		$entry = pfb_due_ledger_read_entry('dcc', $this->dir);

		$this->assertNotNull($entry, 'dcc ledger entry must exist after mark_ran');
		$this->assertSame(self::JITTER_DCC, $entry['jitter'],
			"dcc jitter: expected " . self::JITTER_DCC . " got {$entry['jitter']};\n"
			. "  (pre-computed: abs(crc32('test-seed:dcc')) % 82800 + 1 = " . self::JITTER_DCC . ")");
		$this->assertGreaterThan(0, $entry['jitter'],
			'dcc jitter must be > 0 (no stampede)');
		$this->assertSame(self::NOW + self::DAILY + self::JITTER_DCC, $entry['next_due'],
			"dcc next_due: expected " . (self::NOW + self::DAILY + self::JITTER_DCC)
			. " got {$entry['next_due']}");
	}

	/**
	 * mark_ran uses non-zero seeded jitter for bl (same max as dcc).
	 *
	 * Scenario:
	 *   Background: jitter_max=82800 for bl.
	 *     Given mark_ran('bl', 86400, NOW, SEED, 82800) called once.
	 *     When the ledger entry for 'bl' is read back.
	 *     Then jitter == JITTER_BL (=51070) > 0 and differs from dcc jitter.
	 */
	public function testBlMarkRanWritesNonZeroJitterDifferentFromDcc(): void
	{
		pfb_due_ledger_mark_ran('bl', self::DAILY, self::NOW, self::SEED, self::JITTER_MAX, $this->dir);

		$entry = pfb_due_ledger_read_entry('bl', $this->dir);

		$this->assertNotNull($entry, 'bl ledger entry must exist after mark_ran');
		$this->assertSame(self::JITTER_BL, $entry['jitter'],
			"bl jitter: expected " . self::JITTER_BL . " got {$entry['jitter']};\n"
			. "  (pre-computed: abs(crc32('test-seed:bl')) % 82800 + 1 = " . self::JITTER_BL . ")");
		$this->assertGreaterThan(0, $entry['jitter'],
			'bl jitter must be > 0 (no stampede)');
		$this->assertNotSame(self::JITTER_DCC, $entry['jitter'],
			'bl jitter must differ from dcc jitter (independent spread)');
	}

	/**
	 * mark_ran writes jitter = 0 for cron (no jitter on feed sync).
	 *
	 * Scenario:
	 *   Background: jitter_max=0 for cron (feeds run at their exact interval).
	 *     Given mark_ran('cron', 86400, NOW, SEED, 0) called once.
	 *     When the ledger entry for 'cron' is read back.
	 *     Then jitter == 0 and next_due = NOW + 86400.
	 */
	public function testCronMarkRanWritesZeroJitter(): void
	{
		pfb_due_ledger_mark_ran('cron', self::DAILY, self::NOW, self::SEED, 0, $this->dir);

		$entry = pfb_due_ledger_read_entry('cron', $this->dir);

		$this->assertNotNull($entry, 'cron ledger entry must exist after mark_ran');
		$this->assertSame(0, $entry['jitter'],
			"cron jitter: expected 0 (jitter_max=0), got {$entry['jitter']}");
		$this->assertSame(self::NOW + self::DAILY, $entry['next_due'],
			"cron next_due: expected " . (self::NOW + self::DAILY) . " got {$entry['next_due']}");
	}

	// -----------------------------------------------------------------------
	// pfb_next_tick_boundary — the Update page's "Next schedule check".
	//
	// The ADR-43 tick is a star-slash-N minute cron, so the next event is the
	// next minute-of-hour that is a multiple of $tick_min. The Update page used
	// to compute this from the legacy per-feed interval/min/24hour knobs, which
	// described the feed cadence, NOT the tick — so it could show "[ Missing
	// cron task ]" and a wrong time even though the tick was scheduled.
	//
	// Red→green: before this helper existed, calling pfb_next_tick_boundary()
	// raised "Call to undefined function pfb_next_tick_boundary()".
	// -----------------------------------------------------------------------

	/**
	 * The next tick is later in the same hour when one is still ahead.
	 *
	 * Scenario:
	 *   Given a 15-minute tick and the clock at 10:20:00.
	 *   When pfb_next_tick_boundary(15, 10, 20, 0).
	 *   Then the next event is 10:30 with 600 s remaining.
	 */
	public function testNextTickLaterThisHour(): void
	{
		$this->assertSame([10, 30, 600], pfb_next_tick_boundary(15, 10, 20, 0),
			'15-min tick at 10:20:00 must fire next at 10:30 (600 s remaining)');
	}

	/**
	 * The next tick rolls to :00 of the next hour after the last in-hour slot.
	 *
	 * Scenario:
	 *   Given a 15-minute tick (slots :00/:15/:30/:45) and the clock at 10:50:30.
	 *   When pfb_next_tick_boundary(15, 10, 50, 30).
	 *   Then the next event is 11:00 with 570 s remaining (no :60 slot exists).
	 */
	public function testNextTickRollsToNextHour(): void
	{
		$this->assertSame([11, 0, 570], pfb_next_tick_boundary(15, 10, 50, 30),
			'15-min tick at 10:50:30 must roll to 11:00 (570 s remaining)');
	}

	/**
	 * The hour wraps from 23 back to 0 across midnight.
	 *
	 * Scenario:
	 *   Given a 15-minute tick and the clock at 23:50:00.
	 *   When pfb_next_tick_boundary(15, 23, 50, 0).
	 *   Then the next event is 00:00 with 600 s remaining.
	 */
	public function testNextTickWrapsPastMidnight(): void
	{
		$this->assertSame([0, 0, 600], pfb_next_tick_boundary(15, 23, 50, 0),
			'15-min tick at 23:50:00 must wrap to 00:00 (600 s remaining)');
	}

	/**
	 * On an exact boundary the NEXT slot is returned, not the current one.
	 *
	 * Scenario:
	 *   Given a 15-minute tick and the clock at exactly 10:00:00.
	 *   When pfb_next_tick_boundary(15, 10, 0, 0).
	 *   Then the next event is 10:15 (the :00 tick just fired) with 900 s remaining.
	 */
	public function testNextTickAtExactBoundaryReturnsFollowingSlot(): void
	{
		$this->assertSame([10, 15, 900], pfb_next_tick_boundary(15, 10, 0, 0),
			'15-min tick at 10:00:00 must advance to 10:15 (900 s remaining)');
	}

	/**
	 * An interval that does not divide 60 has its discontinuity at the hour edge.
	 *
	 * A 7-minute tick fires at :00,:07,…,:56 then jumps to the next :00 (never
	 * :63), so the gap between :56 and the next :00 is only 4 minutes.
	 *
	 * Scenario:
	 *   Given a 7-minute tick.
	 *   When at 10:50:00 → next is 10:56 (360 s); when at 10:56:00 → rolls to 11:00 (240 s).
	 */
	public function testNextTickNonDivisorInterval(): void
	{
		$this->assertSame([10, 56, 360], pfb_next_tick_boundary(7, 10, 50, 0),
			'7-min tick at 10:50:00 must fire next at 10:56 (360 s remaining)');
		$this->assertSame([11, 0, 240], pfb_next_tick_boundary(7, 10, 56, 0),
			'7-min tick at 10:56:00 must roll to 11:00 (240 s remaining, no :63 slot)');
	}
}
