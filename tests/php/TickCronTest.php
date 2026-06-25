<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-43 Phase 4 — Due-ledger trigger-tick helpers.
 *
 * Tests the two pure helpers added in Phase 4:
 *   pfb_tick_seed(): string
 *   pfb_tick_due_jobs(int $now, string $seed, string $dbdir,
 *                     int $cron_interval, int $bl_interval): array<string,bool>
 *
 * These functions are defined in pfblockerng_extra.inc (alongside the Phase-2
 * ledger library) and are injectable (clock + seed) so tests are deterministic.
 *
 * Coverage mandate (every branch):
 *   pfb_tick_seed:    returns a non-empty string; identical across calls.
 *   pfb_tick_due_jobs absent ledger:   all jobs due (fail-safe).
 *   pfb_tick_due_jobs future next_due: no jobs due.
 *   pfb_tick_due_jobs past next_due:   due jobs only for past entries (catch-up).
 *   pfb_tick_due_jobs jitter non-zero: mark_ran writes non-zero jitter for dcc/bl.
 *
 * Red→green evidence (pre-change, calling these functions caused
 * "Call to undefined function pfb_tick_seed()" / "pfb_tick_due_jobs()").
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

	/** 23-hour jitter_max used by pfb_tick_due_jobs() for dcc/bl. */
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
		@unlink($this->dir . '/pfb_due_ledger.json');
		@unlink($this->dir . '/pfb_due_ledger.json.tmp');
		@rmdir($this->dir);
	}

	// -----------------------------------------------------------------------
	// pfb_tick_seed — pure, no I/O.
	// -----------------------------------------------------------------------

	/**
	 * pfb_tick_seed returns a non-empty string.
	 *
	 * Scenario:
	 *   When pfb_tick_seed() is called.
	 *   Then a non-empty string is returned.
	 */
	public function testTickSeedIsNonEmpty(): void
	{
		$seed = pfb_tick_seed();

		$this->assertIsString($seed,   'pfb_tick_seed() must return a string');
		$this->assertNotEmpty($seed,   'pfb_tick_seed() must return a non-empty string');
	}

	/**
	 * pfb_tick_seed returns the same value on repeated calls (stable per install).
	 *
	 * Scenario:
	 *   When pfb_tick_seed() is called twice.
	 *   Then both calls return the same value.
	 */
	public function testTickSeedIsStable(): void
	{
		$s1 = pfb_tick_seed();
		$s2 = pfb_tick_seed();

		$this->assertSame($s1, $s2, 'pfb_tick_seed() must return the same value on every call');
	}

	// -----------------------------------------------------------------------
	// pfb_tick_due_jobs — absent ledger ⇒ all jobs due (fail-safe).
	// -----------------------------------------------------------------------

	/**
	 * All three jobs are due when the ledger is absent (first boot / wiped).
	 *
	 * Scenario:
	 *   Background: ledger absent (dir is empty).
	 *     Given an empty ledger directory.
	 *     When pfb_tick_due_jobs($now, $seed, $dir, $cron_interval, $bl_interval).
	 *     Then cron, dcc, bl are all TRUE (fail-safe: run now, jitter on mark_ran).
	 */
	public function testAllDueWhenLedgerAbsent(): void
	{
		$due = pfb_tick_due_jobs(self::NOW, self::SEED, $this->dir, self::DAILY, self::DAILY);

		$this->assertTrue($due['cron'],
			"cron: expected TRUE (absent ledger => due-now), got FALSE;\n"
			. "  now=" . self::NOW . " dir={$this->dir}");
		$this->assertTrue($due['dcc'],
			"dcc: expected TRUE (absent ledger => due-now), got FALSE;\n"
			. "  now=" . self::NOW . " dir={$this->dir}");
		$this->assertTrue($due['bl'],
			"bl: expected TRUE (absent ledger => due-now), got FALSE;\n"
			. "  now=" . self::NOW . " dir={$this->dir}");
	}

	// -----------------------------------------------------------------------
	// pfb_tick_due_jobs — future next_due ⇒ no jobs due.
	// -----------------------------------------------------------------------

	/**
	 * No jobs are due when all ledger entries have next_due in the future.
	 *
	 * Scenario:
	 *   Background: all jobs have next_due = now + 1 hour.
	 *     Given ledger entries with next_due > now for cron, dcc, bl.
	 *     When pfb_tick_due_jobs($now, ...).
	 *     Then cron, dcc, bl are all FALSE (not yet due).
	 */
	public function testNoneDueWhenAllFuture(): void
	{
		$future = self::NOW + 3600;
		foreach (['cron', 'dcc', 'bl'] as $job) {
			pfb_due_ledger_write_entry($job, [
				'last_run' => self::NOW - self::DAILY,
				'next_due' => $future,
				'jitter'   => 0,
			], $this->dir);
		}

		$due = pfb_tick_due_jobs(self::NOW, self::SEED, $this->dir, self::DAILY, self::DAILY);

		$this->assertFalse($due['cron'],
			"cron: expected FALSE (next_due in future), got TRUE;\n"
			. "  now=" . self::NOW . " next_due={$future}");
		$this->assertFalse($due['dcc'],
			"dcc: expected FALSE (next_due in future), got TRUE;\n"
			. "  now=" . self::NOW . " next_due={$future}");
		$this->assertFalse($due['bl'],
			"bl: expected FALSE (next_due in future), got TRUE;\n"
			. "  now=" . self::NOW . " next_due={$future}");
	}

	// -----------------------------------------------------------------------
	// pfb_tick_due_jobs — catch-up: only past next_due is due.
	// -----------------------------------------------------------------------

	/**
	 * Only cron is due when its next_due is in the past; dcc/bl are in the future.
	 *
	 * Scenario:
	 *   Background: cron is overdue; dcc and bl are not yet due.
	 *     Given cron.next_due = now - 1 (past); dcc/bl.next_due = now + 1h (future).
	 *     When pfb_tick_due_jobs($now, ...).
	 *     Then cron = TRUE, dcc = FALSE, bl = FALSE (catch-up for cron only).
	 */
	public function testOnlyCronDueWhenOnlyCronPast(): void
	{
		// cron is overdue.
		pfb_due_ledger_write_entry('cron', [
			'last_run' => self::NOW - self::DAILY - 1,
			'next_due' => self::NOW - 1,
			'jitter'   => 0,
		], $this->dir);

		// dcc and bl are not yet due.
		$future = self::NOW + 3600;
		foreach (['dcc', 'bl'] as $job) {
			pfb_due_ledger_write_entry($job, [
				'last_run' => self::NOW - self::DAILY,
				'next_due' => $future,
				'jitter'   => 0,
			], $this->dir);
		}

		$due = pfb_tick_due_jobs(self::NOW, self::SEED, $this->dir, self::DAILY, self::DAILY);

		$this->assertTrue($due['cron'],
			"cron: expected TRUE (next_due in past = catch-up), got FALSE;\n"
			. "  now=" . self::NOW . " next_due=" . (self::NOW - 1));
		$this->assertFalse($due['dcc'],
			"dcc: expected FALSE (next_due in future), got TRUE;\n"
			. "  now=" . self::NOW . " next_due={$future}");
		$this->assertFalse($due['bl'],
			"bl: expected FALSE (next_due in future), got TRUE;\n"
			. "  now=" . self::NOW . " next_due={$future}");
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
}
