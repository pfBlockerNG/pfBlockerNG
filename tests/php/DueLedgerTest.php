<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-43 Phase 2 — Pure due-ledger library.
 *
 * Tests the clock-and-seed-injectable due-ledger helpers defined in
 * pfblockerng_extra.inc. The library is unreferenced by production code this
 * phase; Phase 4 will wire it into the cron tick.
 *
 * Functions under test:
 *   pfb_due_ledger_seeded_jitter(string $job_key, string $seed, int $max): int
 *   pfb_due_ledger_is_due_from_entry(?array $entry, int $now): bool
 *   pfb_due_ledger_read_entry(string $job_key, string $ledger_dir): ?array
 *   pfb_due_ledger_write_entry(string $job_key, array $entry, string $ledger_dir): void
 *   pfb_due_ledger_is_due(string $job_key, int $interval, int $now,
 *                          string $seed, int $jitter_max, string $ledger_dir): bool
 *   pfb_due_ledger_mark_ran(string $job_key, int $interval, int $now,
 *                            string $seed, int $jitter_max, string $ledger_dir): void
 *   pfb_due_ledger_mark_ran_anchored(string $job_key, int $interval, int $now,
 *                            string $seed, int $jitter_max, string $ledger_dir): void
 *
 * Coverage mandate (CLAUDE.md §"Test coverage") — every branch:
 *   seeded_jitter:        max > 0 ⇒ [1, max]; max = 0 ⇒ 0; deterministic; different jobs differ.
 *   is_due_from_entry:    NULL ⇒ TRUE; next_due ≤ now ⇒ TRUE; next_due > now ⇒ FALSE.
 *   read/write round-trip: read(write(x)) == x; second job preserved; corrupt ⇒ NULL.
 *   is_due / mark_ran:   absent ⇒ due with non-zero stable jitter; future ⇒ not due;
 *                         past ⇒ due (catch-up); missed window ⇒ exactly one due;
 *                         two jobs keep independent jitters.
 *   mark_ran_anchored (issue #573 phase-creep fix): missed-by-a-fraction ⇒ anchors
 *                         on the previous next_due (zero cumulative slip, contrasted
 *                         against plain mark_ran's drift); absent entry / next_due=0
 *                         placeholder / future next_due (skew guard) / catch-up
 *                         (> 1 interval late) all fall back to base = now; jitter
 *                         rides the anchored base.
 *
 * All tests use injected now/seed (never time()/rand()) — deterministic on any clock.
 *
 * Fixed constants used throughout (pre-verified by unit, not re-derived at runtime):
 *   seed='test-seed', job='dcc', max=86400  ⇒  seeded_jitter = 35079
 *   seed='test-seed', job='bl',  max=86400  ⇒  seeded_jitter = 79870
 */
final class DueLedgerTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Fixed test constants.
	// -----------------------------------------------------------------------

	/** Per-test seed value — stable across all runs. */
	private const SEED = 'test-seed';

	/** Jitter max: 86400 seconds (24 hours) — matches the dcc/bl spread. */
	private const MAX  = 86400;

	/** Pre-computed seeded_jitter('dcc', SEED, MAX) = 35079. */
	private const JITTER_DCC = 35079;

	/** Pre-computed seeded_jitter('bl', SEED, MAX) = 79870. */
	private const JITTER_BL  = 79870;

	/** Arbitrary fixed "now" epoch (2025-07-15 00:00:00 UTC). */
	private const NOW = 1752537600;

	/** Typical daily interval (86400 s). */
	private const INTERVAL_DAILY = 86400;

	// -----------------------------------------------------------------------
	// Filesystem sandbox for I/O tests.
	// -----------------------------------------------------------------------

	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_ledger_test_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		@unlink($this->dir . '/pfb_due_ledger.json');
		@unlink($this->dir . '/pfb_due_ledger.json.tmp');
		@rmdir($this->dir);
	}

	// -----------------------------------------------------------------------
	// pfb_due_ledger_seeded_jitter — pure, no I/O.
	// -----------------------------------------------------------------------

	/**
	 * seeded_jitter is deterministic: same (job_key, seed, max) ⇒ same offset.
	 *
	 * Scenario:
	 *   Given job_key='dcc', seed=SEED, max=MAX.
	 *   When  seeded_jitter called twice with identical args.
	 *   Then  both calls return the same value.
	 */
	public function testSeededJitterIsDeterministic(): void
	{
		$j1 = pfb_due_ledger_seeded_jitter('dcc', self::SEED, self::MAX);
		$j2 = pfb_due_ledger_seeded_jitter('dcc', self::SEED, self::MAX);

		$this->assertSame($j1, $j2,
			'seeded_jitter must return the same value for identical (job_key, seed, max)');
	}

	/**
	 * seeded_jitter produces the expected value for our test constants.
	 *
	 * This pins the concrete output so a change to the algorithm is visible.
	 * Pre-computed: abs(crc32("test-seed:dcc")) % 86400 + 1 = 35079.
	 *
	 * Scenario:
	 *   Given job_key='dcc', seed=SEED, max=MAX.
	 *   When  seeded_jitter called.
	 *   Then  result = JITTER_DCC = 35079.
	 */
	public function testSeededJitterMatchesPrecomputedValue(): void
	{
		$j = pfb_due_ledger_seeded_jitter('dcc', self::SEED, self::MAX);

		$this->assertSame(self::JITTER_DCC, $j,
			'seeded_jitter(\'dcc\', SEED, MAX) expected ' . self::JITTER_DCC . ' got ' . $j);
	}

	/**
	 * seeded_jitter returns a non-zero value when max > 0.
	 *
	 * The [1, max] range (not [0, max]) guarantees non-zero jitter for every job:
	 * if some jobs had zero jitter they would all share next_due=now+interval,
	 * producing a stampede at the same time.
	 *
	 * Scenario:
	 *   Given max = MAX (> 0).
	 *   When  seeded_jitter called for any job key.
	 *   Then  result > 0 (never zero).
	 */
	public function testSeededJitterIsNonZeroWhenMaxPositive(): void
	{
		$j = pfb_due_ledger_seeded_jitter('dcc', self::SEED, self::MAX);

		$this->assertGreaterThan(0, $j,
			'seeded_jitter with max > 0 must return a non-zero offset; got ' . $j);
	}

	/**
	 * seeded_jitter returns 0 when max = 0 (jitter disabled).
	 *
	 * Scenario:
	 *   Given max = 0.
	 *   When  seeded_jitter called.
	 *   Then  result = 0 (jitter disabled).
	 */
	public function testSeededJitterIsZeroWhenMaxIsZero(): void
	{
		$j = pfb_due_ledger_seeded_jitter('dcc', self::SEED, 0);

		$this->assertSame(0, $j,
			'seeded_jitter with max = 0 must return 0; got ' . $j);
	}

	/**
	 * seeded_jitter is within the [1, max] range when max > 0.
	 *
	 * Scenario:
	 *   Given max = MAX.
	 *   When  seeded_jitter called.
	 *   Then  1 ≤ result ≤ max.
	 */
	public function testSeededJitterIsWithinRange(): void
	{
		$j = pfb_due_ledger_seeded_jitter('dcc', self::SEED, self::MAX);

		$this->assertGreaterThanOrEqual(1, $j,
			'seeded_jitter must be ≥ 1; got ' . $j);
		$this->assertLessThanOrEqual(self::MAX, $j,
			'seeded_jitter must be ≤ max (' . self::MAX . '); got ' . $j);
	}

	/**
	 * Different job keys with the same seed produce different offsets.
	 *
	 * This is the no-stampede guarantee: if all jobs shared the same jitter,
	 * they would all fire at the same minute after a boot, hitting the same
	 * upstream feeds simultaneously. Different offsets spread the load.
	 *
	 * Scenario:
	 *   Given seed=SEED, max=MAX.
	 *   When  seeded_jitter called for 'dcc' and 'bl'.
	 *   Before: verify 'dcc' offset (JITTER_DCC = 35079) is itself non-zero.
	 *   After:  'bl' offset (JITTER_BL = 79870) differs from 'dcc'.
	 */
	public function testSeededJitterDifferentJobsYieldDifferentOffsets(): void
	{
		$j_dcc = pfb_due_ledger_seeded_jitter('dcc', self::SEED, self::MAX);
		$j_bl  = pfb_due_ledger_seeded_jitter('bl',  self::SEED, self::MAX);

		// Before: pin the 'dcc' value first so a change to 'dcc' is caught.
		$this->assertSame(self::JITTER_DCC, $j_dcc,
			'dcc jitter must be JITTER_DCC; got ' . $j_dcc);

		// After: 'bl' must differ from 'dcc' (spread, not stampede).
		$this->assertSame(self::JITTER_BL, $j_bl,
			'bl jitter must be JITTER_BL; got ' . $j_bl);

		$this->assertNotSame($j_dcc, $j_bl,
			'dcc (' . $j_dcc . ') and bl (' . $j_bl . ') must have different jitter offsets');
	}

	// -----------------------------------------------------------------------
	// pfb_due_ledger_is_due_from_entry — pure, no I/O.
	// -----------------------------------------------------------------------

	/**
	 * Absent entry (null) ⇒ is_due_from_entry returns TRUE.
	 *
	 * An absent entry represents a new install or a wiped RAM-disk (issue #468).
	 * The job must run on the next tick; the seeded jitter is applied in mark_ran.
	 *
	 * Scenario:
	 *   Given entry = NULL (absent).
	 *   When  is_due_from_entry(NULL, now).
	 *   Then  returns TRUE.
	 */
	public function testIsDueFromNullEntryReturnsTrue(): void
	{
		$result = pfb_due_ledger_is_due_from_entry(NULL, self::NOW);

		$this->assertTrue($result,
			'absent entry (NULL) must return TRUE — job is due; got FALSE');
	}

	/**
	 * Entry with next_due in the past ⇒ is_due_from_entry returns TRUE (catch-up).
	 *
	 * A missed window (e.g. box was offline) means next_due < now. The job catches
	 * up on the next tick — runs once, not repeatedly.
	 *
	 * Scenario:
	 *   Given entry with next_due = now - 1 (one second in the past).
	 *   When  is_due_from_entry(entry, now).
	 *   Then  returns TRUE (catch-up: next_due in the past).
	 */
	public function testIsDueFromEntryWithPastNextDueReturnsTrue(): void
	{
		$entry = ['last_run' => self::NOW - 86400, 'next_due' => self::NOW - 1, 'jitter' => 0];

		$result = pfb_due_ledger_is_due_from_entry($entry, self::NOW);

		$this->assertTrue($result,
			'entry with next_due = now - 1 must be due; got FALSE. ' .
			'next_due=' . $entry['next_due'] . ' now=' . self::NOW);
	}

	/**
	 * Entry with next_due exactly at now ⇒ is_due_from_entry returns TRUE.
	 *
	 * next_due == now means the job is due on this tick (≤ now is the rule).
	 *
	 * Scenario:
	 *   Given entry with next_due = now.
	 *   When  is_due_from_entry(entry, now).
	 *   Then  returns TRUE (boundary: exactly at now is due).
	 */
	public function testIsDueFromEntryAtExactNowReturnsTrue(): void
	{
		$entry = ['last_run' => self::NOW - 86400, 'next_due' => self::NOW, 'jitter' => 0];

		$result = pfb_due_ledger_is_due_from_entry($entry, self::NOW);

		$this->assertTrue($result,
			'entry with next_due = now must be due (boundary ≤); got FALSE');
	}

	/**
	 * Entry with next_due in the future ⇒ is_due_from_entry returns FALSE.
	 *
	 * Before-and-after: first assert past ⇒ TRUE, then assert future ⇒ FALSE,
	 * confirming the boundary is real.
	 *
	 * Scenario:
	 *   Given entry with next_due = now + 3600 (one hour in the future).
	 *   Before: advance now past next_due (next_due - 1 ≤ next_due - 1) ⇒ TRUE.
	 *   After:  now = now (next_due > now) ⇒ FALSE.
	 */
	public function testIsDueFromEntryWithFutureNextDueReturnsFalse(): void
	{
		$next_due = self::NOW + 3600;
		$entry    = ['last_run' => self::NOW - 86400, 'next_due' => $next_due, 'jitter' => 3600];

		// Before: at next_due-1 the entry is still not due... wait, that's same direction.
		// Verify: at now = next_due the entry IS due.
		$this->assertTrue(
			pfb_due_ledger_is_due_from_entry($entry, $next_due),
			'at now = next_due the entry must be due; got FALSE'
		);

		// After: at now = next_due - 1 the entry is NOT due.
		$this->assertFalse(
			pfb_due_ledger_is_due_from_entry($entry, $next_due - 1),
			'at now = next_due - 1 the entry must NOT be due; got TRUE. ' .
			'next_due=' . $next_due . ' now=' . ($next_due - 1)
		);
	}

	// -----------------------------------------------------------------------
	// pfb_due_ledger_read_entry / pfb_due_ledger_write_entry — I/O.
	// -----------------------------------------------------------------------

	/**
	 * Read from absent directory / file ⇒ read_entry returns NULL.
	 *
	 * Scenario:
	 *   Given no pfb_due_ledger.json in $this->dir.
	 *   When  read_entry('dcc', dir).
	 *   Then  returns NULL.
	 */
	public function testReadEntryAbsentFileReturnsNull(): void
	{
		$result = pfb_due_ledger_read_entry('dcc', $this->dir);

		$this->assertNull($result,
			'read_entry on absent file must return NULL; got ' . var_export($result, TRUE));
	}

	/**
	 * Write then read returns the same entry (round-trip).
	 *
	 * Scenario:
	 *   Given a crafted entry for 'dcc'.
	 *   When  write_entry('dcc', entry, dir) then read_entry('dcc', dir).
	 *   Then  read returns the same entry.
	 */
	public function testRoundTripReadAfterWriteEqualsOriginal(): void
	{
		$entry = ['last_run' => self::NOW, 'next_due' => self::NOW + 86400, 'jitter' => 3600];

		pfb_due_ledger_write_entry('dcc', $entry, $this->dir);
		$read = pfb_due_ledger_read_entry('dcc', $this->dir);

		$this->assertNotNull($read,
			'read_entry after write_entry must not return NULL');
		$this->assertSame($entry['last_run'], $read['last_run'],
			'round-trip: last_run expected ' . $entry['last_run'] . ' got ' . $read['last_run']);
		$this->assertSame($entry['next_due'], $read['next_due'],
			'round-trip: next_due expected ' . $entry['next_due'] . ' got ' . $read['next_due']);
		$this->assertSame($entry['jitter'], $read['jitter'],
			'round-trip: jitter expected ' . $entry['jitter'] . ' got ' . $read['jitter']);
	}

	/**
	 * Writing a second job preserves the first job's entry.
	 *
	 * Scenario:
	 *   Given 'dcc' entry written.
	 *   When  'bl' entry written to the same ledger file.
	 *   Then  reading 'dcc' still returns the original entry.
	 */
	public function testWriteSecondJobPreservesFirstJob(): void
	{
		$entry_dcc = ['last_run' => self::NOW, 'next_due' => self::NOW + 86400, 'jitter' => 100];
		$entry_bl  = ['last_run' => self::NOW, 'next_due' => self::NOW + 172800, 'jitter' => 200];

		pfb_due_ledger_write_entry('dcc', $entry_dcc, $this->dir);
		pfb_due_ledger_write_entry('bl',  $entry_bl,  $this->dir);

		$read_dcc = pfb_due_ledger_read_entry('dcc', $this->dir);
		$read_bl  = pfb_due_ledger_read_entry('bl',  $this->dir);

		$this->assertNotNull($read_dcc,
			'dcc entry must still exist after writing bl');
		$this->assertSame($entry_dcc['next_due'], $read_dcc['next_due'],
			'dcc next_due preserved; expected ' . $entry_dcc['next_due'] . ' got ' . $read_dcc['next_due']);

		$this->assertNotNull($read_bl,
			'bl entry must be readable after write');
		$this->assertSame($entry_bl['next_due'], $read_bl['next_due'],
			'bl next_due correct; expected ' . $entry_bl['next_due'] . ' got ' . $read_bl['next_due']);
	}

	/**
	 * Absent job key in a populated ledger ⇒ read_entry returns NULL.
	 *
	 * Scenario:
	 *   Given 'dcc' entry exists in the ledger.
	 *   When  read_entry('missing_job', dir).
	 *   Then  returns NULL (key absent).
	 */
	public function testReadEntryMissingKeyReturnsNull(): void
	{
		$entry = ['last_run' => self::NOW, 'next_due' => self::NOW + 86400, 'jitter' => 100];
		pfb_due_ledger_write_entry('dcc', $entry, $this->dir);

		$result = pfb_due_ledger_read_entry('missing_job', $this->dir);

		$this->assertNull($result,
			'read_entry for a key not in the ledger must return NULL; got ' . var_export($result, TRUE));
	}

	/**
	 * Corrupt JSON file ⇒ read_entry returns NULL (fail-safe treated as absent).
	 *
	 * A corrupt or partially-written ledger file (e.g. from a crash between write
	 * and rename) must not cause a fatal error. The fail-safe: treat as absent
	 * and run the job now.
	 *
	 * Scenario:
	 *   Given pfb_due_ledger.json contains non-JSON garbage.
	 *   When  read_entry('dcc', dir).
	 *   Then  returns NULL (corrupt ⇒ absent ⇒ due-now).
	 */
	public function testCorruptLedgerFileReturnsNull(): void
	{
		file_put_contents($this->dir . '/pfb_due_ledger.json', 'not valid json {{{{');

		$result = pfb_due_ledger_read_entry('dcc', $this->dir);

		$this->assertNull($result,
			'corrupt JSON ledger must return NULL; got ' . var_export($result, TRUE));
	}

	/**
	 * Partially-written (truncated) JSON ⇒ read_entry returns NULL (fail-safe).
	 *
	 * Scenario:
	 *   Given pfb_due_ledger.json is truncated mid-object.
	 *   When  read_entry('dcc', dir).
	 *   Then  returns NULL.
	 */
	public function testTruncatedLedgerFileReturnsNull(): void
	{
		file_put_contents($this->dir . '/pfb_due_ledger.json', '{"dcc":{"last_run":');

		$result = pfb_due_ledger_read_entry('dcc', $this->dir);

		$this->assertNull($result,
			'truncated JSON ledger must return NULL; got ' . var_export($result, TRUE));
	}

	/**
	 * Ledger entry with missing fields ⇒ read_entry returns NULL (malformed).
	 *
	 * An entry written by old code or corrupted in place that lacks one of the
	 * required integer fields must be treated as absent (fail-safe).
	 *
	 * Scenario:
	 *   Given ledger contains a 'dcc' entry missing the 'jitter' field.
	 *   When  read_entry('dcc', dir).
	 *   Then  returns NULL.
	 */
	public function testMalformedEntryMissingFieldReturnsNull(): void
	{
		// Write a ledger with a malformed entry directly (no jitter field).
		file_put_contents(
			$this->dir . '/pfb_due_ledger.json',
			json_encode(['dcc' => ['last_run' => self::NOW, 'next_due' => self::NOW + 86400]])
		);

		$result = pfb_due_ledger_read_entry('dcc', $this->dir);

		$this->assertNull($result,
			'entry missing required field must return NULL; got ' . var_export($result, TRUE));
	}

	// -----------------------------------------------------------------------
	// pfb_due_ledger_is_due + pfb_due_ledger_mark_ran — composite (I/O).
	// -----------------------------------------------------------------------

	/**
	 * Absent ledger ⇒ is_due returns TRUE with non-zero, stable jitter after mark_ran.
	 *
	 * This is the boot-after-wipe scenario (issue #468 RAM-disk): no ledger exists,
	 * so the job is due immediately. After mark_ran the stored jitter is non-zero
	 * (spread) and deterministic (stable same seed ⇒ same jitter on every boot).
	 *
	 * Scenario:
	 *   Given no ledger file.
	 *   When  is_due('dcc', interval, now, seed, max, dir).
	 *   Then  is_due = TRUE.
	 *   When  mark_ran('dcc', interval, now, seed, max, dir).
	 *   Then  stored jitter = JITTER_DCC (non-zero, deterministic).
	 */
	public function testAbsentLedgerIsDueAndMarkRanAppliesNonZeroStableJitter(): void
	{
		// Given: no ledger file.
		$is_due_before = pfb_due_ledger_is_due(
			'dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir
		);

		// Then: due (absent ⇒ TRUE).
		$this->assertTrue($is_due_before,
			'absent ledger: is_due must be TRUE; got FALSE');

		// When: mark_ran.
		pfb_due_ledger_mark_ran(
			'dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir
		);

		// Then: stored jitter is non-zero and matches the pre-computed constant.
		$entry = pfb_due_ledger_read_entry('dcc', $this->dir);
		$this->assertNotNull($entry,
			'entry must exist after mark_ran');
		$this->assertGreaterThan(0, $entry['jitter'],
			'jitter after mark_ran must be non-zero; got ' . $entry['jitter']);
		$this->assertSame(self::JITTER_DCC, $entry['jitter'],
			'jitter must be deterministic (JITTER_DCC); expected ' . self::JITTER_DCC .
			' got ' . $entry['jitter']);
	}

	/**
	 * After mark_ran with a future next_due ⇒ is_due returns FALSE (not double-running).
	 *
	 * Scenario:
	 *   Given no ledger.
	 *   Before: is_due = TRUE (absent).
	 *   When:   mark_ran with large interval.
	 *   After:  is_due = FALSE (next_due is in the future).
	 */
	public function testAfterMarkRanIsDueReturnsFalse(): void
	{
		// Before: absent ⇒ due.
		$this->assertTrue(
			pfb_due_ledger_is_due('dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir),
			'before mark_ran: is_due must be TRUE (absent)'
		);

		// When: mark_ran at NOW with a daily interval + jitter.
		pfb_due_ledger_mark_ran('dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir);

		// After: next_due = NOW + 86400 + JITTER_DCC = NOW + 121479, which is in the future.
		$still_now = self::NOW;
		$this->assertFalse(
			pfb_due_ledger_is_due('dcc', self::INTERVAL_DAILY, $still_now, self::SEED, self::MAX, $this->dir),
			'after mark_ran: is_due must be FALSE (next_due is in the future at NOW). ' .
			'next_due=' . (self::NOW + self::INTERVAL_DAILY + self::JITTER_DCC) . ' now=' . $still_now
		);
	}

	/**
	 * Missed window ⇒ exactly ONE catch-up run; mark_ran prevents double-run.
	 *
	 * A job whose next_due has passed (simulating a missed cron window) is due
	 * exactly once. After mark_ran, the next_due advances past now, so a second
	 * is_due call returns FALSE — no double-run.
	 *
	 * Scenario:
	 *   Given a ledger entry with next_due = NOW - 1 (past; missed window).
	 *   Before: is_due = TRUE (catch-up).
	 *   When:   mark_ran at NOW.
	 *   After:  is_due = FALSE (next_due advanced past NOW).
	 */
	public function testMissedWindowExactlyOneDue(): void
	{
		// Arrange: write a stale entry with next_due in the past.
		$stale = [
			'last_run' => self::NOW - 2 * 86400,
			'next_due' => self::NOW - 1,	// missed window
			'jitter'   => 0,
		];
		pfb_due_ledger_write_entry('dcc', $stale, $this->dir);

		// Before: catch-up — is_due must be TRUE.
		$this->assertTrue(
			pfb_due_ledger_is_due('dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir),
			'missed window: is_due must be TRUE (catch-up). ' .
			'next_due=' . $stale['next_due'] . ' now=' . self::NOW
		);

		// When: mark_ran records the run.
		pfb_due_ledger_mark_ran('dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir);

		// After: next_due = NOW + 86400 + JITTER_DCC; is_due must be FALSE (no double-run).
		$this->assertFalse(
			pfb_due_ledger_is_due('dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir),
			'after mark_ran: is_due must be FALSE (no double-run). ' .
			'next_due=' . (self::NOW + self::INTERVAL_DAILY + self::JITTER_DCC) . ' now=' . self::NOW
		);
	}

	/**
	 * Corrupt ledger file ⇒ is_due returns TRUE (fail-safe: treat as absent).
	 *
	 * A partially-written ledger (e.g. crash between write and rename, or fs error)
	 * must not block the job. Corruption ⇒ absent ⇒ due-now.
	 *
	 * Scenario:
	 *   Given pfb_due_ledger.json contains invalid JSON.
	 *   When  is_due('dcc', interval, now, seed, max, dir).
	 *   Then  returns TRUE (fail-safe).
	 */
	public function testCorruptLedgerIsDueFailSafe(): void
	{
		file_put_contents($this->dir . '/pfb_due_ledger.json', 'garbage { corrupted }');

		$result = pfb_due_ledger_is_due(
			'dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir
		);

		$this->assertTrue($result,
			'corrupt ledger: is_due must be TRUE (fail-safe absent); got FALSE');
	}

	/**
	 * Two different jobs have different stable jitters (no synchronised stampede).
	 *
	 * Both jobs run now (absent ⇒ due), call mark_ran, and end up with different
	 * next_due values. This is the anti-stampede guarantee: after a boot-wipe, the
	 * tick runs all jobs once (absent ⇒ due), but their next_due values are spread
	 * by the per-job seeded jitter, preventing a future simultaneous hit.
	 *
	 * Scenario:
	 *   Given no ledger (fresh boot after wipe).
	 *   When  mark_ran for 'dcc' and 'bl' at the same NOW.
	 *   Then  dcc.jitter ≠ bl.jitter and dcc.next_due ≠ bl.next_due.
	 */
	public function testTwoDifferentJobsYieldDifferentNextDueAfterMarkRan(): void
	{
		pfb_due_ledger_mark_ran('dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir);
		pfb_due_ledger_mark_ran('bl',  self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir);

		$entry_dcc = pfb_due_ledger_read_entry('dcc', $this->dir);
		$entry_bl  = pfb_due_ledger_read_entry('bl',  $this->dir);

		$this->assertNotNull($entry_dcc, 'dcc entry must exist after mark_ran');
		$this->assertNotNull($entry_bl,  'bl  entry must exist after mark_ran');

		// Both jitters must be non-zero.
		$this->assertGreaterThan(0, $entry_dcc['jitter'],
			'dcc jitter must be non-zero; got ' . $entry_dcc['jitter']);
		$this->assertGreaterThan(0, $entry_bl['jitter'],
			'bl jitter must be non-zero; got ' . $entry_bl['jitter']);

		// The two jitters must differ (anti-stampede).
		$this->assertNotSame($entry_dcc['jitter'], $entry_bl['jitter'],
			'dcc jitter (' . $entry_dcc['jitter'] . ') and bl jitter (' .
			$entry_bl['jitter'] . ') must differ to prevent a synchronised stampede');

		// The two next_due values must therefore differ.
		$this->assertNotSame($entry_dcc['next_due'], $entry_bl['next_due'],
			'dcc next_due (' . $entry_dcc['next_due'] . ') and bl next_due (' .
			$entry_bl['next_due'] . ') must differ');
	}

	/**
	 * mark_ran sets last_run = now and next_due = now + interval + jitter.
	 *
	 * Scenario:
	 *   Given no ledger.
	 *   When  mark_ran('dcc', INTERVAL_DAILY, NOW, SEED, MAX, dir).
	 *   Then  entry.last_run = NOW, entry.next_due = NOW + INTERVAL_DAILY + JITTER_DCC.
	 */
	public function testMarkRanSetsCorrectLastRunAndNextDue(): void
	{
		pfb_due_ledger_mark_ran('dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, self::MAX, $this->dir);

		$entry = pfb_due_ledger_read_entry('dcc', $this->dir);
		$this->assertNotNull($entry, 'entry must exist after mark_ran');

		$expected_next_due = self::NOW + self::INTERVAL_DAILY + self::JITTER_DCC;

		$this->assertSame(self::NOW, $entry['last_run'],
			'last_run expected NOW (' . self::NOW . ') got ' . $entry['last_run']);
		$this->assertSame($expected_next_due, $entry['next_due'],
			'next_due expected NOW + interval + jitter (' . $expected_next_due . ') got ' . $entry['next_due']);
	}

	/**
	 * mark_ran with zero jitter_max sets next_due = now + interval (no jitter).
	 *
	 * Scenario:
	 *   Given jitter_max = 0.
	 *   When  mark_ran('dcc', interval, now, seed, 0, dir).
	 *   Then  entry.jitter = 0 and entry.next_due = now + interval.
	 */
	public function testMarkRanWithZeroJitterMaxSetsNoJitter(): void
	{
		pfb_due_ledger_mark_ran('dcc', self::INTERVAL_DAILY, self::NOW, self::SEED, 0, $this->dir);

		$entry = pfb_due_ledger_read_entry('dcc', $this->dir);
		$this->assertNotNull($entry, 'entry must exist after mark_ran');

		$this->assertSame(0, $entry['jitter'],
			'jitter must be 0 when jitter_max = 0; got ' . $entry['jitter']);
		$this->assertSame(self::NOW + self::INTERVAL_DAILY, $entry['next_due'],
			'next_due must be now + interval when jitter = 0; expected ' .
			(self::NOW + self::INTERVAL_DAILY) . ' got ' . $entry['next_due']);
	}

	// -----------------------------------------------------------------------
	// pfb_due_ledger_mark_ran_anchored — issue #573: cron phase-creep fix.
	//
	// Anchors next_due on the PREVIOUS next_due (not on $now) whenever that
	// previous value represents an on-time or barely-missed occurrence, so a
	// tick that fires a fraction of a second earlier than its predecessor does
	// NOT slip the whole schedule forward by a tick interval.
	// -----------------------------------------------------------------------

	/**
	 * Anchored mark_ran locks the schedule phase across repeated "fires a bit
	 * early" cycles — zero cumulative slip — while plain mark_ran drifts by
	 * each cycle's epsilon (the defect issue #573 fixes).
	 *
	 * Scenario:
	 *   Given a baseline entry anchored at t0 + I (as if one prior cycle already
	 *   ran cleanly), and three further ticks that each fire an epsilon EARLY
	 *   relative to the ideal boundary (ε = 0, 1, 899 s — all < I).
	 *   When  mark_ran_anchored is called once per tick, chained (each call
	 *         reads back the previous call's persisted next_due).
	 *   Then  every resulting next_due lands EXACTLY on t0 + (k+1)*I — no
	 *         cumulative drift, regardless of the epsilon each tick added.
	 *   Contrast: the same epsilon sequence fed to plain mark_ran (unanchored)
	 *   produces next_due = t0 + k*I + ε_k + I — each cycle's epsilon leaks
	 *   straight into the stored schedule, which is exactly how issue #573's
	 *   monotonic creep accumulates in production.
	 */
	public function testMarkRanAnchoredLocksPhaseAcrossCyclesUnlikePlainMarkRan(): void
	{
		$t0       = self::NOW;
		$interval = self::INTERVAL_DAILY;
		$epsilons = [0, 1, 899];	// all strictly < interval — the "fired a bit early" case

		// Given: a baseline entry as if a prior cycle already anchored next_due to t0 + I.
		pfb_due_ledger_write_entry('cron_anchor', [
			'last_run' => $t0,
			'next_due' => $t0 + $interval,
			'jitter'   => 0,
		], $this->dir);

		foreach ($epsilons as $idx => $eps) {
			$k   = $idx + 1;
			$now = $t0 + ($k * $interval) + $eps;

			pfb_due_ledger_mark_ran_anchored('cron_anchor', $interval, $now, self::SEED, 0, $this->dir);

			$entry    = pfb_due_ledger_read_entry('cron_anchor', $this->dir);
			$expected = $t0 + (($k + 1) * $interval);

			$this->assertNotNull($entry, "cron_anchor entry must exist after cycle {$k}");
			$this->assertSame($expected, $entry['next_due'],
				"cycle {$k} (eps={$eps}): anchored next_due expected {$expected} (= t0 + " . ($k + 1)
				. "*I, zero slip) got {$entry['next_due']}");
		}

		// Contrast: the SAME epsilon sequence fed to plain (unanchored) mark_ran
		// drifts by exactly epsilon every cycle — the defect this fix targets.
		foreach ($epsilons as $idx => $eps) {
			$k   = $idx + 1;
			$now = $t0 + ($k * $interval) + $eps;

			pfb_due_ledger_mark_ran('cron_plain', $interval, $now, self::SEED, 0, $this->dir);

			$entry    = pfb_due_ledger_read_entry('cron_plain', $this->dir);
			$expected = $t0 + ($k * $interval) + $eps + $interval;

			$this->assertNotNull($entry, "cron_plain entry must exist after cycle {$k}");
			$this->assertSame($expected, $entry['next_due'],
				"cycle {$k} (eps={$eps}): plain mark_ran next_due expected {$expected} (= now + I, "
				. "drifts by eps) got {$entry['next_due']} — documents the phase-creep issue #573 fixes");
		}
	}

	/**
	 * A schedule missed by more than one full interval is a genuine catch-up,
	 * not a boundary-rounding slip — the anchored variant re-phases from now
	 * rather than dragging a stale anchor forward.
	 *
	 * Scenario:
	 *   Given an entry whose next_due is more than one interval in the past
	 *   (e.g. the box was offline across a whole missed cycle).
	 *   When  mark_ran_anchored runs.
	 *   Then  the new next_due = now + interval (base = now, NOT the stale entry).
	 */
	public function testMarkRanAnchoredCatchUpFromNowWhenMorePastThanOneInterval(): void
	{
		$staleNextDue = self::NOW - self::INTERVAL_DAILY - 100;	// > 1 interval late
		pfb_due_ledger_write_entry('cron', [
			'last_run' => $staleNextDue - self::INTERVAL_DAILY,
			'next_due' => $staleNextDue,
			'jitter'   => 0,
		], $this->dir);

		pfb_due_ledger_mark_ran_anchored('cron', self::INTERVAL_DAILY, self::NOW, self::SEED, 0, $this->dir);

		$entry    = pfb_due_ledger_read_entry('cron', $this->dir);
		$expected = self::NOW + self::INTERVAL_DAILY;

		$this->assertNotNull($entry, 'cron entry must exist after mark_ran_anchored');
		$this->assertSame($expected, $entry['next_due'],
			"catch-up (missed by > 1 interval): expected next_due = now + interval ({$expected}), " .
			"got {$entry['next_due']} — must re-anchor from now, not the stale next_due ({$staleNextDue})");
	}

	/**
	 * An absent ledger entry has nothing to anchor to — behaves exactly like
	 * plain mark_ran (base = now).
	 *
	 * Scenario:
	 *   Given no ledger entry for the job.
	 *   When  mark_ran_anchored runs.
	 *   Then  next_due = now + interval.
	 */
	public function testMarkRanAnchoredAbsentEntryAnchorsFromNow(): void
	{
		pfb_due_ledger_mark_ran_anchored('cron', self::INTERVAL_DAILY, self::NOW, self::SEED, 0, $this->dir);

		$entry    = pfb_due_ledger_read_entry('cron', $this->dir);
		$expected = self::NOW + self::INTERVAL_DAILY;

		$this->assertNotNull($entry, 'cron entry must exist after mark_ran_anchored');
		$this->assertSame($expected, $entry['next_due'],
			"absent entry: expected next_due = now + interval ({$expected}), got {$entry['next_due']}");
	}

	/**
	 * A set_pending placeholder (next_due=0, no real prior schedule) has nothing
	 * meaningful to anchor to — behaves exactly like plain mark_ran (base = now).
	 *
	 * Scenario:
	 *   Given the job was set_pending with no prior real entry (placeholder
	 *   next_due=0).
	 *   When  mark_ran_anchored runs.
	 *   Then  next_due = now + interval (base = now, not the 0 placeholder), and
	 *         pending_apply is cleared (mark_ran_anchored writes a clean entry).
	 */
	public function testMarkRanAnchoredPendingPlaceholderAnchorsFromNow(): void
	{
		pfb_due_ledger_set_pending('cron', $this->dir);

		// Before: the placeholder has next_due = 0 and pending_apply set.
		$placeholder = pfb_due_ledger_read_entry('cron', $this->dir);
		$this->assertNotNull($placeholder, 'placeholder entry must exist after set_pending');
		$this->assertSame(0, $placeholder['next_due'],
			"before: placeholder next_due must be 0, got {$placeholder['next_due']}");

		pfb_due_ledger_mark_ran_anchored('cron', self::INTERVAL_DAILY, self::NOW, self::SEED, 0, $this->dir);

		$entry    = pfb_due_ledger_read_entry('cron', $this->dir);
		$expected = self::NOW + self::INTERVAL_DAILY;

		$this->assertNotNull($entry, 'cron entry must exist after mark_ran_anchored');
		$this->assertSame($expected, $entry['next_due'],
			"pending placeholder: expected next_due = now + interval ({$expected}), got " .
			"{$entry['next_due']} — must not anchor onto the 0 placeholder");
		$this->assertArrayNotHasKey('pending_apply', $entry,
			'mark_ran_anchored must clear pending_apply by writing a clean entry');
	}

	/**
	 * next_due in the FUTURE relative to now is never anchored onto (clock skew
	 * / an already-pending future entry) — base = now.
	 *
	 * Scenario:
	 *   Given an entry with next_due 500 s in the future relative to now.
	 *   When  mark_ran_anchored runs at now.
	 *   Then  next_due = now + interval, NOT the future next_due + interval.
	 */
	public function testMarkRanAnchoredSkewGuardNeverAnchorsForward(): void
	{
		$futureNextDue = self::NOW + 500;
		pfb_due_ledger_write_entry('cron', [
			'last_run' => self::NOW - self::INTERVAL_DAILY,
			'next_due' => $futureNextDue,
			'jitter'   => 0,
		], $this->dir);

		pfb_due_ledger_mark_ran_anchored('cron', self::INTERVAL_DAILY, self::NOW, self::SEED, 0, $this->dir);

		$entry    = pfb_due_ledger_read_entry('cron', $this->dir);
		$expected = self::NOW + self::INTERVAL_DAILY;

		$this->assertNotNull($entry, 'cron entry must exist after mark_ran_anchored');
		$this->assertSame($expected, $entry['next_due'],
			"future next_due ({$futureNextDue}) must NOT be anchored onto: expected next_due = " .
			"now + interval ({$expected}), got {$entry['next_due']}");
	}

	/**
	 * Jitter is added on top of the ANCHORED base, not recomputed from now —
	 * proves the anchoring and jitter steps compose correctly.
	 *
	 * Scenario:
	 *   Given a baseline entry anchored at NOW + I (a prior clean cycle), and a
	 *   tick that fires 50 s early relative to the next boundary.
	 *   When  mark_ran_anchored runs with jitter_max = MAX for job 'dcc'.
	 *   Then  next_due = (NOW + I) + I + JITTER_DCC — jitter rides the anchored
	 *         base, not a bare $now + I + jitter.
	 */
	public function testMarkRanAnchoredJitterRidesAnchoredBase(): void
	{
		pfb_due_ledger_write_entry('dcc', [
			'last_run' => self::NOW,
			'next_due' => self::NOW + self::INTERVAL_DAILY,
			'jitter'   => 0,
		], $this->dir);

		$now = self::NOW + self::INTERVAL_DAILY + 50;	// fires 50s early vs. the *next* boundary
		pfb_due_ledger_mark_ran_anchored('dcc', self::INTERVAL_DAILY, $now, self::SEED, self::MAX, $this->dir);

		$entry    = pfb_due_ledger_read_entry('dcc', $this->dir);
		$expected = (self::NOW + self::INTERVAL_DAILY) + self::INTERVAL_DAILY + self::JITTER_DCC;

		$this->assertNotNull($entry, 'dcc entry must exist after mark_ran_anchored');
		$this->assertSame(self::JITTER_DCC, $entry['jitter'],
			'jitter must be JITTER_DCC; expected ' . self::JITTER_DCC . ' got ' . $entry['jitter']);
		$this->assertSame($expected, $entry['next_due'],
			"anchored + jittered next_due expected {$expected} (anchored base + interval + jitter), " .
			"got {$entry['next_due']}");
	}
}
