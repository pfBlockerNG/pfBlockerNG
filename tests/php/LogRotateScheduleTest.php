<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-30 Phase 1 — Pure schedule-period deciders.
 *
 * Pins the behaviour of:
 *   pfb_log_rotate_period(string $schedule, int $ts): string
 *   pfb_log_should_reset(string $schedule, string $last_key, int $now_ts): bool
 *
 * Both functions are PURE (no I/O, no globals) — all inputs passed explicitly.
 * They are dormant (uncalled) this phase; only these tests exercise them.
 *
 * Coverage mandate (CLAUDE.md):
 *   - Every schedule value (off/''/daily/weekly/monthly) and every branch.
 *   - Both sides of each boundary (before vs. after period rollover).
 *   - pfb_log_should_reset: off => FALSE; same period => FALSE; new period => TRUE;
 *     empty $last_key (never reset) => TRUE.
 *   - ISO week-year boundary: 2027-01-01 ∈ 2026-W53, 2027-01-04 ∈ 2027-W01.
 *
 * Timestamps: all constructed with mktime() — same timezone as date(), so
 * period keys computed by the functions under test match the assertions here.
 */
final class LogRotateScheduleTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Fixed timestamps for deterministic assertions.
	// All computed via mktime() so they match date() in the local timezone.
	// -----------------------------------------------------------------------

	/** @var int 2025-07-15 noon — a Tuesday in ISO week 2025-W29. */
	private static int $ts20250715;

	/** @var int 2025-07-16 noon — a Wednesday, same ISO week 2025-W29. */
	private static int $ts20250716;

	/** @var int 2025-07-21 noon — a Monday, ISO week 2025-W30 (week boundary). */
	private static int $ts20250721;

	/** @var int 2025-08-01 noon — first of August (monthly boundary from July). */
	private static int $ts20250801;

	/** @var int 2027-01-01 noon — calendar year 2027 but ISO week 2026-W53. */
	private static int $ts20270101;

	/** @var int 2027-01-04 noon — first day of ISO week 2027-W01. */
	private static int $ts20270104;

	public static function setUpBeforeClass(): void
	{
		self::$ts20250715 = mktime(12, 0, 0, 7,  15, 2025);
		self::$ts20250716 = mktime(12, 0, 0, 7,  16, 2025);
		self::$ts20250721 = mktime(12, 0, 0, 7,  21, 2025);
		self::$ts20250801 = mktime(12, 0, 0, 8,  1,  2025);
		self::$ts20270101 = mktime(12, 0, 0, 1,  1,  2027);
		self::$ts20270104 = mktime(12, 0, 0, 1,  4,  2027);
	}

	// -----------------------------------------------------------------------
	// Sanity-check the fixed timestamps match expectations.
	// Prevents silent drift if the date constants are ever wrong.
	// -----------------------------------------------------------------------

	public function testFixedTimestampsSanity(): void
	{
		$this->assertSame('2025-07-15', date('Y-m-d', self::$ts20250715), '2025-07-15 constant');
		$this->assertSame('2025-07-16', date('Y-m-d', self::$ts20250716), '2025-07-16 constant');
		$this->assertSame('2025-07-21', date('Y-m-d', self::$ts20250721), '2025-07-21 constant');
		$this->assertSame('2025-08-01', date('Y-m-d', self::$ts20250801), '2025-08-01 constant');
		$this->assertSame('2027-01-01', date('Y-m-d', self::$ts20270101), '2027-01-01 constant');
		$this->assertSame('2027-01-04', date('Y-m-d', self::$ts20270104), '2027-01-04 constant');

		// Confirm the ISO week-year edge case holds in this environment.
		$this->assertSame('2026-W53', date('o-\WW', self::$ts20270101), '2027-01-01 is ISO 2026-W53');
		$this->assertSame('2027-W01', date('o-\WW', self::$ts20270104), '2027-01-04 is ISO 2027-W01');
	}

	// -----------------------------------------------------------------------
	// pfb_log_rotate_period() — period-key format assertions
	// -----------------------------------------------------------------------

	/**
	 * 'off' and '' both return '' (no period key — schedule disabled).
	 *
	 * Scenario:
	 *   Given $schedule = 'off' or ''.
	 *   When  pfb_log_rotate_period($schedule, $ts).
	 *   Then  returns '' for any timestamp.
	 */
	public function testPeriodOffReturnsEmpty(): void
	{
		$this->assertSame('', pfb_log_rotate_period('off', self::$ts20250715));
		$this->assertSame('', pfb_log_rotate_period('off', self::$ts20270101));
	}

	public function testPeriodEmptyStringReturnsEmpty(): void
	{
		// '' -> '' (same as 'off').
		$this->assertSame('', pfb_log_rotate_period('', self::$ts20250715));
		$this->assertSame('', pfb_log_rotate_period('', self::$ts20270101));
	}

	/**
	 * Unrecognised schedules default to off-behaviour (return '').
	 *
	 * Scenario:
	 *   Given $schedule = some unknown string.
	 *   When  pfb_log_rotate_period($schedule, $ts).
	 *   Then  returns '' (off default for unrecognised input).
	 */
	public function testPeriodUnrecognisedDefaultsToOff(): void
	{
		$this->assertSame('', pfb_log_rotate_period('yearly', self::$ts20250715));
		$this->assertSame('', pfb_log_rotate_period('DAILY',  self::$ts20250715));
		$this->assertSame('', pfb_log_rotate_period('bogus',  self::$ts20250715));
	}

	/**
	 * 'daily' returns 'YYYY-MM-DD' for the given timestamp.
	 *
	 * Scenario:
	 *   Given $schedule = 'daily'.
	 *   When  pfb_log_rotate_period('daily', $ts).
	 *   Then  returns date('Y-m-d', $ts).
	 */
	public function testPeriodDailyReturnsYmd(): void
	{
		$this->assertSame('2025-07-15', pfb_log_rotate_period('daily', self::$ts20250715));
		$this->assertSame('2025-07-16', pfb_log_rotate_period('daily', self::$ts20250716));
		$this->assertSame('2025-07-21', pfb_log_rotate_period('daily', self::$ts20250721));
		$this->assertSame('2025-08-01', pfb_log_rotate_period('daily', self::$ts20250801));
	}

	/**
	 * 'daily' returns distinct keys for distinct calendar days (boundary).
	 *
	 * Before-and-after: two adjacent days yield different keys.
	 *
	 * Scenario:
	 *   Given $ts_a = 2025-07-15, $ts_b = 2025-07-16 (adjacent days).
	 *   Before: same-day keys would be equal — verify they differ across days.
	 *   After:  the day boundary is crossed.
	 */
	public function testPeriodDailyDifferentDaysYieldDifferentKeys(): void
	{
		$key_a = pfb_log_rotate_period('daily', self::$ts20250715);
		$key_b = pfb_log_rotate_period('daily', self::$ts20250716);

		// Same day within the period returns the same key (no boundary).
		$key_same = pfb_log_rotate_period('daily', mktime(8, 0, 0, 7, 15, 2025));
		$this->assertSame($key_a, $key_same, 'same calendar day: same key');

		// Adjacent days cross the boundary.
		$this->assertNotSame($key_a, $key_b, 'adjacent days produce different period keys');
		$this->assertSame('2025-07-15', $key_a);
		$this->assertSame('2025-07-16', $key_b);
	}

	/**
	 * 'weekly' returns ISO 'YYYY-Www' for the given timestamp.
	 *
	 * Format uses date('o-\WW', $ts) so the ISO week-year is correct.
	 *
	 * Scenario:
	 *   Given $schedule = 'weekly'.
	 *   When  pfb_log_rotate_period('weekly', $ts).
	 *   Then  returns date('o-\WW', $ts) format.
	 */
	public function testPeriodWeeklyReturnsIsoWeek(): void
	{
		// 2025-07-15 is a Tuesday — ISO week 29 of 2025.
		$this->assertSame('2025-W29', pfb_log_rotate_period('weekly', self::$ts20250715));

		// 2025-07-16 is a Wednesday — same week W29.
		$this->assertSame('2025-W29', pfb_log_rotate_period('weekly', self::$ts20250716));

		// 2025-07-21 is a Monday — ISO week 30 of 2025 (boundary crossed).
		$this->assertSame('2025-W30', pfb_log_rotate_period('weekly', self::$ts20250721));
	}

	/**
	 * 'weekly' same week yields same key; adjacent weeks yield different keys.
	 *
	 * Before-and-after: two adjacent ISO weeks produce different keys.
	 *
	 * Scenario:
	 *   Given $ts_a in week 2025-W29, $ts_b in week 2025-W30.
	 *   Before: same-week keys are identical.
	 *   After:  the week boundary produces different keys.
	 */
	public function testPeriodWeeklyBoundary(): void
	{
		$key_w29_tue = pfb_log_rotate_period('weekly', self::$ts20250715);
		$key_w29_wed = pfb_log_rotate_period('weekly', self::$ts20250716);
		$key_w30_mon = pfb_log_rotate_period('weekly', self::$ts20250721);

		// Before: same ISO week -> same key.
		$this->assertSame($key_w29_tue, $key_w29_wed, 'same ISO week yields same key');

		// After: different ISO week -> different key.
		$this->assertNotSame($key_w29_tue, $key_w30_mon, 'different ISO weeks yield different keys');
		$this->assertSame('2025-W29', $key_w29_tue);
		$this->assertSame('2025-W30', $key_w30_mon);
	}

	/**
	 * ISO week-year boundary: 2027-01-01 falls in 2026-W53, not 2027-W01.
	 *
	 * This is the critical ISO week-year edge case — using date('Y') would
	 * return '2027-W01', but date('o') correctly returns '2026-W53'.
	 *
	 * Scenario:
	 *   Given $ts_a = 2027-01-01 (calendar year 2027, ISO year 2026, week 53).
	 *   And   $ts_b = 2027-01-04 (first day of ISO week 2027-W01).
	 *   Before (same period): $ts_a is in 2026-W53, not yet in 2027.
	 *   After (boundary crossed): $ts_b enters 2027-W01.
	 *   Then  $ts_a returns '2026-W53' (ISO year 2026, not calendar year 2027).
	 *   And   $ts_b returns '2027-W01' (new ISO year 2027).
	 */
	public function testPeriodWeeklyIsoYearBoundary(): void
	{
		// Before boundary: 2027-01-01 is in ISO week 2026-W53.
		$key_a = pfb_log_rotate_period('weekly', self::$ts20270101);
		$this->assertSame('2026-W53', $key_a, '2027-01-01 must be ISO 2026-W53');

		// After boundary: 2027-01-04 is the first day of ISO week 2027-W01.
		$key_b = pfb_log_rotate_period('weekly', self::$ts20270104);
		$this->assertSame('2027-W01', $key_b, '2027-01-04 must be ISO 2027-W01');

		// The week boundary is crossed.
		$this->assertNotSame($key_a, $key_b, 'ISO year boundary produces different week keys');
	}

	/**
	 * 'monthly' returns 'YYYY-MM' for the given timestamp.
	 *
	 * Scenario:
	 *   Given $schedule = 'monthly'.
	 *   When  pfb_log_rotate_period('monthly', $ts).
	 *   Then  returns date('Y-m', $ts).
	 */
	public function testPeriodMonthlyReturnsYearMonth(): void
	{
		$this->assertSame('2025-07', pfb_log_rotate_period('monthly', self::$ts20250715));
		$this->assertSame('2025-07', pfb_log_rotate_period('monthly', self::$ts20250716));
		$this->assertSame('2025-07', pfb_log_rotate_period('monthly', self::$ts20250721));
		$this->assertSame('2025-08', pfb_log_rotate_period('monthly', self::$ts20250801));
	}

	/**
	 * 'monthly' same month yields same key; adjacent months yield different keys.
	 *
	 * Before-and-after boundary: July vs August.
	 *
	 * Scenario:
	 *   Given $ts_a = last second of July 2025, $ts_b = first second of August 2025.
	 *   Before: within July — same key.
	 *   After:  August — different key.
	 */
	public function testPeriodMonthlyBoundary(): void
	{
		$ts_july_end  = mktime(23, 59, 59, 7, 31, 2025);
		$ts_aug_start = mktime(0,  0,  0,  8, 1,  2025);

		$key_july_mid = pfb_log_rotate_period('monthly', self::$ts20250715);
		$key_july_end = pfb_log_rotate_period('monthly', $ts_july_end);
		$key_aug      = pfb_log_rotate_period('monthly', $ts_aug_start);

		// Before: same month (July) -> same key for any July timestamp.
		$this->assertSame('2025-07', $key_july_mid,  'mid-July: 2025-07');
		$this->assertSame('2025-07', $key_july_end,  'end-of-July: 2025-07');

		// After: next month (August) -> different key.
		$this->assertSame('2025-08', $key_aug,        'start-of-August: 2025-08');
		$this->assertNotSame($key_july_end, $key_aug, 'month boundary crosses to a new key');
	}

	// -----------------------------------------------------------------------
	// pfb_log_should_reset() — decision function assertions
	// -----------------------------------------------------------------------

	/**
	 * 'off' always returns FALSE regardless of $last_key or timestamp.
	 *
	 * Scenario:
	 *   Given $schedule = 'off'.
	 *   When  pfb_log_should_reset('off', $last_key, $ts).
	 *   Then  returns FALSE for any $last_key (empty, matching, stale).
	 */
	public function testShouldResetOffAlwaysFalse(): void
	{
		// 'off' with empty last_key (never reset).
		$this->assertFalse(pfb_log_should_reset('off', '', self::$ts20250715));

		// 'off' with a last_key matching the current daily period.
		$this->assertFalse(pfb_log_should_reset('off', '2025-07-15', self::$ts20250715));

		// 'off' with a stale last_key (period has rolled).
		$this->assertFalse(pfb_log_should_reset('off', '2025-07-14', self::$ts20250715));
	}

	public function testShouldResetEmptyScheduleAlwaysFalse(): void
	{
		// '' behaves identically to 'off'.
		$this->assertFalse(pfb_log_should_reset('', '', self::$ts20250715));
		$this->assertFalse(pfb_log_should_reset('', '2025-07-15', self::$ts20250715));
		$this->assertFalse(pfb_log_should_reset('', '2025-07-14', self::$ts20250715));
	}

	/**
	 * Schedule set + empty $last_key (never reset) => TRUE.
	 *
	 * An empty $last_key means this log has never been reset; any active
	 * schedule triggers a reset on the first tick.
	 *
	 * Scenario:
	 *   Given $schedule in {daily, weekly, monthly}, $last_key = ''.
	 *   When  pfb_log_should_reset($schedule, '', $now_ts).
	 *   Then  returns TRUE (treat as "period has changed" — reset overdue).
	 */
	public function testShouldResetNeverResetEmptyLastKeyReturnsTrue(): void
	{
		// daily: empty last_key -> TRUE.
		$this->assertTrue(pfb_log_should_reset('daily',   '', self::$ts20250715));

		// weekly: empty last_key -> TRUE.
		$this->assertTrue(pfb_log_should_reset('weekly',  '', self::$ts20250715));

		// monthly: empty last_key -> TRUE.
		$this->assertTrue(pfb_log_should_reset('monthly', '', self::$ts20250715));
	}

	/**
	 * 'daily': same period => FALSE; next day => TRUE.
	 *
	 * Before-and-after: first assert same-period is FALSE, then assert new-period is TRUE.
	 *
	 * Scenario:
	 *   Given $schedule = 'daily', $last_key = '2025-07-15'.
	 *   Before: $now_ts = 2025-07-15 -> FALSE (same period, already reset).
	 *   After:  $now_ts = 2025-07-16 -> TRUE (day has rolled).
	 */
	public function testShouldResetDailySamePeriodFalseNewPeriodTrue(): void
	{
		// Before: same daily period -> FALSE.
		$this->assertFalse(
			pfb_log_should_reset('daily', '2025-07-15', self::$ts20250715),
			'same daily period: no reset'
		);

		// After: next day -> TRUE.
		$this->assertTrue(
			pfb_log_should_reset('daily', '2025-07-15', self::$ts20250716),
			'new daily period: reset'
		);
	}

	/**
	 * 'daily': stale $last_key from a previous day => TRUE.
	 *
	 * Scenario:
	 *   Given $schedule = 'daily', $last_key = '2025-07-14' (yesterday).
	 *   When  $now_ts = 2025-07-15.
	 *   Then  returns TRUE (day has rolled over).
	 */
	public function testShouldResetDailyStalePeriodTrue(): void
	{
		$this->assertTrue(
			pfb_log_should_reset('daily', '2025-07-14', self::$ts20250715),
			'stale daily key: reset'
		);
	}

	/**
	 * 'weekly': before-and-after boundary (week 2025-W29 vs 2025-W30).
	 *
	 * Scenario:
	 *   Given $last_key = '2025-W29'.
	 *   Before: $now_ts in 2025-W29 (2025-07-16, Wed) -> FALSE.
	 *   After:  $now_ts in 2025-W30 (2025-07-21, Mon) -> TRUE.
	 */
	public function testShouldResetWeeklyBoundary(): void
	{
		// Before: same ISO week -> FALSE.
		$this->assertFalse(
			pfb_log_should_reset('weekly', '2025-W29', self::$ts20250716),
			'same weekly period (W29): no reset'
		);

		// After: new ISO week -> TRUE.
		$this->assertTrue(
			pfb_log_should_reset('weekly', '2025-W29', self::$ts20250721),
			'new weekly period (W30): reset'
		);
	}

	/**
	 * 'monthly': before-and-after boundary (July vs August 2025).
	 *
	 * Scenario:
	 *   Given $last_key = '2025-07'.
	 *   Before: $now_ts in July 2025 -> FALSE.
	 *   After:  $now_ts in August 2025 -> TRUE.
	 */
	public function testShouldResetMonthlyBoundary(): void
	{
		// Before: same month (July) -> FALSE.
		$this->assertFalse(
			pfb_log_should_reset('monthly', '2025-07', self::$ts20250721),
			'same monthly period (July): no reset'
		);

		// After: new month (August) -> TRUE.
		$this->assertTrue(
			pfb_log_should_reset('monthly', '2025-07', self::$ts20250801),
			'new monthly period (August): reset'
		);
	}

	/**
	 * ISO week-year boundary via pfb_log_should_reset.
	 *
	 * 2027-01-01 is in ISO week 2026-W53; 2027-01-04 is in 2027-W01.
	 * This tests that the function correctly uses the ISO week year (not
	 * the calendar year) when the two differ at year-end.
	 *
	 * Scenario:
	 *   Given $last_key = '2026-W53'.
	 *   Before: $now_ts = 2027-01-01 (still in 2026-W53) -> FALSE.
	 *   After:  $now_ts = 2027-01-04 (in 2027-W01) -> TRUE.
	 */
	public function testShouldResetWeeklyIsoYearBoundary(): void
	{
		// Before: 2027-01-01 is still in 2026-W53 -> no reset.
		$this->assertFalse(
			pfb_log_should_reset('weekly', '2026-W53', self::$ts20270101),
			'2027-01-01 is still 2026-W53: no reset'
		);

		// After: 2027-01-04 enters 2027-W01 -> reset.
		$this->assertTrue(
			pfb_log_should_reset('weekly', '2026-W53', self::$ts20270104),
			'2027-01-04 enters 2027-W01: reset'
		);
	}

	/**
	 * Unrecognised schedules default to off (FALSE) in pfb_log_should_reset.
	 *
	 * Scenario:
	 *   Given $schedule = unknown string (e.g. 'bogus', 'DAILY').
	 *   When  pfb_log_should_reset($schedule, $last_key, $ts).
	 *   Then  returns FALSE (off default).
	 */
	public function testShouldResetUnrecognisedScheduleDefaultsToFalse(): void
	{
		$this->assertFalse(pfb_log_should_reset('bogus', '',  self::$ts20250715));
		$this->assertFalse(pfb_log_should_reset('DAILY', '',  self::$ts20250715));
		$this->assertFalse(pfb_log_should_reset('bogus', '2025-07-14', self::$ts20250715));
	}

	/**
	 * Composition consistency: should_reset($s, $last, $ts) == (period($s, $ts) !== $last).
	 *
	 * Guards against a future refactor accidentally decoupling the two functions.
	 * Covers all four schedule values across both sides of their boundaries.
	 */
	public function testShouldResetComposesWithPeriodCorrectly(): void
	{
		$cases = [
			// [schedule, last_key, ts, expected_reset]

			// daily: same day -> FALSE; different day -> TRUE; empty -> TRUE.
			['daily',   '2025-07-15', self::$ts20250715, FALSE],
			['daily',   '2025-07-14', self::$ts20250715, TRUE],
			['daily',   '',           self::$ts20250715, TRUE],

			// weekly: same week -> FALSE; different week -> TRUE; empty -> TRUE.
			['weekly',  '2025-W29',   self::$ts20250715, FALSE],
			['weekly',  '2025-W28',   self::$ts20250715, TRUE],
			['weekly',  '',           self::$ts20250715, TRUE],

			// monthly: same month -> FALSE; different month -> TRUE; empty -> TRUE.
			['monthly', '2025-07',    self::$ts20250715, FALSE],
			['monthly', '2025-06',    self::$ts20250715, TRUE],
			['monthly', '',           self::$ts20250715, TRUE],

			// off: always FALSE regardless of last_key.
			['off',     '',           self::$ts20250715, FALSE],
			['off',     '2025-07-14', self::$ts20250715, FALSE],
			['off',     '2025-07-15', self::$ts20250715, FALSE],

			// ISO year-boundary: 2027-01-01 is still 2026-W53 -> FALSE.
			['weekly',  '2026-W53',   self::$ts20270101, FALSE],
			// 2027-01-04 is 2027-W01 -> TRUE.
			['weekly',  '2026-W53',   self::$ts20270104, TRUE],
		];

		foreach ($cases as [$schedule, $last_key, $ts, $expected]) {
			$result = pfb_log_should_reset($schedule, $last_key, $ts);
			$this->assertSame(
				$expected,
				$result,
				"schedule={$schedule} last_key='{$last_key}': expected " . ($expected ? 'TRUE' : 'FALSE')
			);
		}
	}
}
