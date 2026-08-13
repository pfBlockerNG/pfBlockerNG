<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Pure calendar and feed-plan primitives for the quarter-hour scheduler.
 *
 * The production seam is intentionally unreachable from runtime callers in this
 * slice. These tests pin the public contracts before the scheduler wiring lands.
 */
final class AnchoredSchedulePrimitivesTest extends TestCase
{
	private string $timezone;
	private DateTimeZone $scheduleTimezone;

	protected function setUp(): void
	{
		$this->timezone = date_default_timezone_get();
		date_default_timezone_set('UTC');
		$this->scheduleTimezone = new DateTimeZone('UTC');
	}

	protected function tearDown(): void
	{
		date_default_timezone_set($this->timezone);
	}

	private function timestamp(string $local): int
	{
		return (new DateTimeImmutable($local))->getTimestamp();
	}

	public function testNextOccurrenceCoversEverySupportedCadenceAndWrapsSundayToMonday(): void
	{
		$reference = $this->timestamp('2026-01-05 00:00:01');
		$cases = [
			['01hour', 1, 0, 15, '2026-01-05 00:15:00'],
			['02hours', 1, 2, 30, '2026-01-05 00:30:00'],
			['03hours', 1, 3, 45, '2026-01-05 00:45:00'],
			['04hours', 1, 4, 00, '2026-01-05 04:00:00'],
			['06hours', 1, 6, 15, '2026-01-05 00:15:00'],
			['08hours', 1, 8, 30, '2026-01-05 00:30:00'],
			['12hours', 1, 12, 45, '2026-01-05 00:45:00'],
			['EveryDay', 1, 23, 00, '2026-01-05 23:00:00'],
			['Weekly', 1, 0, 15, '2026-01-05 00:15:00'],
		];

		foreach ($cases as [$cadence, $weekday, $hour, $minute, $expected]) {
			$actual = pfb_schedule_next_occurrence($cadence, $weekday, $hour, $minute, $reference, $this->scheduleTimezone);
			$this->assertSame(
				$this->timestamp($expected),
				$actual,
				"{$cadence} did not select its first local slot"
			);
		}

		$beforeSunday = $this->timestamp('2026-01-11 23:59:59');
		$this->assertSame(
			$this->timestamp('2026-01-12 00:00:00'),
			pfb_schedule_next_occurrence('Weekly', 1, 0, 0, $beforeSunday, $this->scheduleTimezone),
			'Sunday-to-Monday weekly wrap must use ISO weekday values'
		);
	}

	public function testNextOccurrenceUsesStrictAfterReferenceAndAllQuarterMinutes(): void
	{
		$slot = $this->timestamp('2026-02-03 10:15:00');
		$this->assertSame(
			$slot,
			pfb_schedule_next_occurrence('EveryDay', 7, 10, 15, $slot - 1, $this->scheduleTimezone)
		);
		$this->assertSame(
			$this->timestamp('2026-02-04 10:15:00'),
			pfb_schedule_next_occurrence('EveryDay', 7, 10, 15, $slot, $this->scheduleTimezone),
			'exact reference slot must be skipped'
		);
		$this->assertSame(
			$this->timestamp('2026-02-04 10:15:00'),
			pfb_schedule_next_occurrence('EveryDay', 7, 10, 15, $slot + 1, $this->scheduleTimezone),
			'immediately-after reference slot must be skipped'
		);

		foreach ([0, 15, 30, 45] as $minute) {
			$expected = $this->timestamp("2026-02-03 10:" . str_pad((string) $minute, 2, '0', STR_PAD_LEFT) . ':00');
			$this->assertSame(
				$expected,
				pfb_schedule_next_occurrence('01hour', 7, 10, $minute, $expected - 1, $this->scheduleTimezone),
				"quarter-hour minute {$minute} must be selectable"
			);
		}
	}

	public function testNextOccurrenceWrapsAcrossMonthAndYearBoundaries(): void
	{
		$reference = $this->timestamp('2026-12-31 23:59:59');
		$this->assertSame(
			$this->timestamp('2027-01-01 00:00:00'),
			pfb_schedule_next_occurrence('EveryDay', 1, 0, 0, $reference, $this->scheduleTimezone)
		);
	}

	public function testNextOccurrenceUsesNonzeroPhaseForEveryMultiHourCadence(): void
	{
		$reference = $this->timestamp('2026-01-05 00:00:00');
		foreach (['02hours', '03hours', '04hours', '06hours', '08hours', '12hours'] as $cadence) {
			$this->assertSame(
				$this->timestamp('2026-01-05 01:00:00'),
				pfb_schedule_next_occurrence($cadence, 1, 1, 0, $reference, $this->scheduleTimezone),
				"{$cadence} must honor a nonzero hourly phase"
			);
		}
	}

	public function testNextOccurrenceReturnsNullOnlyForNeverAndRejectsMalformedInputs(): void
	{
		$reference = $this->timestamp('2026-01-05 00:00:00');
		$this->assertNull(pfb_schedule_next_occurrence('Never', 1, 0, 0, $reference, $this->scheduleTimezone));

		$invalid = [
			['Never', 0, 0, 0],
			['bogus', 1, 0, 0],
			['01hour', 0, 0, 0],
			['01hour', 8, 0, 0],
			['01hour', 1, -1, 0],
			['01hour', 1, 24, 0],
			['01hour', 1, 0, 1],
			['01hour', 1, 0, 60],
		];
		foreach ($invalid as [$cadence, $weekday, $hour, $minute]) {
			try {
				pfb_schedule_next_occurrence($cadence, $weekday, $hour, $minute, $reference, $this->scheduleTimezone);
				$this->fail("invalid {$cadence} schedule unexpectedly accepted");
			} catch (InvalidArgumentException $e) {
				$this->assertNotSame('', $e->getMessage());
			}
		}
	}

	public function testNextOccurrencePreservesLocalDstSlotsByScanningActualInstants(): void
	{
		date_default_timezone_set('America/New_York');
		$timezone = new DateTimeZone('America/New_York');
		$springReference = $this->timestamp('2026-03-08 01:00:00 EST');
		$this->assertSame(
			$this->timestamp('2026-03-09 02:15:00 EDT'),
			pfb_schedule_next_occurrence('EveryDay', 7, 2, 15, $springReference, $timezone),
			'nonexistent spring-forward local slot must be skipped'
		);

		$fallBefore = $this->timestamp('2026-11-01 00:00:00 EDT');
		$first = pfb_schedule_next_occurrence('EveryDay', 7, 1, 15, $fallBefore, $timezone);
		$this->assertSame($this->timestamp('2026-11-01 01:15:00 EDT'), $first);
		$this->assertSame(
			$this->timestamp('2026-11-01 01:15:00 EST'),
			pfb_schedule_next_occurrence('EveryDay', 7, 1, 15, (int) $first, $timezone),
			'repeated fall-back local slot must be observed twice'
		);
	}

	public function testWeeklyOccurrenceSearchCrossesMissingSpringForwardWeek(): void
	{
		$timezone = new DateTimeZone('America/New_York');
		$reference = $this->timestamp('2026-03-01 02:15:00 EST');

		$this->assertSame(
			$this->timestamp('2026-03-15 02:15:00 EDT'),
			pfb_schedule_next_occurrence('Weekly', 7, 2, 15, $reference, $timezone),
			'weekly search must continue after a nonexistent DST occurrence'
		);
	}

	public function testInjectedTimezoneMakesOccurrenceIndependentOfAmbientTimezone(): void
	{
		$timezone = new DateTimeZone('America/New_York');
		$reference = $this->timestamp('2026-01-05 00:00:00');
		date_default_timezone_set('UTC');
		$first = pfb_schedule_next_occurrence('EveryDay', 1, 2, 15, $reference, $timezone);
		date_default_timezone_set('America/New_York');
		$second = pfb_schedule_next_occurrence('EveryDay', 1, 2, 15, $reference, $timezone);

		$this->assertSame($first, $second, 'injected timezone must override ambient timezone');
	}

	public function testSchedulePlanUsesInheritedAndOverriddenSchedulesInInputOrder(): void
	{
		$default = ['weekday' => 7, 'hour' => 2, 'minute' => 15];
		$groups = [
			'inherited' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL],
			'overridden' => ['cadence' => 'Weekly', 'enabled' => TRUE, 'has_active_rows' => TRUE,
				'override' => ['weekday' => 1, 'hour' => 2, 'minute' => 30]],
			'disabled' => ['cadence' => 'EveryDay', 'enabled' => FALSE, 'has_active_rows' => TRUE, 'override' => NULL],
			'empty' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => FALSE, 'override' => NULL],
			'never' => ['cadence' => 'Never', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL],
		];
		$since = $this->timestamp('2026-01-05 01:00:00');
		$now = $this->timestamp('2026-01-05 03:00:00');
		$result = pfb_schedule_plan($groups, $default, $since, $now, $this->scheduleTimezone);

		$this->assertSame(['inherited', 'overridden'], $result['due']);
		$this->assertSame([
			'inherited' => $this->timestamp('2026-01-05 02:15:00'),
			'overridden' => $this->timestamp('2026-01-05 02:30:00'),
		], $result['occurrences']);
		$this->assertSame($this->timestamp('2026-01-06 02:15:00'), $result['next_due']);
	}

	public function testSchedulePlanUsesIndependentCursorsForDueAlreadyCompletedAndFutureGroups(): void
	{
		$default = ['weekday' => 1, 'hour' => 4, 'minute' => 0];
		$slot = $this->timestamp('2026-01-05 04:00:00');
		$groups = [
			'due' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL,
				'last_completed_occurrence' => $slot - 1],
			'already_completed' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL,
				'last_completed_occurrence' => $slot],
			'future_cursor' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL,
				'last_completed_occurrence' => $slot + 1],
		];

		$result = pfb_schedule_plan($groups, $default, NULL, $slot, $this->scheduleTimezone);

		$this->assertSame(['due'], $result['due']);
		$this->assertSame(['due' => $slot], $result['occurrences']);
		$this->assertSame($slot + 86400, $result['next_due']);
	}

	public function testSchedulePlanMissingSinceRunsEachEligibleGroupOnceAndFindsSharedWake(): void
	{
		$default = ['weekday' => 1, 'hour' => 4, 'minute' => 0];
		$groups = [
			'first' => ['cadence' => '01hour', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL],
			'shared' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL],
			'weekly' => ['cadence' => 'Weekly', 'enabled' => TRUE, 'has_active_rows' => TRUE,
				'override' => ['weekday' => 7, 'hour' => 5, 'minute' => 15]],
		];
		$now = $this->timestamp('2026-01-05 04:00:00');
		$result = pfb_schedule_plan($groups, $default, NULL, $now, $this->scheduleTimezone);

		$this->assertSame(['first', 'shared', 'weekly'], $result['due']);
		$this->assertSame([
			'first' => $now,
			'shared' => $now,
			'weekly' => $this->timestamp('2026-01-04 05:15:00'),
		], $result['occurrences']);
		$this->assertSame($this->timestamp('2026-01-05 05:00:00'), $result['next_due']);
	}

	public function testSchedulePlanAdvancingSincePreventsDuplicateDueAndHonorsSinceAfterNow(): void
	{
		$default = ['weekday' => 1, 'hour' => 4, 'minute' => 0];
		$groups = ['feed' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL]];
		$slot = $this->timestamp('2026-01-05 04:00:00');
		$due = pfb_schedule_plan($groups, $default, $slot - 1, $slot, $this->scheduleTimezone);
		$this->assertSame(['feed'], $due['due']);
		$this->assertSame(['feed' => $slot], $due['occurrences']);
		$this->assertSame([], pfb_schedule_plan($groups, $default, $slot, $slot, $this->scheduleTimezone)['due']);
		$this->assertSame([], pfb_schedule_plan($groups, $default, $slot + 1, $slot, $this->scheduleTimezone)['due']);
	}

	public function testSchedulePlanCollapsesMultipleMissedOccurrencesIntoOneDueResult(): void
	{
		$default = ['weekday' => 1, 'hour' => 0, 'minute' => 0];
		$groups = ['feed' => ['cadence' => '01hour', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL]];
		$since = $this->timestamp('2026-01-05 00:01:00');
		$now = $this->timestamp('2026-01-05 05:00:00');
		$result = pfb_schedule_plan($groups, $default, $since, $now, $this->scheduleTimezone);

		$this->assertSame(['feed'], $result['due'], 'five missed hourly slots must produce one due group');
		$this->assertSame(['feed' => $this->timestamp('2026-01-05 05:00:00')], $result['occurrences']);
		$this->assertSame($this->timestamp('2026-01-05 06:00:00'), $result['next_due']);

		$replayedGroup = $groups['feed'];
		$replayedGroup['last_completed_occurrence'] = $result['occurrences']['feed'];
		$replayed = pfb_schedule_plan(
			['feed' => $replayedGroup],
			$default,
			NULL,
			$now,
			$this->scheduleTimezone
		);
		$this->assertSame([], $replayed['due'], 'returned occurrence cursor must prevent replay');
		$this->assertSame([], $replayed['occurrences']);
	}

	public function testSchedulePlanMissingCursorUsesLatestRealSlotBeforeNonSlotNow(): void
	{
		$default = ['weekday' => 1, 'hour' => 0, 'minute' => 0];
		$groups = ['feed' => ['cadence' => '01hour', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL]];
		$now = $this->timestamp('2026-01-05 05:07:00');

		$result = pfb_schedule_plan($groups, $default, NULL, $now, $this->scheduleTimezone);

		$this->assertSame(['feed'], $result['due']);
		$this->assertSame(['feed' => $this->timestamp('2026-01-05 05:00:00')], $result['occurrences']);
	}

	public function testColdHourlyPlanMemoizesIdenticalFleetSchedules(): void
	{
		$default = ['weekday' => 1, 'hour' => 0, 'minute' => 0];
		$nextOccurrence = static function (
			string $cadence,
			int $weekday,
			int $hour,
			int $minute,
			int $reference,
			DateTimeZone $timezone,
			int &$calls
		): ?int {
			$calls++;
			return pfb_schedule_next_occurrence($cadence, $weekday, $hour, $minute, $reference, $timezone);
		};
		$one = ['feed_0' => [
			'cadence' => '01hour', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL,
		]];
		$singleCalls = 0;
		pfb_schedule_plan(
			$one,
			$default,
			NULL,
			$this->timestamp('2026-01-05 05:07:00'),
			$this->scheduleTimezone,
			static function (string $cadence, int $weekday, int $hour, int $minute, int $reference, DateTimeZone $timezone)
				use (&$singleCalls, $nextOccurrence): ?int {
				return $nextOccurrence($cadence, $weekday, $hour, $minute, $reference, $timezone, $singleCalls);
			}
		);
		$groups = [];
		for ($i = 0; $i < 5000; $i++) {
			$groups["feed_{$i}"] = [
				'cadence' => '01hour', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL,
			];
		}
		$fleetCalls = 0;
		$result = pfb_schedule_plan(
			$groups,
			$default,
			NULL,
			$this->timestamp('2026-01-05 05:07:00'),
			$this->scheduleTimezone,
			static function (string $cadence, int $weekday, int $hour, int $minute, int $reference, DateTimeZone $timezone)
				use (&$fleetCalls, $nextOccurrence): ?int {
				return $nextOccurrence($cadence, $weekday, $hour, $minute, $reference, $timezone, $fleetCalls);
			}
		);

		$this->assertCount(5000, $result['due']);
		$this->assertGreaterThan(0, $singleCalls);
		$this->assertSame($singleCalls, $fleetCalls,
			'identical schedules must share next/due occurrence resolution');
	}

	public function testSchedulePlanPreservesFamilyKeysIsIdempotentAndTiesNextWake(): void
	{
		$default = ['weekday' => 1, 'hour' => 4, 'minute' => 0];
		$groups = [
			'ipv4_feed' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL],
			'ipv6_feed' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL],
			'dnsbl_feed' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL],
		];
		$slot = $this->timestamp('2026-01-05 04:00:00');
		$first = pfb_schedule_plan($groups, $default, $slot - 1, $slot, $this->scheduleTimezone);
		$second = pfb_schedule_plan($groups, $default, $slot - 1, $slot, $this->scheduleTimezone);

		$this->assertSame(['ipv4_feed', 'ipv6_feed', 'dnsbl_feed'], $first['due']);
		$this->assertSame([
			'ipv4_feed' => $slot,
			'ipv6_feed' => $slot,
			'dnsbl_feed' => $slot,
		], $first['occurrences']);
		$this->assertSame($slot + 86400, $first['next_due']);
		$this->assertSame($first, $second, 'identical pure inputs must produce identical plans');
	}

	public function testSchedulePlanReturnsNoWakeWhenNoEligibleGroupsRemain(): void
	{
		$default = ['weekday' => 1, 'hour' => 4, 'minute' => 0];
		$groups = [
			'disabled' => ['cadence' => 'EveryDay', 'enabled' => FALSE, 'has_active_rows' => TRUE, 'override' => NULL],
			'empty' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => FALSE, 'override' => NULL],
			'never' => ['cadence' => 'Never', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL],
		];
		$result = pfb_schedule_plan($groups, $default, NULL, $this->timestamp('2026-01-05 04:00:00'), $this->scheduleTimezone);

		$this->assertSame(['due' => [], 'next_due' => NULL, 'occurrences' => []], $result);
	}

	public function testSchedulePlanRejectsMalformedNormalizedShapesWithoutCoercion(): void
	{
		$validDefault = ['weekday' => 1, 'hour' => 4, 'minute' => 0];
		$validGroup = ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL];
		$invalid = [
			[['feed' => 42], $validDefault],
			[[1 => $validGroup], $validDefault],
			[['feed' => ['enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL]], $validDefault],
			[['feed' => ['cadence' => 1, 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL]], $validDefault],
			[['feed' => ['cadence' => 'EveryDay', 'enabled' => 'on', 'has_active_rows' => TRUE, 'override' => NULL]], $validDefault],
			[['feed' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE,
				'override' => ['weekday' => 1, 'hour' => '4', 'minute' => 0]]], $validDefault],
			[['feed' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE,
				'override' => ['weekday' => 1, 'hour' => 4]]], $validDefault],
			[['feed' => $validGroup + ['last_completed_occurrence' => -1]], $validDefault],
			[['feed' => $validGroup + ['last_completed_occurrence' => 1.5]], $validDefault],
			[['feed' => $validGroup + ['last_completed_occurrence' => '1']], $validDefault],
			[['feed' => $validGroup + ['unexpected' => TRUE]], $validDefault],
			[['feed' => $validGroup], ['weekday' => 1, 'hour' => 4, 'minute' => 1]],
		];

		foreach ($invalid as [$groups, $default]) {
			try {
				pfb_schedule_plan($groups, $default, NULL, $this->timestamp('2026-01-05 00:00:00'), $this->scheduleTimezone);
				$this->fail('malformed normalized schedule unexpectedly accepted');
			} catch (InvalidArgumentException $e) {
				$this->assertNotSame('', $e->getMessage());
			}
		}
	}

	public function testSchedulePlanRejectsNonArrayDefaultScheduleWithTypeError(): void
	{
		$groups = ['feed' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL]];
		$this->expectException(TypeError::class);
		pfb_schedule_plan($groups, 'not-an-array', NULL, $this->timestamp('2026-01-05 00:00:00'), $this->scheduleTimezone);
	}
}
