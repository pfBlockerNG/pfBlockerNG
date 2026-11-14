<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_core_schedule_faults')]
final class CoreScheduleProviderTitleTest extends TestCase
{
	public function testCoreCannotRewriteTheBlacklistProviderTitle(): void
	{
		$current = [
			'scheduledUpdates' => TRUE,
			'weekday' => 7,
			'hour' => 0,
			'minute' => 0,
			'groups' => [],
			'categoryUpdates' => TRUE,
			'categoryFrequency' => 'EveryDay',
			'categoryProviders' => [[
				'id' => 'work', 'title' => 'Work', 'selected' => TRUE, 'categories' => 'adult',
			]],
		];
		$wanted = $current;
		$wanted['categoryProviders'][0]['title'] = 'Other';

		$faults = pfb_core_schedule_faults($wanted, $current);
		$titleFaults = array_values(array_filter($faults, static fn(array $fault): bool =>
			$fault['field'] === 'schedule.categoryProviders[0].title'));

		$this->assertCount(1, $titleFaults);
		$this->assertSame('read-only', $titleFaults[0]['message']);
	}
}
