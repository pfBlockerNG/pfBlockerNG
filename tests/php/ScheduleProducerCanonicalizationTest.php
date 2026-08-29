<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #2316: post-migration group producers emit only canonical schedule fields. */
final class ScheduleProducerCanonicalizationTest extends TestCase
{
	private const GENERAL = [
		'pfb_scheduled_feed_updates' => 'on',
		'pfb_schedule_weekday' => '7',
		'pfb_schedule_hour' => '2',
		'pfb_schedule_minute' => '30',
	];

	private static function sourceRegion(string $path, string $after, string $start, string $end): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . $path);
		if ($source === FALSE) {
			throw new RuntimeException("test bootstrap: failed to read {$path}");
		}
		$after_offset = strpos($source, $after);
		$start_offset = $after_offset === FALSE ? FALSE : strpos($source, $start, $after_offset);
		$end_offset = $start_offset === FALSE ? FALSE : strpos($source, $end, $start_offset);
		if ($start_offset === FALSE || $end_offset === FALSE) {
			throw new RuntimeException("test bootstrap: producer region not found in {$path}");
		}
		return substr($source, $start_offset, $end_offset - $start_offset);
	}

	private function easyListGroup(string $cron, mixed $dow, array $general = self::GENERAL): array
	{
		$add = [
			'row' => [['header' => 'easy', 'url' => 'https://example.test/easy', 'state' => 'Enabled']],
		];
		$ex_easylists = [
			'action' => 'unbound', 'cron' => $cron, 'dow' => $dow, 'logging' => 'enabled', 'order' => 'default',
		];
		$pfb_general_schedule = $general;
		eval(self::sourceRegion(
			'/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc',
			'// Upgrade EasyList to new Format',
			"\t\t\$add['action']",
			"\n\n\t\t\$dnsblcfg"
		));
		return $add;
	}

	private function wizardGroup(string $key, array $general = self::GENERAL): array
	{
		$add = [
			'row' => [['header' => 'wizard', 'url' => 'https://example.test/wizard', 'state' => 'Enabled']],
		];
		$pfb_general_schedule = $general;
		eval(self::sourceRegion(
			'/src/usr/local/www/wizards/pfblockerng_wizard.inc',
			'// Selected Alias/Groups to add to default installation',
			"\t\t\tif (strpos(\$key, 'dnsbl') !== FALSE)",
			"\n\t\t\t\$new_config[\$key]['config'][] = \$add;"
		));
		return $add;
	}

	private function schedule(array $group): array
	{
		return array_intersect_key($group, array_flip([
			'schedule_override', 'schedule_weekday', 'schedule_hour', 'schedule_minute',
		]));
	}

	public function testEasyListWeeklyConversionPreservesLegacyWeekdayAsCompleteOverride(): void
	{
		$group = $this->easyListGroup('Weekly', '3');

		$this->assertSame([
			'schedule_override' => 'on', 'schedule_weekday' => '3',
			'schedule_hour' => '2', 'schedule_minute' => '30',
		], $this->schedule($group));
		$this->assertArrayNotHasKey('dow', $group);

		$model = pfb_schedule_runtime_model(self::GENERAL, ['ipv4' => [], 'ipv6' => [], 'dnsbl' => [$group]]);
		$this->assertSame(
			['weekday' => 3, 'hour' => 2, 'minute' => 30],
			$model['entries']['dnsbl:easy']['override'] ?? NULL
		);
	}

	public function testEasyListNonWeeklyOrInvalidWeekdayInheritsDefault(): void
	{
		$daily = $this->easyListGroup('EveryDay', '5');
		$invalid = $this->easyListGroup('Weekly', ['bad']);

		$this->assertSame([
			'schedule_override' => '', 'schedule_weekday' => '5',
			'schedule_hour' => '2', 'schedule_minute' => '30',
		], $this->schedule($daily));
		$this->assertSame([
			'schedule_override' => '', 'schedule_weekday' => '7',
			'schedule_hour' => '2', 'schedule_minute' => '30',
		], $this->schedule($invalid));
		$this->assertArrayNotHasKey('dow', $daily);
		$this->assertArrayNotHasKey('dow', $invalid);

		$model = pfb_schedule_runtime_model(self::GENERAL, ['ipv4' => [], 'ipv6' => [], 'dnsbl' => [$daily]]);
		$this->assertArrayHasKey('dnsbl:easy', $model['entries']);
		$this->assertNull($model['entries']['dnsbl:easy']['override']);
	}

	public function testWizardGroupsInheritDefaultWithCompleteCanonicalRecords(): void
	{
		$ipv4 = $this->wizardGroup('pfblockernglistsv4');
		$dnsbl = $this->wizardGroup('pfblockerngdnsbl');
		$expected = [
			'schedule_override' => '', 'schedule_weekday' => '7',
			'schedule_hour' => '2', 'schedule_minute' => '30',
		];

		$this->assertSame($expected, $this->schedule($ipv4));
		$this->assertSame($expected, $this->schedule($dnsbl));
		$this->assertArrayNotHasKey('dow', $ipv4);
		$this->assertArrayNotHasKey('dow', $dnsbl);

		$model = pfb_schedule_runtime_model(self::GENERAL, ['ipv4' => [$ipv4], 'ipv6' => [], 'dnsbl' => [$dnsbl]]);
		$this->assertArrayHasKey('ipv4:wizard_v4', $model['entries']);
		$this->assertArrayHasKey('dnsbl:wizard', $model['entries']);
		$this->assertNull($model['entries']['ipv4:wizard_v4']['override']);
		$this->assertNull($model['entries']['dnsbl:wizard']['override']);
	}

	public function testProducerFallbacksCanonicalizeInvalidGeneralTokens(): void
	{
		$invalid = [
			'pfb_schedule_weekday' => ['bad'],
			'pfb_schedule_hour' => '24',
			'pfb_schedule_minute' => '14',
		];
		$expected = [
			'schedule_override' => '', 'schedule_weekday' => '7',
			'schedule_hour' => '0', 'schedule_minute' => '0',
		];

		$this->assertSame($expected, $this->schedule($this->easyListGroup('EveryDay', ['bad'], $invalid)));
		$this->assertSame($expected, $this->schedule($this->wizardGroup('pfblockernglistsv4', $invalid)));
	}
}
