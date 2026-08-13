<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #2316: the setup wizard reset keeps the persisted Default Schedule. */
final class WizardScheduleResetTest extends TestCase
{
	private const WIZARD = '/src/usr/local/www/wizards/pfblockerng_wizard.inc';

	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . self::WIZARD);
		if ($source === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read wizard source');
		}
		return $source;
	}

	public function testWizardCapturesScheduleBeforeRemovingPackageConfig(): void
	{
		$source = self::source();
		$capture = strpos($source, "\t\$pfb_general_schedule = PfbConfig::readSection('installedpackages/pfblockerng/config/0');");
		$remove = $capture === FALSE ? FALSE : strpos($source, "\n\tpfb_remove_config_settings();", $capture);
		if ($capture === FALSE || $remove === FALSE) {
			throw new RuntimeException('test bootstrap: wizard capture/reset region not found');
		}

		$expected = [
			'pfb_scheduled_feed_updates' => '',
			'pfb_schedule_weekday' => '4',
			'pfb_schedule_hour' => '5',
			'pfb_schedule_minute' => '45',
			'skipfeed' => '0',
		];
		$saved_config = $GLOBALS['config'] ?? NULL;
		try {
			$GLOBALS['config'] = ['installedpackages' => [
				'pfblockerng' => ['config' => [$expected]],
				'pfblockernglistsv4' => ['config' => [['aliasname' => 'removed']]],
			]];
			eval(substr($source, $capture, $remove + strlen("\n\tpfb_remove_config_settings();") - $capture));

			$this->assertSame($expected, $pfb_general_schedule);
			$this->assertSame([], config_get_path('installedpackages', []));
		} finally {
			$GLOBALS['config'] = $saved_config;
		}
	}

	public function testWizardResetPersistsCanonicalGeneralSchedule(): void
	{
		$source = self::source();
		$start = strpos($source, "\t\$new_config = config_get_path('installedpackages');");
		$end = $start === FALSE ? FALSE : strpos($source, "\n\n\t\$new_config['pfblockerngipsettings']", $start);
		if ($start === FALSE || $end === FALSE) {
			throw new RuntimeException('test bootstrap: wizard General reset region not found');
		}

		$saved_config = $GLOBALS['config'] ?? NULL;
		$cases = [
			'absent' => [NULL, 'on'],
			'canonical off' => ['', ''],
			'canonical on' => ['on', 'on'],
			'legacy off' => ['off', ''],
			'case variant' => ['OFF', ''],
			'junk' => ['junk', ''],
			'non-scalar' => [['on'], ''],
		];
		try {
			foreach ($cases as $name => [$raw_master, $expected_master]) {
				$GLOBALS['config'] = ['installedpackages' => []];
				$pfb_general_schedule = [
					'pfb_schedule_weekday' => '4',
					'pfb_schedule_hour' => '5',
					'pfb_schedule_minute' => '45',
					'skipfeed' => '0',
				];
				if ($raw_master !== NULL) {
					$pfb_general_schedule['pfb_scheduled_feed_updates'] = $raw_master;
				}
				eval(substr($source, $start, $end - $start));

				$this->assertSame([
					'pfb_scheduled_feed_updates' => $expected_master,
					'pfb_schedule_weekday' => '4',
					'pfb_schedule_hour' => '5',
					'pfb_schedule_minute' => '45',
					'skipfeed' => '0',
				], array_intersect_key(
					$new_config['pfblockerng']['config'][0],
					array_flip(['pfb_scheduled_feed_updates', 'pfb_schedule_weekday', 'pfb_schedule_hour', 'pfb_schedule_minute', 'skipfeed'])
				), $name);
			}
		} finally {
			$GLOBALS['config'] = $saved_config;
		}
	}
}
