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
		$capture = strpos($source, "\$pfb_general_schedule = PfbConfig::readSection('installedpackages/pfblockerng/config/0');");
		$remove = strpos($source, 'pfb_remove_config_settings();');

		$this->assertNotFalse($capture, 'wizard must capture the persisted Default Schedule');
		$this->assertNotFalse($remove, 'wizard config-removal call must remain present');
		$this->assertLessThan($remove, $capture, 'Default Schedule must be captured before the wizard removes package config');
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
		$GLOBALS['config'] = ['installedpackages' => []];
		$pfb_general_schedule = [
			'pfb_scheduled_feed_updates' => '',
			'pfb_schedule_weekday' => '4',
			'pfb_schedule_hour' => '5',
			'pfb_schedule_minute' => '45',
			'skipfeed' => '0',
		];
		eval(substr($source, $start, $end - $start));
		$GLOBALS['config'] = $saved_config;

		$this->assertSame([
			'pfb_scheduled_feed_updates' => '',
			'pfb_schedule_weekday' => '4',
			'pfb_schedule_hour' => '5',
			'pfb_schedule_minute' => '45',
			'skipfeed' => '0',
		], array_intersect_key($new_config['pfblockerng']['config'][0], $pfb_general_schedule));
	}
}
