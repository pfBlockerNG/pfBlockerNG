<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2308 General-page schedule controller contract.
 *
 * The pure validator is deliberately exercised off-appliance; source pins cover the
 * page's visible controls and save ordering without executing webConfigurator.
 */
final class GeneralScheduleUiTest extends TestCase
{
	private const GENERAL_PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_general.php';
	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	public function testValidScheduleAndWrappingWindowCanonicalize(): void
	{
		$result = pfb_general_schedule_validate([
			'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '23',
			'pfb_schedule_minute' => '45',
			'pfb_quiet_hours_enabled' => 'on',
			'pfb_quiet_hours_start' => '23:00',
			'pfb_quiet_hours_end' => '06:45',
		]);

		$this->assertSame([], $result['errors']);
		$this->assertSame('23:00-06:45', $result['values']['pfb_quiet_hours']);
	}

	public function testScheduleValidationRejectsArraysAndOutOfSetValues(): void
	{
		$result = pfb_general_schedule_validate([
			'pfb_scheduled_feed_updates' => ['on'],
			'pfb_schedule_weekday' => ['7'],
			'pfb_schedule_hour' => '24',
			'pfb_schedule_minute' => '5',
			'pfb_quiet_hours_enabled' => ['on'],
		]);

		$this->assertCount(5, $result['errors']);
		$this->assertSame([], $result['values']);
	}

	public function testDisabledWindowIgnoresMalformedEndpointsAndEqualWindowFails(): void
	{
		$disabled = pfb_general_schedule_validate([
			'pfb_scheduled_feed_updates' => '',
			'pfb_schedule_weekday' => '1',
			'pfb_schedule_hour' => '0',
			'pfb_schedule_minute' => '0',
			'pfb_quiet_hours_enabled' => '',
			'pfb_quiet_hours_start' => 'not-a-time',
			'pfb_quiet_hours_end' => ['06:00'],
		]);
		$this->assertSame([], $disabled['errors']);
		$this->assertSame('', $disabled['values']['pfb_quiet_hours']);

		$equal = pfb_general_schedule_validate([
			'pfb_schedule_weekday' => '1', 'pfb_schedule_hour' => '0', 'pfb_schedule_minute' => '0',
			'pfb_quiet_hours_enabled' => 'on', 'pfb_quiet_hours_start' => '06:00', 'pfb_quiet_hours_end' => '06:00',
		]);
		$this->assertCount(1, $equal['errors']);
	}

	public function testGeneralPageContainsSchedulingControlsAndRemovesLegacyControls(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);

		foreach ([
			'pfb_scheduled_feed_updates', 'pfb_schedule_weekday', 'pfb_schedule_hour',
			'pfb_schedule_minute', 'pfb_quiet_hours_enabled', 'pfb_quiet_hours_start',
			'pfb_quiet_hours_end', 'Automatic Apply Window',
		] as $needle) {
			$this->assertStringContainsString($needle, $source, "General page missing {$needle}");
		}
		foreach (["'pfb_interval'", "'pfb_min'", "'pfb_hour'", "'pfb_dailystart'"] as $needle) {
			$this->assertStringNotContainsString($needle, $source, "retired General control remains: {$needle}");
		}
	}

	/** Issue #3941: Core owns the schedule, so a save writes config, tells Core, syncs the package and redirects with no cache hand-off. */
	public function testSaveWritesConfigThenTellsCoreAndRedirectsPlainly(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$save = strpos($source, 'if (isset($_POST[\'save\'])) {');
		$this->assertNotFalse($save);
		$write = strpos($source, 'PfbConfig::writeSection(', $save);
		$notice = strpos($source, 'pfb_core_settings_changed(NULL, TRUE)', $save);
		$this->assertNotFalse($write);
		$this->assertNotFalse($notice, 'Core must be told of the saved settings');
		$this->assertLessThan($notice, $write, 'config must be persisted before Core is told');
		$this->assertStringContainsString("header('Location: /pfblockerng/pfblockerng_general.php');", $source);
		$this->assertStringContainsString('$pfb[\'save\'] = TRUE; sync_package_pfblockerng();', $source);
		$this->assertMatchesRegularExpression('/pfblockerng_configure_tick_cron\(\s*\$pfb\[\'enable\'\]\s*===\s*PfbToggle::On,\s*\$pfb\[\'log\'\]\s*\)/', php_strip_whitespace(self::APPLY),
			'settings-save sync installs the tick cron only: no schedule cache is regenerated or replaced (issue #3941)');
	}

	public function testAuthorizationRemainsGatewayBound(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$this->assertStringContainsString('PfbConfig::writeSection(', $source);
		$this->assertStringNotContainsString('config_set_path(', $source);
		$this->assertStringContainsString('write_config(', $source);
	}
}
