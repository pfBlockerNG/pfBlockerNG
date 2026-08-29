<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2308 General-page schedule controller contract.
 *
 * The pure validator is deliberately exercised off-appliance; source pins cover the
 * page's visible controls and save/cache ordering without executing webConfigurator.
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
		$this->assertStringContainsString(
			'Default local-time schedule for feed groups and calendar-scheduled Extras. Hourly schedules use the minute; daily schedules use the time; weekly schedules use all three.',
			$source
		);
		$group = strpos($source, "new Form_Group('Default Schedule')");
		$this->assertNotFalse($group);
		$help = strpos($source, 'Default local-time schedule for feed groups and calendar-scheduled Extras.', $group);
		$next = strpos($source, "new Form_Checkbox('pfb_quiet_hours_enabled'", $group);
		$this->assertNotFalse($help);
		$this->assertNotFalse($next);
		$this->assertLessThan($next, $help, 'Default Schedule help must render inside its control group.');
		// issue #2855: the warning names the failing stage instead of asking for a bug report.
		$this->assertStringContainsString(
			"print_info_box(sprintf(gettext('Settings were saved, but schedule-cache generation failed: %s.",
			$source
		);
	}

	public function testSaveWritesConfigBeforeRefreshingScheduleCacheAndRedirectsOnFailure(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$save = strpos($source, 'if (isset($_POST[\'save\'])) {');
		$this->assertNotFalse($save);
		$write = strpos($source, 'PfbConfig::writeSection(', $save);
		$cache = strpos($source, 'pfb_schedule_cache_refresh(', $save);
		$redirect = strpos($source, 'schcache=failed', $save);
		$this->assertNotFalse($write);
		$this->assertNotFalse($cache, 'save must refresh the derived schedule cache');
		$this->assertNotFalse($redirect, 'cache failure must be visible after redirect');
		$this->assertLessThan($cache, $write, 'config must be persisted before cache publication');
	}

	public function testCandidateFailureSelectsVisibleFailureRedirect(): void
	{
		$model = pfb_schedule_runtime_model([
			'pfb_scheduled_feed_updates' => '',
			'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '0',
			'pfb_schedule_minute' => '0',
		], ['ipv4' => [], 'ipv6' => [], 'dnsbl' => []]);
		$this->assertNotNull($model);
		$candidate = sys_get_temp_dir() . '/pfb_schedule_candidate_' . uniqid('', TRUE);
		mkdir($candidate, 0700, TRUE);

		try {
			$this->assertFalse(pfb_schedule_cache_refresh(
				$model,
				['schema' => 1, 'items' => []],
				time(),
				new DateTimeZone('UTC'),
				$candidate,
				['fail_rename' => TRUE]
			));
			$this->assertSame('/pfblockerng/pfblockerng_general.php?schcache=failed',
				pfb_general_schedule_save_redirect(FALSE));
			$this->assertSame('/pfblockerng/pfblockerng_general.php',
				pfb_general_schedule_save_redirect(TRUE));
		} finally {
			@unlink($candidate . '/pfb_due_ledger.json');
			@unlink($candidate . '/pfb_due_ledger.json.lock');
			@rmdir($candidate);
		}
		$this->assertStringContainsString('pfb_general_schedule_save_redirect( $cache_ok,',
			php_strip_whitespace(self::GENERAL_PAGE));
	}

	public function testSaveStagesCandidateWithoutPublishingActiveCache(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$save = strpos($source, 'if (isset($_POST[\'save\'])) {');
		$this->assertNotFalse($save);
		$cache = strpos($source, 'pfb_schedule_cache_refresh(', $save);
		$this->assertNotFalse($cache);
		$window = substr($source, $save, strpos($source, '$pfb[\'save\']', $cache) - $save);
		$this->assertStringContainsString('sys_get_temp_dir()', $window);
		$this->assertStringContainsString('$pfb[\'schedule_state_dir\'] ?? \'/usr/local/etc\'', $window,
			'candidate validation must use the same durable state directory as tick and apply');
		$this->assertStringNotContainsString('pfb_schedule_cache_refresh($runtime_model, $runtime_state, time(), $runtime_timezone, $pfb', $window);
		$this->assertStringContainsString('$pfb[\'save\'] = TRUE; sync_package_pfblockerng();', $source);
		$this->assertMatchesRegularExpression('/pfblockerng_configure_tick_cron\(\s*\$pfb\[\'enable\'\]\s*===\s*PfbToggle::On,\s*\$pfb\[\'log\'\],\s*NULL,\s*FALSE\s*\)/', php_strip_whitespace(self::APPLY),
			'settings-save sync must not regenerate or replace the active cache');
	}

	public function testSaveRemovesEveryDisposableCandidateArtifact(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$this->assertMatchesRegularExpression(
			'/foreach\s*\(scandir\(\$candidate_dir\)\s*\?:\s*\[\]\s+as\s+\$candidate_artifact\)\s*\{\s*'
			. 'if\s*\(\$candidate_artifact\s*!==\s*\x27\.\x27\s*&&\s*\$candidate_artifact\s*!==\s*\x27\.\.\x27\)\s*\{\s*'
			. '@unlink\("\{\$candidate_dir\}\/\{\$candidate_artifact\}"\);/',
			$source,
			'Candidate cleanup must not assume the publisher created only two filenames.'
		);
	}

	public function testAuthorizationRemainsGatewayBound(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$this->assertStringContainsString('PfbConfig::writeSection(', $source);
		$this->assertStringNotContainsString('config_set_path(', $source);
		$this->assertStringContainsString('write_config(', $source);
	}
}
