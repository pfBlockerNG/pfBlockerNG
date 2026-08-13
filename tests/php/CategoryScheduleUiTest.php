<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #2309: feed-group schedule controls and config-authoritative save. */
final class CategoryScheduleUiTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';

	private function general(): array
	{
		return [
			'pfb_schedule_weekday' => '4',
			'pfb_schedule_hour' => '6',
			'pfb_schedule_minute' => '30',
		];
	}

	private function stored(): array
	{
		return [
			'schedule_override' => 'on',
			'schedule_weekday' => '2',
			'schedule_hour' => '9',
			'schedule_minute' => '15',
		];
	}

	public function testOverrideOffPreservesStoredValuesAndDoesNotUseSubmittedValues(): void
	{
		$result = pfb_category_schedule_validate([
			'schedule_override' => '',
			'schedule_weekday' => '7',
			'schedule_hour' => '23',
			'schedule_minute' => '45',
		], $this->stored(), $this->general(), 'EveryDay', 'Deny_Inbound', TRUE);

		$this->assertSame([], $result['errors']);
		$this->assertSame([
			'schedule_override' => '',
			'schedule_weekday' => '2',
			'schedule_hour' => '9',
			'schedule_minute' => '15',
		], $result['values']);
	}

	public function testMissingOrInvalidStoredValuesSeedCurrentGeneralDefaults(): void
	{
		$result = pfb_category_schedule_validate(
			['schedule_override' => ''],
			['schedule_override' => '', 'schedule_weekday' => ['bad'], 'schedule_hour' => '99', 'schedule_minute' => '5'],
			$this->general(), 'Never', 'Disabled', FALSE
		);

		$this->assertSame([], $result['errors']);
		$this->assertSame(['schedule_override' => '', 'schedule_weekday' => '4', 'schedule_hour' => '6', 'schedule_minute' => '30'], $result['values']);
	}

	public function testWeeklyRequiresAllCanonicalComponents(): void
	{
		$result = pfb_category_schedule_validate(
			['schedule_override' => 'on', 'schedule_weekday' => '7', 'schedule_hour' => '23', 'schedule_minute' => '45'],
			$this->stored(), $this->general(), 'Weekly', 'unbound', TRUE
		);

		$this->assertSame([], $result['errors']);
		$this->assertSame(['schedule_override' => 'on', 'schedule_weekday' => '7', 'schedule_hour' => '23', 'schedule_minute' => '45'], $result['values']);
	}

	public function testActiveNonWeeklyRequiresHourMinuteAndPreservesDormantWeekday(): void
	{
		$result = pfb_category_schedule_validate(
			['schedule_override' => 'on', 'schedule_hour' => '12', 'schedule_minute' => '0'],
			$this->stored(), $this->general(), '02hours', 'Deny_Inbound', TRUE
		);

		$this->assertSame([], $result['errors']);
		$this->assertSame(['schedule_override' => 'on', 'schedule_weekday' => '2', 'schedule_hour' => '12', 'schedule_minute' => '0'], $result['values']);
	}

	public function testArrayAndNonCanonicalScheduleInputsRejectSave(): void
	{
		$result = pfb_category_schedule_validate(
			['schedule_override' => ['on'], 'schedule_weekday' => '8', 'schedule_hour' => '24', 'schedule_minute' => '5'],
			$this->stored(), $this->general(), 'Weekly', 'Deny_Inbound', TRUE
		);

		$this->assertCount(4, $result['errors']);
		$this->assertSame([], $result['values']);
	}

	public function testCategoryEditorRendersCanonicalControlsForAllFamiliesAndRetiresDow(): void
	{
		$source = php_strip_whitespace(self::PAGE);
		foreach (['schedule_override', 'schedule_weekday', 'schedule_hour', 'schedule_minute', 'Override Default Schedule', 'Schedule'] as $needle) {
			$this->assertStringContainsString($needle, $source);
		}
		$this->assertStringNotContainsString("'dow'", $source);
		$this->assertStringContainsString("\$gtype == 'ipv4' || \$gtype == 'ipv6'", $source);
		$this->assertStringContainsString("\$gtype == 'dnsbl'", $source);
		$this->assertStringContainsString('disabled', $source);
		$this->assertStringContainsString('schcache=failed', $source);
		$this->assertStringContainsString('settings remain saved', strtolower($source));
		$this->assertStringContainsString('manual updates', strtolower($source));
	}

	public function testSavePersistsBeforeCandidateAndNeverPublishesActiveCache(): void
	{
		$source = php_strip_whitespace(self::PAGE);
		$save = strpos($source, 'if ($_POST && isset($_POST[\'save\']))');
		$this->assertNotFalse($save);
		$write = strpos($source, 'write_config(', $save);
		$candidate = strpos($source, 'pfb_schedule_cache_candidate_validate(', $save);
		$pending = strpos($source, 'pfb_mark_pending_changes()', $save);
		$this->assertNotFalse($write);
		$this->assertNotFalse($candidate);
		$this->assertNotFalse($pending);
		$this->assertLessThan($candidate, $write);
		$this->assertLessThan($pending, $candidate);
		$this->assertStringNotContainsString("pfb_schedule_cache_refresh(\$runtime_model, \$runtime_state, time(), \$runtime_timezone, \$pfb['dbdir']", substr($source, $candidate, $pending - $candidate));
	}

	public function testCandidateFailureIsNonDestructiveAndWarningNamesWorkaround(): void
	{
		$this->assertFalse(pfb_schedule_cache_candidate_validate(NULL, NULL, 'UTC'));
		$source = strtolower(php_strip_whitespace(self::PAGE));
		$this->assertStringContainsString('settings remain saved', $source);
		$this->assertStringContainsString('likely a package bug', $source);
		$this->assertStringContainsString('manual updates remain available', $source);
	}
}
