<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

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

	public static function cadenceMatrix(): array
	{
		return [
			'01hour uses minute and dormant hour' => ['01hour', 'Deny_Inbound', TRUE, '22', '45', '9', '45', '2'],
			'02hours uses hour and minute' => ['02hours', 'Deny_Inbound', TRUE, '12', '0', '12', '0', '2'],
			'EveryDay uses hour and minute' => ['EveryDay', 'Deny_Inbound', TRUE, '18', '30', '18', '30', '2'],
			'Never preserves stored components' => ['Never', 'Deny_Inbound', TRUE, '18', '30', '9', '15', '2'],
			'Disabled preserves stored components' => ['02hours', 'Disabled', TRUE, '18', '30', '9', '15', '2'],
			'No active rows preserves stored components' => ['02hours', 'Deny_Inbound', FALSE, '18', '30', '9', '15', '2'],
		];
	}

	#[DataProvider('cadenceMatrix')]
	public function testCadenceMatrixPreservesDormantAndActiveComponents(
		string $cadence,
		string $action,
		bool $has_active_rows,
		string $submitted_hour,
		string $submitted_minute,
		string $expected_hour,
		string $expected_minute,
		string $expected_weekday
	): void {
		$result = pfb_category_schedule_validate(
			[
				'schedule_override' => 'on',
				'schedule_weekday' => '6',
				'schedule_hour' => $submitted_hour,
				'schedule_minute' => $submitted_minute,
			],
			$this->stored(),
			$this->general(),
			$cadence,
			$action,
			$has_active_rows
		);

		$this->assertSame([], $result['errors']);
		$this->assertSame([
			'schedule_override' => 'on',
			'schedule_weekday' => $expected_weekday,
			'schedule_hour' => $expected_hour,
			'schedule_minute' => $expected_minute,
		], $result['values']);
	}

	public static function dormantWeekdayMatrix(): array
	{
		return [
			'01hour invalid submitted weekday preserves stored' => ['01hour', '22', '45', '8', '2', '2', '9'],
			'02hours missing submitted weekday preserves stored' => ['02hours', '12', '0', NULL, '2', '2', '12'],
			'EveryDay invalid stored weekday seeds General' => ['EveryDay', '18', '30', '8', '9', '4', '18'],
		];
	}

	#[DataProvider('dormantWeekdayMatrix')]
	public function testActiveNonWeeklyInvalidOrMissingWeekdaySeedsGeneralDefault(
		string $cadence,
		string $hour,
		string $minute,
		?string $weekday,
		string $stored_weekday,
		string $expected_weekday,
		string $expected_hour,
		): void {
		$stored = $this->stored();
		$stored['schedule_weekday'] = $stored_weekday;
		$post = ['schedule_override' => 'on', 'schedule_hour' => $hour, 'schedule_minute' => $minute];
		if ($weekday !== NULL) {
			$post['schedule_weekday'] = $weekday;
		}
		$result = pfb_category_schedule_validate(
			$post,
			$stored,
			$this->general(),
			$cadence,
			'Deny_Inbound',
			TRUE
		);

		$this->assertSame([], $result['errors']);
		$this->assertSame([
			'schedule_override' => 'on',
			'schedule_weekday' => $expected_weekday,
			'schedule_hour' => $expected_hour,
			'schedule_minute' => $minute,
		], $result['values']);
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
		$controller = substr($source, $candidate, strpos($source, 'exit;', $candidate) - $candidate);
		$this->assertStringContainsString("\$failure = \$cache_ok ? '' : '&schcache=failed';", $controller);
		$this->assertStringNotContainsString('config_set_path(', $controller);
		$this->assertStringNotContainsString('config_del_path(', $controller);
		$this->assertStringNotContainsString('pfb_schedule_cache_refresh(', $controller);
	}

	public function testInvalidOverrideCannotReachConfigWrite(): void
	{
		$result = pfb_category_schedule_validate(
			['schedule_override' => 'on', 'schedule_weekday' => '8', 'schedule_hour' => '24', 'schedule_minute' => '5'],
			$this->stored(), $this->general(), 'Weekly', 'unbound', TRUE
		);
		$this->assertNotEmpty($result['errors']);
		$source = php_strip_whitespace(self::PAGE);
		$save = strpos($source, 'if ($_POST && isset($_POST[\'save\']))');
		$validate = strpos($source, 'pfb_category_schedule_validate(', $save);
		$gate = strpos($source, 'if (!$input_errors)', $validate);
		$write = strpos($source, 'write_config(', $gate);
		$this->assertNotFalse($validate);
		$this->assertNotFalse($gate);
		$this->assertNotFalse($write);
		$this->assertLessThan($write, $gate);
		$this->assertStringContainsString('$pfb_schedule_result[\'errors\']', substr($source, $validate, $gate - $validate));
	}

	public function testCandidateFailureIsNonDestructiveAndWarningNamesWorkaround(): void
	{
		$model = pfb_schedule_runtime_model([
			'pfb_scheduled_feed_updates' => '',
			'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '0',
			'pfb_schedule_minute' => '0',
		], ['ipv4' => [], 'ipv6' => [], 'dnsbl' => []]);
		$this->assertNotNull($model);
		$state = ['schema' => 1, 'items' => []];
		$active = sys_get_temp_dir() . '/pfb_active_' . bin2hex(random_bytes(4));
		mkdir($active, 0700, TRUE);
		$sentinel = '{"active":"must remain byte-identical"}';
		file_put_contents($active . '/pfb_due_ledger.json', $sentinel);
		$before = file_get_contents($active . '/pfb_due_ledger.json');
		$before_candidates = glob(sys_get_temp_dir() . '/pfb_sched_*') ?: [];
		try {
			$this->assertFalse(pfb_schedule_cache_candidate_validate($model, $state, 'UTC', time(), ['fail_rename' => TRUE]));
			$this->assertSame($before, file_get_contents($active . '/pfb_due_ledger.json'));
			$this->assertSame($before_candidates, glob(sys_get_temp_dir() . '/pfb_sched_*') ?: []);
		} finally {
			@unlink($active . '/pfb_due_ledger.json');
			@rmdir($active);
		}
		$source = strtolower(php_strip_whitespace(self::PAGE));
		$this->assertStringContainsString('settings remain saved', $source);
		$this->assertStringContainsString('likely a package bug', $source);
		$this->assertStringContainsString('manual updates remain available', $source);
	}
}
