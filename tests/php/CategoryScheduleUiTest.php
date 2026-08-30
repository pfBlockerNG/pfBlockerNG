<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/** Issue #2309: feed-group schedule controls and config-authoritative save. */
final class CategoryScheduleUiTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';

	private static function executeControllerScheduleGate(array $post): array
	{
		if (!function_exists('pfb_category_schedule_gate_oracle')) {
			$source = php_strip_whitespace(self::PAGE);
			if (!preg_match('/(\$pfb_schedule_result = pfb_category_schedule_validate\(.*?)(?=if \(!\$input_errors\) \{)/s', $source, $match)) {
				throw new RuntimeException('category schedule controller gate not found');
			}
			eval(
			'function pfb_category_schedule_gate_oracle(array $post): array {'
			. ' $_POST = array_merge(['
			. "'aliasname' => 'validname', 'action' => 'Disabled', 'gtype' => 'ipv4',"
			. "'autoaddrnot_in' => '', 'autoaddrnot_out' => '', 'custom' => '', 'whois_convert' => '',"
			. "'suppression_cidr' => 'Disabled', 'suppression_cidr_v6' => 'Disabled',"
			. "'format-0' => 'auto', 'state-0' => 'Disabled', 'url-0' => '', 'header-0' => ''], \$post);"
			. ' $gtype = "ipv4"; $type = "IP"; $input_errors = []; $write_count = 0;'
			. ' $options_action = []; $options_suppression_cidr = []; $options_suppression_cidr_v6 = []; $line = 1;'
			. ' $pfb_schedule_stored = []; $pfb_schedule_general_input = ['
			. "'pfb_schedule_weekday' => '4', 'pfb_schedule_hour' => '6', 'pfb_schedule_minute' => '30'];"
			. ' $pfb_schedule_active_rows = TRUE;'
			. $match[1]
			. ' if (!$input_errors) { $write_count++; }'
			. " return ['errors' => \$input_errors, 'writes' => \$write_count]; }"
		);
		}
		return pfb_category_schedule_gate_oracle($post);
	}

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
			'01hour uses minute and submitted dormant weekday' => ['01hour', 'Deny_Inbound', TRUE, '22', '45', '9', '45', '6'],
			'02hours uses hour and submitted dormant weekday' => ['02hours', 'Deny_Inbound', TRUE, '12', '0', '12', '0', '6'],
			'EveryDay uses hour and submitted dormant weekday' => ['EveryDay', 'Deny_Inbound', TRUE, '18', '30', '18', '30', '6'],
			'Never stages submitted components' => ['Never', 'Deny_Inbound', TRUE, '18', '30', '18', '30', '6'],
			'Disabled stages submitted components' => ['02hours', 'Disabled', TRUE, '18', '30', '18', '30', '6'],
			'No active rows stages submitted components' => ['02hours', 'Deny_Inbound', FALSE, '18', '30', '18', '30', '6'],
			'Inactive Weekly stages all components' => ['Weekly', 'Disabled', TRUE, '18', '30', '18', '30', '6'],
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
			'01hour missing weekday uses stored' => ['01hour', '22', '45', NULL, '2', '2', '9', TRUE],
			'02hours missing weekday uses stored' => ['02hours', '12', '0', NULL, '2', '2', '12', TRUE],
			'EveryDay invalid weekday rejects direct POST' => ['EveryDay', '18', '30', '8', '2', '2', '18', FALSE],
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
		bool $valid,
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

		if (!$valid) {
			$this->assertNotEmpty($result['errors']);
			return;
		}
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

	public static function hourlyDormantHourMatrix(): array
	{
		return [
			'missing dormant hour preserves stored value' => [NULL, TRUE],
			'out of range dormant hour rejects direct POST' => ['24', FALSE],
			'non-numeric dormant hour rejects direct POST' => ['bad', FALSE],
			'array dormant hour rejects direct POST' => [['24'], FALSE],
		];
	}

	#[DataProvider('hourlyDormantHourMatrix')]
	public function testActiveHourlyDormantHourMissingOrInvalid(mixed $hour, bool $valid): void
	{
		$post = ['schedule_override' => 'on', 'schedule_minute' => '45'];
		if ($hour !== NULL) {
			$post['schedule_hour'] = $hour;
		}
		$result = pfb_category_schedule_validate(
			$post,
			$this->stored(),
			$this->general(),
			'01hour',
			'Deny_Inbound',
			TRUE
		);
		if (!$valid) {
			$this->assertNotEmpty($result['errors']);
			return;
		}
		$this->assertSame([], $result['errors']);
		$this->assertSame('9', $result['values']['schedule_hour']);
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
		$candidate = strpos($source, 'pfb_schedule_cache_candidate_stage(', $save);
		$pending = strpos($source, 'pfb_mark_pending_changes()', $save);
		$this->assertNotFalse($write);
		$this->assertNotFalse($candidate);
		$this->assertNotFalse($pending);
		$this->assertLessThan($candidate, $write);
		$this->assertLessThan($pending, $candidate);
		$controller = substr($source, $candidate, strpos($source, 'exit;', $candidate) - $candidate);
		$this->assertStringContainsString(
			"\$failure = \$cache_ok ? '' : '&schcache=failed&schstage=' . \$cache_stage;", $controller,
			'the failure redirect must carry which stage failed (issue #2888)');
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
		$validation_window = substr($source, $validate, $gate - $validate + 24);
		$this->assertStringContainsString('$pfb_schedule_result[\'errors\']', $validation_window);
		$this->assertStringNotContainsString('$input_errors = array ();', $validation_window);
	}

	public function testInvalidOverrideControllerGateDoesNotMutateOrWrite(): void
	{
		$GLOBALS['config'] = ['installedpackages' => ['pfblockernglistsv4' => ['config' => [['aliasname' => 'before']]]]];
		$before = $GLOBALS['config'];
		$result = self::executeControllerScheduleGate([
			'schedule_override' => 'on', 'schedule_weekday' => '8', 'schedule_hour' => '24', 'schedule_minute' => '5',
		]);
		$this->assertNotEmpty($result['errors']);
		$this->assertSame(0, $result['writes']);
		$this->assertSame($before, $GLOBALS['config']);
	}

	public function testAbsentStateWithNonEmptyUrlCountsAsActiveRow(): void
	{
		$source = php_strip_whitespace(self::PAGE);
		$this->assertStringContainsString("str_starts_with((string) \$pfb_schedule_key, 'url-')", $source);
		$this->assertStringContainsString("\$_POST['state-' . substr((string) \$pfb_schedule_key, 4)] ?? ''", $source);
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
		$this->assertStringContainsString('candidate generation failed: %s', $source,
			'the warning must name the failing stage (issue #2888)');
		$this->assertStringContainsString('manual updates remain available', $source);
		$this->assertStringNotContainsString('likely a package bug', $source);
	}

	public function testCandidateSuccessUsesPrivateDirectoryAndRejectsInvalidTimezoneWithoutWarning(): void
	{
		$model = pfb_schedule_runtime_model([
			'pfb_scheduled_feed_updates' => '', 'pfb_schedule_weekday' => '7', 'pfb_schedule_hour' => '0', 'pfb_schedule_minute' => '0',
		], ['ipv4' => [], 'ipv6' => [], 'dnsbl' => []]);
		$this->assertNotNull($model);
		$active = sys_get_temp_dir() . '/pfb_active_' . bin2hex(random_bytes(4));
		mkdir($active, 0700, TRUE);
		$sentinel = '{"active":"must remain byte-identical"}';
		file_put_contents($active . '/pfb_due_ledger.json', $sentinel);
		$before_candidates = glob(sys_get_temp_dir() . '/pfb_sched_*') ?: [];
		set_error_handler(static function (): bool { throw new RuntimeException('unexpected warning'); });
		try {
			$this->assertTrue(pfb_schedule_cache_candidate_validate($model, ['schema' => 1, 'items' => []], 'UTC', time(), ['active_dir' => $active]));
		} finally {
			restore_error_handler();
		}
		$this->assertSame($sentinel, file_get_contents($active . '/pfb_due_ledger.json'));
		$this->assertSame($before_candidates, glob(sys_get_temp_dir() . '/pfb_sched_*') ?: []);
		$warnings = [];
		set_error_handler(static function (int $severity, string $message) use (&$warnings): bool { $warnings[] = $message; return TRUE; });
		try {
			$this->assertFalse(pfb_schedule_cache_candidate_validate($model, ['schema' => 1, 'items' => []], ['bad'], time()));
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $warnings);
		@unlink($active . '/pfb_due_ledger.json');
		@rmdir($active);
	}

	public function testCandidateExtremeStateReturnsFalseWithoutLeakingTemporaryArtifacts(): void
	{
		$group = ['action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'schedule_override' => '', 'schedule_weekday' => '1', 'schedule_hour' => '4', 'schedule_minute' => '30', 'row' => [['header' => 'feed', 'url' => 'https://192.0.2.1/feed', 'state' => 'Enabled']]];
		$model = pfb_schedule_runtime_model(
			['pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7', 'pfb_schedule_hour' => '2', 'pfb_schedule_minute' => '15'],
			['ipv4' => [$group], 'ipv6' => [], 'dnsbl' => []]
		);
		$this->assertNotNull($model);
		$before = glob(sys_get_temp_dir() . '/pfb_sched_*') ?: [];
		$state = ['schema' => 1, 'items' => ['ipv4:feed_v4' => [
			'last_completed_occurrence' => PHP_INT_MAX,
			'completion_outcome' => 'success',
		]]];
		$this->assertTrue(pfb_schedule_state_valid($state));
		$this->assertFalse(pfb_schedule_cache_candidate_validate($model, $state, 'UTC', time()));
		$this->assertSame($before, glob(sys_get_temp_dir() . '/pfb_sched_*') ?: []);
	}
}
