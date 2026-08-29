<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2855: an incomplete list group must not void the whole schedule model, and a
 * genuine rejection must name the check and the alias responsible -- in the system log,
 * and as a named stage in the General page warning instead of a bare "report a bug".
 */
final class ScheduleRuntimeDiagnosticsTest extends TestCase
{
	private const GENERAL_PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_general.php';

	private const GENERAL = [
		'pfb_scheduled_feed_updates' => 'on',
		'pfb_schedule_weekday'       => '7',
		'pfb_schedule_hour'          => '2',
		'pfb_schedule_minute'        => '15',
	];

	private const STAGES = ['config', 'state', 'timezone', 'workdir', 'refresh', 'readback'];

	private mixed $originalConfig = NULL;

	protected function setUp(): void
	{
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] ??= [];
		$GLOBALS['pfb_test_logger_calls'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->originalConfig;
		$GLOBALS['pfb_test_logger_calls'] = [];
	}

	/**
	 * Scenario: one alias carries no 'row' key at all -- a group that describes no feed
	 * rows. Expected: it contributes no entries, and every other alias still schedules.
	 */
	public function testGroupWithoutRowKeyLeavesTheRestOfTheModelIntact(): void
	{
		$rowless = ['aliasname' => 'No_Rows', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay'];
		$healthy = ['aliasname' => 'Healthy', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay',
			'row' => [['header' => 'healthy', 'url' => 'https://192.0.2.1/healthy', 'state' => 'Enabled']]];

		$model = pfb_schedule_runtime_model(self::GENERAL,
			['ipv4' => [$rowless, $healthy], 'ipv6' => [], 'dnsbl' => []]);

		$this->assertIsArray($model,
			"an alias with no 'row' key describes no feed rows; it must not void the whole schedule model");
		$this->assertSame(['ipv4:healthy_v4'], array_keys($model['entries']),
			'the row-less alias contributes no entries, and the healthy alias still schedules');
	}

	/** NULL stays reserved for input that is genuinely malformed, not merely incomplete. */
	public function testMalformedRowValueStillRejectsTheModel(): void
	{
		$broken = ['aliasname' => 'Broken', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'row' => 'not-a-list'];

		$this->assertNull(pfb_schedule_runtime_model(self::GENERAL,
			['ipv4' => [$broken], 'ipv6' => [], 'dnsbl' => []]),
			"'row' present but not a list is corrupt config, and must still reject the model");
	}

	/** A rejection reports which check failed and which alias tripped it. */
	public function testRejectionReasonNamesTheFailingCheckAndTheAlias(): void
	{
		$reason = NULL;
		$broken = ['aliasname' => 'Broken_List', 'action' => 'Deny_Inbound', 'cron' => 'Fortnightly',
			'row' => [['header' => 'broken', 'url' => 'https://192.0.2.1/broken']]];

		$this->assertNull(pfb_schedule_runtime_model(self::GENERAL,
			['ipv4' => [$broken], 'ipv6' => [], 'dnsbl' => []], [], $reason));

		$this->assertIsString($reason, 'a rejected model must report which check failed');
		$this->assertStringContainsString('Broken_List', $reason,
			"the reason must name the alias responsible; got: " . var_export($reason, TRUE));
		$this->assertStringContainsString('cron', $reason,
			"the reason must name the failing check; got: " . var_export($reason, TRUE));
		$this->assertStringContainsString('ipv4', $reason,
			"the reason must name the section; got: " . var_export($reason, TRUE));
	}

	/** Before-state: an accepted model clears any reason the caller passed in. */
	public function testAcceptedModelReportsNoReason(): void
	{
		$reason = 'stale reason from an earlier call';

		$this->assertIsArray(pfb_schedule_runtime_model(self::GENERAL,
			['ipv4' => [], 'ipv6' => [], 'dnsbl' => []], [], $reason));
		$this->assertNull($reason, 'an accepted model must not leave a stale rejection reason behind');
	}

	/**
	 * The reported failure mode: the GUI said "report a bug" and named nothing. The
	 * detail now reaches the system log at LOG_NOTICE, the way the cron tick reports.
	 */
	public function testRuntimeConfigLogsTheRejectionReasonAtNotice(): void
	{
		config_set_path('installedpackages/pfblockerng/config/0', self::GENERAL);
		config_set_path('installedpackages/pfblockernglistsv4/config', [[
			'aliasname' => 'Broken_List', 'action' => 'Deny_Inbound', 'cron' => 'Fortnightly',
			'row' => [['header' => 'broken', 'url' => 'https://192.0.2.1/broken']],
		]]);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Disable', 'blacklist_selected' => '', 'blacklist_freq' => 'Never', 'item' => [],
		]);

		$this->assertNull(pfb_schedule_runtime_config(),
			'the fixture is deliberately malformed, so the runtime model must be rejected');

		$notices = array_column(array_filter($GLOBALS['pfb_test_logger_calls'] ?? [],
			static fn (array $call): bool => $call['priority'] === LOG_NOTICE), 'message');
		$named = array_filter($notices, static fn (string $m): bool => str_contains($m, 'Broken_List'));
		$this->assertNotSame([], $named,
			'a rejected schedule model must raise a LOG_NOTICE naming the alias; notices were: '
			. var_export($notices, TRUE));
	}

	/** The page renders a fixed label per stage, never the raw query token. */
	public function testStageLabelsAreDistinctAndUnknownTokensDegradeSafely(): void
	{
		$labels = [];
		foreach (self::STAGES as $stage) {
			$label = pfb_schedule_cache_stage_label($stage);
			$this->assertNotSame('', $label, "stage '{$stage}' must carry a label");
			$labels[] = $label;
		}
		$this->assertSame($labels, array_unique($labels),
			'each stage must be distinguishable in the warning: ' . var_export($labels, TRUE));

		$fallback = pfb_schedule_cache_stage_label('<script>alert(1)</script>');
		$this->assertNotContains($fallback, $labels, 'an unrecognised token must fall back to a generic label');
		$this->assertStringNotContainsString('<', $fallback, 'the query token must never reach the page verbatim');
	}

	/** The save path records which stage failed, and the warning names it. */
	public function testGeneralSaveRecordsTheFailingStageAndTheWarningNamesIt(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$save = strpos($source, "if (isset(\$_POST['save'])) {");
		$this->assertNotFalse($save);
		$this->assertNotFalse(strpos($source, 'schstage=', $save),
			'the save redirect must carry the stage that failed');
		foreach (self::STAGES as $stage) {
			$this->assertStringContainsString("\$cache_stage = '{$stage}'", $source,
				"the stage ladder must be able to report '{$stage}'");
		}
		$this->assertStringContainsString('pfb_schedule_cache_stage_label(', $source,
			'the warning must render the stage through the fixed label map');
		$this->assertStringNotContainsString('This is likely a bug; please report it.', $source,
			'the warning must stop asking for a bug report with no detail attached');
	}
}
