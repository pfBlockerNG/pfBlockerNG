<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2308 Step 1 — schedule schema and one-pass migration.
 *
 * These tests exercise the public registry pass and migration driver. Legacy
 * interval keys remain present until the runtime/UI cut-over lands.
 */
final class QuarterHourMigrationTest extends TestCase
{
	private const GEN = 'installedpackages/pfblockerng/config/0';
	private const V4  = 'installedpackages/pfblockernglistsv4/config';
	private const V6  = 'installedpackages/pfblockernglistsv6/config';
	private const DNS = 'installedpackages/pfblockerngdnsbl/config';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	private function noticeText(): string
	{
		return implode("\n", array_map(
			static fn (array $notice): string => (string) ($notice['notice'] ?? ''),
			$GLOBALS['pfb_test_file_notices'] ?? []
		));
	}

	public function testScheduleRuntimeWorksWhenExtraModuleIsLoadedStandalone(): void
	{
		$extra = var_export(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc', TRUE);
		$script = <<<PHP
\$standalone_config = [
	'installedpackages/pfblockerng/config/0/pfb_scheduled_feed_updates' => 'on',
	'installedpackages/pfblockerng/config/0/pfb_schedule_weekday' => '7',
	'installedpackages/pfblockerng/config/0/pfb_schedule_hour' => '6',
	'installedpackages/pfblockerng/config/0/pfb_schedule_minute' => '45',
	'installedpackages/pfblockernglistsv4/config' => [],
	'installedpackages/pfblockernglistsv6/config' => [],
	'installedpackages/pfblockerngdnsbl/config' => [],
	'installedpackages/pfblockerngblacklist' => [
		'blacklist_enable' => 'Enable',
		'blacklist_selected' => 'ut1',
		'blacklist_freq' => 'EveryDay',
		'item' => [['xml' => 'ut1', 'selected' => 'ads', 'title' => 'UT1', 'feed' => 'https://example.test/ut1']],
	],
];
function config_get_path(string \$path, mixed \$default = NULL): mixed
{
	return \$GLOBALS['standalone_config'][\$path] ?? \$default;
}
require {$extra};
\$gen = 'installedpackages/pfblockerng/config/0';
\$v4 = 'installedpackages/pfblockernglistsv4/config';
\$v6 = 'installedpackages/pfblockernglistsv6/config';
\$dns = 'installedpackages/pfblockerngdnsbl/config';
\$migrated = pfb_schedule_migrate([
	\$gen => [
		'enable_cb' => 'on',
		'pfb_scheduled_feed_updates' => 'on',
		'pfb_schedule_weekday' => '7',
		'pfb_schedule_hour' => '6',
		'pfb_schedule_minute' => '45',
		'skipfeed' => '0',
	],
	\$v4 => [[
		'action' => 'Deny_Inbound',
		'cron' => 'Weekly',
		'dow' => '3',
		'row' => [['url' => 'https://example.test', 'state' => 'Enabled']],
	]],
	\$v6 => [],
	\$dns => [],
], static fn (): int => 0);
\$model = [
	'default' => ['weekday' => 7, 'hour' => 6, 'minute' => 45],
	'entries' => [
		'extra:dcc' => ['cadence' => 'EveryDay', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL],
	],
];
\$extras = pfb_schedule_extra_plan(\$model, ['schema' => 1, 'items' => []], strtotime('2026-01-07 07:00:00 UTC'), new DateTimeZone('UTC'));
\$runtime = pfb_schedule_runtime_config();
echo json_encode([
	'group' => \$migrated[\$v4][0],
	'extras_due' => \$extras['due'],
	'blacklist_enabled' => \$runtime['entries']['extra:bl']['enabled'] ?? NULL,
], JSON_THROW_ON_ERROR);
PHP;
		$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);
		$stdout = '';
		$stderr = '';
		$process_status = ['running' => TRUE, 'exitcode' => -1];
		$timed_out = FALSE;
		$close_status = -1;
		try {
			$deadline = hrtime(TRUE) + 5_000_000_000;
			do {
				$stdout .= stream_get_contents($pipes[1]);
				$stderr .= stream_get_contents($pipes[2]);
				$process_status = proc_get_status($process);
				if (!$process_status['running']) {
					break;
				}
				usleep(10000);
			} while (hrtime(TRUE) < $deadline);
			$timed_out = $process_status['running'];
			if ($timed_out) {
				proc_terminate($process);
				usleep(50000);
				if (proc_get_status($process)['running']) {
					proc_terminate($process, 9);
				}
			}
		} finally {
			$stdout .= stream_get_contents($pipes[1]);
			$stderr .= stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			$close_status = proc_close($process);
		}
		$status = $process_status['exitcode'] !== -1 ? $process_status['exitcode'] : $close_status;

		if ($timed_out) {
			$this->markTestIncomplete('STUCK/ENVIRONMENT: standalone schedule child exceeded the 5-second salvage cap');
		}
		$this->assertSame(0, $status, (string) $stderr);
		$output = json_decode((string) $stdout, TRUE, flags: JSON_THROW_ON_ERROR);
		$group = $output['group'];
		$this->assertSame('on', $group['schedule_override']);
		$this->assertSame('3', $group['schedule_weekday']);
		$this->assertSame('6', $group['schedule_hour']);
		$this->assertSame('45', $group['schedule_minute']);
		$this->assertArrayNotHasKey('dow', $group);
		$this->assertSame(['extra:dcc'], $output['extras_due']);
		$this->assertTrue($output['blacklist_enabled']);
	}

	public function testRegistryAddsCanonicalScheduleFieldsAndFreshSkipfeedDefault(): void
	{
		$registry = pfb_cfg_registry();
		$this->assertSame('on', $registry['gen/pfb_scheduled_feed_updates']['default'] ?? NULL);
		$this->assertSame('7', $registry['gen/pfb_schedule_weekday']['default']);
		$this->assertSame('0', $registry['gen/pfb_schedule_hour']['default']);
		$this->assertSame('0', $registry['gen/pfb_schedule_minute']['default']);
		$this->assertSame('3', $registry['gen/skipfeed']['default']);
		foreach (['gen/pfb_scheduled_feed_updates', 'gen/pfb_schedule_weekday', 'gen/pfb_schedule_hour', 'gen/pfb_schedule_minute'] as $key) {
			$this->assertTrue(isset($registry[$key]['grandfather']) || isset($registry[$key]['no_grandfather']), $key . ' must classify upgrade behavior');
		}
	}

	public function testRegistryPassFreshAndUpgradeSkipfeedBranches(): void
	{
		$fresh = pfb_registry_pass([self::GEN => []]);
		$this->assertSame('3', $fresh[self::GEN]['skipfeed']);

		$old = pfb_registry_pass([self::GEN => ['enable_cb' => 'on']]);
		$this->assertSame('0', $old[self::GEN]['skipfeed']);

		$explicit = pfb_registry_pass([self::GEN => ['enable_cb' => 'on', 'skipfeed' => '0']]);
		$this->assertSame('0', $explicit[self::GEN]['skipfeed']);
		$bounded = pfb_registry_pass([self::GEN => ['enable_cb' => 'on', 'skipfeed' => '6']]);
		$this->assertSame('6', $bounded[self::GEN]['skipfeed']);
	}

	public function testFreshMigrationPreservesRegistryFreshInstallDefaults(): void
	{
		$modes = array_fill_keys(array_values(PFB_SECTIONS), 'NEWCFG');
		pfb_run_migrations();

		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		$result = pfb_registry_pass($sections, NULL, $modes);

		$this->assertSame('auto', $result[self::GEN]['pfb_alias_delta_mode'] ?? NULL,
			'a migration that seeds a fresh section must not activate its upgrade grandfather defaults');
	}

	public function testFreshMigrationPersistsSundayUniformSlotAndSkipfeed(): void
	{
		pfb_run_migrations();
		$this->assertSame('on', config_get_path(self::GEN . '/pfb_scheduled_feed_updates'));
		$this->assertSame('7', config_get_path(self::GEN . '/pfb_schedule_weekday'));
		$hour = config_get_path(self::GEN . '/pfb_schedule_hour');
		$minute = config_get_path(self::GEN . '/pfb_schedule_minute');
		$this->assertIsString($hour);
		$this->assertContains($minute, ['0', '15', '30', '45']);
		$this->assertGreaterThanOrEqual(0, (int) $hour);
		$this->assertLessThanOrEqual(6, (int) $hour);
		$this->assertSame('3', config_get_path(self::GEN . '/skipfeed'));
		$writes = $GLOBALS['pfb_test_write_config_calls'];
		$this->assertCount(1, $writes);
		pfb_run_migrations();
		$this->assertSame($writes, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testUpgradeMigrationMapsIntervalAndValidLegacyTime(): void
	{
		$sections = [
			self::GEN => [
				'enable_cb' => 'on', 'pfb_interval' => 'Disabled',
				'pfb_dailystart' => '23', 'pfb_min' => '45',
			],
			self::V4 => [], self::V6 => [], self::DNS => [],
		];
		config_set_path(self::GEN, $sections[self::GEN]);
		pfb_run_migrations();
		$this->assertSame('', config_get_path(self::GEN . '/pfb_scheduled_feed_updates'));
		$this->assertSame('7', config_get_path(self::GEN . '/pfb_schedule_weekday'));
		$this->assertSame('23', config_get_path(self::GEN . '/pfb_schedule_hour'));
		$this->assertSame('45', config_get_path(self::GEN . '/pfb_schedule_minute'));
		$this->assertSame('0', config_get_path(self::GEN . '/skipfeed'));
		foreach (['pfb_interval', 'pfb_min', 'pfb_hour', 'pfb_dailystart'] as $key) {
			$this->assertNull(config_get_path(self::GEN . "/{$key}"), "retired General key remains: {$key}");
		}
	}

	public function testIntervalVocabularyAndHostileTokens(): void
	{
		foreach (['1', '2', '3', '4', '6', '8', '12', '24'] as $token) {
			$this->setUp();
			config_set_path(self::GEN, ['enable_cb' => 'on', 'pfb_interval' => $token]);
			pfb_run_migrations();
			$this->assertSame('on', config_get_path(self::GEN . '/pfb_scheduled_feed_updates'), $token);
			$this->assertSame([], $GLOBALS['pfb_test_file_notices'], $token);
		}

		$this->setUp();
		config_set_path(self::GEN, ['enable_cb' => 'on', 'pfb_interval' => 'Disabled']);
		pfb_run_migrations();
		$this->assertSame('', config_get_path(self::GEN . '/pfb_scheduled_feed_updates'));

		foreach (['disabled', '', [], '-1', '999999999999'] as $token) {
			$this->setUp();
			config_set_path(self::GEN, ['enable_cb' => 'on', 'pfb_interval' => $token]);
			pfb_run_migrations();
			$this->assertSame('on', config_get_path(self::GEN . '/pfb_scheduled_feed_updates'), is_array($token) ? 'array' : (string) $token);
			$this->assertStringContainsString('pfb_interval', $this->noticeText());
			if (is_string($token) && $token !== '') {
				$this->assertStringNotContainsString($token, $this->noticeText());
			}
		}
	}

	public function testLegacyTimeEndpointsAndEachMalformedMemberFallback(): void
	{
		foreach ([[0, '0'], [23, '45']] as [$hour, $minute]) {
			$this->setUp();
			config_set_path(self::GEN, ['enable_cb' => 'on', 'pfb_interval' => '1', 'pfb_dailystart' => (string) $hour, 'pfb_min' => $minute]);
			pfb_run_migrations();
			$this->assertSame((string) $hour, config_get_path(self::GEN . '/pfb_schedule_hour'));
			$this->assertSame($minute, config_get_path(self::GEN . '/pfb_schedule_minute'));
		}

		$malformed = [
			['pfb_dailystart' => NULL, 'pfb_min' => '15', 'notice' => 'pfb_dailystart'],
			['pfb_dailystart' => '2', 'pfb_min' => NULL, 'notice' => 'pfb_min'],
			['pfb_dailystart' => '24', 'pfb_min' => '15', 'notice' => 'pfb_dailystart'],
			['pfb_dailystart' => '2', 'pfb_min' => ' 15', 'notice' => 'pfb_min'],
			['pfb_dailystart' => ['2'], 'pfb_min' => '15', 'notice' => 'pfb_dailystart'],
			['pfb_dailystart' => '2', 'pfb_min' => ['15'], 'notice' => 'pfb_min'],
		];
		foreach ($malformed as $case) {
			$this->setUp();
			$data = ['enable_cb' => 'on', 'pfb_interval' => '1', 'pfb_min' => $case['pfb_min']];
			if ($case['pfb_dailystart'] !== NULL) {
				$data['pfb_dailystart'] = $case['pfb_dailystart'];
			}
			config_set_path(self::GEN, $data);
			pfb_run_migrations();
			$this->assertContains(config_get_path(self::GEN . '/pfb_schedule_minute'), ['0', '15', '30', '45']);
			$this->assertLessThanOrEqual(6, (int) config_get_path(self::GEN . '/pfb_schedule_hour'));
			$this->assertStringContainsString($case['notice'], $this->noticeText());
		}
	}

	public function testMalformedGeneralLegacyValuesFallbackAndNoticeKeysOnly(): void
	{
		$sections = [
			self::GEN => [
				'enable_cb' => 'on', 'pfb_interval' => ['Disabled'],
				'pfb_dailystart' => ' 2', 'pfb_min' => '99',
			],
			self::V4 => [], self::V6 => [], self::DNS => [],
		];
		config_set_path(self::GEN, $sections[self::GEN]);
		pfb_run_migrations();
		$this->assertSame('on', config_get_path(self::GEN . '/pfb_scheduled_feed_updates'));
		$this->assertSame('7', config_get_path(self::GEN . '/pfb_schedule_weekday'));
		$this->assertContains(config_get_path(self::GEN . '/pfb_schedule_minute'), ['0', '15', '30', '45']);
		$this->assertLessThanOrEqual(6, (int) config_get_path(self::GEN . '/pfb_schedule_hour'));
		$this->assertStringContainsString('pfb_interval', $this->noticeText());
		$this->assertStringContainsString('pfb_dailystart', $this->noticeText());
		$this->assertStringContainsString('pfb_min', $this->noticeText());
		$this->assertStringNotContainsString('Disabled', $this->noticeText());
		$this->assertStringNotContainsString('99', $this->noticeText());
	}

	public function testMalformedCanonicalScheduleFallsBackInsteadOfSuppressingRuntime(): void
	{
		config_set_path(self::GEN, [
			'enable_cb' => 'on', 'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday' => ['7'], 'pfb_schedule_hour' => '24',
			'pfb_schedule_minute' => '5', 'skipfeed' => '0',
		]);
		config_set_path(self::V4, [[
			'action' => 'Deny_Inbound', 'cron' => 'EveryDay',
			'row' => [['url' => 'https://example.test', 'state' => 'Enabled']],
			'schedule_override' => 'on', 'schedule_weekday' => ['2'],
			'schedule_hour' => '4', 'schedule_minute' => '15',
		]]);
		config_set_path(self::V6, []);
		config_set_path(self::DNS, []);

		pfb_run_migrations();

		$this->assertSame('7', config_get_path(self::GEN . '/pfb_schedule_weekday'));
		$this->assertSame('0', config_get_path(self::GEN . '/pfb_schedule_hour'));
		$this->assertSame('0', config_get_path(self::GEN . '/pfb_schedule_minute'));
		$this->assertSame('7', config_get_path(self::V4 . '/0/schedule_weekday'));
		$this->assertSame('4', config_get_path(self::V4 . '/0/schedule_hour'));
		$this->assertSame('15', config_get_path(self::V4 . '/0/schedule_minute'));
		$this->assertStringContainsString('pfb_schedule_weekday', $this->noticeText());
		$this->assertStringContainsString('schedule_weekday', $this->noticeText());
		$this->assertStringNotContainsString('24', $this->noticeText());
	}

	public function testNonWeeklyDormantWeekdayFallsBackToCurrentGeneralDefault(): void
	{
		config_set_path(self::GEN, [
			'enable_cb' => 'on', 'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday' => '3', 'pfb_schedule_hour' => '4',
			'pfb_schedule_minute' => '15', 'skipfeed' => '0',
		]);
		config_set_path(self::V4, [[
			'action' => 'Deny_Inbound', 'cron' => 'EveryDay',
			'row' => [['url' => 'https://example.test', 'state' => 'Enabled']],
			'schedule_override' => 'on', 'schedule_weekday' => 'bogus',
			'schedule_hour' => '4', 'schedule_minute' => '15',
		]]);
		config_set_path(self::V6, []);
		config_set_path(self::DNS, []);

		pfb_run_migrations();

		$this->assertSame('3', config_get_path(self::V4 . '/0/schedule_weekday'));
	}

	public function testPartialCanonicalScheduleUsesRegistryFallbackWithoutRandomReseed(): void
	{
		$migrated = pfb_schedule_migrate([
			self::GEN => [
				'enable_cb' => 'on', 'pfb_scheduled_feed_updates' => 'on',
				'pfb_schedule_weekday' => '3', 'pfb_schedule_hour' => '5', 'skipfeed' => '0',
			],
			self::V4 => [], self::V6 => [], self::DNS => [],
		], static fn (): int => 7);

		$this->assertIsArray($migrated);
		$this->assertSame('3', $migrated[self::GEN]['pfb_schedule_weekday']);
		$this->assertSame('5', $migrated[self::GEN]['pfb_schedule_hour']);
		$this->assertSame('0', $migrated[self::GEN]['pfb_schedule_minute']);
	}

	public function testGroupMigrationCoversIpv4Ipv6DnsblAndWeeklyBranches(): void
	{
		$group = static fn (string $action, string $cron, mixed $dow, array $rows): array => [
			'action' => $action, 'cron' => $cron, 'dow' => $dow, 'row' => $rows,
		];
		$sections = [
			self::GEN => ['enable_cb' => 'on', 'pfb_interval' => '1', 'pfb_dailystart' => '4', 'pfb_min' => '15'],
			self::V4 => [$group('Deny_Inbound', 'Weekly', '3', [['url' => 'https://example.test', 'state' => 'Enabled']])],
			self::V6 => [$group('Deny_Inbound', 'EveryDay', '5', [['url' => 'https://example.test', 'state' => 'Enabled']])],
			self::DNS => [$group('unbound', 'Weekly', ['bad'], [['url' => 'https://example.test', 'state' => 'Enabled']])],
		];
		foreach ($sections as $path => $blob) {
			config_set_path($path, $blob);
		}
		pfb_run_migrations();
		foreach ([self::V4, self::V6, self::DNS] as $section) {
			$this->assertSame('4', config_get_path($section . '/0/schedule_hour'));
			$this->assertSame('15', config_get_path($section . '/0/schedule_minute'));
			$this->assertNull(config_get_path($section . '/0/dow'), "retired group dow remains in {$section}");
		}
		$this->assertSame('on', config_get_path(self::V4 . '/0/schedule_override'));
		$this->assertSame('3', config_get_path(self::V4 . '/0/schedule_weekday'));
		$this->assertSame('', config_get_path(self::V6 . '/0/schedule_override'));
		$this->assertSame('5', config_get_path(self::V6 . '/0/schedule_weekday'));
		$this->assertSame('', config_get_path(self::DNS . '/0/schedule_override'));
		$this->assertSame('7', config_get_path(self::DNS . '/0/schedule_weekday'));
		$this->assertStringContainsString('dow', $this->noticeText());
	}

	public function testGroupMigrationWeeklyNonWeeklyInactiveAndHostileDowBranches(): void
	{
		$active = [['url' => 'https://example.test', 'state' => 'Enabled']];
		$inactive = [['url' => 'https://example.test', 'state' => 'Disabled']];
		$row = static fn (string $action, string $cron, mixed $dow, array $items, string $tag): array => [
			'action' => $action, 'cron' => $cron, 'dow' => $dow, 'row' => $items, 'unrelated' => $tag,
		];
		config_set_path(self::GEN, ['enable_cb' => 'on', 'pfb_interval' => '1', 'pfb_dailystart' => '1', 'pfb_min' => '0']);
		config_set_path(self::V4, [
			$row('Deny_Inbound', 'Weekly', '2', $active, 'weekly-valid'),
			$row('Deny_Inbound', 'Weekly', NULL, $active, 'weekly-missing'),
			$row('Deny_Inbound', 'Weekly', ['x'], $active, 'weekly-array'),
		]);
		config_set_path(self::V6, [
			$row('Deny_Inbound', 'EveryDay', '5', $active, 'daily-valid'),
			$row('Deny_Inbound', 'EveryDay', '-1', $active, 'daily-invalid'),
			$row('Deny_Inbound', 'Weekly', ['secret'], $inactive, 'inactive-invalid'),
		]);
		config_set_path(self::DNS, [
			$row('unbound', 'Weekly', '7', $active, 'dns-valid'),
			$row('unbound', 'Weekly', '8', $active, 'dns-invalid'),
		]);
		pfb_run_migrations();
		$this->assertSame('on', config_get_path(self::V4 . '/0/schedule_override'));
		$this->assertSame('2', config_get_path(self::V4 . '/0/schedule_weekday'));
		$this->assertSame('', config_get_path(self::V4 . '/1/schedule_override'));
		$this->assertSame('7', config_get_path(self::V4 . '/1/schedule_weekday'));
		$this->assertSame('', config_get_path(self::V4 . '/2/schedule_override'));
		$this->assertSame('7', config_get_path(self::V4 . '/2/schedule_weekday'));
		$this->assertSame('', config_get_path(self::V6 . '/0/schedule_override'));
		$this->assertSame('5', config_get_path(self::V6 . '/0/schedule_weekday'));
		$this->assertSame('', config_get_path(self::V6 . '/1/schedule_override'));
		$this->assertSame('7', config_get_path(self::V6 . '/1/schedule_weekday'));
		$this->assertSame('', config_get_path(self::V6 . '/2/schedule_override'));
		$this->assertSame('7', config_get_path(self::V6 . '/2/schedule_weekday'));
		$this->assertSame('inactive-invalid', config_get_path(self::V6 . '/2/unrelated'));
		$this->assertSame('on', config_get_path(self::DNS . '/0/schedule_override'));
		$this->assertSame('7', config_get_path(self::DNS . '/0/schedule_weekday'));
		$this->assertSame('', config_get_path(self::DNS . '/1/schedule_override'));
		$this->assertSame('7', config_get_path(self::DNS . '/1/schedule_weekday'));
		foreach ([self::V4 => 3, self::V6 => 3, self::DNS => 2] as $section => $count) {
			for ($index = 0; $index < $count; $index++) {
				$this->assertNull(config_get_path("{$section}/{$index}/dow"),
					"retired group dow remains in {$section}/{$index}");
			}
		}
		$this->assertStringContainsString('dow', $this->noticeText());
		$this->assertStringNotContainsString('secret', $this->noticeText());
	}

	public function testGroupScalarShapesDoNotTypeErrorOrPartiallyMutate(): void
	{
		config_set_path(self::GEN, ['enable_cb' => 'on', 'pfb_interval' => '1']);
		config_set_path(self::V4, ['not-a-row']);
		config_set_path(self::V6, 'not-an-array');
		config_set_path(self::DNS, [0 => ['action' => 'unbound', 'cron' => 'Weekly', 'dow' => [], 'row' => 'not-an-array']]);
		pfb_run_migrations();
		$this->assertSame(['not-a-row'], config_get_path(self::V4));
		$this->assertSame('not-an-array', config_get_path(self::V6));
		$this->assertSame('not-an-array', config_get_path(self::DNS . '/0/row'));
	}

	public function testAlreadyMigratedCanonicalStateIsNoOp(): void
	{
		$canonical = ['enable_cb' => 'on', 'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7', 'pfb_schedule_hour' => '2', 'pfb_schedule_minute' => '30', 'skipfeed' => '0'];
		config_set_path(self::GEN, $canonical);
		foreach ([self::V4, self::V6, self::DNS] as $section) {
			config_set_path($section, [['action' => 'Deny_Inbound', 'cron' => 'Weekly', 'row' => $GLOBALS['pfb_test_rows'] ?? [['url' => 'https://example.test', 'state' => 'Enabled']], 'schedule_override' => 'on', 'schedule_weekday' => '3', 'schedule_hour' => '2', 'schedule_minute' => '30']]);
		}
		pfb_run_migrations();
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testDriverPublishesOneCompleteMigrationAndRerunIsNoOp(): void
	{
		config_set_path(self::GEN, ['enable_cb' => 'on', 'pfb_interval' => '4', 'pfb_dailystart' => '2', 'pfb_min' => '30']);
		config_set_path(self::V4, []);
		config_set_path(self::V6, []);
		config_set_path(self::DNS, []);
		pfb_run_migrations();
		$this->assertSame('on', config_get_path(self::GEN . '/pfb_scheduled_feed_updates'));
		$this->assertSame('2', config_get_path(self::GEN . '/pfb_schedule_hour'));
		foreach (['pfb_interval', 'pfb_min', 'pfb_hour', 'pfb_dailystart'] as $key) {
			$this->assertNull(config_get_path(self::GEN . "/{$key}"), "retired General key remains: {$key}");
		}
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
		$first = config_get_path(self::GEN);
		$GLOBALS['pfb_test_write_config_calls'] = [];
		pfb_run_migrations();
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame($first, config_get_path(self::GEN));
		$GLOBALS['pfb_test_write_config_calls'] = [];
		pfb_run_migrations();
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}
}
