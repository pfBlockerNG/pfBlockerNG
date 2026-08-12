<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Runtime schedule source must drive the real tick, independently of pfb_interval. */
final class TickScheduleRuntimeTest extends TestCase
{
	private string $dir = '';
	private string $stateDir = '';
	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_tick_runtime_' . getmypid() . '_' . uniqid();
		$this->stateDir = $this->dir . '/state';
		mkdir($this->stateDir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['schedule_state_dir'] = $this->stateDir;
		$GLOBALS['pfb']['runlog'] = $this->dir . '/run.log';
		$GLOBALS['pfb']['extraslog'] = $this->dir . '/extras.log';
		$GLOBALS['pfb']['log'] = $this->dir . '/pfb.log';
		$GLOBALS['pfb']['logdir'] = $this->dir;
		$GLOBALS['pfb']['errlog'] = $this->dir . '/error.log';
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['blconfig'] = [];
		$GLOBALS['pfb']['php'] = $this->recorder();
		$GLOBALS['config'] = [];

		$now = new DateTimeImmutable('now', new DateTimeZone(date_default_timezone_get()));
		$slot = $now->modify('-15 minutes');
		$minute = intdiv((int) $slot->format('i'), 15) * 15;
		$general = [
			'pfb_interval' => 'Disabled',
			'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday' => $slot->format('N'),
			'pfb_schedule_hour' => $slot->format('G'),
			'pfb_schedule_minute' => (string) $minute,
			'pfb_quiet_hours' => '',
		];
		foreach ($general as $key => $value) {
			config_set_path('installedpackages/pfblockerng/config/0/' . $key, $value);
		}
		foreach (['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0'] as $key => $value) {
			config_set_path('installedpackages/pfblockerng/config/0/' . $key, $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => ''] as $key => $value) {
			config_set_path('installedpackages/pfblockerngipsettings/config/0/' . $key, $value);
		}
		foreach (['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443'] as $key => $value) {
			config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/' . $key, $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		config_set_path('installedpackages/pfblockernglistsv4/config', [[
			'action' => 'Deny_Inbound',
			'cron' => 'EveryDay',
			'schedule_override' => '',
			'row' => [['header' => 'runtime', 'url' => 'https://example.test/feed', 'state' => 'Enabled']],
		]]);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);

		$model = pfb_schedule_runtime_model(
			[
				'pfb_scheduled_feed_updates' => 'on',
				'pfb_schedule_weekday' => $slot->format('N'),
				'pfb_schedule_hour' => $slot->format('G'),
				'pfb_schedule_minute' => (string) $minute,
			],
			[
				'ipv4' => config_get_path('installedpackages/pfblockernglistsv4/config', []),
				'ipv6' => [],
				'dnsbl' => [],
			]
		);
		$this->assertIsArray($model);
		$future = time() + 86400;
		$this->assertTrue(pfb_due_ledger_write_cache([
			'dcc' => ['last_run' => $future - 1, 'next_due' => $future, 'jitter' => 0],
			'bl' => ['last_run' => $future - 1, 'next_due' => $future, 'jitter' => 0],
			'ss_refresh' => ['last_run' => $future - 1, 'next_due' => $future, 'jitter' => 0],
			'apply_reconcile' => ['last_run' => $future - 1, 'next_due' => $future, 'jitter' => 0],
		], $model['config_hash'], $this->dir));
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		$this->remove($this->dir);
	}

	public function testDisabledLegacyIntervalDoesNotSuppressDueRuntimeSchedule(): void
	{
		pfblockerng_tick([]);

		$this->assertFileExists($this->stateDir . '/pfb_schedule_state.json');
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$this->assertSame(['ipv4:runtime_v4'], array_keys($state['items'] ?? []));
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_scheduled_feed_updates'));
		$this->assertContains('Tick: dispatching feed cron.', array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
		$this->assertSame(
			"/usr/local/www/pfblockerng/pfblockerng.php cron\n",
			$this->awaitSpawnLog(1),
			'scheduled runtime dispatch must invoke configured PHP with the cron command exactly once'
		);
	}

	public function testMissingCacheIsRegeneratedBeforeRuntimeDispatch(): void
	{
		@unlink($this->dir . '/pfb_due_ledger.json');
		pfblockerng_tick([]);
		$cache = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', $cache['_meta']['config_hash']);
		$this->assertIsArray(pfb_due_ledger_read_cache($this->dir, $cache['_meta']['config_hash']));
		$spawns = array_values(array_filter(explode("\n", $this->awaitSpawnLog(1)), 'strlen'));
		$this->assertContains('/usr/local/www/pfblockerng/pfblockerng.php cron', $spawns);

		file_put_contents($this->dir . '/pfb_due_ledger.json', '{"broken":true}');
		$GLOBALS['pfb_test_logger_calls'] = [];
		pfblockerng_tick([]);
		$repaired = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertIsArray(pfb_due_ledger_read_cache($this->dir, $repaired['_meta']['config_hash']));
	}

	public function testWorkerCompletionDuringReservationSuppressesStaleDispatch(): void
	{
		$model = pfb_schedule_runtime_config();
		$this->assertIsArray($model);
		$plan = pfb_schedule_plan($model['entries'], $model['default'], NULL, time(), new DateTimeZone(date_default_timezone_get()));
		$occurrence = $plan['occurrences']['ipv4:runtime_v4'];
		$calls = 0;
		$GLOBALS['pfb']['schedule_state_io'] = [
			'before_document' => function () use (&$calls, $occurrence): void {
				if ($calls++ !== 0) {
					return;
				}
				file_put_contents($this->stateDir . '/pfb_schedule_state.json', json_encode([
					'schema' => 1,
					'items' => ['ipv4:runtime_v4' => [
						'last_completed_occurrence' => $occurrence,
						'completion_outcome' => 'success',
					]],
				]));
			},
		];

		pfblockerng_tick([]);

		$this->assertNotContains(
			'Tick: dispatching feed cron.',
			array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message')
		);
		$this->assertFileDoesNotExist($this->dir . '/spawns');
		$state = pfb_schedule_state_read($this->stateDir);
		$this->assertArrayNotHasKey('pending_occurrence', $state['items']['ipv4:runtime_v4']);
	}

	public function testWorkerCompletionDuringDispatchMarkSuppressesSpawn(): void
	{
		$model = pfb_schedule_runtime_config();
		$this->assertIsArray($model);
		$plan = pfb_schedule_plan($model['entries'], $model['default'], NULL, time(), new DateTimeZone(date_default_timezone_get()));
		$occurrence = $plan['occurrences']['ipv4:runtime_v4'];
		$this->assertTrue(pfb_schedule_state_write([
			'schema' => 1,
			'items' => ['ipv4:runtime_v4' => [
				'pending_occurrence' => $occurrence,
				'pending_dispatch_at' => time() - 900,
			]],
		], $this->stateDir));
		$calls = 0;
		$GLOBALS['pfb']['schedule_state_io'] = [
			'before_document' => function () use (&$calls, $occurrence): void {
				if ($calls++ !== 1) {
					return;
				}
				file_put_contents($this->stateDir . '/pfb_schedule_state.json', json_encode([
					'schema' => 1,
					'items' => ['ipv4:runtime_v4' => [
						'last_completed_occurrence' => $occurrence,
						'completion_outcome' => 'success',
					]],
				]));
			},
		];

		pfblockerng_tick([]);

		$this->assertNotContains(
			'Tick: dispatching feed cron.',
			array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message')
		);
	}

	public function testCachePublicationFailureSuppressesCronAndPreservesBytes(): void
	{
		$before = '{"broken":true}';
		file_put_contents($this->dir . '/pfb_due_ledger.json', $before);
		$GLOBALS['pfb']['schedule_cache_io'] = ['fail_rename' => TRUE];
		pfblockerng_tick([]);
		$this->assertSame($before, file_get_contents($this->dir . '/pfb_due_ledger.json'));
		$this->assertFileDoesNotExist($this->dir . '/spawns');
		$this->assertContains('Tick: scheduled feed runtime unavailable; cron selection suppressed.', array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
	}

	public function testStaleCacheHashIsReplacedFromCurrentRuntimeConfig(): void
	{
		$before = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$current = (string) PfbConfig::read('gen/pfb_schedule_minute');
		PfbConfig::writeSystem('gen/pfb_schedule_minute', $current === '30' ? '45' : '30');
		pfblockerng_tick([]);
		$after = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertNotSame($before['_meta']['config_hash'], $after['_meta']['config_hash']);
		$this->assertIsArray(pfb_due_ledger_read_cache($this->dir, $after['_meta']['config_hash']));
	}

	public function testMasterOffSuppressesLegacyDueAndLeavesNoCronWake(): void
	{
		PfbConfig::writeSystem('gen/pfb_scheduled_feed_updates', PfbToggle::Off);
		PfbConfig::writeSystem('gen/pfb_interval', '1');
		pfblockerng_tick([]);
		$cache = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertArrayNotHasKey('cron', $cache);
		$this->assertFileDoesNotExist($this->dir . '/spawns');
	}

	public function testDueSlotReservesConfiguredFamiliesInStableOrder(): void
	{
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockernglistsv4/config', [[
			'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'row' => [
				['header' => 'alpha', 'url' => 'https://example.test/v4', 'state' => 'Enabled'],
				['header' => 'beta', 'url' => 'https://example.test/v4b', 'state' => 'Enabled'],
			],
		]]);
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockernglistsv6/config', [[
			'action' => 'Permit_Both', 'cron' => 'EveryDay', 'row' => [
				['header' => 'gamma', 'url' => 'https://example.test/v6', 'state' => 'Enabled'],
			],
		]]);
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockerngdnsbl/config', [[
			'action' => 'unbound', 'cron' => 'EveryDay', 'row' => [
				['header' => 'runtime_dns', 'url' => 'https://example.test/dns', 'state' => 'Enabled'],
			],
		]]);

		pfblockerng_tick([]);
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$this->assertSame(
			['ipv4:alpha_v4', 'ipv4:beta_v4', 'ipv6:gamma_v6', 'dnsbl:runtime_dns'],
			array_keys($state['items'] ?? [])
		);
		foreach (array_keys($state['items'] ?? []) as $id) {
			$this->assertArrayHasKey('pending_occurrence', $state['items'][$id]);
		}
		$this->assertCount(1, array_unique(array_column($state['items'], 'pending_occurrence')));
		$this->assertSame(
			"/usr/local/www/pfblockerng/pfblockerng.php cron\n",
			$this->awaitSpawnLog(1)
		);
	}

	public function testSecondTickWithPendingOccurrenceDoesNotReplayCursor(): void
	{
		pfblockerng_tick([]);
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$state['items']['ipv4:runtime_v4']['last_completed_occurrence'] = $state['items']['ipv4:runtime_v4']['pending_occurrence'];
		$state['items']['ipv4:runtime_v4']['completion_outcome'] = 'success';
		unset($state['items']['ipv4:runtime_v4']['pending_occurrence']);
		unset($state['items']['ipv4:runtime_v4']['pending_dispatch_at']);
		$this->assertTrue(pfb_schedule_state_write($state, $this->stateDir));
		@unlink($this->dir . '/spawns');
		pfblockerng_tick([]);
		$this->assertFileDoesNotExist($this->dir . '/spawns');
	}

	public function testStatePublicationFailureSuppressesDispatchAndPreservesCache(): void
	{
		$GLOBALS['pfb']['schedule_state_io'] = ['fail_rename' => TRUE];
		$before = time();
		pfblockerng_tick([]);
		$after = time();
		$this->assertFileDoesNotExist($this->dir . '/spawns');
		$cache = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertGreaterThanOrEqual($before, $cache['cron']['next_due']);
		$this->assertLessThanOrEqual($after, $cache['cron']['next_due']);
	}

	public function testScheduledCronIgnoresQuietWindow(): void
	{
		PfbConfig::writeSystem('gen/pfb_quiet_hours', '00:00-00:01');
		pfblockerng_tick([]);
		$messages = array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message');
		$this->assertContains('Tick: dispatching feed cron.', $messages);
	}

	public function testBusyScheduledCronReservesOccurrenceWithoutManualPendingFlag(): void
	{
		$lock = fopen($this->dir . '/pfb_feed_pass.lock', 'c');
		$this->assertNotFalse($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		pfblockerng_tick([]);
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$this->assertArrayHasKey('pending_occurrence', $state['items']['ipv4:runtime_v4']);
		$cache = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertArrayNotHasKey('pending_apply', $cache['cron']);
		flock($lock, LOCK_UN);
		fclose($lock);
	}

	public function testLegacyPendingApplyDispatchesWhenMasterOff(): void
	{
		PfbConfig::writeSystem('gen/pfb_scheduled_feed_updates', PfbToggle::Off);
		$this->assertTrue(pfb_due_ledger_write_entry('cron', [
			'last_run' => time() - 60, 'next_due' => time() - 1, 'jitter' => 0, 'pending_apply' => TRUE,
		], $this->dir));
		pfblockerng_tick([]);
		$messages = array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message');
		$this->assertContains('Tick: dispatching pending manual apply.', $messages);
		$entry = pfb_due_ledger_read_entry('cron', $this->dir);
		$this->assertFalse($entry['pending_apply'] ?? FALSE);
	}

	public function testDispatcherLockSuppressesConcurrentScheduledTick(): void
	{
		pfblockerng_tick([]);
		$GLOBALS['pfb_test_logger_calls'] = [];
		$path = $this->stateDir . '/pfb_schedule_dispatch.lock';
		$lock = fopen($path, 'c');
		$this->assertNotFalse($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		$before = file_get_contents($this->stateDir . '/pfb_schedule_state.json');
		@unlink($this->dir . '/spawns');
		pfblockerng_tick([]);
		$this->assertSame($before, file_get_contents($this->stateDir . '/pfb_schedule_state.json'));
		$this->assertFileDoesNotExist($this->dir . '/spawns');
		$this->assertNotContains('Tick: dispatching feed cron.', array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
		flock($lock, LOCK_UN);
		fclose($lock);
	}

	public function testMasterOffRetainsDurablePendingOccurrenceWithoutDispatch(): void
	{
		pfblockerng_tick([]);
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$pending = $state['items']['ipv4:runtime_v4']['pending_occurrence'];
		PfbConfig::writeSystem('gen/pfb_scheduled_feed_updates', PfbToggle::Off);
		@unlink($this->dir . '/spawns');
		pfblockerng_tick([]);
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$this->assertSame($pending, $state['items']['ipv4:runtime_v4']['pending_occurrence']);
		$this->assertFileDoesNotExist($this->dir . '/spawns');
	}

	public function testPendingOccurrenceWithoutCompletionSuppressesDuplicateTick(): void
	{
		pfblockerng_tick([]);
		$GLOBALS['pfb_test_logger_calls'] = [];
		@unlink($this->dir . '/spawns');
		pfblockerng_tick([]);
		$this->assertFileDoesNotExist($this->dir . '/spawns');
		$this->assertNotContains('Tick: dispatching feed cron.', array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
		$GLOBALS['pfb_test_logger_calls'] = [];
		pfblockerng_tick([]);
		$this->assertFileDoesNotExist($this->dir . '/spawns');
		$this->assertNotContains('Tick: dispatching feed cron.', array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
	}

	public function testExpiredPendingDispatchMarkerRetriesScheduledTick(): void
	{
		pfblockerng_tick([]);
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$state['items']['ipv4:runtime_v4']['pending_dispatch_at'] = time() - 900;
		file_put_contents($this->stateDir . '/pfb_schedule_state.json', json_encode($state));
		$GLOBALS['pfb_test_logger_calls'] = [];
		pfblockerng_tick([]);
		$this->assertContains('Tick: dispatching feed cron.', array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
	}

	private function recorder(): string
	{
		$path = $this->dir . '/php-recorder';
		$log = escapeshellarg($this->dir . '/spawns');
		file_put_contents($path, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> {$log}\n");
		chmod($path, 0755);
		return $path;
	}

	private function awaitSpawnLog(int $count): string
	{
		$path = $this->dir . '/spawns';
		$deadline = microtime(TRUE) + 2.0;
		do {
			$raw = @file_get_contents($path);
			if (is_string($raw) && substr_count($raw, "\n") >= $count) {
				return $raw;
			}
			usleep(1000);
		} while (microtime(TRUE) < $deadline);
		$this->fail(sprintf('scheduled dispatch did not publish %d spawn record(s)', $count));
	}

	private function remove(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = $dir . '/' . $entry;
			is_dir($path) ? $this->remove($path) : @unlink($path);
		}
		@rmdir($dir);
	}
}
