<?php

declare(strict_types=1);

require_once __DIR__ . '/support/FailingFlockStream.php';

use PHPUnit\Framework\TestCase;

/** Runtime schedule source drives the real fixed tick. */
final class TickScheduleRuntimeTest extends TestCase
{
	private string $dir = '';
	private string $stateDir = '';
	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;
	private int $feedRuns = 0;

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
		$GLOBALS['pfb']['denydir'] = $this->dir . '/deny';
		$GLOBALS['pfb']['matchdir'] = $this->dir . '/match';
		$GLOBALS['pfb']['permitdir'] = $this->dir . '/permit';
		$GLOBALS['pfb']['nativedir'] = $this->dir . '/native';
		$GLOBALS['pfb']['dnsdir'] = $this->dir . '/dnsbl';
		foreach (['denydir', 'matchdir', 'permitdir', 'nativedir', 'dnsdir'] as $dir) {
			mkdir($GLOBALS['pfb'][$dir], 0755, TRUE);
		}
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['blconfig'] = [];
		$GLOBALS['pfb']['php'] = $this->recorder();
		$GLOBALS['config'] = [];

		$now = new DateTimeImmutable('now', new DateTimeZone(date_default_timezone_get()));
		$slot = $now->modify('-15 minutes');
		$minute = intdiv((int) $slot->format('i'), 15) * 15;
		$general = [
			'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday' => $slot->format('N'),
			'pfb_schedule_hour' => $slot->format('G'),
			'pfb_schedule_minute' => (string) $minute,
			'pfb_quiet_hours' => '',
		];
		foreach ($general as $key => $value) {
			config_set_path('installedpackages/pfblockerng/config/0/' . $key, $value);
		}
		foreach (['skipfeed' => '0'] as $key => $value) {
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

	private function tick(): void
	{
		pfblockerng_tick(
			[], NULL, NULL, 5.0, NULL, NULL, 5.0,
			static fn (string $_job, string $_argument = ''): bool => TRUE,
			function (): void {
				$this->feedRuns++;
			},
			static fn (): bool => TRUE
		);
	}

	public function testDueRuntimeScheduleRunsFromCanonicalConfiguration(): void
	{
		$this->tick();

		$this->assertFileExists($this->stateDir . '/pfb_schedule_state.json');
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$this->assertArrayHasKey('ipv4:runtime_v4', $state['items'] ?? []);
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_scheduled_feed_updates'));
		$this->assertContains('Tick: running scheduled feed pass.', array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
		$this->assertSame(1, $this->feedRuns);
		$this->assertFileDoesNotExist($this->dir . '/spawns');
	}

	public function testMissingCacheIsRegeneratedBeforeRuntimeDispatch(): void
	{
		@unlink($this->dir . '/pfb_due_ledger.json');
		$this->tick();
		$cache = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', $cache['_meta']['config_hash']);
		$this->assertIsArray(pfb_due_ledger_read_cache($this->dir, $cache['_meta']['config_hash']));
		$this->assertSame(1, $this->feedRuns);

		file_put_contents($this->dir . '/pfb_due_ledger.json', '{"broken":true}');
		$GLOBALS['pfb_test_logger_calls'] = [];
		$this->tick();
		$repaired = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertIsArray(pfb_due_ledger_read_cache($this->dir, $repaired['_meta']['config_hash']));
	}

	public function testMalformedPendingApplyIsNeverTrustedAsManualWork(): void
	{
		$cache = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$cache['cron'] = ['last_run' => 0, 'next_due' => 0, 'jitter' => 0, 'pending_apply' => 'yes'];
		file_put_contents($this->dir . '/pfb_due_ledger.json', json_encode($cache, JSON_THROW_ON_ERROR));
		$manualRuns = 0;

		pfblockerng_tick(
			[], NULL, NULL, 5.0, NULL, NULL, 5.0,
			static fn (string $_job, string $_argument = ''): bool => TRUE,
			function (): void {
				$this->feedRuns++;
			},
			static function () use (&$manualRuns): bool {
				$manualRuns++;
				return TRUE;
			}
		);

		$this->assertSame(0, $manualRuns);
		$repaired = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertNotSame('yes', $repaired['cron']['pending_apply'] ?? NULL);
	}

	public function testCachePublicationFailureSuppressesCronAndPreservesBytes(): void
	{
		$before = '{"broken":true}';
		file_put_contents($this->dir . '/pfb_due_ledger.json', $before);
		$GLOBALS['pfb']['schedule_cache_io'] = ['fail_rename' => TRUE];
		$this->tick();
		$this->assertSame($before, file_get_contents($this->dir . '/pfb_due_ledger.json'));
		$this->assertSame(0, $this->feedRuns);
		$this->assertContains('Tick: scheduled feed runtime unavailable; cron selection suppressed.', array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
	}

	public function testStaleCacheHashIsReplacedFromCurrentRuntimeConfig(): void
	{
		$before = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$current = (string) PfbConfig::read('gen/pfb_schedule_minute');
		PfbConfig::writeSystem('gen/pfb_schedule_minute', $current === '30' ? '45' : '30');
		$this->tick();
		$after = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertNotSame($before['_meta']['config_hash'], $after['_meta']['config_hash']);
		$this->assertIsArray(pfb_due_ledger_read_cache($this->dir, $after['_meta']['config_hash']));
	}

	public function testMasterOffSuppressesLegacyDueAndLeavesNoCronWake(): void
	{
		PfbConfig::writeSystem('gen/pfb_scheduled_feed_updates', PfbToggle::Off);
		$this->tick();
		$cache = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertArrayNotHasKey('cron', $cache);
		$this->assertSame(0, $this->feedRuns);
	}

	public function testDisabledFeedFailMarkerRemainsDormantAcrossTicks(): void
	{
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockernglistsv4/config', [[
			'action' => 'Disabled',
			'cron' => 'EveryDay',
			'schedule_override' => '',
			'row' => [['header' => 'runtime', 'url' => 'https://example.test/feed', 'state' => 'Enabled']],
		]]);
		file_put_contents($GLOBALS['pfb']['denydir'] . '/runtime_v4.fail', 'failed');
		$this->tick();
		$this->tick();
		$this->assertSame(0, $this->feedRuns);
		$this->assertFileExists($GLOBALS['pfb']['denydir'] . '/runtime_v4.fail');
	}

	public function testFarPastCronWakeCollapsesToOneRunAndReanchorsFuture(): void
	{
		$cachePath = $this->dir . '/pfb_due_ledger.json';
		$cache = json_decode((string) file_get_contents($cachePath), TRUE);
		$cache['cron'] = ['last_run' => time() - 259200, 'next_due' => time() - 172800, 'jitter' => 0];
		file_put_contents($cachePath, json_encode($cache, JSON_THROW_ON_ERROR));
		$feedRunner = function (): void {
			$this->feedRuns++;
			$state = pfb_schedule_state_read($this->stateDir);
			foreach ($state['items'] ?? [] as $id => $item) {
				if (!str_starts_with($id, 'extra:') && isset($item['pending_occurrence'])) {
					pfb_schedule_state_record_outcome($id, PfbScheduleTerminalResult::Success, $this->stateDir);
				}
			}
		};
		for ($tick = 0; $tick < 2; $tick++) {
			pfblockerng_tick(
				[], NULL, NULL, 5.0, NULL, NULL, 5.0,
				static fn (string $_job, string $_argument = ''): bool => TRUE,
				$feedRunner,
				static fn (): bool => TRUE
			);
		}

		$this->assertSame(1, $this->feedRuns);
		$after = json_decode((string) file_get_contents($cachePath), TRUE);
		$this->assertGreaterThan(time(), $after['cron']['next_due']);
	}

	public function testStalePendingFeedCoalescesToLatestMissedOccurrence(): void
	{
		$stale = time() - 172800;
		$this->assertTrue(pfb_schedule_state_write([
			'schema' => 1,
			'items' => ['ipv4:runtime_v4' => ['pending_occurrence' => $stale]],
		], $this->stateDir));
		$feedRunner = function (): void {
			$this->feedRuns++;
			pfb_schedule_state_record_outcome(
				'ipv4:runtime_v4', PfbScheduleTerminalResult::Success, $this->stateDir
			);
		};

		for ($tick = 0; $tick < 2; $tick++) {
			pfblockerng_tick(
				[], NULL, NULL, 5.0, NULL, NULL, 5.0,
				static fn (string $_job, string $_argument = ''): bool => TRUE,
				$feedRunner,
				static fn (): bool => TRUE
			);
		}

		$state = pfb_schedule_state_read($this->stateDir);
		$this->assertSame(1, $this->feedRuns);
		$this->assertGreaterThan($stale, $state['items']['ipv4:runtime_v4']['last_completed_occurrence']);
		$this->assertGreaterThan(
			time(),
			pfb_due_ledger_read_entry('cron', $this->dir)['next_due']
		);
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

		$this->tick();
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$feed_items = array_filter(
			$state['items'] ?? [],
			static fn (string $id): bool => !str_starts_with($id, 'extra:'),
			ARRAY_FILTER_USE_KEY
		);
		$this->assertSame(
			['ipv4:alpha_v4', 'ipv4:beta_v4', 'ipv6:gamma_v6', 'dnsbl:runtime_dns'],
			array_keys($feed_items)
		);
		foreach (array_keys($feed_items) as $id) {
			$this->assertArrayHasKey('pending_occurrence', $state['items'][$id]);
		}
		$this->assertCount(1, array_unique(array_column($feed_items, 'pending_occurrence')));
		$this->assertSame(1, $this->feedRuns);
	}

	public function testSecondTickWithPendingOccurrenceDoesNotReplayCursor(): void
	{
		$this->tick();
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$state['items']['ipv4:runtime_v4']['last_completed_occurrence'] = $state['items']['ipv4:runtime_v4']['pending_occurrence'];
		$state['items']['ipv4:runtime_v4']['completion_outcome'] = 'success';
		unset($state['items']['ipv4:runtime_v4']['pending_occurrence']);
		$this->assertTrue(pfb_schedule_state_write($state, $this->stateDir));
		$this->feedRuns = 0;
		$this->tick();
		$this->assertSame(0, $this->feedRuns);
	}

	public function testStatePublicationFailureSuppressesDispatchAndPreservesCache(): void
	{
		$GLOBALS['pfb']['schedule_state_io'] = ['fail_rename' => TRUE];
		$before = time();
		$this->tick();
		$after = time();
		$this->assertSame(0, $this->feedRuns);
		$cache = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$this->assertGreaterThanOrEqual($before, $cache['cron']['next_due']);
		$this->assertLessThanOrEqual($after, $cache['cron']['next_due']);
	}

	public function testScheduledCronIgnoresQuietWindow(): void
	{
		PfbConfig::writeSystem('gen/pfb_quiet_hours', '00:00-00:01');
		$this->tick();
		$messages = array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message');
		$this->assertContains('Tick: running scheduled feed pass.', $messages);
		$this->assertSame(1, $this->feedRuns);
	}

	public function testPendingApplyDoesNotSuppressLaterChecksOutsideWindow(): void
	{
		$start = ((int) date('G') + 12) % 24;
		PfbConfig::writeSystem('gen/pfb_quiet_hours', sprintf('%02d:00-%02d:01', $start, $start));
		$model = pfb_schedule_runtime_config();
		$this->assertIsArray($model);
		$this->assertTrue(pfb_schedule_cache_refresh(
			$model,
			['schema' => 1, 'items' => []],
			time(),
			new DateTimeZone(date_default_timezone_get()),
			$this->dir
		));
		$cache = pfb_due_ledger_read_cache($this->dir, $model['config_hash']);
		$this->assertIsArray($cache);
		$cache['cron'] = [
				'last_run' => time() - 3600,
				'next_due' => time() - 1,
				'jitter' => 0,
				'pending_apply' => TRUE,
		];
		$state = ['schema' => 1, 'items' => []];
		foreach ($model['entries'] as $id => $entry) {
			if (str_starts_with($id, 'extra:') && $entry['enabled']) {
				$cache[$id] = ['last_run' => time(), 'next_due' => time() + 86400, 'jitter' => 0];
				$state['items'][$id] = [
					'last_completed_occurrence' => time(),
					'completion_outcome' => 'success',
				];
			}
		}
		$this->assertTrue(pfb_schedule_state_write($state, $this->stateDir));
		unset($cache['_meta']);
		$this->assertTrue(pfb_due_ledger_write_cache($cache, $model['config_hash'], $this->dir));
		$manualRuns = 0;
		$feedSawPending = FALSE;

		pfblockerng_tick(
			[], NULL, NULL, 5.0, NULL, NULL, 5.0,
			static fn (string $_job, string $_argument = ''): bool => TRUE,
			function (bool $pendingChange) use (&$feedSawPending): void {
				$this->feedRuns++;
				$feedSawPending = $pendingChange;
			},
			static function () use (&$manualRuns): bool {
				$manualRuns++;
				return TRUE;
			}
		);

		$this->assertSame(1, $this->feedRuns, 'A pending apply must not suppress later scheduled source checks.');
		$this->assertTrue($feedSawPending, 'The feed funnel must retain pending apply intent outside the window.');
		$this->assertSame(0, $manualRuns, 'Automatic apply must remain deferred outside its window.');
		$this->assertTrue(pfb_due_ledger_read_entry('cron', $this->dir)['pending_apply'] ?? FALSE);
	}

	public function testBusyFeedPassLeavesScheduleCacheAndStateUntouched(): void
	{
		$lock = fopen($this->dir . '/pfb_feed_pass.lock', 'c');
		$this->assertNotFalse($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		$before = file_get_contents($this->dir . '/pfb_due_ledger.json');
		$this->tick();
		$this->assertSame($before, file_get_contents($this->dir . '/pfb_due_ledger.json'));
		$this->assertFileDoesNotExist($this->stateDir . '/pfb_schedule_state.json');
		$this->assertSame(0, $this->feedRuns);
		flock($lock, LOCK_UN);
		fclose($lock);
	}

	public function testFeedPassAcquisitionErrorSkipsScheduledWorkWithoutClaimingContention(): void
	{
		$this->assertTrue(stream_wrapper_register('pfbtickfeedlockerror', PfbFailingFlockStream::class));
		$dbdir = $GLOBALS['pfb']['dbdir'];
		$before = file_get_contents($this->dir . '/pfb_due_ledger.json');
		$GLOBALS['pfb_test_logger_calls'] = [];
		try {
			$GLOBALS['pfb']['dbdir'] = 'pfbtickfeedlockerror://state';

			$this->tick();

			$messages = array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message');
			$this->assertContains(
				'Tick: scheduled work skipped -- the feed-pass lock could not be acquired; see the pfBlockerNG log.',
				$messages,
				'an acquisition error must name the lock failure'
			);
			$this->assertNotContains(
				'Tick: scheduled work deferred (another feed pass is running).',
				$messages,
				'an acquisition error must not claim another pass is running'
			);
			$this->assertSame(0, $this->feedRuns, 'an acquisition error must refuse scheduled feed work');
			$this->assertSame($before, file_get_contents($this->dir . '/pfb_due_ledger.json'),
				'an acquisition error must leave the schedule cache unchanged');
			$this->assertFileDoesNotExist($this->stateDir . '/pfb_schedule_state.json',
				'an acquisition error must not publish schedule state');
			$this->assertFalse(is_resource($GLOBALS['pfb_schedule_dispatch_lock'] ?? NULL),
				'the refused tick must release its dispatcher lock');
		} finally {
			$GLOBALS['pfb']['dbdir'] = $dbdir;
			stream_wrapper_unregister('pfbtickfeedlockerror');
		}
	}

	public function testLegacyPendingApplyDispatchesWhenMasterOff(): void
	{
		PfbConfig::writeSystem('gen/pfb_scheduled_feed_updates', PfbToggle::Off);
		$this->assertTrue(pfb_due_ledger_write_entry('cron', [
			'last_run' => time() - 60, 'next_due' => time() - 1, 'jitter' => 0, 'pending_apply' => TRUE,
		], $this->dir));
		$this->tick();
		$messages = array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message');
		$this->assertContains('Tick: dispatching pending manual apply.', $messages);
		$entry = pfb_due_ledger_read_entry('cron', $this->dir);
		$this->assertFalse($entry['pending_apply'] ?? FALSE);
	}

	public function testDispatcherLockSuppressesConcurrentScheduledTick(): void
	{
		$this->tick();
		$this->feedRuns = 0;
		$GLOBALS['pfb_test_logger_calls'] = [];
		$path = $this->stateDir . '/pfb_schedule_dispatch.lock';
		$lock = fopen($path, 'c');
		$this->assertNotFalse($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		$before = file_get_contents($this->stateDir . '/pfb_schedule_state.json');
		$this->tick();
		$this->assertSame($before, file_get_contents($this->stateDir . '/pfb_schedule_state.json'));
		$this->assertSame(0, $this->feedRuns);
		flock($lock, LOCK_UN);
		fclose($lock);
	}

	public function testMasterOffRetainsDurablePendingOccurrenceWithoutDispatch(): void
	{
		$this->tick();
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$pending = $state['items']['ipv4:runtime_v4']['pending_occurrence'];
		PfbConfig::writeSystem('gen/pfb_scheduled_feed_updates', PfbToggle::Off);
		$this->feedRuns = 0;
		$this->tick();
		$state = json_decode((string) file_get_contents($this->stateDir . '/pfb_schedule_state.json'), TRUE);
		$this->assertSame($pending, $state['items']['ipv4:runtime_v4']['pending_occurrence']);
		$this->assertSame(0, $this->feedRuns);
	}

	public function testDurablePendingFeedWakesEvenWhenValidCachePointsToFuture(): void
	{
		$model = pfb_schedule_runtime_config();
		$this->assertIsArray($model);
		$state = ['schema' => 1, 'items' => [
			'ipv4:runtime_v4' => ['pending_occurrence' => time() - 60],
		]];
		$this->assertTrue(pfb_schedule_state_write($state, $this->stateDir));
		$this->assertTrue(pfb_schedule_cache_refresh(
			$model, ['schema' => 1, 'items' => []], time(), new DateTimeZone(date_default_timezone_get()), $this->dir
		));
		$cache = pfb_due_ledger_read_cache($this->dir, $model['config_hash']);
		$this->assertIsArray($cache);
		$cache['cron']['next_due'] = time() + 86400;
		foreach (['extra:dcc', 'extra:bl'] as $id) {
			if (isset($cache[$id])) {
				$cache[$id]['next_due'] = time() + 86400;
			}
		}
		$this->assertNotFalse(file_put_contents(
			$this->dir . '/pfb_due_ledger.json', json_encode($cache, JSON_THROW_ON_ERROR)
		));

		$this->tick();

		$this->assertSame(1, $this->feedRuns);
	}

	public function testFailMarkerWakesACompletedFeedOnTheNextFixedTick(): void
	{
		$this->tick();
		$state = pfb_schedule_state_read($this->stateDir);
		$this->assertIsArray($state);
		$pending = $state['items']['ipv4:runtime_v4']['pending_occurrence'];
		$state['items']['ipv4:runtime_v4'] = [
			'last_successful_check' => time(),
			'last_completed_occurrence' => $pending,
			'completion_outcome' => 'success',
		];
		$this->assertTrue(pfb_schedule_state_write($state, $this->stateDir));
		$model = pfb_schedule_runtime_config();
		$this->assertIsArray($model);
		$this->assertTrue(pfb_schedule_cache_refresh(
			$model, $state, time(), new DateTimeZone(date_default_timezone_get()), $this->dir
		));
		$this->assertNotFalse(file_put_contents($this->dir . '/deny/runtime_v4.fail', ''));
		$this->feedRuns = 0;

		$this->tick();

		$this->assertSame(1, $this->feedRuns, 'urgent .fail must bypass the completed calendar cursor');
	}

	public function testDisabledGroupKeepsPendingOccurrenceDormant(): void
	{
		$this->tick();
		$state = pfb_schedule_state_read($this->stateDir);
		$this->assertArrayHasKey('pending_occurrence', $state['items']['ipv4:runtime_v4']);
		$group = config_get_path('installedpackages/pfblockernglistsv4/config/0');
		$group['action'] = 'Disabled';
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockernglistsv4/config', [$group]);
		$this->feedRuns = 0;

		$this->tick();

		$this->assertSame(0, $this->feedRuns);
		$after = pfb_schedule_state_read($this->stateDir);
		$this->assertSame(
			$state['items']['ipv4:runtime_v4']['pending_occurrence'],
			$after['items']['ipv4:runtime_v4']['pending_occurrence']
		);
	}

	/**
	 * Scenario: the tick meets a ledger authored only by the due-ledger writer.
	 *
	 * Given the refresh-authored cache is gone and the rows are re-published solely
	 *   through pfb_due_ledger_write_entry(),
	 * When the fixed tick reads the ledger to decide what is due,
	 * Then it does not declare the scheduled feed runtime unavailable -- the writer's
	 *   own output has to be acceptable to the cache reader it shares (issue #2598).
	 *
	 * The feed pass is only a positive control that the tick ran to completion: it
	 * dispatches on either side of this contract (an unusable cache still reaches the
	 * dispatch block to regenerate one), so the notice is the sole discriminator.
	 * Its presence is pinned from the other side by
	 * testCachePublicationFailureSuppressesCronAndPreservesBytes.
	 */
	public function testWriterAuthoredLedgerDoesNotSuppressCronSelection(): void
	{
		$suppressed = 'Tick: scheduled feed runtime unavailable; cron selection suppressed.';
		$now = time();
		$dormant = ['last_run' => $now - 1, 'next_due' => $now + 86400, 'jitter' => 0];
		$overdue = ['last_run' => $now - 86400, 'next_due' => $now - 1, 'jitter' => 0];
		$this->assertTrue(unlink($this->dir . '/pfb_due_ledger.json'),
			'precondition: the refresh-authored cache must be gone');
		$this->assertTrue(pfb_due_ledger_write_entry('extra:dcc', $dormant, $this->dir));
		$this->assertTrue(pfb_due_ledger_write_entry('cron', $overdue, $this->dir));
		$this->assertSame($dormant, pfb_due_ledger_read_entry('extra:dcc', $this->dir),
			'precondition: the writer alone must have authored the document');
		$GLOBALS['pfb_test_logger_calls'] = [];

		$this->tick();

		$this->assertNotContains(
			$suppressed,
			array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'),
			'a ledger authored through pfb_due_ledger_write_entry() must not read as an '
			. 'unavailable runtime; logged='
			. var_export(array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'), TRUE)
		);
		$this->assertSame(1, $this->feedRuns,
			'positive control: the tick must have reached the scheduled feed dispatch');
	}

	private function recorder(): string
	{
		$path = $this->dir . '/php-recorder';
		$log = escapeshellarg($this->dir . '/spawns');
		file_put_contents($path, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> {$log}\n");
		chmod($path, 0755);
		return $path;
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
