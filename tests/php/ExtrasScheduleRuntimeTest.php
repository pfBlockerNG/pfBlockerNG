<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #2308: Extras share the runtime schedule, but never the feed cron cache. */
final class ExtrasScheduleRuntimeTest extends TestCase
{
	private string $dir = '';
	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] ??= [];
		$this->dir = sys_get_temp_dir() . '/pfb_extra_schedule_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		rmdir_recursive($this->dir);
	}

	/**
	 * #2016: the extras runner now spawns through pfb_reentry_exec(), so a row that
	 * drives it needs a real timeout(1). A gate whose tool is missing is a failure.
	 */
	private function realTimeout(): string
	{
		$path = trim((string) shell_exec('command -v timeout 2>/dev/null'));
		if ($path === '' || !is_executable($path)) {
			$this->fail('no timeout(1) on PATH: the extras runner rows spawn through the bounded seam');
		}
		return $path;
	}

	private function general(string $master = ''): array
	{
		return [
			'pfb_scheduled_feed_updates' => $master,
			'pfb_schedule_weekday' => '3',
			'pfb_schedule_hour' => '2',
			'pfb_schedule_minute' => '15',
		];
	}

	private function feedSections(): array
	{
		return [
			'ipv4' => [[
				'action' => 'Deny_Inbound',
				'cron' => 'EveryDay',
				'schedule_override' => '',
				'row' => [['header' => 'feed', 'url' => 'https://example.test/feed', 'state' => 'Enabled']],
			]],
			'ipv6' => [],
			'dnsbl' => [],
		];
	}

	public function testExtrasAreIndependentAndUseExactCadence(): void
	{
		$model = pfb_schedule_runtime_model($this->general(), $this->feedSections(), [
			'dcc' => TRUE,
			'bl' => ['enabled' => TRUE, 'cadence' => 'Weekly'],
		]);

		$this->assertIsArray($model);
		$this->assertFalse($model['scheduled']);
		$this->assertSame('EveryDay', $model['entries']['extra:dcc']['cadence']);
		$this->assertTrue($model['entries']['extra:dcc']['enabled']);
		$this->assertSame('Weekly', $model['entries']['extra:bl']['cadence']);
		$this->assertTrue($model['entries']['extra:bl']['enabled']);
		$this->assertTrue(pfb_schedule_runtime_model_valid($model));
	}

	public function testExtraEligibilityAndCadenceAffectSecretFreeHash(): void
	{
		$base = pfb_schedule_runtime_model($this->general(), $this->feedSections(), [
			'dcc' => TRUE,
			'bl' => ['enabled' => TRUE, 'cadence' => 'EveryDay'],
		]);
		$weekly = pfb_schedule_runtime_model($this->general(), $this->feedSections(), [
			'dcc' => TRUE,
			'bl' => ['enabled' => TRUE, 'cadence' => 'Weekly'],
		]);
		$disabled = pfb_schedule_runtime_model($this->general(), $this->feedSections(), [
			'dcc' => FALSE,
			'bl' => ['enabled' => FALSE, 'cadence' => 'EveryDay'],
		]);

		$this->assertIsArray($base);
		$this->assertIsArray($weekly);
		$this->assertIsArray($disabled);
		$this->assertNotSame($base['config_hash'], $weekly['config_hash']);
		$this->assertNotSame($base['config_hash'], $disabled['config_hash']);
		$this->assertStringNotContainsString('secret', $base['config_hash']);
	}

	public function testFeedCacheExcludesLegacyExtraLedgerEntriesAndUsesZeroJitter(): void
	{
		$model = pfb_schedule_runtime_model($this->general('on'), $this->feedSections(), [
			'dcc' => TRUE,
			'bl' => ['enabled' => TRUE, 'cadence' => 'EveryDay'],
		]);
		$this->assertIsArray($model);
		$this->assertTrue(pfb_due_ledger_write_cache([
			'dcc' => ['last_run' => 1, 'next_due' => 2, 'jitter' => 123],
			'bl' => ['last_run' => 1, 'next_due' => 2, 'jitter' => 456],
		], str_repeat('a', 64), $this->dir));
		$this->assertTrue(pfb_schedule_cache_refresh(
			$model,
			['schema' => 1, 'items' => []],
			strtotime('2026-01-07 02:15:00 UTC'),
			new DateTimeZone('UTC'),
			$this->dir
		));
		$cache = pfb_due_ledger_read_cache($this->dir, $model['config_hash']);
		$this->assertIsArray($cache);
		$this->assertSame(0, $cache['extra:dcc']['jitter']);
		$this->assertSame(0, $cache['extra:bl']['jitter']);
		$this->assertArrayHasKey('cron', $cache);
		$this->assertSame(0, $cache['cron']['jitter']);
	}

	public function testExtraOutcomeUsesPendingOccurrenceIdentity(): void
	{
		$occurrence = 1_700_000_000;
		$this->assertTrue(pfb_schedule_state_write([
			'schema' => 1,
			'items' => ['extra:dcc' => [
				'pending_occurrence' => $occurrence,
				'pending_attempted' => TRUE,
			]],
		], $this->dir));
		$this->assertTrue(pfb_schedule_state_record_outcome(
			'extra:dcc',
			PfbScheduleTerminalResult::Success,
			$this->dir,
			$occurrence + 10,
			[],
			$occurrence
		));
		$state = pfb_schedule_state_read($this->dir);
		$this->assertSame($occurrence, $state['items']['extra:dcc']['last_completed_occurrence']);
		$this->assertSame('success', $state['items']['extra:dcc']['completion_outcome']);
		$this->assertSame($occurrence + 10, $state['items']['extra:dcc']['last_successful_check']);
		$this->assertArrayNotHasKey('pending_attempted', $state['items']['extra:dcc']);
	}

	public function testPendingFailureWaitsForNextScheduledOccurrence(): void
	{
		$model = pfb_schedule_runtime_model($this->general(''), $this->feedSections(), [
			'dcc' => TRUE,
			'bl' => ['enabled' => FALSE, 'cadence' => 'EveryDay'],
		]);
		$this->assertIsArray($model);
		$now = strtotime('2026-01-07 02:30:00 UTC');
		$pending = strtotime('2026-01-07 02:15:00 UTC');
		$state = ['schema' => 1, 'items' => ['extra:dcc' => [
			'pending_occurrence' => $pending, 'pending_attempted' => TRUE,
		]]];
		$this->assertTrue(pfb_schedule_cache_refresh($model, $state, $now, new DateTimeZone('UTC'), $this->dir));
		$cache = pfb_due_ledger_read_cache($this->dir, $model['config_hash']);
		$this->assertIsArray($cache);
		$this->assertGreaterThan($now, $cache['extra:dcc']['next_due']);
		$this->assertSame([], pfb_schedule_extra_plan($model, $state, $now, new DateTimeZone('UTC'), $cache)['due']);
	}

	public function testUnattemptedReservedExtraRetriesBeforeFailedExtraCadence(): void
	{
		$model = pfb_schedule_runtime_model($this->general(''), $this->feedSections(), [
			'dcc' => TRUE,
			'bl' => ['enabled' => FALSE, 'cadence' => 'EveryDay'],
		]);
		$this->assertIsArray($model);
		$now = strtotime('2026-01-07 02:30:00 UTC');
		$state = ['schema' => 1, 'items' => ['extra:dcc' => [
			'pending_occurrence' => strtotime('2026-01-07 02:15:00 UTC'),
		]]];
		$this->assertTrue(pfb_schedule_cache_refresh($model, $state, $now, new DateTimeZone('UTC'), $this->dir));
		$cache = pfb_due_ledger_read_cache($this->dir, $model['config_hash']);
		$this->assertSame($now, $cache['extra:dcc']['next_due']);
		$this->assertSame(['extra:dcc'], pfb_schedule_extra_plan(
			$model, $state, $now, new DateTimeZone('UTC'), $cache
		)['due']);
	}

	public function testInterruptedGeoipPublicationForcesDccRecoveryOnNextTick(): void
	{
		$model = pfb_schedule_runtime_model($this->general(''), $this->feedSections(), [
			'dcc' => TRUE,
			'bl' => ['enabled' => FALSE, 'cadence' => 'EveryDay'],
		]);
		$this->assertIsArray($model);
		$now = strtotime('2026-01-07 02:30:00 UTC');
		$completed = strtotime('2026-01-07 02:15:00 UTC');
		$state = ['schema' => 1, 'items' => ['extra:dcc' => [
			'last_completed_occurrence' => $completed, 'completion_outcome' => 'success',
		]]];
		$this->assertTrue(pfb_schedule_cache_refresh($model, $state, $now, new DateTimeZone('UTC'), $this->dir));
		$cache = pfb_due_ledger_read_cache($this->dir, $model['config_hash']);
		$this->assertIsArray($cache);
		$this->assertSame([], pfb_schedule_extra_plan($model, $state, $now, new DateTimeZone('UTC'), $cache)['due']);

		mkdir($this->dir . '/cc');
		$GLOBALS['pfb']['ccdir'] = $this->dir . '/cc';
		file_put_contents($this->dir . '/cc/.pfb_generation_swapping', 'interrupted');

		$this->assertSame(
			['extra:dcc'],
			pfb_schedule_extra_plan($model, $state, $now, new DateTimeZone('UTC'), $cache)['due']
		);
	}

	public function testExtraPublicationFailureLeavesPendingOccurrence(): void
	{
		$occurrence = 1_700_000_000;
		$this->assertTrue(pfb_schedule_state_write([
			'schema' => 1,
			'items' => ['extra:dcc' => ['pending_occurrence' => $occurrence]],
		], $this->dir));
		$this->assertFalse(pfb_schedule_state_record_outcome(
			'extra:dcc',
			PfbScheduleTerminalResult::Success,
			$this->dir,
			$occurrence + 10,
			['fail_rename' => TRUE],
			$occurrence
		));
		$state = pfb_schedule_state_read($this->dir);
		$this->assertArrayHasKey('pending_occurrence', $state['items']['extra:dcc']);
	}

	public function testExtraRunnerUsesConfiguredPhpSynchronously(): void
	{
		$script = $this->dir . '/php';
		$args = $this->dir . '/args';
		file_put_contents($script, "#!/bin/sh\n"
			. "printf '%s\\n' \"\$*\" >> " . escapeshellarg($args) . "\n"
			. "printf 'child output: %s\\n' \"\$*\"\n");
		chmod($script, 0755);
		$GLOBALS['pfb']['php'] = $script;
		$GLOBALS['pfb']['extraslog'] = $this->dir . '/extras.log';
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();

		$this->assertTrue(pfb_schedule_extra_run('dcc'));
		$this->assertTrue(pfb_schedule_extra_run('bl', 'one,two'));
		$this->assertSame([
			'/usr/local/www/pfblockerng/pfblockerng.php dcc scheduled',
			'/usr/local/www/pfblockerng/pfblockerng.php bl scheduled one,two',
		], file($args, FILE_IGNORE_NEW_LINES));
		$this->assertSame([
			'child output: /usr/local/www/pfblockerng/pfblockerng.php dcc scheduled',
			'child output: /usr/local/www/pfblockerng/pfblockerng.php bl scheduled one,two',
		], file($GLOBALS['pfb']['extraslog'], FILE_IGNORE_NEW_LINES));
	}

	public function testScheduledDccReportsTop1mChangeWithoutTreatingItAsFailure(): void
	{
		$script = $this->dir . '/php-changed';
		file_put_contents($script, "#!/bin/sh\nexit 2\n");
		chmod($script, 0755);
		$GLOBALS['pfb']['php'] = $script;
		$GLOBALS['pfb']['extraslog'] = $this->dir . '/extras.log';
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$changed = FALSE;

		$this->assertTrue(pfb_schedule_extra_run('dcc', '', $changed));
		$this->assertTrue($changed);
	}

	public function testScheduledDccPreservesTop1mChangeWhenAnotherExtraFails(): void
	{
		$script = $this->dir . '/php-failed-changed';
		file_put_contents($script, "#!/bin/sh\nexit 3\n");
		chmod($script, 0755);
		$GLOBALS['pfb']['php'] = $script;
		$GLOBALS['pfb']['extraslog'] = $this->dir . '/extras.log';
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$changed = FALSE;

		$this->assertFalse(pfb_schedule_extra_run('dcc', '', $changed));
		$this->assertTrue($changed, 'TOP1M change must survive an unrelated DCC failure');
	}

	public function testMalformedBlacklistIdentitySuppressesRuntimeInsteadOfThrowing(): void
	{
		config_set_path('installedpackages/pfblockerng/config/0', [
			'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '1', 'pfb_schedule_minute' => '0',
		]);
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => 'one', 'blacklist_freq' => 'EveryDay',
			'item' => [['xml' => [], 'selected' => 'yes', 'title' => 'One', 'feed' => 'https://example.test/one']],
		]);

		$this->assertNull(pfb_schedule_runtime_config());

		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => 'bad;id', 'blacklist_freq' => 'EveryDay',
			'item' => [[
				'xml' => 'bad;id', 'selected' => 'yes', 'title' => 'Bad', 'feed' => 'https://example.test/bad',
			]],
		]);
		$this->assertNull(pfb_schedule_runtime_config());

		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => '0', 'blacklist_freq' => 'EveryDay',
			'item' => [[
				'xml' => '0', 'selected' => 'yes', 'title' => 'Zero', 'feed' => 'https://example.test/zero',
			]],
		]);
		$this->assertNull(pfb_schedule_runtime_config());
	}
}
