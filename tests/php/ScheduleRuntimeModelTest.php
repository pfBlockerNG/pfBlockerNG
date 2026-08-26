<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ScheduleRuntimeModelTest extends TestCase
{
	private const HASH = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_schedule_runtime_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	private function general(string $master = 'on'): array
	{
		return [
			'pfb_scheduled_feed_updates' => $master,
			'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '2',
			'pfb_schedule_minute' => '15',
			'secret' => 'do-not-hash',
		];
	}

	private function row(string $header, string $url = 'https://secret.example/feed', string $state = 'Enabled'): array
	{
		return ['header' => $header, 'url' => $url, 'state' => $state, 'credentials' => 'secret'];
	}

	private function group(mixed $action, string $cron, array $rows, string $override = ''): array
	{
		return [
			'action' => $action,
			'cron' => $cron,
			'schedule_override' => $override,
			'schedule_weekday' => '1',
			'schedule_hour' => '4',
			'schedule_minute' => '30',
			'row' => $rows,
			'description' => 'ignored',
		];
	}

	private function sections(array $v4 = [], array $v6 = [], array $dnsbl = []): array
	{
		return ['ipv4' => $v4, 'ipv6' => $v6, 'dnsbl' => $dnsbl];
	}

	public function testModelNormalizesAllFamiliesAndPreservesRowOrder(): void
	{
		$model = pfb_schedule_runtime_model(
			$this->general(),
			$this->sections(
				[$this->group('Deny_Inbound', '01hour', [$this->row('first'), $this->row('second')])],
				[$this->group('Permit_Both', 'Weekly', [$this->row('six')], 'on')],
				[$this->group('unbound', 'Never', [$this->row('dns')])]
			)
		);

		$this->assertIsArray($model);
		$this->assertTrue($model['scheduled']);
		$this->assertSame(['weekday' => 7, 'hour' => 2, 'minute' => 15], $model['default']);
		$this->assertSame(['ipv4:first_v4', 'ipv4:second_v4', 'ipv6:six_v6', 'dnsbl:dns'], array_keys($model['entries']));
		$this->assertSame([
			'cadence' => '01hour', 'enabled' => TRUE, 'has_active_rows' => TRUE, 'override' => NULL,
		], $model['entries']['ipv4:first_v4']);
		$this->assertSame([
			'cadence' => 'Weekly', 'enabled' => TRUE, 'has_active_rows' => TRUE,
			'override' => ['weekday' => 1, 'hour' => 4, 'minute' => 30],
		], $model['entries']['ipv6:six_v6']);
		$this->assertFalse($model['entries']['dnsbl:dns']['enabled']);
		$this->assertStringNotContainsString('secret.example', json_encode($model, JSON_THROW_ON_ERROR));
		$this->assertStringNotContainsString('do-not-hash', $model['config_hash']);
	}

	public function testHashIgnoresReorderingDormantAndUnrelatedValuesButTracksEffectiveChanges(): void
	{
		$base = $this->sections(
			[$this->group('Deny_Inbound', 'EveryDay', [$this->row('one'), $this->row('two')])],
			[$this->group('Permit_Both', '02hours', [$this->row('six')])],
		);
		$reordered = $base;
		$reordered['ipv4'][0]['row'] = [$base['ipv4'][0]['row'][1], $base['ipv4'][0]['row'][0]];
		$first = pfb_schedule_runtime_model($this->general(), $base);
		$second = pfb_schedule_runtime_model($this->general(), $reordered);
		$this->assertSame($first['config_hash'], $second['config_hash']);

		$dormant = $base;
		$dormant['ipv4'][0]['schedule_weekday'] = ['bad', 'ignored'];
		$dormant['ipv4'][0]['schedule_hour'] = 'not-used';
		$dormant['ipv4'][0]['row'][0]['credentials'] = 'changed';
		$this->assertSame($first['config_hash'], pfb_schedule_runtime_model($this->general(), $dormant)['config_hash']);

		$changed = $base;
		$changed['ipv4'][0]['cron'] = 'Weekly';
		$this->assertNotSame($first['config_hash'], pfb_schedule_runtime_model($this->general(), $changed)['config_hash']);
		$this->assertNotSame($first['config_hash'], pfb_schedule_runtime_model($this->general(''), $base)['config_hash']);
		$equivalent_action = $base;
		$equivalent_action['ipv4'][0]['action'] = 'Permit_Both';
		$this->assertSame($first['config_hash'], pfb_schedule_runtime_model($this->general(), $equivalent_action)['config_hash']);
	}

	public function testInactiveRowsAndGroupsDoNotFailButHostileScheduledShapesReturnNull(): void
	{
		$model = pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('invalid-action', 'Never', [$this->row('inactive')]),
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('held', 'https://x', 'Hold')]),
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('disabled', 'https://x', 'Disabled')]),
		]));
		$this->assertIsArray($model);
		$this->assertSame(['ipv4:inactive_v4', 'ipv4:held_v4'], array_keys($model['entries']));
		$this->assertFalse($model['entries']['ipv4:inactive_v4']['enabled']);

		$invalid = [
			[['ipv4' => 'not-array', 'ipv6' => [], 'dnsbl' => []], $this->general()],
			[$this->sections([['action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'row' => 'bad']]), $this->general()],
			[$this->sections([$this->group('Deny_Inbound', 'EveryDay', [$this->row('bad header!')])]), $this->general()],
			[$this->sections([$this->group('Deny_Inbound', 'EveryDay', [$this->row('duplicate')]), $this->group('Deny_Inbound', 'EveryDay', [$this->row('duplicate')])]), $this->general()],
		];
		foreach ($invalid as [$sections, $general]) {
			$this->assertNull(pfb_schedule_runtime_model($general, $sections));
		}
		$this->assertNull(pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('bad')], 'maybe'),
		])));
	}

	public function testMalformedScheduledRowTokensAndActionShapesFailClosed(): void
	{
		$cases = [];
		$row = $this->row('hostile');
		$row['format'] = [];
		$cases[] = $row;
		$row = $this->row('hostile');
		$row['url'] = ['not-a-url'];
		$cases[] = $row;
		$row = $this->row('hostile');
		$row['state'] = ['Enabled'];
		$cases[] = $row;
		$row = $this->row('hostile');
		$row['state'] = 'Unknown';
		$cases[] = $row;
		$row = $this->row('hostile');
		$row['header'] = 123;
		$cases[] = $row;
		foreach ($cases as $hostile_row) {
			$this->assertNull(pfb_schedule_runtime_model($this->general(), $this->sections([
				$this->group('Deny_Inbound', 'EveryDay', [$hostile_row]),
			])));
		}
		$this->assertNull(pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group([], 'EveryDay', [$this->row('hostile')]),
		])));

		$missing = $this->row('missing');
		unset($missing['url']);
		$this->assertSame([], pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$missing]),
		]))['entries']);
		$empty = $this->row('empty', '');
		$this->assertSame([], pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$empty]),
		]))['entries']);
		$unknown_action = pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('unknown-action', 'EveryDay', [$this->row('inactive')]),
		]));
		$this->assertIsArray($unknown_action);
		$this->assertFalse($unknown_action['entries']['ipv4:inactive_v4']['enabled']);
	}

	public function testMalformedSourceInterfaceFailsClosedBeforeScheduledCron(): void
	{
		$general = $this->general();
		$groups = $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('hostile')]),
		]);
		$this->assertIsArray(pfb_schedule_runtime_model($general, $groups));
		$groups['ipv4'][0]['srcint'] = ['wan'];

		$this->assertNull(pfb_schedule_runtime_model($general, $groups));
	}

	public function testModelValidatorRejectsSemanticTampering(): void
	{
		$model = pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('feed')]),
		]));
		$this->assertIsArray($model);
		$this->assertTrue(pfb_schedule_runtime_model_valid($model));
		foreach (['default', 'entries'] as $field) {
			$tampered = $model;
			if ($field === 'default') {
				$tampered['default']['hour'] = 3;
			} else {
				$tampered['entries']['ipv4:feed_v4']['cadence'] = '02hours';
			}
			$this->assertFalse(pfb_schedule_runtime_model_valid($tampered), $field);
		}
		$tampered = $model;
		$tampered['entries']['ipv4:feed_v4']['enabled'] = FALSE;
		$this->assertFalse(pfb_schedule_runtime_model_valid($tampered));
		$tampered = $model;
		$tampered['entries']['ipv4:feed_v4']['override'] = ['weekday' => 1, 'hour' => 4, 'minute' => 30];
		$this->assertFalse(pfb_schedule_runtime_model_valid($tampered));
		$tampered = $model;
		$tampered['entries']['ipv4:other_v4'] = $tampered['entries']['ipv4:feed_v4'];
		unset($tampered['entries']['ipv4:feed_v4']);
		$this->assertFalse(pfb_schedule_runtime_model_valid($tampered));
	}

	public function testRefreshPublishesDueFutureAndPreservesNonCronEntries(): void
	{
		$model = pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('feed')]),
		]));
		$this->assertIsArray($model);
		$state = ['schema' => 1, 'items' => ['ipv4:feed_v4' => ['last_completed_occurrence' => 0, 'completion_outcome' => 'success']]];
		$this->assertTrue(pfb_due_ledger_write_cache([
			'dcc' => ['last_run' => 1, 'next_due' => 2, 'jitter' => 0],
			'cron' => ['last_run' => 1, 'next_due' => 2, 'jitter' => 0],
		], str_repeat('b', 64), $this->dir));
		$now = strtotime('2026-01-04 02:15:00 UTC');
		$this->assertTrue(pfb_schedule_cache_refresh($model, $state, $now, new DateTimeZone('UTC'), $this->dir));
		$cache = pfb_due_ledger_read_cache($this->dir, $model['config_hash']);
		$this->assertIsArray($cache);
		$this->assertSame(0, $cache['cron']['last_run']);
		$this->assertSame($now, $cache['cron']['next_due']);
		$this->assertSame(0, $cache['cron']['jitter']);
		$this->assertSame(['last_run' => 1, 'next_due' => 2, 'jitter' => 0], $cache['dcc']);
	}

	public function testRefreshMasterOffSleepsUnlessConfiguredPending(): void
	{
		$model = pfb_schedule_runtime_model($this->general(''), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('feed')]),
		]));
		$this->assertIsArray($model);
		$state = ['schema' => 1, 'items' => []];
		$now = strtotime('2026-01-04 02:15:00 UTC');
		$this->assertTrue(pfb_schedule_cache_refresh($model, $state, $now, new DateTimeZone('UTC'), $this->dir));
		$this->assertSame(['_meta' => ['schema' => 1, 'config_hash' => $model['config_hash']]], pfb_due_ledger_read_cache($this->dir, $model['config_hash']));
		$state['items']['ipv4:feed_v4'] = ['pending_occurrence' => $now - 60];
		$this->assertTrue(pfb_schedule_cache_refresh($model, $state, $now, new DateTimeZone('UTC'), $this->dir));
		$this->assertSame(
			['_meta' => ['schema' => 1, 'config_hash' => $model['config_hash']]],
			pfb_due_ledger_read_cache($this->dir, $model['config_hash'])
		);
	}

	public function testRefreshReplacesMalformedTargetAtomically(): void
	{
		$model = pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('feed')]),
		]));
		$this->assertIsArray($model);
		$path = $this->dir . '/pfb_due_ledger.json';
		file_put_contents($path, '{"broken":true}');
		$before = file_get_contents($path);
		$this->assertTrue(pfb_schedule_cache_refresh($model, ['schema' => 1, 'items' => []], time(), new DateTimeZone('UTC'), $this->dir));
		$this->assertNotSame($before, file_get_contents($path));
		$this->assertIsArray(pfb_due_ledger_read_cache($this->dir, $model['config_hash']));
	}

	public function testRefreshPublicationFailurePreservesMalformedBytes(): void
	{
		$model = pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('feed')]),
		]));
		$this->assertIsArray($model);
		$path = $this->dir . '/pfb_due_ledger.json';
		file_put_contents($path, '{"broken":true}');
		$before = file_get_contents($path);
		$this->assertFalse(pfb_schedule_cache_refresh($model, ['schema' => 1, 'items' => []], time(), new DateTimeZone('UTC'), $this->dir, ['fail_rename' => TRUE]));
		$this->assertSame($before, file_get_contents($path));
	}

	public function testRefreshPreservesCronPendingApplyAcrossReplacementAndSleep(): void
	{
		$model = pfb_schedule_runtime_model($this->general(), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('feed')]),
		]));
		$this->assertIsArray($model);
		$pending = ['last_run' => 1, 'next_due' => 2, 'jitter' => 0, 'pending_apply' => TRUE];
		$this->assertTrue(pfb_due_ledger_write_cache(['cron' => $pending], str_repeat('b', 64), $this->dir));
		$now = strtotime('2026-01-04 01:15:00 UTC');
		$completed = ['schema' => 1, 'items' => ['ipv4:feed_v4' => [
			'last_completed_occurrence' => $now, 'completion_outcome' => 'success',
		]]];
		$this->assertTrue(pfb_schedule_cache_refresh($model, $completed, $now, new DateTimeZone('UTC'), $this->dir));
		$cache = pfb_due_ledger_read_cache($this->dir, $model['config_hash']);
		$this->assertSame(TRUE, $cache['cron']['pending_apply']);
		$this->assertGreaterThan($now, $cache['cron']['next_due']);
		$scheduled_next_due = $cache['cron']['next_due'];

		$off = pfb_schedule_runtime_model($this->general(''), $this->sections([
			$this->group('Deny_Inbound', 'EveryDay', [$this->row('feed')]),
		]));
		$this->assertIsArray($off);
		$this->assertTrue(pfb_schedule_cache_refresh($off, $completed, $now, new DateTimeZone('UTC'), $this->dir));
		$cache = pfb_due_ledger_read_cache($this->dir, $off['config_hash']);
		$this->assertSame(TRUE, $cache['cron']['pending_apply']);
		$this->assertSame($scheduled_next_due, $cache['cron']['next_due']);
	}
}
