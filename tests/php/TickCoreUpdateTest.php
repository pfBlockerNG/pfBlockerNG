<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941: the tick keeps the Outpost's duties and asks Core to run what only the Outpost can tell is due
 * (docs/misc/core-api-protocol.md, StartUpdate):
 *   - a pending change inside the apply window is one `StartUpdate` of trigger `apply`; outside it the tick only says it is
 *     deferred, and the apply record says waiting;
 *   - a `*.fail` marker of an enabled feed (or an absent DNSBL manifest, DnsblManifestTickRecoveryTest) is one trigger `retry`;
 *   - nothing pending, nothing failed: no call; Core refusing (`conflict`) is a logged skip, Core unreachable a logged notice,
 *     and nothing is ever run in this process instead;
 *   - the tick no longer reads or writes the schedule state or the schedule cache.
 */
#[CoversFunction('pfblockerng_tick')]
final class TickCoreUpdateTest extends TestCase
{
	private string $dir = '';
	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;
	/** @var list<array{0: string, 1: array}> every call the tick made to Core */
	private array $calls = [];
	/** @var array{status: int, body: ?array, error: ?string} what StartUpdate answers */
	private array $answer = ['status' => 200, 'body' => [], 'error' => NULL];
	private int $reconciles = 0;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_tick_core_' . getmypid() . '_' . bin2hex(random_bytes(6));
		foreach (['state', 'deny', 'match', 'permit', 'native', 'dnsbl'] as $sub) {
			mkdir("{$this->dir}/{$sub}", 0755, TRUE);
		}
		$pfb = &$GLOBALS['pfb'];
		$pfb['dbdir'] = $this->dir;
		$pfb['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$pfb['schedule_state_dir'] = "{$this->dir}/state";
		$pfb['runlog'] = "{$this->dir}/run.log";
		$pfb['extraslog'] = "{$this->dir}/extras.log";
		$pfb['log'] = "{$this->dir}/pfb.log";
		$pfb['logdir'] = $this->dir;
		$pfb['errlog'] = "{$this->dir}/error.log";
		$pfb['denydir'] = "{$this->dir}/deny";
		$pfb['matchdir'] = "{$this->dir}/match";
		$pfb['permitdir'] = "{$this->dir}/permit";
		$pfb['nativedir'] = "{$this->dir}/native";
		$pfb['dnsdir'] = "{$this->dir}/dnsbl";
		$pfb['enable'] = PfbToggle::On;
		$pfb['unbound_py_sources'] = '';
		unset($pfb);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		config_set_path('installedpackages/pfblockerng/config/0', [
			'skipfeed' => '0', 'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '0', 'pfb_schedule_minute' => '0', 'pfb_quiet_hours' => '',
		]);
		config_set_path('installedpackages/pfblockernglistsv4/config', [[
			'aliasname' => 'Test', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'schedule_override' => '',
			'row' => [['header' => 'feed', 'url' => 'https://example.test/feed', 'state' => 'Enabled']],
		]]);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		$this->calls = [];
		$this->answer = ['status' => 200, 'body' => [], 'error' => NULL];
		$this->reconciles = 0;
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		unset($GLOBALS['pfb_test_logger_calls']);
		rmdir_recursive($this->dir);
	}

	/** A tick against a stand-in for Core that records its calls; only the Update requests are answered with $this->answer. */
	private function tick(): void
	{
		pfblockerng_tick(
			ps_lines: [],
			ss_refresh: static fn (): bool => TRUE,
			apply_reconcile: function (): void {
				$this->reconciles++;
			},
			core_settings: static fn (): ?string => NULL,
			core_call: function (string $method, array $params = []): array {
				$this->calls[] = [$method, $params];
				return $method === 'StartUpdate' ? $this->answer
					: ['status' => 200, 'body' => ['running' => FALSE, 'update' => NULL, 'log' => '', 'next' => 0], 'error' => NULL];
			}
		);
	}

	/** @return list<string> the triggers the tick asked Core for, in order */
	private function started(): array
	{
		$out = [];
		foreach ($this->calls as [$method, $params]) {
			if ($method === 'StartUpdate') {
				$out[] = $params['trigger'];
			}
		}
		return $out;
	}

	/** @return list<string> */
	private function logged(): array
	{
		return array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message');
	}

	private function windowShut(): void
	{
		$start = ((int) date('G') + 12) % 24;
		PfbConfig::writeSystem('gen/pfb_quiet_hours', sprintf('%02d:00-%02d:01', $start, $start));
		$this->assertFalse(pfb_quiet_hours_in_window(time(), (string) PfbConfig::read('gen/pfb_quiet_hours')), 'fixture: now is outside the window');
	}

	public function testTheProductionPhpIsWhatTheNestedVerbsRun(): void
	{
		$this->assertSame('/usr/local/bin/php', $GLOBALS['pfb']['php']);
	}

	public function testAPendingChangeInsideTheWindowAsksCoreForOneApplyWithARequestId(): void
	{
		pfb_mark_pending_changes();

		$this->tick();

		$this->assertSame(['apply'], $this->started());
		$params = array_values(array_filter($this->calls, static fn (array $c): bool => $c[0] === 'StartUpdate'))[0][1];
		$this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/D', $params['requestId']);
		$this->assertSame(['requestId', 'trigger'], array_keys($params), 'an apply names no scope and no force');
	}

	public function testALedgerPendingApplyAloneAsksCoreForAnApplyAndEachTickMakesItsOwnRequestId(): void
	{
		$this->assertFalse(pfb_pending_changes(), 'before-state: no marker');
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));

		$this->tick();
		$this->tick();

		$ids = [];
		foreach ($this->calls as [$method, $params]) {
			if ($method === 'StartUpdate') {
				$ids[] = $params['requestId'];
			}
		}
		$this->assertCount(2, $ids);
		$this->assertNotSame($ids[0], $ids[1], 'a repeat of one request would replay the first answer');
	}

	public function testAPendingChangeOutsideTheWindowIsDeferredAndRecordedAsWaitingWithNoCall(): void
	{
		$this->windowShut();
		pfb_mark_pending_changes();
		pfb_sync_apply_record('failed', 'an earlier apply', $this->dir, TRUE);

		$this->tick();

		$this->assertSame([], $this->started());
		$this->assertContains('Tick: feed cron deferred (outside apply window).', $this->logged());
		$apply = pfb_sync_receive_state_read($this->dir)['apply'];
		$this->assertSame('waiting', $apply['outcome']);
		$this->assertSame('outside the apply window', $apply['reason']);
	}

	public function testAFailMarkerOfAnEnabledFeedAsksCoreForARetry(): void
	{
		$this->tick();
		$this->assertSame([], $this->started(), 'before-state: nothing failed, nothing pending, no call');

		$this->assertTrue(touch("{$this->dir}/deny/feed_v4.fail"));
		$this->tick();

		$this->assertSame(['retry'], $this->started());
	}

	public function testAFailMarkerOfADisabledFeedStaysDormant(): void
	{
		config_set_path('installedpackages/pfblockernglistsv4/config/0/action', 'Disabled');
		$this->assertTrue(touch("{$this->dir}/deny/feed_v4.fail"));

		$this->tick();

		$this->assertSame([], $this->started());
	}

	public function testAPendingChangeInsideTheWindowIsOneApplyEvenWithAFailMarker(): void
	{
		pfb_mark_pending_changes();
		$this->assertTrue(touch("{$this->dir}/deny/feed_v4.fail"));

		$this->tick();

		$this->assertSame(['apply'], $this->started(), 'Core runs one Update at a time: the retry waits for the next tick');
	}

	public function testAPendingChangeOutsideTheWindowDoesNotHoldBackARetry(): void
	{
		$this->windowShut();
		pfb_mark_pending_changes();
		$this->assertTrue(touch("{$this->dir}/deny/feed_v4.fail"));

		$this->tick();

		$this->assertSame(['retry'], $this->started());
		$this->assertContains('Tick: feed cron deferred (outside apply window).', $this->logged());
	}

	public function testACoreThatRefusesBecauseAnUpdateRunsIsALoggedSkipAndNothingRunsHere(): void
	{
		pfb_mark_pending_changes();
		$this->answer = ['status' => 409, 'body' => ['error' => ['code' => 'conflict', 'message' => 'an Update is running']], 'error' => NULL];

		$this->tick();

		$this->assertSame(['apply'], $this->started());
		$this->assertTrue(pfb_pending_changes(), 'the marker stays for the next tick');
		$logged = array_filter($GLOBALS['pfb_test_logger_calls'], static fn (array $c): bool => str_contains($c['message'], 'an Update is running'));
		$this->assertCount(1, $logged);
		$this->assertSame(LOG_INFO, array_values($logged)[0]['priority'], 'a skip is information, not a problem');
		$this->assertFileDoesNotExist("{$this->dir}/spawns");
	}

	public function testACoreThatDoesNotAnswerIsALoggedNoticeAndNothingRunsHere(): void
	{
		pfb_mark_pending_changes();
		$this->answer = ['status' => 0, 'body' => NULL, 'error' => 'could not connect to the Core API socket'];

		$this->tick();

		$this->assertSame(['apply'], $this->started());
		$logged = array_filter($GLOBALS['pfb_test_logger_calls'], static fn (array $c): bool => str_contains($c['message'], 'could not connect'));
		$this->assertCount(1, $logged, 'the reason is logged once');
		$this->assertSame(LOG_NOTICE, array_values($logged)[0]['priority']);
		$this->assertTrue(pfb_pending_changes(), 'nothing was applied locally');
		$this->assertFileDoesNotExist("{$this->dir}/spawns");
	}

	/**
	 * The tick judges Core's answer by the same rule as the Update page (pfb_update_core_failure()): only a 200 with a reply object
	 * started the Update. An HTTP 200 whose body is no JSON object is Core's answer gone wrong, not an Update that started.
	 */
	public function testAReplyThatIsNoJsonObjectIsALoggedNoticeNotAnUpdateThatStarted(): void
	{
		pfb_mark_pending_changes();
		$this->answer = ['status' => 200, 'body' => NULL, 'error' => 'the Core API reply is not a JSON object'];

		$this->tick();

		$this->assertSame(['apply'], $this->started());
		$logged = array_values(array_filter($GLOBALS['pfb_test_logger_calls'], static fn (array $c): bool => str_contains($c['message'], 'the Core API reply is not a JSON object')));
		$this->assertCount(1, $logged, 'the reason is logged once');
		$this->assertSame(LOG_NOTICE, $logged[0]['priority']);
		$this->assertStringContainsString('nothing was run', $logged[0]['message']);
		$this->assertNotContains('Tick: asked Core to start the apply Update.', $this->logged(), 'an answer that is no answer started nothing');
	}

	public function testARefusalWithNoMessageNamesTheHttpStatus(): void
	{
		pfb_mark_pending_changes();
		$this->answer = ['status' => 500, 'body' => [], 'error' => NULL];

		$this->tick();

		$logged = array_values(array_filter($GLOBALS['pfb_test_logger_calls'], static fn (array $c): bool => str_contains($c['message'], 'the Core API answered 500')));
		$this->assertCount(1, $logged);
		$this->assertSame(LOG_NOTICE, $logged[0]['priority']);
	}

	public function testTheTickTouchesNeitherTheScheduleStateNorTheScheduleCacheAndStillRunsItsOwnDuties(): void
	{
		// Given a group a scheduler would plan, and no state and no cache anywhere
		$this->assertSame([], glob("{$this->dir}/state/*") ?: []);

		// When the tick runs with a marker, a failure and every Outpost job due
		pfb_mark_pending_changes();
		$this->assertTrue(touch("{$this->dir}/deny/feed_v4.fail"));
		$this->tick();

		// Then it wrote no schedule state, no cache entry for the schedule, and ran apply reconciliation
		$this->assertSame([], glob("{$this->dir}/state/pfb_schedule_state.json*") ?: [], 'no schedule state');
		$ledger = is_file("{$this->dir}/pfb_due_ledger.json") ? json_decode((string) file_get_contents("{$this->dir}/pfb_due_ledger.json"), TRUE) : [];
		$this->assertSame([], array_values(array_filter(array_keys($ledger), static fn (string $k): bool => $k === 'cron' || str_starts_with($k, 'extra:') || $k === '_meta')), 'no schedule entry in the ledger');
		$this->assertSame(1, $this->reconciles, 'apply reconciliation is the Outpost\'s and still runs');
		$this->assertFileDoesNotExist("{$this->dir}/state/pfb_schedule_dispatch.lock", 'the tick takes no dispatcher lock: it runs no pass');
	}
}
