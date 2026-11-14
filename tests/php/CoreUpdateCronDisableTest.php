<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941: the `.pfb_cron_disable` sentinel (pfb_cron_disabled(), issue #1204) suppresses SCHEDULED work. Core starts the
 * scheduled Update by itself now, so the Outpost's `core_update` verb honours the sentinel for trigger `scheduled` only: it runs
 * nothing, writes an empty result (no outcome, nothing attempted: Core's reserved feeds stay pending and are planned again),
 * logs one line and exits 75 (PFB_EXIT_LOCKED, "try again later"). `manual`, `apply` and `retry` are an operator's or the
 * Outpost's own request, and the sentinel does not touch them. CoreUpdateServeTest pins the rest of the verb.
 */
#[CoversFunction('pfb_core_update_serve')]
final class CoreUpdateCronDisableTest extends TestCase
{
	private const FEED = 'ipv4:feed_v4';

	private string $dir = '';
	private array $originalPfb = [];
	private mixed $originalConfig = NULL;
	private bool $hadG = FALSE;
	private mixed $originalG = NULL;
	/** @var list<string> what the seams were called with, in order */
	private array $calls = [];

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->hadG = array_key_exists('g', $GLOBALS);
		$this->originalG = $GLOBALS['g'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_core_update_cron_disable_' . getmypid() . '_' . bin2hex(random_bytes(6));
		foreach (['state', 'core', 'cc', 'deny', 'match', 'permit', 'native', 'dnsbl', 'orig', 'dnsorig'] as $sub) {
			mkdir("{$this->dir}/{$sub}", 0755, TRUE);
		}
		$pfb = &$GLOBALS['pfb'];
		$pfb['dbdir'] = $this->dir;
		$pfb['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$pfb['schedule_state_dir'] = "{$this->dir}/state";
		$pfb['core_state'] = "{$this->dir}/core";
		$pfb['runlog'] = "{$this->dir}/run.log";
		$pfb['extraslog'] = "{$this->dir}/extras.log";
		$pfb['log'] = "{$this->dir}/pfb.log";
		$pfb['logdir'] = $this->dir;
		$pfb['errlog'] = "{$this->dir}/error.log";
		$pfb['ccdir'] = "{$this->dir}/cc";
		$pfb['denydir'] = "{$this->dir}/deny";
		$pfb['matchdir'] = "{$this->dir}/match";
		$pfb['permitdir'] = "{$this->dir}/permit";
		$pfb['nativedir'] = "{$this->dir}/native";
		$pfb['dnsdir'] = "{$this->dir}/dnsbl";
		$pfb['origdir'] = "{$this->dir}/orig";
		$pfb['dnsorigdir'] = "{$this->dir}/dnsorig";
		$pfb['enable'] = PfbToggle::On;
		$pfb['skipfeed'] = 0;
		$pfb['run_stdout_override'] = FALSE;	// a terminal running the suite must not turn the mirror on by itself
		unset($pfb['core_update'], $pfb['scheduled_outcomes'], $pfb['scheduled_selected_ids'], $pfb['scheduled_runtime_cron'], $pfb['runlog_active']);
		unset($pfb);
		$GLOBALS['g']['pfblockerng_install'] = TRUE;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		$this->calls = [];
		config_set_path('installedpackages/pfblockerng/config/0', [
			'skipfeed' => '0', 'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '0', 'pfb_schedule_minute' => '0', 'pfb_quiet_hours' => '',
		]);
		config_set_path('installedpackages/pfblockernglistsv4/config', [[
			'aliasname' => 'Test', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'schedule_override' => '', 'srcint' => '',
			'row' => [['header' => 'feed', 'url' => 'https://example.test/feed', 'state' => 'Enabled']],
		]]);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		config_set_path('installedpackages/pfblockerngblacklist', ['blacklist_enable' => 'Disable']);
		$GLOBALS['pfb']['blconfig'] = config_get_path('installedpackages/pfblockerngblacklist');
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		if ($this->hadG) {
			$GLOBALS['g'] = $this->originalG;
		} else {
			unset($GLOBALS['g']);
		}
		unset($GLOBALS['pfb_test_logger_calls']);
		pfb_feed_pass_release();
		pfb_schedule_dispatch_release();
		rmdir_recursive($this->dir);
	}

	/** Seams that record what ran and succeed. */
	private function seams(): array
	{
		return [
			'extra' => function (string $job, string $argument, bool &$changed = FALSE): bool {
				$this->calls[] = "extra:{$job}";
				return TRUE;
			},
			'cron' => function (bool $force, string $scope, bool $pending, bool $hashes, ?string &$deferred, array $ids = []): bool {
				$this->calls[] = 'cron:' . json_encode($ids);
				return TRUE;
			},
			'sync' => function (array $request): bool {
				$this->calls[] = 'sync:' . json_encode($request);
				return TRUE;
			},
		];
	}

	/**
	 * @param array<string, mixed> $request
	 * @return array{exit: int, out: string, result: ?array, raw: ?string}
	 */
	private function serve(array $request): array
	{
		$resultPath = "{$this->dir}/result.json";
		ob_start();
		try {
			$exit = pfb_core_update_serve((string) json_encode($request), $resultPath, $this->seams());
		} finally {
			$out = (string) ob_get_clean();
		}
		$raw = is_file($resultPath) ? (string) file_get_contents($resultPath) : NULL;
		return ['exit' => $exit, 'out' => $out, 'result' => $raw === NULL ? NULL : json_decode($raw, TRUE), 'raw' => $raw];
	}

	/** @return array<string, mixed> */
	private static function req(string $trigger, array $more = []): array
	{
		return array_merge(['version' => 1, 'trigger' => $trigger, 'scope' => 'both', 'force' => 'none', 'token' => str_repeat('a', 64)], $more);
	}

	private function disableTheSchedule(): void
	{
		$this->assertTrue(touch(pfb_cron_disable_path()), 'the sentinel must be creatable');
		$this->assertTrue(pfb_cron_disabled(), 'precondition: the sentinel disables the schedule');
	}

	public function testAScheduledUpdateRunsWithoutTheSentinelAndNothingRunsWithIt(): void
	{
		// Given the same scheduled request, which runs the Extra and the feed it names while the schedule is on
		$request = self::req('scheduled', ['feeds' => [self::FEED], 'extras' => ['extra:dcc']]);
		$before = $this->serve($request);
		$this->assertNotSame(75, $before['exit'], $before['out']);
		$this->assertContains('extra:dcc', $this->calls, 'before-state: the scheduled Update runs the Extra');
		$this->assertContains('cron:' . json_encode([self::FEED]), $this->calls, 'before-state: it runs the feed pass on the feed named');
		$this->calls = [];

		// When the sentinel disables the schedule
		$this->disableTheSchedule();
		$after = $this->serve($request);

		// Then nothing runs
		$this->assertSame([], $this->calls, 'a disabled schedule runs no Extra and no feed pass');
		$this->assertSame(75, $after['exit'], $after['out']);
	}

	public function testTheSkippedUpdateReportsNothingSoCoreKeepsItsFeedsPending(): void
	{
		$this->disableTheSchedule();

		$run = $this->serve(self::req('scheduled', ['feeds' => [self::FEED], 'extras' => ['extra:dcc', 'extra:bl']]));

		$this->assertNotNull($run['raw'], 'the result file is written, so Core records the skip and not a failure to report');
		$this->assertSame('{"version":1,"outcomes":{},"attempted":[],"geoipReady":null}', $run['raw'], 'no outcome, nothing attempted, GeoIP not reported');
	}

	public function testTheSkipIsOneLineInTheProgressLogNamingTheSentinel(): void
	{
		$this->disableTheSchedule();

		$run = $this->serve(self::req('scheduled', ['feeds' => [self::FEED]]));

		$lines = array_values(array_filter(array_map('trim', explode("\n", $run['out'])), static fn (string $line): bool => $line !== ''));
		$this->assertCount(1, $lines, "exactly one line is logged: {$run['out']}");
		$this->assertStringContainsString(pfb_cron_disable_path(), $lines[0], 'the line names the sentinel that disabled the schedule');
	}

	public function testAScheduledUpdateThatFindsNoSentinelIsNotSkipped(): void
	{
		$run = $this->serve(self::req('scheduled', ['extras' => ['extra:dcc']]));

		$this->assertNotSame(75, $run['exit'], $run['out']);
		$this->assertStringNotContainsString('pfb_cron_disable', $run['out']);
	}

	/** @return array<string, array{string}> */
	public static function unaffectedTriggers(): array
	{
		return ['manual' => ['manual'], 'apply' => ['apply'], 'retry' => ['retry']];
	}

	#[DataProvider('unaffectedTriggers')]
	public function testTheSentinelDoesNotTouchAnUpdateThatIsNotScheduled(string $trigger): void
	{
		pfb_mark_pending_changes();
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));
		$this->disableTheSchedule();

		$run = $this->serve(self::req($trigger));

		$this->assertNotSame(75, $run['exit'], "{$trigger} must not be skipped by the sentinel: {$run['out']}");
		$this->assertNotNull($run['result'], 'the result is the Update\'s own');
		$this->assertStringNotContainsString('pfb_cron_disable', $run['out']);
		if ($trigger !== 'retry') {
			$this->assertNotSame([], $this->calls, "{$trigger} ran its pass");
		}
	}
}
