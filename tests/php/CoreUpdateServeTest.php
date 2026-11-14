<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941: Core decides and starts every Update; the Outpost's `core_update` verb (pfb_core_update.sh, --update-cmd) only
 * executes what Core asks (docs/misc/core-api-protocol.md, "Update command"). Pinned here, through the real functions:
 *   - the request is validated before anything runs: a refused one runs nothing, writes no result and exits 2;
 *   - `scheduled`/`retry` run the Extras named (dcc, then bl), report the GeoIP readiness, and run the feed pass only while
 *     GeoIP is ready and there are feeds named, an enabled feed's `.fail` marker or no DNSBL manifest; the pass checks exactly the
 *     feeds named and reports each terminal result in the result file, never in a state file;
 *   - `apply` clears the pending marker, applies, and keeps the marker when the apply fails;
 *   - `manual` runs the scope with the force the page asked for;
 *   - progress is stdout, which Core keeps as the Update's log, and hooks append to the same file.
 */
#[CoversFunction('pfb_core_update_serve')]
#[CoversFunction('pfb_core_update_request')]
final class CoreUpdateServeTest extends TestCase
{
	private const FEED = 'ipv4:feed_v4';
	private const OTHER = 'ipv4:other_v4';

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
		$this->dir = sys_get_temp_dir() . '/pfb_core_update_' . getmypid() . '_' . bin2hex(random_bytes(6));
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
		$pfb['grep'] = 'grep';
		$pfb['continents'] = [];
		$pfb['reuse'] = $pfb['reuse_dnsbl'] = '';
		$pfb['unbound_py_sources'] = '';
		$pfb['php'] = $this->recorder();
		$pfb['timeout'] = $GLOBALS['pfb_test_timeout'];
		$pfb['run_stdout_override'] = FALSE;	// a terminal running the suite must not turn the mirror on by itself
		unset($pfb['core_update'], $pfb['scheduled_outcomes'], $pfb['scheduled_selected_ids'], $pfb['scheduled_runtime_cron'], $pfb['runlog_active']);
		unset($pfb);
		$GLOBALS['g']['pfblockerng_install'] = TRUE;	// a real sync pass ends at once ("Sync terminated during boot process")
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		$this->calls = [];
		config_set_path('installedpackages/pfblockerng/config/0', [
			'skipfeed' => '0', 'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '0', 'pfb_schedule_minute' => '0', 'pfb_quiet_hours' => '',
		]);
		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => 'work', 'blacklist_freq' => 'Weekly',
			'item' => [['xml' => 'work', 'selected' => 'yes', 'title' => 'Work', 'feed' => 'https://example.test/bl']],
		]);
		$GLOBALS['pfb']['blconfig'] = config_get_path('installedpackages/pfblockerngblacklist');
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		$this->feedGroup([['header' => 'feed', 'url' => 'https://example.test/feed', 'state' => 'Enabled']]);
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

	/** @param list<array<string, string>> $rows */
	private function feedGroup(array $rows, string $action = 'Deny_Inbound'): void
	{
		config_set_path('installedpackages/pfblockernglistsv4/config', [[
			'aliasname' => 'Test', 'action' => $action, 'cron' => 'EveryDay', 'schedule_override' => '', 'srcint' => '', 'row' => $rows,
		]]);
	}

	/** A `php` that records its arguments and succeeds. */
	private function recorder(): string
	{
		$path = "{$this->dir}/php-recorder";
		file_put_contents($path, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> " . escapeshellarg("{$this->dir}/spawns") . "\n");
		chmod($path, 0755);
		return $path;
	}

	/** @return list<string> */
	private function spawns(): array
	{
		return is_file("{$this->dir}/spawns") ? (array) file("{$this->dir}/spawns", FILE_IGNORE_NEW_LINES) : [];
	}

	/**
	 * The seams record into $this->calls and answer as the arguments say.
	 *
	 * @return array<string, callable>
	 */
	private function seams(bool $extra = TRUE, bool $cron = TRUE, bool $sync = TRUE, ?callable $onCron = NULL): array
	{
		return [
			'extra' => function (string $job, string $argument, bool &$changed = FALSE) use ($extra): bool {
				$this->calls[] = "extra:{$job}:{$argument}";
				$changed = $job === 'dcc' && $this->changed;
				return $extra && !($this->failing[$job] ?? FALSE);
			},
			'cron' => function (bool $force, string $scope, bool $pending, bool $hashes, ?string &$deferred, array $ids = []) use ($cron, $onCron): bool {
				$this->calls[] = 'cron:' . json_encode([$force, $scope, $pending, $hashes, $ids]);
				if ($onCron !== NULL) {
					$onCron();
				}
				return $cron;
			},
			'sync' => function (array $request) use ($sync): bool {
				$this->calls[] = 'sync:' . json_encode($request);
				return $sync;
			},
		];
	}

	private bool $changed = FALSE;
	/** @var array<string, bool> */
	private array $failing = [];

	/**
	 * Serve one request. Returns the exit status, what was printed (the progress log) and the result file's last line, decoded:
	 * the whole result (NULL when none was written).
	 *
	 * @param array<string, mixed>|string $request
	 * @return array{exit: int, out: string, result: ?array, raw: ?string}
	 */
	private function serve(array|string $request, ?array $seams = NULL): array
	{
		$body = is_string($request) ? $request : (string) json_encode($request);
		$resultPath = "{$this->dir}/result.json";
		ob_start();
		try {
			$exit = pfb_core_update_serve($body, $resultPath, $seams ?? $this->seams());
		} finally {
			$out = (string) ob_get_clean();
		}
		$raw = is_file($resultPath) ? (string) file_get_contents($resultPath) : NULL;
		$lines = $raw === NULL ? [] : explode("\n", rtrim($raw, "\n"));
		return ['exit' => $exit, 'out' => $out, 'result' => $raw === NULL ? NULL : json_decode((string) end($lines), TRUE), 'raw' => $raw];
	}

	/** @return array<string, mixed> */
	private static function req(string $trigger, array $more = []): array
	{
		return array_merge(['version' => 1, 'trigger' => $trigger, 'scope' => 'both', 'force' => 'none'], $more);
	}

	// ----- 1. validation -----

	/** @return array<string, array{0: array<string, mixed>|string}> */
	public static function refusedRequests(): array
	{
		$ok = self::req('apply');
		return [
			'not JSON'                  => ['{"version":'],
			'nothing'                   => [''],
			'two objects'               => [json_encode($ok) . json_encode($ok)],
			'a list'                    => ['[1, 2]'],
			'null'                      => ['null'],
			'over 1 MiB'                => [json_encode($ok) . str_repeat(' ', PFB_CORE_UPDATE_MAX_REQUEST)],
			'no version'                => [array_diff_key($ok, ['version' => 1])],
			'version 2'                 => [['version' => 2] + $ok],
			'version "1"'               => [['version' => '1'] + $ok],
			'no trigger'                => [array_diff_key($ok, ['trigger' => 1])],
			'an unknown trigger'        => [['trigger' => 'daily'] + $ok],
			'a trigger in the wrong case' => [['trigger' => 'Scheduled'] + $ok],
			'a trigger that is not a string' => [['trigger' => 1] + $ok],
			'scope IP'                  => [['scope' => 'IP'] + $ok],
			'scope all'                 => [['scope' => 'all'] + $ok],
			'scope 7'                   => [['scope' => 7] + $ok],
			'force true'                => [['force' => TRUE] + $ok],
			'force full'                => [['force' => 'full'] + $ok],
			'an unknown field'          => [$ok + ['shell' => 'x']],
			'feeds that are no list'    => [$ok + ['feeds' => self::FEED]],
			'a feed id that is no string' => [$ok + ['feeds' => [1]]],
			'a feed id with ../'        => [$ok + ['feeds' => ['ipv4:../x_v4']]],
			'a feed id with a slash'    => [$ok + ['feeds' => ['dnsbl:a/b']]],
			'ipv4 with no _v4 suffix'   => [$ok + ['feeds' => ['ipv4:x']]],
			'ipv6 with the _v4 suffix'  => [$ok + ['feeds' => ['ipv6:x_v4']]],
			'a feed id of another family' => [$ok + ['feeds' => ['geoip:x']]],
			'a feed id naming an extra' => [$ok + ['feeds' => ['extra:dcc']]],
			'a duplicate feed id'       => [$ok + ['feeds' => [self::FEED, self::FEED]]],
			'feeds as an object'        => [$ok + ['feeds' => ['a' => self::FEED]]],
			'extras as an object'       => [$ok + ['extras' => ['a' => 'extra:dcc']]],
			'extras that are no list'   => [$ok + ['extras' => 'extra:dcc']],
			'an extra other than dcc/bl' => [$ok + ['extras' => ['extra:foo']]],
			'an extra without its prefix' => [$ok + ['extras' => ['dcc']]],
			'a duplicate extra'         => [$ok + ['extras' => ['extra:dcc', 'extra:dcc']]],
		];
	}

	/** @param array<string, mixed>|string $request */
	#[DataProvider('refusedRequests')]
	public function testARefusedRequestRunsNothingWritesNoResultAndExitsTwo(array|string $request): void
	{
		// Given a pending change a run would clear, and seams that fail the test when they run
		pfb_mark_pending_changes();
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));
		$seams = ['extra' => fn (): bool => self::fail('an Extra ran'), 'cron' => fn (): bool => self::fail('the feed pass ran'),
			'sync' => fn (): bool => self::fail('a sync ran')];

		// When Core's request is refused
		$run = $this->serve($request, $seams);

		// Then nothing ran, nothing was reported, and the refusal is in the log
		$this->assertSame(2, $run['exit'], $run['out']);
		$this->assertNull($run['raw'], 'a refused request writes no result');
		$this->assertSame([], $this->spawns());
		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dir), 'the pending apply is untouched');
		$this->assertTrue(pfb_pending_changes());
		$this->assertStringContainsString('refused', $run['out'], 'the progress log says why');
	}

	// ----- 2. Extras -----

	public function testScheduledExtrasRunDccThenBlAndAreReportedAsSuccessfulOutcomes(): void
	{
		// Given Core names both Extras, bl first
		// When the Update is served
		$run = $this->serve(self::req('scheduled', ['extras' => ['extra:bl', 'extra:dcc']]));

		// Then dcc ran first, then bl with the selected Blacklist argument; both are reported, and the exit status is 0
		$this->assertSame(0, $run['exit'], $run['out']);
		$this->assertSame(['extra:dcc:', 'extra:bl:work'], $this->calls);
		$this->assertSame(1, $run['result']['version']);
		$this->assertSame(['extra:dcc' => 'success', 'extra:bl' => 'success'], $run['result']['outcomes']);
		$this->assertSame([], $run['result']['attempted']);
		$this->assertTrue($run['result']['geoipReady']);
		$this->assertStringContainsString('"outcomes":{"extra:dcc":"success"', (string) $run['raw'], 'outcomes is a JSON object, which Core decodes as a map');
	}

	public function testAFailedExtraIsReportedAttemptedAndDoesNotBlockTheNext(): void
	{
		$this->failing['dcc'] = TRUE;

		$run = $this->serve(self::req('scheduled', ['extras' => ['extra:dcc', 'extra:bl']]));

		$this->assertSame(['extra:dcc:', 'extra:bl:work'], $this->calls, 'bl still ran');
		$this->assertSame(['extra:bl' => 'success'], $run['result']['outcomes']);
		$this->assertSame(['extra:dcc'], $run['result']['attempted']);
		$this->assertSame(1, $run['exit'], 'a failed Extra fails the Update');
	}

	/** @return array<string, array{0: callable(): void}> an Extra the Outpost skips */
	public static function skippedBlacklists(): array
	{
		return [
			'pfBlockerNG is disabled' => [static function (): void { $GLOBALS['pfb']['enable'] = PfbToggle::Off; }],
			'no Blacklist category is selected' => [static function (): void {
				config_set_path('installedpackages/pfblockerngblacklist/blacklist_selected', '');
			}],
		];
	}

	#[DataProvider('skippedBlacklists')]
	public function testABlacklistTheOutpostSkipsIsReportedAttemptedSoCoreDoesNotAskEveryQuarterHour(callable $arrange): void
	{
		$arrange();

		$run = $this->serve(self::req('scheduled', ['extras' => ['extra:bl']]));

		$this->assertSame([], $this->calls, 'bl did not run');
		$this->assertSame(['extra:bl'], $run['result']['attempted']);
		$this->assertSame([], (array) $run['result']['outcomes']);
		$this->assertSame(0, $run['exit'], 'skipping is no failure');
	}

	public function testTheDefaultExtraRunnerSpawnsTheScheduledVerbsOfTheDispatcherInOrder(): void
	{
		$seams = $this->seams();
		unset($seams['extra']);

		$run = $this->serve(self::req('scheduled', ['extras' => ['extra:dcc', 'extra:bl']]), $seams);

		$this->assertSame(0, $run['exit'], $run['out']);
		$this->assertSame([
			'/usr/local/www/pfblockerng/pfblockerng.php dcc scheduled',
			'/usr/local/www/pfblockerng/pfblockerng.php bl scheduled work',
		], $this->spawns());
	}

	public function testADccThatChangedTheContentOutsideTheApplyWindowKeepsTheChangePendingWithNoPass(): void
	{
		// Given an apply window that does not hold now, and a dcc that changed what it fetched
		$start = ((int) date('G') + 12) % 24;
		PfbConfig::writeSystem('gen/pfb_quiet_hours', sprintf('%02d:00-%02d:01', $start, $start));
		$this->changed = TRUE;
		$this->assertFalse(pfb_pending_changes(), 'before-state: nothing is pending');

		$run = $this->serve(self::req('scheduled', ['extras' => ['extra:dcc']]));

		$this->assertSame(['extra:dcc:'], $this->calls, 'no feed pass and no apply');
		$this->assertTrue(pfb_pending_changes());
		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dir));
		$this->assertSame(0, $run['exit']);
	}

	public function testADccThatChangedTheContentInsideTheApplyWindowAppliesOnceWhenNoFeedPassRuns(): void
	{
		PfbConfig::writeSystem('gen/pfb_quiet_hours', '');
		$this->changed = TRUE;

		$run = $this->serve(self::req('scheduled', ['extras' => ['extra:dcc']]));

		$this->assertSame(['extra:dcc:', 'sync:' . json_encode(['scope' => 'both', 'force' => FALSE, 'trigger' => 'cron'])], $this->calls);
		$this->assertSame(0, $run['exit']);
	}

	// ----- 3. GeoIP -----

	public function testWhileGeoipIsNotReadyTheExtrasRunButNoFeedPassAndNoApplyDo(): void
	{
		$request = self::req('scheduled', ['feeds' => [self::FEED], 'extras' => ['extra:dcc']]);
		$ready = $this->serve($request);
		$this->assertSame(['extra:dcc:', 'cron:' . json_encode([FALSE, 'both', FALSE, FALSE, [self::FEED]])], $this->calls, 'before-state: a ready GeoIP runs the pass');
		$this->assertFalse(pfb_pending_changes());
		$this->calls = [];

		// Given a GeoIP generation that is being swapped
		file_put_contents("{$this->dir}/cc/.pfb_generation_swapping", 'interrupted');
		$run = $this->serve($request);

		// Then the Extra ran, GeoIP is reported not ready, the changes are marked pending, and the feeds get no outcome
		$this->assertSame(['extra:dcc:'], $this->calls);
		$this->assertFalse($run['result']['geoipReady']);
		$this->assertSame(['extra:dcc' => 'success'], $run['result']['outcomes']);
		$this->assertTrue(pfb_pending_changes());
		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dir));
		$this->assertSame(0, $run['exit']);
		$this->assertTrue($ready['result']['geoipReady']);
	}

	// ----- 4./5. the feed pass -----

	public function testAScheduledPassChecksExactlyTheFeedsNamedAndReportsEachTerminalResultWithoutAStateFile(): void
	{
		// Given three feeds of one group: one whose local source is unchanged, one past its retry cap, and one Core did not name
		$source = "{$this->dir}/source.txt";
		file_put_contents($source, "1.2.3.4\n");
		file_put_contents("{$this->dir}/orig/ok_v4.orig", "1.2.3.4\n");
		file_put_contents("{$this->dir}/deny/ok_v4.txt", "1.2.3.4\n");
		$GLOBALS['pfb_test_resolve_map']['example.test.'] = [['type' => 'A', 'data' => '203.0.113.20']];
		$GLOBALS['pfb']['skipfeed'] = 1;
		pfb_logger("\n\n [ pfB_Test - capped_v4 ] Download FAIL [ NOW ]\n", 2);
		$this->feedGroup([
			['header' => 'ok', 'url' => $source, 'state' => 'Enabled'],
			['header' => 'capped', 'url' => 'https://example.test/capped', 'state' => 'Enabled'],
			['header' => 'unnamed', 'url' => 'https://example.test/unnamed', 'state' => 'Enabled'],
		]);
		$seams = $this->seams();
		unset($seams['cron']);

		// When Core names two of them (pfb_determine_list_detail() reads aaddrnot_* keys this pass never sets: a quirk older than the cutover)
		set_error_handler(static fn (int $no, string $message): bool => str_contains($message, 'aaddrnot_'), E_WARNING);
		try {
			$run = $this->serve(self::req('scheduled', ['feeds' => ['ipv4:ok_v4', 'ipv4:capped_v4']]), $seams);
		} finally {
			restore_error_handler();
		}

		// Then both terminal results are in the result, the unnamed feed was not checked, and no state file exists
		$this->assertSame(['ipv4:ok_v4' => 'success', 'ipv4:capped_v4' => 'retry-cap-reached'], $run['result']['outcomes'], $run['out']);
		$this->assertStringNotContainsString('unnamed', $run['out'], 'the feed Core did not name is not checked');
		$this->assertSame([], glob("{$this->dir}/state/pfb_schedule_state.json*") ?: [], 'the PHP state file is retired');
		$this->assertFileDoesNotExist("{$this->dir}/state/pfb_schedule_state.json");
	}

	public function testARetryNamingNoFeedChecksTheFeedOfAnEnabledFailMarker(): void
	{
		// Given a *.fail marker of an enabled feed, and a retry that names no feed
		$this->assertTrue(touch("{$this->dir}/deny/feed_v4.fail"));

		$run = $this->serve(self::req('retry'));

		// Then the feed pass runs, selecting no feed of Core's: the pass itself retries the marked feed
		$this->assertSame(['cron:' . json_encode([FALSE, 'both', FALSE, FALSE, []])], $this->calls);
		$this->assertSame(0, $run['exit']);
	}

	public function testAFailMarkerOfADisabledFeedAndAnEmptyRetryRunNoFeedPass(): void
	{
		$this->feedGroup([['header' => 'feed', 'url' => 'https://example.test/feed', 'state' => 'Enabled']], 'Disabled');
		$this->assertTrue(touch("{$this->dir}/deny/feed_v4.fail"));

		$run = $this->serve(self::req('retry'));

		$this->assertSame([], $this->calls, 'a dormant marker is not a reason to run');
		$this->assertSame(0, $run['exit']);
	}

	public function testARetryWithNoDnsblManifestRunsTheFeedPassAndOnePublishedRunsNone(): void
	{
		// Given pfB-DNS hosting the Python module with DNSBL on (the manifest is then the resolver's only blocklist source, issue #2607)
		$GLOBALS['config']['unbound']['enable'] = '';
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::On);
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/pfb_dnsbl', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/pfb_dnsvip_auto', PfbToggle::On);
		$keys = [];
		foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved', base64_encode((string) json_encode($keys)));
		pfb_global();	// as the verb does before it serves: the effective DNSBL state is read from the configuration
		$GLOBALS['pfb']['unbound_py_sources'] = "{$this->dir}/pfb_py_sources.json";
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"version":1,"config":{},"feeds":[]}');
		$this->serve(self::req('retry'));
		$this->assertSame([], $this->calls, 'before-state: a published manifest asks for nothing');

		// When the manifest is gone
		unlink($GLOBALS['pfb']['unbound_py_sources']);
		$run = $this->serve(self::req('retry'));

		// Then the pass runs, and says why
		$this->assertSame(['cron:' . json_encode([FALSE, 'both', FALSE, FALSE, []])], $this->calls);
		$this->assertSame(0, $run['exit']);
		$this->assertContains('Update: DNSBL manifest absent - this pass rebuilds it.', array_column($GLOBALS['pfb_test_logger_calls'], 'message'));
	}

	public function testAPassTheLocksDeferNamesNoOutcomeAndExitsLocked(): void
	{
		// Given another process holding the feed-pass lock
		$lock = fopen("{$this->dir}/pfb_feed_pass.lock", 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));

		$run = $this->serve(self::req('scheduled', ['feeds' => [self::FEED], 'extras' => ['extra:dcc']]));
		flock($lock, LOCK_UN);
		fclose($lock);

		// Then nothing ran, the feeds stay pending in Core (no outcome), and the exit status is the deferral's
		$this->assertSame(PFB_EXIT_LOCKED, $run['exit'], $run['out']);
		$this->assertSame([], $this->calls);
		$this->assertSame([], (array) ($run['result']['outcomes'] ?? []));
	}

	public function testAPassThatThrowsFailsTheUpdateAndStillReportsWhatWasDone(): void
	{
		$seams = $this->seams(onCron: static function (): never { throw new RuntimeException('disk full'); });

		$run = $this->serve(self::req('scheduled', ['feeds' => [self::FEED], 'extras' => ['extra:dcc']]), $seams);

		$this->assertSame(1, $run['exit']);
		$this->assertSame(['extra:dcc' => 'success'], $run['result']['outcomes'], 'the Extra that finished is still reported');
		$this->assertStringContainsString('disk full', $run['out']);
	}

	public function testTheExtrasThePassAndTheApplyRunWhileBothLocksAreHeld(): void
	{
		// Given a probe that reports whether another handle finds a lock taken (the entry points Core does not start would find it so)
		$held = static function (string $path): bool {
			$probe = fopen($path, 'c');
			$taken = $probe !== FALSE && !flock($probe, LOCK_EX | LOCK_NB);
			if (is_resource($probe)) {
				fclose($probe);
			}
			return $taken;
		};
		$both = fn (): array => [$held("{$this->dir}/state/pfb_schedule_dispatch.lock"), $held("{$this->dir}/pfb_feed_pass.lock")];
		$seen = [];
		$seams = [
			'extra' => function () use (&$seen, $both): bool { $seen['extra'] = $both(); return TRUE; },
			'cron' => function () use (&$seen, $both): bool { $seen['cron'] = $both(); return TRUE; },
			'sync' => function () use (&$seen, $both): bool { $seen['sync'] = $both(); return TRUE; },
		];
		$this->assertSame([FALSE, FALSE], $both(), 'before-state: no lock is held');

		// When a scheduled and an apply Update run
		$this->serve(self::req('scheduled', ['feeds' => [self::FEED], 'extras' => ['extra:dcc']]), $seams);
		$this->serve(self::req('apply'), $seams);

		// Then each ran with both locks held, and both are released afterwards
		$this->assertSame(['extra' => [TRUE, TRUE], 'cron' => [TRUE, TRUE], 'sync' => [TRUE, TRUE]], $seen);
		$this->assertSame([FALSE, FALSE], $both());
	}

	// ----- 6. apply -----

	public function testAnApplyClearsThePendingMarkerBeforeItAppliesAndExitsZero(): void
	{
		pfb_mark_pending_changes();
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));
		$seams = $this->seams();
		$seams['sync'] = function (array $request): bool {
			$this->calls[] = 'sync:' . json_encode($request) . ':pending=' . json_encode(pfb_due_ledger_is_pending('cron', $this->dir));
			return TRUE;
		};

		$run = $this->serve(self::req('apply'), $seams);

		$this->assertSame(['sync:' . json_encode(['scope' => 'both', 'force' => FALSE, 'trigger' => 'manual']) . ':pending=false'], $this->calls);
		$this->assertSame(0, $run['exit']);
		$this->assertFalse(pfb_due_ledger_is_pending('cron', $this->dir));
		$this->assertSame([], (array) $run['result']['outcomes']);
	}

	public function testAnApplyThatFailsKeepsTheChangePendingRecordsTheFailureAndExitsNonZero(): void
	{
		pfb_sync_apply_record('waiting', 'outside the apply window', $this->dir, TRUE);
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));
		$this->assertFalse(pfb_pending_changes());

		$run = $this->serve(self::req('apply'), $this->seams(sync: FALSE));

		$this->assertSame(1, $run['exit']);
		$this->assertTrue(pfb_pending_changes());
		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dir));
		$this->assertSame('failed', pfb_sync_receive_state_read($this->dir)['apply']['outcome']);
	}

	public function testAnApplyTheLocksDeferKeepsThePendingApply(): void
	{
		$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));
		$lock = fopen("{$this->dir}/state/pfb_schedule_dispatch.lock", 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));

		$run = $this->serve(self::req('apply'));
		flock($lock, LOCK_UN);
		fclose($lock);

		$this->assertSame(PFB_EXIT_LOCKED, $run['exit']);
		$this->assertSame([], $this->calls);
		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dir), 'the marker is cleared only by a run that got the locks');
	}

	// ----- 7. manual -----

	/** @return array<string, array{0: string, 1: string, 2: string}> scope, force, the call the page's Run Now makes */
	public static function manualRuns(): array
	{
		$sync = static fn (string $scope, bool $force, string $trigger): string => 'sync:' . json_encode(['scope' => $scope, 'force' => $force, 'trigger' => $trigger]);
		$cron = static fn (string $scope, bool $hashes): string => 'cron:' . json_encode([TRUE, $scope, FALSE, $hashes, []]);
		$out = [];
		foreach (['ip', 'dnsbl', 'both'] as $scope) {
			$out["{$scope} none"] = [$scope, 'none', $sync($scope, FALSE, 'manual')];
			$out["{$scope} parse"] = [$scope, 'parse', $sync($scope, TRUE, 'force')];
			$out["{$scope} download"] = [$scope, 'download', $cron($scope, FALSE)];
			$out["{$scope} both"] = [$scope, 'both', $cron($scope, TRUE)];
		}
		return $out;
	}

	#[DataProvider('manualRuns')]
	public function testAManualUpdateRunsTheScopeWithTheForceTheOperatorAskedFor(string $scope, string $force, string $expected): void
	{
		$run = $this->serve(self::req('manual', ['scope' => $scope, 'force' => $force]));

		$this->assertSame([$expected], $this->calls);
		$this->assertSame(0, $run['exit'], $run['out']);
	}

	/**
	 * A manual Update reports what the Outpost saw of GeoIP like any other: Core's Extras plan uses the last readiness reported, so a
	 * manual Update that ran while a generation swap was in progress must not leave Core believing it is ready.
	 */
	public function testAManualUpdateReportsTheGeoipReadinessItSaw(): void
	{
		$ready = $this->serve(self::req('manual', ['force' => 'parse']));
		$this->assertTrue($ready['result']['geoipReady'], 'a ready GeoIP is reported ready');

		file_put_contents("{$this->dir}/cc/.pfb_generation_swapping", 'interrupted');
		$swapping = $this->serve(self::req('manual', ['force' => 'parse']));

		$this->assertFalse($swapping['result']['geoipReady'], 'a generation swap in progress is reported not ready');
		$this->assertSame(0, $swapping['exit'], 'a manual Update is not refused because of it: the operator asked for it');
	}

	public function testAFailedManualUpdateExitsNonZero(): void
	{
		$run = $this->serve(self::req('manual', ['force' => 'parse']), $this->seams(sync: FALSE));

		$this->assertSame(1, $run['exit']);
	}

	public function testAForceCheckThatTheLocksDeferExitsLocked(): void
	{
		$seams = $this->seams();
		$seams['cron'] = function (bool $force, string $scope, bool $pending, bool $hashes, ?string &$deferred, array $ids = []): bool {
			$deferred = 'feed-pass-lock';
			return FALSE;
		};

		$run = $this->serve(self::req('manual', ['force' => 'download']), $seams);

		$this->assertSame(PFB_EXIT_LOCKED, $run['exit']);
	}

	// ----- 8. progress -----

	public function testProgressReachesStdoutOnlyWhileServing(): void
	{
		// Given a pass that logs a line to the main log
		$seams = $this->seams(onCron: static function (): void { pfb_logger("\n a progress line", 1); });
		ob_start();
		pfb_logger("\n before serving", 1);
		$before = (string) ob_get_clean();

		// When it is served
		$run = $this->serve(self::req('manual', ['force' => 'download']), $seams);

		// Then the line is in the progress log (stdout), the stream is closed afterwards, and the main log has it too
		$this->assertStringContainsString('a progress line', $run['out']);
		$this->assertStringNotContainsString('before serving', $before, 'before-state: a log line is no stdout');
		ob_start();
		pfb_logger("\n after serving", 1);
		$this->assertSame('', (string) ob_get_clean(), 'the mirror ends with the Update');
		$this->assertStringContainsString('a progress line', (string) file_get_contents("{$this->dir}/pfb.log"));
	}

	public function testHooksAppendToTheUpdateLogAndTheRunLogIsNeitherOpenedNorTruncated(): void
	{
		file_put_contents("{$this->dir}/run.log", "an earlier run\n");
		$seen = [];
		$seams = $this->seams(onCron: function () use (&$seen): void {
			$seen['target'] = pfb_run_log_target();
			pfb_runlog_begin();
			$seen['active'] = !empty($GLOBALS['pfb']['runlog_active']);
		});
		$outside = pfb_run_log_target();

		$this->serve(self::req('manual', ['force' => 'download']), $seams);

		$this->assertSame("{$this->dir}/core/update.log", $seen['target'], 'hooks append where Core keeps the progress log');
		$this->assertNotSame($seen['target'], $outside, 'before-state: outside an Update hooks log elsewhere');
		$this->assertFalse($seen['active'], 'the run log is not opened for an Update Core runs');
		$this->assertSame("an earlier run\n", file_get_contents("{$this->dir}/run.log"), 'never truncated');
	}

	public function testTheResultGoesToFdThreeAndTheProgressToStdoutOfARealProcess(): void
	{
		// Given Core's way of running the program: the request on stdin, a regular file on fd 3, stdout a pipe the test reads
		$in = "{$this->dir}/request";
		$result = "{$this->dir}/fd3";
		file_put_contents($in, (string) json_encode(self::req('apply')));
		touch($result);
		$command = [PHP_BINARY, __DIR__ . '/support/CoreUpdateWorker.php'];
		$process = proc_open($command, [0 => ['file', $in, 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'], 3 => ['file', $result, 'w']], $pipes, NULL, ['PFB_TEST_DIR' => $this->dir]);
		$this->assertIsResource($process);
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);

		// When it serves an apply
		$run = pfb_test_finish_process([$process, $pipes, implode(' ', $command)], 60.0);

		// Then it exits 0, says what it did on stdout, and reports exactly one result object on fd 3
		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertStringContainsString('Dispatching pending apply.', $run['stdout']);
		$this->assertSame('{"version":1,"outcomes":{},"attempted":[],"geoipReady":true}' . "\n", file_get_contents($result));
	}

	public function testAPassKilledByTermHasTheFeedsItFinishedReportedOnFdThree(): void
	{
		// Given a real process whose feed pass reports two terminal checks and then gets TERM, as a stop of Core sends it (issue #4002)
		$in = "{$this->dir}/request";
		$result = "{$this->dir}/fd3";
		file_put_contents($in, (string) json_encode(self::req('manual', ['force' => 'download'])));
		touch($result);
		$command = [PHP_BINARY, __DIR__ . '/support/CoreUpdateWorker.php'];
		$env = ['PFB_TEST_DIR' => $this->dir, 'PFB_TEST_TERM_IN_PASS' => '1'];
		$process = proc_open($command, [0 => ['file', $in, 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'], 3 => ['file', $result, 'w']], $pipes, NULL, $env);
		$this->assertIsResource($process);
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);

		$run = pfb_test_finish_process([$process, $pipes, implode(' ', $command)], 60.0);

		// Then the process died of the TERM, and fd 3 already holds both outcomes, a line each
		$this->assertStringContainsString('the pass reported its feeds', $run['stdout'], 'before-state: the pass ran' . $run['stderr']);
		$this->assertNotSame(0, $run['exit'], 'the TERM ended the process before it finished');
		$this->assertSame(
			'{"version":1,"outcomes":{"ipv4:feed_v4":"success"}}' . "\n" . '{"version":1,"outcomes":{"ipv4:other_v4":"retry-cap-reached"}}' . "\n",
			file_get_contents($result),
		);
	}

	// ----- the verb and its wrapper -----

	private const WRAPPER = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfb_core_update.sh';

	public function testTheWrapperExecsTheVerbWithPhpErrorsOffStdoutAndNothingElse(): void
	{
		$lines = file(self::WRAPPER, FILE_IGNORE_NEW_LINES);

		$this->assertIsArray($lines, 'the wrapper exists');
		$this->assertCount(3, $lines);
		$this->assertSame('#!/bin/sh', $lines[0]);
		$this->assertStringStartsWith('# ', $lines[1]);
		$this->assertSame('exec /usr/local/bin/php -d display_errors=stderr -f /usr/local/pkg/pfblockerng/pfblockerng.inc core_update', $lines[2]);
		$this->assertTrue(is_executable(self::WRAPPER), 'the nightly port installs *.sh with their mode; Core execs it');
		$syntax = pfb_test_run_process(['/bin/sh', '-n', self::WRAPPER]);
		$this->assertSame(0, $syntax['exit'], $syntax['stderr']);
	}

	public function testTheVerbRefusesARequestThatIsNoRequestWithExitTwoAndNoResult(): void
	{
		$in = "{$this->dir}/stdin";
		file_put_contents($in, '{"version":1,"trigger":"daily"}');
		$result = "{$this->dir}/verb-result";
		touch($result);
		$command = [PHP_BINARY, __DIR__ . '/bin/cli_dispatch_entry.php', 'core_update'];
		$process = proc_open($command, [0 => ['file', $in, 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'], 3 => ['file', $result, 'w']], $pipes);
		$this->assertIsResource($process);
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);

		$run = pfb_test_finish_process([$process, $pipes, implode(' ', $command)], 60.0);

		$this->assertSame(2, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertStringContainsString('refused', $run['stdout'], 'the refusal is in the progress log');
		$this->assertSame('', (string) file_get_contents($result), 'nothing reported on fd 3');
	}
}
