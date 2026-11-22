<?php

declare(strict_types=1);

namespace PfbWorklistCorpus {

	// Stand-ins the namespaced copy of pfblockerng_sync_cron() reaches before the global functions (PHP resolves an
	// unqualified function call in the namespace first): the pass it ends with is recorded, not run, and every change
	// check is recorded and then made by today's pfb_update_check().

	function sync_package_pfblockerng($cron = '', ?string &$deferred_by = NULL): bool
	{
		$deferred_by = NULL;
		$GLOBALS['pfb_worklist_sync'][] = $cron;
		return TRUE;
	}

	function pfb_software_update_check(): void
	{
	}

	function pfb_update_check($header, $list_url, $pfbfolder, $pfborig, $pflex, $format, $vtype, $srcint = FALSE): ?\PfbScheduleTerminalResult
	{
		$kind = $pfbfolder === $GLOBALS['pfb']['dnsdir'] ? 'dnsbl' : ($vtype === '_v6' ? 'ipv6' : 'ipv4');
		$GLOBALS['pfb_worklist_checked'][] = "{$kind}:{$header}";
		return \pfb_update_check($header, $list_url, $pfbfolder, $pfborig, $pflex, $format, $vtype, $srcint);
	}
}

namespace {

	use PHPUnit\Framework\Attributes\CoversFunction;
	use PHPUnit\Framework\Attributes\DataProvider;
	use PHPUnit\Framework\TestCase;

	require_once __DIR__ . '/support/HttpFixtureReadiness.php';

	/**
	 * The work-list corpus of the Core Updater (issue #4038, tests/updateloop/fixtures/worklist/scenarios.json): which feeds
	 * an Update checks, their outcomes, the change each feed it runs is handed, the fail markers left, and whether the pass
	 * applies now, is left pending, or does not run. Today's code decides it: pfb_core_update_run() routes the request, as the
	 * Outpost's Update program does, and the walk is pfblockerng_sync_cron() with pfb_update_check() probing a local
	 * `php -S` server (tests/php/support/FeedFetchCorpusRouter.php). The walk runs verbatim: its source is evaluated in the
	 * namespace PfbWorklistCorpus, where the pass it ends with (sync_package_pfblockerng()) is recorded instead of run and
	 * each check is recorded before today's pfb_update_check() makes it. A manual Update without a Force Check and an apply
	 * go straight to the pass, which is recorded with its scope and force: for them the change of a feed is today's reuse
	 * rule over its markers (an update or fail marker, or no list: downloaded; else reused; a geoip feed downloaded after a
	 * GeoIP change, the update marker pfblockerng_apply.inc touches for geoip.update), or parse for a Reload. A pending
	 * decision leaves to the apply what today's pending apply rebuilds: the feeds with an update or fail marker or without
	 * their list. The Go
	 * runner (go/pfb_core/update/worklist/corpus_test.go) replays the same file; where Core differs on purpose a case
	 * holds today's answer in old_expect, which this runner asserts.
	 */
	#[CoversFunction('pfblockerng_sync_cron')]
	#[CoversFunction('pfb_update_check')]
	#[CoversFunction('pfb_core_update_run')]
	final class UpdateLoopWorklistCorpusTest extends TestCase
	{
		private const CORPUS = __DIR__ . '/../updateloop/fixtures/worklist/scenarios.json';
		private const KINDS = ['ipv4' => 'pfblockernglistsv4', 'ipv6' => 'pfblockernglistsv6', 'dnsbl' => 'pfblockerngdnsbl'];
		private const STATES = ['enabled' => 'Enabled', 'disabled' => 'Disabled', 'hold' => 'Hold', 'flex' => 'Flex'];

		/** @var array<string, mixed>|null */
		private static ?array $doc = NULL;
		private string $root = '';
		/** @var resource|null */
		private $server = NULL;
		private int $port = 0;
		private mixed $savedPfb = NULL;
		private mixed $savedConfig = NULL;

		public static function setUpBeforeClass(): void
		{
			if (!function_exists('PfbWorklistCorpus\pfblockerng_sync_cron')) {
				$function = new ReflectionFunction('pfblockerng_sync_cron');
				$lines = file((string) $function->getFileName());
				$source = implode('', array_slice($lines, $function->getStartLine() - 1,
					$function->getEndLine() - $function->getStartLine() + 1));
				eval("namespace PfbWorklistCorpus;\nuse PfbConfig, PfbScheduleTerminalResult, PfbToggle;\n{$source}");
			}
		}

		protected function setUp(): void
		{
			if (!extension_loaded('curl')) {
				$this->markTestSkipped('curl extension not available');
			}
			$this->root = sys_get_temp_dir() . '/pfb_worklist_' . getmypid() . '_' . bin2hex(random_bytes(4));
			foreach (['orig', 'dnsorig', 'deny', 'dns', 'db', 'state', 'log', 'tools'] as $d) {
				$this->assertTrue(mkdir("{$this->root}/{$d}", 0700, TRUE));
			}
			$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
			$this->savedConfig = $GLOBALS['config'] ?? NULL;
			$this->startServer();
		}

		protected function tearDown(): void
		{
			if (is_resource($this->server)) {
				proc_terminate($this->server);
				proc_close($this->server);
			}
			pfb_feed_pass_release();
			pfb_schedule_dispatch_release();
			$GLOBALS['pfb'] = $this->savedPfb;
			$GLOBALS['config'] = $this->savedConfig;
			unset($GLOBALS['pfb_worklist_sync'], $GLOBALS['pfb_worklist_checked'], $GLOBALS['pfb_worklist_cron'],
				$GLOBALS['pfb_test_configured_ips'],
				$GLOBALS['pfb_test_resolve_map']);
			exec('rm -rf ' . escapeshellarg($this->root));
		}

		/** @return array<string, mixed> */
		private static function corpus(): array
		{
			if (self::$doc === NULL) {
				$doc = json_decode((string) file_get_contents(self::CORPUS), TRUE, 64, JSON_THROW_ON_ERROR);
				if (($doc['schema'] ?? NULL) !== 1 || !is_array($doc['cases'] ?? NULL)) {
					throw new RuntimeException('scenarios.json: schema 1 and a case list');
				}
				self::$doc = $doc;
			}
			return self::$doc;
		}

		/** @return array<string, array{array<string, mixed>}> */
		public static function cases(): array
		{
			$out = [];
			foreach (self::corpus()['cases'] as $case) {
				if (array_key_exists('old_expect', $case) !== array_key_exists('departure', $case)) {
					throw new RuntimeException("case {$case['id']}: old_expect only with a departure");
				}
				$out[$case['id']] = [$case];
			}
			return $out;
		}

		private function startServer(): void
		{
			file_put_contents("{$this->root}/tools/routes.json", '{}');
			$nonce = bin2hex(random_bytes(16));
			$stderr = "{$this->root}/tools/server.stderr";
			$this->server = proc_open(['php', '-S', '127.0.0.1:0', __DIR__ . '/support/FeedFetchCorpusRouter.php'],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']], $pipes, "{$this->root}/tools", [
					'CORPUS_SERVER' => 'origin', 'CORPUS_ROUTES' => "{$this->root}/tools/routes.json",
					'CORPUS_REQUESTS' => "{$this->root}/tools/requests.log", 'READY_TOKEN' => $nonce,
					'PATH' => (string) getenv('PATH'),
				]);
			$this->assertIsResource($this->server);
			$this->port = pfb_test_http_fixture_port($stderr);
			for ($i = 0; $this->port > 0 && $i < 40; $i++) {
				if (pfb_test_http_fixture_event_received($this->port, $nonce)) {
					return;
				}
				usleep(50000);
			}
			$this->fail('the probe server did not start: ' . (string) @file_get_contents($stderr));
		}

		/** @param array<string, mixed> $group */
		private static function suffix(array $group): string
		{
			return ['ipv4' => '_v4', 'ipv6' => '_v6', 'dnsbl' => ''][$group['kind']];
		}

		/**
		 * The case's feeds in walk order (IPv4, IPv6, DNSBL, groups and rows in config order), each with its id, its file
		 * stem, its folders and whether today's walk visits it.
		 *
		 * @param array<string, mixed> $case
		 * @return list<array{id: string, kind: string, name: string, format: string, list: string, orig: string, walked: bool, run: bool}>
		 */
		private function feeds(array $case): array
		{
			$out = [];
			foreach (array_keys(self::KINDS) as $kind) {
				foreach ($case['groups'] as $group) {
					if ($group['kind'] !== $kind) {
						continue;
					}
					foreach ($group['feeds'] as $feed) {
						$name = $feed['header'] . self::suffix($group);
						$enabled = $group['action'] !== 'Disabled' && $feed['state'] !== 'disabled';
						$out[] = ['id' => "{$kind}:{$name}", 'kind' => $kind, 'name' => $name, 'format' => $feed['format'], 'walked' => $enabled && $group['frequency'] !== 'Never',
							'run' => $enabled, 'list' => $kind === 'dnsbl' ? "{$this->root}/dns" : "{$this->root}/deny",
							'orig' => $kind === 'dnsbl' ? "{$this->root}/dnsorig" : "{$this->root}/orig"];
					}
				}
			}
			return $out;
		}

		/** @param array<string, mixed> $case */
		private function arrange(array $case, array $doc): void
		{
			global $pfb;
			if (($case['folder'] ?? '') === 'link') {
				$this->assertTrue(rename("{$this->root}/orig", "{$this->root}/orig.real") && symlink("{$this->root}/orig.real", "{$this->root}/orig"));
			}
			$pfb = array_merge(is_array($this->savedPfb) ? $this->savedPfb : [], [
				'origdir' => "{$this->root}/orig", 'dnsorigdir' => "{$this->root}/dnsorig", 'denydir' => "{$this->root}/deny",
				'permitdir' => "{$this->root}/deny", 'matchdir' => "{$this->root}/deny", 'nativedir' => "{$this->root}/deny",
				'dnsdir' => "{$this->root}/dns", 'dbdir' => "{$this->root}/db", 'log' => "{$this->root}/log/main.log",
				'errlog' => "{$this->root}/log/error.log", 'grep' => 'grep', 'skipfeed' => $case['skipfeed'] ?? 0, 'failed' => [],
				'schedule_state_dir' => "{$this->root}/state", 'pending_marker' => "{$this->root}/state/pfb_pending_changes",
				'continents' => ['Top Spammers' => 'pfB_Top'], 'ccdir' => '', 'unbound_py_sources' => '', 'curl_retry_sleep' => 0,
				'pnow' => 'now', 'mime_types' => $GLOBALS['pfb_shipped_mime_types'] ?? $pfb['mime_types'] ?? [],
			]);
			unset($pfb['runlog'], $pfb['runlog_active'], $pfb['scheduled_outcomes'], $pfb['core_update'], $pfb['core_update_result']);
			foreach ([CURLOPT_PROXY, CURLOPT_PROXYPORT, CURLOPT_PROXYAUTH, CURLOPT_PROXYUSERPWD] as $opt) {
				unset($pfb['curl_defaults'][$opt]);
			}
			$GLOBALS['pfb_test_configured_ips'] = [];
			$GLOBALS['pfb_test_resolve_map'] = ['feed.example.' => [['type' => 'A', 'data' => '127.0.0.1'], ['type' => 'A', 'data' => '203.0.113.5']]];
			$GLOBALS['pfb_worklist_sync'] = $GLOBALS['pfb_worklist_checked'] = $GLOBALS['pfb_worklist_cron'] = [];

			// A window far from now is outside it; no window is always inside.
			$start = ((int) date('G') + 12) % 24;
			$GLOBALS['config'] = [];
			config_set_path('installedpackages/pfblockerng/config/0', [
				'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7', 'pfb_schedule_hour' => '0',
				'pfb_schedule_minute' => '0',
				'pfb_quiet_hours' => ($case['window'] ?? '') === 'outside' ? sprintf('%02d:00-%02d:01', $start, $start) : '',
			]);
			config_set_path('installedpackages/pfblockerngblacklist', ['blacklist_selected' => '', 'blacklist_freq' => 'Never', 'item' => []]);
			config_set_path('installedpackages/pfblockerngtopspammers/config/0', ['action' => $case['continent'] ?? 'Disabled']);

			$routes = [];
			$sections = array_fill_keys(array_values(self::KINDS), []);
			foreach ($case['groups'] as $group) {
				$rows = [];
				foreach ($group['feeds'] as $feed) {
					$url = $feed['source'];
					if ($feed['format'] === 'auto') {
						$path = "/{$group['kind']}_{$feed['header']}";
						$url = "http://feed.example:{$this->port}{$path}";
						$routes[$path] = match ($feed['source']) {
							'304' => ['etag' => $doc['etag'], 'body' => $doc['baseline']],
							'same' => ['body' => $doc['baseline']],
							'changed' => ['body' => $doc['changed']],
							default => ['status' => 500, 'body' => "err\n"],
						};
					}
					$rows[] = ['header' => $feed['header'], 'state' => self::STATES[$feed['state']], 'format' => $feed['format'], 'url' => $url];
				}
				$sections[self::KINDS[$group['kind']]][] = ['aliasname' => $group['name'], 'action' => $group['action'],
					'cron' => $group['frequency'], 'srcint' => '', 'row' => $rows];
			}
			foreach ($sections as $section => $groups) {
				config_set_path("installedpackages/{$section}/config", $groups);
			}
			file_put_contents("{$this->root}/tools/routes.json", json_encode(['origin' => $routes], JSON_UNESCAPED_SLASHES));

			foreach ($this->feeds($case) as $feed) {
				$files = $case['files'][$feed['id']] ?? [];
				$orig = "{$feed['orig']}/{$feed['name']}.orig";
				match ($files['orig'] ?? TRUE) {
					TRUE => file_put_contents($orig, $doc['baseline']),
					'dir' => mkdir($orig),
					FALSE => NULL,
				};
				file_put_contents("{$orig}.xxhash128", hash('xxh128', $doc['baseline']));
				file_put_contents("{$orig}.etag", $doc['etag']);
				if ($files['list'] ?? TRUE) {
					file_put_contents("{$feed['list']}/{$feed['name']}.txt", "1.2.3.4\n");
				}
				foreach (['fail', 'update'] as $marker) {
					if ($files[$marker] ?? FALSE) {
						touch("{$feed['list']}/{$feed['name']}.{$marker}");
					}
				}
				for ($i = 0; $i < ($case['failures'][$feed['id']] ?? 0); $i++) {
					pfb_logger("\n\n [ pfB_Test - {$feed['name']} ] Download FAIL [ NOW ]\n", 2);
				}
			}
			if ($case['pendingApply'] ?? FALSE) {
				pfb_mark_pending_changes();
			}
			if ($case['geoipChanged'] ?? FALSE) {
				touch("{$pfb['dbdir']}/geoip.update");
			}
		}

		/** @param array<string, mixed> $case */
		#[DataProvider('cases')]
		public function testCaseMatchesTodaysWorkList(array $case): void
		{
			global $pfb;
			$doc = self::corpus();
			$this->arrange($case, $doc);
			$request = $case['request'] + ['scope' => 'both', 'force' => 'none', 'feeds' => [], 'extras' => [], 'lifecycle' => NULL, 'pkgOp' => NULL];
			$result = ['attempted' => [], 'geoipReady' => NULL];
			$status = pfb_core_update_run($request, $result, [
				'cron' => static function (...$args) {
					$GLOBALS['pfb_worklist_cron'][] = [$args[0], $args[1]];
					return PfbWorklistCorpus\pfblockerng_sync_cron(...$args);
				},
				'sync' => static function (array $plan, ?string &$deferred = NULL): bool {
					$deferred = NULL;
					$GLOBALS['pfb_worklist_sync'][] = $plan;
					return TRUE;
				},
				'extra' => static function (string $job, string $argument, bool &$changed) use ($case): bool {
					$changed = ($case['extrasChanged'] ?? FALSE) && $job === 'dcc';
					return TRUE;
				},
			]);
			$this->assertSame(0, $status, "{$case['id']}: the Update program's status; its log:\n" . @file_get_contents($pfb['log']));

			$feeds = $this->feeds($case);
			$cron = $GLOBALS['pfb_worklist_cron'];
			$direct = array_values(array_filter($GLOBALS['pfb_worklist_sync'], 'is_array'));
			$scope = $cron[0][1] ?? $direct[0]['scope'] ?? 'both';
			$inScope = static fn(array $f): bool => $scope === 'both' || ($scope === 'dnsbl') === ($f['kind'] === 'dnsbl');
			$marker = static fn(array $f, string $m): bool => file_exists("{$f['list']}/{$f['name']}.{$m}");
			$changes = [];
			foreach ($feeds as $f) {
				$listed = file_exists("{$f['list']}/{$f['name']}.txt");
				if ($cron !== []) {
					$selected = $f['walked'] && $inScope($f) && ($cron[0][0] || isset($pfb['scheduled_selected_ids'][$f['id']]));
					if ($selected) {
						$changes[$f['id']] = $marker($f, 'update') || !$listed ? 'changed' : ($marker($f, 'fail') ? 'failed' : 'unchanged');
					}
				} elseif ($direct !== [] && $f['run'] && $inScope($f)) {
					$geoip = $f['format'] === 'geoip' && file_exists("{$pfb['dbdir']}/geoip.update");
					$changes[$f['id']] = $direct[0]['force'] ? 'parse'
						: ($geoip || $marker($f, 'update') || $marker($f, 'fail') || !$listed ? 'changed' : 'unchanged');
				}
			}
			$outcomes = array_filter($pfb['scheduled_outcomes'] ?? [], static fn(string $id): bool => !str_starts_with($id, 'extra:'),
				ARRAY_FILTER_USE_KEY);
			$apply = $GLOBALS['pfb_worklist_sync'] !== [] ? 'now' : (pfb_due_ledger_is_pending('cron', $pfb['dbdir']) ? 'pending' : 'nothing');
			$got = [
				'checked' => $GLOBALS['pfb_worklist_checked'],
				'outcomes' => $outcomes,
				'changes' => $changes,
				'fail' => array_values(array_map(static fn(array $f): string => $f['id'], array_filter($feeds, static fn(array $f): bool => $marker($f, 'fail')))),
				'stopped' => [],
				'apply' => $apply,
				'pending' => $apply !== 'pending' ? [] : array_values(array_map(static fn(array $f): string => $f['id'],
					array_filter($feeds, static fn(array $f): bool => $marker($f, 'update') || $marker($f, 'fail')
						|| !file_exists("{$f['list']}/{$f['name']}.txt")))),
			];
			$want = array_merge($case['expect'], $case['old_expect'] ?? []);
			ksort($got);
			ksort($want);
			foreach (['outcomes', 'changes'] as $map) {
				ksort($got[$map]);
				ksort($want[$map]);
			}
			$this->assertSame($want, $got, "{$case['id']}: {$case['description']}; the log:\n" . @file_get_contents($pfb['log']));
		}
	}
}
