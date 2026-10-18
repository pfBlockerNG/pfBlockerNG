<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * #3522: the metrics collector, the atomic publish behind `pfblockerng.php metrics`, and the
 * one-minute cron entry that runs it.
 */
#[CoversFunction('pfb_metrics_collect')]
#[CoversFunction('pfb_metrics_write')]
#[CoversFunction('pfb_metrics_configure_cron')]
#[CoversFunction('pfb_pfctl_tables_raw')]
#[CoversFunction('pfb_metrics_sqlite_rows')]
final class MetricsWriteTest extends TestCase
{
	private const CRON_CMD    = '/usr/bin/timeout 50 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics >> /dev/null 2>&1';
	private const CRON_NEEDLE = 'pfblockerng.php metrics';
	private const MISSING     = 'is missing; is the node_exporter service running?';

	private string $root;
	/** @var array<string,mixed> */
	private array $priorPfb;

	protected function setUp(): void
	{
		global $pfb;

		$this->priorPfb = $pfb;
		$this->root = sys_get_temp_dir() . '/pfb_metrics_write_' . bin2hex(random_bytes(8));
		foreach (['db', 'alias', 'log'] as $sub) {
			mkdir("{$this->root}/{$sub}", 0777, TRUE);
		}
		$pfb['dbdir']              = "{$this->root}/db";
		$pfb['dnsbldir']           = "{$this->root}/db";
		$pfb['schedule_state_dir'] = "{$this->root}/db";
		$pfb['aliasdir']           = "{$this->root}/alias";
		$pfb['dnsbl_info']         = "{$this->root}/db/pfb_py_dnsbl.sqlite";
		$pfb['dnsbl_resolver']     = "{$this->root}/db/pfb_py_resolver.sqlite";
		$pfb['log']                = "{$this->root}/log/pfblockerng.log";
		$pfb['errlog']             = "{$this->root}/log/error.log";
		$pfb['pfctl']              = "{$this->root}/pfctl";
		$pfb['dnsbl']              = PfbToggle::On;

		// Fake pfctl: prints whatever the test wrote to pfctl.out and exits with the status in pfctl.rc.
		file_put_contents("{$this->root}/pfctl.out", '');
		file_put_contents("{$this->root}/pfctl.rc", '0');
		file_put_contents($pfb['pfctl'], "#!/bin/sh\ncat " . escapeshellarg("{$this->root}/pfctl.out") . "\nexit \$(cat " . escapeshellarg("{$this->root}/pfctl.rc") . ")\n");
		chmod($pfb['pfctl'], 0755);

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_pf_rules'] = [];
	}

	protected function tearDown(): void
	{
		global $pfb;

		$pfb = $this->priorPfb;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_pf_rules'] = [];
		rmdir_recursive($this->root);
	}

	/** @param list<string> $statements */
	private function sqlite(string $path, array $statements): void
	{
		$db = new SQLite3($path);
		foreach ($statements as $sql) {
			$db->exec($sql);
		}
		$db->close();
	}

	private function missingLogCount(): int
	{
		$log = is_file($GLOBALS['pfb']['errlog']) ? (string) file_get_contents($GLOBALS['pfb']['errlog']) : '';
		return substr_count($log, self::MISSING);
	}

	/** @return list<array<string,mixed>> */
	private function cronItems(): array
	{
		return array_values(array_filter(
			config_get_path('cron/item', []),
			static fn (array $item): bool => str_contains($item['command'], self::CRON_NEEDLE)
		));
	}

	private function sentinel(): string
	{
		return "{$GLOBALS['pfb']['dbdir']}/.metrics_enabled";
	}

	/** Turns the export on the way a sync pass does, which is what lets a write publish. */
	private function enableExport(string $dir): void
	{
		pfb_metrics_configure_cron(TRUE, $dir);
	}

	public function testCollectReadsDnsblGroupsAndResolverTotals(): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER );',
			"INSERT INTO dnsbl VALUES ('DNSBL_Ads', '2026-10-18 10:00:00', 5000, 17);",
			"INSERT INTO dnsbl VALUES ('Upstream', '2026-10-18 10:00:00', 0, 3);",
			"INSERT INTO dnsbl VALUES ('DNSBL_Malware', '2026-10-18 10:00:00', 'disabled', 9);",
		]);
		$this->sqlite($GLOBALS['pfb']['dnsbl_resolver'], [
			'CREATE TABLE resolver ( row INTEGER, totalqueries INTEGER, queries INTEGER );',
			'INSERT INTO resolver VALUES ( 0, 40, 2 );',
		]);

		$s = pfb_metrics_collect();

		$this->assertSame([
			['group' => 'DNSBL_Ads', 'entries' => 5000, 'counter' => 17],
			['group' => 'Upstream', 'entries' => 0, 'counter' => 3],
			['group' => 'DNSBL_Malware', 'entries' => NULL, 'counter' => 9],
		], $s['dnsbl_groups']);
		$this->assertSame(42, $s['resolver_queries']);
		$this->assertTrue($s['source_up']['dnsbl_db']);
		$this->assertTrue($s['source_up']['resolver_db']);
	}

	public function testMissingSqliteFilesGiveEmptyFamiliesAndSourceUp(): void
	{
		$s = pfb_metrics_collect();

		$this->assertSame([], $s['dnsbl_groups']);
		$this->assertNull($s['resolver_queries']);
		$this->assertTrue($s['source_up']['dnsbl_db']);
		$this->assertTrue($s['source_up']['resolver_db']);
	}

	public function testNonSqliteDnsblFileGivesNullAndSourceDown(): void
	{
		file_put_contents($GLOBALS['pfb']['dnsbl_info'], str_repeat('not a sqlite database ', 64));

		$s = pfb_metrics_collect();

		$this->assertNull($s['dnsbl_groups']);
		$this->assertFalse($s['source_up']['dnsbl_db']);
	}

	public function testInvalidPyStatusJsonClearsItsSourceAndAbsentFileIsUp(): void
	{
		$py = "{$GLOBALS['pfb']['dnsbldir']}/pfb_py_status.json";

		$this->assertTrue(pfb_metrics_collect()['source_up']['py_sync_status']);

		file_put_contents($py, '{"not": valid json');

		$this->assertFalse(pfb_metrics_collect()['source_up']['py_sync_status']);
	}

	/** @return array<string,array{0:string}> */
	public static function damagedSyncLedgerProvider(): array
	{
		return [
			'not JSON'    => ['{"ip": '],
			'JSON scalar' => ['5'],
			// A list decodes to an array, and flattening it would invent a failing row.
			'JSON list'   => ['[{"ip":{"Alias_v4":{"download":{"message":"x","first_seen":1,"last_seen":2}}}}]'],
		];
	}

	#[DataProvider('damagedSyncLedgerProvider')]
	public function testDamagedSyncLedgerClearsItsSourceAndEmitsNoFailingRows(string $raw): void
	{
		file_put_contents("{$GLOBALS['pfb']['dbdir']}/pfb_sync_status.json", $raw);
		file_put_contents("{$GLOBALS['pfb']['dnsbldir']}/pfb_py_status.json", json_encode([
			['facility' => 'dnsbl', 'item' => 'dnsbl:DNSBL_Ads', 'stage' => 'script', 'message' => 'm', 'first_seen' => 1, 'last_seen' => 2],
		]));

		$s = pfb_metrics_collect();

		$this->assertFalse($s['source_up']['sync_status']);
		$this->assertTrue($s['source_up']['py_sync_status'], 'the other ledger is independent');
		$this->assertSame([['facility' => 'dnsbl', 'feed' => 'dnsbl:DNSBL_Ads', 'stage' => 'script']], $s['feed_failing']);
	}

	public function testNonFileAtTheSyncLedgerPathClearsItsSource(): void
	{
		mkdir("{$GLOBALS['pfb']['dbdir']}/pfb_sync_status.json");

		$this->assertFalse(pfb_metrics_collect()['source_up']['sync_status']);
	}

	/** @return array<string,array{0:?string}> raw file bytes; NULL leaves the file absent */
	public static function intactSyncLedgerProvider(): array
	{
		return [
			'absent file'  => [NULL],
			'empty file'   => [''],
			'empty ledger' => ['[]'],
		];
	}

	#[DataProvider('intactSyncLedgerProvider')]
	public function testAbsentOrEmptySyncLedgerIsUpWithNoFailingRows(?string $raw): void
	{
		if ($raw !== NULL) {
			file_put_contents("{$GLOBALS['pfb']['dbdir']}/pfb_sync_status.json", $raw);
		}

		$s = pfb_metrics_collect();

		$this->assertTrue($s['source_up']['sync_status']);
		$this->assertSame([], $s['feed_failing']);
	}

	public function testSyncLedgerRowsAndHealthComeFromOneIntactFile(): void
	{
		file_put_contents("{$GLOBALS['pfb']['dbdir']}/pfb_sync_status.json", json_encode([
			'ip' => ['ipv4:Alias_v4' => ['download' => ['message' => 'x', 'first_seen' => 1, 'last_seen' => 2]]],
		]));

		$s = pfb_metrics_collect();

		$this->assertTrue($s['source_up']['sync_status']);
		$this->assertSame([['facility' => 'ip', 'feed' => 'ipv4:Alias_v4', 'stage' => 'download']], $s['feed_failing']);
	}

	public function testFeedFailingListsOpenEntriesFromBothLedgers(): void
	{
		$dbdir = $GLOBALS['pfb']['dbdir'];
		file_put_contents("{$dbdir}/pfb_sync_status.json", json_encode([
			'ip' => ['ipv4:Alias_v4' => ['download' => ['message' => 'x', 'first_seen' => 1, 'last_seen' => 2]]],
		]));
		file_put_contents("{$GLOBALS['pfb']['dnsbldir']}/pfb_py_status.json", json_encode([
			['facility' => 'dnsbl', 'item' => 'dnsbl:DNSBL_Ads', 'stage' => 'script', 'message' => 'm', 'first_seen' => 1, 'last_seen' => 2],
		]));

		$this->assertSame([
			['facility' => 'ip', 'feed' => 'ipv4:Alias_v4', 'stage' => 'download'],
			['facility' => 'dnsbl', 'feed' => 'dnsbl:DNSBL_Ads', 'stage' => 'script'],
		], pfb_metrics_collect()['feed_failing']);
	}

	public function testCollectMapsScheduleStateToFeedSuccess(): void
	{
		file_put_contents("{$GLOBALS['pfb']['dbdir']}/pfb_schedule_state.json", json_encode(['schema' => 1, 'items' => [
			'dnsbl:DNSBL_Ads' => ['last_successful_check' => 1700000000],
			'extra:dcc' => ['pending_occurrence' => 3],
		]]));

		$s = pfb_metrics_collect();

		$this->assertSame(['dnsbl:DNSBL_Ads' => 1700000000], $s['feed_success']);
		$this->assertTrue($s['source_up']['schedule_state']);
	}

	public function testCollectPublishesVisibleTablesAndHidesVipAndAggregatesByDefault(): void
	{
		file_put_contents("{$GLOBALS['pfb']['pfctl']}.out", implode("\n", [
			"-p-a---\tpfB_Deny_v4",
			"\tAddresses: 1200",
			"-p-a---\tpfB_DNSBL_VIPs",
			"\tAddresses: 1",
			"-p-a---\tpfB_Deny_Aggregated_v4",
			"\tAddresses: 900",
			"-p-a---\tbogon",
			"\tAddresses: 50",
			'',
		]));

		$this->assertSame(['pfB_Deny_v4' => 1200], pfb_metrics_collect()['ip_tables']);
	}

	public function testShowAggRevealsAggregateTablesButNotTheVip(): void
	{
		config_set_path('installedpackages/pfblockerngglobal/widget-show_agg', 'on');
		file_put_contents("{$GLOBALS['pfb']['pfctl']}.out", implode("\n", [
			"-p-a---\tpfB_Deny_v4",
			"\tAddresses: 1200",
			"-p-a---\tpfB_DNSBL_VIPs",
			"\tAddresses: 1",
			"-p-a---\tpfB_Deny_Aggregated_v4",
			"\tAddresses: 900",
			'',
		]));

		$this->assertSame(['pfB_Deny_v4' => 1200, 'pfB_Deny_Aggregated_v4' => 900], pfb_metrics_collect()['ip_tables']);
	}

	public function testRulePacketsCountVisibleAliasesOnly(): void
	{
		config_set_path('filter/rule', [
			['descr' => 'pfB_Deny_v4 block', 'tracker' => 1001, 'type' => 'block', 'source' => ['address' => 'pfB_Deny_v4']],
			['descr' => 'pfB_DNSBL VIP pass', 'tracker' => 1002, 'type' => 'pass', 'destination' => ['address' => 'pfB_DNSBL_VIPs']],
		]);
		$GLOBALS['pfb_test_pf_rules'] = [
			['tracker' => 1001, 'packets' => 42],
			['tracker' => 1002, 'packets' => 7],
		];

		$this->assertSame(['pfB_Deny_v4' => 42], pfb_metrics_collect()['ip_rule_packets']);
	}

	public function testWritePublishesRenderedFileWithMode0644(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);

		$this->assertTrue(pfb_metrics_write($dir));

		$path = "{$dir}/pfblockerng.prom";
		$this->assertFileExists($path);
		$this->assertSame(0644, fileperms($path) & 0777);
		$this->assertSame(pfb_metrics_render(pfb_metrics_collect()), file_get_contents($path));
		$this->assertSame([], glob("{$dir}/.pfbmetrics_*"), 'no temp file may survive a publish');
	}

	public function testMissingDirReturnsFalseAndLogsOncePerOutage(): void
	{
		$dir = "{$this->root}/node_exporter";
		$this->enableExport($dir);

		$this->assertFalse(pfb_metrics_write($dir));
		$this->assertFalse(pfb_metrics_write($dir));
		$this->assertSame(1, $this->missingLogCount());

		mkdir($dir);
		$this->assertTrue(pfb_metrics_write($dir));
		unlink("{$dir}/pfblockerng.prom");
		rmdir($dir);

		$this->assertFalse(pfb_metrics_write($dir));
		$this->assertSame(2, $this->missingLogCount(), 'a successful write re-arms the once-per-outage log');
	}

	public function testCronInstallsOneEntryAndDisableRemovesItAndThePromFile(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);

		pfb_metrics_configure_cron(TRUE, $dir);
		pfb_metrics_configure_cron(TRUE, $dir);

		$this->assertCount(1, $this->cronItems());
		$this->assertSame(
			['minute' => '*', 'hour' => '*', 'mday' => '*', 'month' => '*', 'wday' => '*', 'who' => 'root', 'command' => self::CRON_CMD],
			$this->cronItems()[0]
		);

		file_put_contents("{$dir}/pfblockerng.prom", 'stale');

		pfb_metrics_configure_cron(FALSE, $dir);

		$this->assertSame([], $this->cronItems());
		$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom");
	}

	public function testThrowingSourceIsDownWhileTheOtherSourcesStillPublish(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);
		file_put_contents("{$this->root}/pfctl.out", "-p-a---\tpfB_Deny_v4\n\tAddresses: 1200\n");
		config_set_path('filter/rule', ['not-an-array']);	// makes pfb_rule_alias_packets() throw a TypeError

		$this->assertTrue(pfb_metrics_write($dir));

		$published = (string) file_get_contents("{$dir}/pfblockerng.prom");
		$this->assertStringContainsString('pfblockerng_metrics_source_up{source="pf_rules"} 0', $published);
		$this->assertStringContainsString('pfblockerng_metrics_source_up{source="pfctl"} 1', $published);
		$this->assertStringContainsString('pfblockerng_ip_table_entries{table="pfB_Deny_v4"} 1200', $published);
		$this->assertStringNotContainsString('pfblockerng_ip_rule_packets_total', $published);
		$this->assertSame([], glob("{$dir}/.pfbmetrics_*"), 'no temp file may survive a publish');
	}

	public function testDirectoryAtTargetFailsPublishAndLeavesNoTempFile(): void
	{
		$dir = "{$this->root}/export";
		mkdir("{$dir}/pfblockerng.prom", 0777, TRUE);
		$this->enableExport($dir);

		$this->assertFalse(pfb_metrics_write($dir));
		$this->assertDirectoryExists("{$dir}/pfblockerng.prom");
		$this->assertSame([], glob("{$dir}/.pfbmetrics_*"));
	}

	public function testDisableClearsTheDirMissingMarker(): void
	{
		$marker = "{$GLOBALS['pfb']['dbdir']}/.metrics_dir_missing";
		file_put_contents($marker, '');

		pfb_metrics_configure_cron(FALSE, "{$this->root}/export");

		$this->assertFileDoesNotExist($marker);
	}

	public function testCorruptPassStatusReadsAsNullAndSourceDown(): void
	{
		file_put_contents("{$GLOBALS['pfb']['dbdir']}/pfb_pass_status.json", 'not json');

		$s = pfb_metrics_collect();

		$this->assertNull($s['pass']);
		$this->assertFalse($s['source_up']['pass_status']);
	}

	public function testCorruptScheduleStateReadsAsNullAndSourceDown(): void
	{
		file_put_contents("{$GLOBALS['pfb']['dbdir']}/pfb_schedule_state.json", 'not json');

		$s = pfb_metrics_collect();

		$this->assertNull($s['feed_success']);
		$this->assertFalse($s['source_up']['schedule_state']);
	}

	public function testEmptyPyStatusFileIsValidAndSourceUp(): void
	{
		file_put_contents("{$GLOBALS['pfb']['dnsbldir']}/pfb_py_status.json", '');

		$this->assertTrue(pfb_metrics_collect()['source_up']['py_sync_status']);
	}

	public function testPfctlRawReportsTheExitStatusAndKeepsItsOutput(): void
	{
		file_put_contents("{$this->root}/pfctl.out", "-p-a---\tpfB_Deny_v4\n");
		file_put_contents("{$this->root}/pfctl.rc", '3');

		$rc = NULL;
		$lines = pfb_pfctl_tables_raw('', $rc);

		$this->assertSame(3, $rc);
		$this->assertSame(["-p-a---\tpfB_Deny_v4"], $lines);
	}

	public function testPfctlNonZeroExitIsDownWithNoTablesEvenWhenItPrintedOutput(): void
	{
		file_put_contents("{$this->root}/pfctl.out", "-p-a---\tpfB_Deny_v4\n\tAddresses: 1200\n");
		file_put_contents("{$this->root}/pfctl.rc", '1');

		$s = pfb_metrics_collect();

		$this->assertFalse($s['source_up']['pfctl']);
		$this->assertNull($s['ip_tables']);
	}

	public function testPfctlZeroExitWithNoOutputIsUpWithNoTables(): void
	{
		$s = pfb_metrics_collect();

		$this->assertTrue($s['source_up']['pfctl']);
		$this->assertSame([], $s['ip_tables']);
	}

	public function testMissingPfctlBinaryIsDown(): void
	{
		$GLOBALS['pfb']['pfctl'] = "{$this->root}/no-such-pfctl";

		$s = pfb_metrics_collect();

		$this->assertFalse($s['source_up']['pfctl']);
		$this->assertNull($s['ip_tables']);
	}

	public function testDnsblOffSkipsBothDatabasesAndReportsThemUpWithNoSeries(): void
	{
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER );',
			"INSERT INTO dnsbl VALUES ('DNSBL_Ads', '2026-10-18 10:00:00', 5000, 17);",
		]);
		file_put_contents($GLOBALS['pfb']['dnsbl_resolver'], str_repeat('not a sqlite database ', 64));

		$s = pfb_metrics_collect();

		$this->assertNull($s['dnsbl_groups'], 'a readable database must not be read while DNSBL is off');
		$this->assertNull($s['resolver_queries']);
		$this->assertTrue($s['source_up']['dnsbl_db']);
		$this->assertTrue($s['source_up']['resolver_db'], 'a corrupt database must not be read while DNSBL is off');
		$this->assertStringNotContainsString('pfblockerng_dnsbl_', pfb_metrics_render($s));
	}

	public function testALockedDatabaseIsWaitedForNotReportedDown(): void
	{
		$path = $GLOBALS['pfb']['dnsbl_info'];
		$this->sqlite($path, [
			'CREATE TABLE dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER );',
			"INSERT INTO dnsbl VALUES ('DNSBL_Ads', '2026-10-18 10:00:00', 5000, 17);",
		]);
		$GLOBALS['pfb']['sqlite_timeout'] = 5000;
		// A second process holds the write lock, as the DNSBL writer does, and releases it shortly after announcing it.
		$holder = proc_open(
			[PHP_BINARY, '-r', '$db = new SQLite3($argv[1]); $db->exec("BEGIN EXCLUSIVE"); echo "locked\n"; fflush(STDOUT); usleep(700000); $db->exec("COMMIT");', $path],
			[1 => ['pipe', 'w']],
			$pipes
		);
		$this->assertIsResource($holder);
		try {
			$this->assertSame("locked\n", fgets($pipes[1]), 'the holder must have the database locked before the read starts');

			$s = pfb_metrics_collect();
		} finally {
			fclose($pipes[1]);
			proc_close($holder);
		}

		$this->assertTrue($s['source_up']['dnsbl_db'], 'a busy database is waited for, not reported down');
		$this->assertSame([['group' => 'DNSBL_Ads', 'entries' => 5000, 'counter' => 17]], $s['dnsbl_groups']);
	}

	public function testWriteWithoutTheEnabledSentinelPublishesNothing(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);

		$this->assertFalse(pfb_metrics_write($dir));

		$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom");
		$this->assertSame([], glob("{$dir}/.pfbmetrics_*"));
	}

	public function testEnableCreatesTheSentinelAndDisableRemovesItWithTheCronAndTheFile(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);

		$this->assertFileDoesNotExist($this->sentinel(), 'before: the export starts disabled');
		pfb_metrics_configure_cron(TRUE, $dir);
		pfb_metrics_configure_cron(TRUE, $dir);
		$this->assertFileExists($this->sentinel(), 'enabling must leave the sentinel, also when the cron entry already exists');
		$this->assertTrue(pfb_metrics_write($dir));

		pfb_metrics_configure_cron(FALSE, $dir);

		$this->assertFileDoesNotExist($this->sentinel());
		$this->assertSame([], $this->cronItems());
		$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom");
	}

	public function testARenderedBodyIsNotPublishedAfterTheExportIsDisabled(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);
		$body = pfb_metrics_render(pfb_metrics_collect());	// the run that began before the disable

		pfb_metrics_configure_cron(FALSE, $dir);

		$this->assertFalse(pfb_metrics_publish($body, $dir));
		$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom", 'a disable must not be undone by a run that started before it');
		$this->assertSame([], glob("{$dir}/.pfbmetrics_*"));
	}

	public function testPublishWaitsForTheLockAndGivesUpWhileAnotherRunHoldsIt(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);
		$held = fopen("{$GLOBALS['pfb']['dbdir']}/.metrics.lock", 'c');
		$this->assertNotFalse($held);
		$this->assertTrue(flock($held, LOCK_EX));

		try {
			$this->assertFalse(pfb_metrics_publish('held', $dir, 0.05), 'a publish must not run while the lock is held elsewhere');
			$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom");
		} finally {
			flock($held, LOCK_UN);
			fclose($held);
		}

		$this->assertTrue(pfb_metrics_publish('released', $dir, 0.05));
		$this->assertSame('released', file_get_contents("{$dir}/pfblockerng.prom"));
	}

	public function testDisableProceedsWithoutTheLockWhenItIsWedged(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);
		file_put_contents("{$dir}/pfblockerng.prom", 'stale');
		$held = fopen("{$GLOBALS['pfb']['dbdir']}/.metrics.lock", 'c');
		$this->assertNotFalse($held);
		$this->assertTrue(flock($held, LOCK_EX));

		try {
			pfb_metrics_configure_cron(FALSE, $dir, 0.05);
		} finally {
			flock($held, LOCK_UN);
			fclose($held);
		}

		$this->assertFileDoesNotExist($this->sentinel(), 'a wedged lock holder must not block a disable');
		$this->assertSame([], $this->cronItems());
		$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom");
	}
}
