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
#[CoversFunction('pfb_metrics_sqlite_snapshot')]
final class MetricsWriteTest extends TestCase
{
	private const CRON_CMD    = '/usr/bin/timeout -s TERM -k 5 50 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics >> /dev/null 2>&1';
	private const CRON_NEEDLE = 'pfblockerng.php metrics';
	private const MISSING     = 'is missing; is the node_exporter service running?';
	private const STALE_SENTINEL = 'leftover enabled marker';
	private const NO_SENTINEL = 'is missing, so nothing is published';
	private const SYMLINK     = 'is a symbolic link';

	private string $root;
	/** @var array<string,mixed> */
	private array $priorPfb;

	protected function setUp(): void
	{
		global $pfb;

		$this->priorPfb = $pfb;
		$this->root = sys_get_temp_dir() . '/pfb_metrics_write_' . bin2hex(random_bytes(8));
		foreach (['db', 'alias', 'log', 'etc'] as $sub) {
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
		$pfb['enable']             = PfbToggle::Off;
		// /usr/local/etc stands in: it is outside the RAM-disked /var, which is why the state lives there.
		$pfb['metrics_enabled']          = "{$this->root}/etc/pfb_metrics_enabled";
		$pfb['metrics_lock']             = "{$this->root}/etc/pfb_metrics.lock";
		$pfb['metrics_dir_missing']      = "{$this->root}/etc/pfb_metrics_dir_missing";
		$pfb['metrics_sentinel_missing'] = "{$this->root}/etc/pfb_metrics_sentinel_missing";
		$pfb['pass_status']              = "{$this->root}/etc/pfb_pass_status.json";

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

	private function logCount(string $needle): int
	{
		$log = is_file($GLOBALS['pfb']['errlog']) ? (string) file_get_contents($GLOBALS['pfb']['errlog']) : '';
		return substr_count($log, $needle);
	}

	private function missingLogCount(): int
	{
		return $this->logCount(self::MISSING);
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
		return $GLOBALS['pfb']['metrics_enabled'];
	}

	/** Turns the export on the way a sync pass does: master and option on, sentinel and cron in place. That is what lets a write publish. */
	private function enableExport(string $dir): void
	{
		$this->wantExport(PfbToggle::On, 'on');
		pfb_metrics_configure_cron(TRUE, $dir);
	}

	public function testClientPrivacySaveCoalescesBothDatabasesAndRotatesEpochs(): void
	{
		foreach (['dnsbl_info' => 'dns_metric_blocks', 'dnsbl_resolver' => 'dns_metric_queries'] as $path => $table) {
			$this->sqlite($GLOBALS['pfb'][$path], [
				"CREATE TABLE {$table} (qtype TEXT, transport TEXT, listener_ip TEXT, listener_interface TEXT, client_ip TEXT, count INTEGER);",
				"INSERT INTO {$table} VALUES ('A','UDP','192.0.2.1','LAN','198.51.100.1',2),('A','UDP','192.0.2.1','LAN','198.51.100.2',3);",
				'CREATE TABLE dns_metric_settings (row INTEGER PRIMARY KEY, client_ip INTEGER NOT NULL, epoch TEXT NOT NULL);',
				"INSERT INTO dns_metric_settings VALUES (0,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
			]);
		}
		config_set_path('installedpackages/pfblockerng/config/0/pfb_metrics_client_ip', 'on');
		$this->assertNull(pfb_metrics_client_save(PfbToggle::Off, static function (): void {
			PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::Off);
		}));
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_metrics_client_ip'));
		foreach (['dnsbl_info' => 'dns_metric_blocks', 'dnsbl_resolver' => 'dns_metric_queries'] as $path => $table) {
			$db = new SQLite3($GLOBALS['pfb'][$path]);
			$this->assertSame(5, $db->querySingle("SELECT sum(count) FROM {$table}"));
			$this->assertSame(1, $db->querySingle("SELECT count(*) FROM {$table}"));
			$this->assertSame('', $db->querySingle("SELECT client_ip FROM {$table}"));
			$this->assertSame(0, $db->querySingle('SELECT client_ip FROM dns_metric_settings'));
			$this->assertNotSame(str_repeat('a', 32), $db->querySingle('SELECT epoch FROM dns_metric_settings'));
			$db->close();
		}
	}

	public function testClientPrivacyFailedSecondDatabaseKeepsSettingAndExactFirstSum(): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dns_metric_blocks (qtype TEXT, client_ip TEXT, count INTEGER);',
			"INSERT INTO dns_metric_blocks VALUES ('A','198.51.100.1',2),('A','198.51.100.2',3);",
		]);
		file_put_contents($GLOBALS['pfb']['dnsbl_resolver'], 'corrupt');
		config_set_path('installedpackages/pfblockerng/config/0/pfb_metrics_client_ip', 'on');
		$saved = FALSE;
		$error = pfb_metrics_client_save(PfbToggle::Off, static function () use (&$saved): void {
			$saved = TRUE;
		});
		$this->assertStringContainsString('still enabled', $error);
		$this->assertFalse($saved);
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_metrics_client_ip'));
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$this->assertSame(5, $db->querySingle('SELECT sum(count) FROM dns_metric_blocks'));
		$this->assertSame('', $db->querySingle('SELECT client_ip FROM dns_metric_blocks'));
		$db->close();
		unlink($GLOBALS['pfb']['dnsbl_resolver']);
		$this->assertNull(pfb_metrics_client_save(PfbToggle::Off, static function (): void {
			PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::Off);
		}));
	}

	public function testUnrelatedPrivacySaveDoesNotReadCorruptAccounting(): void
	{
		file_put_contents($GLOBALS['pfb']['dnsbl_info'], 'corrupt');
		$saved = FALSE;
		$this->assertNull(pfb_metrics_client_save(PfbToggle::Off, static function () use (&$saved): void {
			$saved = TRUE;
		}));
		$this->assertTrue($saved);
	}


	public function testCurrentEndpointRowsCoalesceOnlySuppressedClients(): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_resolver'], [
			'CREATE TABLE resolver (row INTEGER, totalqueries INTEGER, queries INTEGER);',
			'INSERT INTO resolver VALUES (0,20,0);',
			'CREATE TABLE dns_metric_queries (qtype TEXT, transport TEXT, listener_ip TEXT, listener_interface TEXT, client_ip TEXT, count INTEGER);',
			"INSERT INTO dns_metric_queries VALUES ('A','UDP','192.0.2.1','Län,\"\\','198.51.100.1',2),('A','UDP','192.0.2.1','Län,\"\\','198.51.100.2',3),('A','UDP','::1','Localhost','198.51.100.1',1);",
			'CREATE TABLE dns_metric_settings (row INTEGER PRIMARY KEY, client_ip INTEGER, epoch TEXT);',
			"INSERT INTO dns_metric_settings VALUES (0,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
		]);
		$s = pfb_metrics_collect();
		$this->assertTrue($s['source_up']['resolver_db']);
		$this->assertCount(2, $s['resolver_detail']);
		$this->assertSame(6, array_sum(array_column($s['resolver_detail'], 'count')));
		$this->assertSame(['', ''], array_column($s['resolver_detail'], 'client_ip'));
		config_set_path('installedpackages/pfblockerng/config/0/pfb_metrics_client_ip', 'on');
		$s = pfb_metrics_collect();
		$this->assertTrue($s['source_up']['resolver_db']);
		$this->assertCount(3, $s['resolver_detail']);
		$this->assertSame('198.51.100.1', $s['resolver_detail'][0]['client_ip']);
		$this->assertSame(str_repeat('a', 32), $s['client_policy_epochs'][$GLOBALS['pfb']['dnsbl_resolver']]);
	}

	public function testOldClientPublisherCannotReturnAfterOffOnEpochRotation(): void
	{
		mkdir("{$this->root}/node");
		$this->enableExport("{$this->root}/node");
		config_set_path('installedpackages/pfblockerng/config/0/pfb_metrics_client_ip', 'on');
		$this->sqlite($GLOBALS['pfb']['dnsbl_resolver'], [
			'CREATE TABLE resolver (row INTEGER, totalqueries INTEGER, queries INTEGER);',
			'INSERT INTO resolver VALUES (0,5,0);',
			'CREATE TABLE dns_metric_queries (qtype TEXT, transport TEXT, listener_ip TEXT, listener_interface TEXT, client_ip TEXT, count INTEGER);',
			"INSERT INTO dns_metric_queries VALUES ('A','UDP','192.0.2.1','LAN','198.51.100.1',5);",
			'CREATE TABLE dns_metric_settings (row INTEGER PRIMARY KEY, client_ip INTEGER, epoch TEXT);',
			"INSERT INTO dns_metric_settings VALUES (0,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
		]);
		$snapshot = pfb_metrics_collect();
		$body = pfb_metrics_render($snapshot);
		$this->assertStringContainsString('client_ip="198.51.100.1"', $body);
		$this->assertTrue(pfb_metrics_publish($body, "{$this->root}/node", 10.0, $snapshot['client_policy_epochs']));
		$this->assertNull(pfb_metrics_client_save(PfbToggle::Off, static function (): void {
			PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::Off);
		}, "{$this->root}/node"));
		$this->assertFileDoesNotExist("{$this->root}/node/pfblockerng.prom");
		$this->assertNull(pfb_metrics_client_save(PfbToggle::On, static function (): void {
			PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::On);
		}, "{$this->root}/node"));
		$this->assertFalse(pfb_metrics_publish($body, "{$this->root}/node", 10.0, $snapshot['client_policy_epochs']));
		$this->assertTrue(pfb_metrics_write("{$this->root}/node"));
		$this->assertStringNotContainsString('client_ip=', (string) file_get_contents("{$this->root}/node/pfblockerng.prom"));
	}

	public function testPrivacyTransactionAbortRollsBackCountsAndPolicy(): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dns_metric_blocks (qtype TEXT, client_ip TEXT, count INTEGER);',
			"INSERT INTO dns_metric_blocks VALUES ('A','198.51.100.1',2),('A','198.51.100.2',3);",
			'CREATE TABLE dns_metric_settings (row INTEGER PRIMARY KEY, client_ip INTEGER, epoch TEXT);',
			"INSERT INTO dns_metric_settings VALUES (0,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
			"CREATE TRIGGER refuse BEFORE INSERT ON dns_metric_blocks BEGIN SELECT RAISE(ABORT,'refuse'); END;",
		]);
		PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::On);
		$this->assertStringContainsString('refuse', pfb_metrics_client_save(PfbToggle::Off, static function (): void {
			self::fail('failed privacy transaction must not persist');
		}));
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$this->assertSame(5, $db->querySingle('SELECT sum(count) FROM dns_metric_blocks'));
		$this->assertSame(2, $db->querySingle('SELECT count(*) FROM dns_metric_blocks'));
		$this->assertSame(2, $db->querySingle("SELECT count(*) FROM dns_metric_blocks WHERE client_ip<>''"));
		$this->assertSame(str_repeat('a', 32), $db->querySingle('SELECT epoch FROM dns_metric_settings'));
		$db->close();
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_metrics_client_ip'));
	}

	public function testLockedRequiredPrivacyTransitionDoesNotSaveFalseOff(): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dns_metric_blocks (qtype TEXT, client_ip TEXT, count INTEGER);',
			"INSERT INTO dns_metric_blocks VALUES ('A','198.51.100.1',5);",
		]);
		PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::On);
		$GLOBALS['pfb']['sqlite_timeout'] = 1;
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('BEGIN IMMEDIATE');
		try {
			$error = pfb_metrics_client_save(PfbToggle::Off, static function (): void {
				self::fail('locked privacy transaction must not persist');
			});
			$this->assertStringContainsString('still enabled', $error);
			$this->assertSame(5, $db->querySingle('SELECT sum(count) FROM dns_metric_blocks'));
			$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_metrics_client_ip'));
		} finally {
			$db->exec('ROLLBACK');
			$db->close();
		}
	}

	/** @return array<string,array{string,string}> */
	public static function hostileEndpointLabels(): array
	{
		return [
			'malformed listener' => ['listener_ip', 'bad'],
			'unspecified v4' => ['listener_ip', '0.0.0.0'],
			'unspecified v6' => ['listener_ip', '::'],
			'brackets' => ['listener_ip', '[::1]'],
			'zone' => ['listener_ip', 'fe80::1%lo0'],
			'prefix' => ['listener_ip', '192.0.2.1/24'],
			'client hostname' => ['client_ip', 'host.example'],
			'client zone' => ['client_ip', 'fe80::1%lo0'],
			'control interface' => ['listener_interface', "LAN\nforged"],
			'C1 interface' => ['listener_interface', "LAN\u{0085}forged"],
			'invalid UTF8 interface' => ['listener_interface', "LAN\xff"],
			'zero width joiner interface' => ['listener_interface', "LAN\u{200D}forged"],
			'bidi mark interface' => ['listener_interface', "LAN\u{200E}forged"],
			'line separator interface' => ['listener_interface', "LAN\u{2028}forged"],
			'paragraph separator interface' => ['listener_interface', "LAN\u{2029}forged"],
			'byte order mark interface' => ['listener_interface', "LAN\u{FEFF}forged"],
		];
	}

	#[DataProvider('hostileEndpointLabels')]
	public function testInvalidEndpointLabelDropsOnlyItsSource(string $field, string $value): void
	{
		$row = ['listener_ip' => '192.0.2.1', 'listener_interface' => 'LAN', 'client_ip' => '198.51.100.1'];
		$row[$field] = $value;
		$values = implode(',', array_map(static fn (string $text): string => "'" . SQLite3::escapeString($text) . "'", array_values($row)));
		$this->sqlite($GLOBALS['pfb']['dnsbl_resolver'], [
			'CREATE TABLE resolver (row INTEGER, totalqueries INTEGER, queries INTEGER);',
			'INSERT INTO resolver VALUES (0,5,0);',
			'CREATE TABLE dns_metric_queries (qtype TEXT, transport TEXT, listener_ip TEXT, listener_interface TEXT, client_ip TEXT, count INTEGER);',
			"INSERT INTO dns_metric_queries VALUES ('A','UDP',{$values},5);",
		]);
		$s = pfb_metrics_collect();
		$this->assertFalse($s['source_up']['resolver_db']);
		$this->assertTrue($s['source_up']['dnsbl_db']);
		$this->assertNull($s['resolver_queries']);
	}

	public function testPublisherReadsFreshSavedClientPermissionUnderLock(): void
	{
		mkdir("{$this->root}/node");
		$this->enableExport("{$this->root}/node");
		PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::On);
		$this->sqlite($GLOBALS['pfb']['dnsbl_resolver'], [
			'CREATE TABLE dns_metric_settings (row INTEGER PRIMARY KEY, client_ip INTEGER, epoch TEXT);',
			"INSERT INTO dns_metric_settings VALUES (0,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
		]);
		$GLOBALS['pfb_test_config_read_hook'] = static function (): void {
			PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::Off);
		};
		try {
			$this->assertFalse(pfb_metrics_publish('counter{client_ip="198.51.100.1"} 5', "{$this->root}/node", 10.0,
				[$GLOBALS['pfb']['dnsbl_resolver'] => str_repeat('a', 32)]));
			$this->assertFileDoesNotExist("{$this->root}/node/pfblockerng.prom");
		} finally {
			unset($GLOBALS['pfb_test_config_read_hook']);
		}
	}

	public function testClientPolicyFenceDoesNotMistakeInterfaceTextForClientLabel(): void
	{
		mkdir("{$this->root}/node");
		$this->enableExport("{$this->root}/node");
		$this->sqlite($GLOBALS['pfb']['dnsbl_resolver'], [
			'CREATE TABLE resolver (row INTEGER, totalqueries INTEGER, queries INTEGER);',
			'INSERT INTO resolver VALUES (0,5,0);',
			'CREATE TABLE dns_metric_queries (qtype TEXT, transport TEXT, listener_ip TEXT, listener_interface TEXT, client_ip TEXT, count INTEGER);',
			"INSERT INTO dns_metric_queries VALUES ('A','UDP','192.0.2.1','client_ip=lab','',5);",
		]);
		$snapshot = pfb_metrics_collect();
		$body = pfb_metrics_render($snapshot);
		$this->assertStringContainsString('listener_interface="client_ip=lab"', $body);
		$this->assertStringNotContainsString(',client_ip="', $body);
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_metrics_client_ip'));
		$this->assertTrue(pfb_metrics_publish($body, "{$this->root}/node", 10.0, $snapshot['client_policy_epochs']));
		$this->assertSame($body, file_get_contents("{$this->root}/node/pfblockerng.prom"));
	}

	public function testMissingAccountingDoesNotGateExplicitPreferenceTransitions(): void
	{
		foreach ([PfbToggle::On, PfbToggle::Off] as $desired) {
			$this->assertNull(pfb_metrics_client_save($desired, static function () use ($desired): void {
				PfbConfig::write('gen/pfb_metrics_client_ip', $desired);
			}));
			$this->assertSame($desired, PfbConfig::read('gen/pfb_metrics_client_ip'));
			$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_info']);
			$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_resolver']);
		}
	}

	public function testUnrelatedSaveWhileOnDoesNotReconcileUnavailableAccounting(): void
	{
		PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::On);
		file_put_contents($GLOBALS['pfb']['dnsbl_info'], 'corrupt');
		$saved = FALSE;
		$this->assertNull(pfb_metrics_client_save(PfbToggle::On, static function () use (&$saved): void {
			$saved = TRUE;
		}));
		$this->assertTrue($saved);
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_metrics_client_ip'));
	}

	public function testDatabaseOffPolicySuppressesClientDespiteSavedOnPreference(): void
	{
		PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::On);
		$this->sqlite($GLOBALS['pfb']['dnsbl_resolver'], [
			'CREATE TABLE resolver (row INTEGER, totalqueries INTEGER, queries INTEGER);',
			'INSERT INTO resolver VALUES (0,5,0);',
			'CREATE TABLE dns_metric_queries (qtype TEXT, transport TEXT, listener_ip TEXT, listener_interface TEXT, client_ip TEXT, count INTEGER);',
			"INSERT INTO dns_metric_queries VALUES ('A','UDP','192.0.2.1','LAN','198.51.100.1',2),('A','UDP','192.0.2.1','LAN','198.51.100.2',3);",
			'CREATE TABLE dns_metric_settings (row INTEGER PRIMARY KEY, client_ip INTEGER, epoch TEXT);',
			"INSERT INTO dns_metric_settings VALUES (0,0,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
		]);
		$snapshot = pfb_metrics_collect();
		$this->assertTrue($snapshot['source_up']['resolver_db']);
		$this->assertSame([], $snapshot['client_policy_epochs']);
		$this->assertCount(1, $snapshot['resolver_detail']);
		$this->assertSame(5, $snapshot['resolver_detail'][0]['count']);
		$this->assertStringNotContainsString(',client_ip="', pfb_metrics_render($snapshot));
	}

	public function testDetailCountersPreserveLegacyResidual(): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER);',
			"INSERT INTO dnsbl VALUES ('Ads', '', 5, 12);",
			'CREATE TABLE dns_metric_blocks (owner TEXT, origin TEXT, groupname TEXT NOT NULL, qtype TEXT NOT NULL, transport TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(owner,origin,groupname,qtype,transport));',
			'CREATE TABLE dnsbl_group_epochs(owner TEXT,origin TEXT,epoch TEXT);',
			"INSERT INTO dnsbl_group_epochs VALUES ('DNSBL_A','custom','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
			'CREATE TABLE dns_metric_totals(owner TEXT,origin TEXT,groupname TEXT,count INTEGER);',
			"INSERT INTO dns_metric_totals VALUES ('DNSBL_A','custom','Ads',5);",
			"INSERT INTO dns_metric_blocks VALUES ('DNSBL_A','custom','Ads', 'AAAA', 'DoH', 3), ('DNSBL_A','custom','Ads', 'MX', '', 2);",
		]);
		$this->sqlite($GLOBALS['pfb']['dnsbl_resolver'], [
			'CREATE TABLE resolver (row INTEGER, totalqueries INTEGER, queries INTEGER);',
			'INSERT INTO resolver VALUES (0, 18, 2);',
			'CREATE TABLE dns_metric_queries (qtype TEXT NOT NULL, transport TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(qtype,transport));',
			"INSERT INTO dns_metric_queries VALUES ('AAAA', 'DoH', 4), ('HTTPS', '', 3);",
		]);

		$s = pfb_metrics_collect();
		$this->assertTrue($s['source_up']['dnsbl_db']);
		$this->assertTrue($s['source_up']['resolver_db']);
		$this->assertCount(2, $s['dnsbl_detail']);
		$this->assertCount(2, $s['resolver_detail']);
		$body = pfb_metrics_render($s);
		$this->assertStringContainsString("pfblockerng_dnsbl_blocked_queries_total{group=\"Ads\"} 7\n", $body);
		$this->assertStringContainsString("pfblockerng_dnsbl_resolver_queries_total 13\n", $body);
		$this->assertStringContainsString("pfblockerng_dnsbl_resolver_queries_total{qtype=\"HTTPS\"} 3\n", $body);
	}

	/** @return array<string,array{0:string}> */
	public static function invalidDetailProvider(): array
	{
		return [
			'negative count' => ["('A', 'UDP', -1)"],
			'noninteger count' => ["('A', 'UDP', 'bad')"],
			'exceeds aggregate' => ["('A', 'UDP', 21)"],
			'combined exceeds aggregate' => ["('A', 'UDP', 12), ('AAAA', '', 9)"],
			'duplicate series' => ["('A', 'UDP', 2), ('A', 'UDP', 3)"],
			'unknown transport' => ["('A', 'QUIC', 1)"],
			'invalid qtype' => ["('client.example', 'UDP', 1)"],
			'out of range qtype' => ["('TYPE65536', 'UDP', 1)"],
			'fractional count' => ["('A', 'UDP', 1.5)"],
			'empty qtype' => ["('', 'UDP', 1)"],
			'null qtype' => ["(NULL, 'UDP', 1)"],
			'null transport' => ["('A', NULL, 1)"],
			'null count' => ["('A', 'UDP', NULL)"],
		];
	}

	#[DataProvider('invalidDetailProvider')]
	public function testInvalidDetailsFailTheSourceInsteadOfExportingFabricatedTotals(string $values): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_resolver'], [
			'CREATE TABLE resolver (row INTEGER, totalqueries INTEGER, queries INTEGER);',
			'INSERT INTO resolver VALUES (0, 18, 2);',
			'CREATE TABLE dns_metric_queries (qtype TEXT, transport TEXT, count INTEGER);',
			"INSERT INTO dns_metric_queries VALUES {$values};",
		]);

		$s = pfb_metrics_collect();
		$this->assertFalse($s['source_up']['resolver_db']);
		$this->assertNull($s['resolver_queries']);
		$this->assertNull($s['resolver_detail']);
		$this->assertStringNotContainsString('pfblockerng_dnsbl_resolver_queries_total', pfb_metrics_render($s));
	}

	public function testMalformedDetailTableIsNotTreatedAsALegacyDatabase(): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dnsbl (groupname TEXT, entries INTEGER, counter INTEGER);',
			"INSERT INTO dnsbl VALUES ('Ads', 5, 12);",
			'CREATE TABLE dns_metric_blocks (wrong TEXT);',
		]);
		$s = pfb_metrics_collect();
		$this->assertFalse($s['source_up']['dnsbl_db']);
		$this->assertNull($s['dnsbl_groups']);
		$this->assertNull($s['dnsbl_detail']);
	}

	public function testAllTransportsNumericQtypeAndDisabledHostileGroupHaveExactSum(): void
	{
		$group = "bad\"\\group\n\xFF";
		$quoted = SQLite3::escapeString($group);
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dnsbl (groupname TEXT, entries INTEGER, counter INTEGER);',
			"INSERT INTO dnsbl VALUES ('{$quoted}', 'disabled', 20);",
			'CREATE TABLE dns_metric_blocks (owner TEXT, origin TEXT, groupname TEXT, qtype TEXT, transport TEXT, count INTEGER);',
			'CREATE TABLE dnsbl_group_epochs(owner TEXT,origin TEXT,epoch TEXT);',
			"INSERT INTO dnsbl_group_epochs VALUES ('DNSBL_A','custom','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
			'CREATE TABLE dns_metric_totals(owner TEXT,origin TEXT,groupname TEXT,count INTEGER);',
			"INSERT INTO dns_metric_totals VALUES ('DNSBL_A','custom','{$quoted}',12);",
		]);
		foreach (['UDP', 'TCP', 'DoT', 'DoH', 'DoQ', ''] as $transport) {
			$this->sqlite($GLOBALS['pfb']['dnsbl_info'], ["INSERT INTO dns_metric_blocks VALUES ('DNSBL_A','custom','{$quoted}', 'TYPE65535', '{$transport}', 2);"]);
		}
		$s = pfb_metrics_collect();
		$this->assertTrue($s['source_up']['dnsbl_db']);
		$this->assertCount(6, $s['dnsbl_detail']);
		$body = pfb_metrics_render($s);
		$this->assertStringNotContainsString('pfblockerng_dnsbl_group_entries', $body);
		$this->assertTrue(mb_check_encoding($body, 'UTF-8'));
		preg_match_all('/^pfblockerng_dnsbl_blocked_queries_total[^\n]* ([0-9]+)$/m', $body, $samples);
		$this->assertSame(20, array_sum(array_map('intval', $samples[1])));
		$this->assertCount(7, $samples[1]);
		foreach (['UDP', 'TCP', 'DoT', 'DoH', 'DoQ'] as $transport) {
			$this->assertStringContainsString('qtype="TYPE65535",transport="' . $transport . '"} 2', $body);
		}
		$this->assertStringContainsString('qtype="TYPE65535"} 2', $body);
	}

	public function testOrphanBlockedDetailsFailOnlyDnsblSource(): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dnsbl (groupname TEXT, entries INTEGER, counter INTEGER);',
			"INSERT INTO dnsbl VALUES ('Ads', 1, 10);",
			'CREATE TABLE dns_metric_blocks (owner TEXT, origin TEXT, groupname TEXT, qtype TEXT, transport TEXT, count INTEGER);',
			'CREATE TABLE dnsbl_group_epochs(owner TEXT,origin TEXT,epoch TEXT);',
			"INSERT INTO dnsbl_group_epochs VALUES ('DNSBL_A','custom','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');",
			'CREATE TABLE dns_metric_totals(owner TEXT,origin TEXT,groupname TEXT,count INTEGER);',
			"INSERT INTO dns_metric_blocks VALUES ('DNSBL_A','custom','Gone', 'A', 'UDP', 1);",
		]);
		$s = pfb_metrics_collect();
		$this->assertFalse($s['source_up']['dnsbl_db']);
		$this->assertTrue($s['source_up']['resolver_db']);
		$this->assertNull($s['dnsbl_groups']);
		$this->assertNull($s['dnsbl_detail']);
		$this->assertStringNotContainsString('pfblockerng_dnsbl_blocked_queries_total', pfb_metrics_render($s));
	}

	public function testSnapshotIsReadonlyAndClosesFailedTransaction(): void
	{
		$path = $GLOBALS['pfb']['dnsbl_resolver'];
		$this->sqlite($path, ['CREATE TABLE resolver (queries INTEGER);', 'INSERT INTO resolver VALUES (10);']);
		$this->assertSame(['aggregate' => [['queries' => 10]], 'detail' => []], pfb_metrics_sqlite_snapshot($path, 'SELECT queries FROM resolver', 'absent', 'SELECT count FROM absent'));
		$this->assertNull(pfb_metrics_sqlite_snapshot($path, 'UPDATE resolver SET queries = 99 RETURNING queries', 'absent', 'SELECT 1'));
		$this->assertNull(pfb_metrics_sqlite_snapshot($path, 'SELECT queries FROM resolver', 'resolver', 'SELECT missing FROM resolver'));
		$db = new SQLite3($path);
		$this->assertSame(10, $db->querySingle('SELECT queries FROM resolver'));
		$this->assertTrue($db->exec('BEGIN EXCLUSIVE'));
		$this->assertTrue($db->exec('ROLLBACK'));
		$this->assertSame(0, $db->querySingle("SELECT count(*) FROM sqlite_master WHERE name = 'absent'"));
		$db->close();
	}

	public function testSnapshotKeepsAggregateAndDetailsTogetherAcrossWalCommit(): void
	{
		$path = $GLOBALS['pfb']['dnsbl_resolver'];
		$this->sqlite($path, [
			'PRAGMA journal_mode=WAL;',
			'CREATE TABLE resolver (queries INTEGER);',
			'INSERT INTO resolver VALUES (10);',
			'CREATE TABLE dns_metric_queries (count INTEGER);',
			'INSERT INTO dns_metric_queries VALUES (3);',
		]);
		$factory = static function (string $path): SQLite3 {
			return new class($path, SQLITE3_OPEN_READONLY) extends SQLite3 {
				public function __construct(private string $path, int $flags)
				{
					parent::__construct($path, $flags);
				}

				public function query(string $query): SQLite3Result|false
				{
					if ($query === 'SELECT count FROM dns_metric_queries') {
						$writer = new SQLite3($this->path);
						$writer->enableExceptions(TRUE);
						$writer->exec('BEGIN IMMEDIATE; UPDATE resolver SET queries = 20; UPDATE dns_metric_queries SET count = 13; COMMIT;');
						$writer->close();
					}
					return parent::query($query);
				}
			};
		};
		$snapshot = pfb_metrics_sqlite_snapshot($path, 'SELECT queries FROM resolver', 'dns_metric_queries', 'SELECT count FROM dns_metric_queries', $factory);
		$this->assertSame(['aggregate' => [['queries' => 10]], 'detail' => [['count' => 3]]], $snapshot);
		$db = new SQLite3($path);
		$this->assertSame(20, $db->querySingle('SELECT queries FROM resolver'));
		$this->assertSame(13, $db->querySingle('SELECT count FROM dns_metric_queries'));
		$db->close();
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

	public function testTwoDnsblRowsForOneGroupGiveOneSampleAndTheLastRowWins(): void
	{
		$this->sqlite($GLOBALS['pfb']['dnsbl_info'], [
			'CREATE TABLE dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER );',
			"INSERT INTO dnsbl VALUES ('DNSBL_Ads', '2026-10-18 10:00:00', 5000, 17);",
			"INSERT INTO dnsbl VALUES ('DNSBL_Malware', '2026-10-18 10:00:00', 70, 1);",
			"INSERT INTO dnsbl VALUES ('DNSBL_Ads', '2026-10-18 10:05:00', 6000, 20);",
		]);

		$body = pfb_metrics_render(pfb_metrics_collect());

		$this->assertSame(1, substr_count($body, 'pfblockerng_dnsbl_blocked_queries_total{group="DNSBL_Ads"}'), 'a repeated sample makes Prometheus reject the whole file');
		$this->assertStringContainsString('pfblockerng_dnsbl_blocked_queries_total{group="DNSBL_Ads"} 20', $body);
		$this->assertSame(1, substr_count($body, 'pfblockerng_dnsbl_group_entries{group="DNSBL_Ads"}'));
		$this->assertStringContainsString('pfblockerng_dnsbl_group_entries{group="DNSBL_Ads"} 6000', $body);
		$this->assertStringContainsString('pfblockerng_dnsbl_blocked_queries_total{group="DNSBL_Malware"} 1', $body);
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

	public function testTheSameFailureInBothLedgersGivesOneRowAndOneSeries(): void
	{
		file_put_contents("{$GLOBALS['pfb']['dbdir']}/pfb_sync_status.json", json_encode([
			'ip' => ['ipv4:Alias_v4' => ['download' => ['message' => 'x', 'first_seen' => 1, 'last_seen' => 2]]],
		]));
		file_put_contents("{$GLOBALS['pfb']['dnsbldir']}/pfb_py_status.json", json_encode([
			['facility' => 'ip', 'item' => 'ipv4:Alias_v4', 'stage' => 'download', 'message' => 'm', 'first_seen' => 1, 'last_seen' => 2],
		]));

		$s = pfb_metrics_collect();

		$this->assertSame([['facility' => 'ip', 'feed' => 'ipv4:Alias_v4', 'stage' => 'download']], $s['feed_failing']);
		$this->assertSame(
			1,
			substr_count(pfb_metrics_render($s), 'pfblockerng_feed_failing{facility="ip",feed="ipv4:Alias_v4",stage="download"} 1'),
			'a repeated label set makes the whole file invalid'
		);
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

	public function testAggregateTablesAreNeverExportedWhateverTheWidgetSettingIs(): void
	{
		config_set_path('installedpackages/pfblockerngglobal/widget-show_agg', 'on');
		$GLOBALS['pfb']['show_agg'] = TRUE;	// what the widget reads: a collector that passed it on would reveal the aggregate
		file_put_contents("{$GLOBALS['pfb']['pfctl']}.out", implode("\n", [
			"-p-a---\tpfB_Deny_v4",
			"\tAddresses: 1200",
			"-p-a---\tpfB_DNSBL_VIPs",
			"\tAddresses: 1",
			"-p-a---\tpfB_Deny_Aggregated_v4",
			"\tAddresses: 900",
			'',
		]));

		$this->assertSame(['pfB_Deny_v4' => 1200], pfb_metrics_collect()['ip_tables'], 'the dashboard checkbox must not add series');
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
		$marker = $GLOBALS['pfb']['metrics_dir_missing'];
		file_put_contents($marker, '');

		pfb_metrics_configure_cron(FALSE, "{$this->root}/export");

		$this->assertFileDoesNotExist($marker);
	}

	public function testCorruptPassStatusReadsAsNullAndSourceDown(): void
	{
		file_put_contents($GLOBALS['pfb']['pass_status'], 'not json');

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
		$this->wantExport(PfbToggle::On, 'on');
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
		$held = fopen($GLOBALS['pfb']['metrics_lock'], 'c');
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

	public function testEnableProceedsWithoutTheLockWhenItIsWedged(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$held = fopen($GLOBALS['pfb']['metrics_lock'], 'c');
		$this->assertNotFalse($held);
		$this->assertTrue(flock($held, LOCK_EX));

		try {
			pfb_metrics_configure_cron(TRUE, $dir, 0.05);
		} finally {
			flock($held, LOCK_UN);
			fclose($held);
		}

		$this->assertFileExists($this->sentinel(), 'a wedged lock holder must not block an enable: touching the sentinel races with nothing');
		$this->assertCount(1, $this->cronItems());
	}

	public function testNonArrayPfRulesReadIsDownWithoutThrowing(): void
	{
		$GLOBALS['pfb_test_pf_rules'] = FALSE;

		$s = pfb_metrics_collect();

		$this->assertFalse($s['source_up']['pf_rules']);
		$this->assertNull($s['ip_rule_packets']);
	}

	public function testNonSqliteResolverFileGivesNullAndSourceDown(): void
	{
		file_put_contents($GLOBALS['pfb']['dnsbl_resolver'], str_repeat('not a sqlite database ', 64));

		$s = pfb_metrics_collect();

		$this->assertNull($s['resolver_queries']);
		$this->assertFalse($s['source_up']['resolver_db']);
		$this->assertTrue($s['source_up']['dnsbl_db'], 'the other database is independent');
	}

	public function testAggregateRulePacketsAreNeverExportedWhateverTheWidgetSettingIs(): void
	{
		config_set_path('filter/rule', [
			['descr' => 'pfB_Deny_Aggregated_v4 block', 'tracker' => 1001, 'type' => 'block', 'source' => ['address' => 'pfB_Deny_Aggregated_v4']],
			['descr' => 'pfB_DNSBL VIP pass', 'tracker' => 1002, 'type' => 'pass', 'destination' => ['address' => 'pfB_DNSBL_VIPs']],
		]);
		$GLOBALS['pfb_test_pf_rules'] = [
			['tracker' => 1001, 'packets' => 42],
			['tracker' => 1002, 'packets' => 7],
		];
		$this->assertSame([], pfb_metrics_collect()['ip_rule_packets'], 'before: aggregates are hidden while show_agg is off');

		config_set_path('installedpackages/pfblockerngglobal/widget-show_agg', 'on');
		$GLOBALS['pfb']['show_agg'] = TRUE;	// what the widget reads: a collector that passed it on would reveal the aggregate

		$this->assertSame([], pfb_metrics_collect()['ip_rule_packets'], 'the dashboard checkbox must not add series');
	}

	public function testEnablingAgainLeavesAnExistingCronEntryAlone(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		pfb_metrics_configure_cron(TRUE, $dir);
		// The install double overwrites a matching entry with who=root, so a reinstall would erase this marker.
		config_set_path('cron/item/0/who', 'marker');

		pfb_metrics_configure_cron(TRUE, $dir);

		$this->assertSame('marker', $this->cronItems()[0]['who'], 'an entry that already matches must not be reinstalled');
	}

	public function testSuccessfulWriteReplacesAnExistingPromFile(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);
		file_put_contents("{$dir}/pfblockerng.prom", 'previous publish');

		$this->assertTrue(pfb_metrics_write($dir));

		$this->assertSame(pfb_metrics_render(pfb_metrics_collect()), file_get_contents("{$dir}/pfblockerng.prom"));
	}

	public function testTheLockIsFreeWhileTheCronEntryIsChanged(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$lockPath = $GLOBALS['pfb']['metrics_lock'];
		$seen = [];
		// Real install_cron_job() can start cron, which would inherit a held lock fd and wedge every publish.
		$GLOBALS['pfb_test_install_cron_hook'] = static function (string $command, bool $active) use ($lockPath, &$seen): void {
			$probe = fopen($lockPath, 'c');
			$seen[] = [$active, flock($probe, LOCK_EX | LOCK_NB)];
			fclose($probe);
		};

		try {
			pfb_metrics_configure_cron(TRUE, $dir);
			pfb_metrics_configure_cron(FALSE, $dir);
		} finally {
			unset($GLOBALS['pfb_test_install_cron_hook']);
		}

		$this->assertSame([[TRUE, TRUE], [FALSE, TRUE]], $seen, 'each cron change must run with the lock free: [active, lock was free]');
	}

	/**
	 * Starts a second process that takes the metrics lock, announces it, runs $then (PHP; $lock and $argv[2..] are in scope)
	 * and releases. Returns once the lock is held, so the caller acts against a lock that is really taken.
	 *
	 * @return array{0: resource, 1: resource} process and its stdout pipe
	 */
	private function lockHolder(string $then, string ...$args): array
	{
		$code = '$lock = fopen($argv[1], "c"); flock($lock, LOCK_EX); echo "locked\n"; fflush(STDOUT); ' . $then . ' flock($lock, LOCK_UN);';
		$proc = proc_open([PHP_BINARY, '-r', $code, $GLOBALS['pfb']['metrics_lock'], ...$args], [1 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($proc);
		$this->assertSame("locked\n", fgets($pipes[1]), 'the holder must hold the lock before the test acts');
		return [$proc, $pipes[1]];
	}

	/** @param array{0: resource, 1: resource} $holder */
	private function releaseHolder(array $holder): void
	{
		fclose($holder[1]);
		proc_close($holder[0]);
	}

	public function testAWriteWaitingForTheLockIsRefusedWhenTheExportIsDisabledMeanwhile(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);
		// The fake pfctl runs during collection, before the lock is wanted, so it tells the holder the write is under way.
		$started = "{$this->root}/write.started";
		file_put_contents($GLOBALS['pfb']['pfctl'], "#!/bin/sh\ntouch " . escapeshellarg($started) . "\nexit 0\n");
		$holder = $this->lockHolder(
			'for ($i = 0; $i < 500 && !file_exists($argv[2]); $i++) { usleep(10000); } usleep(300000); unlink($argv[3]);',
			$started,
			$this->sentinel()
		);

		try {
			$published = pfb_metrics_write($dir);
		} finally {
			$this->releaseHolder($holder);
		}

		$this->assertFalse($published, 'the enabled check must be made once the lock is held, not before waiting for it');
		$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom");
		$this->assertSame([], glob("{$dir}/.pfbmetrics_*"));
	}

	public function testADisableWaitsForAPublishInFlightWhateverBudgetItIsGivenAndRemovesWhatItWrote(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);
		// A publisher that already passed its sentinel check: it holds the lock for a second and then renames its file into place.
		$holder = $this->lockHolder('usleep(1000000); file_put_contents($argv[2], "late");', "{$dir}/pfblockerng.prom");

		$began = microtime(TRUE);
		try {
			pfb_metrics_configure_cron(FALSE, $dir, 0.05);
		} finally {
			$this->releaseHolder($holder);
		}
		$waited = microtime(TRUE) - $began;

		$this->assertGreaterThan(0.5, $waited, 'a disable waits for the lock instead of giving up after the enable budget');
		$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom", 'a disable must wait out a publish in flight, or the file outlives it');
		$this->assertFileDoesNotExist($this->sentinel());
		$this->assertSame([], $this->cronItems());
	}

	public function testSyncLedgerWhoseReadLockTimesOutIsDownWithNoRows(): void
	{
		$path = "{$GLOBALS['pfb']['dbdir']}/pfb_sync_status.json";
		file_put_contents($path, json_encode([
			'ip' => ['ipv4:Alias_v4' => ['download' => ['message' => 'x', 'first_seen' => 1, 'last_seen' => 2]]],
		]));
		$writer = fopen($path, 'r');
		$this->assertNotFalse($writer);
		$this->assertTrue(flock($writer, LOCK_EX));

		try {
			$s = pfb_metrics_collect();	// waits out the collector's 5 s read budget
		} finally {
			flock($writer, LOCK_UN);
			fclose($writer);
		}

		$this->assertFalse($s['source_up']['sync_status'], 'a ledger that could not be read is down, not an empty ledger');
		$this->assertSame([], $s['feed_failing']);
	}

	public function testSyncLedgerRowsAreTakenFromTheSnapshotThatSetTheHealth(): void
	{
		$ledger = static fn (string $alias): string => (string) json_encode([
			'ip' => ["ipv4:{$alias}" => ['download' => ['message' => 'x', 'first_seen' => 1, 'last_seen' => 2]]],
		]);
		// Each open of the ledger hands out the next body: a second read would show the second one.
		MetricsLedgerStream::$bodies = [$ledger('First_v4'), $ledger('Second_v4')];
		MetricsLedgerStream::$opens = 0;
		$this->assertTrue(stream_wrapper_register('pfbledger', MetricsLedgerStream::class));
		$GLOBALS['pfb']['dbdir'] = 'pfbledger://db';

		try {
			$s = pfb_metrics_collect();
		} finally {
			stream_wrapper_unregister('pfbledger');
		}

		$this->assertSame(1, MetricsLedgerStream::$opens, 'the ledger must be read once');
		$this->assertTrue($s['source_up']['sync_status']);
		$this->assertSame([['facility' => 'ip', 'feed' => 'ipv4:First_v4', 'stage' => 'download']], $s['feed_failing']);
	}

	public function testTheStateFilesDefaultToUsrLocalEtcWhichSurvivesARamDiskVar(): void
	{
		$keys = ['metrics_enabled', 'metrics_lock', 'metrics_dir_missing', 'metrics_sentinel_missing', 'pass_status'];

		// setUp saved the values the package defined at load, before it pointed them at the sandbox.
		$this->assertSame([
			'metrics_enabled'          => '/usr/local/etc/pfb_metrics_enabled',
			'metrics_lock'             => '/usr/local/etc/pfb_metrics.lock',
			'metrics_dir_missing'      => '/usr/local/etc/pfb_metrics_dir_missing',
			'metrics_sentinel_missing' => '/usr/local/etc/pfb_metrics_sentinel_missing',
			'pass_status'              => '/usr/local/etc/pfb_pass_status.json',
		], array_intersect_key($this->priorPfb, array_flip($keys)));
	}

	public function testAnEnabledExportKeepsPublishingWhenTheRamDiskVarIsWipedAtBoot(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);
		pfb_pass_status_record('last_start', 1700000000);
		// use_mfs_tmpvar: /var starts empty at every boot, while config.xml still has the cron entry.
		rmdir_recursive($GLOBALS['pfb']['dbdir']);
		mkdir($GLOBALS['pfb']['dbdir']);

		$this->assertTrue(pfb_metrics_write($dir), 'the sentinel must outlive a wipe of /var, or the export stops silently');
		$this->assertStringContainsString(
			'pfblockerng_update_last_start_timestamp_seconds 1700000000',
			(string) file_get_contents("{$dir}/pfblockerng.prom"),
			'the pass times must outlive it too'
		);
	}

	private function wantExport(PfbToggle $enable, string $option): void
	{
		$GLOBALS['pfb']['enable'] = $enable;
		config_set_path('installedpackages/pfblockerng/config/0/pfb_metrics_export', $option);
	}

	public function testAMissingSentinelWithTheExportWantedIsLoggedOncePerOutageAndNothingIsPublished(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->wantExport(PfbToggle::On, 'on');

		$this->assertFalse(pfb_metrics_write($dir));
		$this->assertFalse(pfb_metrics_write($dir));

		$this->assertSame(1, $this->logCount(self::NO_SENTINEL), 'the cron runs every minute: one line per outage, not per run');
		$this->assertFileDoesNotExist($this->sentinel(), 'recreating it here would undo a disable');
		$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom");

		$this->enableExport($dir);
		$this->assertTrue(pfb_metrics_write($dir));
		unlink($this->sentinel());

		$this->assertFalse(pfb_metrics_write($dir));
		$this->assertSame(2, $this->logCount(self::NO_SENTINEL), 'a successful publish re-arms the log');
	}

	/** @return array<string,array{0:PfbToggle,1:string}> */
	public static function exportNotWantedProvider(): array
	{
		return [
			'master switch off' => [PfbToggle::Off, 'on'],
			'option off'        => [PfbToggle::On, ''],
		];
	}

	#[DataProvider('exportNotWantedProvider')]
	public function testAMissingSentinelIsNotLoggedWhileTheExportIsNotWanted(PfbToggle $enable, string $option): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->wantExport($enable, $option);

		$this->assertFalse(pfb_metrics_write($dir));

		$this->assertSame(0, $this->logCount(self::NO_SENTINEL));
	}

	public function testDisableClearsTheSentinelMissingMarker(): void
	{
		$marker = $GLOBALS['pfb']['metrics_sentinel_missing'];
		file_put_contents($marker, '');

		pfb_metrics_configure_cron(FALSE, "{$this->root}/export");

		$this->assertFileDoesNotExist($marker, 're-enabling must log the next outage, not inherit this one');
	}

	#[DataProvider('exportNotWantedProvider')]
	public function testAStaleSentinelDoesNotAuthorizeAPublishWhileTheSettingsTurnTheExportOff(PfbToggle $enable, string $option): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);	// the sentinel a sync left
		$this->wantExport($enable, $option);	// then the settings turned the export off, but that sync returned before reconciling the cron

		$this->assertFalse(pfb_metrics_write($dir));
		$this->assertFalse(pfb_metrics_write($dir));

		$this->assertFileDoesNotExist("{$dir}/pfblockerng.prom", 'a stale sentinel must not outvote the stored disable');
		$this->assertSame([], glob("{$dir}/.pfbmetrics_*"));
		$this->assertFileDoesNotExist($this->sentinel(), 'the stale sentinel is removed');
		$this->assertSame(1, $this->logCount(self::STALE_SENTINEL), 'one line, not one per cron run');
	}

	public function testASymlinkedTextfileDirIsRefusedAndLoggedOncePerOutage(): void
	{
		$target = "{$this->root}/elsewhere";
		mkdir($target);
		$dir = "{$this->root}/node_exporter";
		symlink($target, $dir);
		$this->enableExport($dir);

		$this->assertFalse(pfb_metrics_write($dir));
		$this->assertFalse(pfb_metrics_write($dir));

		$this->assertSame([], array_values(array_diff(scandir($target), ['.', '..'])), 'nothing may be created through the link');
		$this->assertSame(1, $this->logCount(self::SYMLINK));
	}

	public function testDisableDoesNotUnlinkThroughASymlinkedTextfileDir(): void
	{
		$target = "{$this->root}/elsewhere";
		mkdir($target);
		file_put_contents("{$target}/pfblockerng.prom", 'not ours');
		$dir = "{$this->root}/node_exporter";
		symlink($target, $dir);

		pfb_metrics_configure_cron(FALSE, $dir);

		$this->assertSame('not ours', file_get_contents("{$target}/pfblockerng.prom"));
	}

	public function testPublishRemovesStaleTempFilesAndKeepsFreshOnes(): void
	{
		$dir = "{$this->root}/export";
		mkdir($dir);
		$this->enableExport($dir);
		touch("{$dir}/.pfbmetrics_stale", time() - 400);	// a run killed between tempnam() and rename()
		touch("{$dir}/.pfbmetrics_fresh", time() - 30);
		touch("{$dir}/other.prom", time() - 400);

		$this->assertTrue(pfb_metrics_publish('body', $dir));

		$this->assertSame(
			['.pfbmetrics_fresh', 'other.prom', 'pfblockerng.prom'],
			array_values(array_diff(scandir($dir), ['.', '..'])),
			'only an old temp file goes: not a fresh one, and not another collector\'s file'
		);
	}
}

/**
 * Serves pfb_sync_status.json from memory under pfbledger://, one queued body per open, and counts the opens.
 * Everything else under the scheme does not exist.
 */
final class MetricsLedgerStream
{
	/** @var list<string> */
	public static array $bodies = [];
	public static int $opens = 0;
	/** @var resource|null set by PHP */
	public $context;
	private string $body = '';
	private int $pos = 0;

	private static function isLedger(string $path): bool
	{
		return str_ends_with($path, '/pfb_sync_status.json');
	}

	public function stream_open(string $path, string $mode, int $options, ?string &$opened_path): bool
	{
		if (!self::isLedger($path)) {
			return FALSE;
		}
		$this->body = self::$bodies[min(self::$opens, count(self::$bodies) - 1)];
		self::$opens++;
		return TRUE;
	}

	public function stream_read(int $count): string
	{
		$chunk = substr($this->body, $this->pos, $count);
		$this->pos += strlen($chunk);
		return $chunk;
	}

	public function stream_eof(): bool
	{
		return $this->pos >= strlen($this->body);
	}

	public function stream_lock(int $operation): bool
	{
		return TRUE;
	}

	public function stream_close(): void
	{
	}

	/** @return array<string,int> */
	public function stream_stat(): array
	{
		return ['mode' => 0100644, 'size' => strlen($this->body)];
	}

	/** @return array<string,int>|false */
	public function url_stat(string $path, int $flags): array|false
	{
		return self::isLedger($path) ? ['mode' => 0100644, 'size' => 0] : FALSE;
	}
}
