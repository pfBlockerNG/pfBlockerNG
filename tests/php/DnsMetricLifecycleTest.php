<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('dnsbl_save_stats')]
#[CoversFunction('pfBlockerNG_clearsqlite')]
final class DnsMetricLifecycleTest extends TestCase
{
	private string $root;
	private array $priorPfb;

	protected function setUp(): void
	{
		$this->priorPfb = $GLOBALS['pfb'];
		$this->root = sys_get_temp_dir() . '/pfb_dns_lifecycle_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->root, 0700));
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'], [
			'dnsbl_info' => "{$this->root}/dnsbl.sqlite",
			'dnsbl_resolver' => "{$this->root}/resolver.sqlite",
			'log' => "{$this->root}/pfblockerng.log",
			'errlog' => "{$this->root}/error.log",
			'sqlite_timeout' => 2000,
			'alias_dnsbl_configured' => ['DNSBL_A', 'DNSBL_B'],
			'alias_dnsbl_all' => ['DNSBL_A', 'DNSBL_B'],
			'dnsbl_info_stats' => [$this->stat('DNSBL_A', 5), $this->stat('DNSBL_B', 7)],
		]);
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->priorPfb;
		rmdir_recursive($this->root);
	}

	private function stat(string $group, int|string $entries): array
	{
		return ['groupname' => $group, 'timestamp' => '2026-01-01 00:00:00', 'entries' => $entries, 'counter' => 0];
	}

	private function sql(array $statements, bool $resolver = FALSE): void
	{
		$db = new SQLite3($GLOBALS['pfb'][$resolver ? 'dnsbl_resolver' : 'dnsbl_info']);
		try {
			foreach ($statements as $sql) {
				$this->assertTrue($db->exec($sql), $db->lastErrorMsg());
			}
		} finally {
			$db->close();
		}
	}

	private function value(string $sql, bool $resolver = FALSE): mixed
	{
		$db = new SQLite3($GLOBALS['pfb'][$resolver ? 'dnsbl_resolver' : 'dnsbl_info'], SQLITE3_OPEN_READONLY);
		try {
			return $db->querySingle($sql);
		} finally {
			$db->close();
		}
	}

	private function epoch(string $group): ?string
	{
		if (!$this->value("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'dnsbl_group_epochs'")) {
			return NULL;
		}
		return $this->value("SELECT epoch FROM dnsbl_group_epochs WHERE owner = '" . SQLite3::escapeString($group) . "' AND origin = 'custom'");
	}

	private function seed(bool $epochs = TRUE): void
	{
		$this->sql([
			'CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER)',
			"INSERT INTO dnsbl VALUES ('DNSBL_A', 'old', 5, 12), ('DNSBL_B', 'old', 7, 9)",
			"CREATE TABLE dns_metric_blocks (owner TEXT, origin TEXT, groupname TEXT NOT NULL, qtype TEXT NOT NULL, transport TEXT NOT NULL, listener_ip TEXT NOT NULL DEFAULT '', listener_interface TEXT NOT NULL DEFAULT '', client_ip TEXT NOT NULL DEFAULT '', count INTEGER NOT NULL, PRIMARY KEY(owner,origin,groupname,qtype,transport,listener_ip,listener_interface,client_ip))",
			"INSERT INTO dns_metric_blocks VALUES ('DNSBL_A', 'custom', 'DNSBL_A', 'A', 'UDP', '192.0.2.1', 'LAN', '198.51.100.1', 3), ('DNSBL_B', 'custom', 'DNSBL_B', 'AAAA', 'DoH', '::1', 'Localhost', '', 4)",
		]);
		if ($epochs) {
			$this->sql([
				'CREATE TABLE dnsbl_group_epochs (owner TEXT, origin TEXT, epoch TEXT NOT NULL, PRIMARY KEY(owner,origin))',
				"INSERT INTO dnsbl_group_epochs VALUES ('DNSBL_A', 'custom', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), ('DNSBL_B', 'custom', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')",
			]);
		}
	}

	private function assertBPreserved(): void
	{
		$this->assertSame(9, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_B'"));
		$this->assertSame(4, $this->value("SELECT count FROM dns_metric_blocks WHERE groupname = 'DNSBL_B'"));
		$this->assertSame('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', $this->epoch('DNSBL_B'));
	}

	public function testClientPermissionApplySeedsMissingDatabasesWithoutChangingExistingEpoch(): void
	{
		$priorConfig = $GLOBALS['config'] ?? [];
		try {
			$GLOBALS['config'] = [];
			$GLOBALS['pfb']['dnsbl'] = PfbToggle::On;
			pfb_metrics_client_apply();
			$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_info']);
			PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::On);
			pfb_metrics_client_apply();
			$this->assertSame(1, $this->value('SELECT client_ip FROM dns_metric_settings WHERE row=0'));
			$this->assertSame(1, $this->value('SELECT client_ip FROM dns_metric_settings WHERE row=0', TRUE));
			$epoch = $this->value('SELECT epoch FROM dns_metric_settings WHERE row=0');
			pfb_metrics_client_apply();
			$this->assertSame($epoch, $this->value('SELECT epoch FROM dns_metric_settings WHERE row=0'));
		} finally {
			$GLOBALS['config'] = $priorConfig;
		}
	}

	public function testAppliedIniCarriesTheOneClientMetricsPreference(): void
	{
		$priorConfig = $GLOBALS['config'] ?? [];
		$priorG = $GLOBALS['g'] ?? [];
		try {
			$GLOBALS['config'] = [];
			config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
			config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '192.0.2.53');
			config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '');
			$GLOBALS['g']['unbound_chroot_path'] = $this->root;
			pfb_global();
			pfb_dnsbl_ini_inputs();
			$this->assertStringContainsString("metrics_client_ip\t= off\n", pfb_unbound_python_ini('enabled'));
			PfbConfig::write('gen/pfb_metrics_client_ip', PfbToggle::On);
			$this->assertStringContainsString("metrics_client_ip\t= on\n", pfb_unbound_python_ini('enabled'));
		} finally {
			$GLOBALS['config'] = $priorConfig;
			$GLOBALS['g'] = $priorG;
		}
	}

	public function testUpgradeSeedsStableTokensWithoutResettingLegacyCounters(): void
	{
		$this->seed(FALSE);
		$this->assertNull($this->epoch('DNSBL_A'));

		dnsbl_save_stats();

		$a = $this->epoch('DNSBL_A');
		$b = $this->epoch('DNSBL_B');
		$this->assertNotNull($a, 'legacy groups need an incarnation token');
		$this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $a);
		$this->assertNotNull($b);
		$this->assertNotSame($a, $b);
		$this->assertSame(12, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_A'"));
		$this->assertSame(9, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_B'"));
		$this->assertSame(7, $this->value('SELECT sum(count) FROM dns_metric_blocks'));
		dnsbl_save_stats();
		$this->assertSame($a, $this->epoch('DNSBL_A'));
		$this->assertSame($b, $this->epoch('DNSBL_B'));
	}

	public function testDisableRetainsHistoryAndReenableResumesSameIncarnation(): void
	{
		$this->seed();
		$this->assertSame(12, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_A'"));
		$GLOBALS['pfb']['alias_dnsbl_all'] = ['DNSBL_B'];
		$GLOBALS['pfb']['dnsbl_info_stats'][0]['entries'] = 'disabled';

		dnsbl_save_stats();

		$this->assertSame(12, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_A'"));
		$this->assertSame('disabled', $this->value("SELECT entries FROM dnsbl WHERE groupname = 'DNSBL_A'"));
		$this->assertSame(3, $this->value("SELECT count FROM dns_metric_blocks WHERE groupname = 'DNSBL_A'"));
		$this->assertSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $this->epoch('DNSBL_A'));
		$GLOBALS['pfb']['alias_dnsbl_all'][] = 'DNSBL_A';
		$GLOBALS['pfb']['dnsbl_info_stats'][0]['entries'] = 6;
		dnsbl_save_stats();
		$this->sql(["UPDATE dnsbl SET counter = counter + 1 WHERE groupname = 'DNSBL_A'", "UPDATE dns_metric_blocks SET count = count + 1 WHERE groupname = 'DNSBL_A'"]);
		$this->assertSame(13, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_A'"));
		$this->assertSame(4, $this->value("SELECT count FROM dns_metric_blocks WHERE groupname = 'DNSBL_A'"));
		$this->assertSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $this->epoch('DNSBL_A'));
		$this->assertBPreserved();
	}

	public function testDeleteRemovesAllHistoryAndRecreateStartsFresh(): void
	{
		$this->seed();
		$this->assertSame(12, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_A'"));
		$GLOBALS['pfb']['alias_dnsbl_configured'] = ['DNSBL_B'];
		$GLOBALS['pfb']['alias_dnsbl_all'] = ['DNSBL_B'];
		// Stale in-memory stats are not authority to preserve a deleted group.
		dnsbl_save_stats();

		$this->assertSame(0, $this->value("SELECT count(*) FROM dnsbl WHERE groupname = 'DNSBL_A'"));
		$this->assertSame(0, $this->value("SELECT count(*) FROM dns_metric_blocks WHERE groupname = 'DNSBL_A'"));
		$this->assertNull($this->epoch('DNSBL_A'));
		$this->assertBPreserved();
		$GLOBALS['pfb']['alias_dnsbl_configured'][] = 'DNSBL_A';
		$GLOBALS['pfb']['alias_dnsbl_all'][] = 'DNSBL_A';
		dnsbl_save_stats();
		$this->assertSame(0, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_A'"), 'no legacy aggregate residual may resurrect');
		$this->assertSame(0, $this->value("SELECT count(*) FROM dns_metric_blocks WHERE groupname = 'DNSBL_A'"));
		$this->assertNotNull($this->epoch('DNSBL_A'));
		$this->assertNotSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $this->epoch('DNSBL_A'));
		$this->assertBPreserved();
	}

	public static function unavailableMembership(): array
	{
		return ['null' => [FALSE], 'absent' => [TRUE]];
	}

	#[DataProvider('unavailableMembership')]
	public function testUnavailableMembershipCannotProveDeletion(bool $absent): void
	{
		$this->seed();
		$GLOBALS['pfb']['alias_dnsbl_configured'] = NULL;
		if ($absent) {
			unset($GLOBALS['pfb']['alias_dnsbl_configured']);
		}
		$GLOBALS['pfb']['alias_dnsbl_all'] = [];
		$GLOBALS['pfb']['dnsbl_info_stats'] = [];

		dnsbl_save_stats();

		$this->assertSame(1, $this->value("SELECT count(*) FROM sqlite_master WHERE name = 'dnsbl'"), 'unavailable config must not DROP the aggregate table');
		$this->assertSame(12, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_A'"));
		$this->assertSame(3, $this->value("SELECT count FROM dns_metric_blocks WHERE groupname = 'DNSBL_A'"));
		$this->assertSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $this->epoch('DNSBL_A'));
		$this->assertBPreserved();
	}

	public function testEmptyConfiguredMembershipDeletesFeedsButRetainsSyntheticHistory(): void
	{
		$this->seed();
		$synthetic = ['Upstream', 'DNSBL_IDN', 'DNSBL_Homoglyph', 'DNSBL_Homoglyph_Suspect', 'DNSBL_TLD_Allow', 'DNSBL_Regex', 'DNSBL_TLD'];
		foreach ($synthetic as $group) {
			$this->sql([
				"INSERT INTO dnsbl VALUES ('{$group}', 'old', 2, 8)",
				"INSERT INTO dns_metric_blocks (owner,origin,groupname,qtype,transport,count) VALUES ('{$group}', 'builtin', '{$group}', 'MX', '', 2)",
				"INSERT INTO dnsbl_group_epochs VALUES ('{$group}', 'builtin', 'cccccccccccccccccccccccccccccccc')",
			]);
		}
		$this->assertSame(9, $this->value('SELECT count(*) FROM dnsbl'));
		$GLOBALS['pfb']['alias_dnsbl_configured'] = [];
		$GLOBALS['pfb']['alias_dnsbl_all'] = [];
		$GLOBALS['pfb']['dnsbl_info_stats'] = [];

		dnsbl_save_stats();

		$this->assertSame(1, $this->value("SELECT count(*) FROM sqlite_master WHERE name = 'dnsbl'"));
		$this->assertSame(0, $this->value("SELECT count(*) FROM dnsbl WHERE groupname IN ('DNSBL_A', 'DNSBL_B')"));
		foreach ($synthetic as $group) {
			$this->assertSame(8, $this->value("SELECT counter FROM dnsbl WHERE groupname = '{$group}'"), $group);
			$this->assertSame(2, $this->value("SELECT count FROM dns_metric_blocks WHERE groupname = '{$group}'"), $group);
			$this->assertSame('cccccccccccccccccccccccccccccccc', $this->value("SELECT epoch FROM dnsbl_group_epochs WHERE owner='{$group}' AND origin='builtin'"), $group);
		}
	}

	public function testDeleteFailureRollsBackAggregateDetailsAndEpoch(): void
	{
		$this->seed();
		$this->sql(["CREATE TRIGGER refuse_epoch_delete BEFORE DELETE ON dnsbl_group_epochs WHEN OLD.owner = 'DNSBL_A' BEGIN SELECT RAISE(ABORT, 'refuse epoch deletion'); END"]);
		$GLOBALS['pfb']['alias_dnsbl_configured'] = ['DNSBL_B'];
		$GLOBALS['pfb']['alias_dnsbl_all'] = ['DNSBL_B'];
		$GLOBALS['pfb']['dnsbl_info_stats'][1]['entries'] = 99;

		$result = dnsbl_save_stats();

		$this->assertSame(12, $this->value("SELECT counter FROM dnsbl WHERE groupname = 'DNSBL_A'"), 'failed deletion must roll back the aggregate');
		$this->assertSame(3, $this->value("SELECT count FROM dns_metric_blocks WHERE groupname = 'DNSBL_A'"));
		$this->assertSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $this->epoch('DNSBL_A'));
		$this->assertSame(7, (int) $this->value("SELECT entries FROM dnsbl WHERE groupname = 'DNSBL_B'"), 'unrelated metadata update must roll back too');
		$this->assertBPreserved();
		$this->assertFalse($result, 'SQLite ABORT must be returned as failure');
	}

	private function seedResolver(): void
	{
		$this->sql([
			'CREATE TABLE resolver (row INTEGER, totalqueries INTEGER, queries INTEGER)',
			'INSERT INTO resolver VALUES (0, 20, 5)',
			'CREATE TABLE lastclear (row INTEGER, lastipclear TEXT, lastdnsblclear TEXT)',
			"INSERT INTO lastclear VALUES (0, 'old', 'old')",
			'CREATE TABLE dns_metric_queries (qtype TEXT, transport TEXT, listener_ip TEXT, listener_interface TEXT, client_ip TEXT, count INTEGER)',
			"INSERT INTO dns_metric_queries VALUES ('A', 'UDP', '192.0.2.1', 'LAN', '198.51.100.1', 3)",
		], TRUE);
	}

	public function testRolloverRetainsDimensionsAndExplicitClearResetsBothKinds(): void
	{
		$this->seed();
		$this->seedResolver();
		pfBlockerNG_clearsqlite('update_totalqueries', 25);
		$this->assertSame(25, $this->value('SELECT totalqueries + queries FROM resolver', TRUE));
		$this->assertSame(3, $this->value('SELECT count FROM dns_metric_queries', TRUE));
		$this->assertSame(21, $this->value('SELECT sum(counter) FROM dnsbl'));
		$this->assertSame(7, $this->value('SELECT sum(count) FROM dns_metric_blocks'));

		pfBlockerNG_clearsqlite('cleardnsbl');

		$this->assertSame(0, $this->value('SELECT sum(counter) FROM dnsbl'));
		$this->assertSame(0, $this->value('SELECT count(*) FROM dns_metric_blocks'));
		$this->assertSame(0, $this->value('SELECT totalqueries + queries FROM resolver', TRUE));
		$this->assertSame(0, $this->value('SELECT count(*) FROM dns_metric_queries', TRUE));
		$this->assertSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $this->epoch('DNSBL_A'));
	}

	public function testClearFailureCannotResetAggregateWithoutDetails(): void
	{
		$this->seed();
		$this->seedResolver();
		$this->sql(["CREATE TRIGGER refuse_detail_clear BEFORE DELETE ON dns_metric_blocks BEGIN SELECT RAISE(ABORT, 'refuse detail clear'); END"]);

		pfBlockerNG_clearsqlite('cleardnsbl');

		$this->assertSame(21, $this->value('SELECT sum(counter) FROM dnsbl'), 'detail clear failure must roll back its aggregate reset');
		$this->assertSame(7, $this->value('SELECT sum(count) FROM dns_metric_blocks'));
	}
}
