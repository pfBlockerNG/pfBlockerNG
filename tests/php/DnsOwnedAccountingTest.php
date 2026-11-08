<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DnsOwnedAccountingTest extends TestCase
{
	private array $prior;
	private string $root;
	protected function setUp(): void
	{
		$this->prior = $GLOBALS['pfb'];
		$this->root = sys_get_temp_dir() . '/pfb_owned_' . bin2hex(random_bytes(8));
		mkdir($this->root, 0700);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'], ['dnsbl_info' => "$this->root/d.sqlite", 'log' => "$this->root/log", 'errlog' => "$this->root/err", 'alias_dnsbl_configured' => [], 'alias_dnsbl_all' => [], 'dnsbl_info_stats' => []]);
		$GLOBALS['pfb']['sqlite_timeout'] = 2000;
	}
	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->prior;
		rmdir_recursive($this->root);
	}
	private function db(): SQLite3 { return new SQLite3($GLOBALS['pfb']['dnsbl_info']); }
	public static function collisionNames(): array
	{
		return array_map(static fn ($n) => [$n], ['DNSBL_IDN', 'DNSBL_Homoglyph', 'DNSBL_Homoglyph_Suspect', 'DNSBL_TLD_Allow', 'DNSBL_Regex', 'DNSBL_TLD']);
	}
	#[DataProvider('collisionNames')]
	public function testDeleteOnlyOwnedNewCountsAndReaddFresh(string $name): void
	{
		$db = $this->db();
		$db->exec('CREATE TABLE dnsbl(groupname TEXT,timestamp TEXT,entries INTEGER,counter INTEGER)');
		$db->exec("INSERT INTO dnsbl VALUES ('$name','old',2,15)");
		$db->exec('CREATE TABLE dnsbl_group_epochs(owner TEXT,origin TEXT,epoch TEXT NOT NULL,PRIMARY KEY(owner,origin))');
		$db->exec('CREATE TABLE dns_metric_totals(owner TEXT,origin TEXT,groupname TEXT,count INTEGER,PRIMARY KEY(owner,origin,groupname))');
		$db->exec('CREATE TABLE dns_metric_blocks(owner TEXT,origin TEXT,groupname TEXT,qtype TEXT,transport TEXT,count INTEGER,PRIMARY KEY(owner,origin,groupname,qtype,transport))');
		$db->exec("INSERT INTO dnsbl_group_epochs VALUES ('$name','custom','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),('$name','builtin','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),('DNSBL_Other','custom','cccccccccccccccccccccccccccccccc')");
		$db->exec("INSERT INTO dns_metric_totals VALUES ('$name','custom','$name',3),('$name','builtin','$name',4),('DNSBL_Other','custom','$name',3)");
		$db->exec("INSERT INTO dns_metric_blocks SELECT owner,origin,groupname,'A','UDP',count FROM dns_metric_totals");
		$GLOBALS['pfb']['alias_dnsbl_configured'] = [$name, 'DNSBL_Other'];
		$this->assertSame(15, $db->querySingle("SELECT counter FROM dnsbl WHERE groupname='$name'"));
		$saved = dnsbl_save_stats();
		$this->assertSame(15, $db->querySingle("SELECT counter FROM dnsbl WHERE groupname='$name'"), 'disabled owners keep their complete history');
		$this->assertTrue($saved, 'owner schema must be supported');
		$this->assertSame(10, $db->querySingle('SELECT sum(count) FROM dns_metric_totals'), 'legacy five never becomes owned');
		$this->assertSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $db->querySingle("SELECT epoch FROM dnsbl_group_epochs WHERE owner='$name' AND origin='custom'"));
		$GLOBALS['pfb']['alias_dnsbl_configured'] = ['DNSBL_Other'];
		$this->assertTrue(dnsbl_save_stats());
		$this->assertSame(12, $db->querySingle("SELECT counter FROM dnsbl WHERE groupname='$name' ORDER BY rowid LIMIT 1"));
		$this->assertSame(7, $db->querySingle('SELECT sum(count) FROM dns_metric_totals'));
		$this->assertSame(0, $db->querySingle("SELECT count(*) FROM dns_metric_blocks WHERE owner='$name' AND origin='custom'"));
		$this->assertSame('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', $db->querySingle("SELECT epoch FROM dnsbl_group_epochs WHERE owner='$name' AND origin='builtin'"));
		$GLOBALS['pfb']['alias_dnsbl_configured'][] = $name;
		$this->assertTrue(dnsbl_save_stats());
		$this->assertNotSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $db->querySingle("SELECT epoch FROM dnsbl_group_epochs WHERE owner='$name' AND origin='custom'"));
		$this->assertSame(12, $db->querySingle("SELECT counter FROM dnsbl WHERE groupname='$name' ORDER BY rowid LIMIT 1"));
		$db->close();
	}
	public function testRenderCoalescesOwnersWithoutLosingLegacyOrUntypedCounts(): void
	{
		$out = pfb_metrics_render(['version'=>'x','ip_tables'=>NULL,'ip_rule_packets'=>NULL,'dnsbl_groups'=>[['group'=>'DNSBL_Regex','entries'=>2,'counter'=>15]], 'dnsbl_totals'=>[['owner'=>'DNSBL_A','origin'=>'custom','group'=>'DNSBL_Regex','count'=>3],['owner'=>'DNSBL_B','origin'=>'custom','group'=>'DNSBL_Regex','count'=>3],['owner'=>'DNSBL_Regex','origin'=>'builtin','group'=>'DNSBL_Regex','count'=>4]], 'dnsbl_detail'=>[['owner'=>'DNSBL_A','origin'=>'custom','group'=>'DNSBL_Regex','qtype'=>'A','transport'=>'UDP','count'=>2],['owner'=>'DNSBL_B','origin'=>'custom','group'=>'DNSBL_Regex','qtype'=>'A','transport'=>'UDP','count'=>3],['owner'=>'DNSBL_Regex','origin'=>'builtin','group'=>'DNSBL_Regex','qtype'=>'AAAA','transport'=>'','count'=>4]], 'resolver_queries'=>NULL,'feed_success'=>NULL,'feed_failing'=>[],'pass'=>NULL,'source_up'=>[]]);
		$prefix = 'pfblockerng_dnsbl_blocked_queries_total';
		$this->assertStringContainsString($prefix . '{group="DNSBL_Regex"} 5', $out);
		$this->assertStringContainsString($prefix . '{group="DNSBL_Regex",origin="custom"} 1', $out);
		$this->assertStringContainsString($prefix . '{group="DNSBL_Regex",origin="custom",qtype="A",transport="UDP"} 5', $out);
		$this->assertStringContainsString($prefix . '{group="DNSBL_Regex",origin="builtin",qtype="AAAA"} 4', $out);
		preg_match_all('/^' . $prefix . '(\{[^\n]+\}) (\d+)$/m', $out, $rows);
		$this->assertSame(15, array_sum(array_map('intval', $rows[2])));
		$this->assertCount(count(array_unique($rows[1])), $rows[1]);
		$this->assertStringNotContainsString('owner=', $out);
	}
}
