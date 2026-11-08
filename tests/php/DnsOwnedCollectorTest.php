<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DnsOwnedCollectorTest extends TestCase
{
	private array $prior;
	private string $root;
	protected function setUp(): void
	{
		$this->prior = $GLOBALS['pfb'];
		$this->root = sys_get_temp_dir() . '/pfb_owned_collect_' . bin2hex(random_bytes(8));
		mkdir($this->root);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'], ['dnsbl'=>PfbToggle::On,'dnsbl_info'=>"$this->root/info",'dnsbl_resolver'=>"$this->root/resolver",'dnsbldir'=>$this->root,'dbdir'=>$this->root,'schedule_state_dir'=>$this->root]);
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('CREATE TABLE dnsbl(groupname TEXT,entries INTEGER,counter INTEGER)');
		$db->exec("INSERT INTO dnsbl VALUES ('DNSBL_Regex',2,15)");
		$db->exec('CREATE TABLE dnsbl_group_epochs(owner TEXT,origin TEXT,epoch TEXT,PRIMARY KEY(owner,origin))');
		$db->exec("INSERT INTO dnsbl_group_epochs VALUES ('DNSBL_A','custom','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),('DNSBL_B','custom','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),('DNSBL_Regex','builtin','cccccccccccccccccccccccccccccccc')");
		$db->exec('CREATE TABLE dns_metric_totals(owner TEXT,origin TEXT,groupname TEXT,count INTEGER,PRIMARY KEY(owner,origin,groupname))');
		$db->exec("INSERT INTO dns_metric_totals VALUES ('DNSBL_A','custom','DNSBL_Regex',3),('DNSBL_B','custom','DNSBL_Regex',3),('DNSBL_Regex','builtin','DNSBL_Regex',4)");
		$db->exec('CREATE TABLE dns_metric_blocks(owner TEXT,origin TEXT,groupname TEXT,qtype TEXT,transport TEXT,count INTEGER,PRIMARY KEY(owner,origin,groupname,qtype,transport))');
		$db->exec("INSERT INTO dns_metric_blocks VALUES ('DNSBL_A','custom','DNSBL_Regex','A','UDP',2),('DNSBL_B','custom','DNSBL_Regex','A','UDP',3),('DNSBL_Regex','builtin','DNSBL_Regex','AAAA','',4)");
		$db->close();
	}
	protected function tearDown(): void { $GLOBALS['pfb']=$this->prior; rmdir_recursive($this->root); }
	public function testCollectorReadsOwnedTotalsAndDetails(): void
	{
		$s = pfb_metrics_collect();
		$this->assertTrue($s['source_up']['dnsbl_db']);
		$this->assertSame(10, array_sum(array_column($s['dnsbl_totals'], 'count')));
		$this->assertSame(9, array_sum(array_column($s['dnsbl_detail'], 'count')));
		$this->assertSame(15, $s['dnsbl_groups'][0]['counter']);
	}
	public static function corruptions(): array
	{
		return [
			'negative total'=>["UPDATE dns_metric_totals SET count=-1 WHERE owner='DNSBL_A'"],
			'total exceeds aggregate'=>["UPDATE dns_metric_totals SET count=30 WHERE owner='DNSBL_A'"],
			'detail exceeds owned'=>["UPDATE dns_metric_blocks SET count=4 WHERE owner='DNSBL_A'"],
			'orphan total owner'=>["DELETE FROM dnsbl_group_epochs WHERE owner='DNSBL_A'"],
			'orphan detail'=>["DELETE FROM dns_metric_totals WHERE owner='DNSBL_A'"],
			'invalid origin'=>["UPDATE dns_metric_totals SET origin='other' WHERE owner='DNSBL_A'"],
			'negative detail'=>["UPDATE dns_metric_blocks SET count=-1 WHERE owner='DNSBL_A'"],
			'malformed owner token'=>["UPDATE dnsbl_group_epochs SET epoch='bad' WHERE owner='DNSBL_A'"],
			'null owner token'=>["UPDATE dnsbl_group_epochs SET epoch=NULL WHERE owner='DNSBL_A'"],
			'empty owner metadata'=>["INSERT INTO dnsbl_group_epochs VALUES ('','custom','dddddddddddddddddddddddddddddddd')"],
			'null owner metadata'=>["INSERT INTO dnsbl_group_epochs VALUES (NULL,'custom','dddddddddddddddddddddddddddddddd')"],
			'invalid owner origin'=>["INSERT INTO dnsbl_group_epochs VALUES ('DNSBL_Unused','other','dddddddddddddddddddddddddddddddd')"],
			'duplicate owner metadata'=>["CREATE TABLE owner_copy AS SELECT * FROM dnsbl_group_epochs; DROP TABLE dnsbl_group_epochs; ALTER TABLE owner_copy RENAME TO dnsbl_group_epochs; INSERT INTO dnsbl_group_epochs SELECT * FROM dnsbl_group_epochs WHERE owner='DNSBL_A'"],
			'duplicate owned total'=>["CREATE TABLE total_copy AS SELECT * FROM dns_metric_totals; DROP TABLE dns_metric_totals; ALTER TABLE total_copy RENAME TO dns_metric_totals; INSERT INTO dns_metric_totals SELECT * FROM dns_metric_totals WHERE owner='DNSBL_A'"],
			'duplicate zero-count detail'=>["CREATE TABLE detail_copy AS SELECT * FROM dns_metric_blocks; DROP TABLE dns_metric_blocks; ALTER TABLE detail_copy RENAME TO dns_metric_blocks; INSERT INTO dns_metric_blocks SELECT owner,origin,groupname,qtype,transport,0 FROM dns_metric_blocks WHERE owner='DNSBL_A'"],
		];
	}
	#[DataProvider('corruptions')]
	public function testCorruptionDropsOnlyDnsblSource(string $sql): void
	{
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_info']); $this->assertTrue($db->exec($sql)); $db->close();
		$s=pfb_metrics_collect();
		$this->assertFalse($s['source_up']['dnsbl_db']);
		$this->assertNull($s['dnsbl_groups']);
		$this->assertNull($s['dnsbl_detail']);
	}
}
