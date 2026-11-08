<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsOwnedClearTest extends TestCase
{
	private array $prior;
	private string $root;
	protected function setUp(): void
	{
		$this->prior=$GLOBALS['pfb']; $this->root=sys_get_temp_dir().'/pfb_owned_clear_'.bin2hex(random_bytes(8)); mkdir($this->root);
		$GLOBALS['pfb']=array_merge($GLOBALS['pfb'],['dnsbl_info'=>"$this->root/info",'dnsbl_resolver'=>"$this->root/resolver",'sqlite_timeout'=>2000,'log'=>"$this->root/log",'errlog'=>"$this->root/error"]);
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('CREATE TABLE dnsbl(groupname TEXT,timestamp TEXT,entries INTEGER,counter INTEGER)'); $db->exec("INSERT INTO dnsbl VALUES ('DNSBL_A','old',1,12)");
		$db->exec('CREATE TABLE dnsbl_group_epochs(owner TEXT,origin TEXT,epoch TEXT)'); $db->exec("INSERT INTO dnsbl_group_epochs VALUES ('DNSBL_A','custom','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')");
		$db->exec('CREATE TABLE dns_metric_totals(owner TEXT,origin TEXT,groupname TEXT,count INTEGER)'); $db->exec("INSERT INTO dns_metric_totals VALUES ('DNSBL_A','custom','DNSBL_A',3)");
		$db->exec('CREATE TABLE dns_metric_blocks(owner TEXT,origin TEXT,groupname TEXT,qtype TEXT,transport TEXT,count INTEGER)'); $db->exec("INSERT INTO dns_metric_blocks VALUES ('DNSBL_A','custom','DNSBL_A','A','UDP',2)"); $db->close();
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_resolver']); $db->exec('CREATE TABLE resolver(row INTEGER,totalqueries INTEGER,queries INTEGER)'); $db->exec('INSERT INTO resolver VALUES(0,20,5)'); $db->exec('CREATE TABLE lastclear(row INTEGER,lastipclear TEXT,lastdnsblclear TEXT)'); $db->exec("INSERT INTO lastclear VALUES(0,'old','old')"); $db->close();
	}
	protected function tearDown(): void { $GLOBALS['pfb']=$this->prior; rmdir_recursive($this->root); }
	public function testClearResetsAllThreeSetsAndKeepsTokenWithLegacyResolver(): void
	{
		pfBlockerNG_clearsqlite('cleardnsbl');
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$this->assertSame(0,$db->querySingle('SELECT counter FROM dnsbl'));
		$this->assertSame(0,$db->querySingle('SELECT count(*) FROM dns_metric_totals'));
		$this->assertSame(0,$db->querySingle('SELECT count(*) FROM dns_metric_blocks'));
		$this->assertSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',$db->querySingle('SELECT epoch FROM dnsbl_group_epochs')); $db->close();
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_resolver']); $this->assertSame(0,$db->querySingle('SELECT totalqueries+queries FROM resolver')); $db->close();
	}
	public function testPreupgradeClearWithoutAnyOwnedTables(): void
	{
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('DROP TABLE dns_metric_blocks'); $db->exec('DROP TABLE dns_metric_totals');
		pfBlockerNG_clearsqlite('cleardnsbl');
		$this->assertSame(0,$db->querySingle('SELECT counter FROM dnsbl'));
		$this->assertSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',$db->querySingle('SELECT epoch FROM dnsbl_group_epochs'));
		$db->close();
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_resolver']); $this->assertSame(0,$db->querySingle('SELECT totalqueries+queries FROM resolver')); $db->close();
	}

	public function testRealTotalDeleteAbortRollsBackDetailsAndAggregate(): void
	{
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_info']); $db->exec("CREATE TRIGGER refuse BEFORE DELETE ON dns_metric_totals BEGIN SELECT RAISE(ABORT,'refuse'); END");
		$cleared = pfBlockerNG_clearsqlite('cleardnsbl');
		$this->assertSame(12,$db->querySingle('SELECT counter FROM dnsbl'));
		$this->assertFalse($cleared);
		$this->assertSame(3,$db->querySingle('SELECT count FROM dns_metric_totals'));
		$this->assertSame(2,$db->querySingle('SELECT count FROM dns_metric_blocks')); $db->close();
	}
}
