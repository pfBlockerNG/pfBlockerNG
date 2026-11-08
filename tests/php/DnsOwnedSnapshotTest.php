<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsOwnedSnapshotTest extends TestCase
{
	private array $prior;
	private string $root;
	protected function setUp(): void
	{
		$this->prior=$GLOBALS['pfb']; $this->root=sys_get_temp_dir().'/pfb_owned_snapshot_'.bin2hex(random_bytes(8)); mkdir($this->root);
		$GLOBALS['pfb']=array_merge($GLOBALS['pfb'],['dnsbl_info'=>"$this->root/info",'log'=>"$this->root/log",'errlog'=>"$this->root/err",'sqlite_timeout'=>2000,'alias_dnsbl_configured'=>['DNSBL_A','DNSBL_B'],'alias_dnsbl_all'=>[],'dnsbl_info_stats'=>[]]);
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_info']); $db->exec('PRAGMA journal_mode=WAL');
		$db->exec('CREATE TABLE dnsbl(groupname TEXT,timestamp TEXT,entries INTEGER,counter INTEGER)');
		$db->exec("INSERT INTO dnsbl VALUES ('DNSBL_Regex','old',2,15),('DNSBL_A','old',2,9)");
		$db->exec('CREATE TABLE dnsbl_group_epochs(owner TEXT,origin TEXT,epoch TEXT,PRIMARY KEY(owner,origin))');
		$db->exec("INSERT INTO dnsbl_group_epochs VALUES ('DNSBL_A','custom','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),('DNSBL_B','custom','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),('DNSBL_Regex','builtin','cccccccccccccccccccccccccccccccc')");
		$db->exec('CREATE TABLE dns_metric_totals(owner TEXT,origin TEXT,groupname TEXT,count INTEGER,PRIMARY KEY(owner,origin,groupname))');
		$db->exec("INSERT INTO dns_metric_totals VALUES ('DNSBL_A','custom','DNSBL_Regex',3),('DNSBL_B','custom','DNSBL_Regex',3),('DNSBL_Regex','builtin','DNSBL_Regex',4),('DNSBL_A','custom','DNSBL_A',2)");
		$db->exec('CREATE TABLE dns_metric_blocks(owner TEXT,origin TEXT,groupname TEXT,qtype TEXT,transport TEXT,count INTEGER)');
		$db->exec("INSERT INTO dns_metric_blocks SELECT owner,origin,groupname,'A','UDP',count FROM dns_metric_totals"); $db->close();
	}
	protected function tearDown(): void { $GLOBALS['pfb']=$this->prior; rmdir_recursive($this->root); }
	public function testDeleteSubtractsEveryOwnedDisplayButKeepsSharedHistory(): void
	{
		$GLOBALS['pfb']['alias_dnsbl_configured']=['DNSBL_B'];
		$this->assertTrue(dnsbl_save_stats());
		$db=new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$this->assertSame(12,$db->querySingle("SELECT counter FROM dnsbl WHERE groupname='DNSBL_Regex'"));
		$this->assertSame(0,$db->querySingle("SELECT count(*) FROM dnsbl WHERE groupname='DNSBL_A'"));
		$this->assertSame(7,$db->querySingle('SELECT sum(count) FROM dns_metric_totals'));
		$this->assertSame(7,$db->querySingle('SELECT sum(count) FROM dns_metric_blocks'));
		$this->assertSame(0,$db->querySingle("SELECT count(*) FROM dnsbl_group_epochs WHERE owner='DNSBL_A'")); $db->close();
	}
	public function testAllThreeAccountingSetsShareReadonlyWalSnapshot(): void
	{
		$factory=static function(string $path): SQLite3 {
			return new class($path,SQLITE3_OPEN_READONLY) extends SQLite3 {
				public function __construct(private string $path,int $flags) { parent::__construct($path,$flags); }
				public function query(string $query): SQLite3Result|false {
					if ($query==='SELECT * FROM dns_metric_blocks') {
						$writer=new SQLite3($this->path); $writer->enableExceptions(TRUE);
						$writer->exec("BEGIN IMMEDIATE; UPDATE dnsbl SET counter=counter+1 WHERE groupname='DNSBL_Regex'; UPDATE dns_metric_totals SET count=count+1 WHERE owner='DNSBL_B'; UPDATE dns_metric_blocks SET count=count+1 WHERE owner='DNSBL_B'; COMMIT;"); $writer->close();
					}
					return parent::query($query);
				}
			};
		};
		$path=$GLOBALS['pfb']['dnsbl_info'];
		$s=pfb_metrics_sqlite_snapshot($path,'SELECT * FROM dnsbl','dns_metric_blocks','SELECT * FROM dns_metric_blocks',$factory,TRUE);
		$this->assertSame(24,array_sum(array_column($s['aggregate'],'counter')));
		$this->assertSame(12,array_sum(array_column($s['totals'],'count')));
		$this->assertSame(12,array_sum(array_column($s['detail'],'count')));
		$db=new SQLite3($path); $this->assertSame(25,$db->querySingle('SELECT sum(counter) FROM dnsbl')); $this->assertSame(13,$db->querySingle('SELECT sum(count) FROM dns_metric_totals')); $this->assertSame(13,$db->querySingle('SELECT sum(count) FROM dns_metric_blocks')); $db->close();
	}
}
