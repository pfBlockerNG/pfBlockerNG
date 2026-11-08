<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_log_event')]
final class DnsblLogEventEpochTest extends TestCase
{
	private string $tmp;
	private array $prior;
	private array $children = [];

	protected function setUp(): void
	{
		$this->prior = $GLOBALS['pfb'];
		$this->tmp = sys_get_temp_dir() . '/pfb_epoch_' . uniqid();
		mkdir($this->tmp);
		$GLOBALS['pfb'] = array_merge($this->prior, [
			'dnsbldir' => $this->tmp, 'dnsbl_info' => "{$this->tmp}/info.sqlite",
			'dnsbl_resolver' => "{$this->tmp}/resolver.sqlite", 'dnslog' => "{$this->tmp}/dns.log",
			'log' => "{$this->tmp}/pfb.log", 'errlog' => "{$this->tmp}/error.log", 'sqlite_timeout' => 2000,
			'alias_dnsbl_configured' => ['DNSBL_A', 'DNSBL_B'], 'alias_dnsbl_all' => ['DNSBL_A', 'DNSBL_B'],
			'dnsbl_info_stats' => [
				['groupname' => 'DNSBL_A', 'timestamp' => 'old', 'entries' => 1],
				['groupname' => 'DNSBL_B', 'timestamp' => 'old', 'entries' => 1],
			],
		]);
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER)');
		$db->exec("INSERT INTO dnsbl VALUES ('DNSBL_A','old',1,12),('DNSBL_B','old',1,9)");
		$db->exec('CREATE TABLE dnsbl_group_epochs (owner TEXT, origin TEXT, epoch TEXT NOT NULL, PRIMARY KEY(owner,origin))');
		$db->exec("INSERT INTO dnsbl_group_epochs VALUES ('DNSBL_A','custom','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),('DNSBL_B','custom','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')");
		$db->exec('CREATE TABLE dns_metric_totals(owner TEXT,origin TEXT,groupname TEXT,count INTEGER,PRIMARY KEY(owner,origin,groupname))');
		$db->close();
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_resolver']);
		$db->exec('CREATE TABLE lastevent (row INTEGER, groupname TEXT, entry TEXT, details TEXT)');
		$db->exec("INSERT INTO lastevent VALUES (0,'other','other','other')");
		$db->close();
	}

	protected function tearDown(): void
	{
		foreach ($this->children as $pid) {
			posix_kill($pid, SIGKILL);
			pcntl_waitpid($pid, $status);
		}
		$GLOBALS['pfb'] = $this->prior;
		rmdir_recursive($this->tmp);
	}

	private function value(string $sql): mixed
	{
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$value = $db->querySingle($sql);
		$db->close();
		return $value;
	}

	private function respond(bool $replace): void
	{
		$pid = pcntl_fork();
		$this->assertNotSame(-1, $pid);
		if ($pid === 0) {
			$deadline = microtime(true) + 5;
			do {
				$request = json_decode((string) @file_get_contents("{$this->tmp}/pfb_py_query"), true);
				if (isset($request['id'])) {
					$epoch = $this->value("SELECT epoch FROM dnsbl_group_epochs WHERE owner='DNSBL_A' AND origin='custom'");
					if ($replace) {
						$GLOBALS['pfb']['alias_dnsbl_configured'] = ['DNSBL_B'];
						if (!dnsbl_save_stats()) { exit(2); }
						$GLOBALS['pfb']['alias_dnsbl_configured'][] = 'DNSBL_A';
						if (!dnsbl_save_stats()) { exit(3); }
					}
					file_put_contents("{$this->tmp}/pfb_py_query.reply", json_encode([
						'id' => $request['id'], 'blocked' => true, 'b_type' => 'DNSBL', 'group' => 'DNSBL_A',
						'group_epoch' => $epoch, 'b_eval' => 'blocked.example', 'feed' => 'feed', 'p_type' => 'Python',
						'group_owner' => 'DNSBL_A', 'group_origin' => 'custom',
					]));
					exit(0);
				}
				usleep(10000);
			} while (microtime(true) < $deadline);
			exit(4);
		}
		$this->children[] = $pid;
	}

	private function logEvent(): void
	{
		set_error_handler(static function (int $errno, string $message): bool {
			return str_contains($message, 'Unable to find uid for unbound') || str_contains($message, 'Unable to find gid for unbound');
		});
		try {
			pfb_log_event('DNSBL-HTTPS', 'blocked.example', '203.0.113.10', 'browser');
		} finally {
			restore_error_handler();
		}
		$pid = array_shift($this->children);
		pcntl_waitpid($pid, $status);
		$this->assertTrue(pcntl_wifexited($status));
		$this->assertSame(0, pcntl_wexitstatus($status), 'responder must observe a real live query');
	}

	public function testLateVerdictCannotIncrementRecreatedGroupAndDuplicateUsesLiveEpoch(): void
	{
		$this->respond(true);
		$this->logEvent();
		$this->assertSame(0, $this->value("SELECT counter FROM dnsbl WHERE groupname='DNSBL_A'"), 'stale verdict cannot increment recreated group');
		$this->assertNotSame('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', $this->value("SELECT epoch FROM dnsbl_group_epochs WHERE owner='DNSBL_A' AND origin='custom'"));
		$this->respond(false);
		$this->logEvent();
		$this->assertSame(1, $this->value("SELECT counter FROM dnsbl WHERE groupname='DNSBL_A'"), 'matching live epoch increments even for duplicate log');
		$this->assertSame(1, $this->value("SELECT count FROM dns_metric_totals WHERE owner='DNSBL_A' AND origin='custom'"));
		$this->assertSame(9, $this->value("SELECT counter FROM dnsbl WHERE groupname='DNSBL_B'"));
		$this->assertSame('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', $this->value("SELECT epoch FROM dnsbl_group_epochs WHERE owner='DNSBL_B' AND origin='custom'"));
		$logs = file($GLOBALS['pfb']['dnslog']);
		$this->assertCount(2, $logs);
		$this->assertStringEndsWith(",+\n", $logs[0]);
		$this->assertStringEndsWith(",-\n", $logs[1]);
	}
}
