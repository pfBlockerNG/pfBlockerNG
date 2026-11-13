<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3913: General asks Core's dry run before the client-IP metrics privacy change: a refused save leaves the stored client
 * identities alone.
 */
#[CoversFunction('pfb_core_settings_validate')]
final class CoreSettingsGeneralSaveOrderTest extends TestCase
{
	private string $dir;
	private ?array $standIn = NULL;
	private array $priorConfig;
	private array $priorPfb;
	private array $priorPost;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->priorPost = $_POST;
		$this->dir = sys_get_temp_dir() . '/pfb_core_order_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['core_socket'] = "{$this->dir}/api.sock";
		$GLOBALS['pfb']['core_settings_failed'] = "{$this->dir}/core_settings_failed";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['dnsbl_info'] = "{$this->dir}/dnsbl_info.sqlite";
		$GLOBALS['pfb']['dnsbl_resolver'] = "{$this->dir}/dnsbl_resolver.sqlite";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
	}

	protected function tearDown(): void
	{
		if ($this->standIn !== NULL) {
			[$process, $pipes] = $this->standIn;
			proc_terminate($process);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		}
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		$_POST = $this->priorPost;
		unset($GLOBALS['pfb_test_write_config_calls']);
		rmdir_recursive($this->dir);
	}

	public function testACoreRefusedGeneralSaveLeavesTheStoredClientIdentities(): void
	{
		// Given: client-IP metrics are on, with a client identity stored
		config_set_path(PFB_SECTIONS['gen'] . '/pfb_metrics_client_ip', 'on');
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('CREATE TABLE dns_metric_blocks (client_ip TEXT, domain TEXT, count INTEGER)');
		$db->exec("INSERT INTO dns_metric_blocks VALUES ('192.0.2.7', 'example.com', 1)");
		$db->close();
		$this->standIn = pfb_test_start_process([PHP_BINARY, __DIR__ . '/support/CoreSettingsStandIn.php', "{$this->dir}/api.sock", "{$this->dir}/requests",
			json_encode(['ValidateSettings' => [400, ['error' => ['code' => 'invalid_argument', 'message' => 'refused',
				'fieldErrors' => [['field' => 'changes.dns.metricsClientIp', 'message' => 'refused by the stand-in']]]]]], JSON_THROW_ON_ERROR)]);
		$deadline = hrtime(TRUE) + 10_000_000_000;
		for ($out = ''; !str_contains($out, 'ready'); usleep(1000)) {
			$out .= (string) stream_get_contents($this->standIn[1][1]);
			if (hrtime(TRUE) > $deadline) {
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in never listened');
			}
		}

		// When: General is saved with client-IP metrics off and Core refuses it
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$scope = pfb_test_general_save(['pfb_metrics_client_ip' => '']);

		// Then: nothing is saved and the stored identity is still there
		$this->assertSame(['pfBlockerNG Core refused the DNS settings: dns.metricsClientIp: refused by the stand-in'], $scope['input_errors']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$columns = [];
		$info = $db->query('PRAGMA table_info(dns_metric_blocks)');
		while ($column = $info->fetchArray(SQLITE3_ASSOC)) {
			$columns[] = $column['name'];
		}
		$kept = in_array('client_ip', $columns, TRUE) ? $db->querySingle("SELECT count(*) FROM dns_metric_blocks WHERE client_ip = '192.0.2.7'") : 0;
		$db->close();
		$this->assertSame(1, $kept, 'a refused save must not purge stored client identities; columns: ' . implode(',', $columns));
	}
}
