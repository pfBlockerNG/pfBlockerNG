<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3913, PR #3919 review:
 *   - the projected values' hash decides a push: config.xml's revision/time only skips one when the hash is the recorded one
 *     too. Two saves in one second whose pushes finish out of order leave the older values in Core and a record of that
 *     second; the next tick must still push the newer values;
 *   - General asks Core before the client-IP metrics privacy change: a refused save leaves the stored client identities alone.
 */
#[CoversFunction('pfb_core_settings_push')]
final class CoreSettingsPushOrderTest extends TestCase
{
	private const GENERAL_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_general.php';

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
		$GLOBALS['pfb']['core_pushed'] = "{$this->dir}/core_pushed";
		$GLOBALS['pfb']['core_push_failed'] = "{$this->dir}/core_push_failed";
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

	public function testATickPushesWhenTheHashDiffersEvenAtTheRecordedRevisionTime(): void
	{
		// Given: an out-of-order push left Core with the older values and a record of this second with their hash
		config_set_path('revision/time', '1700000000');
		config_set_path(PFB_SECTIONS['dnsbl'] . '/pfb_py_reply', '');
		$older = hash('sha256', (string) json_encode(['dns' => pfb_core_dns_settings()]));
		config_set_path(PFB_SECTIONS['dnsbl'] . '/pfb_py_reply', 'on');
		file_put_contents("{$this->dir}/core_pushed", json_encode(['time' => '1700000000', 'hash' => $older]));
		$methods = [];
		$call = static function (string $method, array $params = []) use (&$methods): array {
			$methods[] = $method;
			$held = array_merge(pfb_core_dns_settings(), ['replyLogging' => FALSE]);
			return $method === 'GetSettings'
				? ['status' => 200, 'body' => ['initialized' => TRUE, 'revision' => 5, 'projections' => [['resourceId' => 'settings/dns', 'generation' => 2, 'value' => $held]]], 'error' => NULL]
				: ['status' => 200, 'body' => ['revision' => 6, 'projections' => []], 'error' => NULL];
		};

		// When: the next tick runs, config.xml unchanged
		$reason = pfb_core_settings_push($call);

		// Then: it pushes the newer values
		$this->assertSame(['GetSettings', 'SaveSettings'], $methods, 'the hash differs from the record: Core is asked and corrected');
		$this->assertNull($reason);
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
		$region = pfb_test_page_region(self::GENERAL_PAGE, "\$pfb['gconfig']['pfb_metrics_client_ip'] = pfb_filter(", 'if ($privacy_error !== NULL) {');
		$_POST['pfb_metrics_client_ip'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$scope = pfb_test_page_eval($region, ['pfb' => ['gconfig' => ['enable_cb' => 'on']], 'input_errors' => []]);

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
