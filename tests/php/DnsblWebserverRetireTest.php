<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4053: the DNSBL web server, its NAT redirect, certificate and auto-created VIP are removed. Every apply and the
 * installer strip what an earlier version left, through the same guards that version used: only the exact pfB DNSBL NAT
 * rows, and only the VIP that carries the auto-VIP marker AND sits at the address the stored id resolves to.
 */
#[CoversFunction('pfb_dnsbl_webserver_retire')]
#[CoversFunction('pfb_dnsbl_vip_retire')]
final class DnsblWebserverRetireTest extends TestCase
{
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';

	private string $dir = '';
	private array $saved = [];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_vip_bring_down_calls'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_service_running'] = ['pfb_dnsbl' => FALSE];
		$this->dir = sys_get_temp_dir() . '/pfb_retire_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
		foreach (['dbdir', 'dnsbl_conf', 'dnsbl_cert', 'unbound_py_vip'] as $k) {
			$this->saved[$k] = $GLOBALS['pfb'][$k] ?? NULL;
		}
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['dnsbl_conf'] = "{$this->dir}/pfb_dnsbl_lighty.conf";
		$GLOBALS['pfb']['dnsbl_cert'] = "{$this->dir}/dnsbl_cert.pem";
		$GLOBALS['pfb']['unbound_py_vip'] = "{$this->dir}/pfb_py_vip";
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $v) {
			$GLOBALS['pfb'][$k] = $v;
		}
		unset($GLOBALS['pfb_test_service_running']);
		exec('rm -rf ' . escapeshellarg($this->dir));
	}

	private function seed(array $dnsbl, array $vips, array $nat = []): void
	{
		config_set_path(self::DNSBL, $dnsbl);
		config_set_path('virtualip/vip', $vips);
		config_set_path('nat/rule', $nat);
	}

	public function testTheMarkedAutoVipAtTheStoredAddressIsRemoved(): void
	{
		$this->seed(['pfb_dnsbl' => 'on', 'pfb_dnsvip4' => '_vip4a', 'pfb_dnsvip6' => '_vip6a'], [
			['uniqid' => '4a', 'subnet' => '10.10.10.1', 'descr' => PFB_AUTO_VIP_DESCR_V4, 'interface' => 'lo0'],
			['uniqid' => '6a', 'subnet' => 'fd00:53:53:53:53:53:53:1', 'descr' => PFB_AUTO_VIP_DESCR_V6, 'interface' => 'lo0'],
			['uniqid' => 'u1', 'subnet' => '192.0.2.7', 'descr' => 'an operator VIP', 'interface' => 'lan'],
		]);

		$this->assertTrue(pfb_dnsbl_vip_retire());

		$this->assertSame(['192.0.2.7'], array_column(config_get_path('virtualip/vip', []), 'subnet'));
		$this->assertCount(2, $GLOBALS['pfb_test_vip_bring_down_calls']);
	}

	public function testAnUnmarkedVipIsNeverDeletedEvenWhenTheStoredIdNamesIt(): void
	{
		$this->seed(['pfb_dnsvip4' => '_vipm1'], [['uniqid' => 'm1', 'subnet' => '10.10.10.1', 'descr' => 'pfBlockerNG DNSBL']]);

		pfb_dnsbl_vip_retire();

		$this->assertSame(['10.10.10.1'], array_column(config_get_path('virtualip/vip', []), 'subnet'));
		$this->assertSame([], $GLOBALS['pfb_test_vip_bring_down_calls']);
	}

	public function testAMarkedVipAwayFromTheStoredAddressStays(): void
	{
		$this->seed(['pfb_dnsvip4' => '_vip4a'], [
			['uniqid' => '4a', 'subnet' => '10.10.10.1', 'descr' => 'an operator VIP'],
			['uniqid' => '4b', 'subnet' => '172.16.53.1', 'descr' => PFB_AUTO_VIP_DESCR_V4],
		]);

		pfb_dnsbl_vip_retire();

		$this->assertSame(['10.10.10.1', '172.16.53.1'], array_column(config_get_path('virtualip/vip', []), 'subnet'));
	}

	public function testTheRetiredKeysLeaveTheDnsblSectionAndTheRestStays(): void
	{
		$stored = ['pfb_dnsbl' => 'on', 'global_log' => 'disabled_log'];
		foreach (PFB_DNSBL_RETIRED_KEYS as $key) {
			$stored[$key] = 'x';
		}
		$this->seed($stored, []);

		$this->assertTrue(pfb_dnsbl_vip_retire());

		$this->assertSame(['pfb_dnsbl' => 'on', 'global_log' => 'disabled_log'], config_get_path(self::DNSBL));
		foreach (['pfb_dnsvip4', 'pfb_dnsvip_auto', 'pfb_dnsport', 'pfb_dnsport_ssl', 'dnsbl_interface', 'pfb_dnsbl_rule',
			'dnsbl_allow_int', 'pfb_py_nolog', 'dnsbl_webpage', 'pfb_dnsvip'] as $key) {
			$this->assertContains($key, PFB_DNSBL_RETIRED_KEYS);
		}
	}

	public function testOnlyTheExactDnsblNatRowsGoAndTheServerFilesAreRemoved(): void
	{
		$this->seed(['pfb_dnsbl' => 'on'], [], [
			['descr' => PFB_MANAGED_NAT_DESCR, 'target' => '127.0.0.1', 'local-port' => '8081'],
			['descr' => 'mine: ' . PFB_MANAGED_NAT_DESCR, 'target' => '192.0.2.9', 'local-port' => '80'],
		]);
		foreach (['dnsbl_conf', 'dnsbl_cert', 'unbound_py_vip'] as $k) {
			file_put_contents($GLOBALS['pfb'][$k], 'x');
		}

		pfb_dnsbl_webserver_retire();

		$this->assertSame(['mine: ' . PFB_MANAGED_NAT_DESCR], array_column(config_get_path('nat/rule', []), 'descr'));
		foreach (['dnsbl_conf', 'dnsbl_cert', 'unbound_py_vip'] as $k) {
			$this->assertFileDoesNotExist($GLOBALS['pfb'][$k]);
		}
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testARunningServiceIsStoppedAndASecondRunChangesNothing(): void
	{
		$this->seed(['pfb_dnsbl' => 'on'], []);
		$GLOBALS['pfb_test_service_running'] = ['pfb_dnsbl' => TRUE];

		pfb_dnsbl_webserver_retire();
		$this->assertContains(['stop_service', 'pfb_dnsbl'], $GLOBALS['pfb_test_service_calls']);

		$GLOBALS['pfb_test_service_running'] = ['pfb_dnsbl' => FALSE];
		$GLOBALS['pfb_test_service_calls'] = [];
		pfb_dnsbl_webserver_retire();
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_service_calls']);
	}
}
