<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsblNatWriterSeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3539 — the DNSBL web server, its NAT, its certificate and the auto-created VIP exist only
 * while some effective DNSBL block answers with the VIP (pfb_dnsbl_vip_demand()).
 *
 * pfb_manage_dnsbl_vip() creates the marked VIP only under demand and otherwise takes the guarded
 * delete path; pfb_create_dnsbl() serves (NAT, conf, cert, restart) under demand and otherwise tears
 * all of it down, needing neither ports nor a VIP to do so.
 */
#[CoversFunction('pfb_manage_dnsbl_vip')]
#[CoversFunction('pfb_create_dnsbl')]
final class DnsblVipLifecycleTest extends TestCase
{
	use DnsblNatWriterSeedTrait;

	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const VIP_WRITE = 'pfBlockerNG: saving DNSBL auto-VIP changes';
	private const USER_ROW = ['descr' => 'user rule', 'interface' => 'wan', 'target' => '10.0.0.9'];
	private const USER_VIP = ['mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => '192.0.2.99', 'subnet_bits' => '32', 'descr' => 'my own VIP', 'uniqid' => 'user1'];

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;
		$this->dir         = sys_get_temp_dir() . '/pfb_vip_lifecycle_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);

		$GLOBALS['pfb_test_file_notices']        = [];
		$GLOBALS['pfb_test_logger_calls']        = [];
		$GLOBALS['pfb_test_write_config_calls']  = [];
		$GLOBALS['pfb_test_service_calls']       = [];
		$GLOBALS['pfb_test_service_running']     = ['pfb_dnsbl' => TRUE];
		$GLOBALS['pfb_test_vip_bring_down_calls'] = [];
		$GLOBALS['pfb_test_ipalias_configure_calls'] = [];
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		if ($this->savedPfb === NULL) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedPfb;
		}
		unset(
			$GLOBALS['pfb_test_file_notices'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_write_config_calls'],
			$GLOBALS['pfb_test_service_calls'], $GLOBALS['pfb_test_service_running'], $GLOBALS['pfb_test_vip_list'],
			$GLOBALS['pfb_test_vip_bring_down_calls'], $GLOBALS['pfb_test_ipalias_configure_calls']
		);
	}

	/** @return array<string,mixed> */
	private static function markedVip(string $family, string $uniqid, string $subnet): array
	{
		return [
			'mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $subnet,
			'subnet_bits' => $family === 'v4' ? '32' : '128',
			'descr' => $family === 'v4' ? PFB_AUTO_VIP_DESCR_V4 : PFB_AUTO_VIP_DESCR_V6, 'uniqid' => $uniqid,
		];
	}

	/** @return array<string,mixed> */
	private static function dnsblNatRow(): array
	{
		return [
			'source' => ['any' => ''], 'destination' => ['address' => '203.0.113.10', 'port' => '80'], 'protocol' => 'tcp',
			'target' => '127.0.0.1', 'local-port' => '8081', 'interface' => 'opt-double', 'descr' => PFB_MANAGED_NAT_DESCR,
			'associated-rule-id' => 'pass', 'natreflection' => 'purenat',
		];
	}

	/** Auto-create on, the resolver-facing interface lo0, and the stored VIP ids the caller names. */
	private function seedAutoVip(bool $demand, array $vips, string $id4 = '', string $id6 = ''): void
	{
		$this->seedDnsblNatWriter($this->dir, [], $demand);
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', 'on');
		PfbConfig::write('dnsbl/dnsbl_interface', 'lo0');
		config_set_path(self::DNSBL . '/pfb_dnsvip4', $id4);
		config_set_path(self::DNSBL . '/pfb_dnsvip6', $id6);
		config_set_path('virtualip/vip', $vips);
		$GLOBALS['pfb_test_vip_list'] = [];
	}

	private function runVipManager(string $mode): void
	{
		pfb_global();
		pfb_manage_dnsbl_vip($mode);
	}

	/** @return list<string> */
	private function serviceCalls(string $function): array
	{
		return array_values(array_map(
			static fn (array $call): string => $call[1],
			array_filter($GLOBALS['pfb_test_service_calls'], static fn (array $call): bool => $call[0] === $function)
		));
	}

	/** @return list<array<string,mixed>> */
	private function dnsblNat(): array
	{
		return array_values(array_filter(config_get_path('nat/rule', []), static fn (array $row): bool => ($row['descr'] ?? '') === PFB_MANAGED_NAT_DESCR));
	}

	// ------------------------------------------------------------------------------------------
	// pfb_manage_dnsbl_vip(): create only under demand, guarded delete otherwise
	// ------------------------------------------------------------------------------------------

	public function testDemandCreatesTheMarkedVipAndPointsTheStoredIdAtIt(): void
	{
		// GIVEN auto-create on, a block that answers with the VIP, and no VIP yet
		$this->seedAutoVip(TRUE, []);
		$this->assertSame([], config_get_path('virtualip/vip', []), 'before-state: no VIP in config');

		// WHEN the VIP manager runs for an enabled DNSBL
		$this->runVipManager('enabled');

		// THEN one marked VIP exists on the DNSBL interface and the stored v4 id names it
		$vips = config_get_path('virtualip/vip');
		$this->assertCount(1, $vips);
		$this->assertSame(PFB_AUTO_VIP_DESCR_V4, $vips[0]['descr']);
		$this->assertSame('lo0', $vips[0]['interface']);
		$this->assertSame('_vip' . $vips[0]['uniqid'], config_get_path(self::DNSBL . '/pfb_dnsvip4'));
		$this->assertContains(self::VIP_WRITE, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testNoDemandDeletesBothMarkedVipsAndForgetsTheirStoredIds(): void
	{
		// GIVEN auto-create on, the package's v4 and v6 VIPs stored, a user VIP beside them, and no block answering with the VIP
		$this->seedAutoVip(FALSE, [
			self::markedVip('v4', 'auto4', '172.16.53.53'),
			self::markedVip('v6', 'auto6', 'fd00:53:53:53:53:53:53:53'),
			self::USER_VIP,
		], '_vipauto4', '_vipauto6');
		$this->assertCount(3, config_get_path('virtualip/vip'), 'before-state: both marked VIPs and the user VIP exist');

		// WHEN the VIP manager runs for an enabled DNSBL
		$this->runVipManager('enabled');

		// THEN only the package's VIPs are gone, brought down live, and the stored ids no longer name them
		$this->assertSame([self::USER_VIP], config_get_path('virtualip/vip'));
		$this->assertCount(2, $GLOBALS['pfb_test_vip_bring_down_calls']);
		$this->assertEmpty(config_get_path(self::DNSBL . '/pfb_dnsvip4'));
		$this->assertEmpty(config_get_path(self::DNSBL . '/pfb_dnsvip6'));
		$this->assertContains(self::VIP_WRITE, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testNoDemandNeverDeletesAnUnmarkedVipAtTheStoredAddress(): void
	{
		// GIVEN auto-create on, no block answering with the VIP, and the stored id naming the user's own (unmarked) VIP
		$this->seedAutoVip(FALSE, [self::USER_VIP], '_vipuser1');
		$configBefore = $GLOBALS['config'];
		$this->assertSame('_vipuser1', config_get_path(self::DNSBL . '/pfb_dnsvip4'), 'before-state: the stored id names the user VIP');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN nothing changed: the VIP stays, no VIP was brought down, no config was written
		$this->assertSame($configBefore, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_vip_bring_down_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testNoDemandInManualModeChangesNothing(): void
	{
		// GIVEN manual VIP mode (auto-create off), no block answering with the VIP, a manual VIP referenced
		$this->seedDnsblNatWriter($this->dir, [], FALSE);
		$configBefore = $GLOBALS['config'];
		$this->assertSame('_vip_test_valid', config_get_path(self::DNSBL . '/pfb_dnsvip4'), 'before-state: the manual VIP is referenced');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN config is untouched and nothing was written
		$this->assertSame($configBefore, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	// ------------------------------------------------------------------------------------------
	// pfb_create_dnsbl(): serve under demand, tear down otherwise
	// ------------------------------------------------------------------------------------------

	public function testDemandServesTheNatTheConfTheCertificateAndRestartsTheWebServer(): void
	{
		// GIVEN a block answering with the VIP on a real interface, and nothing served yet
		$this->seedDnsblNatWriter($this->dir, [self::USER_ROW], TRUE);
		unlink($GLOBALS['pfb']['dnsbl_cert']);
		$this->assertSame([], $this->dnsblNat(), 'before-state: no DNSBL NAT');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf'], 'before-state: no web server conf');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_cert'], 'before-state: no certificate');

		// WHEN DNSBL is applied enabled
		$this->applyDnsblEnabled();

		// THEN the user rule is kept and the HTTP + HTTPS port forwards exist
		$nat = config_get_path('nat/rule');
		$this->assertSame(self::USER_ROW, $nat[0]);
		$this->assertSame(['80', '443'], array_map(static fn (array $row): string => $row['destination']['port'], $this->dnsblNat()));
		// AND the conf is what pfb_create_lighttpd() builds, the certificate exists and the web server was restarted
		$this->assertSame(pfb_create_lighttpd(), file_get_contents($GLOBALS['pfb']['dnsbl_conf']));
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_cert']);
		$this->assertContains('pfb_dnsbl', $this->serviceCalls('restart_service'));
		$this->assertSame([], $this->serviceCalls('stop_service'));
	}

	public function testEnabledWithoutDemandTearsDownTheServedStateWithoutPortsOrVip(): void
	{
		// GIVEN a served state (NAT, conf, certificate, running web server) whose block no longer answers with the VIP,
		// and neither ports nor a VIP configured
		$this->seedDnsblNatWriter($this->dir, [self::USER_ROW, self::dnsblNatRow()], FALSE);
		config_set_path(self::DNSBL . '/pfb_dnsport', '');
		config_set_path(self::DNSBL . '/pfb_dnsport_ssl', '');
		config_set_path(self::DNSBL . '/pfb_dnsvip4', '');
		config_set_path('virtualip/vip', []);
		$GLOBALS['pfb_test_vip_list'] = [];
		file_put_contents($GLOBALS['pfb']['dnsbl_conf'], "serving\n");
		$this->assertCount(1, $this->dnsblNat(), 'before-state: the DNSBL NAT exists');
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_conf'], 'before-state: the conf exists');
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_cert'], 'before-state: the certificate exists');

		// WHEN DNSBL is applied enabled
		pfb_create_dnsbl('enabled');

		// THEN the DNSBL NAT is gone, the user rule kept, conf and certificate are unlinked
		$this->assertSame([self::USER_ROW], config_get_path('nat/rule'));
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_cert']);
		// AND the web server was stopped, never restarted, and DNSBL is neither force-disabled nor noticed
		$this->assertSame(['pfb_dnsbl'], $this->serviceCalls('stop_service'));
		$this->assertSame([], $this->serviceCalls('restart_service'));
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testTeardownDoesNotStopAWebServerThatIsAlreadyDown(): void
	{
		// GIVEN a served state without demand and a web server that is not running
		$this->seedDnsblNatWriter($this->dir, [self::dnsblNatRow()], FALSE);
		$GLOBALS['pfb_test_service_running'] = ['pfb_dnsbl' => FALSE];
		$this->assertCount(1, $this->dnsblNat(), 'before-state: the DNSBL NAT exists');

		// WHEN DNSBL is applied enabled
		pfb_create_dnsbl('enabled');

		// THEN the teardown happened and no stop was issued
		$this->assertSame([], $this->dnsblNat());
		$this->assertSame([], $this->serviceCalls('stop_service'));
	}

	public function testDisabledTearsDownTheSameStateIncludingConfAndCertificate(): void
	{
		// GIVEN a served state under demand
		$this->seedDnsblNatWriter($this->dir, [self::USER_ROW, self::dnsblNatRow()], TRUE);
		file_put_contents($GLOBALS['pfb']['dnsbl_conf'], "serving\n");
		$this->assertCount(1, $this->dnsblNat(), 'before-state: the DNSBL NAT exists');
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_conf'], 'before-state: the conf exists');
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_cert'], 'before-state: the certificate exists');

		// WHEN DNSBL is applied disabled
		pfb_create_dnsbl('disabled');

		// THEN demand does not matter: NAT, conf and certificate are gone and the web server stopped
		$this->assertSame([self::USER_ROW], config_get_path('nat/rule'));
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_cert']);
		$this->assertSame(['pfb_dnsbl'], $this->serviceCalls('stop_service'));
	}

	public function testResolverOffModeTearsDownTheWebServerAndLeavesTheVipAlone(): void
	{
		// GIVEN DNSBL on with the DNS Resolver off (mode ''), a served state, and the package's own VIP in place
		$vips = [self::markedVip('v4', 'auto4', '203.0.113.10')];
		$this->seedAutoVip(TRUE, $vips, '_vipauto4');
		config_set_path('nat/rule', [self::USER_ROW, self::dnsblNatRow()]);
		file_put_contents($GLOBALS['pfb']['dnsbl_conf'], "serving\n");
		$this->assertCount(1, $this->dnsblNat(), 'before-state: the DNSBL NAT exists');
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_conf'], 'before-state: the conf exists');

		// WHEN DNSBL is applied in the resolver-off mode
		pfb_create_dnsbl('');

		// THEN NAT, conf and certificate are gone and the web server stopped
		$this->assertSame([self::USER_ROW], config_get_path('nat/rule'));
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_cert']);
		$this->assertSame(['pfb_dnsbl'], $this->serviceCalls('stop_service'));
		// AND VIP management stayed a no-op for '': the VIP and its stored id are untouched
		$this->assertSame($vips, config_get_path('virtualip/vip'));
		$this->assertSame('_vipauto4', config_get_path(self::DNSBL . '/pfb_dnsvip4'));
		$this->assertNotContains(self::VIP_WRITE, $GLOBALS['pfb_test_write_config_calls']);
	}
}
