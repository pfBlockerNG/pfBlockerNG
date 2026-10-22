<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsblNatWriterSeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3539 — the DNSBL web server, its NAT, its certificate and the auto-created VIP exist only
 * while some effective DNSBL block answers with the VIP (pfb_dnsbl_vip_demand()).
 *
 * pfb_manage_dnsbl_vip() creates the marked VIP only under demand and otherwise takes the guarded
 * delete path; pfb_create_dnsbl() serves (NAT, conf, cert, restart) under demand and otherwise tears
 * all of it down, needing neither ports nor a VIP to do so.
 *
 * issue #3540 — on an HA pair a policy receiver provisions its auto-VIP at the address the primary
 * published (pfb_dnsvip_auto4/6): an address that is not free there means no VIP and a Sync finding.
 * A node that has not received policy publishes the address it picked and ignores any stored one.
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
	private const SYNCED4 = self::DNSBL . '/pfb_dnsvip_auto4';
	private const SYNCED6 = self::DNSBL . '/pfb_dnsvip_auto6';
	private const V6_CANDIDATE = 'fd00:53:53:53:53:53:53:53';
	// A stored v6 id core no longer knows: it requests a v6 VIP without naming one that exists.
	private const V6_REQUEST_ID = '_vip_gone_v6';

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
		@unlink($GLOBALS['pfb']['log'] ?? '');
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

	/** The VIPs in config as core lists them, so the picker sees each address as taken. */
	private function listConfiguredVips(): void
	{
		$GLOBALS['pfb_test_vip_list'] = [];
		foreach (config_get_path('virtualip/vip', []) as $vip) {
			$GLOBALS['pfb_test_vip_list']["_vip{$vip['uniqid']}"] = $vip['subnet'];
		}
	}

	/** seedAutoVip() plus the VIP list: the node is an auto-VIP node that already knows its VIPs. */
	private function seedNode(bool $demand, array $vips, string $id4 = '', string $id6 = ''): void
	{
		$this->seedAutoVip($demand, $vips, $id4, $id6);
		$this->listConfiguredVips();
	}

	/** A node that accepted a primary's policy, recorded under $acceptedDigest. */
	private function writeReceiveState(string $acceptedDigest): void
	{
		file_put_contents("{$this->dir}/pfb_sync_receive.json", json_encode(['accepted_digest' => $acceptedDigest]));
	}

	/** @return array<string,mixed> an unmarked VIP of the user's that occupies $subnet */
	private static function userVipAt(string $subnet): array
	{
		return [
			'mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => $subnet,
			'subnet_bits' => str_contains($subnet, ':') ? '128' : '32', 'descr' => 'occupies the address', 'uniqid' => 'occupier',
		];
	}

	/** @return list<array<string,mixed>> */
	private function markedVips(string $family): array
	{
		$marker = $family === 'v4' ? PFB_AUTO_VIP_DESCR_V4 : PFB_AUTO_VIP_DESCR_V6;
		return array_values(array_filter(config_get_path('virtualip/vip', []), static fn (array $row): bool => ($row['descr'] ?? '') === $marker));
	}

	private function conflictFact(): mixed
	{
		return $GLOBALS['pfb']['dnsbl_vip_conflict'] ?? 'dnsbl_vip_conflict is not set';
	}

	private function vipWrites(): int
	{
		return count(array_keys($GLOBALS['pfb_test_write_config_calls'], self::VIP_WRITE, TRUE));
	}

	private function mainLog(): string
	{
		$log = $GLOBALS['pfb']['log'];
		return is_file($log) ? (string) file_get_contents($log) : '';
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
	// issue #3540: a policy receiver provisions at the address its primary published
	// ------------------------------------------------------------------------------------------

	public function testReceiverCreatesTheMarkedVipAtTheSyncedAddressNotItsOwnFirstPick(): void
	{
		// GIVEN a policy receiver whose primary published 192.168.53.53, with no VIP yet and every candidate free
		$this->seedNode(TRUE, []);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '192.168.53.53');
		$this->assertSame('172.16.53.53', pfb_pick_free_dnsbl_vip(AF_INET, 'lo0'), 'before-state: a standalone node would take the first candidate');
		$this->assertSame([], config_get_path('virtualip/vip', []), 'before-state: no VIP in config');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the one marked VIP sits at the synced address and the stored id names it
		$vips = $this->markedVips('v4');
		$this->assertCount(1, $vips);
		$this->assertSame('192.168.53.53', $vips[0]['subnet'], 'the receiver must provision at the primary\'s address');
		$this->assertSame('_vip' . $vips[0]['uniqid'], config_get_path(self::DNSBL . '/pfb_dnsvip4'));
		// AND a receiver never rewrites the address it received
		$this->assertSame('192.168.53.53', config_get_path(self::SYNCED4));
	}

	public function testReceiverWithTheSyncedAddressInUseCreatesNoVipAndReportsTheConflict(): void
	{
		// GIVEN a policy receiver whose primary published 172.16.53.53, a user VIP already holds it,
		// and the next candidate is free (a standalone node would take it)
		$this->seedNode(TRUE, [self::userVipAt('172.16.53.53')]);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '172.16.53.53');
		$this->assertSame('192.168.53.53', pfb_pick_free_dnsbl_vip(AF_INET, 'lo0'), 'before-state: a standalone node would take 192.168.53.53');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN nothing was created anywhere: the user's VIP is the only one, and no id was stored
		$this->assertSame([self::userVipAt('172.16.53.53')], config_get_path('virtualip/vip'));
		$this->assertEmpty(config_get_path(self::DNSBL . '/pfb_dnsvip4'));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		// AND the conflict is reported for the Sync page and logged
		$this->assertSame(['IPv4'], $this->conflictFact());
		$this->assertStringContainsString('DNSBL auto-VIP: synced ' . PFB_AUTO_VIP_DESCR_V4 . ' address [ 172.16.53.53 ] is not free on this node; not created', $this->mainLog());
	}

	public function testReceiverMovesItsMarkedVipToTheSyncedAddress(): void
	{
		// GIVEN a receiver holding its own marked VIP at 172.16.53.53 while the primary published 192.168.53.53
		$this->seedNode(TRUE, [self::markedVip('v4', 'old4', '172.16.53.53')], '_vipold4');
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '192.168.53.53');
		$this->assertSame('172.16.53.53', $this->markedVips('v4')[0]['subnet'], 'before-state: the marked VIP sits at its own pick');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the old VIP was brought down and removed, and the one marked VIP now sits at the synced address
		$this->assertCount(1, $GLOBALS['pfb_test_vip_bring_down_calls'], 'a marked VIP at another address than the synced one must be brought down');
		$this->assertSame('old4', $GLOBALS['pfb_test_vip_bring_down_calls'][0]['uniqid']);
		$vips = $this->markedVips('v4');
		$this->assertCount(1, $vips, 'exactly one marked VIP: the moved one replaces the old one');
		$this->assertSame('192.168.53.53', $vips[0]['subnet']);
		$this->assertNotSame('old4', $vips[0]['uniqid']);
		$this->assertSame('_vip' . $vips[0]['uniqid'], config_get_path(self::DNSBL . '/pfb_dnsvip4'), 'the stored id names the new VIP');
		$this->assertSame(1, $this->vipWrites());
	}

	public function testReceiverRemovesItsMarkedVipWhenTheSyncedAddressIsInUse(): void
	{
		// GIVEN a receiver holding its marked VIP at 192.168.53.53 while the primary published 172.16.53.53,
		// an address a user VIP holds on this node
		$this->seedNode(TRUE, [self::markedVip('v4', 'old4', '192.168.53.53'), self::userVipAt('172.16.53.53')], '_vipold4');
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '172.16.53.53');
		$this->assertCount(1, $this->markedVips('v4'), 'before-state: the marked VIP exists');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the marked VIP was brought down and removed, none replaced it, and the user's VIP is untouched
		$this->assertCount(1, $GLOBALS['pfb_test_vip_bring_down_calls'], 'a marked VIP at another address than the synced one must be brought down');
		$this->assertSame('old4', $GLOBALS['pfb_test_vip_bring_down_calls'][0]['uniqid']);
		$this->assertSame([self::userVipAt('172.16.53.53')], config_get_path('virtualip/vip'));
		$this->assertEmpty(config_get_path(self::DNSBL . '/pfb_dnsvip4'), 'the stored id no longer names a VIP');
		// AND the conflict survives the pass that changed config (which refreshes $pfb at its end)
		$this->assertSame(['IPv4'], $this->conflictFact());
	}

	public function testReceiverWithItsMarkedVipAlreadyAtTheSyncedAddressChangesNothing(): void
	{
		// GIVEN a receiver whose marked VIP already sits at the synced address
		$this->seedNode(TRUE, [self::markedVip('v4', 'auto4', '192.168.53.53')], '_vipauto4');
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '192.168.53.53');
		$configBefore = $GLOBALS['config'];
		$this->assertSame('192.168.53.53', $this->markedVips('v4')[0]['subnet'], 'before-state: the VIP is at the synced address');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN there is no churn: config is identical, no write, nothing brought down
		$this->assertSame($configBefore, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_vip_bring_down_calls']);
	}

	public function testReceiverWithoutASyncedAddressPicksItsOwnAndPublishesNothing(): void
	{
		// GIVEN a receiver of an older primary: policy accepted, but the primary never sent an auto-VIP address
		$this->seedNode(TRUE, []);
		$this->writeReceiveState('d');
		$this->assertNull(config_get_path(self::SYNCED4), 'before-state: no synced address stored');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN it picked as a standalone node does
		$vips = $this->markedVips('v4');
		$this->assertCount(1, $vips);
		$this->assertSame('172.16.53.53', $vips[0]['subnet']);
		// AND a receiver never writes the synced field: the primary owns it
		$this->assertNull(config_get_path(self::SYNCED4), 'a receiver must not publish its own address');
	}

	public function testReceiverWithoutDemandRemovesTheMarkedVipAndLeavesTheSyncedAddressAsReceived(): void
	{
		// GIVEN a receiver with a marked VIP, a received synced address, and no block answering with the VIP
		$this->seedNode(FALSE, [self::markedVip('v4', 'auto4', '172.16.53.53')], '_vipauto4');
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '192.168.53.53');
		$this->assertCount(1, $this->markedVips('v4'), 'before-state: the marked VIP exists');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the VIP is gone and its id forgotten, but the received address is policy and stays
		$this->assertSame([], $this->markedVips('v4'));
		$this->assertEmpty(config_get_path(self::DNSBL . '/pfb_dnsvip4'));
		$this->assertSame('192.168.53.53', config_get_path(self::SYNCED4));
	}

	public function testNonReceiverIgnoresAStoredSyncedAddressAndPublishesItsOwnPick(): void
	{
		// GIVEN a node that never received policy, holding a stale synced address, with no VIP yet
		$this->seedNode(TRUE, []);
		config_set_path(self::SYNCED4, '192.168.53.53');
		$this->assertFileDoesNotExist("{$this->dir}/pfb_sync_receive.json", 'before-state: no receive state');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN it picked as a standalone node does, ignoring the stored address
		$vips = $this->markedVips('v4');
		$this->assertCount(1, $vips);
		$this->assertSame('172.16.53.53', $vips[0]['subnet']);
		// AND it published the address it picked, in the same single write
		$this->assertSame('172.16.53.53', config_get_path(self::SYNCED4));
		$this->assertSame(1, $this->vipWrites());
	}

	public function testNonReceiverPublishesTheAddressOfAMarkedVipItAlreadyHas(): void
	{
		// GIVEN an upgraded node: a marked VIP and its id exist, no address was ever published
		$this->seedNode(TRUE, [self::markedVip('v4', 'auto4', '172.16.53.53')], '_vipauto4');
		$this->assertNull(config_get_path(self::SYNCED4), 'before-state: nothing published');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the VIP address is published with one write, and the VIP itself is untouched
		$this->assertSame('172.16.53.53', config_get_path(self::SYNCED4));
		$this->assertSame(1, $this->vipWrites());
		$this->assertSame([], $GLOBALS['pfb_test_vip_bring_down_calls']);
		$this->assertSame('172.16.53.53', $this->markedVips('v4')[0]['subnet']);
	}

	public function testNonReceiverWithoutDemandRemovesTheVipAndClearsThePublishedAddress(): void
	{
		// GIVEN a node that published its address, with no block answering with the VIP any more
		$this->seedNode(FALSE, [self::markedVip('v4', 'auto4', '172.16.53.53')], '_vipauto4');
		config_set_path(self::SYNCED4, '172.16.53.53');
		$this->assertSame('172.16.53.53', config_get_path(self::SYNCED4), 'before-state: the address is published');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the VIP is gone and so is the published address, so no peer provisions at a stale one
		$this->assertSame([], $this->markedVips('v4'));
		$this->assertArrayNotHasKey('pfb_dnsvip_auto4', config_get_path(self::DNSBL), 'the published address must be cleared with the VIP');
	}

	public function testNodeThatOnlyRefusedPolicyActsAsANonReceiver(): void
	{
		// GIVEN a receive state with no accepted digest (policy was only ever refused, or the role flipped)
		// and a stale synced address
		$this->seedNode(TRUE, []);
		$this->assertTrue(pfb_sync_receive_record('refused', NULL, 'syncscope is not policy', $this->dir), 'before-state: the real writer recorded a refusal');
		config_set_path(self::SYNCED4, '192.168.53.53');
		$this->assertNull(pfb_sync_receive_state_read($this->dir)['accepted_digest'], 'before-state: a receive state without an accepted digest');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN it behaves as a standalone/primary node: own pick, published
		$vips = $this->markedVips('v4');
		$this->assertCount(1, $vips);
		$this->assertSame('172.16.53.53', $vips[0]['subnet']);
		$this->assertSame('172.16.53.53', config_get_path(self::SYNCED4));
	}

	public function testReceiverCreatesTheMarkedV6VipAtTheSyncedV6Address(): void
	{
		// GIVEN a receiver that requests a v6 VIP (a v6 id is stored) and was told the v6 candidate
		$this->seedNode(TRUE, [], '', self::V6_REQUEST_ID);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED6, self::V6_CANDIDATE);
		$this->assertSame([], $this->markedVips('v6'), 'before-state: no v6 VIP');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the marked v6 VIP sits at the synced address and the stored v6 id names it
		$vips = $this->markedVips('v6');
		$this->assertCount(1, $vips);
		$this->assertSame(self::V6_CANDIDATE, $vips[0]['subnet']);
		$this->assertSame('_vip' . $vips[0]['uniqid'], config_get_path(self::DNSBL . '/pfb_dnsvip6'));
		// AND a receiver publishes neither family
		$this->assertSame(self::V6_CANDIDATE, config_get_path(self::SYNCED6));
		$this->assertNull(config_get_path(self::SYNCED4));
	}

	public function testNonReceiverPublishesTheAddressesOfBothFamilies(): void
	{
		// GIVEN a node that requests a v6 VIP and has published nothing
		$this->seedNode(TRUE, [], '', self::V6_REQUEST_ID);
		$this->assertNull(config_get_path(self::SYNCED4), 'before-state: no v4 address published');
		$this->assertNull(config_get_path(self::SYNCED6), 'before-state: no v6 address published');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN each family publishes the address it created
		$this->assertSame('172.16.53.53', config_get_path(self::SYNCED4));
		$this->assertSame(self::V6_CANDIDATE, config_get_path(self::SYNCED6));
	}

	public function testReceiverWithTheSyncedV6AddressInUseReportsOnlyIPv6(): void
	{
		// GIVEN a receiver that requests a v6 VIP, was told the v6 candidate, and a user VIP holds it;
		// the v4 side has no synced address, so it picks its own
		$this->seedNode(TRUE, [self::userVipAt(self::V6_CANDIDATE)], '', self::V6_REQUEST_ID);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED6, self::V6_CANDIDATE);

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN no v6 VIP exists, the v4 VIP was created as usual, and only IPv6 is reported
		$this->assertSame([], $this->markedVips('v6'));
		$this->assertCount(1, $this->markedVips('v4'));
		$this->assertSame(['IPv6'], $this->conflictFact());
	}

	/** @return array<string,array{0:string}> */
	public static function hostileSyncedAddresses(): array
	{
		return [
			'routable address'        => ['203.0.113.5'],
			'candidate with a prefix' => ['172.16.53.53/12'],
			'the v6 candidate on v4'  => ['fd00:53:53:53:53:53:53:53'],
			'300 chars with markup'   => ['<b>' . str_repeat('x', 297)],
		];
	}

	#[DataProvider('hostileSyncedAddresses')]
	public function testReceiverNeverProvisionsAtAHostileSyncedAddress(string $synced): void
	{
		// GIVEN a receiver whose synced v4 address is not one of the fixed candidates; every candidate is free
		$this->seedNode(TRUE, []);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, $synced);
		$this->assertSame([], config_get_path('virtualip/vip', []), 'before-state: no VIP in config');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN no VIP was created at any address, the value was not altered, and the conflict is reported
		$this->assertSame([], config_get_path('virtualip/vip', []));
		$this->assertSame($synced, config_get_path(self::SYNCED4));
		$this->assertSame(['IPv4'], $this->conflictFact());
	}

	public function testAHostileSyncedAddressIsTruncatedAndEscapedInTheLog(): void
	{
		// GIVEN a receiver whose synced v4 address is 300 characters of markup
		$this->seedNode(TRUE, []);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '<b>' . str_repeat('x', 297));

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the log line carries 100 characters of the value, HTML-escaped, never the raw markup
		$log = $this->mainLog();
		$this->assertSame(1, preg_match('/address \[ (.*?) \] is not free on this node; not created/s', $log, $match), "the conflict line must be logged. Log:\n{$log}");
		$this->assertSame(100, strlen($match[1]), 'the logged value must be cut to 100 characters');
		$this->assertStringStartsWith('&lt;b&gt;', $match[1]);
		$this->assertStringNotContainsString('<b>', $log);
	}

	public function testReceiverWithAutoCreateOffCreatesNoVipAndPublishesNothing(): void
	{
		// GIVEN a receiver in manual VIP mode (auto-create off), with a received synced address
		$this->seedNode(TRUE, []);
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', '');
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '192.168.53.53');
		$configBefore = $GLOBALS['config'];

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the package creates no VIP and writes nothing, and the received address is untouched
		$this->assertSame([], config_get_path('virtualip/vip', []));
		$this->assertSame($configBefore, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testConflictFactIsClearedByTheNextPassWhoseSyncedAddressIsFree(): void
	{
		// GIVEN a receiver whose first pass hit a conflict at 172.16.53.53
		$this->seedNode(TRUE, [self::userVipAt('172.16.53.53')]);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '172.16.53.53');
		$this->runVipManager('enabled');
		$this->assertSame(['IPv4'], $this->conflictFact(), 'before-state: the first pass reported the conflict');

		// WHEN the user VIP goes away and the manager runs again
		config_set_path('virtualip/vip', []);
		$this->listConfiguredVips();
		$this->runVipManager('enabled');

		// THEN the fact is empty again, so the finding does not outlive the conflict, and the VIP was created
		$this->assertSame([], $this->conflictFact());
		$this->assertSame('172.16.53.53', $this->markedVips('v4')[0]['subnet'] ?? NULL);
	}

	public function testStaleV6RemovalKeepsTheV4VipCreatedEarlierInTheSamePass(): void
	{
		// GIVEN a receiver with no v4 VIP yet and a marked v6 VIP away from the synced v6 address
		$this->seedNode(TRUE, [self::markedVip('v6', 'old6', 'fd00:53:53:53:53:53:53:99')], '', '_vipold6');
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '192.168.53.53');
		config_set_path(self::SYNCED6, self::V6_CANDIDATE);
		$this->assertSame([], $this->markedVips('v4'), 'before-state: no v4 VIP');

		// WHEN the VIP manager runs: the v4 VIP is created in memory, then the v6 one is moved
		$this->runVipManager('enabled');

		// THEN the move did not drop the v4 VIP created earlier in the same pass
		$v4 = $this->markedVips('v4');
		$v6 = $this->markedVips('v6');
		$this->assertCount(1, $v4, 'the v4 VIP created in the same pass must survive the v6 removal');
		$this->assertSame('192.168.53.53', $v4[0]['subnet']);
		$this->assertCount(1, $v6);
		$this->assertSame(self::V6_CANDIDATE, $v6[0]['subnet']);
		$this->assertSame('_vip' . $v4[0]['uniqid'], config_get_path(self::DNSBL . '/pfb_dnsvip4'));
		$this->assertSame('_vip' . $v6[0]['uniqid'], config_get_path(self::DNSBL . '/pfb_dnsvip6'));
	}

	public function testReceiverWithoutASyncedAddressKeepsItsExistingMarkedVipUntouched(): void
	{
		// GIVEN a receiver of an older primary that already holds its own marked VIP
		$this->seedNode(TRUE, [self::markedVip('v4', 'auto4', '172.16.53.53')], '_vipauto4');
		$this->writeReceiveState('d');
		$before = $GLOBALS['config'];

		// WHEN the VIP manager runs again
		$this->runVipManager('enabled');

		// THEN nothing is replaced, written or brought down
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_vip_bring_down_calls']);
	}

	public function testReceiverWithoutASyncedAddressAndNoFreeCandidateReportsNoConflict(): void
	{
		// GIVEN a receiver of an older primary whose three IPv4 candidates are all taken
		$this->seedNode(TRUE, [
			self::userVipAt('172.16.53.53'),
			array_merge(self::userVipAt('192.168.53.53'), ['uniqid' => 'o2']),
			array_merge(self::userVipAt('10.53.53.53'), ['uniqid' => 'o3']),
		]);
		$this->writeReceiveState('d');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN no synced address was refused, so there is no Sync finding, only the standalone log line
		$this->assertSame([], $this->conflictFact());
		$this->assertStringContainsString('no free ' . PFB_AUTO_VIP_DESCR_V4 . ' address available; not created', $this->mainLog());
	}

	public function testBothFamiliesInConflictAreBothReported(): void
	{
		// GIVEN a receiver whose synced IPv4 and IPv6 addresses are both taken by the user's VIPs
		$this->seedNode(TRUE, [self::userVipAt('172.16.53.53'), array_merge(self::userVipAt(self::V6_CANDIDATE), ['uniqid' => 'o6'])], '', self::V6_REQUEST_ID);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '172.16.53.53');
		config_set_path(self::SYNCED6, self::V6_CANDIDATE);

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN both families are reported
		$this->assertSame(['IPv4', 'IPv6'], $this->conflictFact());
	}

	public function testAnIPv4ConflictDoesNotStopIPv6Provisioning(): void
	{
		// GIVEN a receiver whose synced IPv4 address is taken and whose synced IPv6 address is free
		$this->seedNode(TRUE, [self::userVipAt('172.16.53.53')], '', self::V6_REQUEST_ID);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '172.16.53.53');
		config_set_path(self::SYNCED6, self::V6_CANDIDATE);

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN only IPv4 is reported and the IPv6 VIP is still created at the synced address
		$this->assertSame(['IPv4'], $this->conflictFact());
		$v6 = $this->markedVips('v6');
		$this->assertCount(1, $v6);
		$this->assertSame(self::V6_CANDIDATE, $v6[0]['subnet']);
	}

	public function testAMovedVipIsBroughtUpLiveAtTheSyncedAddress(): void
	{
		// GIVEN a receiver whose marked VIP sits away from the synced address
		$this->seedNode(TRUE, [self::markedVip('v4', 'old4', '172.16.53.53')], '_vipold4');
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '192.168.53.53');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the alias is configured live once, at the synced address
		$this->assertCount(1, $GLOBALS['pfb_test_ipalias_configure_calls']);
		$this->assertSame('192.168.53.53', $GLOBALS['pfb_test_ipalias_configure_calls'][0]['subnet']);
	}

	public function testAPaddedSyncedAddressIsAConflictNotAVip(): void
	{
		// GIVEN a receiver whose synced address carries a trailing newline
		$this->seedNode(TRUE, []);
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, "172.16.53.53\n");

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the value is not a candidate as sent: no VIP, and the conflict is reported
		$this->assertSame([], $this->markedVips('v4'));
		$this->assertSame(['IPv4'], $this->conflictFact());
	}

	public function testTheGuardedDeleteKeepsAMarkedCopyAtAnotherAddress(): void
	{
		// GIVEN no demand, the stored marked VIP, and a copy of it (pfSense's copy keeps the descr) at another address
		$this->seedNode(FALSE, [self::markedVip('v4', 'auto4', '172.16.53.53'), self::markedVip('v4', 'copy4', '192.168.53.53')], '_vipauto4');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN only the stored VIP is removed; the copy fails the address guard and stays
		$this->assertSame(['copy4'], array_column($this->markedVips('v4'), 'uniqid'));
	}

	/** @return array<string,array{bool,list<array<string,mixed>>,string,string}> demand, VIPs, stored v4 id, pfb_dnsvip_auto */
	public static function unmanagedNonReceiverStates(): array
	{
		return [
			'no demand, the VIP and its id already gone' => [FALSE, [], '', 'on'],
			'auto-create off, the id repointed at a manual VIP' => [TRUE, [self::markedVip('v4', 'auto4', '172.16.53.53'), self::USER_VIP], '_vipuser1', ''],
		];
	}

	/** @param list<array<string,mixed>> $vips */
	#[DataProvider('unmanagedNonReceiverStates')]
	public function testNonReceiverThatNoLongerManagesTheFamilyClearsThePublishedAddress(bool $demand, array $vips, string $id4, string $auto): void
	{
		// GIVEN a node that published 172.16.53.53 and no longer manages an IPv4 auto-VIP, where the guard deletes nothing
		$this->seedNode($demand, $vips, $id4);
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', $auto);
		config_set_path(self::SYNCED4, '172.16.53.53');
		$markedBefore = $this->markedVips('v4');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the published address is cleared, so no receiver follows an address this node does not use
		$this->assertArrayNotHasKey('pfb_dnsvip_auto4', config_get_path(self::DNSBL));
		// AND the guard still keeps every marked VIP it may not delete
		$this->assertSame($markedBefore, $this->markedVips('v4'));
	}

	public function testReceiverReportsAMarkedVipTheGuardMayNotMove(): void
	{
		// GIVEN a receiver holding a marked VIP whose stored id was cleared (auto-create toggled off with no VIP
		// selected, then on again), away from the synced address
		$this->seedNode(TRUE, [self::markedVip('v4', 'orph4', '172.16.53.53')], '');
		$this->writeReceiveState('d');
		config_set_path(self::SYNCED4, '192.168.53.53');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the guard keeps the VIP, nothing is created, and the node reports it instead of staying silent
		$this->assertSame(['172.16.53.53'], array_column($this->markedVips('v4'), 'subnet'));
		$this->assertSame(['IPv4'], $this->conflictFact());
		$this->assertStringContainsString(PFB_AUTO_VIP_DESCR_V4 . ' at [ 172.16.53.53 ] is not the stored VIP; not moved to the synced address', $this->mainLog());
	}

	// ------------------------------------------------------------------------------------------
	// issue #3565: a standalone node never creates its VIP at an address a VIP already holds
	// ------------------------------------------------------------------------------------------

	public function testStandaloneNodeCreatesItsVipAtTheNextCandidateWhenAUserVipHoldsTheFirst(): void
	{
		// GIVEN a node that never received policy, and the user's described VIP at the first candidate
		$this->seedNode(TRUE, [self::userVipAt('172.16.53.53')]);
		$this->assertSame([], $this->markedVips('v4'), 'before-state: no marked VIP');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN the marked VIP sits at the second candidate, the user's VIP is untouched, and that address is published
		$this->assertSame(['192.168.53.53'], array_column($this->markedVips('v4'), 'subnet'),
			'a VIP already at 172.16.53.53 must make the picker take 192.168.53.53');
		$this->assertContains(self::userVipAt('172.16.53.53'), config_get_path('virtualip/vip'));
		$this->assertSame('192.168.53.53', config_get_path(self::SYNCED4));
	}

	public function testStandaloneNodeCreatesNoV6VipWhenAUserVipHoldsTheV6Candidate(): void
	{
		// GIVEN a node that requests a v6 VIP, and the user's described VIP at the only v6 candidate
		$this->seedNode(TRUE, [self::userVipAt(self::V6_CANDIDATE)], '', self::V6_REQUEST_ID);
		$this->assertSame([], $this->markedVips('v6'), 'before-state: no marked v6 VIP');

		// WHEN the VIP manager runs
		$this->runVipManager('enabled');

		// THEN no v6 VIP was created and the shortage is logged, while v4 is provisioned as usual with no Sync finding
		$this->assertSame([], $this->markedVips('v6'), 'a VIP already at the v6 candidate must leave the family without an auto-VIP');
		$this->assertStringContainsString('no free ' . PFB_AUTO_VIP_DESCR_V6 . ' address available; not created', $this->mainLog());
		$this->assertSame(['172.16.53.53'], array_column($this->markedVips('v4'), 'subnet'));
		$this->assertSame([], $this->conflictFact());
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
