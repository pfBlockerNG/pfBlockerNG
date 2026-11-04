<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsListenVipLifecycleTest extends TestCase
{
	private array $saved;
	private string $dir;

	protected function setUp(): void
	{
		$this->saved = [];
		foreach (['config', 'pfb', 'pfb_test_vip_list', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info',
			'pfb_test_service_calls', 'pfb_test_unbound_configure_calls', 'pfb_test_write_config_hook', 'pfb_test_write_config_result',
			'pfb_test_config_read_hook', 'pfb_test_config_read_calls', 'pfb_test_interfaces'] as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_listen_vip_' . bin2hex(random_bytes(5));
		mkdir($this->dir, 0700);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['log'] = $this->dir . '/pfblockerng.log';
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1', 'lo0' => '127.0.0.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1', 'lo0' => '::1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_unbound_configure_calls'] = [];
		$GLOBALS['pfb_test_config_read_calls'] = [];
		unset($GLOBALS['pfb_test_write_config_hook'], $GLOBALS['pfb_test_write_config_result'], $GLOBALS['pfb_test_config_read_hook']);
		config_set_path('unbound/active_interface', 'lan');
		PfbConfig::write('dns/pfb_dns_interface', 'lan');
		PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
		foreach ($this->saved as $name => [$exists, $value]) {
			if ($exists) { $GLOBALS[$name] = $value; } else { unset($GLOBALS[$name]); }
		}
	}

	public function testManualAddressIsPublishedAndReceiverRecreatesItWithoutTheSendersLocalId(): void
	{
		config_set_path('virtualip/vip', [['mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => 'fd12:3456::53', 'subnet_bits' => '128', 'descr' => 'operator', 'uniqid' => 'primary']]);
		PfbConfig::write('gen/pfb_dns_listen_vip6', '_vipprimary');
		pfb_dns_listen_vips_apply();
		$this->assertSame('fd12:3456::53', PfbConfig::read('gen/pfb_dns_listen_auto6'));
		$policy = pfb_sync_policy_projection(['pfblockerng' => ['config' => [PfbConfig::readSection(PFB_SECTIONS['gen'])]]]);
		$this->assertSame('_vipprimary', $policy[PFB_SECTIONS['gen'] . '/pfb_dns_listen_vip6']);
		config_set_path('virtualip/vip', []);
		config_set_path('dhcpdv6/lan', ['dnsserver' => ['2001:db8::1']]);
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		pfb_dns_listen_vips_apply();
		$this->assertSame('fd12:3456::53', config_get_path('virtualip/vip/0/subnet'));
		$this->assertSame('pfB_DNS_LISTEN_VIP_v6', config_get_path('virtualip/vip/0/descr'));
		$this->assertSame('lo0', config_get_path('virtualip/vip/0/interface'));
		$this->assertSame(['2001:db8::1', 'fd12:3456::53'], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertSame(['192.0.2.1', 'fd12:3456::53'], pfb_dns_proxy_listen());
		$before = config_get_path('virtualip/vip');
		pfb_dns_listen_vips_apply();
		$this->assertSame($before, config_get_path('virtualip/vip'), 'sync replay reuses the marked VIP');
	}

	public function testResolverKeepsLocalhostAndVipWithBothDnsFeaturesOff(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_listen_vips_apply();
		$id = '_vip' . config_get_path('virtualip/vip/0/uniqid');
		$this->assertSame(['lan', 'lo0', $id], pfb_dns_proxy_tokens(config_get_path('unbound/active_interface')));
	}

	public function testEveryEncryptedCategoryKeepsBothLoopbackBackendsWithVipSubstitution(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip4', 'auto');
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_listen_vips_apply();
		foreach (['dot', 'doh', 'doq'] as $kind) {
			PfbConfig::write('dns_shared/pfb_dns_' . $kind, 'on');
			PfbConfig::write('dns/pfb_dns_' . $kind . '_interface', 'lan');
		}
		$warnings = [];
		$flags = pfb_dns_proxy_tls_flags($warnings);
		foreach (['dot', 'doh', 'doq'] as $kind) {
			foreach (['127.0.0.1', '::1', '172.16.53.53', 'fd00:53:53:53:53:53:53:53'] as $host) {
				$this->assertStringContainsString('--' . $kind . "-listen '{$host}'", $flags);
			}
		}
		$this->assertSame(['172.16.53.53', 'fd00:53:53:53:53:53:53:53'], pfb_dns_proxy_interface_addresses(['lo0']));
	}

	public function testRcListenerInventoryUsesEachFamilysPortAndPlainDnsStillUses53(): void
	{
		$before = @file_get_contents(PFB_DNS_PROXY_RCFILE);
		@mkdir(dirname(PFB_DNS_PROXY_RCFILE), 0755, TRUE);
		$command = "#!/bin/sh\n /usr/sbin/daemon pfb-dns --listen '127.0.0.1' --listen '::1' --port 53";
		foreach (['dot', 'doh', 'doq'] as $kind) {
			$command .= " --{$kind}-listen '192.0.2.1' --{$kind}-listen '2001:db8::1' --{$kind}-port '8853' --{$kind}-port6 '443'";
		}
		try {
			file_put_contents(PFB_DNS_PROXY_RCFILE, $command . "\n");
			$list = pfb_dns_proxy_command_listeners();
			$this->assertSame(['127.0.0.1:53', '[::1]:53'], $list['udp+tcp']);
			foreach (['dot', 'doh', 'doq'] as $kind) {
				$this->assertSame(['192.0.2.1:8853', '[2001:db8::1]:443'], $list[$kind]);
			}
		} finally {
			if ($before === FALSE) { unlink(PFB_DNS_PROXY_RCFILE); } else { file_put_contents(PFB_DNS_PROXY_RCFILE, $before); }
		}
	}

	public function testResolverApplyProvisionsGeneralVipsEvenWithBothDnsFeaturesOff(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_proxy_resolver(FALSE);
		$this->assertSame('fd00:53:53:53:53:53:53:53', config_get_path('virtualip/vip/0/subnet'));
		$this->assertContains('lo0', pfb_dns_proxy_tokens(config_get_path('unbound/active_interface')));
	}

	public function testSavingVipRegeneratesResolverImmediately(): void
	{
		$before = count($GLOBALS['pfb_test_unbound_configure_calls'] ?? []);
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_listen_vips_apply();
		$this->assertCount($before + 1, $GLOBALS['pfb_test_unbound_configure_calls'] ?? []);
		pfb_dns_listen_vips_apply();
		$this->assertCount($before + 1, $GLOBALS['pfb_test_unbound_configure_calls'] ?? [], 'replay does not restart an unchanged Resolver');
	}

	public function testTurningTheListenerOffRemovesTheOwnedVipEvenWhenTheSelectionStaysAuto(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_listen_vips_apply();
		$owned = config_get_path('virtualip/vip/0/subnet');
		$copy = ['mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => 'fd12:3456::99', 'subnet_bits' => '128', 'descr' => 'pfB_DNS_LISTEN_VIP_v6', 'uniqid' => 'copy'];
		config_set_path('virtualip/vip', [$copy, config_get_path('virtualip/vip/0')]);
		PfbConfig::write('gen/pfb_dns_listen_vip', '');
		pfb_dns_listen_vips_apply();
		$this->assertSame(['fd12:3456::99'], array_column(config_get_path('virtualip/vip'), 'subnet'));
		$this->assertNotSame('fd12:3456::99', $owned);
	}

	public function testASaveThatChangesUnboundAndDhcpAppliesBoth(): void
	{
		config_set_path('unbound/active_interface', 'lan');
		config_set_path('dhcpd/lan', ['dnsserver' => ['192.0.2.1']]);
		$unbound = count($GLOBALS['pfb_test_unbound_configure_calls'] ?? []);
		$dhcp = count(array_filter($GLOBALS['pfb_test_service_calls'] ?? [], static fn (array $call): bool => $call[0] === 'services_dhcpd_configure'));
		PfbConfig::write('gen/pfb_dns_listen_vip4', 'auto');
		pfb_dns_listen_vips_apply();
		$this->assertCount($unbound + 1, $GLOBALS['pfb_test_unbound_configure_calls'] ?? []);
		$this->assertCount($dhcp + 1, array_filter($GLOBALS['pfb_test_service_calls'] ?? [], static fn (array $call): bool => $call[0] === 'services_dhcpd_configure'));
	}

	public function testReceiverDeletesOnlyItsOwnedVipAfterPolicyRemovesTheSyncedAddress(): void
	{
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		PfbConfig::write('gen/pfb_dns_listen_auto6', 'fd00:53:53:53:53:53:53:54');
		pfb_dns_listen_vips_apply();
		$this->assertSame('fd00:53:53:53:53:53:53:54', config_get_path('virtualip/vip/0/subnet'));
		PfbConfig::write('gen/pfb_dns_listen_vip', '');
		PfbConfig::write('gen/pfb_dns_listen_vip6', '');
		PfbConfig::write('gen/pfb_dns_listen_auto6', '');
		pfb_dns_listen_vips_apply();
		$this->assertSame([], config_get_path('virtualip/vip'));
	}

	public function testReceiverReconcilesOneMarkedVipToADifferentSyncedAddress(): void
	{
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		PfbConfig::write('gen/pfb_dns_listen_auto6', 'fd00:53:53:53:53:53:53:54');
		pfb_dns_listen_vips_apply();
		$this->assertSame('fd00:53:53:53:53:53:53:54', config_get_path('virtualip/vip/0/subnet'));
		PfbConfig::write('gen/pfb_dns_listen_auto6', 'fd00:53:53:53:53:53:53:55');
		pfb_dns_listen_vips_apply();
		$this->assertCount(1, config_get_path('virtualip/vip'));
		$this->assertSame('fd00:53:53:53:53:53:53:55', config_get_path('virtualip/vip/0/subnet'));
		$this->assertSame('auto', PfbConfig::read('gen/pfb_dns_listen_vip6'));
		$before = config_get_path('virtualip/vip');
		pfb_dns_listen_vips_apply();
		$this->assertSame($before, config_get_path('virtualip/vip'), 'same-policy replay does not regenerate the VIP');
	}

	public function testACopiedMarkedVipPlacedFirstIsNotDeletedWhenTheOptionIsTurnedOff(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_listen_vips_apply();
		$created = config_get_path('virtualip/vip/0');
		$this->assertSame('pfB_DNS_LISTEN_VIP_v6', $created['descr']);
		$copy = ['mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => 'fd12:3456::99', 'subnet_bits' => '128', 'descr' => 'pfB_DNS_LISTEN_VIP_v6', 'uniqid' => 'copy'];
		config_set_path('virtualip/vip', [$copy, $created]);
		pfb_dns_listen_vips_apply();
		$this->assertSame([$created['subnet']], array_keys(pfb_dns_listen_vips()), 'the copy is not advertised in place of the VIP this feature made');
		PfbConfig::write('gen/pfb_dns_listen_vip', '');
		PfbConfig::write('gen/pfb_dns_listen_vip6', '');
		pfb_dns_listen_vips_apply();
		pfb_dns_listen_vips_apply();
		$this->assertSame([$copy], config_get_path('virtualip/vip'), 'only the address this feature created is removed, on this apply and every later one');
	}

	public function testAnUnownedMarkedVipSurvivesEnableThenDisable(): void
	{
		$copy = ['mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => 'fd12:3456::99', 'subnet_bits' => '128', 'descr' => 'pfB_DNS_LISTEN_VIP_v6', 'uniqid' => 'copy'];
		config_set_path('virtualip/vip', [$copy]);
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_listen_vips_apply();
		PfbConfig::write('gen/pfb_dns_listen_vip', '');
		PfbConfig::write('gen/pfb_dns_listen_vip6', '');
		pfb_dns_listen_vips_apply();
		$this->assertSame(['fd12:3456::99'], array_column(config_get_path('virtualip/vip'), 'subnet'), 'a marked VIP this feature did not create is not deleted when the option is turned off');
	}

	public function testReceiverCreatesTheSyncedAddressWhenTheSendersIdNamesAnotherLocalVip(): void
	{
		config_set_path('virtualip/vip', [[
			'mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => 'fd34::53',
			'subnet_bits' => '128', 'descr' => 'operator', 'uniqid' => 'sender',
		]]);
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_vip6', '_vipsender');
		PfbConfig::write('gen/pfb_dns_listen_auto6', 'fd12::53');
		pfb_dns_listen_vips_apply();
		$this->assertSame(['fd34::53', 'fd12::53'], array_column(config_get_path('virtualip/vip'), 'subnet'));
		$this->assertSame(['fd12::53'], array_keys(pfb_dns_listen_vips()));
	}

	public function testUninstallDropsRecordedAdvertisementsAfterTheVipSweep(): void
	{
		config_set_path('dhcpdv6/lan/dnsserver', ['2001:db8::53', 'fd12::53']);
		config_set_path('dhcpdv6/lan/radnsserver', ['fd12::53']);
		config_set_path('unbound/active_interface', 'lo0,fd12::53');
		PfbConfig::write('gen/pfb_dns_listen_added', json_encode([
			'vip6' => ['fd12::53'],
			'dhcpdv6/lan/dnsserver' => ['fd12::53'],
			'dhcpdv6/lan/radnsserver' => ['fd12::53'],
			'unbound/active_interface' => ['fd12::53'],
		]));
		config_set_path('virtualip/vip', [[
			'mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => 'fd12::53',
			'subnet_bits' => '128', 'descr' => 'pfB_DNS_LISTEN_VIP_v6', 'uniqid' => 'owned',
		]]);
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$sweep = strpos($source, "pfb_deinstall_sweep_managed_objects();\n");
		$drop = strpos($source, 'pfb_dns_listen_advertisements_drop();', $sweep === FALSE ? 0 : $sweep);
		$this->assertNotFalse($sweep);
		$this->assertNotFalse($drop, 'uninstall drops the recorded advertisements after the VIP sweep');
		pfb_deinstall_sweep_managed_objects();
		pfb_dns_listen_advertisements_drop();
		$this->assertSame(['2001:db8::53'], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertSame([], config_get_path('dhcpdv6/lan/radnsserver'));
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertSame('', PfbConfig::read('gen/pfb_dns_listen_added'));
		$this->assertSame([], config_get_path('virtualip/vip'));
		$this->assertContains('services_dhcpd_configure', array_column($GLOBALS['pfb_test_service_calls'], 0));
		$this->assertNotEmpty($GLOBALS['pfb_test_unbound_configure_calls']);
	}

	public function testReceiverAdvertisesTheSyncedAddressNotADifferentVipTheSendersIdResolvesTo(): void
	{
		$vip = static fn (string $id, string $address): array => ['mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => $address, 'subnet_bits' => '128', 'descr' => 'operator', 'uniqid' => $id];
		config_set_path('virtualip/vip', [$vip('sender', 'fd34::53'), $vip('local', 'fd12::53')]);
		config_set_path('dhcpdv6/lan', ['dnsserver' => ['2001:db8::1']]);
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_vip6', '_vipsender');
		PfbConfig::write('gen/pfb_dns_listen_auto6', 'fd12::53');
		pfb_dns_listen_vips_apply();
		$this->assertSame(['fd12::53' => '_viplocal'], pfb_dns_listen_vips());
		$this->assertSame(['2001:db8::1', 'fd12::53'], config_get_path('dhcpdv6/lan/dnsserver'));
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('preservedAddresses')]
	public function testFreshAutoReceiverCreatesThePreservedSyncedAddress(int $family, string $address): void
	{
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write("gen/pfb_dns_listen_vip{$family}", 'auto');
		PfbConfig::write("gen/pfb_dns_listen_auto{$family}", $address);
		pfb_dns_listen_vips_apply();
		$this->assertSame([$address], array_column(config_get_path('virtualip/vip', []), 'subnet'));
		$this->assertSame("pfB_DNS_LISTEN_VIP_v{$family}", config_get_path('virtualip/vip/0/descr'));
		$this->assertSame([$address], array_keys(pfb_dns_listen_vips()));
	}

	public static function preservedAddresses(): array
	{
		return [
			'IPv6 outside pool' => [6, 'fd12:3456::53'],
			'IPv4 outside pool' => [4, '192.0.2.53'],
			'uppercase IPv6' => [6, 'FD00:53:53:53:53:53:53:54'],
		];
	}

	public function testAutoReceiverMovesItsOwnedVipToAFreePreservedAddress(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_listen_vips_apply();
		$this->assertSame('fd00:53:53:53:53:53:53:53', config_get_path('virtualip/vip/0/subnet'));
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_auto6', 'fd12:3456::99');
		pfb_dns_listen_vips_apply();
		$this->assertSame(['fd12:3456::99'], array_column(config_get_path('virtualip/vip'), 'subnet'));
		$this->assertSame([], $GLOBALS['pfb']['dns_listen_vip_conflict']);
	}

	public function testAutoReceiverKeepsItsOwnedVipWhenTheSyncedAddressIsTaken(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_listen_vips_apply();
		$owned = config_get_path('virtualip/vip/0');
		$taken = ['mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single',
			'subnet' => 'fd00:53:53:53:53:53:53:55', 'subnet_bits' => '128', 'descr' => 'operator', 'uniqid' => 'taken'];
		config_set_path('virtualip/vip', [$owned, $taken]);
		$GLOBALS['pfb_test_vip_list'] = [$owned['subnet'], $taken['subnet']];
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_auto6', $taken['subnet']);
		pfb_dns_listen_vips_apply();
		$this->assertSame([$owned, $taken], config_get_path('virtualip/vip'));
		$this->assertContains('IPv6', $GLOBALS['pfb']['dns_listen_vip_conflict']);
	}

	public function testAutoReceiverReusesAnOwnedVipWhenOnlyTheSyncedSpellingDiffers(): void
	{
		$owned = ['mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => 'fd00::53', 'subnet_bits' => '128', 'descr' => 'pfB_DNS_LISTEN_VIP_v6', 'uniqid' => 'owned'];
		config_set_path('virtualip/vip', [$owned]);
		$GLOBALS['pfb_test_vip_list'] = ['fd00::53'];
		PfbConfig::write('gen/pfb_dns_listen_interface', 'lan');
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		PfbConfig::write('gen/pfb_dns_listen_added', json_encode(['vip6' => ['fd00::53']]));
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_auto6', 'FD00::53');
		pfb_dns_listen_vips_apply();
		$this->assertSame([$owned], config_get_path('virtualip/vip'));
		$this->assertNotContains('IPv6', $GLOBALS['pfb']['dns_listen_vip_conflict'] ?? []);
		$this->assertSame(['fd00::53' => '_vipowned'], pfb_dns_listen_vips());
	}

	public function testADownInterfaceDoesNotGainTheListenerVip(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip4', 'auto');
		pfb_dns_listen_vips_apply();
		$GLOBALS['pfb_test_interface_info']['opt1'] = ['status' => 'down', 'enable' => TRUE];
		$this->assertSame([], pfb_dns_proxy_interface_addresses(['opt1']));
		$this->assertSame([], pfb_dns_proxy_interface_addresses([]));
		$this->assertSame(['172.16.53.53'], pfb_dns_proxy_interface_addresses(['lo0']));
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('rejectedSyncedAddresses')]
	public function testAutoReceiverRejectsUnsafeSyncedAddressesWithoutDeletingItsVip(string $address, bool $owned): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		if ($owned) {
			pfb_dns_listen_vips_apply();
		}
		$before = config_get_path('virtualip/vip', []);
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_auto6', $address);
		pfb_dns_listen_vips_apply();
		$this->assertSame($before, config_get_path('virtualip/vip', []));
		$this->assertContains('IPv6', $GLOBALS['pfb']['dns_listen_vip_conflict']);
	}

	public function testAutoReceiverRejectsAnUnspecifiedIpv4AddressWithoutDeletingItsVip(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip4', 'auto');
		pfb_dns_listen_vips_apply();
		$before = config_get_path('virtualip/vip', []);
		$this->assertNotSame([], $before, 'the owned IPv4 listener VIP exists before the bad sync');
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_auto4', '0.0.0.0');
		pfb_dns_listen_vips_apply();
		$this->assertSame($before, config_get_path('virtualip/vip', []));
		$this->assertContains('IPv4', $GLOBALS['pfb']['dns_listen_vip_conflict']);
	}

	public function testAutoReceiverDoesNotCreateAnUnspecifiedIpv4Address(): void
	{
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_vip4', 'auto');
		PfbConfig::write('gen/pfb_dns_listen_auto4', '0.0.0.0');
		pfb_dns_listen_vips_apply();
		$this->assertSame([], config_get_path('virtualip/vip', []));
		$this->assertContains('IPv4', $GLOBALS['pfb']['dns_listen_vip_conflict']);
	}

	public static function rejectedSyncedAddresses(): array
	{
		return [
			'link-local fresh' => ['fe80::53', FALSE],
			'link-local owned' => ['fe80::53', TRUE],
			'mapped fresh' => ['::ffff:192.0.2.53', FALSE],
			'mapped owned' => ['::ffff:192.0.2.53', TRUE],
			'invalid fresh' => ['not-an-ip', FALSE],
			'invalid owned' => ['not-an-ip', TRUE],
			'unspecified fresh' => ['::', FALSE],
			'unspecified owned' => ['::', TRUE],
			'unspecified spelling' => ['::0', FALSE],
		];
	}

	public function testVipOwnershipSurvivesAFailedAdvertisementWriteAndRetryThenDisable(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		PfbConfig::write('gen/pfb_dns_listen_added', json_encode(['dhcpdv6/lan/dnsserver' => ['fd34::53']]));
		config_set_path('dhcpdv6/lan/dnsserver', ['fd34::53']);
		$disk = $GLOBALS['config'];
		$fail = TRUE;
		$vipLedger = NULL;
		$GLOBALS['pfb_test_write_config_hook'] = static function (string $description) use (&$disk, &$fail, &$vipLedger): void {
			$GLOBALS['pfb_test_write_config_result'] = !($fail && str_contains($description, 'DNS listener advertisements'));
			if ($GLOBALS['pfb_test_write_config_result']) {
				$disk = $GLOBALS['config'];
				if (str_contains($description, 'DNSBL auto-VIP')) {
					$vipLedger = json_decode((string) PfbConfig::read('gen/pfb_dns_listen_added'), TRUE);
				}
			}
		};
		$GLOBALS['pfb_test_config_read_hook'] = static function () use (&$disk): void {
			$GLOBALS['config'] = $disk;
		};
		$this->assertFalse(pfb_dns_listen_vips_apply());
		$this->assertSame([[FALSE, FALSE]], $GLOBALS['pfb_test_config_read_calls']);
		$ledger = json_decode((string) PfbConfig::read('gen/pfb_dns_listen_added'), TRUE);
		$this->assertSame(['fd00:53:53:53:53:53:53:53'], $ledger['vip6'] ?? []);
		$this->assertSame(['fd34::53'], $vipLedger['dhcpdv6/lan/dnsserver']);
		$this->assertSame($vipLedger, $ledger);
		$fail = FALSE;
		$this->assertTrue(pfb_dns_listen_vips_apply());
		PfbConfig::write('gen/pfb_dns_listen_vip', '');
		pfb_manage_dnsbl_vip('disabled', TRUE);
		$this->assertSame([], config_get_path('virtualip/vip'));
	}

	public function testDroppingAnEmptyLedgerDoesNotRegenerateServices(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_added', '{}');
		pfb_dns_listen_advertisements_drop();
		$this->assertSame([], $GLOBALS['pfb_test_service_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_unbound_configure_calls']);
	}

	public function testLoopbackOnlyDoesNotAddAVipWhenTheOptionIsOff(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		pfb_dns_listen_vips_apply();
		PfbConfig::write('gen/pfb_dns_listen_vip', '');
		$this->assertSame([], pfb_dns_proxy_interface_addresses(['lo0']));
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('unparsablePublishedAddresses')]
	public function testReceiverDoesNotAdvertiseACollidingLocalIdWithoutAParsablePublishedAddress(string $published): void
	{
		config_set_path('virtualip/vip', [[
			'mode' => 'ipalias', 'interface' => 'lan', 'type' => 'single', 'subnet' => 'fd34::53',
			'subnet_bits' => '128', 'descr' => 'operator', 'uniqid' => 'collide',
		]]);
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => 'received']));
		PfbConfig::write('gen/pfb_dns_listen_vip6', '_vipcollide');
		PfbConfig::write('gen/pfb_dns_listen_auto6', $published);
		$this->assertSame([], pfb_dns_listen_vips());
	}

	public static function unparsablePublishedAddresses(): array
	{
		return ['empty' => [''], 'newline suffix' => ["fd12::53\n"], 'not an IP' => ['not-an-ip']];
	}

	/**
	 * Issue #3693: a DNS-server list that already names a server the administrator chose gets no Resolver VIP.
	 *
	 * @return array<string,array{string,string,int,string,string,string}> section, list, family, the interface's own address, a server of the administrator's own, the Resolver VIP
	 */
	public static function dnsServerLists(): array
	{
		return [
			'DHCPv4 dnsserver' => ['dhcpd', 'dnsserver', 4, '192.0.2.1', '172.20.0.53', '172.16.53.53'],
			'DHCPv6 dnsserver' => ['dhcpdv6', 'dnsserver', 6, '2001:db8::1', '2001:db8:77::53', 'fd00:53:53:53:53:53:53:53'],
			'RA radnsserver' => ['dhcpdv6', 'radnsserver', 6, '2001:db8::1', '2001:db8:77::53', 'fd00:53:53:53:53:53:53:53'],
		];
	}

	/** Select an automatic Resolver VIP of the family and seed the list on the lan scope; returns its config path. */
	private function dnsList(string $section, string $list, int $family, array $servers): string
	{
		PfbConfig::write("gen/pfb_dns_listen_vip{$family}", 'auto');
		config_set_path("{$section}/lan", [$list => $servers]);
		return "{$section}/lan/{$list}";
	}

	private function ledger(): array
	{
		$ledger = json_decode((string) PfbConfig::read('gen/pfb_dns_listen_added'), TRUE);
		return is_array($ledger) ? $ledger : [];
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('dnsServerLists')]
	public function testAnEmptyDnsServerListGainsTheResolverVip(string $section, string $list, int $family, string $own, string $foreign, string $vip): void
	{
		$path = $this->dnsList($section, $list, $family, []);
		pfb_dns_listen_vips_apply();
		$this->assertSame([$vip], config_get_path($path));
		$this->assertSame([$vip], $this->ledger()[$path] ?? NULL, 'the insertion is recorded as ours');
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('dnsServerLists')]
	public function testAListNamingOnlyTheInterfacesOwnAddressGainsTheResolverVip(string $section, string $list, int $family, string $own, string $foreign, string $vip): void
	{
		$path = $this->dnsList($section, $list, $family, [$own]);
		pfb_dns_listen_vips_apply();
		$this->assertSame([$own, $vip], config_get_path($path));
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('dnsServerLists')]
	public function testAListNamingAServerOfTheAdministratorsOwnIsLeftAloneAndLogged(string $section, string $list, int $family, string $own, string $foreign, string $vip): void
	{
		$path = $this->dnsList($section, $list, $family, [$foreign]);
		pfb_dns_listen_vips_apply();
		pfb_dns_listen_vips_apply();
		$this->assertSame([$foreign], config_get_path($path), 'the administrator\'s list is not changed, on this apply and the next');
		$this->assertArrayNotHasKey($path, $this->ledger(), 'nothing was inserted, so nothing is recorded');
		$log = (string) @file_get_contents($GLOBALS['pfb']['log']);
		$this->assertSame(2, substr_count($log, 'the Resolver VIP is not added'), 'one line per skipped scope, per apply');
		$this->assertStringContainsString($foreign, $log);
		$this->assertStringContainsString(' on lan ', $log);
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('dnsServerLists')]
	public function testOurRecordedVipIsRemovedWhenAForeignServerAppearsAndReturnsWhenItIsGone(string $section, string $list, int $family, string $own, string $foreign, string $vip): void
	{
		$path = $this->dnsList($section, $list, $family, []);
		pfb_dns_listen_vips_apply();
		$this->assertSame([$vip], config_get_path($path), 'the VIP was added while the list was empty');
		config_set_path($path, [$vip, $foreign]);
		pfb_dns_listen_vips_apply();
		$this->assertSame([$foreign], config_get_path($path), 'our recorded VIP is removed, the administrator\'s server kept');
		$this->assertArrayNotHasKey($path, $this->ledger());
		config_set_path($path, []);
		pfb_dns_listen_vips_apply();
		$this->assertSame([$vip], config_get_path($path), 'the decision is recomputed from config on every apply');
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('dnsServerLists')]
	public function testAVipTheAdministratorAddedByHandNextToAForeignServerIsNotTouched(string $section, string $list, int $family, string $own, string $foreign, string $vip): void
	{
		$path = $this->dnsList($section, $list, $family, [$vip, $foreign]);
		pfb_dns_listen_vips_apply();
		$this->assertSame([$vip, $foreign], config_get_path($path));
		$this->assertArrayNotHasKey($path, $this->ledger(), 'an unrecorded VIP is the administrator\'s');
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('dnsServerLists')]
	public function testTurningResolverAddressesOffStillRemovesOnlyTheRecordedVip(string $section, string $list, int $family, string $own, string $foreign, string $vip): void
	{
		$path = $this->dnsList($section, $list, $family, [$foreign, $vip]);
		PfbConfig::write('gen/pfb_dns_listen_added', json_encode([$path => [$vip]]));
		PfbConfig::write('gen/pfb_dns_listen_vip', '');
		pfb_dns_listen_vips_apply();
		$this->assertSame([$foreign], config_get_path($path));
		$this->assertArrayNotHasKey($path, $this->ledger());
	}

	public function testEachDhcpv6ListIsDecidedOnItsOwn(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		config_set_path('dhcpdv6/lan', ['dnsserver' => ['2001:db8:77::53'], 'radnsserver' => []]);
		pfb_dns_listen_vips_apply();
		$this->assertSame(['2001:db8:77::53'], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertSame(['fd00:53:53:53:53:53:53:53'], config_get_path('dhcpdv6/lan/radnsserver'), 'a foreign DHCPv6 server does not withhold the VIP from the RA list');
	}

	public function testAnRaListTheDhcpv6ListReplacesIsNeitherSkippedNorWarned(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'auto');
		config_set_path('dhcpdv6/lan', ['dnsserver' => [], 'radnsserver' => ['2001:db8:77::53'], 'rasamednsasdhcp6' => '']);
		pfb_dns_listen_vips_apply();
		$this->assertSame(['fd00:53:53:53:53:53:53:53'], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertStringNotContainsString('the Resolver VIP is not added', (string) @file_get_contents($GLOBALS['pfb']['log']), 'an RA list nobody reads is not a skipped scope');
		$this->assertSame([], pfb_dns_listen_foreign_warnings());
	}

	public function testAnotherSpellingOfTheInterfacesOwnIpv6AddressIsStillItsOwn(): void
	{
		$path = $this->dnsList('dhcpdv6', 'dnsserver', 6, ['2001:0DB8:0:0:0:0:0:1']);
		pfb_dns_listen_vips_apply();
		$this->assertSame(['2001:0DB8:0:0:0:0:0:1', 'fd00:53:53:53:53:53:53:53'], config_get_path($path));
	}

	public function testAnInterfaceWithoutAnAddressOfTheFamilyOwnsNoEntry(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip4', 'auto');
		config_set_path('dhcpd/opt1', ['dnsserver' => ['192.0.2.1']]);
		pfb_dns_listen_vips_apply();
		$this->assertSame(['192.0.2.1'], config_get_path('dhcpd/opt1/dnsserver'), 'another interface\'s address is a server of the administrator\'s here');
	}

	public function testAnEmptyEntryNamesNoServer(): void
	{
		$path = $this->dnsList('dhcpd', 'dnsserver', 4, ['']);
		pfb_dns_listen_vips_apply();
		$this->assertSame(['', '172.16.53.53'], config_get_path($path));
	}

	public function testDnsGeneralWarnsOfEachScopeLeftAloneNamingTheInterfaceTheListAndTheServers(): void
	{
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN', 'opt1' => 'DOCKER'];
		$GLOBALS['pfb_test_interface_ip']['opt1'] = '172.20.0.1';
		PfbConfig::write('gen/pfb_dns_listen_vip4', 'auto');
		config_set_path('dhcpd/opt1', ['dnsserver' => ['172.20.0.53']]);
		pfb_dns_listen_vips_apply();
		$warnings = pfb_dns_listen_foreign_warnings();
		$this->assertCount(1, $warnings);
		foreach (['DOCKER (opt1)', 'DHCPv4', '172.20.0.53', '172.16.53.53'] as $needle) {
			$this->assertStringContainsString($needle, $warnings[0]);
		}
		$this->assertStringContainsString('by hand', $warnings[0], 'it tells the administrator how to add the VIP');
		PfbConfig::write('gen/pfb_dns_listen_vip', '');
		$this->assertSame([], pfb_dns_listen_foreign_warnings(), 'with Resolver addresses off there is nothing to warn about');
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('dnsServerLists')]
	public function testDnsGeneralNamesTheListTypeOfEachScopeAndNoOtherList(string $section, string $list, int $family, string $own, string $foreign, string $vip): void
	{
		$path = $this->dnsList($section, $list, $family, [$foreign]);
		pfb_dns_listen_vips_apply();
		$warnings = pfb_dns_listen_foreign_warnings();
		$this->assertCount(1, $warnings, $path);
		$label = $list === 'radnsserver' ? 'RA' : ($family === 4 ? 'DHCPv4' : 'DHCPv6');
		$this->assertStringContainsString("the {$label} DNS servers of lan", $warnings[0]);
		config_set_path($path, [$own]);
		$this->assertSame([], pfb_dns_listen_foreign_warnings(), 'a list naming only the interface\'s own address is not warned about');
	}

	public function testDnsGeneralEscapesWhatItPrints(): void
	{
		$GLOBALS['pfb_test_interfaces'] = ['lan' => '<b>LAN</b>'];
		PfbConfig::write('gen/pfb_dns_listen_vip4', 'auto');
		config_set_path('dhcpd/lan', ['dnsserver' => ['<i>x</i>']]);
		pfb_dns_listen_vips_apply();
		$text = implode('', pfb_dns_listen_foreign_warnings());
		$this->assertStringContainsString('&lt;b&gt;LAN&lt;/b&gt;', $text);
		$this->assertStringContainsString('&lt;i&gt;x&lt;/i&gt;', $text);
		$this->assertStringNotContainsString('<b>', $text);
		$this->assertStringNotContainsString('<i>', $text);
	}

	public function testDnsGeneralPrintsEachWarningInAWarningBoxJustBeforeTheForm(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
		$page = 'src/usr/local/www/pfblockerng/pfblockerng_dns_general.php';
		$source = pfb_test_page_source($page);
		$this->assertSame(1, substr_count($source, 'pfb_dns_listen_foreign_warnings()'), 'one loop');
		$this->assertLessThan(strpos($source, 'pfb_dns_listen_foreign_warnings()'), strpos($source, 'pfb_print_pending_changes_box();'), 'below the pending-changes box');
		$GLOBALS['pfb_test_info_boxes'] = [];
		PfbConfig::write('gen/pfb_dns_listen_vip4', 'auto');
		config_set_path('dhcpd/lan', ['dnsserver' => ['172.20.0.53']]);
		config_set_path('dhcpd/opt1', ['dnsserver' => ['172.21.0.53']]);
		$GLOBALS['pfb_test_interface_ip']['opt1'] = '172.21.0.1';
		pfb_dns_listen_vips_apply();
		pfb_test_page_eval(pfb_test_page_region($page, 'foreach (pfb_dns_listen_foreign_warnings()', '$form = new Form('), []);
		$boxes = $GLOBALS['pfb_test_info_boxes'];
		unset($GLOBALS['pfb_test_info_boxes']);
		$this->assertCount(2, $boxes, 'one box per scope left alone');
		$this->assertSame(array_map(static fn (string $text): array => [$text, 'warning'], pfb_dns_listen_foreign_warnings()), array_map(static fn (array $box): array => [$box[0], $box[1]], $boxes));
	}
}
