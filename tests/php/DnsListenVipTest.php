<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Issue #3688: dedicated DNS listener VIPs never own the DNSBL sinkholes. */
final class DnsListenVipTest extends TestCase
{
	private const V6 = 'fd00:53:53:53:53:53:53:53';
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['config', 'pfb', 'pfb_test_vip_list', 'pfb_test_configured_subnets', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info', 'pfb_test_write_config_calls', 'pfb_test_vip_bring_down_calls', 'pfb_test_ipalias_configure_calls'] as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_vip_bring_down_calls'] = [];
		$GLOBALS['pfb_test_ipalias_configure_calls'] = [];
		PfbConfig::write('dns/pfb_dns_interface', 'lan');
		config_set_path('unbound/active_interface', 'lan');
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $name => [$exists, $value]) {
			if ($exists) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	private function put(string $key, mixed $value): void
	{
		$home = str_starts_with($key, 'pfb_dns_listen_') ? 'gen/' : 'dns_shared/';
		$this->assertArrayHasKey($home . $key, pfb_cfg_registry(), 'the setting has its registered General or transport home');
		PfbConfig::write($home . $key, $value);
	}

	private function apply(): void
	{
		$this->assertTrue(function_exists('pfb_dns_listen_vips_apply'), 'save/apply must provision and advertise dedicated listener VIPs immediately');
		pfb_dns_listen_vips_apply();
	}

	private function vip(string $address, string $id = 'chosen', string $descr = 'operator VIP'): array
	{
		return ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address,
			'subnet_bits' => str_contains($address, ':') ? '128' : '32', 'descr' => $descr, 'uniqid' => $id];
	}

	public function testAbsentOptionIsOffAndDoesNotChangeListenersOrConfiguration(): void
	{
		$this->assertArrayHasKey('gen/pfb_dns_listen_vip', pfb_cfg_registry());
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_dns_listen_vip'));
		$before = $GLOBALS['config'];
		$this->apply();
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame(['192.0.2.1', '2001:db8::1'], pfb_dns_proxy_interface_addresses(['lan'], []));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	#[DataProvider('noSelection')]
	public function testEmptyNoneAndDeletedSelectionsDoNotSubstituteOrAdvertise(string $id): void
	{
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip6', $id);
		config_set_path('dhcpdv6/lan', ['dnsserver' => ['2001:db8::53']]);
		$this->apply();
		$this->assertSame(['192.0.2.1', '2001:db8::1'], pfb_dns_proxy_interface_addresses(['lan'], []));
		$this->assertSame(['2001:db8::53'], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertSame([], config_get_path('virtualip/vip', []));
	}

	public static function noSelection(): array
	{
		return [[''], ['none'], ['_vip_gone_old']];
	}

	public function testSelectedIpv6JoinsTheInterfaceAddressesAndPreservesUserVipOnDisable(): void
	{
		config_set_path('virtualip/vip', [$this->vip(self::V6)]);
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip6', '_vipchosen');
		$this->apply();
		$this->assertSame(['192.0.2.1', '2001:db8::1', self::V6], pfb_dns_proxy_interface_addresses(['lan'], []), 'the IPv6 VIP joins the addresses and adds no IPv4 one');
		$this->assertSame(['192.0.2.1', self::V6], pfb_dns_proxy_interface_addresses(['lan'], [6]), 'where it stands in, it takes the IPv6 address\'s place only');
		$this->assertContains('_vipchosen', pfb_dns_proxy_tokens(config_get_path('unbound/active_interface')));
		$this->put('pfb_dns_listen_vip', '');
		$this->apply();
		$this->assertSame([$this->vip(self::V6)], config_get_path('virtualip/vip'));
		$this->assertSame('lan', config_get_path('unbound/active_interface'));
	}

	/** @return array<string,array{0:list<int>,1:list<string>}> families whose VIP stands in for the addresses, the addresses listened on */
	public static function vipOnlyFamilies(): array
	{
		return [
			'no family: both VIPs join' => [[], ['192.0.2.1', '2001:db8::1', '172.16.53.53', self::V6]],
			'IPv4: its VIP takes the IPv4 address\'s place, the IPv6 VIP joins' => [[4], ['172.16.53.53', '2001:db8::1', self::V6]],
			'IPv6: its VIP takes the IPv6 address\'s place, the IPv4 VIP joins' => [[6], ['192.0.2.1', self::V6, '172.16.53.53']],
			'both families: the VIPs take both places' => [[4, 6], ['172.16.53.53', self::V6]],
		];
	}

	/**
	 * @param list<int> $vipOnly
	 * @param list<string> $expected
	 */
	#[DataProvider('vipOnlyFamilies')]
	public function testAFamilyListedAsVipOnlyHasItsVipTakeThePlaceOfItsAddresses(array $vipOnly, array $expected): void
	{
		config_set_path('virtualip/vip', [$this->vip('172.16.53.53', 'chosen4'), $this->vip(self::V6, 'chosen6')]);
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip4', '_vipchosen4');
		$this->put('pfb_dns_listen_vip6', '_vipchosen6');
		$this->assertSame($expected, pfb_dns_proxy_interface_addresses(['lan'], $vipOnly));
	}

	public function testAutoIpv6CreatesOnlyDedicated128AndNeverDeletesDnsblVip(): void
	{
		$sinkhole = $this->vip('fd00:53:53:53:53:53:53:1', 'sink', 'pfB_AUTO_VIP_v6');
		config_set_path('virtualip/vip', [$sinkhole]);
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip6', 'auto');
		$this->apply();
		$vips = config_get_path('virtualip/vip');
		$this->assertCount(2, $vips);
		$this->assertSame(self::V6, $vips[1]['subnet']);
		$this->assertSame('128', $vips[1]['subnet_bits']);
		$this->assertSame('ipalias', $vips[1]['mode']);
		$this->assertNotSame('pfB_AUTO_VIP_v6', $vips[1]['descr']);
		$this->assertSame(self::V6, PfbConfig::read('gen/pfb_dns_listen_auto6'));
		$this->put('pfb_dns_listen_vip', '');
		$this->put('pfb_dns_listen_vip6', '');
		$this->apply();
		$this->assertSame([$sinkhole], config_get_path('virtualip/vip'));
	}

	public function testAutoIpv6SkipsOccupiedAddress(): void
	{
		config_set_path('virtualip/vip', [$this->vip(self::V6)]);
		$GLOBALS['pfb_test_vip_list'] = ['_vipchosen' => self::V6];
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip6', 'auto');
		$this->apply();
		$this->assertCount(2, config_get_path('virtualip/vip'));
		$this->assertSame('fd00:53:53:53:53:53:53:54', config_get_path('virtualip/vip/1/subnet'));
		$this->assertSame(['192.0.2.1', '2001:db8::1', 'fd00:53:53:53:53:53:53:54'], pfb_dns_proxy_interface_addresses(['lan'], []));
	}

	#[DataProvider('v4Conflicts')]
	public function testAutoIpv4UsesFirstFreeNonSinkholeAddress(array $subnets, ?string $expected): void
	{
		$GLOBALS['pfb_test_configured_subnets'] = $subnets;
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip4', 'auto');
		$this->apply();
		$vips = config_get_path('virtualip/vip', []);
		$this->assertSame($expected, $vips[0]['subnet'] ?? NULL);
		$this->assertSame($expected === NULL ? [] : [$expected], array_column($vips, 'subnet'));
	}

	public static function v4Conflicts(): array
	{
		return [
			[[], '172.16.53.53'], [['172.16.0.0/12'], '192.168.53.53'],
			[['172.16.0.0/12', '192.168.0.0/16'], '10.53.53.53'],
			[['172.16.0.0/12', '192.168.0.0/16', '10.0.0.0/8'], NULL],
		];
	}

	public function testMarkedListenerVipIsReusedRegardlessOfItsOldAddress(): void
	{
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip6', 'auto');
		$this->apply();
		$rows = config_get_path('virtualip/vip');
		$rows[0]['subnet'] = 'fd00:53:53:53:53:53:53:1';
		config_set_path('virtualip/vip', $rows);
		$this->apply();
		$this->assertSame($rows, config_get_path('virtualip/vip'));
		$this->assertSame(['192.0.2.1', '2001:db8::1', 'fd00:53:53:53:53:53:53:1'], pfb_dns_proxy_interface_addresses(['lan'], []));
	}

	#[DataProvider('raModes')]
	public function testAdvertisementsPreserveExistingServersAndTrackOnlyOwnInsertions(bool $same): void
	{
		config_set_path('virtualip/vip', [$this->vip(self::V6)]);
		config_set_path('dhcpdv6/lan', ['dnsserver' => ['2001:db8::1'], 'radnsserver' => ['2001:db8::1']] + ($same ? ['rasamednsasdhcp6' => ''] : []));
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip6', '_vipchosen');
		$this->apply();
		$this->apply();
		$this->assertSame(['2001:db8::1', self::V6], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertSame($same ? ['2001:db8::1'] : ['2001:db8::1', self::V6], config_get_path('dhcpdv6/lan/radnsserver'));
		$this->put('pfb_dns_listen_vip', '');
		$this->apply();
		$this->assertSame(['2001:db8::1'], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertSame(['2001:db8::1'], config_get_path('dhcpdv6/lan/radnsserver'));
	}

	public static function raModes(): array { return [[false], [true]]; }

	public function testPreexistingAdvertisementIsNotRemovedAndMissingDhcpIsNotCreated(): void
	{
		config_set_path('virtualip/vip', [$this->vip(self::V6)]);
		config_set_path('dhcpdv6/lan', ['dnsserver' => [self::V6], 'rasamednsasdhcp6' => '']);
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip6', '_vipchosen');
		$this->apply();
		$this->put('pfb_dns_listen_vip', '');
		$this->apply();
		$this->assertSame([self::V6], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertNull(config_get_path('dhcpd'));
		$this->assertSame(['lan'], array_keys(config_get_path('dhcpdv6')));
	}

	public function testIpv4AdvertisementAndProxyOnLeaveResolverOnLoopback(): void
	{
		config_set_path('virtualip/vip', [$this->vip('172.16.53.1')]);
		config_set_path('dhcpd/lan', ['dnsserver' => ['192.0.2.1']]);
		config_set_path('unbound/active_interface', 'lo0');
		PfbConfig::write('dns/pfb_dns', 'on');
		$this->put('pfb_dns_listen_vip', 'on');
		$this->put('pfb_dns_listen_vip4', '_vipchosen');
		$this->apply();
		$this->assertSame(['192.0.2.1', '2001:db8::1', '172.16.53.1'], pfb_dns_proxy_interface_addresses(['lan'], []), 'the VIP joins the interface addresses');
		$this->assertSame(['192.0.2.1', '172.16.53.1'], config_get_path('dhcpd/lan/dnsserver'));
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
	}

	public function testNewPolicyKeysActuallyProjectAndMergeWhileInterfaceStaysLocal(): void
	{
		foreach (['pfb_dns_listen_vip', 'pfb_dns_listen_vip4', 'pfb_dns_listen_vip6', 'pfb_dns_listen_auto4', 'pfb_dns_listen_auto6'] as $key) {
			$this->assertSame('policy', pfb_cfg_registry()['gen/' . $key]['sync'] ?? NULL, $key);
		}
		foreach (['pfb_dns_dot_port6', 'pfb_dns_doh_port6', 'pfb_dns_doq_port6'] as $key) {
			$this->assertSame('local', pfb_cfg_registry()['dns_shared/' . $key]['sync'] ?? NULL, $key);
		}
		// issue #3694: the per-interface DoH 443 selection is drawn from the node's own DoH interface list, so it stays with it
		$this->assertSame('local', pfb_cfg_registry()['dns/pfb_dns_ddr_doh_443_interfaces']['sync'] ?? NULL);
		$this->assertSame('local', pfb_cfg_registry()['gen/pfb_dns_listen_interface']['sync'] ?? NULL);
		$this->put('pfb_dns_listen_vip6', '_vipchosen');
		$sections = ['pfblockerng' => ['config' => [PfbConfig::readSection(PFB_SECTIONS['gen'])]]];
		$projection = pfb_sync_policy_projection($sections);
		$this->assertSame('_vipchosen', $projection[PFB_SECTIONS['gen'] . '/pfb_dns_listen_vip6'] ?? NULL);
		$merged = pfb_sync_policy_merge($sections, []);
		$this->assertSame('_vipchosen', $merged['pfblockerng']['config'][0]['pfb_dns_listen_vip6'] ?? NULL);
	}

	#[DataProvider('transports')]
	public function testFamilyPortsDefaultToIpv4AndCanDiffer(string $kind): void
	{
		PfbConfig::write('dns/pfb_dns_name', 'fw.example.lan');
		PfbConfig::write('dns_shared/pfb_dns_' . $kind, 'on');
		PfbConfig::write('dns_shared/pfb_dns_' . $kind . '_port', '8853');
		PfbConfig::write('dns/pfb_dns_' . $kind . '_interface', 'lan');
		$warnings = [];
		$this->assertStringNotContainsString('--' . $kind . '-port6', pfb_dns_proxy_tls_flags($warnings));
		$this->put('pfb_dns_' . $kind . '_port6', '443');
		$flags = pfb_dns_proxy_tls_flags($warnings);
		$this->assertStringContainsString('--' . $kind . "-port '8853'", $flags);
		$this->assertStringContainsString('--' . $kind . "-port6 '443'", $flags);
		$this->assertSame(['192.0.2.1', '2001:db8::1'], pfb_dns_proxy_listen());
	}

	public static function transports(): array { return [['dot'], ['doh'], ['doq']]; }

	#[DataProvider('badV6Ports')]
	public function testIpv6PortUsesExistingPortValidation(string $port): void
	{
		$post = ['pfb_dns_interface' => ['lan'], 'pfb_dns_sslcertref' => ''];
		foreach (['dot', 'doh', 'doq'] as $kind) {
			$post['pfb_dns_' . $kind . '_port'] = '853';
			$post['pfb_dns_' . $kind . '_port6'] = $port;
			$post['pfb_dns_' . $kind . '_interface'] = ['lan'];
		}
		$this->assertCount(3, pfb_validate_dns_proxy_listeners_post($post, ['lan'], []));
	}

	public static function badV6Ports(): array { return [['0'], ['65536'], ['bad']]; }

	public function testDnsblCandidatesUseDotOneWithoutMigratingMarkedVips(): void
	{
		$this->assertSame(['172.16.53.1', '192.168.53.1', '10.53.53.1'], pfb_dnsbl_vip_candidates(AF_INET));
		$this->assertSame(['fd00:53:53:53:53:53:53:1'], pfb_dnsbl_vip_candidates(AF_INET6));
	}
}
