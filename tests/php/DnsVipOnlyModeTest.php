<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Explicit opt-in changes client endpoints, never administrator-owned DNS lists. */
final class DnsVipOnlyModeTest extends TestCase
{
	private const VIP4 = '172.16.53.53';
	private const VIP6 = 'fd00:53:53:53:53:53:53:53';
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['config', 'pfb', 'pfb_test_vip_list', 'pfb_test_configured_subnets', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info', 'pfb_test_interfaces', 'pfb_test_configured_ip_addresses', 'pfb_test_write_config_calls', 'pfb_test_unbound_configure_calls', 'pfb_test_dhcpd_configure_calls'] as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1', 'wan' => '8.8.4.4', 'lo0' => '127.0.0.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1', 'lo0' => '::1'];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN', 'wan' => 'WAN'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE], 'wan' => ['status' => 'up', 'enable' => TRUE]];
		unset($GLOBALS['pfb_test_configured_ip_addresses']);
		PfbConfig::write('dns/pfb_dns', 'on');
		PfbConfig::write('dns/pfb_dns_interface', 'lan');
		PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
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

	private function mode(bool $on): void
	{
		// Raw stored input also exercises old installations where the new key was absent.
		config_set_path(PFB_SECTIONS['gen'] . '/pfb_dns_listen_vip_only', $on ? 'on' : '');
	}

	private function vips(array $families, bool $managed = FALSE): void
	{
		$rows = [];
		foreach ([4 => self::VIP4, 6 => self::VIP6] as $family => $address) {
			$selected = in_array($family, $families, TRUE);
			PfbConfig::write("gen/pfb_dns_listen_vip{$family}", $selected ? ($managed ? 'auto' : "_vipv{$family}") : '');
			PfbConfig::write("gen/pfb_dns_listen_auto{$family}", $selected && $managed ? $address : '');
			if ($selected) {
				$rows[] = ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address,
					'subnet_bits' => $family === 4 ? '32' : '128', 'descr' => $managed ? "pfB_DNS_LISTEN_VIP_v{$family}" : 'operator', 'uniqid' => "v{$family}"];
			}
		}
		config_set_path('virtualip/vip', $rows);
	}

	public static function endpoints(): iterable
	{
		foreach (['plain', 'dot', 'doh', 'doq'] as $kind) {
			foreach (['v4' => [[4], [self::VIP4]], 'v6' => [[6], [self::VIP6]], 'dual' => [[4, 6], [self::VIP4, self::VIP6]], 'missing' => [[], []]] as $label => [$families, $wanted]) {
				foreach ([FALSE, TRUE] as $managed) {
					foreach (['lan', 'all', 'lo0', 'down'] as $selection) {
						yield "{$kind}-{$label}-" . ($managed ? 'managed' : 'manual') . "-{$selection}" => [$kind, $families, $wanted, $managed, $selection];
					}
				}
			}
		}
	}

	#[DataProvider('endpoints')]
	public function testEveryTransportUsesOnlyActiveVipsWithoutMissingFamilyFallback(string $kind, array $families, array $wanted, bool $managed, string $selection): void
	{
		$this->vips($families, $managed);
		if ($selection === 'down') {
			$GLOBALS['pfb_test_interface_info']['down'] = ['status' => 'down', 'enable' => TRUE];
		}
		$interfaces = [$selection];
		$this->mode(FALSE);
		$before = pfb_dns_proxy_interface_addresses($interfaces, pfb_dns_proxy_vip_only_families($kind));
		if ($selection === 'lan') {
			$this->assertSame(['192.0.2.1', '2001:db8::1', ...$wanted], $before, 'mode off retains ordinary endpoints');
		}
		$this->mode(TRUE);
		$this->assertSame([4, 6], pfb_dns_proxy_vip_only_families($kind));
		$this->assertSame($wanted, pfb_dns_proxy_interface_addresses($interfaces, pfb_dns_proxy_vip_only_families($kind)), 'no interface/public fallback, including unavailable VIP families');
		$this->assertSame($wanted, pfb_dns_proxy_listen());
	}

	public function testNameAnswersUseTheVipPairAlsoOnInternalLoopback(): void
	{
		$this->vips([4, 6]);
		$this->mode(FALSE);
		$this->assertSame(['192.0.2.1', '2001:db8::1'], pfb_dns_proxy_name_answers()['192.0.2.1'] ?? NULL);
		$this->assertArrayNotHasKey('127.0.0.1', pfb_dns_proxy_name_answers());
		$this->mode(TRUE);
		$this->assertSame([
			self::VIP4 => [self::VIP4, self::VIP6], self::VIP6 => [self::VIP4, self::VIP6],
			'127.0.0.1' => [self::VIP4, self::VIP6], '::1' => [self::VIP4, self::VIP6],
		], pfb_dns_proxy_name_answers());
		$this->vips([6]);
		$this->assertSame([self::VIP6 => [self::VIP6], '127.0.0.1' => [self::VIP6], '::1' => [self::VIP6]], pfb_dns_proxy_name_answers());
		$this->vips([]);
		$this->assertSame(['127.0.0.1' => [], '::1' => []], pfb_dns_proxy_name_answers(), 'missing VIPs keep loopback ownership without interface answers');
	}

	public function testStoredModeIsDormantWhenPfbDnsIsDisabled(): void
	{
		$this->vips([4]);
		$this->mode(TRUE);
		PfbConfig::write('dns/pfb_dns', '');
		$this->assertSame(['192.0.2.1', '2001:db8::1', self::VIP4], pfb_dns_proxy_interface_addresses(['lan'], []));
		$this->assertSame([], pfb_dns_proxy_vip_only_families('plain'));
		config_set_path('unbound/active_interface', 'lan');
		pfb_dns_listen_vips_apply();
		$this->assertContains('lan', pfb_dns_proxy_tokens(config_get_path('unbound/active_interface')), 'standalone Resolver interfaces remain administrator-owned');
	}

	private function validate(array $post): array
	{
		return pfb_validate_dns_listen_vip_only_post($post);
	}

	private function post(): array
	{
		return ['pfb_dns_listen_vip_only' => 'on', 'pfb_dns_listen_vip' => 'on', 'pfb_dns_listen_vip4' => 'auto', 'pfb_dns_listen_vip6' => 'auto'];
	}

	public function testActivationChecksProspectiveFamiliesBeforeCreatingAutomaticVips(): void
	{
		$before = $GLOBALS['config'];
		$this->assertSame([], $this->validate($this->post()));
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame([], config_get_path('virtualip/vip', []));
		PfbConfig::write('dns/pfb_dns', '');
		$this->assertNotEmpty($this->validate($this->post()), 'pfB-DNS must be enabled');
		PfbConfig::write('dns/pfb_dns', 'on');
		$this->assertNotEmpty($this->validate(array_replace($this->post(), ['pfb_dns_listen_vip' => ''])), 'Resolver addresses must be enabled');
		$this->assertNotEmpty($this->validate(array_replace($this->post(), ['pfb_dns_listen_vip4' => 'none', 'pfb_dns_listen_vip6' => ''])), 'at least one family is required');
		$this->assertSame([], $this->validate(['pfb_dns_listen_vip_only' => '']), 'disable is unconditional');
	}

	public function testOwnDnsListsRemainAppendOnlyAndSharedRaListIsNotInvented(): void
	{
		$this->vips([4, 6]);
		config_set_path('dhcpd/lan/dnsserver', ['192.0.2.1']);
		config_set_path('dhcpdv6/lan', ['dnsserver' => ['2001:db8::1'], 'radnsserver' => ['2001:db8::1']]);
		$this->mode(TRUE);
		pfb_dns_listen_vips_apply();
		$this->assertSame(['192.0.2.1', self::VIP4], config_get_path('dhcpd/lan/dnsserver'));
		$this->assertSame(['2001:db8::1', self::VIP6], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertSame(['2001:db8::1', self::VIP6], config_get_path('dhcpdv6/lan/radnsserver'));
		config_set_path('dhcpdv6/lan/rasamednsasdhcp6', '');
		config_set_path('dhcpdv6/lan/radnsserver', ['2001:db8:99::99']);
		$this->assertSame([], $this->validate($this->post()), 'unused RA override is not an active custom list');
		pfb_dns_listen_vips_apply();
		$this->assertSame(['2001:db8:99::99'], config_get_path('dhcpdv6/lan/radnsserver'));
		$this->mode(FALSE);
		pfb_dns_listen_vips_apply();
		$this->assertSame(['192.0.2.1', self::VIP4], config_get_path('dhcpd/lan/dnsserver'), 'changing listener mode never removes pre-existing DNS servers');
		$this->mode(TRUE);
		config_set_path('dhcpd/lan/dnsserver', ['203.0.113.53']);
		$foreign = config_get_path('dhcpd/lan/dnsserver');
		pfb_dns_listen_vips_apply();
		$this->assertSame($foreign, config_get_path('dhcpd/lan/dnsserver'), 'subsequent core-page custom lists stay byte-identical');
		config_set_path('dhcpd/unknown/dnsserver', ['198.51.100.53']);
		pfb_dns_listen_vips_apply();
		$this->assertSame(['198.51.100.53'], config_get_path('dhcpd/unknown/dnsserver'), 'frozen lists remain untouched on apply');
	}

	public function testDefaultOffRoundtripAndPolicyProjection(): void
	{
		$key = 'gen/pfb_dns_listen_vip_only';
		$this->assertArrayHasKey($key, pfb_cfg_registry());
		$this->assertSame(PfbToggle::Off, PfbConfig::read($key));
		$this->assertSame($key, pfb_dns_config_key('pfb_dns_listen_vip_only'));
		PfbConfig::write($key, 'on');
		$this->assertSame(PfbToggle::On, PfbConfig::read($key));
		$sections = ['pfblockerng' => ['config' => [PfbConfig::readSection(PFB_SECTIONS['gen'])]]];
		$this->assertSame('on', pfb_sync_policy_projection($sections)[PFB_SECTIONS['gen'] . '/pfb_dns_listen_vip_only'] ?? NULL);
		$merged = pfb_sync_policy_merge($sections, []);
		$this->assertSame('on', $merged['pfblockerng']['config'][0]['pfb_dns_listen_vip_only'] ?? NULL);
		PfbConfig::write($key, PfbToggle::Off);
		$this->assertSame('', config_get_path(PFB_SECTIONS['gen'] . '/pfb_dns_listen_vip_only'));
	}
}
