<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/** Issue #3694: naming an automatic Resolver VIP in the DoH list must not make it selectable for 443 advertisement. */
#[CoversFunction('pfb_dns_proxy_ddr_doh_443_options')]
#[CoversFunction('pfb_validate_dns_proxy_listeners_post')]
#[CoversFunction('pfb_dns_proxy_listeners_stored')]
#[CoversFunction('pfb_dns_proxy_ddr_doh_443_addresses')]
#[CoversFunction('pfb_dns_proxy_ddr_flags')]
final class DnsProxyDdrDoh443AutoVipSelectionTest extends TestCase
{
	private const FIELD = 'pfb_dns_ddr_doh_443_interfaces';
	private const GLOBALS = [
		'config', 'pfb', 'pfb_test_vip_list', 'pfb_test_configured_subnets', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6',
		'pfb_test_interface_info', 'pfb_test_configured_ip_addresses', 'pfb_test_interfaces',
	];

	/** @var array<string,array{bool,mixed}> */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_vip_list'] = ['_vipauto4' => '172.16.53.53', '_vipuser6' => 'fd12:3456::9'];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		unset($GLOBALS['pfb_test_configured_ip_addresses']);
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$this->store('pfb_dns_interface', 'lan');
		$this->store('pfb_dns_doh_interface', 'lan,_vipauto4,_vipuser6');
		$this->store('pfb_dns_listen_vip', 'on');
		$this->store('pfb_dns_listen_vip4', 'auto');
		$this->store('pfb_dns_listen_auto4', '172.16.53.53');
		$this->store('pfb_dns_listen_vip6', '_vipuser6');
		config_set_path('virtualip/vip', [
			['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => '172.16.53.53', 'subnet_bits' => '32',
				'descr' => 'pfB_DNS_LISTEN_VIP_v4', 'uniqid' => 'auto4'],
			['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => 'fd12:3456::9', 'subnet_bits' => '128',
				'descr' => 'operator VIP', 'uniqid' => 'user6'],
		]);
		$this->assertSame(['172.16.53.53' => '_vipauto4', 'fd12:3456::9' => '_vipuser6'], pfb_dns_listen_vips(), 'premise: both Resolver VIPs are active');
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

	private function store(string $key, string $value): void
	{
		config_set_path(PFB_SECTIONS[explode('/', pfb_dns_config_key($key), 2)[0]] . '/' . $key, $value);
	}

	/** @param list<string> $selected @return array<string,mixed> */
	private function post(array $selected): array
	{
		return [
			'pfb_dns_interface' => ['lan'],
			'pfb_dns_dot' => '', 'pfb_dns_dot_port' => '853', 'pfb_dns_dot_interface' => ['lan'],
			'pfb_dns_doh' => '', 'pfb_dns_doh_port' => '4443', 'pfb_dns_doh_interface' => ['lan', '_vipauto4', '_vipuser6'],
			'pfb_dns_doh_trusted' => '',
			'pfb_dns_doq' => '', 'pfb_dns_doq_port' => '853', 'pfb_dns_doq_interface' => ['lan'],
			'pfb_dns_sslcertref' => '', 'pfb_dns_name' => 'fw.example.lan', 'pfb_dns_ddr' => '',
			self::FIELD => $selected,
		];
	}

	public function testStoredDohTokensDoNotOfferTheAutomaticVipButKeepLanAndTheManualVip(): void
	{
		$this->assertSame(['lan' => 'LAN', '_vipuser6' => 'fd12:3456::9'], pfb_dns_proxy_ddr_doh_443_options());
	}

	public function testPostingTheAutomaticVipInBothListsIsRejected(): void
	{
		$post = $this->post(['_vipauto4']);
		$this->assertSame(
			['Advertise DoH on port 443: Invalid selection: _vipauto4'],
			pfb_validate_dns_proxy_listeners_post($post, ['lan', '_vipauto4', '_vipuser6'], [])
		);
	}

	public function testPostingLanAndTheManualVipIsStillAcceptedAndStored(): void
	{
		$post = $this->post(['lan', '_vipuser6']);
		$this->assertSame([], pfb_validate_dns_proxy_listeners_post($post, ['lan', '_vipauto4', '_vipuser6'], []));
		$this->assertSame('lan,_vipuser6', pfb_dns_proxy_listeners_stored($post)[self::FIELD] ?? NULL);
	}

	public function testStoredAutomaticVipSelectionDoesNotOverrideItsActualBoundPort(): void
	{
		$this->store('pfb_dns_doh', 'on');
		$this->store('pfb_dns_doh_port', '4443');
		$this->store(self::FIELD, 'lan,_vipauto4,_vipuser6');
		$this->assertSame(
			['192.0.2.1', 'fd12:3456::9'],
			pfb_dns_proxy_ddr_doh_443_addresses(),
			'a migrated or retained automatic VIP token must not force 443; its actual listener determines DDR'
		);
	}

	public function testStoredAutomaticVipTokenAddsNoDdrPortOverrideFlag(): void
	{
		$this->store('pfb_dns_doh', 'on');
		$this->store('pfb_dns_doh_port', '4443');
		$this->store('pfb_dns_ddr', 'on');
		$this->store('pfb_dns_name', 'fw.example.lan');
		$this->store(self::FIELD, 'lan,_vipauto4,_vipuser6');
		$flags = pfb_dns_proxy_ddr_flags();
		$this->assertStringContainsString(" --ddr-doh-443 '192.0.2.1'", $flags);
		$this->assertStringContainsString(" --ddr-doh-443 'fd12:3456::9'", $flags);
		$this->assertStringNotContainsString(" --ddr-doh-443 '172.16.53.53'", $flags);
	}
}
