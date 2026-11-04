<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ADR-36/#3400/#3694: pin the redirect target of each family on assigned and fallback interfaces. The IPv6 target is an address the
 * DNS service answering port 53 listens on: `<iface>ip` when that interface's IPv6 address is one it serves, else the active IPv6
 * Resolver VIP, else today's target. pfB-DNS serves its plain DNS list; with pfB-DNS off the Resolver serves its own interfaces.
 */
#[CoversFunction('pfb_dns_redirect_rule')]
final class DnsRedirectRuleBuilderTest extends TestCase
{
	private const VIP6 = 'fd00:53:53:53:53:53:53:53';
	private const VIP4 = '192.0.2.53';
	private const LAN6 = '2001:db8:1::1';
	private const OPT6 = '2001:db8:2::1';

	private const GLOBALS = [
		'config', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info', 'pfb_test_configured_ip_addresses',
		'pfb_test_interfaces',
	];

	private array $saved = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = ['aliases' => ['alias' => []]];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1', 'opt1' => '192.0.2.129'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => self::LAN6, 'opt1' => self::OPT6];
		$GLOBALS['pfb_test_configured_ip_addresses'] = ['lan' => '192.0.2.1', 'opt1' => '192.0.2.129'];
		$GLOBALS['pfb_test_interface_info'] = [];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN', 'opt1' => 'OPT1'];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	/** pfB-DNS fronts the Resolver (its snapshot exists) and serves plain DNS on $plainInterfaces. */
	private function pfbDnsServes(string $plainInterfaces): void
	{
		PfbConfig::writeSystem('dns/pfb_dns_saved', base64_encode((string) json_encode([
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		])));
		PfbConfig::write('dns/pfb_dns_interface', $plainInterfaces);
		config_set_path('unbound/active_interface', 'lo0');
	}

	/** pfB-DNS is off and the Resolver listens on $active ('' = every interface, as an unset list does). */
	private function resolverServes(string $active): void
	{
		PfbConfig::writeSystem('dns/pfb_dns_saved', '');
		config_set_path('unbound/active_interface', $active);
	}

	/** An active Resolver VIP of each family named: 4 and/or 6. */
	private function resolverVips(int ...$families): void
	{
		$rows = [];
		foreach ($families as $family) {
			$address = $family === 6 ? self::VIP6 : self::VIP4;
			$rows[] = ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address,
				'subnet_bits' => $family === 6 ? '128' : '32', 'descr' => 'listener VIP', 'uniqid' => "v{$family}"];
			PfbConfig::write("gen/pfb_dns_listen_vip{$family}", "_vipv{$family}");
		}
		PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
		config_set_path('virtualip/vip', $rows);
	}

	private function target6(string $iface): string
	{
		return pfb_dns_redirect_rule($iface, 'inet6', '')['target'];
	}

	public function testIpv4RowIsTheAdr36Shape(): void
	{
		$this->assertSame(
			[
				'source'             => ['any' => ''],
				'destination'        => ['network' => '(self)', 'not' => '', 'port' => '53'],
				'ipprotocol'         => 'inet',
				'protocol'           => 'tcp/udp',
				'target'             => '127.0.0.1',
				'local-port'         => '53',
				'interface'          => 'lan',
				'descr'              => 'pfB_DNS_Redirect_lan_v4',
				'associated-rule-id' => 'pass',
				'natreflection'      => 'disable',
			],
			pfb_dns_redirect_rule('lan', 'inet', '')
		);
	}

	public function testIpv6RowOnLanTargetsTheLanAddressKeyword(): void
	{
		$this->assertSame(
			[
				'source'             => ['any' => ''],
				'destination'        => ['network' => '(self)', 'not' => '', 'port' => '53'],
				'ipprotocol'         => 'inet6',
				'protocol'           => 'tcp/udp',
				'target'             => 'lanip',
				'local-port'         => '53',
				'interface'          => 'lan',
				'descr'              => 'pfB_DNS_Redirect_lan_v6',
				'associated-rule-id' => 'pass',
				'natreflection'      => 'disable',
			],
			pfb_dns_redirect_rule('lan', 'inet6', '')
		);
	}

	#[DataProvider('assignedInterfaces')]
	public function testIpv6TargetOnAssignedInterfaceIsItsAddressKeyword(string $iface): void
	{
		$this->assertSame("{$iface}ip", $this->target6($iface));
	}

	public static function assignedInterfaces(): array
	{
		return ['wan' => ['wan'], 'lan' => ['lan'], 'opt1' => ['opt1'], 'opt12' => ['opt12']];
	}

	#[DataProvider('fallbackInterfaces')]
	public function testIpv6TargetOnOtherInterfaceStaysLoopback(string $iface): void
	{
		$this->assertSame('::1', $this->target6($iface));
	}

	public static function fallbackInterfaces(): array
	{
		return [
			'enc0' => ['enc0'], 'openvpn' => ['openvpn'], 'l2tp' => ['l2tp'],
			'wireguard' => ['wireguard'], 'wlan0' => ['wlan0'], 'lan2' => ['lan2'], 'opt1x' => ['opt1x'],
		];
	}

	#[DataProvider('assignedInterfaces')]
	public function testIpv4TargetOnAssignedInterfaceIsLoopback(string $iface): void
	{
		$this->assertSame('127.0.0.1', pfb_dns_redirect_rule($iface, 'inet', '')['target']);
	}

	#[DataProvider('fallbackInterfaces')]
	public function testIpv4TargetOnOtherInterfaceStaysLoopback(string $iface): void
	{
		$this->assertSame('127.0.0.1', pfb_dns_redirect_rule($iface, 'inet', '')['target']);
	}

	public function testUsableExceptionAliasBecomesNegatedSourceForBothFamilies(): void
	{
		$GLOBALS['config']['aliases']['alias'] = [['name' => 'DNS_Exceptions', 'type' => 'network']];

		foreach (['inet', 'inet6'] as $family) {
			$this->assertSame(
				['address' => 'DNS_Exceptions', 'not' => ''],
				pfb_dns_redirect_rule('lan', $family, 'DNS_Exceptions')['source'],
				$family
			);
		}
	}

	// -----------------------------------------------------------------------
	// pfB-DNS fronts the Resolver: its plain DNS list is the listen set
	// -----------------------------------------------------------------------

	/** The interface's own address is served, so it stays the target whether or not a VIP is also served. */
	public function testPfbDnsServingTheInterfaceAddressKeepsTheAddressKeywordWithOrWithoutAnIpv6Vip(): void
	{
		$this->pfbDnsServes('lan,lo0');
		$this->assertSame('lanip', $this->target6('lan'), 'no VIP');

		$this->resolverVips(4, 6);
		$this->assertSame('lanip', $this->target6('lan'), 'an active IPv6 VIP does not displace an address that is served');
	}

	/** The interface's address is not served and an IPv6 VIP is: that VIP is the one address DNS listens on that FreeBSD delivers. */
	#[DataProvider('assignedInterfaces')]
	public function testPfbDnsNotServingTheInterfaceAddressTargetsTheIpv6Vip(string $iface): void
	{
		$GLOBALS['pfb_test_configured_ipv6'][$iface] = '2001:db8:9::1';
		$this->pfbDnsServes('lo0');
		$this->resolverVips(4, 6);

		$this->assertSame(self::VIP6, $this->target6($iface));
	}

	#[DataProvider('fallbackInterfaces')]
	public function testPfbDnsTargetsTheIpv6VipOnAnInterfaceThatHasNoAddressKeyword(string $iface): void
	{
		$this->pfbDnsServes('lo0');
		$this->resolverVips(6);

		$this->assertSame(self::VIP6, $this->target6($iface));
	}

	public function testPfbDnsNotServingTheInterfaceAddressKeepsTodaysTargetWithoutAnIpv6Vip(): void
	{
		$this->pfbDnsServes('lo0');
		$this->assertSame('lanip', $this->target6('lan'), 'no VIP at all');
		$this->assertSame('::1', $this->target6('enc0'), 'no VIP at all, fallback interface');

		$this->resolverVips(4);
		$this->assertSame('lanip', $this->target6('lan'), 'an IPv4 VIP is no IPv6 listener');
		$this->assertSame('::1', $this->target6('enc0'), 'an IPv4 VIP is no IPv6 listener, fallback interface');
	}

	/** A listener on another interface does not serve this one's address. */
	public function testPfbDnsServingAnotherInterfaceDoesNotServeThisOnesAddress(): void
	{
		$this->pfbDnsServes('opt1,lo0');
		$this->resolverVips(6);

		$this->assertSame(self::VIP6, $this->target6('lan'));
		$this->assertSame('opt1ip', $this->target6('opt1'));
	}

	// -----------------------------------------------------------------------
	// pfB-DNS off: the Resolver's own interfaces are the listen set
	// -----------------------------------------------------------------------

	#[DataProvider('resolverOnEveryInterface')]
	public function testResolverOnEveryInterfaceKeepsTheAddressKeywordWhateverTheVip(string $active): void
	{
		$this->resolverServes($active);
		$this->assertSame('lanip', $this->target6('lan'), 'no VIP');

		$this->resolverVips(6);
		$this->assertSame('lanip', $this->target6('lan'), 'an IPv6 VIP');
	}

	public static function resolverOnEveryInterface(): array
	{
		return ['unset list' => [''], 'all' => ['all'], 'all among others' => ['lo0,all']];
	}

	public function testResolverNotListeningOnTheInterfaceTargetsTheIpv6VipAndElseKeepsTodaysTarget(): void
	{
		$this->resolverServes('opt1');
		$this->assertSame('lanip', $this->target6('lan'), 'no VIP: today\'s target');

		$this->resolverVips(6);
		$this->assertSame(self::VIP6, $this->target6('lan'), 'an IPv6 VIP');
		$this->assertSame('opt1ip', $this->target6('opt1'), 'the interface it does listen on');
	}

	// -----------------------------------------------------------------------
	// The rest of the row
	// -----------------------------------------------------------------------

	#[DataProvider('assignedInterfaces')]
	public function testIpv4TargetStaysLoopbackWhateverIsListeningAndWhateverVipIsActive(string $iface): void
	{
		$this->pfbDnsServes('lo0');
		$this->resolverVips(4, 6);

		$this->assertSame('127.0.0.1', pfb_dns_redirect_rule($iface, 'inet', '')['target']);
	}

	public function testOnlyTheTargetOfTheIpv6RowMovesSoTheStoredKeyOrderHolds(): void
	{
		$this->pfbDnsServes('lan,lo0');
		$served = pfb_dns_redirect_rule('lan', 'inet6', 'DNS_Exceptions');

		$this->pfbDnsServes('lo0');
		$this->resolverVips(6);
		$vip = pfb_dns_redirect_rule('lan', 'inet6', 'DNS_Exceptions');

		$this->assertSame(array_replace($served, ['target' => self::VIP6]), $vip, 'the stored key order is the sync change-detection order');
	}
}
