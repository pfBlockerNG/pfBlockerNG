<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3694: a Resolver VIP (DNS > General > Resolver addresses) joins the addresses pfB-DNS listens on; it no longer takes the
 * place of the interface addresses. Hosts with a static DNS configuration keep resolving at the LAN address.
 *
 * Plain DNS, DoT and DoQ listen on the configured addresses plus each VIP. DoH does too, except for a family whose DoH port is
 * 443 or whose "Advertise DoH on port 443" option is on: port 443 on the interface address belongs to the webConfigurator and DDR
 * advertises the VIP there, so that family stays VIP-only. Loopback is unchanged. Every row asserts the before-state first (no
 * VIP) so that the VIP is what is shown to change the set, and drives the production surface each transport is served through.
 */
#[CoversFunction('pfb_dns_proxy_interface_addresses')]
#[CoversFunction('pfb_dns_proxy_plain_listen')]
#[CoversFunction('pfb_dns_proxy_tls_flags')]
#[CoversFunction('pfb_dns_proxy_ddr_warnings')]
final class DnsListenVipInterfaceAddressesTest extends TestCase
{
	private const LAN4 = '192.0.2.1';
	private const LAN6 = '2001:db8::1';
	private const VIP4 = '172.16.53.53';
	private const VIP6 = 'fd00:53:53:53:53:53:53:53';
	private const PUBLIC_LAN4 = '8.8.8.8';
	private const PUBLIC_VIP4 = '1.1.1.1';

	private const GLOBALS = [
		'config', 'pfb', 'pfb_test_vip_list', 'pfb_test_configured_subnets', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6',
		'pfb_test_interface_info', 'pfb_test_configured_ip_addresses', 'pfb_test_interfaces',
	];

	/** @var array<string,array{0:bool,1:mixed}> */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		unset($GLOBALS['pfb_test_configured_ip_addresses']);
		$this->lan([self::LAN4], [self::LAN6]);
		PfbConfig::write('dns/pfb_dns_interface', 'lan'); // seeded: an unseeded list makes every setting read as the Resolver's
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

	/** The LAN interface, up, with these addresses; an `lo0` entry is there for the loopback-only list. */
	private function lan(array $v4, array $v6): void
	{
		$GLOBALS['pfb_test_interface_ip'] = $v4 === [] ? [] : ['lan' => $v4[0], 'lo0' => '127.0.0.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = $v6 === [] ? [] : ['lan' => $v6[0]];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE], 'lo0' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
	}

	private function vip(string $address, string $id): array
	{
		return ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address,
			'subnet_bits' => str_contains($address, ':') ? '128' : '32', 'descr' => 'operator VIP', 'uniqid' => $id];
	}

	/** The Resolver addresses option on, with an operator VIP chosen for each family that is asked for. */
	private function vips(bool $v4, bool $v6, string $address4 = self::VIP4): void
	{
		$rows = array_values(array_filter([$v4 ? $this->vip($address4, 'v4') : NULL, $v6 ? $this->vip(self::VIP6, 'v6') : NULL]));
		config_set_path('virtualip/vip', $rows);
		PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
		PfbConfig::write('gen/pfb_dns_listen_vip4', $v4 ? '_vipv4' : '');
		PfbConfig::write('gen/pfb_dns_listen_vip6', $v6 ? '_vipv6' : '');
		$this->assertSame(
			array_values(array_filter([$v4 ? $address4 : NULL, $v6 ? self::VIP6 : NULL])),
			array_keys(pfb_dns_listen_vips()),
			'premise: the Resolver VIPs of the case are the active ones'
		);
	}

	/**
	 * The addresses a transport is served on, as the service asks for them: plain DNS from pfb_dns_proxy_plain_listen(), the encrypted
	 * transports from the --<kind>-listen arguments pfb_dns_proxy_tls_flags() gives (loopback included, which plain DNS adds itself).
	 *
	 * @return list<string>
	 */
	private function served(string $kind, string $interfaces = 'lan'): array
	{
		if ($kind === 'plain') {
			PfbConfig::write('dns/pfb_dns_interface', $interfaces);
			$warnings = [];
			return pfb_dns_proxy_plain_listen($warnings);
		}
		PfbConfig::write("dns_shared/pfb_dns_{$kind}", 'on');
		PfbConfig::write("dns/pfb_dns_{$kind}_interface", $interfaces);
		$warnings = [];
		$flags = pfb_dns_proxy_tls_flags($warnings);
		preg_match_all("/ --{$kind}-listen '([^']+)'/", $flags, $found);
		return $found[1];
	}

	/** @param list<string> $addresses the addresses of the interface list; the encrypted transports add loopback after them */
	private static function withLoopback(string $kind, array $addresses): array
	{
		return $kind === 'plain' ? $addresses : [...$addresses, ...PFB_DNS_PROXY_LOOPBACK];
	}

	// -----------------------------------------------------------------------
	// plain DNS, DoT, DoQ: the VIP is added
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:string,1:bool,2:bool,3:string,4:list<string>,5:list<string>}> kind, IPv4 VIP, IPv6 VIP, interface list, before, after */
	public static function addedVips(): array
	{
		$rows = [];
		foreach (['plain' => 'plain DNS', 'dot' => 'DoT', 'doq' => 'DoQ'] as $kind => $label) {
			$both = [self::LAN4, self::LAN6];
			$rows["{$label}, IPv4 VIP"] = [$kind, TRUE, FALSE, 'lan', $both, [...$both, self::VIP4]];
			$rows["{$label}, IPv6 VIP"] = [$kind, FALSE, TRUE, 'lan', $both, [...$both, self::VIP6]];
			$rows["{$label}, both VIPs"] = [$kind, TRUE, TRUE, 'lan', $both, [...$both, self::VIP4, self::VIP6]];
			$rows["{$label}, loopback-only list, both VIPs"] = [$kind, TRUE, TRUE, 'lo0', [], [self::VIP4, self::VIP6]];
		}
		return $rows;
	}

	/**
	 * @param list<string> $before
	 * @param list<string> $after
	 */
	#[DataProvider('addedVips')]
	public function testPlainDnsDotAndDoqKeepTheInterfaceAddressesAndAddTheVip(string $kind, bool $v4, bool $v6, string $interfaces, array $before, array $after): void
	{
		// Given the interface list and no Resolver VIP
		$this->assertSame(self::withLoopback($kind, $before), $this->served($kind, $interfaces), 'before: the configured addresses only');

		// When the Resolver VIP is set
		$this->vips($v4, $v6);

		// Then it is listened on besides the configured addresses
		$this->assertSame(self::withLoopback($kind, $after), $this->served($kind, $interfaces));
	}

	/** @return array<string,array{0:string}> */
	public static function addedKinds(): array
	{
		return ['plain DNS' => ['plain'], 'DoT' => ['dot'], 'DoQ' => ['doq']];
	}

	#[DataProvider('addedKinds')]
	public function testAnAddressTheListAlreadyHoldsAndTheVipIsListenedOnOnce(string $kind): void
	{
		// Given the list "all", which names the VIP's own address among the box's addresses
		$GLOBALS['pfb_test_configured_ip_addresses'] = ['lan' => self::LAN4, '_vipv4' => self::VIP4];
		$this->assertSame(self::withLoopback($kind, [self::LAN4, self::VIP4, self::LAN6]), $this->served($kind, 'all'), 'before: every address once');

		// When that address is the Resolver VIP
		$this->vips(TRUE, FALSE);

		// Then it is still listened on once, beside the other addresses
		$this->assertSame(self::withLoopback($kind, [self::LAN4, self::VIP4, self::LAN6]), $this->served($kind, 'all'));
	}

	#[DataProvider('addedKinds')]
	public function testAnInterfaceListThatServesNothingIsNotGivenTheVipAlone(string $kind): void
	{
		// Given a LAN that is down, so the list adds no address
		$GLOBALS['pfb_test_interface_info']['lan'] = ['status' => 'down', 'enable' => TRUE];
		$this->assertSame(self::withLoopback($kind, []), $this->served($kind), 'before: nothing');

		// When a Resolver VIP is set, then it stays nothing: the VIP is no substitute for the interface the admin chose
		$this->vips(TRUE, TRUE);
		$this->assertSame(self::withLoopback($kind, []), $this->served($kind));
	}

	// -----------------------------------------------------------------------
	// DoH: the VIP is added, but replaces the address of a family DDR advertises on port 443
	// -----------------------------------------------------------------------

	/**
	 * @return array<string,array{0:bool,1:bool,2:array<string,string>,3:list<string>,4:list<string>}> IPv4 VIP, IPv6 VIP, DoH settings,
	 *         listen set before the VIP, listen set after
	 */
	public static function dohRows(): array
	{
		$lan = [self::LAN4, self::LAN6];
		$not443 = ['dns_shared/pfb_dns_doh_port' => '4443'];
		$v4Replaced = ['dns_shared/pfb_dns_doh_port' => '443', 'dns_shared/pfb_dns_doh_port6' => '4443'];
		$v6Replaced = ['dns_shared/pfb_dns_doh_port' => '4443', 'dns_shared/pfb_dns_doh_port6' => '443'];
		return [
			'IPv4 VIP, port 4443, no 443 advertisement' => [TRUE, FALSE, $not443, $lan, [...$lan, self::VIP4]],
			'IPv6 VIP, port 4443, no 443 advertisement' => [FALSE, TRUE, $not443, $lan, [...$lan, self::VIP6]],
			'both VIPs, port 4443, no 443 advertisement' => [TRUE, TRUE, $not443, $lan, [...$lan, self::VIP4, self::VIP6]],
			'IPv4 VIP, DoH port 443: the VIP stands in for the IPv4 address' => [TRUE, FALSE, ['dns_shared/pfb_dns_doh_port' => '443'], $lan, [self::VIP4, self::LAN6]],
			'both VIPs, DoH port 443: the VIPs stand in for both addresses' => [TRUE, TRUE, ['dns_shared/pfb_dns_doh_port' => '443'], $lan, [self::VIP4, self::VIP6]],
			'both VIPs, IPv4 on 443 and IPv6 on its own port: only IPv4 is replaced' => [TRUE, TRUE, $v4Replaced, $lan, [self::VIP4, self::LAN6, self::VIP6]],
			'both VIPs, IPv6 on 443 and IPv4 on its own port: only IPv6 is replaced' => [TRUE, TRUE, $v6Replaced, $lan, [self::LAN4, self::VIP6, self::VIP4]],
			'IPv4 VIP, IPv6 on 443: IPv4 is added' => [TRUE, FALSE, $v6Replaced, $lan, [...$lan, self::VIP4]],
			'IPv6 VIP, IPv4 on 443: IPv6 is added' => [FALSE, TRUE, $v4Replaced, $lan, [...$lan, self::VIP6]],
			'IPv6 VIP only, DoH port 443: IPv6 has a VIP to stand in, IPv4 has none to' => [FALSE, TRUE, ['dns_shared/pfb_dns_doh_port' => '443'], $lan, [self::LAN4, self::VIP6]],
			'IPv4 VIP, IPv4 443 advertisement on: the VIP stands in for the IPv4 address' => [TRUE, FALSE, $not443 + ['dns_shared/pfb_dns_ddr_doh_443' => 'on'], $lan, [self::VIP4, self::LAN6]],
			'IPv6 VIP, IPv6 443 advertisement on: the VIP stands in for the IPv6 address' => [FALSE, TRUE, $not443 + ['dns_shared/pfb_dns_ddr_doh_443_6' => 'on'], $lan, [self::LAN4, self::VIP6]],
			'both VIPs, only the IPv4 advertisement on' => [TRUE, TRUE, $not443 + ['dns_shared/pfb_dns_ddr_doh_443' => 'on'], $lan, [self::VIP4, self::LAN6, self::VIP6]],
			'both VIPs, only the IPv6 advertisement on' => [TRUE, TRUE, $not443 + ['dns_shared/pfb_dns_ddr_doh_443_6' => 'on'], $lan, [self::LAN4, self::VIP6, self::VIP4]],
			'IPv4 VIP, IPv6 advertisement on: IPv4 is added' => [TRUE, FALSE, $not443 + ['dns_shared/pfb_dns_ddr_doh_443_6' => 'on'], $lan, [...$lan, self::VIP4]],
		];
	}

	/**
	 * @param array<string,string> $settings
	 * @param list<string> $before
	 * @param list<string> $after
	 */
	#[DataProvider('dohRows')]
	public function testDohAddsTheVipUnlessThatFamilyIsAdvertisedOnPort443(bool $v4, bool $v6, array $settings, array $before, array $after): void
	{
		// Given DoH on the LAN with these settings and no Resolver VIP
		foreach ($settings as $key => $value) {
			PfbConfig::write($key, $value);
		}
		$this->assertEqualsCanonicalizing(self::withLoopback('doh', $before), $this->served('doh'), 'before: the configured addresses only');

		// When the Resolver VIP is set
		$this->vips($v4, $v6);

		// Then the VIP is added for a family that is not on 443, and stands in for the address of one that is
		$listened = $this->served('doh');
		$this->assertEqualsCanonicalizing(self::withLoopback('doh', $after), $listened);
		$this->assertSame(array_values(array_unique($listened)), $listened, 'no address is listened on twice');
	}

	// -----------------------------------------------------------------------
	// DDR: the certificate warning names the addresses that are listened on now
	// -----------------------------------------------------------------------

	private static function warning(string $address, string $served): string
	{
		return "DDR: {$served} on {$address} will not be used by clients that verify DDR, because the selected SSL/TLS Certificate has no IP address (iPAddress) SAN for it.";
	}

	/** DDR on and a certificate with these SANs; the LAN holds a public address and so does the VIP, which no case lists as a SAN unless it says so. */
	private function ddr(array $san, array $settings): void
	{
		$this->lan([self::PUBLIC_LAN4], []);
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost', NULL, $san))];
		config_set_path(PFB_SECTIONS[explode('/', pfb_dns_config_key('pfb_dns_sslcertref'), 2)[0]] . '/pfb_dns_sslcertref', 'cert1');
		PfbConfig::write('dns_shared/pfb_dns_ddr', 'on');
		foreach ($settings + ['dns_shared/pfb_dns_dot' => 'on'] as $key => $value) {
			PfbConfig::write($key, $value);
		}
		foreach (['dot', 'doh', 'doq'] as $kind) {
			PfbConfig::write("dns/pfb_dns_{$kind}_interface", 'lan');
		}
		$this->vips(TRUE, FALSE, self::PUBLIC_VIP4);
	}

	public function testTheWarningNamesTheInterfaceAddressAndTheVipOfATransport(): void
	{
		// Given DoT on the LAN's public address and on a public VIP, with a certificate that has no IP SAN
		$this->ddr([], []);

		// Then both addresses are named, since both are listened on
		$this->assertSame([self::warning(self::PUBLIC_LAN4, 'DoT'), self::warning(self::PUBLIC_VIP4, 'DoT')], pfb_dns_proxy_ddr_warnings());
	}

	public function testTheInterfaceAddressIsCheckedAgainstTheCertificateOnceTheVipIsCovered(): void
	{
		// Given a certificate whose IP SAN is the VIP's
		$this->ddr(['IP:' . self::PUBLIC_VIP4], []);

		// Then the interface address the transport still listens on is the one named
		$this->assertSame([self::warning(self::PUBLIC_LAN4, 'DoT')], pfb_dns_proxy_ddr_warnings());
	}

	public function testOneWarningNamesEveryTransportListeningOnTheInterfaceAddress(): void
	{
		// Given DoT, DoH (port 4443, no 443 advertisement) and DoQ on both addresses
		$this->ddr([], ['dns_shared/pfb_dns_doh' => 'on', 'dns_shared/pfb_dns_doh_port' => '4443', 'dns_shared/pfb_dns_doq' => 'on']);

		// Then each address carries all three transports
		$this->assertSame(
			[self::warning(self::PUBLIC_LAN4, 'DoT, DoH and DoQ'), self::warning(self::PUBLIC_VIP4, 'DoT, DoH and DoQ')],
			pfb_dns_proxy_ddr_warnings()
		);
	}

	public function testDohOnPort443IsCheckedOnTheVipOnly(): void
	{
		// Given DoH alone on port 443: its listen set is the VIP
		$this->ddr([], ['dns_shared/pfb_dns_dot' => '', 'dns_shared/pfb_dns_doh' => 'on', 'dns_shared/pfb_dns_doh_port' => '443']);

		// Then only the VIP is named: the interface address does not listen for DoH
		$this->assertSame([self::warning(self::PUBLIC_VIP4, 'DoH')], pfb_dns_proxy_ddr_warnings());
	}
}
