<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the DNS proxy takes over the addresses the DNS Resolver served before it was moved onto
 * loopback. pfb_dns_proxy_listen() derives them from the Resolver's SAVED active_interface the way
 * pfSense's unbound.inc binds them: an explicit list binds each interface that is up and enabled (an IP
 * entry verbatim, else its IPv4 and IPv6 address); empty or 'all' makes Unbound bind everything, which the
 * proxy (one wildcard UDP socket cannot answer from the address a client queried) turns into every address
 * of the box, as pfSense lists them (interfaces and CARP/IP-alias VIPs). Only valid, non-link-local,
 * non-loopback, unscoped addresses survive, once each, in derivation order. Loopback is never derived from the
 * saved interfaces: pfb_dns_proxy_service() always adds 127.0.0.1 and ::1 itself (DnsProxyServiceTest).
 *
 * Each row seeds the pfSense answers the derivation reads and asserts the exact address list.
 */
#[CoversFunction('pfb_dns_proxy_listen')]
final class DnsProxyListenTest extends TestCase
{
	private const GLOBALS = [
		'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info', 'pfb_test_configured_ip_addresses',
	];

	private array $originalGlobals = [];
	private bool $hadConfig = FALSE;
	private array $originalConfig = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->originalGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->originalGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	/** The saved Resolver snapshot of a box whose Resolver listened on $interfaces (NULL = key absent). */
	private static function saved(?string $interfaces): array
	{
		return [
			'active_interface' => ['present' => $interfaces !== NULL, 'value' => $interfaces],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
	}

	/** @param array<string,array{status:string,enable:bool}> $info */
	private function seedInterfaces(array $v4, array $v6 = [], array $info = []): void
	{
		$GLOBALS['pfb_test_interface_ip'] = $v4;
		$GLOBALS['pfb_test_configured_ipv6'] = $v6;
		$GLOBALS['pfb_test_interface_info'] = $info;
	}

	private const UP = ['status' => 'up', 'enable' => TRUE];

	// -----------------------------------------------------------------------
	// An explicit interface list
	// -----------------------------------------------------------------------

	public function testExplicitInterfaceWithOnlyAnIpv4AddressYieldsThatAddress(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.1'], pfb_dns_proxy_listen(self::saved('lan')));
	}

	public function testExplicitInterfaceWithBothFamiliesYieldsIpv4ThenIpv6(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], ['lan' => '2001:db8::1'], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.1', '2001:db8::1'], pfb_dns_proxy_listen(self::saved('lan')));
	}

	/** @return array<string,array{array<string,array{status:string,enable:bool}>}> */
	public static function unusableInterfaces(): array
	{
		return [
			'status down'       => [['status' => 'down', 'enable' => TRUE]],
			'no carrier'        => [['status' => 'no carrier', 'enable' => TRUE]],
			'up but not enabled' => [['status' => 'up', 'enable' => FALSE]],
		];
	}

	/** @param array{status:string,enable:bool} $opt1 */
	#[DataProvider('unusableInterfaces')]
	public function testAnInterfaceThatIsNotUpAndEnabledIsSkippedLikeUnboundDoes(array $opt1): void
	{
		$this->seedInterfaces(
			['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'],
			['opt1' => '2001:db8:1::1'],
			['lan' => self::UP, 'opt1' => $opt1]
		);

		$this->assertSame(['192.0.2.1'], pfb_dns_proxy_listen(self::saved('lan,opt1')),
			'opt1 must contribute neither its IPv4 nor its IPv6 address');
	}

	public function testAnIpEntryIsUsedVerbatimWithoutAskingForAnInterface(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.5', '2001:db8::5'], pfb_dns_proxy_listen(self::saved('192.0.2.5,2001:db8::5')));
	}

	public function testLoopbackEntryYieldsNoAddressBecauseUnboundKeepsLoopback(): void
	{
		$this->seedInterfaces(['lo0' => '127.0.0.1'], ['lo0' => '::1']);

		$this->assertSame([], pfb_dns_proxy_listen(self::saved('lo0')));
	}

	public function testLoopbackAddressesNamedAsIpEntriesAreDroppedInAnySpelling(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(
			['192.0.2.1'],
			pfb_dns_proxy_listen(self::saved('127.0.0.1,127.0.0.5,::1,0:0:0:0:0:0:0:1,lan'))
		);
	}

	public function testDuplicateAddressesAreListedOnce(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.1'], pfb_dns_proxy_listen(self::saved('lan,192.0.2.1,lan')));
	}

	public function testALinkLocalAddressIsDropped(): void
	{
		$this->seedInterfaces(
			['lan' => '192.0.2.1', 'opt1' => '169.254.7.7'],
			['lan' => 'fe80::1', 'opt1' => '2001:db8:1::1'],
			['lan' => self::UP, 'opt1' => self::UP]
		);

		$this->assertSame(['192.0.2.1', '2001:db8:1::1'], pfb_dns_proxy_listen(self::saved('lan,opt1')),
			'neither fe80::/10 nor 169.254.0.0/16 can be served to a client');
	}

	public function testNoAddressAtAllYieldsAnEmptyList(): void
	{
		$this->seedInterfaces([], [], ['opt9' => self::UP]);

		$this->assertSame([], pfb_dns_proxy_listen(self::saved('opt9')),
			'an up interface that has no address gives the proxy nothing to bind');
	}

	// -----------------------------------------------------------------------
	// Unbound's wildcard: every address of the box
	// -----------------------------------------------------------------------

	private function seedBox(): void
	{
		// As pfSense lists them: interface addresses keyed by name, CARP/IP-alias VIPs keyed '_vip<id>' (a
		// proxy-ARP VIP is not in either list). get_configured_ipv6_addresses() leaves out a link-local address.
		$GLOBALS['pfb_test_configured_ip_addresses'] = [
			'wan' => '198.51.100.1', 'lan' => '192.0.2.1', 'opt1' => NULL,
			'_vip1' => '203.0.113.7', '_vip2' => '192.0.2.254', '_vip3' => '192.0.2.1',
		];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1', 'wan' => 'fe80::9', '_vip4' => '2001:db8::53'];
	}

	/** @return array<string,array{?string}> */
	public static function wildcardRows(): array
	{
		return [
			"'all'"                 => ['all'],
			'empty'                 => [''],
			'absent'                => [NULL],
			"'all' among others"    => ['lan,all'],
		];
	}

	#[DataProvider('wildcardRows')]
	public function testAWildcardResolverGivesEveryNonLoopbackAddressOfTheBoxIncludingAliasAndCarpVips(?string $interfaces): void
	{
		$this->seedBox();

		$this->assertSame(
			['198.51.100.1', '192.0.2.1', '203.0.113.7', '192.0.2.254', '2001:db8::1', '2001:db8::53'],
			pfb_dns_proxy_listen(self::saved($interfaces)),
			'IPv4 interfaces and VIPs, then IPv6 ones, as pfSense lists them; no loopback, no link-local fe80::9, '
			. 'the duplicate VIP address once'
		);
	}

	public function testTheListenDerivationReadsNoVipFromConfigXmlBecausePfsenseAlreadyListsThem(): void
	{
		// Given a VIP in config.xml that pfSense's own address lists do not carry
		$this->seedBox();
		$GLOBALS['config']['virtualip']['vip'] = [['mode' => 'ipalias', 'subnet' => '203.0.113.99', 'interface' => 'wan']];

		// Then the proxy does not add it on its own
		$this->assertNotContains('203.0.113.99', pfb_dns_proxy_listen(self::saved('all')));
	}

	// -----------------------------------------------------------------------
	// Hostile values never reach the rc script
	// -----------------------------------------------------------------------

	public function testScopedShellMetacharacterAndNonAddressValuesAreDropped(): void
	{
		$GLOBALS['pfb_test_configured_ip_addresses'] = [
			'lan'  => '192.0.2.1;reboot',
			'opt1' => '$(touch /tmp/pwned)',
			'opt2' => '192.0.2.2 ',
			'opt3' => '192.0.2.3',
			'_vipa' => "192.0.2.9\n--listen 0.0.0.0",
			'_vipb' => '192.0.2.8 && reboot',
		];
		$GLOBALS['pfb_test_configured_ipv6'] = [
			'opt1' => '2001:db8::1%em1',
			'opt2' => 'fe80::1%em0',
			'opt3' => '`id`',
		];

		$this->assertSame(['192.0.2.3'], pfb_dns_proxy_listen(self::saved('all')));
	}

	public function testAnInterfaceNameWithShellMetacharactersYieldsNoAddress(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.1'], pfb_dns_proxy_listen(self::saved('lan,wan;reboot,$(id), ,opt 1')),
			'only the real interface contributes: the others are unknown names with no address');
	}
}
