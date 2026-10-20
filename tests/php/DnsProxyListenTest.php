<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the DNS proxy takes over the addresses the DNS Resolver served before it was moved onto
 * loopback. issue #3538 -- pfB-DNS owns that list: pfb_dns_proxy_listen() derives the addresses from its own stored
 * interface list (dns/pfb_dns_interface), the way pfSense's unbound.inc binds them: an explicit list binds each
 * interface that is up and enabled (an IP entry verbatim, else its IPv4 and IPv6 address); 'all' makes Unbound bind
 * everything, which the proxy (one wildcard UDP socket cannot answer from the address a client queried) turns into
 * every address of the box, as pfSense lists them (interfaces and CARP/IP-alias VIPs); an empty list is no address at
 * all. Only valid, non-link-local, non-loopback, unscoped addresses survive, once each, in derivation order. Loopback
 * is never derived from the list: pfb_dns_proxy_service() always adds 127.0.0.1 and ::1 itself (DnsProxyServiceTest).
 * Every entry that adds no address is reported, with its reason, so that the startup warnings can name it.
 *
 * Each row seeds the pfSense answers the derivation reads and asserts the exact address list.
 */
#[CoversFunction('pfb_dns_proxy_listen')]
#[CoversFunction('pfb_dns_proxy_interface_addresses')]
#[CoversFunction('pfb_dns_proxy_skipped_warnings')]
final class DnsProxyListenTest extends TestCase
{
	private const GLOBALS = [
		'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info', 'pfb_test_configured_ip_addresses',
		'pfb_test_interfaces',
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

	/**
	 * pfb_dns_proxy_listen() over a stored pfB-DNS interface list; NULL or '' stores nothing, which is the not-seeded-yet
	 * state (the seed of a box with no Resolver interfaces is 'all').
	 *
	 * @param list<array{interface:string,why:string}>|null $skipped
	 * @return list<string>
	 */
	private function listen(?string $interfaces, ?array &$skipped = NULL): array
	{
		if ($interfaces !== NULL && $interfaces !== '') {
			config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_interface', $interfaces);
		}
		return pfb_dns_proxy_listen($skipped);
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

		$this->assertSame(['192.0.2.1'], $this->listen('lan'));
	}

	public function testExplicitInterfaceWithBothFamiliesYieldsIpv4ThenIpv6(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], ['lan' => '2001:db8::1'], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.1', '2001:db8::1'], $this->listen('lan'));
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

		$this->assertSame(['192.0.2.1'], $this->listen('lan,opt1'),
			'opt1 must contribute neither its IPv4 nor its IPv6 address');
	}

	public function testAnIpEntryIsUsedVerbatimWithoutAskingForAnInterface(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.5', '2001:db8::5'], $this->listen('192.0.2.5,2001:db8::5'));
	}

	public function testLoopbackEntryYieldsNoAddressBecauseUnboundKeepsLoopback(): void
	{
		$this->seedInterfaces(['lo0' => '127.0.0.1'], ['lo0' => '::1']);

		$this->assertSame([], $this->listen('lo0'));
	}

	public function testLoopbackAddressesNamedAsIpEntriesAreDroppedInAnySpelling(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(
			['192.0.2.1'],
			$this->listen('127.0.0.1,127.0.0.5,::1,0:0:0:0:0:0:0:1,lan')
		);
	}

	public function testDuplicateAddressesAreListedOnce(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.1'], $this->listen('lan,192.0.2.1,lan'));
	}

	public function testALinkLocalAddressIsDropped(): void
	{
		$this->seedInterfaces(
			['lan' => '192.0.2.1', 'opt1' => '169.254.7.7'],
			['lan' => 'fe80::1', 'opt1' => '2001:db8:1::1'],
			['lan' => self::UP, 'opt1' => self::UP]
		);

		$this->assertSame(['192.0.2.1', '2001:db8:1::1'], $this->listen('lan,opt1'),
			'neither fe80::/10 nor 169.254.0.0/16 can be served to a client');
	}

	public function testNoAddressAtAllYieldsAnEmptyList(): void
	{
		$this->seedInterfaces([], [], ['opt9' => self::UP]);

		$this->assertSame([], $this->listen('opt9'),
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
			$this->listen($interfaces),
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
		$this->assertNotContains('203.0.113.99', $this->listen('all'));
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

		$this->assertSame(['192.0.2.3'], $this->listen('all'));
	}

	public function testAnInterfaceNameWithShellMetacharactersYieldsNoAddress(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.1'], $this->listen('lan,wan;reboot,$(id), ,opt 1'),
			'only the real interface contributes: the others are unknown names with no address');
	}

	// -----------------------------------------------------------------------
	// issue #3513: the DoH/DoQ listeners pick their own interfaces through the same derivation
	// -----------------------------------------------------------------------

	public function testTheSameDerivationServesAnInterfaceListOfItsOwn(): void
	{
		$this->seedInterfaces(
			['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'],
			['opt1' => '2001:db8:1::1'],
			['lan' => self::UP, 'opt1' => self::UP]
		);

		$this->assertSame(['198.51.100.1', '2001:db8:1::1'], pfb_dns_proxy_interface_addresses(['opt1']));
		$this->assertSame(
			$this->listen('lan,opt1'),
			pfb_dns_proxy_interface_addresses(['lan', 'opt1']),
			'listen() is this derivation over the stored list: one rule set, not two'
		);
	}

	public function testAnAllListMeansEveryAddressOfTheBoxAndAnEmptyListMeansNone(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);
		$GLOBALS['pfb_test_configured_ip_addresses'] = ['lan' => '192.0.2.1'];

		$this->assertSame(['192.0.2.1'], pfb_dns_proxy_interface_addresses(['lan', 'all']));
		$this->assertSame([], pfb_dns_proxy_interface_addresses([], $skipped), 'an empty list is not a running value: it never means every address');
		$this->assertSame([], $skipped);
	}

	public function testAnInterfaceListDeduplicatesItsAddressesAndSkipsADownInterface(): void
	{
		$this->seedInterfaces(
			['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'],
			[],
			['lan' => self::UP, 'opt1' => ['status' => 'down', 'enable' => TRUE]]
		);

		$this->assertSame(['192.0.2.1'], pfb_dns_proxy_interface_addresses(['lan', 'lan', 'opt1']));
	}

	// -----------------------------------------------------------------------
	// issue #3538: several interfaces, and the entries that add no address are reported with their reason
	// -----------------------------------------------------------------------

	public function testSeveralStoredInterfacesGiveEachOnesIpv4AndIpv6AddressesInListOrder(): void
	{
		$this->seedInterfaces(
			['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'],
			['lan' => '2001:db8::1', 'opt1' => '2001:db8:1::1'],
			['lan' => self::UP, 'opt1' => self::UP]
		);

		$this->assertSame(['192.0.2.1', '2001:db8::1', '198.51.100.1', '2001:db8:1::1'], $this->listen('lan,opt1'));
	}

	public function testEveryEntryThatAddsNoAddressIsReportedWithItsReasonInListOrder(): void
	{
		// Given an unknown name, a down interface, an interface with no address and one that works
		$this->seedInterfaces(
			['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'],
			[],
			['lan' => self::UP, 'opt1' => ['status' => 'down', 'enable' => TRUE], 'opt2' => ['status' => 'up', 'enable' => FALSE], 'opt9' => self::UP]
		);
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN', 'opt1' => 'OPT1', 'opt2' => 'OPT2', 'opt9' => 'OPT9'];

		// When the list is derived
		$addresses = $this->listen('wan2,opt1,lan,opt2,opt9', $skipped);

		// Then only lan serves, and the others come back in list order, each with why it added nothing
		$this->assertSame(['192.0.2.1'], $addresses);
		$this->assertSame([
			['interface' => 'wan2', 'why' => 'unknown'],
			['interface' => 'opt1', 'why' => 'down'],
			['interface' => 'opt2', 'why' => 'down'],
			['interface' => 'opt9', 'why' => 'no address'],
		], $skipped);
	}

	public function testAWorkingListReportsNothing(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];

		$this->assertSame(['192.0.2.1'], $this->listen('lan', $skipped));
		$this->assertSame([], $skipped);
	}

	public function testAStoredListThatNamesNoInterfaceYieldsNoAddressAndReportsNothing(): void
	{
		// Given a hand-edited list of separators only: no token, so no interface and no wildcard
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame([], $this->listen(' , ', $skipped));
		$this->assertSame([], $skipped);
	}

	/** @return array<string,array{string}> a wildcard in the list: all wins, so no other entry is reported, and Localhost never is */
	public static function listsWhereNothingIsReported(): array
	{
		return [
			'all wins over a name that does not exist' => ['all,wan2,opt9'], 'all wins over a working interface' => ['all,lan'],
			'all with Localhost' => ['all,lo0'], 'Localhost alone' => ['lo0'], 'Localhost beside a working interface' => ['lo0,lan'],
		];
	}

	#[DataProvider('listsWhereNothingIsReported')]
	public function testALocalhostEntryAndEveryEntryBesideAllAreNeverReported(string $list): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);
		$GLOBALS['pfb_test_configured_ip_addresses'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];

		$this->listen($list, $skipped);

		$this->assertSame([], $skipped);
	}

	public function testAllAndLocalhostGiveEveryAddressOfTheBoxAndNoLoopback(): void
	{
		$this->seedBox();

		$this->assertSame(
			['198.51.100.1', '192.0.2.1', '203.0.113.7', '192.0.2.254', '2001:db8::1', '2001:db8::53'],
			$this->listen('all,lo0', $skipped)
		);
		$this->assertSame([], $skipped);
	}

	/** @return array<string,array{string}> hand-edited stored names: none is an interface, and none may reach a command line or a page unquoted */
	public static function hostileNames(): array
	{
		return ['a shell command' => ['lo0;rm'], 'a path' => ['../x'], 'an unknown name' => ['wan2'], 'markup' => ['<b>x</b>']];
	}

	#[DataProvider('hostileNames')]
	public function testAHostileOrUnknownStoredNameAddsNoAddressIsReportedUnknownAndNamedVerbatimInItsWarning(string $name): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];

		$addresses = $this->listen("lan,{$name}", $skipped);

		$this->assertSame(['192.0.2.1'], $addresses);
		$this->assertSame([['interface' => $name, 'why' => 'unknown']], $skipped);
		$this->assertSame(
			["DNS proxy: plain DNS interface \"{$name}\" is not a configured interface; it is skipped"],
			pfb_dns_proxy_skipped_warnings('plain DNS', $skipped),
			'verbatim: the notice stores the text encoded itself, so escaping here would encode twice'
		);
	}

	public function testEachReasonHasItsOwnWarningLineStartingWithDnsProxy(): void
	{
		$skipped = [
			['interface' => 'wan2', 'why' => 'unknown'],
			['interface' => 'opt1', 'why' => 'down'],
			['interface' => 'opt9', 'why' => 'no address'],
		];

		$this->assertSame([
			'DNS proxy: DoT interface "wan2" is not a configured interface; it is skipped',
			'DNS proxy: DoT interface opt1 is down or disabled; it adds no listener',
			'DNS proxy: DoT interface opt9 has no usable address; it adds no listener',
		], pfb_dns_proxy_skipped_warnings('DoT', $skipped));
		$this->assertSame([], pfb_dns_proxy_skipped_warnings('DoH', []));
	}
}
