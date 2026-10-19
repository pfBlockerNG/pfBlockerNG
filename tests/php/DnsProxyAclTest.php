<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- with the Resolver on loopback, pfSense's unbound_acls_config() no longer grants the LAN IPv6
 * subnets (it derives them from unbound/active_interface; the IPv4 grants come from the NAT networks and survive),
 * so every IPv6 client the proxy relays would be REFUSED. pfb_dns_proxy_resolver(TRUE) therefore adds the same
 * `access-control: <subnet> allow` rows to its marked server clause, derived from the SAVED interfaces the way
 * pfSense derives them: the non-link-local IPv6 subnet of each interface that has no gateway (a LAN-type one),
 * plus the enabled static routes that leave through such an interface; nothing when the admin turned the
 * automatic access control off.
 *
 * Each row seeds what pfSense answers and asserts the rows in the Resolver's custom options afterwards.
 */
final class DnsProxyAclTest extends TestCase
{
	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_configured_ipv6', 'pfb_test_interface_subnetv6', 'pfb_test_interfaces_with_gateway',
		'pfb_test_interfaces', 'pfb_test_gateway_interfaces', 'pfb_test_write_config_calls', 'pfb_test_file_notices',
	];

	private string $tmp;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_proxy_acl_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir' => $this->tmp,
			'log'    => "{$this->tmp}/pfb.log",
			'errlog' => "{$this->tmp}/pfb.err",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->tmp);
	}

	/** A Resolver listening on $interfaces (NULL = key absent), before the proxy moves it. */
	private function seedResolver(?string $interfaces, string $custom = "do-ip6: no\nprefetch: yes"): void
	{
		$unbound = ['enable' => '', 'port' => '53', 'custom_options' => base64_encode($custom)];
		if ($interfaces !== NULL) {
			$unbound['active_interface'] = $interfaces;
		}
		$GLOBALS['config']['unbound'] = $unbound;
	}

	/**
	 * @param array<string,string> $v6   interface => its IPv6 address
	 * @param array<string,string> $bits interface => its prefix length
	 * @param list<string> $withGateway interfaces that reach the Internet through a gateway
	 */
	private function seedBox(array $v6, array $bits, array $withGateway = []): void
	{
		$GLOBALS['pfb_test_configured_ipv6'] = $v6;
		$GLOBALS['pfb_test_interface_subnetv6'] = $bits;
		$GLOBALS['pfb_test_interfaces_with_gateway'] = $withGateway;
		$GLOBALS['pfb_test_interfaces'] = array_fill_keys(array_keys($v6), '');
	}

	private function customText(): string
	{
		return (string) base64_decode((string) config_get_path('unbound/custom_options'), TRUE);
	}

	/** @return list<string> the `access-control:` rows of the Resolver's custom options, in order */
	private function grants(): array
	{
		return array_values(array_filter(
			explode("\n", $this->customText()),
			static fn (string $line): bool => str_starts_with($line, 'access-control:')
		));
	}

	private function moveOn(): void
	{
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
	}

	// -----------------------------------------------------------------------
	// The layout of the clause
	// -----------------------------------------------------------------------

	public function testTheGrantsSitInsideOurMarkedClauseAfterTheProxyLines(): void
	{
		// Given a LAN with a global IPv6 address
		$this->seedBox(['lan' => '2001:db8:1::1'], ['lan' => '64']);
		$this->seedResolver('lan');
		$this->assertSame([], $this->grants(), 'before: no grants');

		// When the proxy moves the Resolver
		$this->moveOn();

		// Then the whole text is the user's lines plus one clause, the grant between the PROXYv2 line and the end marker
		$this->assertSame(
			"do-ip6: no\nprefetch: yes\nserver:\n# pfBlockerNG DNS proxy\nport: 5354\ninterface: 127.0.0.1@5353\ninterface: ::1@5353\n"
			. "proxy-protocol-port: 5353\nedns-buffer-size: 1432\naccess-control: 2001:db8:1::/64 allow\n# end pfBlockerNG DNS proxy",
			$this->customText()
		);
	}

	// -----------------------------------------------------------------------
	// Which interfaces are granted
	// -----------------------------------------------------------------------

	public function testALanTypeInterfaceIsGrantedItsSubnetAndAnInterfaceWithAGatewayIsNot(): void
	{
		$this->seedBox(
			['lan' => '2001:db8:1::1', 'opt1' => '2001:db8:2::1', 'wan' => '2001:db8:ff::2'],
			['lan' => '64', 'opt1' => '56', 'wan' => '64'],
			['wan']
		);
		$this->seedResolver('lan,opt1,wan');

		$this->moveOn();

		$this->assertSame(
			['access-control: 2001:db8:1::/64 allow', 'access-control: 2001:db8:2::/56 allow'],
			$this->grants(),
			'the subnet of an Internet-facing interface (wan) is never granted'
		);
	}

	/** @return array<string,array{?string}> */
	public static function wildcardRows(): array
	{
		return ["'all'" => ['all'], 'empty' => [''], 'absent' => [NULL], "'all' among others" => ['lan,all']];
	}

	#[DataProvider('wildcardRows')]
	public function testAWildcardResolverGrantsEveryLanTypeInterfaceOfTheBox(?string $interfaces): void
	{
		$this->seedBox(
			['lan' => '2001:db8:1::1', 'opt1' => '2001:db8:2::1', 'wan' => '2001:db8:ff::2'],
			['lan' => '64', 'opt1' => '64', 'wan' => '64'],
			['wan']
		);
		$this->seedResolver($interfaces);

		$this->moveOn();

		$this->assertSame(
			['access-control: 2001:db8:1::/64 allow', 'access-control: 2001:db8:2::/64 allow'],
			$this->grants()
		);
	}

	public function testAnInterfaceWithoutAnIpv6AddressGrantsNothing(): void
	{
		$this->seedBox(['lan' => '2001:db8:1::1'], ['lan' => '64']);
		$this->seedResolver('lan,opt9');

		$this->moveOn();

		$this->assertSame(['access-control: 2001:db8:1::/64 allow'], $this->grants(), 'opt9 has no address: no row');
	}

	public function testALinkLocalAddressIsNotGrantedItsSubnet(): void
	{
		$this->seedBox(['lan' => 'fe80::1', 'opt1' => '2001:db8:2::1'], ['lan' => '64', 'opt1' => '64']);
		$this->seedResolver('lan,opt1');

		$this->moveOn();

		$this->assertSame(['access-control: 2001:db8:2::/64 allow'], $this->grants());
	}

	public function testAnIpEntryOfTheSavedListGrantsNothing(): void
	{
		$this->seedBox(['lan' => '2001:db8:1::1'], ['lan' => '64']);
		$this->seedResolver('2001:db8:1::1');

		$this->moveOn();

		$this->assertSame([], $this->grants(), 'only interfaces have a subnet; an address entry is not one');
	}

	// -----------------------------------------------------------------------
	// Static routes
	// -----------------------------------------------------------------------

	public function testAnEnabledStaticRouteThatLeavesThroughALanTypeInterfaceIsGranted(): void
	{
		$this->seedBox(['lan' => '2001:db8:1::1', 'opt1' => '2001:db8:2::1'], ['lan' => '64', 'opt1' => '64'], ['opt1']);
		$GLOBALS['pfb_test_gateway_interfaces'] = ['LAN_GW' => 'lan', 'OPT1_GW' => 'opt1', 'GONE' => 'opt9'];
		$GLOBALS['config']['staticroutes']['route'] = [
			['network' => '2001:db8:100::/48', 'gateway' => 'LAN_GW'],
			['network' => '2001:db8:200::/48', 'gateway' => 'OPT1_GW'],
			['network' => '2001:db8:300::/48', 'gateway' => 'LAN_GW', 'disabled' => ''],
			['network' => '2001:db8:400::/48', 'gateway' => 'UNKNOWN_GW'],
			['network' => '2001:db8:500::/48', 'gateway' => 'GONE'],
		];
		$this->seedResolver('lan,opt1');

		$this->moveOn();

		$this->assertSame(
			['access-control: 2001:db8:1::/64 allow', 'access-control: 2001:db8:100::/48 allow'],
			$this->grants(),
			'only the enabled route through the gateway-less lan: not opt1 (has a gateway), not a disabled or unknown one'
		);
	}

	// -----------------------------------------------------------------------
	// Never invent a grant
	// -----------------------------------------------------------------------

	public function testASubnetThatIsNotAValidSubnetNeverReachesTheConfig(): void
	{
		$this->seedBox(['lan' => '2001:db8:1::1'], ['lan' => "64\nproxy-protocol-port: 1"]);
		$this->seedResolver('lan');

		$this->moveOn();

		$this->assertSame([], $this->grants());
		$this->assertSame(1, substr_count($this->customText(), 'proxy-protocol-port'), 'nothing was injected into the clause');
	}

	public function testTheSameSubnetIsGrantedOnce(): void
	{
		$this->seedBox(['lan' => '2001:db8:1::1', 'opt1' => '2001:db8:1::7'], ['lan' => '64', 'opt1' => '64']);
		$this->seedResolver('lan,opt1');

		$this->moveOn();

		$this->assertSame(['access-control: 2001:db8:1::/64 allow'], $this->grants());
	}

	public function testNothingIsGrantedWhenTheAdminTurnedTheAutomaticAccessControlOff(): void
	{
		$this->seedBox(['lan' => '2001:db8:1::1'], ['lan' => '64']);
		$this->seedResolver('lan');
		$GLOBALS['config']['unbound']['disable_auto_added_access_control'] = '';

		$this->moveOn();

		$this->assertSame([], $this->grants(), 'pfSense would have added none, so neither do we');
		$this->assertStringContainsString('proxy-protocol-port: 5353', $this->customText(), 'the rest of the clause is unaffected');
	}

	// -----------------------------------------------------------------------
	// Derived from the SAVED interfaces, kept current
	// -----------------------------------------------------------------------

	public function testASecondApplyDerivesTheGrantsFromTheSavedInterfacesNotFromTheMovedResolver(): void
	{
		// Given a moved Resolver (active_interface is now lo0) whose snapshot remembers the LAN
		$this->seedBox(['lan' => '2001:db8:1::1'], ['lan' => '64']);
		$this->seedResolver('lan');
		$this->moveOn();
		$this->assertSame('lo0', config_get_path('unbound/active_interface'), 'before: moved');
		$text = $this->customText();

		// When it is applied again
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the grants are still the LAN's and nothing is written
		$this->assertFalse($changed);
		$this->assertSame($text, $this->customText());
		$this->assertSame(1, count($GLOBALS['pfb_test_write_config_calls']), 'only the first call wrote config.xml');
	}

	public function testAChangedPrefixReplacesTheGrantInPlaceAndKeepsTheUsersOwnLines(): void
	{
		// Given a moved Resolver, and an admin who added lines before AND after our clause
		$this->seedBox(['lan' => '2001:db8:1::1'], ['lan' => '64']);
		$this->seedResolver('lan');
		$this->moveOn();
		$snapshot = config_get_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved');
		$edited = "# mine\n" . $this->customText() . "\nprefetch-key: yes";
		config_set_path('unbound/custom_options', base64_encode($edited));

		// When the LAN's prefix changes (a delegated prefix renewal) and the proxy is applied again
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8:9::1'];
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the old grant is gone, the new one is in our clause, and the admin's lines survive untouched
		$this->assertTrue($changed);
		$this->assertSame(['access-control: 2001:db8:9::/64 allow'], $this->grants());
		$this->assertSame(
			"# mine\ndo-ip6: no\nprefetch: yes\nserver:\n# pfBlockerNG DNS proxy\nport: 5354\ninterface: 127.0.0.1@5353\ninterface: ::1@5353\n"
			. "proxy-protocol-port: 5353\nedns-buffer-size: 1432\naccess-control: 2001:db8:9::/64 allow\n# end pfBlockerNG DNS proxy\nprefetch-key: yes",
			$this->customText()
		);
		$this->assertSame($snapshot, config_get_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved'),
			'the snapshot still holds the original custom options');
	}

	public function testTurningTheProxyOffRemovesTheGrantsWithTheRestOfTheMove(): void
	{
		$this->seedBox(['lan' => '2001:db8:1::1'], ['lan' => '64']);
		$this->seedResolver('lan');
		$original = config_get_path('unbound');
		$this->moveOn();
		$this->assertNotSame([], $this->grants(), 'before: the move granted the LAN');

		$this->assertTrue(pfb_dns_proxy_resolver(FALSE));

		$this->assertSame($original, config_get_path('unbound'));
		$this->assertSame([], $this->grants());
	}
}
