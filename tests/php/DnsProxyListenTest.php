<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the DNS proxy takes over the addresses the DNS Resolver served before it was moved to
 * loopback 5353. pfb_dns_proxy_listen() derives them from the Resolver's SAVED active_interface the way
 * pfSense's unbound.inc binds them: an explicit list binds each interface that is up and enabled (an IP
 * entry verbatim, else its IPv4 and IPv6 address); empty or 'all' makes Unbound bind everything, which the
 * proxy (one wildcard UDP socket cannot answer from the address a client queried) turns into every address
 * of the box. Only valid, non-link-local, unscoped addresses survive, once each, in derivation order.
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
			'port'             => ['present' => TRUE, 'value' => '53'],
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

	public function testLoopbackEntryYieldsTheLoopbackAddresses(): void
	{
		$this->seedInterfaces(['lo0' => '127.0.0.1'], ['lo0' => '::1']);

		$this->assertSame(['127.0.0.1', '::1'], pfb_dns_proxy_listen(self::saved('lo0')));
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
		$GLOBALS['pfb_test_configured_ip_addresses'] = [
			'wan' => '198.51.100.1', 'lan' => '192.0.2.1', 'opt1' => NULL,
		];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1', 'wan' => 'fe80::9'];
		$GLOBALS['config']['virtualip']['vip'] = [
			['mode' => 'ipalias', 'subnet' => '203.0.113.7', 'interface' => 'wan'],
			['mode' => 'carp', 'subnet' => '192.0.2.254', 'interface' => 'lan'],
			['mode' => 'proxyarp', 'subnet' => '203.0.113.99', 'interface' => 'wan'],
			['mode' => 'ipalias', 'subnet' => '2001:db8::53', 'interface' => 'lan'],
			['mode' => 'ipalias', 'subnet' => '192.0.2.1', 'interface' => 'lan'],
		];
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
	public function testAWildcardResolverGivesEveryAddressOfTheBoxIncludingAliasAndCarpVips(?string $interfaces): void
	{
		$this->seedBox();

		$this->assertSame(
			[
				'127.0.0.1', '::1', '198.51.100.1', '192.0.2.1', '2001:db8::1',
				'203.0.113.7', '192.0.2.254', '2001:db8::53',
			],
			pfb_dns_proxy_listen(self::saved($interfaces)),
			'loopbacks first, then interface addresses, then alias/carp VIPs; a proxyarp VIP, the duplicate '
			. 'VIP address and the link-local fe80::9 are left out'
		);
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
		];
		$GLOBALS['pfb_test_configured_ipv6'] = [
			'opt1' => '2001:db8::1%em1',
			'opt2' => 'fe80::1%em0',
			'opt3' => '`id`',
		];
		$GLOBALS['config']['virtualip']['vip'] = [
			['mode' => 'ipalias', 'subnet' => "192.0.2.9\n--listen 0.0.0.0"],
			['mode' => 'ipalias', 'subnet' => '192.0.2.8 && reboot'],
			['mode' => 'carp'],
		];

		$this->assertSame(['127.0.0.1', '::1', '192.0.2.3'], pfb_dns_proxy_listen(self::saved('all')));
	}

	public function testAnInterfaceNameWithShellMetacharactersYieldsNoAddress(): void
	{
		$this->seedInterfaces(['lan' => '192.0.2.1'], [], ['lan' => self::UP]);

		$this->assertSame(['192.0.2.1'], pfb_dns_proxy_listen(self::saved('lan,wan;reboot,$(id), ,opt 1')),
			'only the real interface contributes: the others are unknown names with no address');
	}
}
