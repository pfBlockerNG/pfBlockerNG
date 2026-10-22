<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3583 -- the pfB-DNS page warns, without blocking the save, about each address an encrypted listener serves that is
 * public and is not an `iPAddress` SAN of the selected certificate: a client verifying DDR (RFC 9462 section 4.2) checks the
 * address it queried against that SAN, so there it will not use DoT, DoH or DoQ. Spec: docs/specs/encrypted-dns-discovery.md,
 * "Certificate warning", acceptance criterion 8.
 *
 * The warnings come from the stored settings (config.xml), the certificate is a real one issued with the SANs of the case, and
 * the listener addresses are what pfb_dns_proxy_interface_addresses() derives from seeded interfaces, as on a box: the tests
 * assert that derived list too, so a case never passes only because no address was listened on.
 */
#[CoversFunction('pfb_dns_proxy_ddr_warnings')]
#[CoversFunction('pfb_dns_proxy_public_address')]
#[CoversFunction('pfb_dns_proxy_certificate_ip_sans')]
final class DnsProxyDdrWarningTest extends TestCase
{
	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';

	private const GLOBALS = [
		'config', 'pfb_test_interface_ip', 'pfb_test_interface_info', 'pfb_test_configured_ipv6', 'pfb_test_configured_ip_addresses', 'pfb_test_interfaces',
	];

	/** @var array<string,array{0:bool,1:mixed}> */
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$GLOBALS['config'] = [];
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
	}

	// -----------------------------------------------------------------------
	// fixtures
	// -----------------------------------------------------------------------

	/** The warning for one address: $served is the transports' names as the page prints them ("DoT", "DoT and DoQ"). */
	private static function warning(string $address, string $served): string
	{
		return "DDR: {$served} on {$address} will not be used by clients that verify DDR, because the selected SSL/TLS Certificate has no IP address (iPAddress) SAN for it.";
	}

	/**
	 * Interfaces that are up, each with at most one IPv4 and one IPv6 address.
	 *
	 * @param array<string,list<string>> $interfaces name => addresses
	 */
	private function interfaces(array $interfaces): void
	{
		$v4 = $v6 = $info = [];
		foreach ($interfaces as $name => $addresses) {
			$info[$name] = ['status' => 'up', 'enable' => TRUE];
			foreach ($addresses as $address) {
				if (str_contains($address, ':')) {
					$v6[$name] = $address;
				} else {
					$v4[$name] = $address;
				}
			}
		}
		$GLOBALS['pfb_test_interface_ip'] = $v4;
		$GLOBALS['pfb_test_configured_ipv6'] = $v6;
		$GLOBALS['pfb_test_interface_info'] = $info;
		$GLOBALS['pfb_test_interfaces'] = array_fill_keys(array_keys($interfaces), '');
	}

	/** @param array<string,string> $settings */
	private function store(array $settings): void
	{
		foreach ($settings as $key => $value) {
			config_set_path(self::SETTINGS . $key, $value);
		}
	}

	/**
	 * A box with DDR on and DoT on every one of these interfaces (port 853), certificate `cert1` with these SANs selected.
	 *
	 * @param array<string,list<string>> $interfaces
	 * @param list<string> $san OpenSSL subjectAltName entries of the certificate
	 * @param array<string,string> $settings stored settings that replace the defaults
	 */
	private function box(array $interfaces, array $san = [], array $settings = []): void
	{
		$this->interfaces($interfaces);
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost', NULL, $san))];
		$names = implode(',', array_keys($interfaces));
		$this->store($settings + [
			'pfb_dns_interface' => $names, 'pfb_dns_sslcertref' => 'cert1', 'pfb_dns_ddr' => 'on', 'pfb_dns_ddr_doh_443' => '',
			'pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '853', 'pfb_dns_dot_interface' => $names,
			'pfb_dns_doh' => '', 'pfb_dns_doh_port' => '8443', 'pfb_dns_doh_interface' => $names,
			'pfb_dns_doq' => '', 'pfb_dns_doq_port' => '8853', 'pfb_dns_doq_interface' => $names,
		]);
	}

	// -----------------------------------------------------------------------
	// which address warns (criterion 8 table)
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:array<string,list<string>>,1:list<string>,2:list<string>,3:list<string>}> interfaces, SANs, listened addresses, warned addresses */
	public static function listenerRows(): array
	{
		$reserved = ['a' => ['0.0.0.1', '::'], 'b' => ['192.0.2.1', '2001:db8::1'], 'c' => ['198.18.0.1']];
		return [
			'public IPv4, certificate without SANs' => [['wan' => ['8.8.8.8']], [], ['8.8.8.8'], ['8.8.8.8']],
			'public IPv4, certificate has the SAN of another address' => [['wan' => ['8.8.8.8']], ['IP:1.1.1.1'], ['8.8.8.8'], ['8.8.8.8']],
			'public IPv4, matching iPAddress SAN' => [['wan' => ['8.8.8.8']], ['IP:8.8.8.8'], ['8.8.8.8'], []],
			'public IPv6, certificate without SANs' => [['wan' => ['2606:4700::1']], [], ['2606:4700::1'], ['2606:4700::1']],
			'IPv6 listener compressed, SAN written out in full' => [['wan' => ['2606:4700::1']], ['IP:2606:4700:0:0:0:0:0:1'], ['2606:4700::1'], []],
			'IPv6 listener written out in full, SAN compressed' => [['wan' => ['2606:4700:0:0:0:0:0:1']], ['IP:2606:4700::1'], ['2606:4700:0:0:0:0:0:1'], []],
			'a DNS SAN equal to the address is not an iPAddress SAN' => [['wan' => ['8.8.8.8']], ['DNS:8.8.8.8'], ['8.8.8.8'], ['8.8.8.8']],
			'two public addresses, none in the certificate' => [['wan' => ['8.8.8.8', '2606:4700::1']], [], ['8.8.8.8', '2606:4700::1'], ['8.8.8.8', '2606:4700::1']],
			'two public addresses, one in the certificate' => [['wan' => ['8.8.8.8', '2606:4700::1']], ['IP:8.8.8.8'], ['8.8.8.8', '2606:4700::1'], ['2606:4700::1']],
			'loopback, private, CGNAT, link-local and ULA addresses' => [
				['lan' => ['192.168.1.1', 'fd12:3456::1'], 'opt1' => ['172.31.255.254', 'fe80::1'], 'opt2' => ['100.127.255.254'], 'lo0' => ['127.0.0.1', '::1']],
				[], ['192.168.1.1', 'fd12:3456::1', '172.31.255.254', '100.127.255.254'], [],
			],
			'reserved, documentation and benchmarking addresses' => [$reserved, [], ['0.0.0.1', '::', '192.0.2.1', '2001:db8::1', '198.18.0.1'], []],
			'a public address beside non-public ones is the only one named' => [
				['lan' => ['192.168.1.1', 'fd12:3456::1'], 'wan' => ['8.8.8.8']], [], ['192.168.1.1', 'fd12:3456::1', '8.8.8.8'], ['8.8.8.8'],
			],
			'IPv4-mapped private address' => [['wan' => ['::ffff:10.0.0.1']], [], ['::ffff:10.0.0.1'], []],
			'IPv4-mapped public address, certificate without SANs' => [['wan' => ['::ffff:8.8.8.8']], [], ['::ffff:8.8.8.8'], ['::ffff:8.8.8.8']],
			'IPv4-mapped public address, matching SAN' => [['wan' => ['::ffff:8.8.8.8']], ['IP:::ffff:8.8.8.8'], ['::ffff:8.8.8.8'], []],
		];
	}

	/**
	 * @param array<string,list<string>> $interfaces
	 * @param list<string> $san
	 * @param list<string> $listened
	 * @param list<string> $warned
	 */
	#[DataProvider('listenerRows')]
	public function testAWarningNamesEachPublicListenerAddressTheCertificateDoesNotCarryAsAnIpAddressSan(array $interfaces, array $san, array $listened, array $warned): void
	{
		// Given DDR on, DoT on these interfaces, and a certificate with these SANs
		$this->box($interfaces, $san);
		$this->assertSame($listened, pfb_dns_proxy_interface_addresses(array_keys($interfaces)), 'the addresses pfSense lists for the DoT interfaces');

		// Then exactly the public addresses that are not an iPAddress SAN are named, one warning each
		$this->assertSame(array_map(static fn (string $address): string => self::warning($address, 'DoT'), $warned), pfb_dns_proxy_ddr_warnings());
	}

	public function testDdrOffWarnsAboutNothing(): void
	{
		// Given a public address missing from the certificate, and DDR on
		$this->box(['wan' => ['8.8.8.8']]);
		$this->assertSame([self::warning('8.8.8.8', 'DoT')], pfb_dns_proxy_ddr_warnings(), 'with DDR on it warns');

		// When DDR is turned off
		$this->store(['pfb_dns_ddr' => '']);

		// Then it does not
		$this->assertSame([], pfb_dns_proxy_ddr_warnings());
	}

	public function testNoSelectedCertificateWarnsAboutNothing(): void
	{
		// Given a public address missing from the certificate
		$this->box(['wan' => ['8.8.8.8']]);
		$this->assertSame([self::warning('8.8.8.8', 'DoT')], pfb_dns_proxy_ddr_warnings(), 'with the certificate selected it warns');

		// When no certificate is selected, then there is nothing to warn about
		$this->store(['pfb_dns_sslcertref' => '']);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings(), 'an empty selection');

		// And neither when the selected one is not in the configuration
		$this->store(['pfb_dns_sslcertref' => 'gone']);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings(), 'a selection that names no certificate');
	}

	// -----------------------------------------------------------------------
	// which transports count
	// -----------------------------------------------------------------------

	public function testDohOn443LeavesTheDohListenerOutAndKeepsDotAndDoq(): void
	{
		// Given DoH alone on a public address that the certificate lacks, the 443 option off
		$this->box(['wan' => ['8.8.8.8']], [], ['pfb_dns_dot' => '', 'pfb_dns_doh' => 'on']);
		$this->assertSame([self::warning('8.8.8.8', 'DoH')], pfb_dns_proxy_ddr_warnings(), 'with the option off DoH warns');

		// When the option is on, its clients see the reverse proxy's certificate: no warning
		$this->store(['pfb_dns_ddr_doh_443' => 'on']);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings(), 'DoH alone, the option on');

		// And with DoT on the same address too, the warning is back and names DoT only
		$this->store(['pfb_dns_dot' => 'on']);
		$this->assertSame([self::warning('8.8.8.8', 'DoT')], pfb_dns_proxy_ddr_warnings(), 'DoT and DoH, the option on');

		// And with DoQ on as well it names DoT and DoQ
		$this->store(['pfb_dns_doq' => 'on']);
		$this->assertSame([self::warning('8.8.8.8', 'DoT and DoQ')], pfb_dns_proxy_ddr_warnings(), 'DoT, DoH and DoQ, the option on');
	}

	public function testOneAddressServedByTwoOrThreeTransportsIsOneWarningNamingThem(): void
	{
		// Given DoT and DoQ on the same public address
		$this->box(['wan' => ['8.8.8.8']], [], ['pfb_dns_doq' => 'on']);

		// Then one warning names both
		$this->assertSame([self::warning('8.8.8.8', 'DoT and DoQ')], pfb_dns_proxy_ddr_warnings());

		// And with DoH on too, one warning names all three
		$this->store(['pfb_dns_doh' => 'on']);
		$this->assertSame([self::warning('8.8.8.8', 'DoT, DoH and DoQ')], pfb_dns_proxy_ddr_warnings());
	}

	public function testATransportOnItsOwnInterfaceNamesOnlyThatTransportOnThatAddress(): void
	{
		// Given DoT on wan and DoQ on opt1, two public addresses
		$this->box(['wan' => ['8.8.8.8'], 'opt1' => ['1.1.1.1']], [], ['pfb_dns_dot_interface' => 'wan', 'pfb_dns_doq' => 'on', 'pfb_dns_doq_interface' => 'opt1']);

		// Then each address names its own transport
		$this->assertSame([self::warning('8.8.8.8', 'DoT'), self::warning('1.1.1.1', 'DoQ')], pfb_dns_proxy_ddr_warnings());
	}

	/** @return array<string,array{0:string}> */
	public static function unusablePorts(): array
	{
		return ['above 65535' => ['70000'], 'zero' => ['0'], 'not a number' => ['https'], 'signed' => ['+853']];
	}

	#[DataProvider('unusablePorts')]
	public function testATransportWithAnUnusableStoredPortIsNotCounted(string $port): void
	{
		// Given DoT and DoQ on a public address, both with a usable port
		$this->box(['wan' => ['8.8.8.8']], [], ['pfb_dns_doq' => 'on']);
		$this->assertSame([self::warning('8.8.8.8', 'DoT and DoQ')], pfb_dns_proxy_ddr_warnings(), 'both listen');

		// When the DoT port is unusable, the gateway does not serve DoT: only DoQ is named
		$this->store(['pfb_dns_dot_port' => $port]);
		$this->assertSame([self::warning('8.8.8.8', 'DoQ')], pfb_dns_proxy_ddr_warnings());

		// And with DoQ's unusable too, nothing is served
		$this->store(['pfb_dns_doq_port' => $port]);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings());
	}

	public function testATransportWhoseInterfaceListNamesNoInterfaceIsNotCounted(): void
	{
		// Given DoT and DoQ on a public address
		$this->box(['wan' => ['8.8.8.8']], [], ['pfb_dns_doq' => 'on']);
		$this->assertSame([self::warning('8.8.8.8', 'DoT and DoQ')], pfb_dns_proxy_ddr_warnings(), 'both listen');

		// When DoT's interface list holds no name, only DoQ is named
		$this->store(['pfb_dns_dot_interface' => ' , ']);
		$this->assertSame([self::warning('8.8.8.8', 'DoQ')], pfb_dns_proxy_ddr_warnings());
	}

	public function testATransportThatIsOffIsNotCounted(): void
	{
		// Given DoT and DoQ on a public address, DoQ off
		$this->box(['wan' => ['8.8.8.8']], [], ['pfb_dns_doq' => 'on']);
		$this->assertSame([self::warning('8.8.8.8', 'DoT and DoQ')], pfb_dns_proxy_ddr_warnings(), 'both on');

		// When DoT is off, only DoQ is named
		$this->store(['pfb_dns_dot' => '']);
		$this->assertSame([self::warning('8.8.8.8', 'DoQ')], pfb_dns_proxy_ddr_warnings());

		// And with DoQ off too, no encrypted transport serves anything
		$this->store(['pfb_dns_doq' => '']);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings());
	}

	// -----------------------------------------------------------------------
	// a certificate that cannot be read
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:string}> the crt field of a config.xml <cert> entry */
	public static function undecodableCertificates(): array
	{
		return [
			'not base64' => ['!!! not base64 !!!'],
			'base64 of something that is no certificate' => [base64_encode('this is not a certificate')],
			'no crt at all' => [''],
		];
	}

	#[DataProvider('undecodableCertificates')]
	public function testACertificateThatCannotBeDecodedHasNoSansAndNothingThrows(string $crt): void
	{
		// Given a public address, and a certificate whose SAN matches it
		$this->box(['wan' => ['8.8.8.8']], ['IP:8.8.8.8']);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings(), 'the readable certificate covers it');

		// When the stored certificate is unreadable
		$GLOBALS['config']['cert'][0]['crt'] = $crt;

		// Then the address is warned about, without an exception
		$this->assertSame([self::warning('8.8.8.8', 'DoT')], pfb_dns_proxy_ddr_warnings());
	}

	// -----------------------------------------------------------------------
	// public or not
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:string,1:bool}> */
	public static function addresses(): array
	{
		$rows = [];
		// each excluded range: first address, last address, and the nearest address outside it on each side
		foreach ([
			'0.0.0.0/8' => ['0.0.0.0', '0.255.255.255', NULL, '1.0.0.0'],
			'10.0.0.0/8' => ['10.0.0.0', '10.255.255.255', '9.255.255.255', '11.0.0.0'],
			'100.64.0.0/10' => ['100.64.0.0', '100.127.255.255', '100.63.255.255', '100.128.0.0'],
			'127.0.0.0/8' => ['127.0.0.0', '127.255.255.255', '126.255.255.255', '128.0.0.0'],
			'169.254.0.0/16' => ['169.254.0.0', '169.254.255.255', '169.253.255.255', '169.255.0.0'],
			'172.16.0.0/12' => ['172.16.0.0', '172.31.255.255', '172.15.255.255', '172.32.0.0'],
			'192.0.2.0/24' => ['192.0.2.0', '192.0.2.255', '192.0.1.255', '192.0.3.0'],
			'192.168.0.0/16' => ['192.168.0.0', '192.168.255.255', '192.167.255.255', '192.169.0.0'],
			'198.18.0.0/15' => ['198.18.0.0', '198.19.255.255', '198.17.255.255', '198.20.0.0'],
			'198.51.100.0/24' => ['198.51.100.0', '198.51.100.255', '198.51.99.255', '198.51.101.0'],
			'203.0.113.0/24' => ['203.0.113.0', '203.0.113.255', '203.0.112.255', '203.0.114.0'],
			'::/128' => ['::', '0:0:0:0:0:0:0:0', NULL, '::2'],
			'::1/128' => ['::1', '0:0:0:0:0:0:0:1', NULL, '::2'],
			'fc00::/7' => ['fc00::', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fe00::'],
			'fe80::/10' => ['fe80::', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fec0::1'],
			'2001:db8::/32' => ['2001:db8::', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', '2001:db7:ffff::', '2001:db9::'],
		] as $range => [$first, $last, $below, $above]) {
			$rows["{$range} first"] = [$first, FALSE];
			$rows["{$range} last"] = [$last, FALSE];
			if ($below !== NULL) {
				$rows["just below {$range}"] = [$below, TRUE];
			}
			$rows["just above {$range}"] = [$above, TRUE];
		}
		foreach (['8.8.8.8', '1.1.1.1', '2606:4700::1', '2001:4860:4860::8888', 'fbff:ffff::'] as $address) {
			$rows["public {$address}"] = [$address, TRUE];
		}
		// an IPv4-mapped address is classified by the IPv4 address it carries
		foreach ([
			'::ffff:10.0.0.1' => FALSE, '::ffff:127.0.0.1' => FALSE, '::ffff:100.64.0.1' => FALSE, '::ffff:0.0.0.1' => FALSE, '::ffff:192.0.2.1' => FALSE,
			'::ffff:8.8.8.8' => TRUE, '::ffff:172.15.255.255' => TRUE, '::ffff:172.32.0.0' => TRUE,
			// only the ::ffff: prefix maps: the same low 32 bits under another prefix are an address of their own
			'::a00:1' => TRUE, '64:ff9b::a00:1' => TRUE,
		] as $address => $public) {
			$rows["mapped {$address}"] = [$address, $public];
		}
		foreach (['', 'lan', '1.2.3', '::ffff:999.1.1.1', '8.8.8.8/32', ' 8.8.8.8', 'fe80::1%em0', '2606:4700::1::1'] as $text) {
			$rows["not an address '{$text}'"] = [$text, FALSE];
		}
		return $rows;
	}

	#[DataProvider('addresses')]
	public function testAnAddressIsPublicUnlessItIsInOneOfTheExcludedRangesOrIsNoAddress(string $address, bool $public): void
	{
		$this->assertSame($public, pfb_dns_proxy_public_address($address), "is '{$address}' public?");
	}
}
