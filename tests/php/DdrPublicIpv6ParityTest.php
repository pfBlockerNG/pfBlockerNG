<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3694: the gateway gives a DDR query that arrives on a public IPv6 address no designations (a global prefix changes, so
 * no certificate can keep an IP SAN for it), and the pfB-DNS page does not warn about such an address for the same reason. Which
 * addresses those are is decided twice, by PFB_DNS_PROXY_NON_PUBLIC here and by go/pfb_dns_gateway there. Both read the shared
 * fixture tests/fixtures/ddr_public_ipv6.json (go/pfb_dns_gateway/ddr_public_ipv6_test.go holds the gateway to it), so a range or
 * an address that moves on one side and not the other fails a test.
 */
#[CoversFunction('pfb_dns_proxy_public_address')]
#[CoversFunction('pfb_dns_proxy_ddr_warnings')]
final class DdrPublicIpv6ParityTest extends TestCase
{
	private const GLOBALS = ['config', 'pfb_test_interface_ip', 'pfb_test_interface_info', 'pfb_test_configured_ipv6', 'pfb_test_interfaces'];

	/** @var array<string,array{0:bool,1:mixed}> */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$GLOBALS['config'] = [];
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

	/** @return array{ranges:list<string>,addresses:list<array{address:string,public:bool,ddr:bool}>} */
	private static function fixture(): array
	{
		return json_decode((string) file_get_contents(__DIR__ . '/../fixtures/ddr_public_ipv6.json'), TRUE, 8, JSON_THROW_ON_ERROR);
	}

	/** @return array<string,array{0:string,1:bool,2:bool}> address, public (PHP's predicate), designated by the gateway */
	public static function addresses(): array
	{
		$rows = [];
		foreach (self::fixture()['addresses'] as $row) {
			$rows[$row['address']] = [$row['address'], $row['public'], $row['ddr']];
		}
		return $rows;
	}

	public function testTheFixtureNamesExactlyTheIpv6RangesPfbDnsNeverWarnsAbout(): void
	{
		$this->assertSame(
			array_values(array_filter(PFB_DNS_PROXY_NON_PUBLIC, static fn (string $range): bool => str_contains($range, ':'))),
			self::fixture()['ranges'],
			'the gateway withholds DDR on a public IPv6 address, public being outside these ranges: change both lists together'
		);
	}

	#[DataProvider('addresses')]
	public function testPhpAndTheFixtureAgreeWhichAddressIsPublicAndWhichIsDesignated(string $address, bool $public, bool $designated): void
	{
		$this->assertSame($public, pfb_dns_proxy_public_address($address));
		$ipv6 = str_contains($address, ':') && pfb_ipv4_from_mapped($address) === NULL;
		$this->assertSame(!($ipv6 && $public), $designated, 'DDR is withheld on a public IPv6 address and nowhere else; an IPv4-mapped address is its IPv4 one');
	}

	/** DoT on the LAN's address, DDR on, and a certificate with no IP SAN: the only reason not to warn about a public address is that DDR is withheld on it. */
	#[DataProvider('addresses')]
	public function testTheCertificateWarningSkipsExactlyWhatTheGatewayDoesNotDesignate(string $address, bool $public, bool $designated): void
	{
		// Given DoT on this address of the LAN
		$ipv4 = !str_contains($address, ':');
		$GLOBALS['pfb_test_interface_ip'] = $ipv4 ? ['lan' => $address] : [];
		$GLOBALS['pfb_test_configured_ipv6'] = $ipv4 ? [] : ['lan' => $address];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost', NULL, []))];
		config_set_path(PFB_SECTIONS[explode('/', pfb_dns_config_key('pfb_dns_sslcertref'), 2)[0]] . '/pfb_dns_sslcertref', 'cert1');
		foreach (['dns/pfb_dns_interface' => 'lan', 'dns_shared/pfb_dns_ddr' => 'on', 'dns_shared/pfb_dns_dot' => 'on', 'dns/pfb_dns_dot_interface' => 'lan'] as $key => $value) {
			PfbConfig::write($key, $value);
		}

		// Then a public address is warned about unless the gateway gives no designations on it
		$warning = "DDR: DoT on {$address} will not be used by clients that verify DDR, because the selected SSL/TLS Certificate has no IP address (iPAddress) SAN for it.";
		$this->assertSame($public && $designated ? [$warning] : [], pfb_dns_proxy_ddr_warnings());
	}
}
