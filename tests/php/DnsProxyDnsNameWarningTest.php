<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3694 -- what the pfB-DNS page says about the DNS Name, without blocking the save:
 *   (a) DDR is On and no DNS Name is set: nothing is said, and DDR answers nothing until a name is entered;
 *   (b) a name is set, DoT, DoH or DoQ is on, the selected certificate resolves, and none of its dNSName SANs covers the name: a
 *       client that connects by that name will not accept it. Covering is the name itself, ASCII case-insensitive, or a wildcard
 *       `*.<parent>` whose parent is everything after the name's first label. An iPAddress SAN never covers a name.
 * Neither depends on the iPAddress warnings (DnsProxyDdrWarningTest), which are only computed while DDR is On and a name is set.
 *
 * The certificates are real ones issued with the SANs of the case.
 */
#[CoversFunction('pfb_dns_proxy_ddr_warnings')]
#[CoversFunction('pfb_dns_proxy_certificate_sans')]
final class DnsProxyDnsNameWarningTest extends TestCase
{
	private const NAME = 'fw.example.lan';
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

	private static function noSan(string $name): string
	{
		return "DNS Name: the selected SSL/TLS Certificate has no DNS name (dNSName) SAN for {$name}; clients that connect by that name will not accept it.";
	}

	private static function noIpSan(string $address): string
	{
		return "DDR: DoT on {$address} will not be used by clients that verify DDR, because the selected SSL/TLS Certificate has no IP address (iPAddress) SAN for it.";
	}

	/** @param array<string,string> $settings */
	private function store(array $settings): void
	{
		foreach ($settings as $key => $value) {
			config_set_path(PFB_SECTIONS[explode('/', pfb_dns_config_key($key), 2)[0]] . '/' . $key, $value);
		}
	}

	/**
	 * A box with a public address on `wan`, DoT on it (port 853), certificate `cert1` with these SANs selected, DDR off and no name.
	 *
	 * @param list<string> $san OpenSSL subjectAltName entries of the certificate
	 * @param array<string,string> $settings stored settings that replace the defaults
	 */
	private function box(array $san = [], array $settings = []): void
	{
		$GLOBALS['pfb_test_interface_ip'] = ['wan' => '8.8.8.8'];
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$GLOBALS['pfb_test_interface_info'] = ['wan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['wan' => ''];
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost', NULL, $san))];
		$this->store($settings + [
			'pfb_dns_interface' => 'wan', 'pfb_dns_sslcertref' => 'cert1', 'pfb_dns_ddr' => '', 'pfb_dns_name' => '',
			'pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '853', 'pfb_dns_dot_interface' => 'wan',
			'pfb_dns_doh' => '', 'pfb_dns_doh_port' => '8443', 'pfb_dns_doh_interface' => 'wan',
			'pfb_dns_doq' => '', 'pfb_dns_doq_port' => '8853', 'pfb_dns_doq_interface' => 'wan',
		]);
	}

	// -----------------------------------------------------------------------
	// the certificate's SANs
	// -----------------------------------------------------------------------

	public function testBothKindsOfSanAreReadTheDnsOnesLowerCased(): void
	{
		// Given a certificate with SANs of three kinds
		$this->box(['DNS:FW.Example.LAN', 'DNS:*.example.lan', 'IP:192.0.2.1', 'IP:2606:4700::1', 'email:a@b.example']);

		// When they are parsed
		$sans = pfb_dns_proxy_certificate_sans($GLOBALS['config']['cert'][0]);

		// Then the DNS names are lower-cased, in the certificate's order, and the addresses are packed so that spellings match
		$this->assertSame(['fw.example.lan', '*.example.lan'], $sans['dns']);
		$this->assertSame([inet_pton('192.0.2.1'), inet_pton('2606:4700::1')], array_keys($sans['ip']));
	}

	public function testACertificateWithNoSansOrThatCannotBeDecodedHasNoneAndNothingThrows(): void
	{
		$this->box();
		$this->assertSame(['ip' => [], 'dns' => []], pfb_dns_proxy_certificate_sans($GLOBALS['config']['cert'][0]), 'a certificate without the extension');

		// When the stored certificate is unreadable, with OpenSSL's error queue empty before
		$this->box(['DNS:fw.example.lan']);
		$this->assertSame(['fw.example.lan'], pfb_dns_proxy_certificate_sans($GLOBALS['config']['cert'][0])['dns'], 'before: the readable certificate has its SAN');
		while (openssl_error_string() !== FALSE) {
			continue;
		}
		foreach (['!!! not base64 !!!', base64_encode('this is not a certificate'), ''] as $crt) {
			$GLOBALS['config']['cert'][0]['crt'] = $crt;

			// Then it has no SAN, and the failed parse leaves nothing in the queue for the next caller
			$this->assertSame(['ip' => [], 'dns' => []], pfb_dns_proxy_certificate_sans($GLOBALS['config']['cert'][0]), "crt: '{$crt}'");
			$this->assertFalse(openssl_error_string(), 'OpenSSL error queue left empty');
		}
	}

	// -----------------------------------------------------------------------
	// (b) a name no SAN of the certificate covers
	// -----------------------------------------------------------------------

	/** @return array<string,array{list<string>,string,bool}> the certificate's SANs, the stored name, whether the warning appears */
	public static function coverRows(): array
	{
		return [
			'the name as a DNS SAN' => [['DNS:fw.example.lan'], 'fw.example.lan', FALSE],
			'a DNS SAN in capitals, the name in lower case' => [['DNS:FW.EXAMPLE.LAN'], 'fw.example.lan', FALSE],
			'a DNS SAN in lower case, the name in capitals' => [['DNS:fw.example.lan'], 'FW.Example.LAN', FALSE],
			'a wildcard covers one label under its parent' => [['DNS:*.example.lan'], 'fw.example.lan', FALSE],
			'a wildcard covers a name of exactly one label under it, whatever the parent is' => [['DNS:*.lan'], 'example.lan', FALSE],
			'the name among other SANs of every kind' => [['IP:192.0.2.1', 'DNS:other.example.lan', 'email:a@b.example', 'DNS:fw.example.lan'], 'fw.example.lan', FALSE],
			'a wildcard does not cover its own parent' => [['DNS:*.example.lan'], 'example.lan', TRUE],
			'a wildcard covers one label only, not two' => [['DNS:*.example.lan'], 'a.fw.example.lan', TRUE],
			'a wildcard of another parent' => [['DNS:*.other.lan'], 'fw.example.lan', TRUE],
			'another name' => [['DNS:other.example.lan'], 'fw.example.lan', TRUE],
			'a longer name' => [['DNS:a.fw.example.lan'], 'fw.example.lan', TRUE],
			'an iPAddress SAN is no name' => [['IP:192.0.2.1'], 'fw.example.lan', TRUE],
			'no SAN at all' => [[], 'fw.example.lan', TRUE],
		];
	}

	/** @param list<string> $san */
	#[DataProvider('coverRows')]
	public function testTheWarningNamesTheDnsNameWhenNoDnsSanOfTheCertificateCoversIt(array $san, string $name, bool $warns): void
	{
		// Given DoT on and a certificate with these SANs; DDR is off, so the warning stands on its own
		$this->box($san, ['pfb_dns_name' => $name]);

		// Then the warning is there exactly when no SAN covers the name
		$this->assertSame($warns ? [self::noSan($name)] : [], pfb_dns_proxy_ddr_warnings());
	}

	public function testNoWarningWithoutAnEncryptedTransportOrACertificate(): void
	{
		// Given a name the certificate lacks, with DoT on: it warns
		$this->box([], ['pfb_dns_name' => self::NAME]);
		$this->assertSame([self::noSan(self::NAME)], pfb_dns_proxy_ddr_warnings(), 'before');

		// When no encrypted transport is wanted, there is no certificate to check against the name
		$this->store(['pfb_dns_dot' => '']);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings(), 'no transport');

		// And DoH or DoQ alone is enough
		$this->store(['pfb_dns_doh' => 'on']);
		$this->assertSame([self::noSan(self::NAME)], pfb_dns_proxy_ddr_warnings(), 'DoH alone');
		$this->store(['pfb_dns_doh' => '', 'pfb_dns_doq' => 'on']);
		$this->assertSame([self::noSan(self::NAME)], pfb_dns_proxy_ddr_warnings(), 'DoQ alone');
		$this->store(['pfb_dns_doq' => '']);

		// And with a transport but no certificate selected, or one that does not exist, there is nothing to warn about
		$this->store(['pfb_dns_dot' => 'on']);
		$this->assertSame([self::noSan(self::NAME)], pfb_dns_proxy_ddr_warnings(), 'DoT back on');
		$this->store(['pfb_dns_sslcertref' => '']);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings(), 'no certificate selected');
		$this->store(['pfb_dns_sslcertref' => 'gone']);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings(), 'a selection that names no certificate');
	}

	public function testNoNameMeansNoSanWarning(): void
	{
		$this->box([], ['pfb_dns_name' => self::NAME]);
		$this->assertSame([self::noSan(self::NAME)], pfb_dns_proxy_ddr_warnings(), 'before: a name the certificate lacks');

		$this->store(['pfb_dns_name' => '']);

		$this->assertSame([], pfb_dns_proxy_ddr_warnings());
	}

	// -----------------------------------------------------------------------
	// (a) DDR On and no name
	// -----------------------------------------------------------------------

	public function testDdrOnWithoutANameWarnsAboutNothing(): void
	{
		// Given DDR off with a public address the certificate lacks, and no name: nothing to say
		$this->box();
		$this->assertSame([], pfb_dns_proxy_ddr_warnings(), 'before: DDR off');

		// When DDR is On (row N14), with a transport and a certificate that would otherwise warn about the address
		$this->store(['pfb_dns_ddr' => 'on']);

		// Then nothing is said, and the iPAddress warning is not computed for a DDR that answers nothing
		$this->assertSame([], pfb_dns_proxy_ddr_warnings());

		// And entering a name brings the address warning and the name warning back
		$this->store(['pfb_dns_name' => self::NAME]);
		$this->assertSame([self::noSan(self::NAME), self::noIpSan('8.8.8.8')], pfb_dns_proxy_ddr_warnings(), 'with a name');
	}

	public function testAStoredNameThatIsNoValidNameCountsAsNone(): void
	{
		$this->box(['DNS:fw.example.lan'], ['pfb_dns_ddr' => 'on', 'pfb_dns_name' => self::NAME]);
		$this->assertSame([self::noIpSan('8.8.8.8')], pfb_dns_proxy_ddr_warnings(), 'before: a valid name');

		$this->store(['pfb_dns_name' => "fw.example.lan'; rm -rf /"]);

		$this->assertSame([], pfb_dns_proxy_ddr_warnings());
	}

	public function testTheAddressWarningsAreOnlyComputedWhileDdrIsOn(): void
	{
		// Given a certificate that covers the name but not the public address, and DDR off
		$this->box(['DNS:fw.example.lan'], ['pfb_dns_name' => self::NAME]);
		$this->assertSame([], pfb_dns_proxy_ddr_warnings(), 'DDR off: a name alone adds no address warning');

		// When DDR is turned on
		$this->store(['pfb_dns_ddr' => 'on']);

		// Then the address is named
		$this->assertSame([self::noIpSan('8.8.8.8')], pfb_dns_proxy_ddr_warnings());
	}
}
