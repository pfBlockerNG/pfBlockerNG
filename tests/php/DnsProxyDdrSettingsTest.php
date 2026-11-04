<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3583 -- pfB-DNS's DDR (RFC 9462) toggle on its page: `pfb_dns_ddr`.
 *
 * Functions under test, through their production surface:
 *   - pfb_validate_dns_proxy_listeners_post(): the toggle adds no input error while a DNS Name is set (DDR needs one, issue #3694).
 *   - pfb_dns_proxy_listeners_stored(): the toggle is on only for 'on', whatever else is posted.
 *
 * "Advertise DoH on port 443" is a selection of interfaces since issue #3694 (DnsProxyDdrDoh443InterfacesTest); the two per-family
 * checkboxes it replaced, and the lock that disabled one of them while the stored DoH port was 443, are gone.
 * The rc command line (--ddr and the rest) is pinned in DnsProxyServiceTest and DnsProxyNameAnswersTest; the page wiring in
 * PfbDnsPageWiringTest. Every post here carries a DNS Name, so that the toggle is the only thing that varies; DnsProxyDnsNameSettingsTest
 * pins the rest.
 */
#[CoversFunction('pfb_validate_dns_proxy_listeners_post')]
#[CoversFunction('pfb_dns_proxy_listeners_stored')]
final class DnsProxyDdrSettingsTest extends TestCase
{
	private const IFACES = ['all', 'lo0', 'lan', 'opt1'];
	private const CERTS = ['cert5f3a'];
	private const DDR = 'pfb_dns_ddr';

	private mixed $savedConfig = NULL;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
	}

	/** @param array<string,mixed> $over fields replacing the defaults the page posts: every list holds one entry, every transport and DDR are off, the DNS Name is set */
	private function post(array $over = []): array
	{
		return $over + [
			'pfb_dns_interface' => ['lan'],
			'pfb_dns_dot' => '', 'pfb_dns_dot_port' => '853', 'pfb_dns_dot_interface' => ['lan'],
			'pfb_dns_doh' => '', 'pfb_dns_doh_port' => '4443', 'pfb_dns_doh_interface' => ['lan'],
			'pfb_dns_doh_trusted' => '',
			'pfb_dns_doq' => '', 'pfb_dns_doq_port' => '853', 'pfb_dns_doq_interface' => ['lan'],
			'pfb_dns_sslcertref' => '',
			'pfb_dns_name' => 'fw.example.lan',
			self::DDR => '',
		];
	}

	/** @return array<string,array{array<string,string>,string}> posted fields (absent when not given), what is stored */
	public static function postedValues(): array
	{
		return ['on' => [['v' => 'on'], 'on'], 'absent' => [[], ''], 'empty' => [['v' => ''], ''], 'yes' => [['v' => 'yes'], '']];
	}

	/** The toggle: posted on is on, and absent, empty or anything else is stored off. */
	public function testTheToggleIsStoredOnOnlyWhenPostedOn(): void
	{
		foreach (self::postedValues() as $label => [$posted, $expected]) {
			$post = $this->post();
			unset($post[self::DDR]);
			if (isset($posted['v'])) {
				$post[self::DDR] = $posted['v'];
			}

			$this->assertSame($expected, pfb_dns_proxy_listeners_stored($post)[self::DDR] ?? NULL, "DDR posted as {$label}");
		}
	}

	public function testTheToggleOnIsNeverAnInputErrorWhileANameIsSet(): void
	{
		$this->assertSame([], pfb_validate_dns_proxy_listeners_post($this->post(), self::IFACES, self::CERTS), 'before: DDR off posts no error');

		$this->assertSame([], pfb_validate_dns_proxy_listeners_post($this->post([self::DDR => 'on']), self::IFACES, self::CERTS));
	}

	public function testAPostWithNoFieldsStoresTheToggleOff(): void
	{
		$this->assertSame('', pfb_dns_proxy_listeners_stored([])[self::DDR] ?? NULL);
	}

	/** @return array<string,array{string}> the stored DoH port: whatever it is, DDR is taken from the post */
	public static function dohPorts(): array
	{
		return ['443' => ['443'], '4443' => ['4443']];
	}

	#[DataProvider('dohPorts')]
	public function testTheToggleIsAlwaysTakenFromThePostWhateverTheStoredDohPort(string $port): void
	{
		PfbConfig::write('dns_shared/pfb_dns_doh_port', $port);
		PfbConfig::write(pfb_dns_config_key(self::DDR), 'on');
		$post = $this->post();
		unset($post[self::DDR]);

		$this->assertSame('', pfb_dns_proxy_listeners_stored($post)[self::DDR] ?? NULL, 'absent turns DDR off');
		$this->assertSame('on', pfb_dns_proxy_listeners_stored($this->post([self::DDR => 'on']))[self::DDR] ?? NULL, 'posted on turns it on');
	}
}
