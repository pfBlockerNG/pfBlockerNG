<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3583 -- pfB-DNS's DDR (RFC 9462) settings on its page: the toggle `pfb_dns_ddr` and the toggle
 * `pfb_dns_ddr_doh_443` that leaves the port out of the DDR DoH record.
 *
 * Functions under test, through their production surface:
 *   - pfb_validate_dns_proxy_listeners_post(): the two toggles add no input error, whatever they post.
 *   - pfb_dns_proxy_listeners_stored(): each toggle is stored on only for 'on' and is stored independently of the other,
 *     except that the 443 toggle keeps its stored value while the page disables it (the STORED DoH port is 443), because
 *     a disabled control posts nothing.
 *
 * The rc command line (--ddr, --ddr-doh-443) is pinned in DnsProxyServiceTest; the page wiring in PfbDnsPageWiringTest.
 */
#[CoversFunction('pfb_validate_dns_proxy_listeners_post')]
#[CoversFunction('pfb_dns_proxy_listeners_stored')]
final class DnsProxyDdrSettingsTest extends TestCase
{
	private const IFACES = ['all', 'lo0', 'lan', 'opt1'];
	private const CERTS = ['cert5f3a'];
	private const DDR = 'pfb_dns_ddr';
	private const DOH_443 = 'pfb_dns_ddr_doh_443';

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

	/** @param array<string,mixed> $over fields replacing the defaults the page posts: every list holds one entry, every transport and both DDR toggles are off */
	private function post(array $over = []): array
	{
		return $over + [
			'pfb_dns_interface' => ['lan'],
			'pfb_dns_dot' => '', 'pfb_dns_dot_port' => '853', 'pfb_dns_dot_interface' => ['lan'],
			'pfb_dns_doh' => '', 'pfb_dns_doh_port' => '4443', 'pfb_dns_doh_interface' => ['lan'],
			'pfb_dns_doh_trusted' => '',
			'pfb_dns_doq' => '', 'pfb_dns_doq_port' => '853', 'pfb_dns_doq_interface' => ['lan'],
			'pfb_dns_sslcertref' => '',
			self::DDR => '', self::DOH_443 => '',
		];
	}

	/** @return array<string,array{string}> */
	public static function ddrToggles(): array
	{
		return ['DDR' => [self::DDR], 'DoH on port 443' => [self::DOH_443]];
	}

	/** @return array<string,array{array<string,string>,string}> posted fields (absent when not given), what is stored */
	public static function postedValues(): array
	{
		return ['on' => [['v' => 'on'], 'on'], 'absent' => [[], ''], 'empty' => [['v' => ''], ''], 'yes' => [['v' => 'yes'], '']];
	}

	/** Each toggle: posted on is on, and absent, empty or anything else is stored off. */
	#[DataProvider('ddrToggles')]
	public function testEachToggleIsStoredOnOnlyWhenPostedOn(string $field): void
	{
		foreach (self::postedValues() as $label => [$posted, $expected]) {
			$post = $this->post();
			unset($post[$field]);
			if (isset($posted['v'])) {
				$post[$field] = $posted['v'];
			}

			$this->assertSame($expected, pfb_dns_proxy_listeners_stored($post)[$field] ?? NULL, "{$field} posted as {$label}");
		}
	}

	#[DataProvider('ddrToggles')]
	public function testEitherToggleOnIsNeverAnInputError(string $field): void
	{
		$this->assertSame([], pfb_validate_dns_proxy_listeners_post($this->post(), self::IFACES, self::CERTS), 'before: both off posts no error');

		$this->assertSame([], pfb_validate_dns_proxy_listeners_post($this->post([$field => 'on']), self::IFACES, self::CERTS));
	}

	/** @return array<string,array{string,string,string,string}> posted DDR, posted 443, stored DDR, stored 443 */
	public static function combinations(): array
	{
		return [
			'both off'            => ['', '', '', ''],
			'DDR only'            => ['on', '', 'on', ''],
			'443 only'            => ['', 'on', '', 'on'],
			'both on'             => ['on', 'on', 'on', 'on'],
		];
	}

	#[DataProvider('combinations')]
	public function testTheTwoTogglesAreStoredIndependentlyOfEachOther(string $ddr, string $doh443, string $storedDdr, string $stored443): void
	{
		$stored = pfb_dns_proxy_listeners_stored($this->post([self::DDR => $ddr, self::DOH_443 => $doh443]));

		$this->assertSame($storedDdr, $stored[self::DDR] ?? NULL, 'DDR');
		$this->assertSame($stored443, $stored[self::DOH_443] ?? NULL, 'DoH on port 443 (kept while DDR is off, for when it is turned on again)');
	}

	public function testAPostWithNoFieldsStoresBothTogglesOff(): void
	{
		$stored = pfb_dns_proxy_listeners_stored([]);

		$this->assertSame('', $stored[self::DDR] ?? NULL);
		$this->assertSame('', $stored[self::DOH_443] ?? NULL);
	}

	/**
	 * @return array<string,array{?string,string,?string,string}> the stored DoH port (NULL = never stored), the stored 443 toggle,
	 *         the posted 443 toggle (NULL = absent), what the save stores
	 */
	public static function lockedRows(): array
	{
		return [
			'port 443, stored On, absent'                      => ['443', 'on', NULL, 'on'],
			'port 443, stored On, posted on'                   => ['443', 'on', 'on', 'on'],
			'port 443, stored Off, posted on'                  => ['443', '', 'on', ''],
			'port 443, stored Off, absent'                     => ['443', '', NULL, ''],
			'port 0443 reads as 443, stored On, absent'        => ['0443', 'on', NULL, 'on'],
			'port 4443, stored On, absent'                     => ['4443', 'on', NULL, ''],
			'port 4443, stored Off, posted on'                 => ['4443', '', 'on', 'on'],
			'port 4443, stored On, posted on'                  => ['4443', 'on', 'on', 'on'],
			'port 1443, stored On, absent'                     => ['1443', 'on', NULL, ''],
			'port 4430, stored Off, posted on'                 => ['4430', '', 'on', 'on'],
			'port 8443, stored Off, posted on'                 => ['8443', '', 'on', 'on'],
			'a stored port that is no port, stored On, absent' => ['abc', 'on', NULL, ''],
			'no stored port (default 4443), stored On, absent' => [NULL, 'on', NULL, ''],
			'no stored port (default 4443), posted on'         => [NULL, '', 'on', 'on'],
		];
	}

	#[DataProvider('lockedRows')]
	public function testTheDohOn443ToggleKeepsItsStoredValueExactlyWhileTheStoredDohPortIs443(?string $storedPort, string $storedToggle, ?string $posted, string $expected): void
	{
		// Given the stored DoH port and 443 toggle; the form posts the port field either way
		if ($storedPort !== NULL) {
			PfbConfig::write('dns/pfb_dns_doh_port', $storedPort);
		}
		PfbConfig::write('dns/' . self::DOH_443, $storedToggle);
		$post = $this->post();
		unset($post[self::DOH_443]);
		if ($posted !== NULL) {
			$post[self::DOH_443] = $posted;
		}

		// When the save computes what to store
		$stored = pfb_dns_proxy_listeners_stored($post);

		// Then the toggle is the stored one while the page disables it, and the posted one otherwise
		$this->assertSame($expected, $stored[self::DOH_443] ?? NULL);
	}

	public function testOnlyTheStoredDohPortDecidesWhetherTheControlWasDisabledNotThePostedOne(): void
	{
		// Given the stored port 4443 (the checkbox was enabled)
		PfbConfig::write('dns/pfb_dns_doh_port', '4443');
		PfbConfig::write('dns/' . self::DOH_443, '');
		$this->assertSame('on', pfb_dns_proxy_listeners_stored($this->post(['pfb_dns_doh_port' => '4443', self::DOH_443 => 'on']))[self::DOH_443] ?? NULL, 'before: the same post with the port left alone');

		// Then a post that moves DoH to 443 in the same save still takes the posted toggle
		$this->assertSame('on', pfb_dns_proxy_listeners_stored($this->post(['pfb_dns_doh_port' => '443', self::DOH_443 => 'on']))[self::DOH_443] ?? NULL);

		// And with the stored port 443 (control disabled, nothing posted) a post that moves DoH away keeps the stored On
		PfbConfig::write('dns/pfb_dns_doh_port', '443');
		PfbConfig::write('dns/' . self::DOH_443, 'on');
		$post = $this->post(['pfb_dns_doh_port' => '4443']);
		unset($post[self::DOH_443]);
		$this->assertSame('on', pfb_dns_proxy_listeners_stored($post)[self::DOH_443] ?? NULL);
	}

	public function testTheDdrToggleIsAlwaysTakenFromThePostWhateverTheStoredDohPort(): void
	{
		PfbConfig::write('dns/pfb_dns_doh_port', '443');
		PfbConfig::write('dns/' . self::DDR, 'on');
		$post = $this->post();
		unset($post[self::DDR]);

		$this->assertSame('', pfb_dns_proxy_listeners_stored($post)[self::DDR] ?? NULL, 'absent turns DDR off');
		$this->assertSame('on', pfb_dns_proxy_listeners_stored($this->post([self::DDR => 'on']))[self::DDR] ?? NULL, 'posted on turns it on');
	}
}
