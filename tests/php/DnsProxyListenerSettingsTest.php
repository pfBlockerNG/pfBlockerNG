<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3513 -- the DNSBL page's DoH/DoQ listener settings of the DNS proxy.
 *
 * Functions under test:
 *   - pfb_validate_dns_proxy_listeners_post(): the save-time input errors for the seven fields. A port is a
 *     whole number 1-65535, an interface is one the page offers, every trusted front end is an IP or CIDR
 *     (never a link-local zone, never shell text), and DoH/DoQ need the DNS Resolver's SSL/TLS certificate.
 *   - pfb_dns_proxy_listeners_stored(): the canonical stored strings the page persists once validation passed.
 *   - pfb_dns_proxy_tokens(): the one splitter for a space/comma separated list.
 *
 * The page's section save cannot run under PHPUnit (guiconfig.inc exits), so the page calls only these
 * functions; tests/smoke/ui/test_functional.py covers the page itself on a live box.
 */
#[CoversFunction('pfb_validate_dns_proxy_listeners_post')]
#[CoversFunction('pfb_dns_proxy_listeners_stored')]
#[CoversFunction('pfb_dns_proxy_tokens')]
final class DnsProxyListenerSettingsTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_dns.php';
	private const IFACES = ['lan', 'opt1'];
	private const PORT_FIELDS = ['DoH port' => ['pfb_dns_doh_port'], 'DoQ port' => ['pfb_dns_doq_port']];
	private const INTERFACE_FIELDS = ['DoH' => ['pfb_dns_doh_interface'], 'DoQ' => ['pfb_dns_doq_interface']];

	/** @param array<string,mixed> $over fields replacing the defaults the page posts on a fresh install */
	private function post(array $over = []): array
	{
		return $over + [
			'pfb_dns_doh' => '', 'pfb_dns_doh_port' => '4443', 'pfb_dns_doh_interface' => [],
			'pfb_dns_doh_trusted' => '',
			'pfb_dns_doq' => '', 'pfb_dns_doq_port' => '853', 'pfb_dns_doq_interface' => [],
		];
	}

	/** @return list<string> */
	private function errors(array $over = [], string $certref = 'cert5f3a'): array
	{
		return pfb_validate_dns_proxy_listeners_post($this->post($over), self::IFACES, $certref);
	}

	// -----------------------------------------------------------------------
	// V1 -- ports
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> */
	public static function badPorts(): array
	{
		return [
			'empty'            => [''],
			'zero'             => ['0'],
			'one past the top' => ['65536'],
			'trailing junk'    => ['53x'],
			'negative'         => ['-1'],
			'service name'     => ['domain'],
			'padded'           => [' 443'],
			'overflowing int'  => ['99999999999999999999'],
			'fullwidth digits' => ['４４４３'],
		];
	}

	#[DataProvider('badPorts')]
	public function testAPortOutsideOneToSixtyFiveThousandIsAnInputErrorForBothFields(string $port): void
	{
		foreach (array_keys(self::PORT_FIELDS) as $label) {
			$field = self::PORT_FIELDS[$label][0];
			$this->assertSame([], $this->errors(), 'before: the defaults post no error');

			$errors = $this->errors([$field => $port]);

			$this->assertCount(1, $errors, "{$label} {$port}: " . json_encode($errors));
			$this->assertStringContainsString(str_starts_with($field, 'pfb_dns_doh') ? 'DoH' : 'DoQ', $errors[0]);
			$this->assertStringContainsString('Port', $errors[0]);
		}
	}

	/** @return array<string,array{string}> */
	public static function goodPorts(): array
	{
		return ['default DoH' => ['4443'], 'lowest' => ['1'], 'highest' => ['65535'], 'zero padded' => ['00443']];
	}

	#[DataProvider('goodPorts')]
	public function testAPortInRangeIsAccepted(string $port): void
	{
		$this->assertSame([], $this->errors(['pfb_dns_doh_port' => $port, 'pfb_dns_doq_port' => $port]));
	}

	// -----------------------------------------------------------------------
	// V2 -- interfaces
	// -----------------------------------------------------------------------

	/** @return array<string,array{mixed,string}> posted value, the token the error must name */
	public static function badInterfaces(): array
	{
		return [
			'not configured'          => [['opt99'], 'opt99'],
			'wrong case'              => [['LAN'], 'LAN'],
			'one bad among good ones' => [['lan', 'opt99'], 'opt99'],
			'markup'                  => [['<b>lan</b>'], '&lt;b&gt;lan&lt;/b&gt;'],
		];
	}

	#[DataProvider('badInterfaces')]
	public function testAnInterfaceThePageDoesNotOfferIsAnInputError(array $posted, string $named): void
	{
		foreach (self::INTERFACE_FIELDS as $label => [$field]) {
			$this->assertSame([], $this->errors([$field => ['lan']]), 'before: a configured interface is accepted');

			$errors = $this->errors([$field => $posted]);

			$this->assertCount(1, $errors, "{$label}: " . json_encode($errors));
			$this->assertStringContainsString($named, $errors[0], 'the error names the offending value, escaped');
		}
	}

	public function testANestedArrayPostedAsAnInterfaceIsAnInputErrorNotAFatal(): void
	{
		$errors = $this->errors(['pfb_dns_doh_interface' => [['lan']]]);

		$this->assertCount(1, $errors, json_encode($errors));
	}

	public function testConfiguredInterfacesAndAnEmptySelectionAreAccepted(): void
	{
		$this->assertSame([], $this->errors(['pfb_dns_doh_interface' => ['lan', 'opt1', 'lan']]), 'duplicates are not an error');
		$this->assertSame([], $this->errors(['pfb_dns_doh_interface' => []]), 'none = the proxy\'s own addresses');
	}

	// -----------------------------------------------------------------------
	// V3 -- trusted front ends
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> */
	public static function badTrusted(): array
	{
		return [
			'prefix too long'        => ['10.0.0.0/33'],
			'a word'                 => ['foo'],
			'shell command'          => ['1.2.3.4;rm -rf /'],
			'command substitution'   => ['$(id)'],
			'link-local zone'        => ['fe80::1%em0'],
			'one bad among good'     => ['192.0.2.10 foo 10.0.0.0/8'],
			'fullwidth digits'       => ['１０.0.0.1'],
			'v6 prefix too long'     => ['2001:db8::/129'],
			'host with a path'       => ['192.0.2.10/32/8'],
			'v4 prefix with a leading zero'   => ['10.0.0.0/08'],
			'v4 prefix with two leading zeros' => ['10.0.0.0/008'],
			'v4 host prefix with a leading zero' => ['192.0.2.10/032'],
			'v6 prefix with a leading zero'   => ['2001:db8::/064'],
			'v4 host with a v6-sized prefix'  => ['192.0.2.1/64'],
			'v4 octet with a leading zero'    => ['010.0.0.1'],
			'empty prefix'                    => ['10.0.0.0/'],
			'four-digit prefix'               => ['10.0.0.0/0008'],
		];
	}

	#[DataProvider('badTrusted')]
	public function testATrustedEntryThatIsNotAnIpOrCidrIsAnInputError(string $trusted): void
	{
		$this->assertSame([], $this->errors(['pfb_dns_doh_trusted' => '192.0.2.10']), 'before: an address is accepted');

		$errors = $this->errors(['pfb_dns_doh_trusted' => $trusted]);

		$this->assertNotSame([], $errors, "trusted {$trusted} must be rejected");
		$this->assertStringContainsString('trusted', strtolower($errors[0]));
	}

	public function testTheOffendingTrustedEntryIsEscapedInTheError(): void
	{
		$errors = $this->errors(['pfb_dns_doh_trusted' => '<script>alert(1)</script>']);

		$this->assertCount(1, $errors);
		$this->assertStringNotContainsString('<script>', $errors[0]);
		$this->assertStringContainsString('&lt;script&gt;', $errors[0]);
	}

	public function testControlAndFormatCharactersAreStrippedAtIngestionAndWhatRemainsIsStillValidated(): void
	{
		// Given the page's ingestion step (pfb_sanitize_text) ran first on what the browser posted
		$clean = pfb_sanitize_text("192.0.2.10\u{200B}\x07");
		$this->assertSame('192.0.2.10', $clean, 'precondition: control and format characters are gone');
		$this->assertSame([], $this->errors(['pfb_dns_doh_trusted' => $clean]));

		// When the rest is not an address, it is rejected
		$junk = pfb_sanitize_text("192.0.2.10 ev\x00il\u{202E}");
		$this->assertSame('192.0.2.10 evil', $junk);
		$this->assertNotSame([], $this->errors(['pfb_dns_doh_trusted' => $junk]));
	}

	/** @return array<string,array{string}> */
	public static function goodTrusted(): array
	{
		return [
			'empty'                      => [''],
			'only separators'            => [' , ,'],
			'v4, v6 prefix and v4 prefix' => ['192.0.2.10 2001:db8::/32,10.0.0.0/8'],
			'trailing comma and space'   => ['192.0.2.10, '],
			'host bits set'              => ['10.1.2.3/8'],
			'v4-mapped v6'               => ['::ffff:192.0.2.10'],
			'prefix zero'                => ['0.0.0.0/0'],
			'v6 prefix zero'             => ['::/0'],
			'v4 host prefix at its limit' => ['10.0.0.1/32'],
			'v6 host prefix at its limit' => ['2001:db8::1/128'],
			'bare v6'                    => ['2001:db8::1'],
		];
	}

	#[DataProvider('goodTrusted')]
	public function testTrustedAddressesAndPrefixesSeparatedBySpacesOrCommasAreAccepted(string $trusted): void
	{
		$this->assertSame([], $this->errors(['pfb_dns_doh_trusted' => $trusted]));
	}

	public function testThreeHundredTrustedEntriesAreAccepted(): void
	{
		$entries = [];
		for ($i = 0; $i < 300; $i++) {
			$entries[] = '10.' . intdiv($i, 250) . '.' . ($i % 250) . '.0/24';
		}

		$this->assertSame([], $this->errors(['pfb_dns_doh_trusted' => implode(' ', $entries)]));
	}

	// -----------------------------------------------------------------------
	// V4 -- the Resolver's certificate
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,string}> */
	public static function tlsToggles(): array
	{
		return ['DoH' => ['pfb_dns_doh', 'DoH'], 'DoQ' => ['pfb_dns_doq', 'DoQ']];
	}

	#[DataProvider('tlsToggles')]
	public function testDohOrDoqOnWithoutAResolverCertificateIsAnInputError(string $toggle, string $label): void
	{
		$this->assertSame([], $this->errors([$toggle => 'on'], 'cert5f3a'), 'before: with a certificate it is accepted');

		$errors = $this->errors([$toggle => 'on'], '');

		$this->assertCount(1, $errors, json_encode($errors));
		$this->assertStringContainsString($label, $errors[0]);
		$this->assertStringContainsString('DNS Resolver', $errors[0]);
		$this->assertStringContainsString('SSL/TLS', $errors[0]);
	}

	public function testBothOnWithoutACertificateReportsEach(): void
	{
		$this->assertCount(2, $this->errors(['pfb_dns_doh' => 'on', 'pfb_dns_doq' => 'on'], ''));
	}

	public function testBothOffNeedNoCertificate(): void
	{
		$this->assertSame([], $this->errors([], ''));
	}

	// -----------------------------------------------------------------------
	// What the page stores
	// -----------------------------------------------------------------------

	public function testAFreshPostStoresTheRegisteredDefaults(): void
	{
		$this->assertSame([
			'pfb_dns_doh'           => '',
			'pfb_dns_doh_port'      => '4443',
			'pfb_dns_doh_interface' => '',
			'pfb_dns_doh_trusted'   => '',
			'pfb_dns_doq'           => '',
			'pfb_dns_doq_port'      => '853',
			'pfb_dns_doq_interface' => '',
		], pfb_dns_proxy_listeners_stored($this->post()));
	}

	public function testAPostWithTheFieldsAbsentStoresOffAndTheDefaults(): void
	{
		// An unchecked checkbox and an empty multi-select are simply absent from a browser POST.
		$stored = pfb_dns_proxy_listeners_stored([]);

		$this->assertSame('', $stored['pfb_dns_doh']);
		$this->assertSame('', $stored['pfb_dns_doq']);
		$this->assertSame('', $stored['pfb_dns_doh_interface']);
	}

	public function testStoredValuesAreCanonical(): void
	{
		$stored = pfb_dns_proxy_listeners_stored($this->post([
			'pfb_dns_doh'           => 'on',
			'pfb_dns_doh_port'      => '00443',
			'pfb_dns_doh_interface' => ['lan', 'lan', 'opt1'],
			'pfb_dns_doh_trusted'   => '192.0.2.10, 2001:db8::/32 ,,10.0.0.0/8 192.0.2.10',
			'pfb_dns_doq'           => 'yes',
			'pfb_dns_doq_interface' => 'lan',
		]));

		$this->assertSame([
			'pfb_dns_doh'           => 'on',
			'pfb_dns_doh_port'      => '443',
			'pfb_dns_doh_interface' => 'lan,opt1',
			'pfb_dns_doh_trusted'   => '192.0.2.10 2001:db8::/32 10.0.0.0/8',
			'pfb_dns_doq'           => '',
			'pfb_dns_doq_port'      => '853',
			'pfb_dns_doq_interface' => 'lan',
		], $stored, 'port without leading zeros; interfaces and trusted deduplicated; a toggle is on only for "on"');
	}

	public function testTokensSplitOnSpacesCommasAndTabsAndDropEmptiesAndRepeats(): void
	{
		$this->assertSame(['a', 'b', 'c'], pfb_dns_proxy_tokens(" a,, b  c,\t a "));
		$this->assertSame([], pfb_dns_proxy_tokens(''));
		$this->assertSame([], pfb_dns_proxy_tokens(' , '));
	}

	// -----------------------------------------------------------------------
	// The page wires the contract in, in the right order
	// -----------------------------------------------------------------------

	public function testThePageSanitizesThenValidatesBeforeItPersistsAndStoresOnlyTheCanonicalValues(): void
	{
		$page = (string) file_get_contents(self::PAGE);

		$sanitize = strpos($page, "'pfb_dns_doh_port', 'pfb_dns_doq_port', 'pfb_dns_doh_trusted'");
		$validate = strpos($page, 'pfb_validate_dns_proxy_listeners_post(');
		$gate     = strpos($page, 'if (!$input_errors) {');
		$store    = strpos($page, 'pfb_dns_proxy_listeners_stored(');

		$this->assertNotFalse($sanitize, 'the single-line text fields join the ingestion prologue');
		$this->assertNotFalse($validate, 'the page validates the seven fields');
		$this->assertNotFalse($gate);
		$this->assertNotFalse($store, 'the page persists the canonical values');
		$this->assertLessThan($validate, $sanitize, 'sanitize before validate');
		$this->assertLessThan($gate, $validate, 'validate before the save gate');
		$this->assertLessThan($store, $gate, 'persist only inside the save gate');
	}
}
