<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3694 -- the DNS Name setting of pfB-DNS on DNS > General (`dns/pfb_dns_name`, next to the certificate): DDR's target name and the
 * name pfB-DNS answers A and AAAA for. Active encrypted transports and DDR need a name, accepted only in the
 * shape the gateway takes (a hand-typed name must never be the reason it refuses to start).
 *
 * Functions under test, through their production surface:
 *   - pfb_validate_dns_proxy_listeners_post(): an empty name is fine for plain-only or disable; a non-empty one is trimmed, loses one
 *     trailing dot, and must be at most 253 characters, at least two labels of 1-63 ASCII letters, digits and hyphens (none starting
 *     or ending with one), a last label that is not all digits (an IPv4 literal is no name), and not resolver.arpa or under it.
 *     Any other value, an array included, is an input error that names the field and raises no PHP warning.
 *   - pfb_dns_proxy_listeners_stored(): the name as validated, its trailing dot stripped and its case kept.
 *
 * The flags are DnsProxyNameAnswersTest's, the warnings DnsProxyDnsNameWarningTest's, the registry row CfgGatewayTest's.
 */
#[CoversFunction('pfb_validate_dns_proxy_listeners_post')]
#[CoversFunction('pfb_dns_proxy_listeners_stored')]
final class DnsProxyDnsNameSettingsTest extends TestCase
{
	private const IFACES = ['all', 'lo0', 'lan', 'opt1'];
	private const CERTS = ['cert5f3a'];
	private const NAME = 'pfb_dns_name';

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

	/** @param array<string,mixed> $over fields replacing the defaults the page posts: every list holds one entry, every transport and DDR are off, the name is empty */
	private function post(array $over = []): array
	{
		return $over + [
			'pfb_dns' => 'on',
			'pfb_dns_interface' => ['lan'],
			'pfb_dns_dot' => '', 'pfb_dns_dot_port' => '853', 'pfb_dns_dot_interface' => ['lan'],
			'pfb_dns_doh' => '', 'pfb_dns_doh_port' => '4443', 'pfb_dns_doh_interface' => ['lan'],
			'pfb_dns_doh_trusted' => '',
			'pfb_dns_doq' => '', 'pfb_dns_doq_port' => '853', 'pfb_dns_doq_interface' => ['lan'],
			'pfb_dns_sslcertref' => '',
			'pfb_dns_ddr' => '',
			self::NAME => '',
		];
	}

	/** @return list<string> */
	private function errors(array $post): array
	{
		return pfb_validate_dns_proxy_listeners_post($post, self::IFACES, self::CERTS);
	}

	/** A name of $length characters (at least 193) made of three labels of 63 characters and a last one that fills the rest. */
	private static function longName(int $length): string
	{
		$label = str_repeat('a', 63);
		return "{$label}.{$label}.{$label}." . str_repeat('a', $length - 192);
	}

	// -----------------------------------------------------------------------
	// a name that is accepted
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,string}> posted, stored */
	public static function acceptedNames(): array
	{
		$label63 = str_repeat('a', 63);
		return [
			'a plain name' => ['fw.example.lan', 'fw.example.lan'],
			'one trailing dot, stripped' => ['fw.example.lan.', 'fw.example.lan'],
			'mixed case, kept' => ['FW.Example.LAN.', 'FW.Example.LAN'],
			'blanks around it, trimmed' => ["  fw.example.lan \t", 'fw.example.lan'],
			'a punycode label' => ['xn--bcher-kva.example', 'xn--bcher-kva.example'],
			'two one-letter labels' => ['a.b', 'a.b'],
			'hyphens inside labels' => ['my-fw.my-domain.example', 'my-fw.my-domain.example'],
			'digits in the labels and a last label that is not all digits' => ['fw1.2lan.example3', 'fw1.2lan.example3'],
			'an IPv4-looking name under a real last label' => ['1.2.3.4.example', '1.2.3.4.example'],
			'a label of 63 characters' => ["{$label63}.example", "{$label63}.example"],
			'a name of 253 characters' => [self::longName(253), self::longName(253)],
		];
	}

	#[DataProvider('acceptedNames')]
	public function testAValidNameIsNoInputErrorAndIsStoredWithoutItsTrailingDotKeepingItsCase(string $posted, string $stored): void
	{
		$this->assertSame([], $this->errors($this->post([self::NAME => $posted])), 'no input error');
		$this->assertSame($stored, pfb_dns_proxy_listeners_stored($this->post([self::NAME => $posted]))[self::NAME] ?? NULL);
	}

	// -----------------------------------------------------------------------
	// a name that is refused
	// -----------------------------------------------------------------------

	/** @return array<string,array{mixed}> */
	public static function refusedNames(): array
	{
		return [
			'one label' => ['fw'],
			'one label and a dot' => ['fw.'],
			'a dot alone' => ['.'],
			'an empty first label' => ['.example.lan'],
			'an empty inner label' => ['a..b'],
			'two trailing dots' => ['fw.example.lan..'],
			'not ASCII' => ['bücher.example'],
			'a wildcard' => ['*.example.lan'],
			'an underscore' => ['a_b.example'],
			'a label that starts with a hyphen' => ['-a.example'],
			'a label that ends with a hyphen' => ['a-.example'],
			'an IPv4 literal' => ['10.0.0.1'],
			'a dotted quad and a fifth number' => ['1.2.3.4.5'],
			'numbers that are no address' => ['999.999.999.999'],
			'resolver.arpa itself' => ['resolver.arpa'],
			'under resolver.arpa' => ['fw.resolver.arpa'],
			'resolver.arpa in capitals with a dot' => ['RESOLVER.ARPA.'],
			'deep under resolver.arpa in mixed case' => ['a.b.Resolver.Arpa'],
			'a label of 64 characters' => [str_repeat('a', 64) . '.example'],
			'a name of 254 characters' => [self::longName(254)],
			'text a shell would run' => ["fw.example.lan'; rm -rf /"],
			'a newline inside' => ["fw.example\n.lan"],
			'a NUL byte inside' => ["fw.exa\0mple.lan"],
			'a space inside' => ['fw example.lan'],
			'a URL' => ['https://fw.example.lan'],
			'a name with a port' => ['fw.example.lan:853'],
			'an array' => [['fw.example.lan']],
			'an integer' => [10],
			'a boolean' => [TRUE],
		];
	}

	#[DataProvider('refusedNames')]
	public function testAnInvalidNameIsAnInputErrorThatNamesTheFieldAndRaisesNoPhpWarning(mixed $posted): void
	{
		// Given a valid name: no error (the same post otherwise)
		$this->assertSame([], $this->errors($this->post([self::NAME => 'fw.example.lan'])), 'before: a valid name');

		// When the name is the case's, with every PHP warning recorded
		$warnings = [];
		set_error_handler(static function (int $_number, string $message) use (&$warnings): bool {
			$warnings[] = $message;
			return TRUE;
		});
		try {
			$errors = $this->errors($this->post([self::NAME => $posted]));
			$stored = pfb_dns_proxy_listeners_stored($this->post([self::NAME => $posted]));
		} finally {
			restore_error_handler();
		}

		$this->assertCount(1, $errors, 'an invalid name is rejected without duplicate validation errors');
		$this->assertSame([], $warnings, 'no PHP warning');
		$this->assertSame('', $stored[self::NAME] ?? NULL, 'whatever was posted, a refused name is never stored');
	}

	// -----------------------------------------------------------------------
	// DDR needs a name
	// -----------------------------------------------------------------------

	public function testDdrOnWithoutANameIsAnInputError(): void
	{
		// Given DDR on with a name: accepted
		$this->assertSame([], $this->errors($this->post(['pfb_dns_ddr' => 'on', self::NAME => 'fw.example.lan'])), 'before: a name is entered');

		foreach (['', '   '] as $empty) {
			$errors = $this->errors($this->post(['pfb_dns_ddr' => 'on', self::NAME => $empty]));
			$this->assertCount(1, $errors, json_encode($errors));
		}
		$this->assertCount(1, $this->errors($this->post(['pfb_dns_ddr' => 'on', self::NAME => '.'])), 'an invalid name does not also produce a missing-name error');
	}

	public function testDdrOffAndDdrNeitherOnNorOffAcceptAnEmptyName(): void
	{
		$this->assertNotEmpty($this->errors($this->post(['pfb_dns_ddr' => 'on', self::NAME => ''])), 'before: DDR on is refused');
		$this->assertSame([], $this->errors($this->post(['pfb_dns_ddr' => '', self::NAME => ''])), 'DDR off');
		$this->assertSame([], $this->errors($this->post(['pfb_dns_ddr' => 'yes', self::NAME => ''])), 'DDR posted as anything but on is off');
		$post = $this->post();
		unset($post['pfb_dns_ddr'], $post[self::NAME]);
		$this->assertSame([], $this->errors($post), 'neither field posted');
		$this->assertSame('', pfb_dns_proxy_listeners_stored($post)[self::NAME] ?? NULL, 'an absent name is stored empty');
	}

	public function testDdrOnWithAnInvalidNameIsOnlyTheNameError(): void
	{
		$this->assertCount(1, $this->errors($this->post(['pfb_dns_ddr' => 'on', self::NAME => 'fw'])));
	}

	public function testTheNameIsStoredWhetherOrNotDdrIsOn(): void
	{
		// The name is also what pfB-DNS answers A and AAAA for, so DDR off keeps it
		$this->assertSame('fw.example.lan', pfb_dns_proxy_listeners_stored($this->post(['pfb_dns_ddr' => '', self::NAME => 'fw.example.lan']))[self::NAME] ?? NULL, 'DDR off');
		$this->assertSame('fw.example.lan', pfb_dns_proxy_listeners_stored($this->post(['pfb_dns_ddr' => 'on', self::NAME => 'fw.example.lan']))[self::NAME] ?? NULL, 'DDR on');
	}
}
