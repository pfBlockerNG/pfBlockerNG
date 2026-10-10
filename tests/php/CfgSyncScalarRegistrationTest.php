<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3450 — the 20 IP and DNSBL settings scalars that were written by their pages and
 * read by the package without a registry entry now register as plain scalars, so each one
 * can carry its sync ownership class and the toggle checker can hold the pages to the
 * gateway.
 *
 * Like CfgToggleRegistryPageParityTest, the claim is a PARITY claim: reading a field through
 * PfbConfig on a configuration that predates the registration must resolve to what the page
 * expression resolved to before. That expression, `$raw ?: <default>`, is re-evaluated here
 * for every raw state a producer can leave (absent, '', canonical tokens, padded and
 * upper-cased variants) instead of being described.
 *
 * One state differs on purpose and is pinned as an accepted delta (D3): a stored '0'.
 * Plain registered scalars pass '0' through (the #1887/#2120 plain-scalar rule), where the
 * old `?:` read it as falsy and took the default. No producer writes '0' for any of these.
 */
final class CfgSyncScalarRegistrationTest extends TestCase
{
	private const IP_SECTION    = 'installedpackages/pfblockerngipsettings/config/0';
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';

	private bool $hadConfig   = FALSE;
	private mixed $savedConfig = NULL;

	protected function setUp(): void
	{
		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		unset($GLOBALS['pfb_test_allowed_pages']);
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_allowed_pages']);
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	/**
	 * registry key => [section path, registered default, sync class, canonical producer tokens].
	 * The tokens are the vocabularies the page selects and the save handler writes.
	 *
	 * @return array<string,array{0:string,1:string,2:string,3:list<string>}>
	 */
	private static function fields(): array
	{
		$ip    = self::IP_SECTION;
		$dnsbl = self::DNSBL_SECTION;

		return [
			'ip/ip_placeholder'     => [$ip, '127.1.7.7', 'policy', ['127.1.7.7', '10.255.255.254']],
			'ip/maxmind_locale'     => [$ip, 'en', 'local', ['en', 'fr', 'pt-BR', 'de', 'ja', 'zh-CN', 'es']],
			'ip/maxmind_account'    => [$ip, '', 'local', ['1234567', '7654321']],
			'ip/maxmind_key'        => [$ip, '', 'local', ['fake-key-AAAA1111', 'Zz9_fake-key-BBBB2222']],
			'ip/asn_reporting'      => [$ip, 'disabled', 'local', ['disabled', 'week', '24hour', '12hour', '4hour', '1hour']],
			'ip/asn_token'          => [$ip, '', 'local', ['fake-asn-token-1', 'fake-asn-token-2']],
			'ip/inbound_interface'  => [$ip, '', 'local', ['wan', 'wan,opt1', 'lan,opt2,opt3']],
			'ip/inbound_deny_action' => [$ip, 'block', 'policy', ['block', 'reject']],
			'ip/outbound_interface' => [$ip, '', 'local', ['lan', 'lan,opt1']],
			'ip/outbound_deny_action' => [$ip, 'reject', 'policy', ['block', 'reject']],
			'ip/pass_order'         => [$ip, 'order_0', 'policy', ['order_0', 'order_1', 'order_2', 'order_3', 'order_4']],
			'ip/autorule_suffix'    => [$ip, 'autorule', 'policy', ['autorule', 'standard', 'ar']],

			'dnsbl/agateway_in'     => [$dnsbl, 'default', 'local', ['default', 'WAN_DHCP', 'VPN_GW']],
			'dnsbl/agateway_out'    => [$dnsbl, 'default', 'local', ['default', 'WAN_DHCP', 'VPN_GW']],
			'dnsbl/aliasaddr_in'    => [$dnsbl, '', 'policy', ['LAN_hosts', 'Trusted_Addr']],
			'dnsbl/aliasaddr_out'   => [$dnsbl, '', 'policy', ['LAN_hosts', 'Trusted_Addr']],
			'dnsbl/aliasports_in'   => [$dnsbl, '', 'policy', ['Web_ports', 'DNS_ports']],
			'dnsbl/aliasports_out'  => [$dnsbl, '', 'policy', ['Web_ports', 'DNS_ports']],
			// The parity reference is the rule builder's raw read, not the page's `?: 'any'`: an unset
			// protocol lets pfSense derive proto tcp from a port (filter.inc:4497-4500), 'any' does not.
			'dnsbl/autoproto_in'    => [$dnsbl, '', 'policy', ['any', 'tcp', 'udp', 'tcp/udp']],
			'dnsbl/autoproto_out'   => [$dnsbl, '', 'policy', ['any', 'tcp', 'udp', 'tcp/udp']],
		];
	}

	private static function bare(string $key): string
	{
		return substr($key, strpos($key, '/') + 1);
	}

	/** @return iterable<string,array{0:string}> */
	public static function fieldProvider(): iterable
	{
		foreach (array_keys(self::fields()) as $key) {
			yield $key => [$key];
		}
	}

	/** @return iterable<string,array{0:string,1:string,2:string,3:?string}> */
	public static function rawStateProvider(): iterable
	{
		foreach (self::fields() as $key => [$section, $default, , $tokens]) {
			yield "{$key} [absent]" => [$key, $section, $default, NULL];
			yield "{$key} [empty]"  => [$key, $section, $default, ''];
			foreach ($tokens as $token) {
				yield "{$key} [{$token}]" => [$key, $section, $default, $token];
			}
			yield "{$key} [padded]" => [$key, $section, $default, " {$tokens[0]} "];
			yield "{$key} [upper]"  => [$key, $section, $default, strtoupper($tokens[0])];
		}
	}

	/** @return iterable<string,array{0:string,1:string,2:string}> */
	public static function canonicalTokenProvider(): iterable
	{
		foreach (self::fields() as $key => [$section, , , $tokens]) {
			foreach ($tokens as $token) {
				yield "{$key} [{$token}]" => [$key, $section, $token];
			}
		}
	}

	// D1 -- each field is registered with its default, plain adapters, sync class and grandfather decision.
	#[DataProvider('fieldProvider')]
	public function testFieldIsRegisteredAsAPlainScalarWithItsClassAndDecision(string $key): void
	{
		[, $default, $sync] = self::fields()[$key];
		$registry = pfb_cfg_registry();

		$this->assertArrayHasKey($key, $registry, "{$key} must be registered");
		$entry = $registry[$key];

		$this->assertSame($default, $entry['default'], "{$key}: the registered default is the page/save producer default");
		$this->assertNull($entry['read_adapter'], "{$key}: plain scalar, no read adapter");
		$this->assertNull($entry['write_adapter'], "{$key}: plain scalar, no write adapter");
		$this->assertArrayNotHasKey('write_priv', $entry, "{$key}: the default write privilege applies");
		$this->assertArrayNotHasKey('old_name', $entry, "{$key}: never renamed");
		$this->assertSame($sync, $entry['sync'] ?? NULL, "{$key}: sync ownership class");

		if ($key === 'ip/autorule_suffix') {
			// The old runtime read the raw value with no default, so an absent or '' suffix generated
			// no suffix (the 'standard' branch): an upgrade keeps that, a fresh install takes 'autorule'.
			$this->assertArrayNotHasKey('no_grandfather', $entry);
			$this->assertSame([PFB_GF_ABSENT => 'standard', '' => 'standard'], $entry['grandfather'] ?? NULL);
			return;
		}
		$this->assertArrayNotHasKey('grandfather', $entry, "{$key}: absence already read as the default");
		$this->assertIsString($entry['no_grandfather'] ?? NULL, "{$key}: records why no grandfather is needed");
		$this->assertNotSame('', $entry['no_grandfather'] ?? '', "{$key}: the reason must not be empty");
	}

	// D2 -- the gateway read equals the page expression it replaces, for every raw state.
	#[DataProvider('rawStateProvider')]
	public function testGatewayReadEqualsThePreRegistrationExpression(string $key, string $section, string $default, ?string $raw): void
	{
		if ($raw !== NULL) {
			config_set_path($section . '/' . self::bare($key), $raw);
		}

		// $pfb['iconfig'|'dconfig'][$bare] ?: <default>, the expression every page site carried.
		$expected = $raw ?: $default;

		$this->assertSame($expected, PfbConfig::read($key));
	}

	// D3 -- accepted delta: a stored '0' now reads '0' where the old `?:` fell back to the default.
	#[DataProvider('fieldProvider')]
	public function testStoredZeroReadsZeroUnlikeThePreRegistrationExpression(string $key): void
	{
		[$section, $default] = self::fields()[$key];
		config_set_path($section . '/' . self::bare($key), '0');

		$this->assertSame($default, '0' ?: $default, 'before-state: the retired expression took the default for a stored 0');
		$this->assertSame('0', PfbConfig::read($key), 'plain registered scalars pass a stored 0 through (#1887/#2120)');
	}

	// D4 -- the canonical tokens persist byte-identical through the single-field writer.
	#[DataProvider('canonicalTokenProvider')]
	public function testWriteSystemStoresTheCanonicalTokenUnchanged(string $key, string $section, string $token): void
	{
		$path = $section . '/' . self::bare($key);
		$this->assertNull(config_get_path($path, NULL), 'before-state: nothing stored');

		PfbConfig::writeSystem($key, $token);

		$this->assertSame($token, config_get_path($path));
		$this->assertSame($token, PfbConfig::read($key));
	}

	// D4 -- a section blob carrying every new key (canonical, empty, junk) is persisted byte-identical.
	public function testSectionBlobsCarryingTheNewKeysPersistByteIdentical(): void
	{
		foreach ([self::IP_SECTION, self::DNSBL_SECTION] as $section) {
			$new = [];
			foreach (self::fields() as $key => [$fieldSection, , , $tokens]) {
				if ($fieldSection === $section) {
					$new[self::bare($key)] = $tokens;
				}
			}
			$this->assertNotEmpty($new, 'vacuity guard: the section has new keys');

			$blobs = [
				'canonical' => array_map(static fn (array $tokens): string => $tokens[0], $new),
				'empty'     => array_fill_keys(array_keys($new), ''),
				'junk'      => array_map(static fn (array $tokens): string => " <b>junk&'\"</b>\t" . $tokens[0] . "\n", $new),
			];
			foreach ($blobs as $label => $blob) {
				$GLOBALS['config'] = [];

				PfbConfig::writeSectionSystem($section, $blob);

				$this->assertSame($blob, config_get_path($section), "{$section} [{$label}] must round-trip untouched");
			}
		}
	}

	// D5 -- a new credential is written only by a caller holding the default write privilege.
	#[DataProvider('credentialProvider')]
	public function testCredentialWriteRequiresThePagePrivilege(string $key, string $path): void
	{
		$GLOBALS['pfb_test_allowed_pages'] = ['pfblockerng/pfblockerng_general.php' => FALSE];
		try {
			PfbConfig::write($key, 'fake-secret-value');
			$this->fail("write of {$key} must be refused without the page privilege");
		} catch (RuntimeException $e) {
			$this->assertStringContainsString($key, $e->getMessage(), 'the refusal names the key, never the value');
			$this->assertStringNotContainsString('fake-secret-value', $e->getMessage());
		}
		$this->assertNull(config_get_path($path, NULL), 'a refused write stores nothing');

		$GLOBALS['pfb_test_allowed_pages'] = ['pfblockerng/pfblockerng_general.php' => TRUE];
		PfbConfig::write($key, 'fake-secret-value');

		$this->assertSame('fake-secret-value', config_get_path($path));
	}

	/** @return iterable<string,array{0:string,1:string}> */
	public static function credentialProvider(): iterable
	{
		foreach (['ip/maxmind_key', 'ip/asn_token', 'ip/maxmind_account'] as $key) {
			yield $key => [$key, self::IP_SECTION . '/' . self::bare($key)];
		}
	}

	// D6 -- fresh installs seed every new default; upgrades keep the old no-suffix behaviour.
	public function testFreshIpSectionSeedsAllTwelveIpDefaults(): void
	{
		$seeded = pfb_registry_pass([self::IP_SECTION => []])[self::IP_SECTION] ?? [];

		$count = 0;
		foreach (self::fields() as $key => [$section, $default]) {
			if ($section === self::IP_SECTION) {
				$count++;
				$this->assertArrayHasKey(self::bare($key), $seeded, "{$key} must be seeded on a fresh install");
				$this->assertSame($default, $seeded[self::bare($key)], "{$key} seeds its registered default");
			}
		}
		$this->assertSame(12, $count, 'vacuity guard: twelve IP scalars');
		$this->assertSame('autorule', $seeded['autorule_suffix'], 'a fresh install takes the page default suffix');
	}

	public function testFreshDnsblSectionSeedsAllEightDnsblDefaults(): void
	{
		$seeded = pfb_registry_pass([self::DNSBL_SECTION => []])[self::DNSBL_SECTION] ?? [];

		$count = 0;
		foreach (self::fields() as $key => [$section, $default]) {
			if ($section === self::DNSBL_SECTION) {
				$count++;
				$this->assertArrayHasKey(self::bare($key), $seeded, "{$key} must be seeded on a fresh install");
				$this->assertSame($default, $seeded[self::bare($key)], "{$key} seeds its registered default");
			}
		}
		$this->assertSame(8, $count, 'vacuity guard: eight DNSBL scalars');
	}

	/** @return iterable<string,array{0:array<string,string>,1:string}> */
	public static function upgradeSuffixProvider(): iterable
	{
		yield 'absent keeps no suffix'   => [['enable_dup' => 'on'], 'standard'];
		yield "empty keeps no suffix"    => [['enable_dup' => 'on', 'autorule_suffix' => ''], 'standard'];
		yield 'ar is untouched'          => [['enable_dup' => 'on', 'autorule_suffix' => 'ar'], 'ar'];
		yield 'autorule is untouched'    => [['enable_dup' => 'on', 'autorule_suffix' => 'autorule'], 'autorule'];
		yield 'standard is untouched'    => [['enable_dup' => 'on', 'autorule_suffix' => 'standard'], 'standard'];
	}

	/** @param array<string,string> $blob */
	#[DataProvider('upgradeSuffixProvider')]
	public function testUpgradedIpSectionKeepsItsOldSuffixBehaviour(array $blob, string $expected): void
	{
		$sections = [self::IP_SECTION => $blob + ['ip_placeholder' => '10.1.1.1']];

		$result = pfb_registry_pass($sections)[self::IP_SECTION] ?? [];

		$this->assertSame($expected, $result['autorule_suffix'], 'autorule_suffix after the upgrade pass');
		$this->assertSame('10.1.1.1', $result['ip_placeholder'], 'a stored value is never replaced by a default');
		$this->assertSame('order_0', $result['pass_order'], 'an absent key with no grandfather seeds its default');
		$this->assertSame('block', $result['inbound_deny_action']);

		$merged = array_replace($sections, pfb_registry_pass($sections));
		$this->assertSame([], pfb_registry_pass($merged), 'a second pass over the first pass output changes nothing');
	}

	// D7 -- the toggle-checker / gateway sniff knows every new path.
	public function testSniffRegisteredPathsListEveryNewField(): void
	{
		if (!interface_exists(\PHP_CodeSniffer\Sniffs\Sniff::class)) {
			eval('namespace PHP_CodeSniffer\Sniffs; interface Sniff {}');
		}
		require_once dirname(__DIR__) . '/phpcs/PfBlockerNG/Sniffs/Config/RequireConfigGatewaySniff.php';

		$paths = (array) (new \PfBlockerNG\Sniffs\Config\RequireConfigGatewaySniff())->registeredPaths;

		$this->assertCount(20, self::fields(), 'vacuity guard');
		foreach (self::fields() as $key => [$section]) {
			$this->assertContains($section . '/' . self::bare($key), $paths, "{$key} must be in the sniff \$registeredPaths");
		}
	}
}
