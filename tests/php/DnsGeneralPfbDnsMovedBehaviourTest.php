<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

/**
 * issue #3771 -- two behaviours the pfB-DNS settings brought with them onto DNS > General, executed from the shipped page:
 *   - the first load takes pfB-DNS's unset listener settings from the DNS Resolver once (issue #3538), now on the DNS tab's landing page;
 *   - the pfB-DNS save strips control characters from its text fields before anything reads them (issue #1723).
 */
final class DnsGeneralPfbDnsMovedBehaviourTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_dns_general.php';
	private const SEED_WRITE = '[pfBlockerNG] pfB-DNS took its listener settings from the DNS Resolver';
	private const GLOBALS = ['config', 'pfb_test_write_config_calls', 'pfb_test_lock_held', 'pfb_test_lock_events', '_POST'];

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
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
	}

	/** Run one region of the shipped page with the page's globals in scope. */
	private static function runRegion(string $start, string $end): void
	{
		$code = pfb_test_page_region(self::PAGE, $start, $end);
		(static function () use ($code): void {
			eval($code);
		})();
	}

	public function testTheFirstLoadOfDnsGeneralSeedsTheUnsetListenerSettingsFromTheResolverOnceUnderTheLock(): void
	{
		// Given a Resolver on LAN with its SSL/TLS service and certificate, and pfB-DNS's listener settings never seeded
		$GLOBALS['config'] = ['unbound' => ['enable' => '', 'port' => '53', 'active_interface' => 'lan', 'enablessl' => 'on', 'tlsport' => '853', 'sslcertref' => 'abc']];
		$this->assertSame('', PfbConfig::read('dns/pfb_dns_interface'), 'before: the DNS interface list is unseeded');
		$this->assertNotSame([], pfb_dns_proxy_seed_values(), 'before: there is something to seed');

		// When DNS > General loads
		self::runRegion('if (pfb_dns_proxy_seed_values() !== []) {', '$pconfig = array();');

		// Then the settings are the Resolver's, written once under the config lock, which is released
		$this->assertSame([self::SEED_WRITE], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame('lan', PfbConfig::read('dns/pfb_dns_interface'));
		$this->assertSame('abc', PfbConfig::read('dns/pfb_dns_sslcertref'));
		$this->assertContains(['try_lock', 'pfb_dns_config', PFB_DNS_CONFIG_LOCK_WAIT], $GLOBALS['pfb_test_lock_events'], 'the seed takes the config lock');
		$this->assertFalse((bool) ($GLOBALS['pfb_test_lock_held'] ?? FALSE), 'the lock is released');

		// And a second load seeds nothing and writes nothing
		self::runRegion('if (pfb_dns_proxy_seed_values() !== []) {', '$pconfig = array();');
		$this->assertSame([self::SEED_WRITE], $GLOBALS['pfb_test_write_config_calls'], 'once only');
	}

	public function testThePfbDnsSaveStripsControlCharactersFromItsTextFieldsBeforeAnythingReadsThem(): void
	{
		// Given a pfB-DNS post whose ports, trusted front ends and DNS Name carry control characters
		$_POST = [
			'save_pfb_dns' => 'Save',
			'pfb_dns_dot_port' => "853\x1b", 'pfb_dns_dot_port6' => "\x00", 'pfb_dns_doh_port' => "\t4443 ",
			'pfb_dns_doh_port6' => '', 'pfb_dns_doq_port' => "8853\x07", 'pfb_dns_doq_port6' => '',
			'pfb_dns_doh_trusted' => "10.0.0.0/8\x07 192.0.2.1\x00", 'pfb_dns_name' => "fw.example.lan\x07",
		];

		// When the save's ingestion step runs
		self::runRegion('// issue #1723: sanitize at ingestion', '$pfb_dns = pfb_filter(');

		// Then every text field is the plain text the validator expects
		$this->assertSame('853', $_POST['pfb_dns_dot_port']);
		$this->assertSame('', $_POST['pfb_dns_dot_port6']);
		$this->assertSame('4443', $_POST['pfb_dns_doh_port']);
		$this->assertSame('8853', $_POST['pfb_dns_doq_port']);
		$this->assertSame('10.0.0.0/8 192.0.2.1', $_POST['pfb_dns_doh_trusted']);
		$this->assertSame('fw.example.lan', $_POST['pfb_dns_name']);
	}

	public function testANonTextDnsNameIsLeftAsPostedForTheValidatorToRefuse(): void
	{
		// Given a DNS Name posted as an array (a hand-crafted request)
		$_POST = ['save_pfb_dns' => 'Save', 'pfb_dns_name' => ['fw.example.lan']];

		// When the save's ingestion step runs
		self::runRegion('// issue #1723: sanitize at ingestion', '$pfb_dns = pfb_filter(');

		// Then it is not cast (which would warn): it stays an array, which the validator refuses
		$this->assertSame(['fw.example.lan'], $_POST['pfb_dns_name']);
	}
}
