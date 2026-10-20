<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3538 -- a seed the save does not take is no move. Written after the DnsProxySeedTest red run, in its own file so
 * that file keeps the bytes it had when it was seen to fail.
 */
#[CoversFunction('pfb_dns_proxy_resolver')]
final class DnsProxySeedWriteFailureTest extends TestCase
{
	private const SECTION = 'installedpackages/pfblockerngdns/config/0/';
	private const SEEDED = [
		'pfb_dns_interface', 'pfb_dns_dot', 'pfb_dns_dot_port', 'pfb_dns_dot_interface', 'pfb_dns_sslcertref',
		'pfb_dns_doh_interface', 'pfb_dns_doq_interface',
	];
	private const GLOBALS = ['pfb', 'config', 'pfb_test_write_config_calls', 'pfb_test_file_notices', 'pfb_test_interface_mtu',
		'pfb_test_interfaces', 'pfb_test_configured_ipv6', 'pfb_test_interface_subnetv6', 'pfb_test_write_config_result'];

	private string $tmp;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_seed_write_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'logdir' => $this->tmp, 'log' => "{$this->tmp}/pfb.log", 'errlog' => "{$this->tmp}/pfb.err",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_interface_mtu'] = ['lan' => '1500', 'opt1' => '1500', 'lo0' => '16384'];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN', 'opt1' => 'OPT1'];
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$GLOBALS['pfb_test_interface_subnetv6'] = ['opt1' => '64'];
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
		rmdir_recursive($this->tmp);
	}

	/** @param array<string,mixed> $unbound */
	private function seedBox(array $unbound): void
	{
		$GLOBALS['config'] = [
			'unbound' => $unbound + ['enable' => '', 'port' => '53', 'custom_options' => base64_encode("do-ip6: no\nprefetch: yes")],
			'installedpackages' => ['pfblockerngdns' => ['config' => [0 => []]]],
		];
	}

	private function writes(): int
	{
		return count($GLOBALS['pfb_test_write_config_calls'] ?? []);
	}

	public function testASeedThatTheSaveDoesNotTakeIsReportedAndIsNotAMove(): void
	{
		// Given a moved box whose keys were never seeded, and a save that config.xml does not take.
		$this->seedBox(['active_interface' => 'lan', 'enablessl' => 'on', 'tlsport' => '8853', 'sslcertref' => 'abc']);
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE), 'precondition: the first turn-on moves the Resolver');
		foreach (self::SEEDED as $leaf) {
			config_del_path(self::SECTION . $leaf);
		}
		$this->assertSame('', PfbConfig::read('dns/pfb_dns_interface'), 'before: unseeded');
		$GLOBALS['pfb_test_write_config_result'] = FALSE;
		$writes = $this->writes();

		// When the proxy is turned on again.
		$this->assertFalse(pfb_dns_proxy_resolver(TRUE), 'a seed the save did not take is not a move');

		// Then the save was attempted once and the operator is told it did not happen.
		$this->assertSame($writes + 1, $this->writes(), 'one write_config attempt');
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the failed save is an operator-visible notice');
		$this->assertStringContainsString('config.xml could not be written', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}
}
