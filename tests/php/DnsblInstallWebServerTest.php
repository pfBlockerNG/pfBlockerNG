<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsblNatWriterSeedTrait.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3539 — a package (re)install creates, writes and starts the DNSBL web server only for an
 * enabled package with DNSBL on, the resolver on, a block answering with the VIP and both ports set; and
 * what it starts is real: the conf it builds is written, because the rc script launches lighttpd only
 * when that conf exists.
 *
 * pfblockerng_install.inc is a procedural script that cannot be include()d off-appliance (host-absolute
 * requires, sqlite, service control), so the block under test is cut out of the shipped file between its
 * two comment anchors and executed as shipped, against the real package functions and the pfSense doubles.
 */
final class DnsblInstallWebServerTest extends TestCase
{
	use DnsblNatWriterSeedTrait;

	private const START = '// Create DNSBL Lighttpd config file and DNSBL Certificate and restart DNSBL Service';
	private const END = "// Replace 'default' DNSBL active blocked webpage";
	private const GENERAL = 'installedpackages/pfblockerng/config/0';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;
	private mixed $savedG;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;
		$this->savedG      = $GLOBALS['g'] ?? NULL;
		$this->dir         = sys_get_temp_dir() . '/pfb_install_web_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);
		$GLOBALS['pfb_test_service_calls'] = [];
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
		foreach (['config' => $this->savedConfig, 'pfb' => $this->savedPfb, 'g' => $this->savedG] as $name => $value) {
			if ($value === NULL) {
				unset($GLOBALS[$name]);
			} else {
				$GLOBALS[$name] = $value;
			}
		}
		unset($GLOBALS['pfb_test_service_calls'], $GLOBALS['pfb_test_vip_list']);
	}

	private static function installBlock(): string
	{
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$from   = strpos($source, self::START);
		$to     = strpos($source, self::END);
		self::assertIsInt($from, 'the install web server block lost its start anchor');
		self::assertIsInt($to, 'the install web server block lost its end anchor');
		self::assertGreaterThan($from, $to);
		return substr($source, $from, $to - $from);
	}

	/**
	 * @param array{enable?:bool,dnsbl?:bool,unbound?:bool,demand?:bool,http?:bool,https?:bool} $o
	 */
	private function arrange(array $o): void
	{
		$o += ['enable' => TRUE, 'dnsbl' => TRUE, 'unbound' => TRUE, 'demand' => TRUE, 'http' => TRUE, 'https' => TRUE];
		$this->seedDnsblNatWriter($this->dir, [], $o['demand']);
		file_put_contents($GLOBALS['pfb']['dnsbl_cert'], 'STALE');
		config_set_path(self::GENERAL . '/enable_cb', $o['enable'] ? 'on' : '');
		config_set_path(self::DNSBL . '/pfb_dnsport', $o['http'] ? '8081' : '');
		config_set_path(self::DNSBL . '/pfb_dnsport_ssl', $o['https'] ? '8443' : '');
		PfbConfig::write('dnsbl/pfb_dnsbl', $o['dnsbl'] ? 'on' : '');
		if ($o['unbound']) {
			$GLOBALS['config']['unbound'] = ['enable' => ''];
		}
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
	}

	private function runInstallBlock(): void
	{
		$code = self::installBlock();
		pfb_global();	// pfblockerng_install.inc has run pfb_global() long before this block
		(function () use ($code): void {
			global $pfb;
			eval($code);
		})();
	}

	/** @return list<array{string,string}> */
	private function starts(): array
	{
		return array_values(array_filter($GLOBALS['pfb_test_service_calls'], static fn (array $call): bool => $call[0] === 'start_service'));
	}

	public function testAllConditionsMetWritesTheConfCreatesTheCertificateAndStartsTheWebServer(): void
	{
		// GIVEN an enabled package, DNSBL and resolver on, a block answering with the VIP, both ports set, no conf and an old certificate
		$this->arrange([]);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf'], 'before-state: no conf');
		$this->assertSame('STALE', file_get_contents($GLOBALS['pfb']['dnsbl_cert']), 'before-state: an old certificate');

		// WHEN the install block runs
		$this->runInstallBlock();

		// THEN the conf it built is on disk, the certificate is a new one, and the web server was started
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_conf']);
		$this->assertSame(pfb_create_lighttpd(), file_get_contents($GLOBALS['pfb']['dnsbl_conf']));
		$this->assertNotSame('STALE', file_get_contents($GLOBALS['pfb']['dnsbl_cert']));
		$this->assertSame([['start_service', 'pfb_dnsbl']], $this->starts());
	}

	/** @return array<string,array{array<string,bool>}> */
	public static function unmetConditionRows(): array
	{
		return [
			'package off' => [['enable' => FALSE]],
			'DNSBL off' => [['dnsbl' => FALSE]],
			'resolver off' => [['unbound' => FALSE]],
			'no block answers with the VIP' => [['demand' => FALSE]],
			'HTTP port empty' => [['http' => FALSE]],
			'HTTPS port empty' => [['https' => FALSE]],
		];
	}

	/** @param array<string,bool> $state */
	#[DataProvider('unmetConditionRows')]
	public function testAnUnmetConditionCreatesNothingAndStartsNothing(array $state): void
	{
		// GIVEN every condition met except the one under test
		$this->arrange($state);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf'], 'before-state: no conf');

		// WHEN the install block runs
		$this->runInstallBlock();

		// THEN no conf is written, the old certificate is left alone and nothing is started
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf']);
		$this->assertSame('STALE', file_get_contents($GLOBALS['pfb']['dnsbl_cert']));
		$this->assertSame([], $this->starts());
	}
}
