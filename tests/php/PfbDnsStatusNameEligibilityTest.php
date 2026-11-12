<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * The DNS Name the status shows, by mode. The off returns (not in use, recovery, on but not active) show ''. A moved box that is on is
 * expected to run, and a gateway whose child process is alive is running: when no valid applied snapshot answers for either, the name is
 * NULL (Unavailable). Otherwise it is ''. A valid applied snapshot names the gateway it describes, even while pfB-DNS is being turned off.
 */
#[CoversFunction('pfb_dns_status')]
final class PfbDnsStatusNameEligibilityTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_service_calls', 'pfb_test_valid_pids', 'pfb_test_rcfile_dir',
		'pfb_test_interface_ip', 'pfb_test_interface_info',
	];

	private string $dir;
	private array $savedGlobals = [];
	private array $servers = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_name_eligibility_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir' => $this->dir,
			'log' => "{$this->dir}/pfb.log",
			'errlog' => "{$this->dir}/pfb.err",
			'dns_proxy_ctl' => "{$this->dir}/ctl.sock",
			'pfb_dns' => PfbToggle::On,
			'enable' => PfbToggle::On,
		]);
		$GLOBALS['config'] = [];
		PfbConfig::write('dns/pfb_dns_name', 'saved.example.com');
		// Nothing saved: a box that was never moved, rather than one whose saved copy is invalid (recovery)
		config_set_path(self::SAVED, '');
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
		$this->clearProxyFiles();
		$this->setUpUpstreamFixture();
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as [$process, $pipes]) {
			foreach ($pipes as $pipe) {
				fclose($pipe);
			}
			proc_close($process);
		}
		$this->servers = [];
		$this->tearDownUpstreamFixture();
		$this->clearProxyFiles();
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		@unlink(PFB_DNS_PROXY_RCFILE);
		rmdir_recursive($this->dir);
	}

	/** The Resolver as pfB-DNS leaves it when moved: a valid saved snapshot of a Resolver that listened on lan. */
	private function moved(): void
	{
		$keys = [];
		foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
	}

	/** Answer the applied-status requests on this test's control socket with a valid snapshot whose applied DNS Name is $name. */
	private function servesName(string $name): void
	{
		$wire = json_encode([
			'version' => 1, 'pid' => 4242, 'executable' => PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns',
			'ready' => TRUE, 'upstream' => '127.0.0.1:5353', 'dns_name' => $name,
			'listeners' => [['kind' => 'udp+tcp', 'address' => '192.0.2.1:53', 'state' => 'listening', 'reason' => '']],
			'name_answers' => (object) [], 'ddr' => FALSE,
			'advertisements' => (object) ['192.0.2.1' => ['records' => [], 'additional' => []]],
		], JSON_THROW_ON_ERROR) . "\nok\n";
		$process = proc_open([PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php', $GLOBALS['pfb']['dns_proxy_ctl'],
			"{$this->dir}/frames", base64_encode($wire)], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$process, $pipes];
	}

	public function testAnOffBoxThatIsNotRunningKeepsAnEmptyName(): void
	{
		// Given a moved Resolver with pfB-DNS off, and no gateway running
		$this->moved();
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::Off;
		$this->clearProxyFiles();

		// When the status is read
		$status = pfb_dns_status();

		// Then nothing is applied, and the name stays empty
		$this->assertFalse($status['active']);
		$this->assertSame('', $status['name']);
	}

	public function testABoxNotInUseKeepsAnEmptyName(): void
	{
		// Given a Resolver that was never moved, and no gateway running
		$this->clearProxyFiles();

		// When the status is read
		$status = pfb_dns_status();

		// Then the box is not in use, and its name stays empty
		$this->assertSame('Not in use', $status['service']);
		$this->assertSame('', $status['name']);
	}

	public function testAnOnBoxThatIsNotActiveKeepsAnEmptyName(): void
	{
		// Given a Resolver that was never moved, with pfB-DNS on but pfBlockerNG disabled
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		$this->clearProxyFiles();

		// When the status is read
		$status = pfb_dns_status();

		// Then the box is not in use, and its name stays empty
		$this->assertSame('Not in use', $status['service']);
		$this->assertSame('', $status['name']);
	}

	public function testAStoppedOwnedOnBoxWithNoAnswerIsUnavailable(): void
	{
		// Given a moved Resolver with pfB-DNS on, expected to run, and no gateway running
		$this->moved();
		$this->clearProxyFiles();

		// When the status is read
		$status = pfb_dns_status();

		// Then the gateway is stopped, and what it applies is unavailable rather than absent
		$this->assertTrue($status['active']);
		$this->assertSame('Stopped', $status['service']);
		$this->assertNull($status['name']);
	}

	public function testAnOwnedOnBoxWhoseChildIsAliveButNeverServesIsUnavailable(): void
	{
		// Given a moved Resolver with pfB-DNS on, and a gateway process alive that never published its ready marker
		$this->moved();
		$this->proxyLivesButNeverServes();

		// When the status is read
		$status = pfb_dns_status();

		// Then the process is running, its applied snapshot cannot be read, and the name is unavailable
		$this->assertSame('Starting', $status['service']);
		$this->assertNull($status['name']);
	}

	public function testAnInUseGatewayWhoseSnapshotFailsIsUnavailable(): void
	{
		// Given a moved Resolver with pfB-DNS on, and a serving gateway whose applied status does not answer
		$this->moved();
		$this->proxyServes();

		// When the status is read
		$status = pfb_dns_status();

		// Then the name is unavailable, not absent
		$this->assertTrue($status['active']);
		$this->assertNull($status['name']);
	}

	public function testATurningOffGatewayThatIsAliveButNeverServesIsUnavailable(): void
	{
		// Given a moved Resolver with pfB-DNS turned off, and its gateway process alive but never publishing its ready marker
		$this->moved();
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::Off;
		$this->proxyLivesButNeverServes();

		// When the status is read
		$status = pfb_dns_status();

		// Then the process is running, its applied snapshot cannot be read, and the name is unavailable
		$this->assertFalse($status['active']);
		$this->assertSame('Starting', $status['service']);
		$this->assertNull($status['name']);
	}

	public function testATurningOffGatewayStillLiveShowsItsAppliedName(): void
	{
		// Given a moved Resolver with pfB-DNS turned off, and its gateway still running and answering
		$this->moved();
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::Off;
		$this->proxyServes();
		$this->servesName('actual.example.com');

		// When the status is read
		$status = pfb_dns_status();

		// Then the name is the one the running gateway applies
		$this->assertFalse($status['active']);
		$this->assertSame('actual.example.com', $status['name']);
	}
}
