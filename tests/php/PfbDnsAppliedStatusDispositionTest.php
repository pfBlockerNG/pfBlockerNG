<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Configured listeners stay visible beside the applied inventory: an address the rc script asks for that the gateway neither serves nor
 * refuses is a row of its own. An applied status that does not answer is not an unhealthy gateway while nothing is started or restarted;
 * an activation that starts the gateway still waits for an answered status and is reported, with the Resolver left moved, when it never comes.
 */
#[CoversFunction('pfb_dns_status')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_serving_ready')]
final class PfbDnsAppliedStatusDispositionTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_service_calls', 'pfb_test_service_hook', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles',
		'pfb_test_valid_pids', 'pfb_test_rcfile_dir', 'pfb_test_interface_ip', 'pfb_test_interface_info',
		'pfb_test_configured_ipv6', 'pfb_test_configured_ip_addresses',
	];

	private string $dir;
	private array $savedGlobals = [];
	private array $servers = [];
	private ?string $savedChroot = NULL;

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_applied_disposition_' . getmypid() . '_' . uniqid();
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
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
		$this->clearProxyFiles();
		$this->setUpUpstreamFixture();
		$this->setProxyMode();
		// A restart re-reads the package's settings: the keys it reads are present, as in DnsMetricLifecycleTest, not undefined.
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '192.0.2.53');
		config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '');
		$this->savedChroot = $GLOBALS['g']['unbound_chroot_path'] ?? NULL;
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
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
		if ($this->savedChroot === NULL) {
			unset($GLOBALS['g']['unbound_chroot_path']);
		} else {
			$GLOBALS['g']['unbound_chroot_path'] = $this->savedChroot;
		}
		@unlink(PFB_DNS_PROXY_RCFILE);
		rmdir_recursive($this->dir);
	}

	/** The Resolver as pfB-DNS leaves it on a proxy-mode box: a valid saved snapshot of a Resolver that listened on lan. */
	private function setProxyMode(): void
	{
		$keys = [];
		foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
	}

	/** The rc script an apply writes: its daemon line carries the listen flags the gateway is asked to bind. */
	private function desiredRc(string $flags): void
	{
		file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n/usr/sbin/daemon -p /var/run/pfb_dns_proxy.pid " . PFB_DNS_PROXY_DIR
			. "/pfb_dns.sh {$flags}\n");
	}

	/**
	 * @param list<array{kind:string,address:string,state:string,reason:string}> $listeners
	 * @param list<string> $locals the hosts of the listening plain listeners, each with an empty advertisement
	 */
	private static function snapshot(array $listeners, array $locals): array
	{
		$advertisements = [];
		foreach ($locals as $host) {
			$advertisements[$host] = ['records' => [], 'additional' => []];
		}
		return [
			'version' => 1, 'pid' => 4242, 'executable' => PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns',
			'ready' => TRUE, 'upstream' => '127.0.0.1:5353', 'dns_name' => 'fw.example.lan',
			'listeners' => $listeners, 'name_answers' => (object) [], 'ddr' => FALSE,
			'advertisements' => (object) $advertisements,
		];
	}

	private static function wire(array $snapshot): string
	{
		return json_encode($snapshot, JSON_THROW_ON_ERROR) . "\nok\n";
	}

	/**
	 * Answer the applied-status requests on pfb's sandbox control socket with $reply, written as it is: NULL serves nothing (no socket),
	 * '' closes each connection unanswered. The stand-in is this file's own, so the answer is exactly what the test states.
	 */
	private function serve(?string $reply): void
	{
		if ($reply === NULL) {
			return;
		}
		$process = proc_open([PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php', $GLOBALS['pfb']['dns_proxy_ctl'],
			"{$this->dir}/frames", base64_encode($reply)], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$process, $pipes];
	}

	/** @return array<string,array{state:string,reason:string}> address => state and reason, over one transport's rows */
	private static function rowsOf(array $status, string $transport): array
	{
		$rows = [];
		foreach ($status['transports'][$transport]['rows'] ?? [] as $row) {
			foreach ($row['addresses'] as $address) {
				$rows[$address] = ['state' => $row['state'], 'reason' => $row['reason']];
			}
		}
		ksort($rows);
		return $rows;
	}

	/** ensure_running and its readiness wait on a virtual clock, so the 30 s start budget costs no time (as the other proxy suites do). */
	private function clockedEnsureRunning(): array
	{
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(
			['pfb_dns_proxy_ensure_running', 'pfb_dns_proxy_confirm_started', 'pfb_dns_proxy_confirm_ready', 'pfb_dns_proxy_await_ready'],
			['PFB_DNS_PROXY_START_WAIT' => 1]
		);
		return [$clock, $namespace . '\\pfb_dns_proxy_ensure_running'];
	}

	public function testAListenerTheRcScriptAsksForAndTheGatewayNeverReportedStaysNotListening(): void
	{
		// Given an rc script asking for 192.0.2.1 and 192.0.2.2 on port 53, and a gateway that serves only 192.0.2.1
		$this->desiredRc("--listen '192.0.2.1' --listen '192.0.2.2' --port '53'");
		$this->proxyServes();
		$this->serve(self::wire(self::snapshot(
			[['kind' => 'udp+tcp', 'address' => '192.0.2.1:53', 'state' => 'listening', 'reason' => '']],
			['192.0.2.1']
		)));

		// When the status is read
		$rows = self::rowsOf(pfb_dns_status(), 'plain');

		// Then the address it never reported is still a configured row, not listening, with the reason it was given
		$this->assertSame([
			'192.0.2.1:53' => ['state' => 'listening', 'reason' => ''],
			'192.0.2.2:53' => ['state' => 'not_listening', 'reason' => 'the gateway did not report it'],
		], $rows);
	}

	public function testAListenerTheGatewayRefusedKeepsTheReasonItGaveForIt(): void
	{
		// Given the same rc script, and a gateway that refuses 192.0.2.2 with a reason
		$this->desiredRc("--listen '192.0.2.1' --listen '192.0.2.2' --port '53'");
		$this->proxyServes();
		$this->serve(self::wire(self::snapshot([
			['kind' => 'udp+tcp', 'address' => '192.0.2.1:53', 'state' => 'listening', 'reason' => ''],
			['kind' => 'udp+tcp', 'address' => '192.0.2.2:53', 'state' => 'refused', 'reason' => 'Address in use'],
		], ['192.0.2.1'])));

		// When the status is read
		$rows = self::rowsOf(pfb_dns_status(), 'plain');

		// Then the refusal is what the row says
		$this->assertSame([
			'192.0.2.1:53' => ['state' => 'listening', 'reason' => ''],
			'192.0.2.2:53' => ['state' => 'not_listening', 'reason' => 'Address in use'],
		], $rows);
	}

	public static function unansweredStatus(): array
	{
		return [
			'no control socket' => [NULL],
			'an older gateway refuses the verb' => ["error: a message of 4294967292 bytes is not between 1 and 65536\n"],
			'the connection closes unanswered' => [''],
		];
	}

	#[DataProvider('unansweredStatus')]
	public function testAReadyGatewayWhoseScriptIsUnchangedIsKeptWhenItsAppliedStatusIsUnanswered(?string $reply): void
	{
		// Given a current rc script, a live and ready gateway, and a control socket that does not answer the status
		pfb_dns_proxy_service();
		$this->proxyServes();
		$this->serve($reply);
		[$clock, $ensure] = $this->clockedEnsureRunning();

		// When the apply finds nothing to reload
		$ready = $ensure();

		// Then the gateway is kept as it is: nothing is started, restarted or restored
		$this->assertTrue($ready, 'an unanswered status is unknown, not an unhealthy gateway');
		$this->assertSame([], $GLOBALS['pfb_test_service_calls']);
		$this->assertTrue(pfb_dns_proxy_ready());
	}

	public function testAnActivationThatStartsTheGatewayIsNotConfirmedWhenItsAppliedStatusIsUnanswered(): void
	{
		// Given a proxy that is not running; the start brings up a ready gateway whose applied status never answers
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service): void {
			if ($fn === 'start_service' && $service === 'pfb_dns_proxy') {
				$this->proxyServes();
			}
		};
		[$clock, $ensure] = $this->clockedEnsureRunning();

		// When the activation starts it and waits for it to serve
		$ready = $ensure();

		// Then the activation is not confirmed, and the gateway was started
		$this->assertFalse($ready, 'an activation waits for an applied status, and an unanswered one is not confirmation');
		$this->assertContains(['start_service', 'pfb_dns_proxy'], $GLOBALS['pfb_test_service_calls']);
	}

	public function testARestartForcedByChangedListenAddressesIsNotConfirmedWhenItsAppliedStatusStaysUnanswered(): void
	{
		// Given a live and ready gateway whose applied status never answers, and an rc script whose listen addresses changed
		pfb_dns_proxy_service();
		file_put_contents(PFB_DNS_PROXY_RCFILE, str_replace(' --port ', " --listen '192.0.2.9' --port ", (string) file_get_contents(PFB_DNS_PROXY_RCFILE)));
		$this->proxyServes();
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service): void {
			if ($fn === 'restart_service' && $service === 'pfb_dns_proxy') {
				$this->proxyServes();
			}
		};
		[$clock, $ensure] = $this->clockedEnsureRunning();

		// When the apply restarts it for the new addresses and waits for it to serve
		$ready = $ensure();

		// Then the restart is an activation: it is not confirmed by a status that never answers
		$this->assertContains(['restart_service', 'pfb_dns_proxy'], $GLOBALS['pfb_test_service_calls']);
		$this->assertFalse($ready, 'a restart waits for an applied status, and an unanswered one is not confirmation');
	}

	public function testServingReadinessNeedsAnAnsweredAppliedStatus(): void
	{
		// Given a ready gateway whose Unbound backend is healthy, but no control socket answers the status
		$this->proxyServes();
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'before: nothing answers the applied status');

		// When the gateway answers with its applied upstream, which Unbound owns
		$this->serve(self::wire(self::snapshot(
			[['kind' => 'udp+tcp', 'address' => '192.0.2.1:53', 'state' => 'listening', 'reason' => '']],
			['192.0.2.1']
		)));

		// Then it serves
		$this->assertTrue(pfb_dns_proxy_serving_ready());
	}
}
