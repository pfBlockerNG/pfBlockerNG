<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The gateway's actual status wires, captured from the built binary and kept byte for byte (support/real-status-*.wire). Only the pid and
 * the executable are replaced, for this box's package binary and the pid this proxy's marker names. A canonical numeric upstream is in the
 * wire and readiness needs Unbound to own it; a hostname or scoped-IPv6 upstream is absent from the wire, and the snapshot still serves its
 * DNS Name, listeners and DDR, while readiness is not claimed.
 */
#[CoversFunction('pfb_dns_proxy_applied_status')]
#[CoversFunction('pfb_dns_proxy_upstream_ready')]
#[CoversFunction('pfb_dns_status')]
final class PfbDnsAppliedStatusRealWireConsumerTest extends TestCase
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
		$this->dir = sys_get_temp_dir() . '/pfb_real_wire_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir' => $this->dir,
			'log' => "{$this->dir}/pfb.log",
			'errlog' => "{$this->dir}/pfb.err",
			'dns_proxy_ctl' => "{$this->dir}/ctl.sock",
			'dns_proxy_activation_failed' => "{$this->dir}/activation_failed",
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

	/** The captured wire with only its pid and executable replaced: this box's package binary, and the pid the proxy marker names. */
	private function captured(string $file): string
	{
		$body = json_decode(substr((string) file_get_contents(__DIR__ . '/support/' . $file), 0, -4), FALSE, 16, JSON_THROW_ON_ERROR);
		$body->pid = 4242;
		$body->executable = PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns';
		return json_encode($body, JSON_THROW_ON_ERROR) . "\nok\n";
	}

	/** Answer the applied-status requests on this test's control socket with $wire, as the gateway does. */
	private function serve(string $wire): void
	{
		$process = proc_open([PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php', $GLOBALS['pfb']['dns_proxy_ctl'],
			"{$this->dir}/frames", base64_encode($wire)], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
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

	public function testCanonicalBracketedIpv4UpstreamIsAcceptedAndReadyWhenUnboundOwnsIt(): void
	{
		// Given the gateway's actual wire for --upstream '[127.0.0.1]:5353', and Unbound owning 127.0.0.1:5353 over TCP and UDP
		$this->serve($this->captured('real-status-bracketed-ipv4.wire'));
		$this->proxyServes();

		// When the applied status is read
		$status = pfb_dns_proxy_applied_status(NULL, 0.5);

		// Then the snapshot is accepted with its canonical upstream, and the gateway is ready
		$this->assertNotNull($status, 'a valid snapshot is accepted');
		$this->assertSame('127.0.0.1:5353', $status['upstream']);
		$this->assertTrue(pfb_dns_proxy_upstream_ready($status));
		$this->assertTrue(pfb_dns_proxy_serving_ready());
	}

	public static function absentUpstreamWires(): array
	{
		return [
			'hostname' => ['real-status-hostname.wire'],
			'scoped IPv6' => ['real-status-scoped-ipv6.wire'],
		];
	}

	#[DataProvider('absentUpstreamWires')]
	public function testAnAbsentUpstreamIsAValidSnapshotThatStillServesNameListenersAndDdrButClaimsNoReadiness(string $file): void
	{
		// Given the gateway's actual wire for a spelling it does not canonicalise (no upstream field), and Unbound owning 127.0.0.1:5353
		$this->serve($this->captured($file));
		$this->proxyServes();

		// When the applied status is read
		$status = pfb_dns_proxy_applied_status(NULL, 0.5);

		// Then the snapshot is accepted without an upstream, its name and listeners are kept, and readiness is not claimed
		$this->assertNotNull($status, 'an absent upstream is a valid snapshot');
		$this->assertArrayNotHasKey('upstream', $status);
		$this->assertSame('', $status['dns_name'], 'the applied DNS Name is present (empty), not unavailable');
		$this->assertCount(1, $status['listeners']);
		$this->assertSame('listening', $status['listeners'][0]['state']);
		$this->assertFalse(pfb_dns_proxy_upstream_ready($status), 'with no endpoint to prove, readiness is not claimed');
		$this->assertFalse(pfb_dns_proxy_serving_ready());

		// And the status page keeps the listener and the DDR row, with the name it applied
		$page = pfb_dns_status();
		$this->assertNotSame('Running', $page['service']);
		$this->assertSame('', $page['name']);
		$listener = $status['listeners'][0]['address'];
		$this->assertSame([$listener => ['state' => 'listening', 'reason' => '']], self::rowsOf($page, 'plain'));
		$this->assertSame([$listener], array_column($page['ddr']['rows'], 'address'));
	}
}
