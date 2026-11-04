<?php

declare(strict_types=1);

require_once __DIR__ . '/support/KeepRunningScenario.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';
require_once __DIR__ . '/support/PfbFlockClockFixture.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_proxy_service')]
#[CoversFunction('pfb_dns_proxy_tls_flags')]
#[CoversFunction('pfb_dns_proxy_command_listeners')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
final class DnsProxyManagedVipPortsTest extends TestCase
{
	use KeepRunningScenario;
	use LiveListenerStandIn;

	private const VIP4 = '172.16.53.53';
	private const VIP6 = 'fd00:53::1';
	private const PORTS = ['udp+tcp' => 1053, 'dot' => 1853, 'doh' => 4443, 'doq' => 2853];
	private const STANDARD = ['udp+tcp' => 53, 'dot' => 853, 'doh' => 443, 'doq' => 853];
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach ([...self::krGlobals(), 'pfb_test_vip_list', 'pfb_test_configured_subnets'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->krSeed(sys_get_temp_dir() . '/pfb_standard_' . getmypid() . '_' . bin2hex(random_bytes(4)));
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1'];
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		$this->store('pfb_dns_interface', 'lan');
		$this->store('pfb_dns_name', 'dns.example.net');
		foreach (['dot', 'doh', 'doq'] as $kind) {
			$this->store("pfb_dns_{$kind}", 'on');
			$this->store("pfb_dns_{$kind}_interface", 'lan');
			$this->store("pfb_dns_{$kind}_port", (string) self::PORTS[$kind]);
			$this->store("pfb_dns_{$kind}_port6", (string) (self::PORTS[$kind] + 100));
		}
	}

	protected function tearDown(): void
	{
		$this->standInsStop();
		$this->clearProxyFiles();
		@unlink(PFB_DNS_PROXY_RCFILE);
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		rmdir_recursive($this->krDir);
	}

	private function store(string $key, string $value): void
	{
		config_set_path(PFB_SECTIONS[explode('/', pfb_dns_config_key($key), 2)[0]] . '/' . $key, $value);
	}

	private function vips(bool $managed): void
	{
		$rows = [];
		foreach ([4 => self::VIP4, 6 => self::VIP6] as $family => $address) {
			$rows[] = ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address,
				'subnet_bits' => $family === 6 ? '128' : '32', 'uniqid' => "vip{$family}",
				'descr' => $managed ? "pfB_DNS_LISTEN_VIP_v{$family}" : 'operator VIP'];
			$this->store("pfb_dns_listen_vip{$family}", $managed ? 'auto' : "_vipvip{$family}");
			$this->store("pfb_dns_listen_auto{$family}", $managed ? $address : '');
		}
		config_set_path('virtualip/vip', $rows);
		$this->store('pfb_dns_listen_vip', 'on');
	}

	private function command(int $plainPort = 1053): array
	{
		$this->krApply(['port' => (string) $plainPort]);
		return pfb_dns_proxy_command_listeners();
	}

	public function testManagedVipsUseOnlyStandardPortsWhileInterfacesAndLoopbackKeepCustomPorts(): void
	{
		$this->vips(TRUE);
		$wanted = $this->command();
		foreach (self::PORTS as $kind => $port) {
			$port6 = $kind === 'udp+tcp' ? $port : $port + 100;
			$this->assertEqualsCanonicalizing([
				"192.0.2.1:{$port}", "[2001:db8::1]:{$port6}", "127.0.0.1:{$port}", "[::1]:{$port6}",
				self::VIP4 . ':' . self::STANDARD[$kind], '[' . self::VIP6 . ']:' . self::STANDARD[$kind],
			], $wanted[$kind] ?? [], $kind);
		}
	}

	/** @return array<string,array{bool}> */
	public static function vipOwnership(): array
	{
		return ['managed' => [TRUE], 'administrator-managed' => [FALSE]];
	}

	#[DataProvider('vipOwnership')]
	public function testVipOnlyRemovesOrdinaryEndpointsAndKeepsEachVipsOwnPortsAndInternalLoopback(bool $managed): void
	{
		$this->vips($managed);
		$this->store('pfb_dns', 'on');
		$this->store('pfb_dns_listen_vip_only', 'on');
		$wanted = $this->command();
		foreach (self::PORTS as $kind => $port) {
			$port6 = $kind === 'udp+tcp' ? $port : $port + 100;
			$vip_port = $managed ? self::STANDARD[$kind] : $port;
			$vip_port6 = $managed ? self::STANDARD[$kind] : $port6;
			$this->assertEqualsCanonicalizing([
				"127.0.0.1:{$port}", "[::1]:{$port6}",
				self::VIP4 . ':' . $vip_port, '[' . self::VIP6 . ']:' . $vip_port6,
			], $wanted[$kind] ?? [], $kind);
		}
	}

	public function testUnmanagedVipsRetainTheirConfiguredFamilyPorts(): void
	{
		$this->vips(FALSE);
		$wanted = $this->command();
		foreach (self::PORTS as $kind => $port) {
			$port6 = $kind === 'udp+tcp' ? $port : $port + 100;
			$this->assertContains(self::VIP4 . ":{$port}", $wanted[$kind], $kind);
			$this->assertContains('[' . self::VIP6 . "]:{$port6}", $wanted[$kind], $kind);
			$this->assertCount(6, $wanted[$kind], $kind);
		}
	}

	public function testDefaultConfiguredPortsDoNotDuplicateManagedEndpointsAndDohKeepsItsFamilyReplacement(): void
	{
		$this->vips(TRUE);
		foreach (['dot', 'doh', 'doq'] as $kind) {
			$this->store("pfb_dns_{$kind}_port", (string) self::STANDARD[$kind]);
			$this->store("pfb_dns_{$kind}_port6", (string) self::STANDARD[$kind]);
		}
		$wanted = $this->command(53);
		foreach (self::STANDARD as $kind => $port) {
			$this->assertSame(array_values(array_unique($wanted[$kind])), $wanted[$kind], $kind);
			$this->assertContains(self::VIP4 . ":{$port}", $wanted[$kind], $kind);
			$this->assertContains('[' . self::VIP6 . "]:{$port}", $wanted[$kind], $kind);
		}
		$this->assertNotContains('192.0.2.1:443', $wanted['doh']);
		$this->assertNotContains('[2001:db8::1]:443', $wanted['doh']);
	}

	public function testDisabledEncryptedTransportsHaveNoOrdinaryOrFixedVipEndpoints(): void
	{
		$this->vips(TRUE);
		foreach (['dot', 'doh', 'doq'] as $kind) {
			$this->store("pfb_dns_{$kind}", '');
		}
		$this->assertSame(['udp+tcp'], array_keys($this->command()));
	}

	public function testNoVipKeepsEveryOrdinaryFamilyPortUnchanged(): void
	{
		$wanted = $this->command();
		foreach (self::PORTS as $kind => $port) {
			$port6 = $kind === 'udp+tcp' ? $port : $port + 100;
			$this->assertSame(["192.0.2.1:{$port}", "[2001:db8::1]:{$port6}", "127.0.0.1:{$port}", "[::1]:{$port6}"], $wanted[$kind], $kind);
		}
	}

	public function testManagedEndpointRemovalReconcilesAllFixedFlagsWithoutRestart(): void
	{
		$this->vips(TRUE);
		$wanted = $this->command();
		$lines = [];
		foreach ($wanted as $kind => $endpoints) {
			foreach ($endpoints as $endpoint) {
				$lines[] = "{$kind} {$endpoint}";
			}
		}
		$record = $this->standIn($GLOBALS['pfb']['dns_proxy_ctl'], [], ['listening' => $lines]);
		config_set_path('virtualip/vip', []);
		$this->assertTrue($this->krEnsure());
		$this->assertSame([], $this->krProxyCalls(), 'all fixed flags are address-only changes');
		$removed = array_column(array_filter(self::changeFrames($record), static fn (array $frame): bool => $frame['head'] !== 'fffffffb'), 'body');
		$expected = [];
		foreach (self::STANDARD as $kind => $port) {
			$expected[] = "{$kind} " . self::VIP4 . ":{$port}";
			$expected[] = "{$kind} [" . self::VIP6 . "]:{$port}";
		}
		$this->assertEqualsCanonicalizing($expected, $removed);
	}
}
