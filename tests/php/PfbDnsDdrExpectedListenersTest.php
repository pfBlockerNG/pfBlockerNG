<?php

declare(strict_types=1);

require_once __DIR__ . '/support/LiveListenerStandIn.php';
require_once __DIR__ . '/support/DdrProbeFixture.php';
require_once __DIR__ . '/PfbDnsDdrStatusTest.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_ddr_status')]
final class PfbDnsDdrExpectedListenersTest extends TestCase
{
	use LiveListenerStandIn;

	private array $saved = [];
	private string $dir;

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_valid_pids', 'pfb_test_interfaces', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info'] as $key) {
			$this->saved[$key] = [array_key_exists($key, $GLOBALS), $GLOBALS[$key] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/ddr_expected_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);
		$GLOBALS['pfb'] = ['dbdir' => $this->dir, 'dns_proxy_pidfile' => "{$this->dir}/pid", 'dns_proxy_ready' => "{$this->dir}/ready", 'dns_proxy_ctl' => "{$this->dir}/ctl"];
		$GLOBALS['config'] = [];
		file_put_contents($GLOBALS['pfb']['dns_proxy_pidfile'], "4242\n");
		file_put_contents($GLOBALS['pfb']['dns_proxy_ready'], "4242\n");
		$GLOBALS['pfb_test_valid_pids'] = [$GLOBALS['pfb']['dns_proxy_pidfile'] => TRUE];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		PfbConfig::write('dns/pfb_dns_name', 'dns.example.com');
		PfbConfig::write('dns/pfb_dns_interface', 'lan');
		PfbConfig::write('dns_shared/pfb_dns_ddr', 'on');
	}

	protected function tearDown(): void
	{
		$this->standInsStop();
		rmdir_recursive($this->dir);
		foreach ($this->saved as $key => [$present, $value]) {
			if ($present) {
				$GLOBALS[$key] = $value;
			} else {
				unset($GLOBALS[$key]);
			}
		}
	}

	public static function listeners(): array
	{
		$cases = [];
		foreach (['dot' => 8853, 'doh' => 4443, 'doq' => 8853] as $kind => $port) {
			foreach ([4, 6] as $family) {
				foreach (['interface', 'manual', 'auto', 'only', 'loopback'] as $addressKind) {
					$cases["{$kind} IPv{$family} {$addressKind}"] = [$kind, $port, $family, $addressKind, FALSE];
				}
				$cases["{$kind} IPv{$family} standard"] = [$kind, $kind === 'doh' ? 443 : 853, $family, 'interface', FALSE];
				if ($kind === 'doh') {
					foreach (['interface', 'manual'] as $addressKind) {
						$cases["DoH IPv{$family} 443 override {$addressKind}"] = [$kind, $port, $family, $addressKind, TRUE];
					}
				}
			}
		}
		return $cases;
	}

	#[DataProvider('listeners')]
	public function testSavedPerFamilyPortsAndVipNamePairsMatchOnlyTheirBoundAdvertisement(string $kind, int $port, int $family, string $addressKind, bool $override): void
	{
		$isVip = $addressKind !== 'interface';
		$isAuto = $addressKind === 'auto';
		$v4 = $isVip ? '192.0.2.53' : '192.0.2.1';
		$v6 = $isVip ? '2001:db8::53' : '2001:db8::1';
		$host = $family === 4 ? $v4 : $v6;
		if ($addressKind === 'loopback') {
			$host = $family === 4 ? '127.0.0.1' : '::1';
		}
		if ($isVip) {
			$rows = [];
			foreach ([4 => $v4, 6 => $v6] as $f => $address) {
				$rows[] = ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address,
					'subnet_bits' => $f === 4 ? '32' : '128', 'descr' => $isAuto ? "pfB_DNS_LISTEN_VIP_v{$f}" : 'Admin VIP', 'uniqid' => "v{$f}"];
				PfbConfig::write("gen/pfb_dns_listen_vip{$f}", $isAuto ? 'auto' : "_vipv{$f}");
				PfbConfig::write("gen/pfb_dns_listen_auto{$f}", $isAuto ? $address : '');
			}
			config_set_path('virtualip/vip', $rows);
			PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
			if (in_array($addressKind, ['only', 'loopback'], TRUE)) {
				PfbConfig::write('gen/pfb_dns_listen_vip_only', 'on');
				PfbConfig::write('dns/pfb_dns', 'on');
			}
		}
		PfbConfig::write("dns_shared/pfb_dns_{$kind}", 'on');
		PfbConfig::write("dns/pfb_dns_{$kind}_interface", 'lan');
		PfbConfig::write("dns_shared/pfb_dns_{$kind}_port", (string) $port);
		$port6 = $port === 443 || $port === 853 ? $port : $port + 1;
		PfbConfig::write("dns_shared/pfb_dns_{$kind}_port6", (string) $port6);
		if ($override) {
			PfbConfig::write('dns/pfb_dns_ddr_doh_443_interfaces', $isVip ? "_vipv{$family}" : 'lan');
		}
		$standard = $kind === 'doh' ? 443 : 853;
		$boundPort = $isAuto ? $standard : ($family === 6 ? $port6 : $port);
		$advertisedPort = $override ? 443 : $boundPort;
		$this->gatewayServes(['udp+tcp ' . pfb_dns_proxy_host_port($host, '5353'), "{$kind} " . pfb_dns_proxy_host_port($host, (string) $boundPort)]);
		$fixture = new DdrProbeFixture();
		$fixture->responses = [
			'_dns.resolver.arpa. SVCB' => PfbDnsDdrStatusTest::response(
				[PfbDnsDdrStatusTest::record($host, ['dot' => 'dot', 'doh' => 'h2', 'doq' => 'doq'][$kind], $advertisedPort)],
				additional: ['dns.example.com. 300 IN ' . ($family === 4 ? 'A' : 'AAAA') . " {$host}"]),
			'dns.example.com A' => PfbDnsDdrStatusTest::response(["dns.example.com. 300 IN A {$v4}"], 'dns.example.com.', 'A'),
			'dns.example.com AAAA' => PfbDnsDdrStatusTest::response(["dns.example.com. 300 IN AAAA {$v6}"], 'dns.example.com.', 'AAAA'),
		];
		$result = $fixture->status(pfb_dns_proxy_host_port($host, '5353'));
		$this->assertSame('matched', $result['rows'][0]['state'], json_encode($result));
		$this->assertCount(3, $fixture->calls);
		PfbConfig::write("dns_shared/pfb_dns_{$kind}_port", 'invalid');
		$invalid = $fixture->status(pfb_dns_proxy_host_port($host, '5353'));
		$this->assertSame('no_transport', $invalid['rows'][0]['state'], 'An invalid base port disables the group even for IPv6 and managed VIP overrides: ' . json_encode($invalid));
		$this->assertCount(3, $fixture->calls, 'Invalid settings must not launch more queries');
	}

	public static function ipv6Fallbacks(): array
	{
		return [['dot', 'dot', 8853], ['doh', 'h2', 4443], ['doq', 'doq', 8853]];
	}

	#[DataProvider('ipv6Fallbacks')]
	public function testInvalidIpv6OverrideKeepsTheBasePort(string $kind, string $alpn, int $port): void
	{
		PfbConfig::write("dns_shared/pfb_dns_{$kind}", 'on');
		PfbConfig::write("dns/pfb_dns_{$kind}_interface", 'lan');
		PfbConfig::write("dns_shared/pfb_dns_{$kind}_port", (string) $port);
		PfbConfig::write("dns_shared/pfb_dns_{$kind}_port6", 'invalid');
		$this->gatewayServes(['udp+tcp [2001:db8::1]:5353', "{$kind} [2001:db8::1]:{$port}"]);
		$fixture = new DdrProbeFixture();
		$fixture->responses = [
			'_dns.resolver.arpa. SVCB' => PfbDnsDdrStatusTest::response(
				[PfbDnsDdrStatusTest::record('2001:db8::1', $alpn, $port)],
				additional: ['dns.example.com. 300 IN AAAA 2001:db8::1']),
			'dns.example.com A' => PfbDnsDdrStatusTest::response(['dns.example.com. 300 IN A 192.0.2.1'], 'dns.example.com.', 'A'),
			'dns.example.com AAAA' => PfbDnsDdrStatusTest::response(['dns.example.com. 300 IN AAAA 2001:db8::1'], 'dns.example.com.', 'AAAA'),
		];
		$status = $fixture->status('[2001:db8::1]:5353');
		$this->assertSame('matched', $status['rows'][0]['state'], json_encode($status));
	}

	public static function nonCanonicalVips(): array
	{
		$cases = [];
		foreach (['dot' => 'dot', 'doh' => 'h2', 'doq' => 'doq'] as $kind => $alpn) {
			foreach (['manual', 'auto', 'only'] as $mode) {
				$cases["{$kind} {$mode}"] = [$kind, $alpn, $mode, FALSE];
			}
		}
		$cases['DoH 443 override manual'] = ['doh', 'h2', 'manual', TRUE];
		return $cases;
	}

	/** config.xml keeps a VIP as typed; the gateway lists it canonically, so a typed spelling must not lose the match. */
	#[DataProvider('nonCanonicalVips')]
	public function testVipStoredInNonCanonicalSpellingStillMatches(string $kind, string $alpn, string $mode, bool $override): void
	{
		$auto = $mode === 'auto';
		$host = '2001:db8::53';
		$rows = [];
		foreach ([4 => '192.0.2.53', 6 => '2001:DB8:0::53'] as $family => $stored) {
			$rows[] = ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $stored,
				'subnet_bits' => $family === 4 ? '32' : '128', 'descr' => $auto ? "pfB_DNS_LISTEN_VIP_v{$family}" : 'Admin VIP', 'uniqid' => "v{$family}"];
			PfbConfig::write("gen/pfb_dns_listen_vip{$family}", $auto ? 'auto' : "_vipv{$family}");
			PfbConfig::write("gen/pfb_dns_listen_auto{$family}", $auto ? $stored : '');
		}
		config_set_path('virtualip/vip', $rows);
		PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
		if ($mode === 'only') {
			PfbConfig::write('gen/pfb_dns_listen_vip_only', 'on');
			PfbConfig::write('dns/pfb_dns', 'on');
		}
		$port = $kind === 'doh' ? 4443 : 8853;
		PfbConfig::write("dns_shared/pfb_dns_{$kind}", 'on');
		PfbConfig::write("dns/pfb_dns_{$kind}_interface", 'lan');
		PfbConfig::write("dns_shared/pfb_dns_{$kind}_port", (string) $port);
		if ($override) {
			PfbConfig::write('dns/pfb_dns_ddr_doh_443_interfaces', '_vipv6');
		}
		$bound = $auto ? ($kind === 'doh' ? 443 : 853) : $port;
		$this->gatewayServes(["udp+tcp [{$host}]:5353", "{$kind} [{$host}]:{$bound}"]);
		$fixture = new DdrProbeFixture();
		$fixture->responses = [
			'_dns.resolver.arpa. SVCB' => PfbDnsDdrStatusTest::response(
				[PfbDnsDdrStatusTest::record($host, $alpn, $override ? 443 : $bound)],
				additional: ["dns.example.com. 300 IN AAAA {$host}"]),
			'dns.example.com A' => PfbDnsDdrStatusTest::response(['dns.example.com. 300 IN A 192.0.2.53'], 'dns.example.com.', 'A'),
			'dns.example.com AAAA' => PfbDnsDdrStatusTest::response(["dns.example.com. 300 IN AAAA {$host}"], 'dns.example.com.', 'AAAA'),
		];
		$status = $fixture->status("[{$host}]:5353");
		$this->assertSame('matched', $status['rows'][0]['state'], json_encode($status));
	}

	/** A manual VIP no client can be handed (loopback here) still has its bound listener checked, not reported as absent. */
	public function testUnusableManualVipStillComparesItsBoundListener(): void
	{
		$host = '127.0.0.2';
		config_set_path('virtualip/vip', [['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $host,
			'subnet_bits' => '32', 'descr' => 'Admin VIP', 'uniqid' => 'v4']]);
		PfbConfig::write('gen/pfb_dns_listen_vip4', '_vipv4');
		PfbConfig::write('gen/pfb_dns_listen_vip6', 'none');
		PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
		PfbConfig::write('dns_shared/pfb_dns_dot', 'on');
		PfbConfig::write('dns/pfb_dns_dot_interface', 'lan');
		PfbConfig::write('dns_shared/pfb_dns_dot_port', '8853');
		$this->gatewayServes(["udp+tcp {$host}:5353", "dot {$host}:8853"]);
		$fixture = new DdrProbeFixture();
		$fixture->responses = [
			'_dns.resolver.arpa. SVCB' => PfbDnsDdrStatusTest::response([PfbDnsDdrStatusTest::record($host, 'dot', 8853)],
				additional: ["dns.example.com. 300 IN A {$host}"]),
		];
		$status = $fixture->status("{$host}:5353");
		// No DNS Name answer is owned for an address clients cannot be given, so a matching SVCB stays unverified.
		$this->assertSame('unverified', $status['rows'][0]['state'], json_encode($status));
		$this->assertCount(1, $fixture->calls);
	}
}
