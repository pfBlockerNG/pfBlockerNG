<?php

declare(strict_types=1);

require_once __DIR__ . '/support/LiveListenerStandIn.php';
require_once __DIR__ . '/support/DdrProbeFixture.php';
require_once __DIR__ . '/PfbDnsDdrStatusTest.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_ddr_status')]
#[CoversFunction('pfb_dns_ddr_probe')]
final class PfbDnsDdrProbeTest extends TestCase
{
	use LiveListenerStandIn;

	private array $saved;
	private string $dir;
	private DdrProbeFixture $fixture;

	protected function setUp(): void
	{
		$this->saved = [];
		foreach (['pfb', 'config', 'pfb_test_valid_pids', 'pfb_test_interfaces', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info'] as $key) {
			$this->saved[$key] = [array_key_exists($key, $GLOBALS), $GLOBALS[$key] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/ddr_probe_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);
		$GLOBALS['pfb'] = ['dns_proxy_pidfile' => "{$this->dir}/pid", 'dns_proxy_ready' => "{$this->dir}/ready", 'dns_proxy_ctl' => "{$this->dir}/ctl"];
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
		PfbConfig::write('dns/pfb_dns_dot_interface', 'lan');
		PfbConfig::write('dns_shared/pfb_dns_ddr', 'on');
		PfbConfig::write('dns_shared/pfb_dns_dot', 'on');
		PfbConfig::write('dns_shared/pfb_dns_dot_port', '853');
		$this->fixture = new DdrProbeFixture();
		$this->fixture->responses = [
			'_dns.resolver.arpa. SVCB' => PfbDnsDdrStatusTest::response([PfbDnsDdrStatusTest::record()],
				additional: ['dns.example.com. 300 IN A 192.0.2.1']),
			'dns.example.com A' => PfbDnsDdrStatusTest::response(['dns.example.com. 300 IN A 192.0.2.1'], 'dns.example.com.', 'A'),
			'dns.example.com AAAA' => PfbDnsDdrStatusTest::response(['dns.example.com. 300 IN AAAA 2001:db8::1'], 'dns.example.com.', 'AAAA'),
		];
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

	public function testAutomaticQueriesUseActualPlainPortAndBothOwnedNameFamilies(): void
	{
		$this->gatewayServes(['udp+tcp 192.0.2.1:5353', 'dot 192.0.2.1:853', 'doh 192.0.2.99:443'], ['udp+tcp 192.0.2.50:53' => 'refused']);
		$result = $this->fixture->status();
		$this->assertSame(['matched'], array_column($result['rows'], 'state'));
		$this->assertCount(3, $this->fixture->calls);
		foreach ($this->fixture->calls as $call) {
			$this->assertSame(['-p', '5353'], array_slice($call, array_search('-p', $call, TRUE), 2));
			$this->assertContains('@192.0.2.1', $call);
			$this->assertContains('-b1232', $call);
			$this->assertContains('127.0.0.1', $call);
			$this->assertContains('/usr/bin/timeout', $call);
			$this->assertContains('-k1', $call);
		}
	}

	public function testSourceSelectionKeepsLoopbackVipsSeparateFromOrdinaryIpv6(): void
	{
		$this->fixture->interfaces = ['lo0' => ['unicast' => [['address' => '::1'], ['address' => '2001:db8::53']]]];
		foreach (['192.0.2.1:5353' => '127.0.0.1', '[::1]:53' => '::1', '[2001:db8::53]:53' => '::1', '[2001:db8::1]:5354' => NULL] as $at => $source) {
			$this->fixture->probe($at, 2.0);
			$call = $this->fixture->calls[count($this->fixture->calls) - 1];
			if ($source === NULL) {
				$this->assertNotContains('-I', $call);
			} else {
				$this->assertSame($source, $call[array_search('-I', $call, TRUE) + 1]);
			}
			$this->assertSame(str_contains($at, '['), in_array('-6', $call, TRUE));
		}
	}

	public function testDisabledInvalidNameAndRefusedTransportCannotTurnGreenOrLaunchQueries(): void
	{
		$this->gatewayServes(['udp+tcp 192.0.2.1:53'], ['dot 192.0.2.1:853' => 'refused']);
		$this->assertSame('no_transport', $this->fixture->status()['rows'][0]['state']);
		PfbConfig::write('dns/pfb_dns_name', '');
		$this->assertSame('unverified', $this->fixture->status()['rows'][0]['state']);
		PfbConfig::write('dns_shared/pfb_dns_ddr', '');
		$this->assertSame('off', $this->fixture->status()['rows'][0]['state']);
		$this->assertSame([], $this->fixture->calls);
	}

	public function testStaleBoundPortsDoNotBlessTheStaleAdvertisement(): void
	{
		$this->gatewayServes(['udp+tcp 192.0.2.1:53', 'dot 192.0.2.1:8853']);
		$this->assertSame('no_transport', $this->fixture->status()['rows'][0]['state']);
		$this->assertSame([], $this->fixture->calls);
	}

	public function testWholeRequestBudgetStopsFurtherProcesses(): void
	{
		$this->gatewayServes(['udp+tcp 192.0.2.1:53', 'dot 192.0.2.1:853', 'udp+tcp 127.0.0.1:53', 'dot 127.0.0.1:853']);
		$this->fixture->elapsedPerQuery = 5000000000;
		$result = $this->fixture->status();
		$this->assertSame(['budget', 'budget'], array_column($result['rows'], 'state'));
		$this->assertCount(2, $this->fixture->calls);
	}

	public function testLoopbackWithoutOwnedNameMappingChecksOnlySvcb(): void
	{
		$this->gatewayServes(['udp+tcp 127.0.0.1:53', 'dot 127.0.0.1:853']);
		$this->fixture->responses['_dns.resolver.arpa. SVCB'] = PfbDnsDdrStatusTest::response([PfbDnsDdrStatusTest::record('127.0.0.1')],
			additional: ['dns.example.com. 300 IN A 127.0.0.1']);
		$result = $this->fixture->status()['rows'][0];
		$this->assertSame('matched', $result['state']);
		$this->assertStringContainsString('name resolution not checked', $result['reason']);
		$this->assertCount(1, $this->fixture->calls);
	}

	public function testInvalidRepeatedRootLabelsCannotBeNormalizedIntoTheQuestionOwner(): void
	{
		$reply = PfbDnsDdrStatusTest::response([PfbDnsDdrStatusTest::record()]);
		$this->assertSame('error', pfb_dns_ddr_result(str_replace('_dns.resolver.arpa.', '_dns.resolver.arpa..', $reply), 0)['state']);
	}
}
