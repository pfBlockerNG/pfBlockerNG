<?php

declare(strict_types=1);

require_once __DIR__ . '/support/LiveListenerStandIn.php';
require_once __DIR__ . '/support/DdrProbeFixture.php';
require_once __DIR__ . '/PfbDnsDdrStatusTest.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
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

	public function testMetadataShowsTheAppliedRowsAndTimestampWithoutDnsProcesses(): void
	{
		$this->gatewayServes(['udp+tcp 192.0.2.1:5353', 'dot 192.0.2.1:853', 'udp+tcp [2001:db8::1]:5354', 'dot [2001:db8::1]:853']);
		$this->gatewayAdvertisement('192.0.2.1');
		$status = $this->fixture->status();
		$this->assertSame([], $this->fixture->calls, 'Page metadata must not launch DNS subprocesses');
		$this->assertMatchesRegularExpression('/\A\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC\z/', (string) $status['queried']);
		$this->assertSame(['192.0.2.1:5353', '[2001:db8::1]:5354'], array_column($status['rows'], 'address'));
		$this->assertSame(['matched', 'no_transport'], array_column($status['rows'], 'state'));
		foreach ($status['rows'] as $row) {
			$this->assertArrayNotHasKey('name', $row);
		}
	}

	public static function selectedListeners(): array
	{
		return [['192.0.2.1:5353', '192.0.2.1'], ['[2001:db8::1]:5354', '2001:db8::1']];
	}

	/** The selector API is gone: each directed question is an explicit diagnostic at the exact address it names, on its own port. */
	#[DataProvider('selectedListeners')]
	public function testExplicitDiagnosticAsksEachDirectedQuestionAtExactlyItsBoundAddress(string $listener, string $host): void
	{
		$this->fixture->responses['_dns.resolver.arpa. SVCB'] = PfbDnsDdrStatusTest::response(
			[PfbDnsDdrStatusTest::record($host)], additional: ['dns.example.com. 300 IN ' . (str_contains($host, ':') ? 'AAAA' : 'A') . " {$host}"]);
		foreach ([['_dns.resolver.arpa.', 'SVCB'], ['dns.example.com', 'A'], ['dns.example.com', 'AAAA']] as [$question, $type]) {
			$this->assertSame('ok', $this->fixture->probe($listener, 2.0, $question, $type)['state'], "{$question} {$type}");
		}
		$this->assertCount(3, $this->fixture->calls);
		foreach ($this->fixture->calls as $call) {
			$this->assertContains("@{$host}", $call);
			$this->assertSame(str_contains($host, ':') ? '5354' : '5353', $call[array_search('-p', $call, TRUE) + 1]);
		}
	}

	public static function hostileTargets(): array
	{
		return PfbDnsDdrStatusTest::hostileListeners();
	}

	/** Hostile input is refused at the explicit boundary; the HTTP boundary refuses every listener parameter (smoke-owned). */
	#[DataProvider('hostileTargets')]
	public function testHostileDiagnosticTargetIsRefusedWithoutAQuery(string $listener): void
	{
		$this->assertSame('error', $this->fixture->probe($listener, 2.0)['state']);
		$this->assertSame([], $this->fixture->calls, "Rejected target {$listener} must not launch DNS subprocesses");
	}

	public static function canonicalUnboundTargets(): array
	{
		return [['192.0.2.99:53'], ['192.0.2.50:53'], ['192.0.2.1:853'], ['192.0.2.1:53']];
	}

	/** A canonical numeric target is a valid diagnostic target bound or not: the explicit probe does not check the bound list. */
	#[DataProvider('canonicalUnboundTargets')]
	public function testCanonicalNumericDiagnosticTargetIsQueriedOnceWithoutABoundListCheck(string $listener): void
	{
		$colon = strrpos($listener, ':');
		$this->assertSame('ok', $this->fixture->probe($listener, 2.0)['state']);
		$this->assertCount(1, $this->fixture->calls);
		$this->assertContains('@' . substr($listener, 0, $colon), $this->fixture->calls[0]);
		$this->assertSame(substr($listener, $colon + 1), $this->fixture->calls[0][array_search('-p', $this->fixture->calls[0], TRUE) + 1]);
	}

	/** The multi-query budget is gone from automatic status: a slow DNS server cannot starve a request that launches nothing. */
	public function testAutomaticStatusCannotBeStarvedBySlowDnsBecauseItLaunchesNoQuery(): void
	{
		$this->gatewayServes(['udp+tcp 192.0.2.1:53', 'udp+tcp 127.0.0.1:53']);
		$this->gatewayAdvertisement('192.0.2.1');
		$this->fixture->exit = 124;
		$status = $this->fixture->status();
		$this->assertSame([], $this->fixture->calls);
		$states = array_column($status['rows'], 'state', 'address');
		ksort($states);
		$this->assertSame(['127.0.0.1:53' => 'no_transport', '192.0.2.1:53' => 'matched'], $states);
	}

	/** The explicit timeout reports timeout, and the next explicit request still gets its own deadline and query. */
	public function testATimedOutDiagnosticQueryDoesNotStarveTheNextDiagnosticQuery(): void
	{
		$this->fixture->exit = 124;
		$this->assertSame('timeout', $this->fixture->probe('192.0.2.1:53', 2.0)['state']);
		$this->fixture->exit = 0;
		$this->fixture->responses['_dns.resolver.arpa. SVCB'] = PfbDnsDdrStatusTest::response([PfbDnsDdrStatusTest::record('127.0.0.1')],
			additional: ['dns.example.com. 300 IN A 127.0.0.1']);
		$this->assertSame('ok', $this->fixture->probe('127.0.0.1:53', 2.0)['state']);
		$this->assertCount(2, $this->fixture->calls, 'The next explicit request launches its own query');
	}

	public function testExplicitQueriesUseTheActualPlainPortAndBothOwnedNameFamilies(): void
	{
		foreach ([['_dns.resolver.arpa.', 'SVCB'], ['dns.example.com', 'A'], ['dns.example.com', 'AAAA']] as [$question, $type]) {
			$this->assertSame('ok', $this->fixture->probe('192.0.2.1:5353', 2.0, $question, $type)['state'], "{$question} {$type}");
		}
		$this->assertSame([['_dns.resolver.arpa.', 'SVCB'], ['dns.example.com', 'A'], ['dns.example.com', 'AAAA']],
			array_map(static fn (array $call): array => [$call[count($call) - 3], $call[count($call) - 1]], $this->fixture->calls));
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

	/** Applied state governs the row: a saved name, DDR or transport change made after the snapshot does not alter it. */
	public function testAppliedStateGovernsTheRowAndSavedChangesCannotOverrideIt(): void
	{
		$this->gatewayServes(['udp+tcp 192.0.2.1:53'], ['dot 192.0.2.1:853' => 'refused']);
		$this->gatewayStatus(['dns_name' => 'dns.example.com', 'ddr' => TRUE,
			'advertisements' => (object) ['192.0.2.1' => ['records' => [], 'additional' => []]]]);
		$this->assertSame('no_transport', $this->fixture->status()['rows'][0]['state']);
		PfbConfig::write('dns/pfb_dns_name', '');
		PfbConfig::write('dns_shared/pfb_dns_ddr', '');
		$this->assertSame('no_transport', $this->fixture->status()['rows'][0]['state'], 'Saved name and DDR changes do not override the applied row');
		$this->gatewayStatus(['ddr' => FALSE, 'dns_name' => 'dns.example.com']);
		PfbConfig::write('dns_shared/pfb_dns_ddr', 'on');
		$this->assertSame('off', $this->fixture->status()['rows'][0]['state'], 'Applied DDR off wins over saved DDR on');
		$this->assertSame([], $this->fixture->calls);
	}

	/** The actual bound nonstandard port stays advertised until it is applied; the unapplied saved port (853, set in setUp) does not override it. */
	public function testAppliedBoundPortWinsOverAnUnappliedSavedPort(): void
	{
		$this->gatewayServes(['udp+tcp 192.0.2.1:53', 'dot 192.0.2.1:8853']);
		$this->gatewayAdvertisement('192.0.2.1', 'dot', 8853);
		$row = $this->fixture->status()['rows'][0];
		$this->assertSame('matched', $row['state']);
		$this->assertStringContainsString('dot dns.example.com:8853 (192.0.2.1)', $row['reason']);
		$this->assertSame([], $this->fixture->calls);
	}

	/** An address with no owned DNS Name mapping shows its applied advertisement as forwarded, never as a verified name. */
	public function testLoopbackWithoutOwnedNameIsAdvertisedAsForwardedNotChecked(): void
	{
		$this->gatewayServes(['udp+tcp 127.0.0.1:53', 'dot 127.0.0.1:853']);
		$this->gatewayAdvertisement('127.0.0.1');
		$row = $this->fixture->status()['rows'][0];
		$this->assertSame('matched', $row['state']);
		$this->assertStringContainsString('DNS Name queries are forwarded', $row['reason']);
		$this->assertSame([], $this->fixture->calls);
	}

	public function testExplicitLoopbackDiagnosticAsksOnlySvcb(): void
	{
		$this->fixture->responses['_dns.resolver.arpa. SVCB'] = PfbDnsDdrStatusTest::response([PfbDnsDdrStatusTest::record('127.0.0.1')],
			additional: ['dns.example.com. 300 IN A 127.0.0.1']);
		$this->assertSame('ok', $this->fixture->probe('127.0.0.1:53', 2.0)['state']);
		$this->assertCount(1, $this->fixture->calls);
		$this->assertContains('_dns.resolver.arpa.', $this->fixture->calls[0]);
		$this->assertContains('SVCB', $this->fixture->calls[0]);
	}

	public function testInvalidRepeatedRootLabelsCannotBeNormalizedIntoTheQuestionOwner(): void
	{
		$reply = PfbDnsDdrStatusTest::response([PfbDnsDdrStatusTest::record()]);
		$this->assertSame('error', pfb_dns_ddr_result(str_replace('_dns.resolver.arpa.', '_dns.resolver.arpa..', $reply), 0)['state']);
	}
}
