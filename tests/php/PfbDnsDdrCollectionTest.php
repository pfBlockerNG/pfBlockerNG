<?php

declare(strict_types=1);

require_once __DIR__ . '/support/LiveListenerStandIn.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_ddr_status')]
#[CoversFunction('pfb_dns_ddr_probe')]
final class PfbDnsDdrCollectionTest extends TestCase
{
	use LiveListenerStandIn;

	private const GLOBALS = ['pfb', 'config', 'pfb_test_valid_pids', 'pfb_test_interfaces', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6'];
	private array $saved = [];
	private string $dir;

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $key) {
			$this->saved[$key] = [array_key_exists($key, $GLOBALS), $GLOBALS[$key] ?? NULL];
			unset($GLOBALS[$key]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_ddr_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['pfb'] = [
			'dns_proxy_pidfile' => "{$this->dir}/pid", 'dns_proxy_ready' => "{$this->dir}/ready",
			'dns_proxy_ctl' => "{$this->dir}/ctl.sock",
		];
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN <guest>', 'lo0' => 'Localhost'];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1'];
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

	private function ready(): void
	{
		file_put_contents($GLOBALS['pfb']['dns_proxy_pidfile'], "4242\n");
		file_put_contents($GLOBALS['pfb']['dns_proxy_ready'], "4242\n");
		$GLOBALS['pfb_test_valid_pids'][$GLOBALS['pfb']['dns_proxy_pidfile']] = TRUE;
	}

	/** The applied snapshot the projection reads: the fields pfb_dns_proxy_applied_status() returns, as the arrays it returns them. */
	private static function applied(array $listeners, array $advertisements): array
	{
		return ['ddr' => TRUE, 'listeners' => $listeners, 'name_answers' => [], 'advertisements' => $advertisements];
	}

	public function testOnlyBoundPlainAddressesAreAppliedWithTheirRealAddressIdentity(): void
	{
		config_set_path('virtualip/vip', [
			['subnet' => '192.0.2.53', 'interface' => 'lo0', 'descr' => 'pfB_DNS_LISTEN_VIP_v4'],
			['subnet' => '2001:db8::53', 'interface' => 'lo0', 'descr' => 'pfB_DNS_LISTEN_VIP_v6'],
			['subnet' => '192.0.2.54', 'interface' => 'lan', 'descr' => 'Admin <VIP>'],
		]);
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_interface', 'wan');
		$status = pfb_dns_ddr_status(self::applied([
			['kind' => 'udp+tcp', 'address' => '192.0.2.1:5353', 'state' => 'listening', 'reason' => ''],
			['kind' => 'udp+tcp', 'address' => '[2001:db8::1]:5354', 'state' => 'listening', 'reason' => ''],
			['kind' => 'udp+tcp', 'address' => '192.0.2.53:53', 'state' => 'listening', 'reason' => ''],
			['kind' => 'udp+tcp', 'address' => '[2001:db8::53]:53', 'state' => 'listening', 'reason' => ''],
			['kind' => 'udp+tcp', 'address' => '192.0.2.54:1053', 'state' => 'listening', 'reason' => ''],
			['kind' => 'udp+tcp', 'address' => '192.0.2.56:53', 'state' => 'refused', 'reason' => 'bind refused'],
			['kind' => 'doh', 'address' => '192.0.2.55:443', 'state' => 'listening', 'reason' => ''],
		], array_fill_keys(['192.0.2.1', '2001:db8::1', '192.0.2.53', '2001:db8::53', '192.0.2.54'], ['records' => [], 'additional' => []])));

		$this->assertSame('', $status['notice']);
		$this->assertMatchesRegularExpression('/\A\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC\z/', (string) $status['queried']);
		$this->assertSame([
			['LAN <guest>', 'Interface', '192.0.2.1:5353'],
			['LAN <guest>', 'Interface', '[2001:db8::1]:5354'],
			['Localhost', 'Managed Resolver VIP', '192.0.2.53:53'],
			['Localhost', 'Managed Resolver VIP', '[2001:db8::53]:53'],
			['LAN <guest>', 'Manual VIP: Admin <VIP>', '192.0.2.54:1053'],
		], array_map(static fn (array $row): array => [$row['interface'], $row['identity'], $row['address']], $status['rows']));
		foreach ($status['rows'] as $row) {
			$this->assertSame('no_transport', $row['state']);
			$this->assertArrayNotHasKey('stdout', $row);
			$this->assertArrayNotHasKey('stderr', $row);
			$this->assertArrayNotHasKey('name', $row);
			$this->assertArrayHasKey('reason', $row);
		}
	}

	public function testAVipWhoseSubnetIsIpv4MappedIsTheVipOfTheIpv4AddressTheGatewayServes(): void
	{
		// Given a manual VIP on lan whose subnet is spelled ::ffff:192.0.2.9, and a gateway row for the address it is: 192.0.2.9
		config_set_path('virtualip/vip', [['subnet' => '::ffff:192.0.2.9', 'interface' => 'lan', 'descr' => 'Admin <VIP>']]);

		// When the applied DDR table is built
		$status = pfb_dns_ddr_status(self::applied(
			[['kind' => 'udp+tcp', 'address' => '192.0.2.9:53', 'state' => 'listening', 'reason' => '']],
			['192.0.2.9' => ['records' => [], 'additional' => []]]
		));

		// Then the row has the VIP's identity and lan's description, not the bare address of an interface (issue #3849)
		$this->assertSame(
			[['LAN <guest>', 'Manual VIP: Admin <VIP>', '192.0.2.9:53']],
			array_map(static fn (array $row): array => [$row['interface'], $row['identity'], $row['address']], $status['rows'])
		);
	}

	public function testAnIpAliasOnACarpVipShowsTheInterfaceOfTheCarpVipNotItsInternalId(): void
	{
		// Given a CARP VIP on lan, and an IP alias on it that pfSense stores as `_vip<uniqid>`, which the gateway serves
		$this->ready();
		config_set_path('virtualip/vip', [
			['mode' => 'carp', 'interface' => 'lan', 'uniqid' => 'carp1', 'subnet' => '192.0.2.50', 'descr' => 'Carp'],
			['mode' => 'ipalias', 'interface' => '_vipcarp1', 'uniqid' => 'alias1', 'subnet' => '192.0.2.60', 'descr' => 'Alias'],
		]);
		$this->gatewayServes(['udp+tcp 192.0.2.60:53'], []);

		// Then its row names lan's description
		$this->assertSame(
			[['LAN <guest>', 'Manual VIP: Alias', '192.0.2.60:53']],
			array_map(static fn (array $row): array => [$row['interface'], $row['identity'], $row['address']], pfb_dns_ddr_status()['rows'])
		);
	}

	public function testStoppedServiceDoesNotTurnIntoAnEmptySuccessfulQuery(): void
	{
		$status = pfb_dns_ddr_status();
		$this->assertStringContainsString('Applied pfB-DNS status unavailable', $status['notice']);
		$this->assertSame([], $status['rows']);
		$this->assertNull($status['queried']);
	}

	public function testUnavailableControlListDoesNotInferTargetsFromPendingSettings(): void
	{
		$this->ready();
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_interface', 'lan');
		$status = pfb_dns_ddr_status();
		$this->assertStringContainsString('Applied pfB-DNS status unavailable', $status['notice']);
		$this->assertSame([], $status['rows']);
		$this->assertNull($status['queried']);
	}

	public function testKnownEmptyControlListIsNotTheUnknownControlList(): void
	{
		$this->ready();
		$this->gatewayServes([]);
		$status = pfb_dns_ddr_status();
		$this->assertStringContainsString('no bound plain DNS listeners', $status['notice']);
		$this->assertStringNotContainsString('unavailable', $status['notice']);
		$this->assertSame([], $status['rows']);
	}

	public function testExhaustedProbeBudgetsNeverLaunchAQuery(): void
	{
		foreach (['192.0.2.1:5353', '[2001:db8::1]:5354'] as $listener) {
			$this->assertSame('budget', pfb_dns_ddr_probe($listener, 0.0)['state']);
		}
	}
}
