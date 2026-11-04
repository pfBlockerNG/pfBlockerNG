<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_proxy_interface_options')]
#[CoversFunction('pfb_validate_dns_proxy_listeners_post')]
final class DnsProxySettingsPolicyRegressionTest extends TestCase
{
	private const LISTS = ['pfb_dns_interface', 'pfb_dns_dot_interface', 'pfb_dns_doh_interface', 'pfb_dns_doq_interface'];
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['config', 'pfb_test_interfaces', 'pfb_test_vip_list', '_POST'] as $key) {
			$this->saved[$key] = [array_key_exists($key, $GLOBALS), $GLOBALS[$key] ?? NULL];
		}
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $key => [$exists, $value]) {
			if ($exists) {
				$GLOBALS[$key] = $value;
			} else {
				unset($GLOBALS[$key]);
			}
		}
	}

	/** @return array<string,array{bool}> */
	public static function availability(): array
	{
		return ['native options' => [TRUE], 'inactive saved recovery' => [FALSE]];
	}

	#[DataProvider('availability')]
	public function testOwnedVipsAreNeverOfferedButManualAndUnknownTokensSurvive(bool $active): void
	{
		$rows = [
			['uniqid' => 'sink4', 'subnet' => '192.0.2.2', 'descr' => 'pfB_AUTO_VIP_v4'],
			['uniqid' => 'sink6', 'subnet' => '2001:db8::2', 'descr' => 'pfB_AUTO_VIP_v6'],
			['uniqid' => 'dns4', 'subnet' => '192.0.2.3', 'descr' => 'pfB_DNS_LISTEN_VIP_v4'],
			['uniqid' => 'dns6', 'subnet' => '2001:db8::3', 'descr' => 'pfB_DNS_LISTEN_VIP_v6'],
			['uniqid' => 'nat', 'subnet' => '192.0.2.4', 'descr' => PFB_MANAGED_NAT_DESCR],
			['uniqid' => 'manual', 'subnet' => '192.0.2.5', 'descr' => 'Manual Resolver VIP'],
			['uniqid' => 'other', 'subnet' => '2001:db8::5', 'descr' => 'Other package'],
		];
		$native = [];
		foreach ($rows as $row) {
			$native['_vip' . $row['uniqid']] = $row['subnet'];
		}
		$stored = 'all,lo0,lan,optgone,_vipgone,' . implode(',', array_keys($native));
		$GLOBALS['config'] = [
			'virtualip' => ['vip' => $rows],
			'installedpackages' => ['pfblockerngdns' => ['config' => [array_fill_keys(self::LISTS, $stored)]]],
		];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$GLOBALS['pfb_test_vip_list'] = $active ? $native : [];
		$before = $GLOBALS['config'];

		$options = pfb_dns_proxy_interface_options();

		foreach (['sink4', 'sink6', 'dns4', 'dns6', 'nat'] as $id) {
			$this->assertArrayNotHasKey('_vip' . $id, $options, json_encode($options));
		}
		foreach (['all', 'lo0', 'lan', 'optgone', '_vipgone', '_vipmanual', '_vipother'] as $token) {
			$this->assertArrayHasKey($token, $options, json_encode($options));
		}
		$this->assertSame($active ? '192.0.2.5' : '_vipmanual (not currently available)', $options['_vipmanual']);
		$this->assertSame($before, $GLOBALS['config'], 'building choices must not migrate or reset stored selections');
	}

	/** @return array<string,array{string}> */
	public static function namedServices(): array
	{
		return ['DoT' => ['dot'], 'DoH' => ['doh'], 'DoQ' => ['doq'], 'DDR' => ['ddr']];
	}

	private static function post(): array
	{
		return array_fill_keys(self::LISTS, ['lo0']) + [
			'pfb_dns' => 'on', 'pfb_dns_name' => '', 'pfb_dns_sslcertref' => 'cert',
			'pfb_dns_dot_port' => '853', 'pfb_dns_doh_port' => '4443', 'pfb_dns_doq_port' => '853',
		];
	}

	#[DataProvider('namedServices')]
	public function testAnActiveNamedServiceRejectsEmptyNameButDisableIsSaveable(string $kind): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
		$page = 'src/usr/local/www/pfblockerng/pfblockerng_dns.php';
		$code = pfb_test_page_region($page, '$pfb_dns = pfb_filter(', '// issue #3515:');
		$_POST = self::post() + ['pfb_dns_' . $kind => 'on'];
		$vars = ['input_errors' => [], 'options_dns_interface' => ['lo0' => 'Localhost'], 'options_dns_cert' => ['cert' => 'Certificate']];
		$before = $GLOBALS['config'];
		$errors = pfb_test_page_eval($code, $vars)['input_errors'];
		$this->assertCount(1, $errors, json_encode($errors));
		$this->assertStringContainsString('Name', $errors[0], 'the error identifies the missing field');
		$this->assertSame($before, $GLOBALS['config'], 'rejection must not change config');

		unset($_POST['pfb_dns']);
		$scope = pfb_test_page_eval($code, $vars);
		$this->assertSame([], $scope['input_errors'], 'an unchecked pfB-DNS must be saveable with stale service toggles');
		$this->assertSame('', $scope['pfb_dns']);

		$_POST['pfb_dns'] = 'on';
		$_POST['pfb_dns_name'] = 'fw.example.lan';
		$this->assertSame([], pfb_test_page_eval($code, $vars)['input_errors'], 'a valid Name accepts each enabled service');
	}

	public function testPlainOnlyAcceptsAnEmptyName(): void
	{
		$this->assertSame([], pfb_validate_dns_proxy_listeners_post(self::post(), ['lo0'], ['cert']));
	}
}
