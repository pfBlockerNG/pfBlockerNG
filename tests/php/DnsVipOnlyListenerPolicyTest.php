<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** VIP-only owns listener/Name policy, not certification of administrator DHCP/RA overrides. */
final class DnsVipOnlyListenerPolicyTest extends TestCase
{
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['config', 'pfb', 'pfb_test_interfaces', 'pfb_test_interface_info', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_vip_list', 'pfb_test_configured_subnets', 'pfb_test_write_config_calls', 'pfb_test_write_config_args', 'pfb_test_dhcpd_configure_calls', 'pfb_test_unbound_configure_calls'] as $key) {
			$this->saved[$key] = [array_key_exists($key, $GLOBALS), $GLOBALS[$key] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1'];
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_write_config_args'] = [];
		PfbConfig::write('dns/pfb_dns', 'on');
		PfbConfig::write('dns/pfb_dns_interface', 'lan');
		PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
		config_set_path('interfaces/lan', ['enable' => '', 'ipaddr' => '192.0.2.1', 'subnet' => '24', 'ipaddrv6' => '2001:db8::1', 'subnetv6' => '64']);
		config_set_path('unbound/enable', '');
		config_set_path('virtualip/vip', [
			['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => '172.16.53.53', 'subnet_bits' => '32', 'descr' => 'operator', 'uniqid' => 'v4'],
			['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => 'fd00:53::53', 'subnet_bits' => '128', 'descr' => 'operator', 'uniqid' => 'v6'],
		]);
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

	private function post(array $families): array
	{
		return ['pfb_dns_listen_vip_only' => 'on', 'pfb_dns_listen_vip' => 'on',
			'pfb_dns_listen_vip4' => in_array(4, $families, TRUE) ? '_vipv4' : 'none',
			'pfb_dns_listen_vip6' => in_array(6, $families, TRUE) ? '_vipv6' : 'none'];
	}

	public static function advertisements(): iterable
	{
		foreach (['v4' => [[4], ['172.16.53.53']], 'v6' => [[6], ['fd00:53::53']], 'dual' => [[4, 6], ['172.16.53.53', 'fd00:53::53']]] as $mode => [$families, $pair]) {
			foreach ([['dhcpd', 'dnsserver', '203.0.113.53'], ['dhcpdv6', 'dnsserver', '2001:db8:99::53'], ['dhcpdv6', 'radnsserver', '2001:db8:99::53']] as [$section, $list, $server]) {
				foreach ([FALSE, TRUE] as $active) {
					foreach (['lan', 'unknown'] as $interface) {
						yield "{$mode}-{$section}-{$list}-" . ($active ? 'active' : 'dormant') . "-{$interface}" => [$families, $pair, $section, $list, $server, $active, $interface];
					}
				}
			}
		}
	}

	#[DataProvider('advertisements')]
	public function testAdministratorAdvertisementsDoNotBlockOrMutateListenerPolicy(array $families, array $pair, string $section, string $list, string $server, bool $active, string $interface): void
	{
		$custom = base64_encode('{"option-data":[{"code":6,"data":"203.0.113.54"}]}');
		$settings = [$list => [$server], 'ramode' => $active ? 'unmanaged' : 'disabled',
			'pool' => [['dnsserver' => [$server], 'custom_kea_config' => $custom]],
			'staticmap' => [['dnsserver' => [$server], 'custom_kea_config' => $custom]],
			'numberoptions' => ['item' => [['number' => '6', 'type' => 'ip-address', 'value' => base64_encode($server)]]],
			'custom_kea_config' => $custom];
		if ($active) {
			$settings['enable'] = '';
		}
		config_set_path("{$section}/{$interface}", $settings);
		config_set_path('kea/custom_kea_config', $custom);
		config_set_path('kea6/custom_kea_config', base64_encode('{"option-data":[{"code":23,"data":"2001:db8:99::54"}]}'));
		$before = serialize($GLOBALS['config']);
		$errors = pfb_validate_dns_listen_vip_only_post($this->post($families));
		$this->assertSame($before, serialize($GLOBALS['config']), 'validation must leave every administrator object byte-identical');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'validation must not save or normalize core config');
		$this->assertSame([], $errors, 'listener-only activation must not certify or reject DHCP/RA advertisements');

		$post = $this->post($families);
		PfbConfig::write('gen/pfb_dns_listen_vip_only', 'on');
		PfbConfig::write('gen/pfb_dns_listen_vip4', $post['pfb_dns_listen_vip4'] === 'none' ? '' : $post['pfb_dns_listen_vip4']);
		PfbConfig::write('gen/pfb_dns_listen_vip6', $post['pfb_dns_listen_vip6'] === 'none' ? '' : $post['pfb_dns_listen_vip6']);
		foreach (['plain', 'dot', 'doh', 'doq'] as $kind) {
			$this->assertSame($pair, pfb_dns_proxy_interface_addresses(['lan'], pfb_dns_proxy_vip_only_families($kind)), "{$kind} must not reopen ordinary listeners for administrator DNS advertisements");
		}
		$this->assertSame($pair, pfb_dns_proxy_listen());
		$this->assertSame(array_fill_keys([...$pair, '127.0.0.1', '::1'], $pair), pfb_dns_proxy_name_answers(), 'Name ownership stays VIP-only, including firewall loopback');
	}

	public function testBasicPrerequisitesRemainAndAutomaticSelectionDoesNotNeedAnExistingVip(): void
	{
		$post = $this->post([4]);
		$this->assertSame([], pfb_validate_dns_listen_vip_only_post($post));
		PfbConfig::write('dns/pfb_dns', '');
		$this->assertNotEmpty(pfb_validate_dns_listen_vip_only_post($post));
		$this->assertSame([], pfb_validate_dns_listen_vip_only_post(['pfb_dns_listen_vip_only' => '']), 'disable stays unconditional');
		PfbConfig::write('dns/pfb_dns', 'on');
		$this->assertNotEmpty(pfb_validate_dns_listen_vip_only_post(array_replace($post, ['pfb_dns_listen_vip' => ''])));
		$this->assertNotEmpty(pfb_validate_dns_listen_vip_only_post($this->post([])));
		$this->assertNotEmpty(pfb_validate_dns_listen_vip_only_post(array_replace($post, ['pfb_dns_listen_vip4' => '_vipmissing'])));
		$this->assertNotEmpty(pfb_validate_dns_listen_vip_only_post(array_replace($post, ['pfb_dns_listen_vip4' => ['auto']])));
		config_set_path('virtualip/vip', []);
		$before = serialize($GLOBALS['config']);
		$this->assertSame([], pfb_validate_dns_listen_vip_only_post(array_replace($post, ['pfb_dns_listen_vip4' => 'auto'])));
		$this->assertSame($before, serialize($GLOBALS['config']), 'prospective automatic selection must not create VIPs during validation');
	}

	public function testApplyStillPreservesSelectedForeignFrozenListsAndTheirOwnershipRecords(): void
	{
		PfbConfig::write('gen/pfb_dns_listen_vip_only', 'on');
		PfbConfig::write('gen/pfb_dns_listen_vip4', '_vipv4');
		PfbConfig::write('gen/pfb_dns_listen_vip6', '_vipv6');
		$lists = ['dhcpd/lan/dnsserver' => ['203.0.113.53', '172.16.53.53'],
			'dhcpdv6/unknown/dnsserver' => ['2001:db8:99::53', 'fd00:53::53']];
		$records = ['dhcpd/lan/dnsserver' => ['172.16.53.53'], 'dhcpdv6/unknown/dnsserver' => ['fd00:53::53']];
		foreach ($lists as $path => $servers) {
			config_set_path($path, $servers);
		}
		PfbConfig::write('gen/pfb_dns_listen_added', json_encode($records));
		pfb_dns_listen_vips_apply();
		foreach ($lists as $path => $servers) {
			$this->assertSame($servers, config_get_path($path), 'activation permission does not transfer ownership of administrator lists');
		}
		$after = json_decode((string) PfbConfig::read('gen/pfb_dns_listen_added'), TRUE);
		foreach ($records as $path => $servers) {
			$this->assertSame($servers, $after[$path] ?? NULL, 'foreign/frozen ownership bookkeeping must not be dropped');
		}
	}
}
