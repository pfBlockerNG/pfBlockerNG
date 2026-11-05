<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** A missing VIP family must not leave clients with ordinary or automatic DNS advertisements. */
final class DnsVipOnlyAdvertisementFamiliesTest extends TestCase
{
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['config', 'pfb', 'pfb_test_interfaces', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_vip_list', 'pfb_test_configured_subnets', 'pfb_test_write_config_calls', 'pfb_test_dhcpd_configure_calls', 'pfb_test_unbound_configure_calls'] as $key) {
			$this->saved[$key] = [array_key_exists($key, $GLOBALS), $GLOBALS[$key] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1'];
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		PfbConfig::write('dns/pfb_dns', 'on');
		PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
		config_set_path('interfaces/lan', ['enable' => '', 'ipaddr' => '192.0.2.1', 'subnet' => '24', 'ipaddrv6' => '2001:db8::1', 'subnetv6' => '64']);
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

	private function post(int $selected): array
	{
		return ['pfb_dns_listen_vip_only' => 'on', 'pfb_dns_listen_vip' => 'on',
			'pfb_dns_listen_vip4' => $selected === 6 ? 'none' : '_vipv4',
			'pfb_dns_listen_vip6' => $selected === 4 ? 'none' : '_vipv6'];
	}

	public static function configuredScopes(): iterable
	{
		foreach ([['dhcpd', 'dnsserver', 'DHCPv4', 6, '192.0.2.1', '203.0.113.53'],
			['dhcpdv6', 'dnsserver', 'DHCPv6', 4, '2001:db8::1', '2001:db8:99::53'],
			['dhcpdv6', 'radnsserver', 'RA', 4, '2001:db8::1', '2001:db8:99::53']] as [$section, $list, $type, $selected, $own, $foreign]) {
			foreach (['foreign' => $foreign, 'own' => $own, 'recorded' => $own, 'frozen' => $foreign] as $kind => $server) {
				yield "{$type}-{$kind}" => [$section, $list, $type, $selected, $kind, $server];
			}
		}
	}

	#[DataProvider('configuredScopes')]
	public function testUnselectedConfiguredScopesRejectWithoutAnyWrites(string $section, string $list, string $type, int $selected, string $kind, string $server): void
	{
		$interface = $kind === 'frozen' ? 'unknown' : 'lan';
		$path = "{$section}/{$interface}/{$list}";
		config_set_path($path, [$server]);
		if ($kind === 'recorded') {
			PfbConfig::write('gen/pfb_dns_listen_added', json_encode([$path => [$server]]));
		}
		$before = serialize($GLOBALS['config']);
		$errors = implode(' ', pfb_validate_dns_listen_vip_only_post($this->post($selected)));
		$this->assertSame($before, serialize($GLOBALS['config']), 'rejected activation must preserve the whole config byte-identically');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertStringContainsString($type, $errors, "unselected {$type} {$kind} list must block activation");
		$this->assertStringContainsString($interface, $errors);
		$this->assertSame([], pfb_validate_dns_listen_vip_only_post(['pfb_dns_listen_vip_only' => '']), 'disable never depends on advertisements');
	}

	public static function automaticScopes(): iterable
	{
		yield 'DHCPv4-own' => [6, 'dhcpd', ['enable' => ''], 'DHCPv4', TRUE, []];
		yield 'DHCPv4-system' => [6, 'dhcpd', ['enable' => ''], 'DHCPv4', FALSE, ['203.0.113.53']];
		yield 'DHCPv6-own' => [4, 'dhcpdv6', ['enable' => '', 'ramode' => 'disabled'], 'DHCPv6', TRUE, []];
		yield 'DHCPv6-system' => [4, 'dhcpdv6', ['enable' => '', 'ramode' => 'disabled'], 'DHCPv6', FALSE, ['2001:db8:99::53']];
		yield 'RA-absent-independent' => [4, 'dhcpdv6', ['ramode' => 'unmanaged'], 'RA', TRUE, []];
		yield 'RA-shared-empty' => [4, 'dhcpdv6', ['ramode' => 'unmanaged', 'rasamednsasdhcp6' => '', 'dnsserver' => []], 'RA', TRUE, []];
		yield 'RA-system' => [4, 'dhcpdv6', ['ramode' => 'unmanaged'], 'RA', FALSE, ['2001:db8:99::53']];
		yield 'RA-legacy-mode' => [4, 'dhcpdv6', ['mode' => 'unmanaged'], 'RA', TRUE, []];
	}

	#[DataProvider('automaticScopes')]
	public function testActiveAutomaticDnsRequiresTheMissingVipFamily(int $selected, string $section, array $settings, string $type, bool $resolver, array $system): void
	{
		config_set_path("{$section}/lan", $settings);
		config_set_path('unbound', $resolver ? ['enable' => ''] : []);
		config_set_path('system/dnsserver', $system);
		$before = serialize($GLOBALS['config']);
		$errors = implode(' ', pfb_validate_dns_listen_vip_only_post($this->post($selected)));
		$this->assertSame($before, serialize($GLOBALS['config']));
		$this->assertStringContainsString($type, $errors, 'an empty stored list is not proof that core advertises no DNS');
		$this->assertStringContainsString('lan', $errors);
		$this->assertStringContainsString('IPv' . ($selected === 4 ? 6 : 4), $errors, 'instruction must identify the missing Resolver VIP family');
	}

	public static function silentScopes(): iterable
	{
		yield 'v4-disabled' => [6, 'dhcpd', ['dnsserver' => []], TRUE];
		yield 'v4-no-dns-provider' => [6, 'dhcpd', ['enable' => '', 'dnsserver' => []], FALSE];
		yield 'v6-disabled' => [4, 'dhcpdv6', ['ramode' => 'disabled', 'dnsserver' => []], TRUE];
		yield 'v6-native-dns-controls' => [4, 'dhcpdv6', ['enable' => '', 'dhcp6c-dns' => 'disabled', 'ramode' => 'unmanaged', 'radvd-dns' => 'disabled'], TRUE];
		yield 'ra-explicit-independent-empty' => [4, 'dhcpdv6', ['ramode' => 'unmanaged', 'radnsserver' => []], TRUE];
		yield 'shared-ignores-unused-override' => [4, 'dhcpdv6', ['ramode' => 'disabled', 'rasamednsasdhcp6' => '', 'dnsserver' => [], 'radnsserver' => ['2001:db8:99::53']], TRUE];
	}

	#[DataProvider('silentScopes')]
	public function testSingleFamilyRemainsUsableWithoutOtherFamilyDns(int $selected, string $section, array $settings, bool $resolver): void
	{
		config_set_path("{$section}/lan", $settings);
		config_set_path('unbound', $resolver ? ['enable' => ''] : []);
		$before = serialize($GLOBALS['config']);
		$this->assertSame([], pfb_validate_dns_listen_vip_only_post($this->post($selected)));
		$this->assertSame($before, serialize($GLOBALS['config']));
	}

	public function testDualFamilyOwnListsStillBecomeVipsAndLaterUnselectedEditsArePreserved(): void
	{
		config_set_path('dhcpd/lan/dnsserver', ['192.0.2.1']);
		config_set_path('dhcpdv6/lan', ['dnsserver' => ['2001:db8::1'], 'radnsserver' => ['2001:db8::1']]);
		$this->assertSame([], pfb_validate_dns_listen_vip_only_post($this->post(0)));
		PfbConfig::write('gen/pfb_dns_listen_vip_only', 'on');
		PfbConfig::write('gen/pfb_dns_listen_vip4', '_vipv4');
		PfbConfig::write('gen/pfb_dns_listen_vip6', '_vipv6');
		pfb_dns_listen_vips_apply();
		$this->assertSame(['172.16.53.53'], config_get_path('dhcpd/lan/dnsserver'));
		$this->assertSame(['fd00:53::53'], config_get_path('dhcpdv6/lan/dnsserver'));
		$this->assertSame(['fd00:53::53'], config_get_path('dhcpdv6/lan/radnsserver'));
		PfbConfig::write('gen/pfb_dns_listen_vip6', '');
		$before = serialize(config_get_path('dhcpdv6'));
		$owned = json_decode((string) PfbConfig::read('gen/pfb_dns_listen_added'), TRUE);
		pfb_dns_listen_vips_apply();
		$this->assertSame($before, serialize(config_get_path('dhcpdv6')), 'later removal of a VIP family must warn rather than clobber existing DNS data');
		$after = json_decode((string) PfbConfig::read('gen/pfb_dns_listen_added'), TRUE);
		$this->assertSame($owned['dhcpdv6/lan/dnsserver'], $after['dhcpdv6/lan/dnsserver'] ?? NULL);
		$this->assertStringContainsString('DHCPv6', implode(' ', pfb_dns_listen_foreign_warnings()));
		PfbConfig::write('dns/pfb_dns', '');
		$this->assertFalse(pfb_dns_listen_vip_only(), 'disabling pfB-DNS remains possible');
	}
}
