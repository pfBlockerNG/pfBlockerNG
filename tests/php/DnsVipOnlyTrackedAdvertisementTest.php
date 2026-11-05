<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Track6's dynamic RA pass may advertise system DNS before an interface has an address. */
final class DnsVipOnlyTrackedAdvertisementTest extends TestCase
{
	public static function trackedScopes(): iterable
	{
		yield 'dynamic-system-DNS' => [['radvd-dns' => 'enabled'], TRUE, TRUE];
		yield 'dynamic-DNS-disabled' => [['radvd-dns' => 'disabled'], TRUE, FALSE];
		yield 'dynamic-RA-disabled' => [['ramode' => 'disabled', 'radvd-dns' => 'enabled'], TRUE, FALSE];
		yield 'no-dynamic-DNS-setting' => [[], TRUE, FALSE];
		yield 'missing-tracked-parent' => [['radvd-dns' => 'enabled'], FALSE, FALSE];
	}

	#[DataProvider('trackedScopes')]
	public function testTrackedAutomaticDnsUsesNativeControlsWithoutInventingAFamilyRequirement(array $settings, bool $parent, bool $conflict): void
	{
		$saved = [];
		foreach (['config', 'pfb_test_interfaces', 'pfb_test_configured_ipv6'] as $key) {
			$saved[$key] = [array_key_exists($key, $GLOBALS), $GLOBALS[$key] ?? NULL];
		}
		try {
			$GLOBALS['config'] = [];
			$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
			$GLOBALS['pfb_test_configured_ipv6'] = [];
			PfbConfig::write('dns/pfb_dns', 'on');
			config_set_path('interfaces/lan', ['enable' => '', 'ipaddrv6' => 'track6', 'track6-interface' => 'wan']);
			if ($parent) {
				config_set_path('interfaces/wan', ['enable' => '', 'ipaddrv6' => 'dhcp6']);
			}
			config_set_path('system/dnsserver', ['2001:db8:99::53']);
			config_set_path('dhcpdv6/lan', $settings);
			$before = serialize($GLOBALS['config']);
			$errors = pfb_validate_dns_listen_vip_only_post(['pfb_dns_listen_vip_only' => 'on', 'pfb_dns_listen_vip' => 'on', 'pfb_dns_listen_vip4' => 'auto', 'pfb_dns_listen_vip6' => 'none']);
			$this->assertSame($before, serialize($GLOBALS['config']));
			if ($conflict) {
				$this->assertStringContainsString('RA', implode(' ', $errors), 'native dynamic RA advertises IPv6 system DNS even before a prefix is assigned');
				$this->assertStringContainsString('lan', implode(' ', $errors));
			} else {
				$this->assertSame([], $errors, 'native silent dynamic RA must not force an unnecessary second VIP family');
			}
		} finally {
			foreach ($saved as $key => [$exists, $value]) {
				if ($exists) {
					$GLOBALS[$key] = $value;
				} else {
					unset($GLOBALS[$key]);
				}
			}
		}
	}
}
