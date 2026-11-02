<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfblockerng_do_xmlrpc_sync')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_send')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv')]
#[CoversFunction('pfb_run_migrations')]
#[CoversFunction('pfb_dns_proxy_seed_values')]
final class SyncDnsSettingsTest extends TestCase
{
	private const LOCAL = 'installedpackages/pfblockerngdns/config/0';
	private const SHARED = 'installedpackages/pfblockerngdnssettings/config/0';
	private const VALUES = [
		'pfb_dns_dot' => '', 'pfb_dns_doh' => 'on', 'pfb_dns_doq' => 'off',
		'pfb_dns_dot_port' => '8853', 'pfb_dns_doh_port' => '443', 'pfb_dns_doq_port' => '8854',
		'pfb_dns_doh_trusted' => '192.0.2.20/32', 'pfb_dns_ddr' => 'on', 'pfb_dns_ddr_doh_443' => '',
	];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_xmlrpc_calls'] = [];
		@mkdir($GLOBALS['pfb']['dbdir'], 0777, TRUE);
	}

	/** @return array<string,string> */
	private static function local(string $toggle): array
	{
		return ['pfb_dns' => $toggle, 'pfb_dns_saved' => 'B-SNAPSHOT', 'pfb_dns_interface' => 'opt2',
			'pfb_dns_dot_interface' => 'opt3', 'pfb_dns_doh_interface' => '192.0.2.2',
			'pfb_dns_doq_interface' => '192.0.2.3', 'pfb_dns_sslcertref' => 'B-CERT'];
	}

	public function testMigrationPreservesAllRawValuesAndIsIdempotent(): void
	{
		$values = ['pfb_dns_dot' => FALSE, 'pfb_dns_doh_trusted' => ''] + self::VALUES;
		config_set_path(self::LOCAL, self::local('on') + $values);
		pfb_run_migrations();
		$this->assertSame($values, PfbConfig::readSection(self::SHARED));
		$this->assertSame(self::local('on'), PfbConfig::readSection(self::LOCAL));
		$before = $GLOBALS['config'];
		$writes = $GLOBALS['pfb_test_write_config_calls'];
		pfb_run_migrations();
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame($writes, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testReceivedExplicitValuesWinOverStaleOldKeys(): void
	{
		config_set_path(self::LOCAL, self::local('') + self::VALUES);
		$received = ['pfb_dns_dot' => '', 'pfb_dns_doh' => FALSE, 'pfb_dns_dot_port' => ''];
		config_set_path(self::SHARED, $received);
		pfb_run_migrations();
		$this->assertSame($received + self::VALUES, PfbConfig::readSection(self::SHARED));
		$this->assertSame(self::local(''), PfbConfig::readSection(self::LOCAL));
	}

	/** @return iterable<string,array{string,string}> */
	public static function transports(): iterable
	{
		foreach (['manual', 'auto'] as $transport) {
			foreach (['on', ''] as $toggle) {
				yield $transport . '-' . ($toggle ?: 'off') => [$transport, $toggle];
			}
		}
	}

	#[DataProvider('transports')]
	public function testLegacyAllTransfersOnlySharedSettingsWithoutEnablingOrDisablingReceiver(string $transport, string $toggle): void
	{
		config_set_path(self::LOCAL, self::local($toggle === 'on' ? '' : 'on') + self::VALUES);
		pfb_run_migrations();
		config_set_path(PFB_SECTIONS['sync'], ['syncscope' => 'all', 'varsynconchanges' => $transport]);
		if ($transport === 'manual') {
			pfblockerng_do_xmlrpc_sync('192.0.2.2', '443', 'https', 'admin', 'password', 5);
			$this->assertCount(1, $GLOBALS['pfb_test_xmlrpc_calls']);
			[$method, $payload] = $GLOBALS['pfb_test_xmlrpc_calls'][0];
			$this->assertSame('merge_installedpackages_section', $method);
		} else {
			$payload = [];
			foreach (pfblockerng_plugin_xmlrpc_send() as $path) {
				array_set_path($payload, $path, array_get_path($GLOBALS['config'], $path, []));
			}
			$payload = $payload['installedpackages'];
		}
		$this->assertSame(self::VALUES, $payload['pfblockerngdnssettings']['config'][0] ?? NULL);
		$this->assertArrayNotHasKey('pfblockerngdns', $payload);
		// B already owns a moved Resolver and its snapshot, or has explicitly disabled pfB-DNS.
		$GLOBALS['config'] = ['unbound' => ['active_interface' => 'lo0', 'custom_options' => 'B-MOVED']];
		config_set_path(self::LOCAL, self::local($toggle));
		config_set_path(self::SHARED, ['pfb_dns_doh_port' => '4443']);
		$unbound = $GLOBALS['config']['unbound'];
		if ($transport === 'manual') {
			// Core xmlrpc.php merge_installedpackages_section replaces sent sections, without package hooks.
			config_set_path('installedpackages', array_merge(config_get_path('installedpackages'), $payload));
		} else {
			foreach (pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $payload]) as $path => $value) {
				if ($path !== 'xmlrpc_recv_result') {
					config_set_path($path, $value);
				}
			}
		}
		$this->assertSame(self::local($toggle), PfbConfig::readSection(self::LOCAL));
		$this->assertSame($unbound, $GLOBALS['config']['unbound']);
		$this->assertSame(self::VALUES, PfbConfig::readSection(self::SHARED));
		$this->assertSame('443', PfbConfig::read('dns_shared/pfb_dns_doh_port'));
	}

	public function testPolicyAndListsLeavePfBDnsUntouched(): void
	{
		config_set_path(self::LOCAL, self::local('on') + self::VALUES);
		pfb_run_migrations();
		foreach (['policy', 'lists'] as $scope) {
			config_set_path(PFB_SECTIONS['sync'], ['syncscope' => $scope, 'varsynconchanges' => 'manual']);
			$GLOBALS['pfb_test_xmlrpc_calls'] = [];
			pfblockerng_do_xmlrpc_sync('192.0.2.2', '443', 'https', 'admin', 'password', 5);
			$payload = $GLOBALS['pfb_test_xmlrpc_calls'][0][1];
			$this->assertArrayNotHasKey('pfblockerngdnssettings', $payload['installedpackages'] ?? $payload);
			$this->assertStringNotContainsString('B-SNAPSHOT', serialize($payload));
			config_set_path(PFB_SECTIONS['sync'] . '/varsynconchanges', 'auto');
			foreach (pfblockerng_plugin_xmlrpc_send() as $path) {
				$this->assertStringNotContainsString('pfblockerngdnssettings', $path);
				$this->assertStringNotContainsString('pfblockerngdns/config', $path);
			}
		}
	}

	public function testUnseededReceiverKeepsExplicitSharedDotSettings(): void
	{
		config_set_path('unbound', ['active_interface' => 'lan', 'enablessl' => '', 'tlsport' => '853']);
		config_set_path(self::SHARED, ['pfb_dns_dot' => '', 'pfb_dns_dot_port' => '8853']);
		pfb_dns_proxy_seed();
		$this->assertSame('', PfbConfig::readSection(self::SHARED)['pfb_dns_dot']);
		$this->assertSame('8853', pfb_dns_proxy_setting('pfb_dns_dot_port'));
		$this->assertSame(PfbToggle::Off, pfb_dns_proxy_setting('pfb_dns_dot'));
		$this->assertSame('lan', PfbConfig::read('dns/pfb_dns_interface'));
	}
}
