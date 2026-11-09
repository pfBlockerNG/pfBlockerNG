<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyTransportTest.php';

#[CoversFunction('pfblockerng_do_xmlrpc_sync')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_send')]
final class SyncDnsMixedVersionTest extends TestCase
{
	/** @return iterable<string,array{string,string}> */
	public static function peers(): iterable
	{
		foreach (['manual', 'auto'] as $transport) {
			foreach (['on', ''] as $toggle) {
				yield $transport . '-' . ($toggle ?: 'off') => [$transport, $toggle];
			}
		}
	}

	#[DataProvider('peers')]
	public function testOlderPeerNeverStoresAnotherNodesEnableStateOrReceivesItsSnapshot(string $transport, string $toggle): void
	{
		$localPath = 'installedpackages/pfblockerngdns/config/0';
		$sharedPath = 'installedpackages/pfblockerngdnssettings/config/0';
		$local = ['pfb_dns' => $toggle, 'pfb_dns_saved' => 'B-SNAPSHOT', 'pfb_dns_interface' => 'opt2',
			'pfb_dns_dot' => '', 'pfb_dns_dot_port' => '853', 'pfb_dns_sslcertref' => 'B-CERT'];
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_xmlrpc_calls'] = [];
		@mkdir($GLOBALS['pfb']['dbdir'], 0777, TRUE);
		config_set_path($localPath, ['pfb_dns' => $toggle === 'on' ? '' : 'on', 'pfb_dns_saved' => 'A-SNAPSHOT']);
		config_set_path($sharedPath, ['pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '8853']);
		config_set_path(PFB_SECTIONS['sync'], ['syncscope' => 'all', 'varsynconchanges' => $transport]);
		if ($transport === 'manual') {
			pfblockerng_do_xmlrpc_sync('192.0.2.2', '443', 'https', 'admin', 'password', 5);
			$payload = $GLOBALS['pfb_test_xmlrpc_calls'][0][1];
		} else {
			$payload = [];
			foreach (pfblockerng_plugin_xmlrpc_send() as $path) {
				array_set_path($payload, $path, array_get_path($GLOBALS['config'], $path, []));
			}
			$payload = $payload['installedpackages'];
		}
		$this->assertArrayHasKey('pfblockerngdnssettings', $payload, 'vacuity guard: the new sender sent its new section');
		if ($transport === 'manual') {
			// merge_installedpackages_section replaces a section wholesale and calls no hook, so it never carries pfblockerngdns (#3770).
			$this->assertArrayNotHasKey('pfblockerngdns', $payload);
		} else {
			// Over pfSense HA sync the legacy scope carries the enable alone (Off travels as []); the released hook ignores it below.
			$this->assertSame(['config' => [0 => ['pfb_dns' => $toggle === 'on' ? [] : 'on']]], $payload['pfblockerngdns'] ?? NULL);
		}
		if ($transport === 'manual') {
			// The live XMLRPC smoke case covers core's receiver; this case proves the sender's safe payload.
			return;
		}
		$GLOBALS['config'] = ['unbound' => ['active_interface' => 'lo0', 'custom_options' => 'B-MOVED']];
		config_set_path($localPath, $local);
		$before = $GLOBALS['config'];
		// The released hook has no knowledge of the new section and ignores it.
		foreach (pfb_test_released_plugin_xmlrpc_recv(['installedpackages' => $payload]) as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
		$this->assertNull(config_get_path($sharedPath));
		$this->assertSame($local, config_get_path($localPath));
		$this->assertSame($before['unbound'], config_get_path('unbound'));
	}

	public function testCurrentReceiverKeepsExplicitEmptyLocalChoices(): void
	{
		$local = array_fill_keys(['pfb_dns', 'pfb_dns_saved', 'pfb_dns_interface', 'pfb_dns_dot_interface',
			'pfb_dns_doh_interface', 'pfb_dns_doq_interface', 'pfb_dns_sslcertref'], '');
		$GLOBALS['config'] = [];
		config_set_path(PFB_SECTIONS['dns'], $local);
		$payload = ['installedpackages' => [
			'pfblockerngsync' => ['config' => [0 => ['varsynconchanges' => 'auto']]],
			'pfblockerngdnssettings' => ['config' => [0 => ['pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '8853']]],
		]];
		foreach (pfblockerng_plugin_xmlrpc_recv($payload) as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
		$this->assertSame($local, PfbConfig::readSection(PFB_SECTIONS['dns']));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns_shared/pfb_dns_dot'));
	}
}
