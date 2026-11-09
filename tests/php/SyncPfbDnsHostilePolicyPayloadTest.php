<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3770 — a hostile policy payload cannot set a node-local pfB-DNS key.
 *
 * SyncPfbDnsEnableTest drives honest senders. This one hand-builds the pfblockerngdns section no sender of this package
 * would put on the wire: every key the registry knows under dns/ plus an unregistered future key, all carrying SENDER-...
 * values (the enable itself carries 'on'). The policy receive takes the enable and nothing else of the section, and no
 * SENDER-... value reaches the stored config or a state file the receive writes.
 */
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv')]
#[CoversFunction('pfb_sync_policy_merge')]
final class SyncPfbDnsHostilePolicyPayloadTest extends TestCase
{
	private const DNS = 'installedpackages/pfblockerngdns/config/0';
	/** A key a later version may register: unknown here, so it never syncs */
	private const FUTURE_KEY = 'pfb_dns_future_knob';

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;

		$this->dir = sys_get_temp_dir() . '/pfb_sync_dns_hostile_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);

		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb_test_mwexec_bg']    = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		pfb_sync_receive_changed(FALSE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			unlink($file);
		}
		rmdir($this->dir);

		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		if ($this->savedPfb === NULL) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedPfb;
		}
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls']);
		pfb_sync_receive_changed(FALSE);
	}

	/** @return list<string> every key the registry knows under dns/, the enable included */
	private static function registeredDnsKeys(): array
	{
		$keys = [];
		foreach (array_keys(pfb_cfg_registry()) as $path) {
			if (str_starts_with((string) $path, 'dns/')) {
				$keys[] = substr((string) $path, strlen('dns/'));
			}
		}
		return $keys;
	}

	public function testAHostilePfbDnsSectionOnAPolicyPayloadSetsTheEnableAndNothingElse(): void
	{
		$registered = self::registeredDnsKeys();
		$this->assertContains('pfb_dns', $registered, 'vacuity guard: the registry knows the enable');
		$this->assertGreaterThan(1, count($registered), 'vacuity guard: the registry knows node-local dns keys to attack');

		$receiver = [self::FUTURE_KEY => 'RECEIVER-FUTURE', 'pfb_dns' => ''];
		$hostile  = [self::FUTURE_KEY => 'SENDER-FUTURE', 'pfb_dns' => 'on'];
		foreach ($registered as $key) {
			if ($key !== 'pfb_dns') {
				$receiver[$key] = "RECEIVER-{$key}";
				$hostile[$key]  = "SENDER-{$key}";
			}
		}

		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerngdns'           => ['config' => [0 => $receiver]],
				'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsbl' => '']]],
				'pfblockerngsync'          => ['config' => [0 => ['syncscope' => 'policy', 'varsynconchanges' => 'auto']]],
			],
		];

		$result = pfblockerng_plugin_xmlrpc_recv(['installedpackages' => [
			'pfblockerngdns'           => ['config' => [0 => $hostile]],
			'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsbl' => 'on']]],
			'pfblockerngsync'          => ['config' => [0 => ['syncscope' => 'policy']]],
		]]);
		foreach ($result as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}

		$this->assertSame('on', config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl'), 'vacuity guard: the policy receive applied');
		$this->assertSame(array_replace($receiver, ['pfb_dns' => 'on']), config_get_path(self::DNS),
			'the receiver\'s pfB-DNS section is its own, but for the enable');

		$stored = serialize($GLOBALS['config']);
		$this->assertStringNotContainsString('SENDER-', $stored, 'no sender value is stored');
		$files = glob("{$this->dir}/*") ?: [];
		$this->assertNotSame([], $files, 'vacuity guard: the receive wrote its state files');
		foreach ($files as $file) {
			$this->assertStringNotContainsString('SENDER-', (string) file_get_contents($file), basename($file) . ' carries no sender value');
		}
	}
}
