<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3770 -- DNSBL runs only through pfB-DNS, and the setup wizard's default configuration turns DNSBL on, so it also stores
 * the pfB-DNS enable (the Update that follows moves the Resolver). The reset is run up to its configuration write, where the
 * doubled write_config() stops it, and the stored sections are read back.
 */
#[CoversFunction('step4_submitphpaction')]
final class WizardEnablesPfbDnsWithDnsblTest extends TestCase
{
	private const GLOBALS = ['pfb', 'config', 'input_errors', 'stepid', 'pfb_test_file_notices', 'pfb_test_write_config_hook', 'pfb_test_write_config_calls',
		'pfb_test_config_read_hook', 'pfb_test_config_read_calls', 'pfb_test_config_read_lock_held', 'pfb_test_lock_held', 'pfb_test_try_lock_fail', 'pfb_test_lock_events'];
	private const SWEPT = [
		'asn_cache', 'dbdir', 'denydir', 'dnsbl_cache', 'dnsbl_info', 'dnsbl_resolver', 'dnsbl_supptxt', 'dnsdir',
		'dnsorigdir', 'etdir', 'ip_cache', 'matchdir', 'nativedir', 'origdir', 'permitdir', 'snapdir', 'supptxt', 'supptxt_v6',
	];
	private const RESET_WRITE = 'pfBlockerNG: Default Wizard configuration saved';

	private string $dir;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_wizard_pfbdns_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		file_put_contents("{$this->dir}/feeds.json", (string) json_encode([
			'ipv4'  => ['PRI1' => ['description' => 'Primary', 'feeds' => []]],
			'dnsbl' => ['ADs_Basic' => ['description' => 'Ads', 'feeds' => []]],
		]));
		$GLOBALS['pfb'] = [
			'feeds'  => "{$this->dir}/feeds.json",
			'logdir' => $this->dir,
			'log'    => "{$this->dir}/pfb.log",
			'errlog' => "{$this->dir}/pfb.err",
			'php'    => PHP_BINARY,
			'dns_proxy_activation_failed' => "{$this->dir}/dns_proxy_activation_failed",
		];
		foreach (self::SWEPT as $key) {
			$GLOBALS['pfb'][$key] = "{$this->dir}/{$key}";
		}
		$GLOBALS['config'] = [];
		$GLOBALS['input_errors'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_write_config_hook'] = static function (string $description): void {
			if ($description === self::RESET_WRITE) {
				throw new \RuntimeException(self::RESET_WRITE);
			}
		};
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->dir);
	}

	public function testTheDefaultConfigurationTurnsPfbDnsOnBesideDnsbl(): void
	{
		// Given a box whose swept package config held pfB-DNS off (a value the reset must replace, not keep)
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns', '');

		// When the wizard resets, up to the write of its default configuration
		try {
			step4_submitphpaction();
			$this->fail('the reset must reach its configuration write');
		} catch (\RuntimeException $stop) {
			$this->assertSame(self::RESET_WRITE, $stop->getMessage());
		}

		// Then DNSBL is on and so is pfB-DNS: DNSBL has no other host
		$this->assertSame('on', config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl'), 'the wizard writes DNSBL on');
		$this->assertSame('on', config_get_path('installedpackages/pfblockerngdns/config/0/pfb_dns'), 'pfB-DNS is stored on with it');
	}
}
