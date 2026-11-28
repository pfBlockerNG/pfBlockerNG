<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #3977: the uninstall disable pass is Outpost apply code with no Update. pfb_outpost_disable_pass() turns pfBlockerNG off
 * through the apply steps alone (the settings, the DNS teardown, the alias and rule teardown, the hooks through pfb-core): it
 * fetches and parses nothing, so a MaxMind key with the GeoIP files missing starts no download. The boot branch is
 * pfb_outpost_boot(), which runs no pass. sync_package_pfblockerng() is gone.
 */
#[CoversFunction('pfb_outpost_disable_pass')]
final class OutpostDisablePassTest extends TestCase
{
	private string $dir = '';
	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;
	private mixed $originalG = NULL;

	protected function setUp(): void
	{
		$this->originalPfb    = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->originalG      = $GLOBALS['g'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_disable_pass_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$pfb = &$GLOBALS['pfb'];
		foreach (['dbdir' => '', 'schedule_state_dir' => '/state', 'denydir' => '/deny', 'matchdir' => '/match', 'permitdir' => '/permit',
			'nativedir' => '/native', 'dnsdir' => '/dnsbl', 'geoipshare' => '/geoip', 'ccdir' => '/geoip/cc', 'aliasdir' => '/aliases'] as $key => $sub) {
			$pfb[$key] = $this->dir . $sub;
			if (!is_dir($pfb[$key])) {
				mkdir($pfb[$key], 0755, TRUE);
			}
		}
		$pfb['geoip_isos'] = "{$this->dir}/geoip/cc/isos";
		$pfb['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		foreach (['runlog' => 'run.log', 'extraslog' => 'extras.log', 'log' => 'pfb.log', 'errlog' => 'error.log'] as $key => $file) {
			$pfb[$key] = "{$this->dir}/{$file}";
		}
		$pfb['logdir'] = $this->dir;
		$pfb['php'] = "{$this->dir}/php-recorder";
		file_put_contents($pfb['php'], "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> " . escapeshellarg("{$this->dir}/spawns") . "\n");
		chmod($pfb['php'], 0755);
		$pfb['blconfig'] = [];
		$pfb['save'] = $pfb['install'] = TRUE;
		$pfb['hook_lifecycle'] = 'uninstall';
		unset($pfb);
		$GLOBALS['pfb_test_mwexec_bg'] = $GLOBALS['pfb_test_logger_calls'] = $GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['config'] = [];
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		$GLOBALS['g']['pfblockerng_install'] = FALSE;

		$gen = 'installedpackages/pfblockerng/config/0';
		foreach (['enable_cb' => 'on', 'pfb_keep' => '', 'skipfeed' => '0', 'pfb_quiet_hours' => '', 'pfb_reuse' => '', 'pfb_interval' => '24'] as $key => $value) {
			config_set_path("{$gen}/{$key}", $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '',
			'maxmind_account' => '123456', 'maxmind_key' => 'aMaxmindKey123', 'enable_dup' => '', 'enable_agg' => '', 'enable_float' => '',
			'enable_log' => '', 'killstates' => '', 'ip_placeholder' => '', 'inbound_deny_action' => '', 'outbound_deny_action' => '',
			'pass_order' => '', 'autorule_suffix' => ''] as $key => $value) {
			config_set_path("installedpackages/pfblockerngipsettings/config/0/{$key}", $value);
		}
		foreach (['enable_dedup', 'enable_pdup', 'enable_rep', 'et_update', 'ccwhite', 'ccblack', 'etblock', 'etmatch', 'p24_max_var',
			'p24_dmax_var', 'p24_pmax_var', 'ccexclude'] as $key) {
			config_set_path("installedpackages/pfblockerngreputation/config/0/{$key}", '');
		}
		config_set_path('installedpackages/pfblockerngblacklist/blacklist_enable', 'Disable');
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb']    = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		if ($this->originalG === NULL) {
			unset($GLOBALS['g']);
		} else {
			$GLOBALS['g'] = $this->originalG;
		}
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_file_notices']);
		pfb_feed_pass_release();
		pfb_schedule_dispatch_release();
		exec('rm -rf ' . escapeshellarg($this->dir));
	}

	public function testTheDisablePassFetchesNothingAndTurnsPfblockerngOff(): void
	{
		$this->assertFileDoesNotExist("{$this->dir}/geoip/GeoLite2-Country.mmdb", 'before-state: a MaxMind key and no GeoIP files');

		$this->assertTrue(pfb_outpost_disable_pass());

		$this->assertFileDoesNotExist("{$this->dir}/spawns", 'no pfblockerng.php re-entry (the MaxMind download) ran');
		$this->assertSame(PfbToggle::Off, $GLOBALS['pfb']['enable']);
		$log = (string) file_get_contents($GLOBALS['pfb']['log']);
		$this->assertStringNotContainsString('MaxMind Database downloading', $log);
		$this->assertSame(2, substr_count($log, '[ hooks ] no pfb-core'), "the pre and post hooks go to pfb-core alone:\n{$log}");
	}

	public function testTheUninstallAndTheBootBranchCallTheOutpostCodeAlone(): void
	{
		$inc = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$start = strpos($inc, 'function pfblockerng_php_pre_deinstall_command');
		$this->assertNotFalse($start);
		$this->assertStringContainsString('pfb_outpost_disable_pass();', substr($inc, $start, 20000));
		$xml = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng.xml');
		$this->assertMatchesRegularExpression('~if \(platform_booting\(\)\) \{[^}]*pfb_outpost_boot\(\);~s', $xml);
	}
}
