<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/** PHP-side TLD bridge tests exercise the writer and manifest at runtime. */
#[CoversFunction('pfb_unbound_python')]
#[CoversFunction('pfb_unbound_python_sources')]
final class TldBridgeEmitTest extends TestCase
{
	private string $tmp;
	private bool $hadPfb = FALSE;
	private bool $hadConfig = FALSE;
	private bool $hadG = FALSE;
	private array $originalPfb = [];
	private array $originalConfig = [];
	private array $originalG = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->hadG = array_key_exists('g', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$this->originalG = $GLOBALS['g'] ?? [];
		$GLOBALS['config'] = [];
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		$this->tmp = sys_get_temp_dir() . '/pfb_tldbridge_' . uniqid('', TRUE);
		mkdir("{$this->tmp}/dnsbl", 0777, TRUE);
		mkdir("{$this->tmp}/db", 0777, TRUE);

		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'logdir'             => $this->tmp,
			'unbound_py_conf'    => "{$this->tmp}/pfb_unbound.ini",
			'unbound_py_wh'      => "{$this->tmp}/pfb_whitelist.txt",
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => 'off',
			'dnsbl_unlock'       => "{$this->tmp}/dnsbl_unlock",
			'dnsbl_tld_wildcard' => '',
			'dnsbl_control'      => PfbToggle::Off,
			'dnsbl_control_legacy' => PfbToggle::Off,
			'dnsblconfig'        => [
				'tld_wildcard_blacklist' => '',
				'tld_wildcard_exclusion' => '',
				'whitelist'              => '',
			],
		]);
		$this->seedConfig();
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
		if ($this->hadG) {
			$GLOBALS['g'] = $this->originalG;
		} else {
			unset($GLOBALS['g']);
		}
		rmdir_recursive($this->tmp);
	}

	private function seedConfig(): void
	{
		$gen = 'installedpackages/pfblockerng/config/0';
		$ip = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		PfbConfig::writeSectionSystem($gen, ['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0']);
		PfbConfig::writeSectionSystem($ip, [
			'suppression' => '', 'database_cc' => '', 'asn_token' => '', 'maxmind_account' => '',
			'maxmind_key' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled',
		]);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		PfbConfig::writeSectionSystem($dnsbl, [
			'pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443',
			'top1m_enable' => '', 'pfb_cache' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '',
			'pfb_cname' => '', 'tld_allow' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '',
			'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'whitelist' => '', 'tld_wildcard' => '',
			'tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => '',
			'pfb_dnsbl' => '', 'pfb_dnsvip_auto' => '', 'dnsbl_interface' => 'lo0',
		]);
	}

	private function emitIni(string $toggle, array $fields): string
	{
		PfbConfig::writeSystem('dnsbl/tld_allow', $toggle);
		foreach ($fields as $key => $value) {
			PfbConfig::writeSystem("dnsbl/{$key}", $value);
		}
		pfb_unbound_python('enabled');
		$ini = file_get_contents($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertNotFalse($ini, 'writer must create the Python INI');
		return $ini;
	}

	public function testIniBridgeReadsAllTldAllowFieldsWhenOn(): void
	{
		$ini = $this->emitIni('on', [
			'tld_allow_gtld' => 'com,net',
			'tld_allow_cctld' => 'uk',
			'tld_allow_itld' => '公司',
			'tld_allow_bgtld' => 'example',
		]);
		$this->assertMatchesRegularExpression('/^tld_allow\s*=\s*on$/m', $ini);
		$this->assertMatchesRegularExpression('/^tld_allow_list\s*=\s*com,net,uk,公司,example$/m', $ini);
	}

	public function testIniBridgeOffToggleSuppressesConfiguredTldList(): void
	{
		$ini = $this->emitIni('', [
			'tld_allow_gtld' => 'com',
			'tld_allow_cctld' => 'uk',
			'tld_allow_itld' => '公司',
			'tld_allow_bgtld' => 'example',
		]);
		$this->assertMatchesRegularExpression('/^tld_allow\s*=\s*off$/m', $ini);
		$this->assertMatchesRegularExpression('/^tld_allow_list\s*=\s*$/m', $ini);
	}

	public function testIniBridgeOnWithEmptyFieldsEmitsOffAndEmptyList(): void
	{
		$ini = $this->emitIni('on', [
			'tld_allow_gtld' => '',
			'tld_allow_cctld' => '',
			'tld_allow_itld' => '',
			'tld_allow_bgtld' => '',
		]);
		$this->assertMatchesRegularExpression('/^tld_allow\s*=\s*off$/m', $ini);
		$this->assertMatchesRegularExpression('/^tld_allow_list\s*=\s*$/m', $ini);
	}

	public function testPslPolicyIniPreservesCanonicalTldStorageByteForByte(): void
	{
		$canonical = [
			'tld_wildcard' => 'on',
			'tld_wildcard_blacklist' => base64_encode("com\nпример\n"),
			'tld_wildcard_exclusion' => base64_encode("safe.example\n"),
			'tld_allow' => 'on',
			'tld_allow_sort' => 'on',
			'tld_allow_gtld' => 'com,net',
			'tld_allow_cctld' => 'uk',
			'tld_allow_itld' => 'xn--p1ai',
			'tld_allow_bgtld' => 'example',
		];
		foreach ($canonical as $key => $value) {
			PfbConfig::writeSystem("dnsbl/{$key}", $value);
		}
		PfbConfig::writeSystem('dnsbl/pfb_psl_include_private', 'on');
		PfbConfig::writeSystem('dnsbl/pfb_psl_allow_private', '');
		$before = [];
		foreach ($canonical as $key => $_value) {
			$before[$key] = config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/' . $key);
		}

		pfb_unbound_python('enabled');
		$ini = file_get_contents($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertNotFalse($ini);
		$this->assertMatchesRegularExpression('/^psl_include_private\s*=\s*on$/m', $ini);
		$this->assertMatchesRegularExpression('/^psl_allow_private\s*=\s*off$/m', $ini);
		foreach ($before as $key => $value) {
			$this->assertSame($value, config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/' . $key), $key);
		}
	}

	public function testManifestTldKeysEmptyWhenDnsblTldOff(): void
	{
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsblconfig']['tld_wildcard_blacklist'] = base64_encode("evil-tld\n\xff");
		$GLOBALS['pfb']['dnsblconfig']['tld_wildcard_exclusion'] = base64_encode('good.example');

		$manifest = pfb_unbound_python_sources([]);
		$this->assertIsArray($manifest);
		$this->assertArrayNotHasKey('tld_wildcard_master', $manifest['config']);
		$this->assertSame([], $manifest['config']['tld_wildcard_blacklist']);
		$this->assertSame([], $manifest['config']['tld_wildcard_exclusion']);
	}

	public function testManifestTldKeysPopulatedWhenDnsblTldOn(): void
	{
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = 'on';
		$GLOBALS['pfb']['dnsblconfig']['tld_wildcard_blacklist'] = base64_encode('evil-tld');
		$GLOBALS['pfb']['dnsblconfig']['tld_wildcard_exclusion'] = base64_encode('good.example');

		$manifest = pfb_unbound_python_sources([]);
		$this->assertIsArray($manifest);
		$this->assertArrayNotHasKey('tld_wildcard_master', $manifest['config']);
		$this->assertSame(['evil-tld'], $manifest['config']['tld_wildcard_blacklist']);
		$this->assertSame(['good.example'], $manifest['config']['tld_wildcard_exclusion']);
	}
}
