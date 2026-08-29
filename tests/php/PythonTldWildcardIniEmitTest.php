<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** The Python INI carries configured DNSBL toggles. */
final class PythonTldWildcardIniEmitTest extends TestCase
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
		$this->tmp = sys_get_temp_dir() . '/pfb_tld_ini_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'logdir'          => $this->tmp,
			'unbound_py_conf' => "{$this->tmp}/pfb_unbound.ini",
			'unbound_py_wh'   => "{$this->tmp}/pfb_whitelist.txt",
			'unbound_py_sources' => "{$this->tmp}/pfb_sources.json",
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
			'pfb_dnsbl' => '', 'pfb_dnsvip_auto' => '', 'dnsbl_interface' => 'lo0',
		]);
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsbl_control'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_control_legacy'] = PfbToggle::Off;
	}

	private function emit(string $toggle): string
	{
		PfbConfig::writeSystem('dnsbl/tld_wildcard', $toggle);
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = $toggle;
		pfb_unbound_python('enabled');
		$ini = file_get_contents($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertNotFalse($ini, 'writer must create the Python INI');
		return $ini;
	}

	public function testOffToggleEmitsOffKey(): void
	{
		$ini = $this->emit('');
		$this->assertMatchesRegularExpression('/^python_tld_wildcard\s*=\s*off$/m', $ini);
	}

	public function testOnToggleEmitsOnKey(): void
	{
		$ini = $this->emit('on');
		$this->assertMatchesRegularExpression('/^python_tld_wildcard\s*=\s*on$/m', $ini);
	}

	public function testPslPolicyDefaultsAndExplicitFlipsReachPythonIni(): void
	{
		$ini = $this->emit('');
		$this->assertMatchesRegularExpression('/^psl_include_private\s*=\s*on$/m', $ini);
		$this->assertMatchesRegularExpression('/^psl_allow_private\s*=\s*off$/m', $ini);

		PfbConfig::writeSystem('dnsbl/pfb_psl_include_private', '');
		PfbConfig::writeSystem('dnsbl/pfb_psl_allow_private', 'on');
		pfb_global();
		pfb_unbound_python('enabled');
		$flipped = file_get_contents($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertNotFalse($flipped);
		$this->assertMatchesRegularExpression('/^psl_include_private\s*=\s*off$/m', $flipped);
		$this->assertMatchesRegularExpression('/^psl_allow_private\s*=\s*on$/m', $flipped);
	}

	public function testFeedSuffixPolicyDefaultsAndExplicitValuesReachPythonIni(): void
	{
		$ini = $this->emit('');
		$this->assertMatchesRegularExpression('/^psl_feed_private_policy\s*=\s*honor$/m', $ini);
		$this->assertMatchesRegularExpression('/^psl_feed_icann_policy\s*=\s*honor$/m', $ini);

		PfbConfig::writeSystem('dnsbl/pfb_psl_feed_private_policy', PfbFeedSuffixPolicy::Ignore);
		PfbConfig::writeSystem('dnsbl/pfb_psl_feed_icann_policy', PfbFeedSuffixPolicy::Apex);
		pfb_global();
		pfb_unbound_python('enabled');
		$flipped = file_get_contents($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertNotFalse($flipped);
		$this->assertMatchesRegularExpression('/^psl_feed_private_policy\s*=\s*ignore$/m', $flipped);
		$this->assertMatchesRegularExpression('/^psl_feed_icann_policy\s*=\s*apex$/m', $flipped);
	}

	public function testStoredIdnMaliciousOffReachesPythonIni(): void
	{
		PfbConfig::writeSystem('dnsbl/pfb_idn', 'confusable');
		PfbConfig::writeSystem('dnsbl/pfb_idn_block_malicious', '');

		pfb_global();
		pfb_unbound_python('enabled');
		$ini = file_get_contents($GLOBALS['pfb']['unbound_py_conf']);

		$this->assertNotFalse($ini, 'writer must create the Python INI');
		$this->assertMatchesRegularExpression('/^idn_mode\s*=\s*confusable$/m', $ini);
		$this->assertMatchesRegularExpression('/^python_idn_block_malicious\s*=\s*off$/m', $ini);
	}
}
