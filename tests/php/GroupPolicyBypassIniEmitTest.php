<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #3508: the Group Policy bypass textarea reaches the resolver's [GP_Bypass_List]
 * section row for row, so a CIDR entry arrives at pfb_unbound.py exactly as typed.
 */
final class GroupPolicyBypassIniEmitTest extends TestCase
{
	private string $tmp;
	private array $originalPfb = [];
	private array $originalConfig = [];
	private array $originalG = [];

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$this->originalG = $GLOBALS['g'] ?? [];
		$GLOBALS['config'] = [];
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		$this->tmp = sys_get_temp_dir() . '/pfb_gp_ini_' . uniqid('', TRUE);
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
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		$GLOBALS['g'] = $this->originalG;
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

	private function emit(string $textarea): string
	{
		PfbConfig::writeSystem('dnsbl/pfb_gp', 'on');
		PfbConfig::writeSystem('dnsbl/pfb_gp_bypass_list', base64_encode($textarea));
		pfb_unbound_python('enabled');
		$ini = file_get_contents($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertNotFalse($ini, 'writer must create the Python INI');
		return $ini;
	}

	public function testWriterEmitsBareIpAndCidrRowsVerbatim(): void
	{
		$ini = $this->emit("192.168.1.5\n10.0.0.0/24\n2001:db8::/64\n");

		$this->assertStringContainsString("[GP_Bypass_List]\n0 = 192.168.1.5\n1 = 10.0.0.0/24\n2 = 2001:db8::/64\n", $ini);
	}

	public function testWriterKeepsTheCidrAheadOfAnInlineCommentAndLowercasesIt(): void
	{
		$ini = $this->emit("10.0.0.0/24 # office\n2001:DB8::/64\n");

		$this->assertMatchesRegularExpression('/^0 = 10\.0\.0\.0\/24 ?$/m', $ini);
		$this->assertStringContainsString("\n1 = 2001:db8::/64\n", $ini);
		$this->assertStringNotContainsString('office', $ini);
	}
}
