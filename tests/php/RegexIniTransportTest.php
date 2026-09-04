<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** The configured regex textarea remains an opaque stored blob in MAIN. */
final class RegexIniTransportTest extends TestCase
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
		$this->tmp = sys_get_temp_dir() . '/pfb_regex_ini_' . uniqid('', TRUE);
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

	private function emit(string $regexToggle, string $storedBlob): string
	{
		PfbConfig::writeSystem('dnsbl/pfb_regex', $regexToggle);
		PfbConfig::writeSystem('dnsbl/pfb_regex_list', $storedBlob);
		pfb_unbound_python('enabled');
		$ini = file_get_contents($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertNotFalse($ini, 'writer must create the Python INI');
		return $ini;
	}

	public function testWriterEmitsStoredRegexBlobUnderMainWithoutDecode(): void
	{
		$decoded = "(?i)evil\xff\n[unterminated";
		$stored = base64_encode($decoded);
		$ini = $this->emit('on', $stored);

		$this->assertStringContainsString('[MAIN]', $ini);
		$this->assertStringContainsString("regex_list = {$stored}", $ini);
		$this->assertStringNotContainsString($decoded, $ini);
		$this->assertStringNotContainsString('[REGEX]', $ini);
	}

	public function testWriterOmitsStoredBlobWhenRegexToggleIsOff(): void
	{
		$stored = base64_encode('legacy.regex');
		$ini = $this->emit('', $stored);
		$this->assertStringNotContainsString("regex_list = {$stored}", $ini);
	}

	public function testWriterOmitsEmptyRegexBlobWhenToggleIsOn(): void
	{
		$ini = $this->emit('on', '');
		$this->assertStringNotContainsString('regex_list =', $ini);
	}

	/**
	 * Issue #3194: #3192's pfb_regex_exception_list shipped only in pre-alpha, so it is
	 * dropped outright with no migration and no fold-back. A value left behind in a dev
	 * config is inert -- the resolver blob is the MAIN list byte-for-byte, and the stale
	 * pattern never reaches Unbound.
	 */
	public function testWriterIgnoresAStaleExceptionListValueLeftInTheConfig(): void
	{
		config_set_path(
			'installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex_exception_list',
			base64_encode('^stale\\.example\\.com$')
		);
		$stored = base64_encode('^main\\.example\\.com$');
		$ini = $this->emit('on', $stored);

		$this->assertStringContainsString("regex_list = {$stored}", $ini);
		$this->assertStringNotContainsString('stale', pfb_b64_text($stored));
		preg_match('/regex_list = ([A-Za-z0-9+\/=]+)/', $ini, $match);
		$this->assertSame(
			'^main\\.example\\.com$',
			pfb_b64_text($match[1] ?? ''),
			'the emitted blob must be the main list alone'
		);
	}
}
