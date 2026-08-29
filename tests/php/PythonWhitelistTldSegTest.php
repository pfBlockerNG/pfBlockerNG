<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/** Whitelist output and the Python TLD-segment bridge are runtime behaviour. */
#[CoversFunction('pfb_unbound_python_whitelist')]
#[CoversFunction('pfb_unbound_python')]
final class PythonWhitelistTldSegTest extends TestCase
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
		$this->tmp = sys_get_temp_dir() . '/pfb_whitelist_ini_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'logdir'          => $this->tmp,
			'unbound_py_conf' => "{$this->tmp}/pfb_unbound.ini",
			'unbound_py_wh'   => "{$this->tmp}/pfb_whitelist.txt",
			'unbound_py_sources' => "{$this->tmp}/pfb_sources.json",
		]);
		$this->seedGlobalPrereqs();
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

	private function seedGlobalPrereqs(): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		PfbConfig::writeSectionSystem($gen, ['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0']);
		PfbConfig::writeSectionSystem($ip, [
			'suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled',
			'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => '',
		]);

		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');

		PfbConfig::writeSectionSystem($dnsbl, [
			'pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443',
			'top1m_enable' => '', 'pfb_cache' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '',
			'pfb_cname' => '', 'tld_allow' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '',
			'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'tld_wildcard' => '', 'pfb_dnsbl' => '',
			'pfb_dnsvip_auto' => '', 'dnsbl_interface' => 'lo0',
		]);
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsbl_control'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_control_legacy'] = PfbToggle::Off;
	}

	private function setWhitelist(string $decoded): void
	{
		PfbConfig::writeSystem('dnsbl/whitelist', base64_encode($decoded));
	}

	private function emitIni(): string
	{
		pfb_unbound_python('enabled');
		$ini = file_get_contents($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertNotFalse($ini, 'writer must create the Python INI');
		return $ini;
	}

	// --- Whitelist behaviour, including hostile legacy configuration. ---

	public function testMixedSuppressionListProducesExpectedCsv(): void
	{
		$this->setWhitelist("example.com\r\n.wild.org\r\nwww.stripme.net\r\n\r\n");

		$this->assertSame(
			"example.com,0\nwild.org,1\nstripme.net,0\n",
			pfb_unbound_python_whitelist()
		);
	}

	public function testLeadingDotWildcardEntryGetsSuffixOne(): void
	{
		$this->setWhitelist(".wild.org\r\n");
		$this->assertSame("wild.org,1\n", pfb_unbound_python_whitelist());
	}

	public function testWwwPrefixIsStrippedAndSuffixedZero(): void
	{
		$this->setWhitelist("www.stripme.net\r\n");
		$this->assertSame("stripme.net,0\n", pfb_unbound_python_whitelist());
	}

	public function testEmptySuppressionReturnsEmptyString(): void
	{
		$this->setWhitelist('');
		$this->assertSame('', pfb_unbound_python_whitelist());
	}

	public function testHostileLegacyTldSegmentsConfigDoesNotChangeWhitelist(): void
	{
		$this->setWhitelist("example.com\n.wild.org\n");
		config_set_path(
			'installedpackages/pfblockerngdnsblsettings/config/0/tld_segments',
			base64_encode("\xff\nlegacy.invalid")
		);

		$this->assertSame("example.com,0\nwild.org,1\n", pfb_unbound_python_whitelist());
	}

	public function testWriterEmitsFixedPythonTldSegment(): void
	{
		$ini = $this->emitIni();
		$this->assertMatchesRegularExpression('/^python_tld_seg\s*=\s*1$/m', $ini);
	}
}
