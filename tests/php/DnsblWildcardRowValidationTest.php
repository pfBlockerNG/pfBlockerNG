<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Multi-dot suppression / No-AAAA rows must never become whole-domain
 * wildcards (issue #1741).
 *
 * '.example.com' is the wildcard form and covers the domain plus every
 * subdomain. Three consumers turned a row into that wildcard by stripping its
 * leading dot(s) with ltrim(), which strips ALL of them — so an invalid
 * '..example.com' row, which pfb_filter(PFB_FILTER_DOMAIN) rejects and the
 * webConfigurator would never have accepted, was promoted to a wildcard
 * covering more than the operator wrote. An invalid row is skipped instead,
 * and its valid neighbours still make it through.
 */
final class DnsblWildcardRowValidationTest extends TestCase
{
	private static string $applySrc;
	private static string $applyWhitelistRegion;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
		$src = php_strip_whitespace($path);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		self::$applySrc = $src;
		$start = strpos(self::$applySrc, 'pfb_logger("\\n Loading DNSBL Whitelist...", 1);');
		$end = strpos(self::$applySrc, '$pfb_whitelist .= ",localhost.localdomain,,\\n";', $start === false ? 0 : $start);
		if ($start === false || $end === false || $end <= $start) {
			throw new RuntimeException('test bootstrap: apply-side whitelist region not found');
		}
		self::$applyWhitelistRegion = substr(self::$applySrc, $start, $end - $start);
	}

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$this->seedGlobalPrereqs();
	}

	/**
	 * Seed the minimum config keys pfb_global() reads (mirrors
	 * PythonWhitelistTldSegTest::seedGlobalPrereqs()), since the functions
	 * under test call pfb_global() internally.
	 */
	private function seedGlobalPrereqs(): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		config_set_path("{$gen}/pfb_min",        '0');
		config_set_path("{$gen}/pfb_hour",       '0');
		config_set_path("{$gen}/pfb_dailystart", '0');
		config_set_path("{$gen}/skipfeed",       '0');

		config_set_path("{$ip}/suppression",     '');
		config_set_path("{$ip}/database_cc",     '');
		config_set_path("{$ip}/maxmind_locale",  'en');
		config_set_path("{$ip}/asn_reporting",   'disabled');
		config_set_path("{$ip}/asn_token",       '');
		config_set_path("{$ip}/maxmind_account", '');
		config_set_path("{$ip}/maxmind_key",     '');

		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');

		config_set_path("{$dnsbl}/pfb_dnsvip4",     '');
		config_set_path("{$dnsbl}/pfb_dnsvip6",     '');
		config_set_path("{$dnsbl}/pfb_dnsport",     '8081');
		config_set_path("{$dnsbl}/pfb_dnsport_ssl", '8443');
		config_set_path("{$dnsbl}/top1m_enable",    '');
		config_set_path("{$dnsbl}/pfb_cache",       '');
		config_set_path("{$dnsbl}/pfb_py_reply",    '');
		config_set_path("{$dnsbl}/pfb_regex",       '');
		config_set_path("{$dnsbl}/pfb_regex_list",  '');
		config_set_path("{$dnsbl}/pfb_cname",       '');
		config_set_path("{$dnsbl}/tld_allow",       '');
		config_set_path("{$dnsbl}/pfb_py_nolog",    '');
		config_set_path("{$dnsbl}/pfb_noaaaa",      '');
		config_set_path("{$dnsbl}/pfb_noaaaa_list", '');
		config_set_path("{$dnsbl}/pfb_gp",          '');
		config_set_path("{$dnsbl}/pfb_gp_bypass_list", '');

		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}

		PfbConfig::write('dnsbl/pfb_dnsbl', 'on');
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', '');
		PfbConfig::write('dnsbl/dnsbl_interface', 'lo0');
	}

	private function setWhitelist(string $decoded): void
	{
		config_set_path(
			'installedpackages/pfblockerngdnsblsettings/config/0/whitelist',
			base64_encode($decoded)
		);
	}

	// --- The Python whitelist CSV (pfb_unbound_python_whitelist()) ---

	public function testPythonWhitelistDropsDoubleDotRow(): void
	{
		$this->setWhitelist("..example.com\n");
		$this->assertSame('', pfb_unbound_python_whitelist());
	}

	public function testPythonWhitelistKeepsNeighboursOfADroppedRow(): void
	{
		$this->setWhitelist("good.com\n..example.com\n.wild.org\n");
		$this->assertSame("good.com,0\nwild.org,1\n", pfb_unbound_python_whitelist());
	}

	public function testPythonWhitelistStillMarksTheSingleDotWildcard(): void
	{
		// The valid wildcard form is the whole point of the ',1' suffix — it
		// must survive the row gate untouched.
		$this->setWhitelist(".wild.org\nplain.net\nwww.stripme.net\n");
		$this->assertSame("wild.org,1\nplain.net,0\nstripme.net,0\n", pfb_unbound_python_whitelist());
	}

	// --- The grep -vF whitelist file (pfblockerng_apply.inc) ---

	/**
	 * Run the apply-side whitelist collection over the seeded suppression list.
	 *
	 * The block lives deep inside sync_package_pfblockerng() and is not
	 * unit-reachable, so it is eval-extracted verbatim from the REAL source
	 * (house precedent: tests/php/CategoryEditPostGuardTest.php).
	 */
	private function collectApplyWhitelist(): string
	{
		pfb_global();
		$pfb = $GLOBALS['pfb'];
		$pfb_whitelist = '';
		eval(self::$applyWhitelistRegion);

		return $pfb_whitelist;
	}

	public function testApplyWhitelistExtractionUsesExecutableBoundaryNotProductionComment(): void
	{
		$this->assertStringStartsWith('pfb_logger("\\n Loading DNSBL Whitelist...', self::$applyWhitelistRegion);
	}

	public function testApplyWhitelistDropsDoubleDotRow(): void
	{
		$this->setWhitelist("..example.com\n");
		$this->assertSame('', $this->collectApplyWhitelist());
	}

	public function testApplyWhitelistKeepsNeighboursOfADroppedRow(): void
	{
		$this->setWhitelist("..example.com\n.wild.org\nplain.net\n");
		$this->assertSame(
			".wild.org,,\n,wild.org,,\n,plain.net,,\n,www.plain.net,,\n",
			$this->collectApplyWhitelist()
		);
	}

	// --- The Python No-AAAA section (pfb_unbound_python()) ---

	/**
	 * Run the No-AAAA conf-section builder over a given list, returning the
	 * emitted `[noAAAA]` body. Same eval-extraction rationale as above; the
	 * section is built inline inside pfb_unbound_python().
	 */
	private function buildNoAaaaSection(string $decodedList): string
	{
		$src = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertNotFalse($src, 'failed to read pfblockerng.inc');
		if (!preg_match(
			'/\t+if \(\$pfb\[\'dnsbl_noaaaa\'\] === PfbToggle::On && isset.*?\n(?=\t+if \(\$pfb\[\'dnsbl_gp\'\] === PfbToggle::On)/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: No-AAAA region not found');
		}

		$pfb = [
			'dnsbl_noaaaa'      => PfbToggle::On,
			'dnsbl_noaaaa_list' => base64_encode($decodedList),
		];
		$pfb_py_conf = '';
		eval($m[0]);

		return $pfb_py_conf;
	}

	public function testNoAaaaSectionDropsDoubleDotRow(): void
	{
		// Nothing valid is left, so no section is emitted at all.
		$this->assertSame('', $this->buildNoAaaaSection("..example.com\n"));
	}

	public function testNoAaaaSectionKeepsNeighboursOfADroppedRow(): void
	{
		$section = $this->buildNoAaaaSection("..example.com\n.wild.org\nplain.net\n");
		$this->assertStringContainsString('wild.org,1', $section);
		$this->assertStringContainsString('plain.net,0', $section);
		$this->assertStringNotContainsString('example.com', $section);
	}
}
