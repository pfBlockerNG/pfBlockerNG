<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Runtime identity coverage for DNSBL toggle mirrors initialized by pfb_global().
 *
 * These fields historically came from the raw dnsbl section and were adapted at each
 * assignment. Issue #3137 moves the remaining seven registered toggles to field-level
 * PfbConfig::read() calls, so the runtime mirror must be the exact PfbToggle returned by
 * the gateway. pfb_regex_cap already used that route and stays in the matrix as the
 * established sibling.
 *
 * The raw section itself remains strings for storage-boundary consumers; only the named
 * runtime mirrors are enums.
 */
#[CoversFunction('pfb_global')]
final class ToggleSectionMirrorTypeTest extends TestCase
{
	/** Runtime mirror => registered DNSBL key. */
	private const SECTION_MIRRORS = [
		'dnsbl_top1m'     => 'top1m_enable',
		'dnsbl_regex'     => 'pfb_regex',
		'dnsbl_regex_cap' => 'pfb_regex_cap',
		'dnsbl_cname'     => 'pfb_cname',
		'dnsbl_tld_allow' => 'tld_allow',
		'dnsbl_py_nolog'  => 'pfb_py_nolog',
		'dnsbl_noaaaa'    => 'pfb_noaaaa',
		'dnsbl_gp'        => 'pfb_gp',
	];

	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';

	protected function setUp(): void
	{
		$GLOBALS['config']                = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_vip_list']     = [];
		unset($GLOBALS['pfb_test_specialnet']);
		$this->seedGlobalPrereqs();
	}

	private function seedGlobalPrereqs(): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = self::DNSBL;

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
		config_set_path("{$dnsbl}/pfb_gp_bypass_list", '');
		config_set_path("{$dnsbl}/pfb_noaaaa_list", '');
		config_set_path("{$dnsbl}/pfb_regex_list",  '');

		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}

		PfbConfig::write('dnsbl/dnsbl_interface', 'lo0');
	}

	/** Seed every section-mirror key to one raw token. */
	private function seedAll(string $token): void
	{
		foreach (self::SECTION_MIRRORS as $key) {
			config_set_path(self::DNSBL . '/' . $key, $token);
		}
	}

	/** Every DNSBL toggle mirror is a PfbToggle after pfb_global(). */
	public function testEverySectionMirrorIsAPfbToggleInstance(): void
	{
		$this->seedAll('on');

		pfb_global();

		foreach (array_keys(self::SECTION_MIRRORS) as $mirror) {
			$this->assertArrayHasKey($mirror, $GLOBALS['pfb'], "\$pfb['{$mirror}'] must be published");
			$this->assertInstanceOf(
				PfbToggle::class,
				$GLOBALS['pfb'][$mirror],
				"\$pfb['{$mirror}'] must carry the gateway's PfbToggle runtime identity"
			);
		}
	}

	/**
	 * A stored 'on' surfaces as On for every one of them.
	 */
	public function testStoredOnSurfacesAsOnForEverySectionMirror(): void
	{
		$this->seedAll('on');

		pfb_global();

		foreach (array_keys(self::SECTION_MIRRORS) as $mirror) {
			$this->assertSame(
				PfbToggle::On,
				$GLOBALS['pfb'][$mirror],
				"\$pfb['{$mirror}']: a stored 'on' must surface as PfbToggle::On"
			);
		}
	}

	/** An absent registered key surfaces as Off — not NULL, not ''. */
	public function testAbsentSectionKeySurfacesAsOff(): void
	{
		pfb_global();

		foreach (array_keys(self::SECTION_MIRRORS) as $mirror) {
			$this->assertSame(
				PfbToggle::Off,
				$GLOBALS['pfb'][$mirror],
				"\$pfb['{$mirror}']: an absent section key must surface as PfbToggle::Off"
			);
		}
	}

}
