<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1887 — on/off mirrors read straight from a raw section blob carry PfbToggle too.
 *
 * ToggleMirrorTypeTest covers the mirrors sourced through PfbConfig::read(). These are the
 * other half: pfb_global() also publishes toggle mirrors by reaching directly into the raw
 * $pfb['dnsblconfig'] / $pfb['ipconfig'] section arrays, e.g.
 *
 *     $pfb['dnsbl_regex'] = $pfb['dnsblconfig']['pfb_regex'];
 *
 * Those bypass the gateway entirely, so they arrived as raw stored tokens and every
 * consumer compared them against 'on' by hand — the same untyped pattern, just reached by
 * a different route. Typing them at the single assignment site converts every downstream
 * comparison at once.
 *
 * The raw section arrays themselves stay strings: they are the storage boundary, and
 * $pfb['config'] / ['ipconfig'] / ['dnsblconfig'] are consumed by code that legitimately
 * wants the stored form (the py_unbound.ini writer, section write-back). Only the named
 * per-feature mirrors are typed.
 *
 * Scope note: mirrors assigned inside sync_package_pfblockerng() rather than pfb_global()
 * (float, dup, agg, global_log, dnsbl_control, dnsbl_control_legacy) are converted in the
 * same pass but are not asserted here — invoking that function off-box is not viable, so
 * their coverage rides the existing apply-path suites.
 *
 * issue #1907 (#1921 S3): dnsbl_res_cache, dnsbl_py_reply and supp moved OUT of this
 * file -- pfb_global() now sources all three through PfbConfig::read() (registered,
 * default 'on'), so their absent-key polarity is no longer PfbToggle::Off; they belong
 * to ToggleMirrorTypeTest now, alongside dnsbl_hsts.
 *
 * Seeding mirrors DnsblVipDisableNoticeTest::seedGlobalPrereqs().
 */
#[CoversFunction('pfb_global')]
final class ToggleSectionMirrorTypeTest extends TestCase
{
	/**
	 * Toggle mirrors pfb_global() publishes from a raw section blob, with the DNSBL
	 * settings key each one reads.
	 */
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

	/**
	 * Every section-blob toggle mirror is a PfbToggle after pfb_global().
	 */
	public function testEverySectionMirrorIsAPfbToggleInstance(): void
	{
		$this->seedAll('on');

		pfb_global();

		foreach (array_keys(self::SECTION_MIRRORS) as $mirror) {
			$this->assertArrayHasKey($mirror, $GLOBALS['pfb'], "\$pfb['{$mirror}'] must be published");
			$this->assertInstanceOf(
				PfbToggle::class,
				$GLOBALS['pfb'][$mirror],
				"\$pfb['{$mirror}'] reads a raw section token and must be typed at its assignment"
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

	/**
	 * An unset key surfaces as Off — not NULL, not ''.
	 *
	 * The polarity pair for the test above: without it, a mirror hard-wired to On would
	 * satisfy the On case. Unset rather than 'off' because these keys reach pfb_global()
	 * straight from the section array, so absent is the state a fresh install actually
	 * presents, and the untyped code relied on NULL/'' being falsy.
	 */
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

	/**
	 * No section mirror holds a raw string in any polarity.
	 */
	public function testNoSectionMirrorHoldsARawToken(): void
	{
		$this->seedAll('off');

		pfb_global();

		foreach (array_keys(self::SECTION_MIRRORS) as $mirror) {
			$this->assertIsNotString(
				$GLOBALS['pfb'][$mirror] ?? NULL,
				"\$pfb['{$mirror}'] still holds a raw token"
			);
		}
	}
}
