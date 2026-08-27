<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1887 — the $pfb[] toggle mirrors carry PfbToggle, not a raw token.
 *
 * pfb_global() used to publish these mirrors as `PfbConfig::read($key)->value`, i.e. it
 * read the enum and immediately threw the type away. Consumers then re-derived the
 * meaning with hand-written string comparisons, and the vocabulary drifted three ways:
 * 'on', legacy 'off', and a bare '' assigned by the force-disable paths.
 *
 * That is what produced the fail-dangerous class this issue had to repair: `== ''` does not
 * match legacy 'off', and `!empty()` inverts outright because '' is falsy while 'off' is
 * truthy. Neither mistake is visible at the call site, and both fail silently.
 *
 * Publishing the enum itself is the fix: one runtime vocabulary, no raw tokens, and a comparison
 * that has to name PfbToggle::On or PfbToggle::Off to mean anything. www/ already
 * re-parsed these mirrors through pfb_cfg_toggle_read() to get an enum back — with the
 * mirror typed, that re-parsing is deleted rather than rewritten.
 *
 * Seeding mirrors DnsblVipDisableNoticeTest::seedGlobalPrereqs() — the established
 * minimum pfb_global() needs to run warning-free off-box.
 */
#[CoversFunction('pfb_global')]
final class ToggleMirrorTypeTest extends TestCase
{
	/**
	 * Every $pfb[] mirror sourced from a toggle field, plus the runtime-derived
	 * unbound_state, which shares the same vocabulary and the same comparisons.
	 */
	private const TOGGLE_MIRRORS = [
		'enable',
		'keep',
		'dnsbl',
		'dnsbl_vip_auto',
		'dnsbl_nonat',
		'dnsbl_hsts',
		// issue #1907 (#1921 S3): moved from ToggleSectionMirrorTypeTest -- now sourced
		// through PfbConfig::read() (registered, default 'on'), not a raw section reach.
		'dnsbl_res_cache',
		'dnsbl_py_reply',
		'supp',
		'unbound_state',
	];

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

		PfbConfig::write('dnsbl/dnsbl_interface', 'lo0');
	}

	/**
	 * Every toggle mirror is a PfbToggle instance after pfb_global(), never a string.
	 *
	 * Asserted as a type check over the whole set rather than per value, so a mirror
	 * added later without the enum is caught by this same test.
	 */
	public function testEveryToggleMirrorIsAPfbToggleInstance(): void
	{
		PfbConfig::write('gen/enable_cb', PfbToggle::On);
		PfbConfig::write('dnsbl/pfb_dnsbl', PfbToggle::On);

		pfb_global();

		foreach (self::TOGGLE_MIRRORS as $mirror) {
			$this->assertArrayHasKey($mirror, $GLOBALS['pfb'], "\$pfb['{$mirror}'] must be published");
			$this->assertInstanceOf(
				PfbToggle::class,
				$GLOBALS['pfb'][$mirror],
				"\$pfb['{$mirror}'] must carry PfbToggle, not a raw stored token"
			);
		}
	}

	/**
	 * An enabled package and DNSBL surface as PfbToggle::On.
	 *
	 * Pairs with the Off case below: a test that only checked one polarity would pass
	 * against a mirror hard-wired to a single enum case.
	 */
	public function testEnabledStateSurfacesAsOn(): void
	{
		PfbConfig::write('gen/enable_cb', PfbToggle::On);
		PfbConfig::write('dnsbl/pfb_dnsbl', PfbToggle::On);

		// A resolvable VIP on the doubled interface, so pfb_global()'s VIP validation
		// does not force-disable DNSBL — otherwise this asserts On against a value the
		// production code is right to have turned Off, and proves nothing about typing.
		// Same setup as DnsblVipDisableNoticeTest::testValidVipDoesNotSurfaceNotice().
		$GLOBALS['pfb_test_vip_list'] = ['_vip_test_valid' => '203.0.113.10'];
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		config_set_path(
			'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4',
			'_vip_test_valid'
		);

		pfb_global();

		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['enable'], 'an enabled package reads as On');
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl'], 'enabled DNSBL reads as On');
	}

	/**
	 * A disabled package surfaces as PfbToggle::Off — not '' and not 'off'.
	 */
	public function testDisabledStateSurfacesAsOff(): void
	{
		PfbConfig::write('gen/enable_cb', PfbToggle::Off);
		PfbConfig::write('dnsbl/pfb_dnsbl', PfbToggle::Off);

		pfb_global();

		$this->assertSame(PfbToggle::Off, $GLOBALS['pfb']['enable'], 'a disabled package reads as Off');
		$this->assertSame(PfbToggle::Off, $GLOBALS['pfb']['dnsbl'], 'disabled DNSBL reads as Off');
	}

	/**
	 * The force-disable path publishes PfbToggle::Off rather than assigning a bare ''.
	 *
	 * pfb_global() force-disables DNSBL on an invalid/unresolved VIP in manual mode.
	 * That path assigned '' directly, which is how a third value entered a two-valued
	 * vocabulary — and why a downstream !empty() check silently inverted. Driven through
	 * the real validation failure (an unresolvable VIP id on the doubled interface), not
	 * by writing the mirror, so the assignment site itself is covered.
	 */
	public function testForceDisableOnInvalidVipPublishesOffNotEmptyString(): void
	{
		PfbConfig::write('gen/enable_cb', PfbToggle::On);
		PfbConfig::write('dnsbl/pfb_dnsbl', PfbToggle::On);
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', PfbToggle::Off);
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		config_set_path(
			'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4',
			'_vip_test_missing'
		);

		pfb_global();

		$this->assertSame(
			PfbToggle::Off,
			$GLOBALS['pfb']['dnsbl'],
			'the force-disable path must publish PfbToggle::Off, not a bare empty string'
		);
		$this->assertNotSame('', $GLOBALS['pfb']['dnsbl'], "no mirror may hold '' once toggles are typed");
	}

	/**
	 * No toggle mirror holds a raw string in either polarity.
	 *
	 * The catch-all for the vocabulary drift: '' from the force-disable paths, 'on' from
	 * a direct assignment, 'off' from the merged stored token. Any of the three reaching
	 * a mirror means some site still speaks tokens instead of the enum.
	 */
	public function testNoToggleMirrorHoldsARawToken(): void
	{
		PfbConfig::write('gen/enable_cb', PfbToggle::On);
		PfbConfig::write('dnsbl/pfb_dnsbl', PfbToggle::On);

		pfb_global();

		foreach (self::TOGGLE_MIRRORS as $mirror) {
			$value = $GLOBALS['pfb'][$mirror] ?? NULL;
			$this->assertIsNotString(
				$value,
				"\$pfb['{$mirror}'] still holds a raw token — every toggle mirror must be a PfbToggle"
			);
		}
	}
}
