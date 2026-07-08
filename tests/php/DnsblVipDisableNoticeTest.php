<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #331 — a manual-mode DNSBL VIP validation failure (e.g. a restored config.xml
 * with a malformed VIP reference) force-disables DNSBL inside pfb_global() with only a
 * pfb_logger() entry — nothing in the pfSense GUI ever tells the operator why DNSBL
 * stopped. This pins the fix: the same force-disable now also raises a file_notice(),
 * mirroring the existing MaxMind/ASN credential-notice pattern in this same function.
 *
 * Scenario A (the bug) — manual mode, invalid VIP:
 *   Given pfb_dnsbl='on', pfb_dnsvip_auto='' (manual), pfb_dnsvip4 an id pfb_get_vips()
 *         cannot resolve (empty VIP list -> "invalid IPv4 VIP").
 *   Before: no notices raised.
 *   When  pfb_global() runs.
 *   Then  $pfb['dnsbl'] is force-disabled (unchanged behaviour) AND a file_notice()
 *         fires naming the reason -- FAILS on pre-fix code (no notice), PASSES after.
 *
 * Scenario B (must stay unaffected) — auto-create mode, invalid VIP:
 *   Given the same invalid VIP, but pfb_dnsvip_auto='on'.
 *   Then  validation is deferred to the auto-create bootstrap (existing behaviour) and
 *         NO file_notice() fires -- the fix must not fire while auto-create still owns
 *         provisioning.
 *
 * Scenario C (must stay unaffected) — manual mode, valid VIP:
 *   Given a VIP id that resolves via the seeded pfb_test_vip_list on the matching
 *         interface, so pfb_validate_vips() returns valid.
 *   Then  DNSBL stays enabled and NO file_notice() fires.
 */
#[CoversFunction('pfb_global')]
final class DnsblVipDisableNoticeTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config']                    = [];
		$GLOBALS['pfb_test_file_notices']     = [];
		$GLOBALS['pfb_test_vip_list']         = [];
		unset($GLOBALS['pfb_test_specialnet']);
		$this->seedGlobalPrereqs();
	}

	/**
	 * Seed the minimum config keys pfb_global() reads (mirrors
	 * TickEntrypointTest::seedTickPrereqs() -- the established minimum pfb_global()
	 * needs to run warning-free off-box), trimmed to the non-DNSBL keys this suite
	 * does not vary.
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

		config_set_path("{$dnsbl}/pfb_dnsvip6",     '');
		config_set_path("{$dnsbl}/pfb_dnsport",     '8081');
		config_set_path("{$dnsbl}/pfb_dnsport_ssl", '8443');
		config_set_path("{$dnsbl}/alexa_enable",    '');
		config_set_path("{$dnsbl}/pfb_cache",       '');
		config_set_path("{$dnsbl}/pfb_py_reply",    '');
		config_set_path("{$dnsbl}/pfb_regex",       '');
		config_set_path("{$dnsbl}/pfb_regex_list",  '');
		config_set_path("{$dnsbl}/pfb_cname",       '');
		config_set_path("{$dnsbl}/pfb_pytld",       '');
		config_set_path("{$dnsbl}/pfb_py_nolog",    '');
		config_set_path("{$dnsbl}/pfb_noaaaa",      '');
		config_set_path("{$dnsbl}/pfb_noaaaa_list", '');
		config_set_path("{$dnsbl}/pfb_gp",          '');
		config_set_path("{$dnsbl}/pfb_gp_bypass_list", '');

		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}

		PfbConfig::write('pfb_dnsbl', 'on');
		PfbConfig::write('pfb_dnsvip_auto', '');
		PfbConfig::write('dnsbl_interface', 'lo0');
	}

	public function testManualModeInvalidVipSurfacesFileNotice(): void
	{
		// Given: manual mode (auto='off'), a VIP id on the matching (doubled) interface
		// but absent from the (empty) seeded vip list -> pfb_validate_vips() passes the
		// interface check, then fails "invalid IPv4 VIP" (unresolved).
		PfbConfig::write('dnsbl_interface', 'opt-double');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_missing');

		// Before: no notices raised yet.
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'no notice before pfb_global() runs');

		// When
		pfb_global();

		// Then: force-disable still happens (unchanged behaviour) ...
		$this->assertSame('', $GLOBALS['pfb']['dnsbl'], 'manual mode: an invalid VIP still force-disables DNSBL');

		// ... AND a file_notice() now surfaces the reason (the fix).
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'exactly one notice raised');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertSame('pfBlockerNG DNSBL', $notice['id']);
		$this->assertStringContainsString('DNSBL disabled:', $notice['notice']);
		$this->assertStringContainsString('invalid IPv4 VIP', $notice['notice']);
		$this->assertSame('/pfblockerng/pfblockerng_dnsbl.php', $notice['url']);
	}

	public function testAutoModeInvalidVipDoesNotSurfaceNotice(): void
	{
		// Given: the SAME invalid VIP, but auto-create mode owns provisioning.
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_missing');
		PfbConfig::write('pfb_dnsvip_auto', 'on');

		// When
		pfb_global();

		// Then: auto-create's deferral is unchanged -- no notice, DNSBL stays enabled
		// for this same pass (pfb_manage_dnsbl_vip provisions it afterwards).
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'auto mode defers -- no notice fires');
		$this->assertSame('on', $GLOBALS['pfb']['dnsbl'], 'auto mode: DNSBL is not force-disabled here');
	}

	public function testValidVipDoesNotSurfaceNotice(): void
	{
		// Given: a VIP id that DOES resolve -- seed the doubled VIP list + specialnet so
		// pfb_get_vips() finds it, and use the doubled 'opt-double' interface so the
		// interface check passes too (see pfsense_doubles.php get_configured_vip_interface).
		$GLOBALS['pfb_test_vip_list'] = ['_vip_test_valid' => '203.0.113.10'];
		PfbConfig::write('dnsbl_interface', 'opt-double');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_valid');

		// When
		pfb_global();

		// Then: validation passes -- DNSBL stays enabled, no notice.
		$this->assertSame('on', $GLOBALS['pfb']['dnsbl'], 'a genuinely valid VIP leaves DNSBL enabled');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'no notice when the VIP is valid');
	}
}
