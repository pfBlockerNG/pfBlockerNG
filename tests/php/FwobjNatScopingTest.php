<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-35 — regression guard for the NAT-classify loop scoping fix in pfb_create_dnsbl().
 *
 * Bug (F3 / CodeRabbit): the 'enabled' NAT classify loop used pfb_fwobj_is_owned($descr)
 * to bucket existing rules into DNSBL-owned (to rebuild) vs other (to preserve). Because
 * pfb_fwobj_is_owned() matches ANY pfBlockerNG marker — including 'pfB_' prefix rules —
 * a pfBlockerNG-owned-but-NOT-DNSBL NAT rule (e.g. a future ADR-36 managed rule whose
 * descr starts with 'pfB_') would be silently dropped into the DNSBL rebuild bucket and
 * lost on every pfb_create_dnsbl('enabled') call.
 *
 * Fix: narrow the DNSBL bucket to str_contains($descr, PFB_FWOBJ_NAT_LEGACY_PFX)
 * (i.e. descr containing 'pfB DNSBL'). Any pfBlockerNG-owned rule whose descr does NOT
 * carry that substring stays in the preserved 'other' bucket.
 *
 * This test pins that fix: it seeds an owned-non-DNSBL NAT rule, runs
 * pfb_create_dnsbl('enabled'), and asserts that the rule survives.
 *
 * Functions under test:
 *   - pfb_create_dnsbl()
 */
#[CoversFunction('pfb_create_dnsbl')]
final class FwobjNatScopingTest extends TestCase
{
	// -------------------------------------------------------------------------
	// Helpers — replicated from FwobjCurrentBehaviourTest (that class is a frozen
	// golden oracle; its helpers are private and cannot be reused here).
	// -------------------------------------------------------------------------

	/**
	 * Minimal $pfb keys required by pfb_create_dnsbl() to fire the NAT block
	 * on mode='enabled': DNSBL on, non-lo0 interface, ports, VIP address.
	 *
	 * @return array<string,mixed>
	 */
	private function natPfb(): array
	{
		$pfb = $GLOBALS['pfb'] ?? [];
		$pfb['dnsbl']          = 'on';
		$pfb['dnsbl_port']     = '8081';
		$pfb['dnsbl_port_ssl'] = '8443';
		$pfb['dnsbl_iface']    = 'opt1';
		$pfb['dnsbl_vip4']     = '10.10.10.53';
		$pfb['dnsbl_vip6']     = '';
		$pfb['dnsbl_cert']     = '/tmp/pfb_fwobj_nat_scoping_test_cert.pem';
		$pfb['dnsbl_conf']     = '/tmp/pfb_fwobj_nat_scoping_test_lighttpd.conf';
		$pfb['dnsbl_vip_auto'] = '';
		$pfb['dnsblconfig']    = [];
		return $pfb;
	}

	/**
	 * Seed $GLOBALS['config'] with the minimal installedpackages structure and DNSBL
	 * settings so pfb_global() and pfb_validate_vips() pass and keep $pfb['dnsbl']='on'.
	 *
	 * @param array<string,string> $dnsblCfg  DNSBL settings section (pfblockerngdnsblsettings)
	 */
	private function seedConfig(array $dnsblCfg = []): void
	{
		$GLOBALS['config'] = [
			'virtualip' => ['vip' => []],
			'installedpackages' => [
				'pfblockerng'               => ['config' => [0 => []]],
				'pfblockerngipsettings'     => ['config' => [0 => []]],
				'pfblockerngdnsblsettings'  => ['config' => [0 => $dnsblCfg]],
				'pfblockerngglobal'         => [],
				'pfblockerngblacklist'      => [],
			],
		];
	}

	/**
	 * A pfBlockerNG-OWNED but NOT-DNSBL NAT rule: descr starts with 'pfB_' (owned per
	 * pfb_fwobj_is_owned) but does NOT contain 'pfB DNSBL' (not in the DNSBL bucket).
	 * Stands in for any future managed NAT rule (e.g. ADR-36) that pfBlockerNG owns but
	 * which must not be destroyed by DNSBL rebuild.
	 *
	 * @return array<string,mixed>
	 */
	private function ownedNonDnsblNatRule(): array
	{
		return [
			'source'      => ['any' => ''],
			'destination' => ['address' => '10.10.10.100', 'port' => '80'],
			'protocol'    => 'tcp',
			'target'      => '10.10.10.200',
			'local-port'  => '9090',
			'interface'   => 'opt1',
			'descr'       => 'pfB_Redirect_test - DO NOT EDIT',
		];
	}

	/** A user-owned NAT rule with no pfBlockerNG marker. Must always survive. */
	private function userNatRule(): array
	{
		return [
			'source'      => ['any' => ''],
			'destination' => ['address' => '192.168.1.100', 'port' => '80'],
			'protocol'    => 'tcp',
			'target'      => '192.168.1.200',
			'local-port'  => '9000',
			'interface'   => 'wan',
			'descr'       => 'my-user-nat',
		];
	}

	// -------------------------------------------------------------------------
	// setUp / tearDown
	// -------------------------------------------------------------------------

	protected function setUp(): void
	{
		$GLOBALS['config']                           = [];
		$GLOBALS['pfb_test_write_config_calls']      = [];
		$GLOBALS['pfb_test_interface_ip']            = [];
		$GLOBALS['pfb_test_configured_ipv6']         = [];
		$GLOBALS['pfb_test_interfaces_with_gateway'] = [];
		$GLOBALS['pfb_test_vip_bring_down_calls']    = [];
		$GLOBALS['pfb_test_ipalias_configure_calls'] = [];
	}

	protected function tearDown(): void
	{
		unset(
			$GLOBALS['config'],
			$GLOBALS['pfb_test_write_config_calls'],
			$GLOBALS['pfb_test_vip_bring_down_calls'],
			$GLOBALS['pfb_test_ipalias_configure_calls'],
			$GLOBALS['pfb_test_vip_list']
		);
	}

	// =========================================================================
	// Regression test
	// =========================================================================

	/**
	 * pfb_create_dnsbl('enabled') preserves an owned-but-non-DNSBL NAT rule.
	 *
	 * Scenario: the NAT classify loop must bucket by DNSBL ownership only —
	 * not by the broad pfb_fwobj_is_owned() predicate — so that a future managed
	 * non-DNSBL NAT rule (descr starts with 'pfB_' but does not carry 'pfB DNSBL')
	 * survives a DNSBL rebuild.
	 *
	 *   Background:
	 *     Given a valid-VIP DNSBL-on configuration (pfb_validate_vips passes)
	 *       and nat/rule contains:
	 *         (a) an owned-non-DNSBL NAT rule (descr='pfB_Redirect_test - DO NOT EDIT')
	 *         (b) a user-owned NAT rule        (descr='my-user-nat')
	 *       and no 'pfB DNSBL' rule yet exists
	 *
	 *   When  pfb_create_dnsbl('enabled') is called
	 *
	 *   Then  (1) the owned-non-DNSBL rule ('pfB_Redirect_test...') STILL present
	 *         (2) the user rule ('my-user-nat') STILL present
	 *         (3) a new DNSBL NAT rule with descr='pfB DNSBL - DO NOT EDIT' was created
	 *
	 * Regression guarantee: with the old pfb_fwobj_is_owned() bucketing the
	 * 'pfB_Redirect_test...' rule (owned = TRUE) would have been sorted into the
	 * DNSBL rebuild bucket and then discarded when the new DNSBL rule set replaced it.
	 * Assertion (1) catches that exact regression — it would FAIL on unfixed code.
	 */
	public function testEnableRebuildPreservesOwnedNonDnsblNat(): void
	{
		// Given: a valid VIP configuration so pfb_validate_vips passes and $pfb['dnsbl']
		// remains 'on' after pfb_global() runs inside pfb_create_dnsbl().
		$vipId = '_vip_test_nat4';
		$vipIp = '10.10.10.53';
		$this->seedConfig([
			'pfb_dnsbl'       => 'on',
			'pfb_dnsport'     => '8081',
			'pfb_dnsport_ssl' => '8443',
			'pfb_dnsvip4'     => $vipId,
			'dnsbl_interface' => 'opt-double',	// matched by get_configured_vip_interface double
		]);
		// Seed get_configured_vip_list so pfb_get_vips includes the test VIP id.
		$GLOBALS['pfb_test_vip_list'] = [$vipId => $vipIp];
		// Set dnsbl_cert / dnsbl_conf to safe temp paths (pfb_global reads them from $pfb;
		// pfb_create_dnsbl later checks file_exists and writes to dnsbl_conf).
		$GLOBALS['pfb']['dnsbl_cert'] = '/tmp/pfb_fwobj_nat_scoping_test_cert.pem';
		$GLOBALS['pfb']['dnsbl_conf'] = '/tmp/pfb_fwobj_nat_scoping_test_lighttpd.conf';

		// Seed nat/rule: (a) owned-non-DNSBL rule, (b) user rule.
		$ownedNonDnsbl = $this->ownedNonDnsblNatRule();
		$userRule      = $this->userNatRule();
		$GLOBALS['config']['nat'] = ['rule' => [$ownedNonDnsbl, $userRule]];

		// Assert before-state: owned-non-DNSBL and user rules present; no DNSBL rule yet.
		$before = config_get_path('nat/rule', []);
		$this->assertCount(2, $before, 'before: exactly two NAT rules must be present');

		$ownedBefore = array_filter(
			$before,
			fn($r) => ($r['descr'] ?? '') === 'pfB_Redirect_test - DO NOT EDIT'
		);
		$userBefore = array_filter(
			$before,
			fn($r) => ($r['descr'] ?? '') === 'my-user-nat'
		);
		$dnsblBefore = array_filter(
			$before,
			fn($r) => str_contains($r['descr'] ?? '', 'pfB DNSBL')
		);
		$this->assertCount(1, $ownedBefore, 'before: owned-non-DNSBL rule must be present');
		$this->assertCount(1, $userBefore,  'before: user NAT rule must be present');
		$this->assertCount(0, $dnsblBefore, 'before: no pfB DNSBL NAT rule must exist yet');

		// Verify that pfb_fwobj_is_owned() does consider the owned-non-DNSBL rule as owned
		// (proves the old broad bucket check WOULD have caught it and triggered the bug).
		$this->assertTrue(
			pfb_fwobj_is_owned('pfB_Redirect_test - DO NOT EDIT'),
			'pfb_fwobj_is_owned must return TRUE for a pfB_-prefixed descr (confirming the old bucket was too broad)'
		);
		// And confirm it does NOT contain 'pfB DNSBL' (so the fix correctly excludes it).
		$this->assertFalse(
			str_contains('pfB_Redirect_test - DO NOT EDIT', PFB_FWOBJ_NAT_LEGACY_PFX),
			'the owned-non-DNSBL descr must NOT contain PFB_FWOBJ_NAT_LEGACY_PFX'
		);

		// When: pfb_create_dnsbl('enabled') — fires the NAT classify loop + rebuild.
		pfb_create_dnsbl('enabled');

		// Then: assert all three post-conditions.
		$after = config_get_path('nat/rule', []);

		// (1) Owned-non-DNSBL rule STILL present (regression guard — old code drops it).
		$ownedAfter = array_filter(
			$after,
			fn($r) => ($r['descr'] ?? '') === 'pfB_Redirect_test - DO NOT EDIT'
		);
		$this->assertCount(
			1,
			$ownedAfter,
			'after enable: owned-non-DNSBL rule must survive (regression: old pfb_fwobj_is_owned bucket would drop it)'
		);
		$this->assertSame(
			$ownedNonDnsbl,
			array_values($ownedAfter)[0],
			'after enable: owned-non-DNSBL rule must be byte-identical to what was seeded'
		);

		// (2) User rule STILL present, byte-identical.
		$userAfter = array_filter(
			$after,
			fn($r) => ($r['descr'] ?? '') === 'my-user-nat'
		);
		$this->assertCount(1, $userAfter, 'after enable: user NAT rule must survive');
		$this->assertSame(
			$userRule,
			array_values($userAfter)[0],
			'after enable: user NAT rule must be byte-identical to what was seeded'
		);

		// (3) New DNSBL NAT rule created with the exact ownership descr.
		$dnsblAfter = array_filter(
			$after,
			fn($r) => ($r['descr'] ?? '') === 'pfB DNSBL - DO NOT EDIT'
		);
		$this->assertNotEmpty(
			$dnsblAfter,
			'after enable: at least one NAT rule with descr="pfB DNSBL - DO NOT EDIT" must be created'
		);
	}
}
