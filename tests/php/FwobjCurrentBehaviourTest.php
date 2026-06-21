<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-35 Phase 1 — oracle: pin today's VIP ownership + teardown and DNSBL-NAT
 * add/strip behaviour BEFORE any refactor. These tests are the contract; the Phase-2/3
 * refactor must not break them.
 *
 * Functions under test:
 *   - pfb_find_marked_vip()       — pure marker-only find
 *   - pfb_manage_dnsbl_vip()      — create idempotency; disable double-guard (marker AND IP)
 *   - pfb_create_dnsbl()          — NAT add (descr='pfB DNSBL - DO NOT EDIT');
 *                                   NAT strip on disable via strpos($descr,'pfB DNSBL') !== FALSE
 *
 * Coverage mandate (CLAUDE.md):
 *   - Every branch exercised (both sides of every conditional).
 *   - Every transition test asserts the BEFORE state before acting (no false passes).
 *   - Complex flows use BDD-style Given/When/Then comments.
 */
#[CoversFunction('pfb_find_marked_vip')]
#[CoversFunction('pfb_manage_dnsbl_vip')]
#[CoversFunction('pfb_create_dnsbl')]
final class FwobjCurrentBehaviourTest extends TestCase
{
	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Minimal $pfb keys required by pfb_manage_dnsbl_vip() and pfb_global().
	 * folder_array is preserved from load-time so pfb_global's safe_mkdir loop works.
	 *
	 * @return array<string,mixed>
	 */
	private function basePfb(): array
	{
		$pfb = $GLOBALS['pfb'] ?? [];
		// The only keys pfb_manage_dnsbl_vip reads from global $pfb directly:
		$pfb['dnsbl_vip_auto']  = '';		// auto-create OFF by default (tests that need ON override)
		$pfb['dnsbl_iface']     = 'lo0';	// passes PFB_FILTER_WORD; 'lo0' → no NAT (safe default)
		$pfb['dnsblconfig']     = [];		// pfb_dnsvip4/6 absent → $want_v6 = false
		// Additional keys pfb_global() reads from config (set via $GLOBALS['config']):
		// These are set in $GLOBALS['config'] seeds so pfb_global re-reads them cleanly.
		return $pfb;
	}

	/**
	 * Minimal $pfb keys for pfb_create_dnsbl() NAT tests. Sets DNSBL enabled with
	 * ports so the NAT block fires on mode='enabled', and a non-lo0 interface so
	 * NAT rules are generated (not skipped for localhost listener).
	 *
	 * @return array<string,mixed>
	 */
	private function natPfb(): array
	{
		$pfb = $this->basePfb();
		$pfb['dnsbl']          = 'on';		// DNSBL enabled — required for enabled NAT block
		$pfb['dnsbl_port']     = '8081';	// lighttpd http port
		$pfb['dnsbl_port_ssl'] = '8443';	// lighttpd https port
		$pfb['dnsbl_iface']    = 'opt1';	// non-lo0 → NAT rules generated
		$pfb['dnsbl_vip4']     = '10.10.10.53';	// sinkhole IPv4 address
		$pfb['dnsbl_vip6']     = '';		// no IPv6 VIP
		$pfb['dnsbl_cert']     = '/tmp/pfb_fwobj_test_nonexistent_cert.pem';
		$pfb['dnsbl_conf']     = '/tmp/pfb_fwobj_test_lighttpd.conf';
		return $pfb;
	}

	/**
	 * Minimal config seeded at the DNSBL settings path. Controls what pfb_global()
	 * reads for dnsbl section, and what pfb_manage_dnsbl_vip() reads via config_get_path.
	 *
	 * @param string $dnsvip4  '_vip<uniqid>' id or '' when absent
	 * @param string $dnsvip6  '_vip<uniqid>' id or '' when absent
	 * @return array<string,string>
	 */
	private function dnsblCfg(string $dnsvip4 = '', string $dnsvip6 = ''): array
	{
		$cfg = [];
		if ($dnsvip4 !== '') {
			$cfg['pfb_dnsvip4'] = $dnsvip4;
		}
		if ($dnsvip6 !== '') {
			$cfg['pfb_dnsvip6'] = $dnsvip6;
		}
		return $cfg;
	}

	/**
	 * Seed $GLOBALS['config'] with a virtualip/vip array and optionally a
	 * DNSBL settings config so both pfb_manage_dnsbl_vip and pfb_global see them.
	 *
	 * @param list<array<string,string>> $vips
	 * @param array<string,string>       $dnsblCfg
	 */
	private function seedConfig(array $vips = [], array $dnsblCfg = []): void
	{
		$GLOBALS['config'] = [
			'virtualip' => ['vip' => $vips],
			'installedpackages' => [
				'pfblockerng'               => ['config' => [0 => []]],
				'pfblockerngipsettings'     => ['config' => [0 => []]],
				'pfblockerngdnsblsettings'  => ['config' => [0 => $dnsblCfg]],
				'pfblockerngglobal'         => [],
				'pfblockerngblacklist'      => [],
			],
		];
	}

	/** A user-owned VIP with no pfBlockerNG marker. Must never be touched. */
	private function userVip(): array
	{
		return [
			'descr'    => 'My custom user VIP',
			'mode'     => 'ipalias',
			'interface' => 'lan',
			'type'     => 'single',
			'subnet'   => '192.168.1.200',
			'subnet_bits' => '32',
			'uniqid'   => 'user0001',
		];
	}

	/** A pfBlockerNG auto-managed v4 VIP with the current marker. */
	private function markedVip4(string $subnet = '10.10.10.53', string $uniqid = 'pfb0001'): array
	{
		return [
			'descr'       => PFB_AUTO_VIP_DESCR_V4,
			'mode'        => 'ipalias',
			'interface'   => 'lo0',
			'type'        => 'single',
			'subnet'      => $subnet,
			'subnet_bits' => '32',
			'uniqid'      => $uniqid,
		];
	}

	/** A pfBlockerNG auto-managed v6 VIP with the current marker. */
	private function markedVip6(string $subnet = 'fd00::53', string $uniqid = 'pfb0002'): array
	{
		return [
			'descr'       => PFB_AUTO_VIP_DESCR_V6,
			'mode'        => 'ipalias',
			'interface'   => 'lo0',
			'type'        => 'single',
			'subnet'      => $subnet,
			'subnet_bits' => '128',
			'uniqid'      => $uniqid,
		];
	}

	/** A NAT rule with the current pfBlockerNG DNSBL marker. */
	private function pfbDnsblNatRule(string $descr = 'pfB DNSBL - DO NOT EDIT'): array
	{
		return [
			'source'             => ['any' => ''],
			'destination'        => ['address' => '10.10.10.53', 'port' => '80'],
			'protocol'           => 'tcp',
			'target'             => '127.0.0.1',
			'local-port'         => '8081',
			'interface'          => 'opt1',
			'descr'              => $descr,
			'associated-rule-id' => 'pass',
			'natreflection'      => 'purenat',
		];
	}

	/** A user-owned NAT rule with no pfBlockerNG marker. Must survive disable. */
	private function userNatRule(): array
	{
		return [
			'source'      => ['any' => ''],
			'destination' => ['address' => '192.168.1.100', 'port' => '80'],
			'protocol'    => 'tcp',
			'target'      => '192.168.1.200',
			'local-port'  => '9000',
			'interface'   => 'wan',
			'descr'       => 'My custom rule',
		];
	}

	// -------------------------------------------------------------------------
	// setUp / tearDown
	// -------------------------------------------------------------------------

	protected function setUp(): void
	{
		// Reset per-test global state while preserving load-time $pfb path keys.
		$GLOBALS['config']                        = [];
		$GLOBALS['pfb_test_write_config_calls']   = [];
		$GLOBALS['pfb_test_interface_ip']         = [];
		$GLOBALS['pfb_test_configured_ipv6']      = [];
		$GLOBALS['pfb_test_interfaces_with_gateway'] = [];
		// Clear the NAT-test doubles' call log.
		$GLOBALS['pfb_test_vip_bring_down_calls'] = [];
		$GLOBALS['pfb_test_ipalias_configure_calls'] = [];
	}

	protected function tearDown(): void
	{
		// Restore pfb to a safe state (folder_array is preserved; dynamic keys are cleared).
		unset(
			$GLOBALS['config'],
			$GLOBALS['pfb_test_write_config_calls'],
			$GLOBALS['pfb_test_vip_bring_down_calls'],
			$GLOBALS['pfb_test_ipalias_configure_calls']
		);
	}

	// =========================================================================
	// VIP tests (a–g): pfb_find_marked_vip + pfb_manage_dnsbl_vip
	// =========================================================================

	/**
	 * a. pfb_find_marked_vip returns the marked v4 VIP and ignores the user VIP.
	 *
	 * The ownership predicate must be marker-only (no IP needed for find-by-marker).
	 * The user VIP at index 0 must never match PFB_AUTO_VIP_DESCR_V4.
	 */
	public function testVipFindByMarkerV4(): void
	{
		// Given: one user VIP (index 0) and one auto-managed v4 VIP (index 1).
		$vips = [$this->userVip(), $this->markedVip4()];

		// When/Then: find by v4 marker returns index 1, not index 0.
		$idx = pfb_find_marked_vip($vips, PFB_AUTO_VIP_DESCR_V4, null);
		$this->assertSame(1, $idx, 'find by v4 marker must return the marked entry only');

		// And the user VIP at index 0 must never be returned.
		$this->assertNotSame(0, $idx, 'user VIP (no marker) must never match the v4 marker');
	}

	/**
	 * b. pfb_find_marked_vip returns the marked v6 VIP and ignores the user VIP.
	 */
	public function testVipFindByMarkerV6(): void
	{
		// Given: one user VIP (index 0) and one auto-managed v6 VIP (index 1).
		$vips = [$this->userVip(), $this->markedVip6()];

		// When/Then: find by v6 marker returns index 1.
		$idx = pfb_find_marked_vip($vips, PFB_AUTO_VIP_DESCR_V6, null);
		$this->assertSame(1, $idx, 'find by v6 marker must return the marked entry only');
		$this->assertNotSame(0, $idx, 'user VIP must never match the v6 marker');
	}

	/**
	 * c. pfb_find_marked_vip returns null when no marked VIP is present.
	 *
	 * Before any auto-VIP is created, or with only user VIPs, both families return null.
	 */
	public function testVipFindReturnsNullWhenAbsent(): void
	{
		// Given: only a user VIP (no pfBlockerNG marker).
		$vips = [$this->userVip()];

		// When/Then: neither v4 nor v6 marker matches anything.
		$this->assertNull(pfb_find_marked_vip($vips, PFB_AUTO_VIP_DESCR_V4, null));
		$this->assertNull(pfb_find_marked_vip($vips, PFB_AUTO_VIP_DESCR_V6, null));

		// Also: an empty array returns null.
		$this->assertNull(pfb_find_marked_vip([], PFB_AUTO_VIP_DESCR_V4, null));
	}

	/**
	 * d. pfb_manage_dnsbl_vip('enabled') is idempotent when the marked VIP already exists.
	 *
	 * Scenario: VIP auto-create is ON and a marked v4 VIP already exists.
	 *
	 *   Background:
	 *     Given a marked v4 VIP exists in virtualip/vip
	 *       and dnsbl_vip_auto = 'on'
	 *
	 *   When  manage('enabled') is called twice
	 *   Then  exactly one VIP entry remains in config after each call (no duplicate)
	 *
	 * The before-state (one VIP) is asserted before the second call to prove
	 * the second call did not duplicate it.
	 */
	public function testVipCreateIsIdempotent(): void
	{
		// Given: one marked v4 VIP with a stored VIP id in DNSBL config.
		$uniqid = 'pfb_idem01';
		$vipId  = "_vip{$uniqid}";
		$this->seedConfig(
			[$this->markedVip4('10.10.10.53', $uniqid)],
			$this->dnsblCfg($vipId)
		);
		$GLOBALS['pfb']                  = $this->basePfb();
		$GLOBALS['pfb']['dnsbl_vip_auto'] = 'on';
		$GLOBALS['pfb']['dnsbl_iface']    = 'lo0';
		$GLOBALS['pfb']['dnsblconfig']    = $this->dnsblCfg($vipId);

		// Assert before-state: exactly one VIP.
		$before = config_get_path('virtualip/vip', []);
		$this->assertCount(1, $before, 'before: exactly one VIP must exist');

		// When: first enabled call (VIP already exists → reuse, no duplicate).
		pfb_manage_dnsbl_vip('enabled');

		// Then: still exactly one VIP.
		$after1 = config_get_path('virtualip/vip', []);
		$this->assertCount(1, $after1, 'after first call: still exactly one VIP (no duplicate)');

		// When: second enabled call (idempotency check).
		pfb_manage_dnsbl_vip('enabled');

		// Then: still exactly one VIP.
		$after2 = config_get_path('virtualip/vip', []);
		$this->assertCount(1, $after2, 'after second call: still exactly one VIP (idempotent)');

		// Marker preserved on the surviving VIP.
		$survivor = array_values($after2)[0];
		$this->assertSame(PFB_AUTO_VIP_DESCR_V4, $survivor['descr'], 'surviving VIP must still carry the v4 marker');
	}

	/**
	 * e. pfb_manage_dnsbl_vip('disabled') removes the marked VIP when IP matches stored config.
	 *
	 * Scenario: double-guard (marker AND IP) both satisfied → VIP is removed.
	 *
	 *   Background:
	 *     Given a marked v4 VIP with subnet='10.10.10.53'
	 *       and pfb_dnsvip4 pointing to a VIP id that resolves to '10.10.10.53'
	 *
	 *   When  manage('disabled') is called
	 *   Then  the marked VIP is gone from virtualip/vip
	 */
	public function testVipDisableRemovesMarkedVipWithMatchingIp(): void
	{
		// Given: a marked v4 VIP and a stored VIP id whose subnet matches.
		$uniqid = 'pfb_del01';
		$vipId  = "_vip{$uniqid}";
		$ip     = '10.10.10.53';
		$this->seedConfig(
			[$this->markedVip4($ip, $uniqid)],
			$this->dnsblCfg($vipId)
		);
		$GLOBALS['pfb']                   = $this->basePfb();
		$GLOBALS['pfb']['dnsbl_vip_auto'] = '';	// auto OFF → triggers delete branch
		$GLOBALS['pfb']['dnsbl_iface']    = 'lo0';
		$GLOBALS['pfb']['dnsblconfig']    = $this->dnsblCfg($vipId);

		// Assert before-state: the marked VIP is present.
		$before = config_get_path('virtualip/vip', []);
		$this->assertCount(1, $before, 'before: marked VIP must be present');
		$this->assertSame(PFB_AUTO_VIP_DESCR_V4, $before[0]['descr'], 'before: VIP must carry the marker');

		// When: disable with a matching IP (get_configured_vip_ipv4 returns '10.10.10.53').
		pfb_manage_dnsbl_vip('disabled');

		// Then: the marked VIP is removed.
		$after = config_get_path('virtualip/vip', []);
		$this->assertCount(0, $after, 'after disable with matching IP: marked VIP must be removed');
	}

	/**
	 * f. The double-guard prevents removal when the stored IP does NOT match the VIP's subnet.
	 *
	 * Scenario: marker matches but IP guard fails → VIP survives disable.
	 *
	 *   Background:
	 *     Given a marked v4 VIP with subnet='10.10.10.53'
	 *       and pfb_dnsvip4 pointing to a VIP id that resolves to a DIFFERENT IP '10.10.1.53'
	 *
	 *   When  manage('disabled') is called
	 *   Then  the marked VIP is still present (double-guard prevented deletion)
	 */
	public function testVipDisableDoesNotRemoveVipWithNonMatchingIp(): void
	{
		// Given: a marked VIP at '10.10.10.53' but the stored VIP id resolves to '10.10.1.53'.
		$uniqidVip    = 'pfb_stay01';	// the VIP in virtualip/vip
		$uniqidStored = 'pfb_other01';	// the VIP id stored in pfb_dnsvip4 (different addr)
		$vipIdStored  = "_vip{$uniqidStored}";

		// Seed virtualip/vip: only the marked VIP at '10.10.10.53'.
		// Seed a SECOND VIP row for get_configured_vip_ipv4 to resolve to '10.10.1.53'.
		$otherVip = [
			'descr'       => 'other',
			'mode'        => 'ipalias',
			'interface'   => 'lo0',
			'type'        => 'single',
			'subnet'      => '10.10.1.53',
			'subnet_bits' => '32',
			'uniqid'      => $uniqidStored,
		];
		$this->seedConfig(
			[$this->markedVip4('10.10.10.53', $uniqidVip), $otherVip],
			$this->dnsblCfg($vipIdStored)
		);
		$GLOBALS['pfb']                   = $this->basePfb();
		$GLOBALS['pfb']['dnsbl_vip_auto'] = '';
		$GLOBALS['pfb']['dnsbl_iface']    = 'lo0';
		$GLOBALS['pfb']['dnsblconfig']    = $this->dnsblCfg($vipIdStored);

		// Assert before-state: the marked VIP is present.
		$before = config_get_path('virtualip/vip', []);
		$markedBefore = array_filter($before, fn($v) => ($v['descr'] ?? '') === PFB_AUTO_VIP_DESCR_V4);
		$this->assertCount(1, $markedBefore, 'before: the marked VIP must be present');

		// When: disable with a NON-MATCHING stored IP.
		pfb_manage_dnsbl_vip('disabled');

		// Then: the marked VIP must NOT have been removed (double-guard protected it).
		$after = config_get_path('virtualip/vip', []);
		$markedAfter = array_filter($after, fn($v) => ($v['descr'] ?? '') === PFB_AUTO_VIP_DESCR_V4);
		$this->assertCount(1, $markedAfter, 'after: marked VIP must survive when stored IP does not match');
	}

	/**
	 * g. pfb_manage_dnsbl_vip('disabled') never touches a user VIP even when a marked VIP is removed.
	 *
	 * Scenario: user VIP survival — the removal is scoped to marked VIPs only.
	 *
	 *   Background:
	 *     Given a marked v4 VIP (matching IP) and a sibling user VIP (no marker)
	 *
	 *   When  manage('disabled') is called
	 *   Then  the marked VIP is removed AND the user VIP survives
	 */
	public function testVipDisableNeverTouchesUserVip(): void
	{
		// Given: [0] = user VIP, [1] = marked v4 VIP with matching IP.
		$uniqid = 'pfb_surv01';
		$vipId  = "_vip{$uniqid}";
		$ip     = '10.10.10.53';
		$this->seedConfig(
			[$this->userVip(), $this->markedVip4($ip, $uniqid)],
			$this->dnsblCfg($vipId)
		);
		$GLOBALS['pfb']                   = $this->basePfb();
		$GLOBALS['pfb']['dnsbl_vip_auto'] = '';
		$GLOBALS['pfb']['dnsbl_iface']    = 'lo0';
		$GLOBALS['pfb']['dnsblconfig']    = $this->dnsblCfg($vipId);

		// Assert before-state: both VIPs are present.
		$before = config_get_path('virtualip/vip', []);
		$this->assertCount(2, $before, 'before: user VIP and marked VIP must both be present');
		$userBefore   = array_filter($before, fn($v) => ($v['descr'] ?? '') === 'My custom user VIP');
		$markedBefore = array_filter($before, fn($v) => ($v['descr'] ?? '') === PFB_AUTO_VIP_DESCR_V4);
		$this->assertCount(1, $userBefore,   'before: user VIP must be present');
		$this->assertCount(1, $markedBefore, 'before: marked VIP must be present');

		// When: disable.
		pfb_manage_dnsbl_vip('disabled');

		// Then: marked VIP is removed, user VIP survives.
		$after = config_get_path('virtualip/vip', []);
		$userAfter   = array_filter($after, fn($v) => ($v['descr'] ?? '') === 'My custom user VIP');
		$markedAfter = array_filter($after, fn($v) => ($v['descr'] ?? '') === PFB_AUTO_VIP_DESCR_V4);
		$this->assertCount(1, $userAfter,   'after: user VIP must survive disable');
		$this->assertCount(0, $markedAfter, 'after: marked VIP must be removed');
		// Confirm the surviving user VIP is byte-identical to the original.
		$this->assertSame($this->userVip(), array_values($userAfter)[0], 'user VIP must be unchanged');
	}

	// =========================================================================
	// NAT tests (h–k): pfb_create_dnsbl() NAT section
	// =========================================================================

	/**
	 * h. pfb_create_dnsbl('enabled') writes 'pfB DNSBL - DO NOT EDIT' as the NAT rule descr.
	 *
	 * Scenario: on enable, DNSBL NAT rules are added with the exact ownership descr.
	 *
	 *   Background:
	 *     Given no existing NAT rules
	 *       and DNSBL is enabled with port 8081 on interface 'opt-double' with VIP 10.10.10.53
	 *       and a valid VIP id '_vip_test_nat4' is configured (passes pfb_validate_vips)
	 *
	 *   When  pfb_create_dnsbl('enabled') is called
	 *   Then  nat/rule contains a rule with descr='pfB DNSBL - DO NOT EDIT'
	 *
	 * Setup note: pfb_create_dnsbl() calls pfb_global() which re-reads $pfb from config.
	 * To keep DNSBL enabled after pfb_global() we must pass pfb_validate_vips():
	 *   - pfb_dnsvip4 = '_vip_test_nat4' (uses the get_configured_vip_interface double
	 *     which returns 'opt-double' for '_vip_test_*' prefixed ids)
	 *   - dnsbl_interface = 'opt-double' (matches what the double returns)
	 *   - pfb_test_vip_list seeds get_configured_vip_list so pfb_get_vips finds the VIP
	 */
	public function testNatAddWritesPfbDnslDescr(): void
	{
		// Given: a valid VIP configuration so pfb_validate_vips passes and $pfb['dnsbl']
		// remains 'on' after pfb_global() runs inside pfb_create_dnsbl().
		$vipId  = '_vip_test_nat4';
		$vipIp  = '10.10.10.53';
		$this->seedConfig(
			[],	// virtualip/vip: no VIP entries needed; pfb_get_vips uses get_configured_vip_list
			[
				'pfb_dnsbl'         => 'on',
				'pfb_dnsport'       => '8081',
				'pfb_dnsport_ssl'   => '8443',
				'pfb_dnsvip4'       => $vipId,
				'dnsbl_interface'   => 'opt-double',	// matched by get_configured_vip_interface double
			]
		);
		// Empty NAT rules.
		$GLOBALS['config']['nat'] = ['rule' => []];
		// Seed get_configured_vip_list so pfb_get_vips includes the test VIP id.
		$GLOBALS['pfb_test_vip_list'] = [$vipId => $vipIp];
		// Seed $pfb['dnsbl_cert'] / dnsbl_conf path (pfb_global reads cert path from config;
		// these live in pfb_global's path assignments which use $g paths. Set them directly
		// in $pfb so the file_exists / file_put_contents calls target safe temp paths).
		$GLOBALS['pfb']['dnsbl_cert'] = '/tmp/pfb_fwobj_nat_test_cert.pem';
		$GLOBALS['pfb']['dnsbl_conf'] = '/tmp/pfb_fwobj_nat_test_lighttpd.conf';

		// Assert before-state: no NAT rules exist.
		$before = config_get_path('nat/rule', []);
		$this->assertCount(0, $before, 'before: nat/rule must be empty');

		// When: enable. pfb_create_dnsbl calls pfb_global() first, then the NAT block.
		pfb_create_dnsbl('enabled');

		// Then: at least one NAT rule with the exact ownership descr exists.
		$after = config_get_path('nat/rule', []);
		$this->assertNotCount(0, $after, 'after enable: nat/rule must not be empty');
		$pfbRules = array_filter($after, fn($r) => ($r['descr'] ?? '') === 'pfB DNSBL - DO NOT EDIT');
		$this->assertNotEmpty($pfbRules, 'at least one NAT rule must carry descr="pfB DNSBL - DO NOT EDIT"');
		// Verify the descr is byte-identical (no truncation, no variant).
		$rule = array_values($pfbRules)[0];
		$this->assertSame('pfB DNSBL - DO NOT EDIT', $rule['descr'], 'NAT rule descr must be exactly "pfB DNSBL - DO NOT EDIT"');
	}

	/**
	 * i. pfb_create_dnsbl('disabled') removes a NAT rule carrying 'pfB DNSBL - DO NOT EDIT'.
	 *
	 * Scenario: on disable, the current-format pfBlockerNG NAT rule is stripped.
	 *
	 *   Background:
	 *     Given a NAT rule with descr='pfB DNSBL - DO NOT EDIT' in nat/rule
	 *
	 *   When  pfb_create_dnsbl('disabled') is called
	 *   Then  that rule is gone from nat/rule
	 */
	public function testNatStripsOnDisable(): void
	{
		// Given: one pfBlockerNG NAT rule in config.
		$this->seedConfig();	// no VIPs needed for disabled path
		$GLOBALS['config']['nat'] = ['rule' => [$this->pfbDnsblNatRule()]];
		$GLOBALS['pfb']           = $this->basePfb();
		// dnsbl_vip_auto OFF + no VIP ids → pfb_manage_dnsbl_vip is a no-op on disable.
		$GLOBALS['pfb']['dnsbl_vip_auto'] = '';
		$GLOBALS['pfb']['dnsblconfig']    = [];

		// Assert before-state: the pfB DNSBL rule is present.
		$before = config_get_path('nat/rule', []);
		$this->assertCount(1, $before, 'before: one pfB DNSBL NAT rule must be present');
		$this->assertSame('pfB DNSBL - DO NOT EDIT', $before[0]['descr'], 'before: rule must carry the exact descr');

		// When: disable.
		pfb_create_dnsbl('disabled');

		// Then: the pfB DNSBL rule is removed.
		$after = config_get_path('nat/rule', []);
		$pfbRules = array_filter($after, fn($r) => strpos($r['descr'] ?? '', 'pfB DNSBL') !== FALSE);
		$this->assertCount(0, $pfbRules, 'after disable: pfB DNSBL NAT rule must be removed');
	}

	/**
	 * j. pfb_create_dnsbl('disabled') strips legacy 'pfB DNSBL' descr (bare, no suffix).
	 *
	 * The detection is strpos($descr, 'pfB DNSBL') !== FALSE, which matches the legacy
	 * form 'pfB DNSBL' (no ' - DO NOT EDIT' suffix) — important for upgrade safety.
	 *
	 *   Background:
	 *     Given a NAT rule with descr='pfB DNSBL' (legacy form, no ' - DO NOT EDIT')
	 *
	 *   When  pfb_create_dnsbl('disabled') is called
	 *   Then  that rule is removed (strpos detects the legacy prefix)
	 */
	public function testNatStripsLegacyPfbDnsblPrefix(): void
	{
		// Given: a NAT rule with only the bare legacy prefix.
		$legacyRule = $this->pfbDnsblNatRule('pfB DNSBL');
		$this->seedConfig();
		$GLOBALS['config']['nat'] = ['rule' => [$legacyRule]];
		$GLOBALS['pfb']           = $this->basePfb();
		$GLOBALS['pfb']['dnsbl_vip_auto'] = '';
		$GLOBALS['pfb']['dnsblconfig']    = [];

		// Assert before-state: the legacy rule is present.
		$before = config_get_path('nat/rule', []);
		$this->assertCount(1, $before, 'before: one legacy pfB DNSBL NAT rule must be present');
		$this->assertSame('pfB DNSBL', $before[0]['descr'], 'before: rule must carry the legacy descr');

		// When: disable.
		pfb_create_dnsbl('disabled');

		// Then: the legacy rule is removed (strpos matched 'pfB DNSBL' prefix).
		$after = config_get_path('nat/rule', []);
		$pfbRules = array_filter($after, fn($r) => strpos($r['descr'] ?? '', 'pfB DNSBL') !== FALSE);
		$this->assertCount(0, $pfbRules, 'after disable: legacy pfB DNSBL rule must be removed');
	}

	/**
	 * k. pfb_create_dnsbl('disabled') never removes a user NAT rule.
	 *
	 * Scenario: user rule survival — stripping is scoped to pfB DNSBL descr only.
	 *
	 *   Background:
	 *     Given one pfB DNSBL NAT rule and one user-owned NAT rule (no pfB DNSBL descr)
	 *
	 *   When  pfb_create_dnsbl('disabled') is called
	 *   Then  the pfB DNSBL rule is removed AND the user rule survives unchanged
	 */
	public function testNatNeverTouchesUserRule(): void
	{
		// Given: [0] = pfB DNSBL rule, [1] = user rule.
		$this->seedConfig();
		$GLOBALS['config']['nat'] = ['rule' => [$this->pfbDnsblNatRule(), $this->userNatRule()]];
		$GLOBALS['pfb']           = $this->basePfb();
		$GLOBALS['pfb']['dnsbl_vip_auto'] = '';
		$GLOBALS['pfb']['dnsblconfig']    = [];

		// Assert before-state: both rules are present.
		$before = config_get_path('nat/rule', []);
		$this->assertCount(2, $before, 'before: both pfB DNSBL and user NAT rules must be present');
		$pfbBefore  = array_filter($before, fn($r) => strpos($r['descr'] ?? '', 'pfB DNSBL') !== FALSE);
		$userBefore = array_filter($before, fn($r) => ($r['descr'] ?? '') === 'My custom rule');
		$this->assertCount(1, $pfbBefore,  'before: pfB DNSBL rule must be present');
		$this->assertCount(1, $userBefore, 'before: user rule must be present');

		// When: disable.
		pfb_create_dnsbl('disabled');

		// Then: pfB DNSBL rule removed, user rule survives.
		$after = config_get_path('nat/rule', []);
		$pfbAfter  = array_filter($after, fn($r) => strpos($r['descr'] ?? '', 'pfB DNSBL') !== FALSE);
		$userAfter = array_filter($after, fn($r) => ($r['descr'] ?? '') === 'My custom rule');
		$this->assertCount(0, $pfbAfter,  'after disable: pfB DNSBL NAT rule must be removed');
		$this->assertCount(1, $userAfter, 'after disable: user NAT rule must survive');
		// User rule must be byte-identical to what was put in.
		$this->assertSame($this->userNatRule(), array_values($userAfter)[0], 'user NAT rule must be unchanged');
	}
}
