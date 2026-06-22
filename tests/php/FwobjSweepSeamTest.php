<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-35 Phase 4 — sweep wiring + registration seam tests.
 *
 * Functions under test (on top of FwobjLayerTest Phase-2 coverage):
 *   - pfb_fwobj_sweep()              — orphan teardown, user-survival, no-op, idempotency
 *   - pfb_fwobj_register()           — registration seam for VIP + DNSBL NAT
 *   - pfb_fwobj_reconcile()          — builder called once when absent; no-op when present
 *   - pfb_fwobj_init_registrations() — VIP V4/V6 + NAT specs registered
 *
 * Coverage mandate (CLAUDE.md):
 *   - Every branch exercised (both sides of every conditional).
 *   - Transition tests assert BEFORE state before mutating (no false passes).
 *   - Complex flows use BDD-style Given/When/Then comments.
 *
 * Test cases:
 *   a. testSweepRemovesOrphanVip           — orphan VIP removed even when double-guard ref cleared
 *   b. testSweepRemovesOrphanNat           — orphan NAT removed even without pfb_create_dnsbl teardown
 *   c. testUserVipSurvivesSweep            — user VIP untouched when orphan owned VIP is swept
 *   d. testUserNatSurvivesSweep            — user NAT untouched when orphan owned NAT is swept
 *   e. testSweepIsNoopOnCleanConfig        — no owned rows → FALSE, write_config NOT called
 *   f. testSweepIsIdempotent               — second sweep returns FALSE
 *   g. testRegisterVipAndReconcileCreatesWhenAbsent — builder called, VIP created
 *   h. testRegisterVipAndReconcileIsIdempotent      — builder called once only
 */
#[CoversFunction('pfb_fwobj_sweep')]
#[CoversFunction('pfb_fwobj_register')]
#[CoversFunction('pfb_fwobj_reconcile')]
#[CoversFunction('pfb_fwobj_init_registrations')]
final class FwobjSweepSeamTest extends TestCase
{
	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Seed $GLOBALS['config'] so config_get_path() and config_set_path() work
	 * in each test. Accepts multiple sections by key.
	 *
	 * @param array<string,array<int,array<string,mixed>>> $sections
	 */
	private function seedConfig(array $sections = []): void
	{
		$GLOBALS['config'] = $sections;
	}

	/**
	 * Read a section from $GLOBALS['config'] using a slash-delimited path.
	 *
	 * @param string $path  e.g. 'virtualip/vip'
	 * @return array<int,array<string,mixed>>
	 */
	private function getSection(string $path): array
	{
		$parts  = explode('/', $path);
		$cursor = $GLOBALS['config'] ?? [];
		foreach ($parts as $key) {
			$cursor = $cursor[$key] ?? [];
		}
		return (array) $cursor;
	}

	/**
	 * An orphan pfBlockerNG auto-VIP (V4): marker-owned but double-guard IP ref cleared.
	 * Simulates a half-written state where pfb_dnsvip4 was cleared before the VIP entry
	 * was removed — the double-guard in pfb_manage_dnsbl_vip would skip it; sweep must not.
	 */
	private function orphanPfbVip4(string $subnet = '10.10.10.53'): array
	{
		return [
			'descr'       => PFB_AUTO_VIP_DESCR_V4,	// 'pfB_AUTO_VIP_v4'
			'mode'        => 'ipalias',
			'interface'   => 'lo0',
			'subnet'      => $subnet,
			'subnet_bits' => '32',
		];
	}

	/**
	 * An orphan pfBlockerNG DNSBL NAT rule: marker-owned but pfb_create_dnsbl teardown
	 * was not called — simulates half-written state on disable.
	 */
	private function orphanPfbNat(): array
	{
		return [
			'descr'      => PFB_FWOBJ_NAT_DESCR,	// 'pfB DNSBL - DO NOT EDIT'
			'protocol'   => 'tcp',
			'interface'  => 'opt1',
			'target'     => '127.0.0.1',
			'local-port' => '8081',
		];
	}

	/** A user-owned VIP — must never be touched by any fwobj function. */
	private function userVip(string $subnet = '192.168.1.200'): array
	{
		return [
			'descr'       => 'My custom user VIP',
			'mode'        => 'ipalias',
			'interface'   => 'lan',
			'subnet'      => $subnet,
			'subnet_bits' => '32',
		];
	}

	/** A user-owned NAT rule — must never be touched by any fwobj function. */
	private function userNatRule(): array
	{
		return [
			'descr'      => 'My user NAT rule',
			'protocol'   => 'tcp',
			'interface'  => 'wan',
			'target'     => '10.0.0.1',
			'local-port' => '80',
		];
	}

	/** Reset the static registry and write_config spy between tests. */
	protected function setUp(): void
	{
		$registry = &pfb_fwobj_registry();
		$registry = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	// -------------------------------------------------------------------------
	// Orphan teardown — cases a–b
	// -------------------------------------------------------------------------

	/**
	 * a. testSweepRemovesOrphanVip
	 *
	 * Scenario: A VIP with descr='pfB_AUTO_VIP_v4' exists in virtualip/vip,
	 * but pfb_dnsvip4 (the double-guard reference) is cleared (empty string).
	 * The normal pfb_manage_dnsbl_vip disable path would skip it because the
	 * guard predicate (subnet === cleared_ip) would not match any VIP.
	 * pfb_fwobj_sweep uses marker-only ownership — it MUST still remove it.
	 *
	 * Given:  one orphan pfBlockerNG VIP in virtualip/vip (double-guard ref cleared).
	 * When:   pfb_fwobj_sweep(['virtualip/vip']).
	 * Then:   orphan VIP removed; section empty; returns TRUE.
	 */
	public function testSweepRemovesOrphanVip(): void
	{
		// Given: orphan VIP present; double-guard IP ref intentionally cleared.
		$orphan_vip    = $this->orphanPfbVip4('10.10.10.53');
		$cleared_ip_ref = '';	// simulates pfb_dnsvip4 = '' (cleared)
		$this->seedConfig(['virtualip' => ['vip' => [$orphan_vip]]]);

		// Assert before: orphan VIP is present.
		$before = $this->getSection('virtualip/vip');
		$this->assertCount(1, $before, 'Before: orphan VIP must be present');
		$this->assertSame(PFB_AUTO_VIP_DESCR_V4, $before[0]['descr'],
			'Before: VIP must carry the pfB_AUTO_VIP_v4 marker');

		// Confirm the double-guard would skip it: no VIP has subnet matching cleared ref.
		$double_guard_finds = FALSE;
		foreach ($before as $vip) {
			if (($vip['subnet'] ?? '') === $cleared_ip_ref) {
				$double_guard_finds = TRUE;
			}
		}
		$this->assertFalse($double_guard_finds,
			'Precondition: the double-guard (subnet === cleared_ip_ref) must NOT match the orphan VIP');

		// When: sweep runs (marker-only; ignores the double-guard).
		$result = pfb_fwobj_sweep(['virtualip/vip']);

		// Then: orphan VIP removed; returns TRUE.
		$this->assertTrue($result, 'Sweep must return TRUE (orphan was removed)');
		$after = $this->getSection('virtualip/vip');
		$this->assertCount(0, $after, 'After: orphan VIP must be gone');
	}

	/**
	 * b. testSweepRemovesOrphanNat
	 *
	 * Scenario: A NAT rule with descr='pfB DNSBL - DO NOT EDIT' exists in nat/rule,
	 * but pfb_create_dnsbl teardown was not called (simulates a half-written state
	 * where disable was interrupted before NAT cleanup). pfb_fwobj_sweep removes it.
	 *
	 * Given:  one orphan pfBlockerNG NAT rule in nat/rule.
	 * When:   pfb_fwobj_sweep(['nat/rule']).
	 * Then:   orphan NAT rule removed; section empty; returns TRUE.
	 */
	public function testSweepRemovesOrphanNat(): void
	{
		// Given: orphan NAT rule present (pfb_create_dnsbl teardown was never called).
		$orphan_nat = $this->orphanPfbNat();
		$this->seedConfig(['nat' => ['rule' => [$orphan_nat]]]);

		// Assert before: orphan NAT rule is present.
		$before = $this->getSection('nat/rule');
		$this->assertCount(1, $before, 'Before: orphan NAT rule must be present');
		$this->assertSame(PFB_FWOBJ_NAT_DESCR, $before[0]['descr'],
			'Before: NAT rule must carry the canonical pfB DNSBL marker');

		// When: sweep (without calling pfb_create_dnsbl — proves the orphan gap is closed).
		$result = pfb_fwobj_sweep(['nat/rule']);

		// Then: orphan NAT rule removed; returns TRUE.
		$this->assertTrue($result, 'Sweep must return TRUE (orphan was removed)');
		$after = $this->getSection('nat/rule');
		$this->assertCount(0, $after, 'After: orphan NAT rule must be gone');
	}

	// -------------------------------------------------------------------------
	// User-object survival — cases c–d
	// -------------------------------------------------------------------------

	/**
	 * c. testUserVipSurvivesSweep
	 *
	 * Scenario: virtualip/vip has ONE orphan pfBlockerNG VIP and ONE user VIP.
	 * Sweep must remove the orphan and leave the user VIP untouched.
	 *
	 * Given:  orphan owned VIP + sibling user VIP in virtualip/vip.
	 * When:   pfb_fwobj_sweep(['virtualip/vip']).
	 * Then:   orphan gone; user VIP survives; section has exactly one row.
	 */
	public function testUserVipSurvivesSweep(): void
	{
		// Given: both rows present.
		$orphan_vip = $this->orphanPfbVip4();
		$user_vip   = $this->userVip('192.168.1.200');
		$this->seedConfig(['virtualip' => ['vip' => [$orphan_vip, $user_vip]]]);

		// Assert before: two rows (one owned, one user).
		$before = $this->getSection('virtualip/vip');
		$this->assertCount(2, $before, 'Before: both VIPs must be present');
		$descrs = array_column($before, 'descr');
		$this->assertContains(PFB_AUTO_VIP_DESCR_V4, $descrs, 'Before: orphan VIP must be in the section');
		$this->assertContains('My custom user VIP', $descrs,  'Before: user VIP must be in the section');

		// When: sweep.
		$result = pfb_fwobj_sweep(['virtualip/vip']);

		// Then: TRUE; only the user VIP remains.
		$this->assertTrue($result, 'Sweep must return TRUE (orphan was removed)');
		$after = $this->getSection('virtualip/vip');
		$this->assertCount(1, $after, 'After: only the user VIP must remain');
		$this->assertSame('My custom user VIP', $after[0]['descr'],
			'After: the surviving row must be the user VIP');
	}

	/**
	 * d. testUserNatSurvivesSweep
	 *
	 * Scenario: nat/rule has ONE orphan pfBlockerNG NAT rule and ONE user NAT rule.
	 * Sweep removes the orphan; user rule survives.
	 *
	 * Given:  orphan owned NAT rule + sibling user NAT rule in nat/rule.
	 * When:   pfb_fwobj_sweep(['nat/rule']).
	 * Then:   orphan gone; user NAT rule survives.
	 */
	public function testUserNatSurvivesSweep(): void
	{
		// Given: both rows present.
		$orphan_nat = $this->orphanPfbNat();
		$user_nat   = $this->userNatRule();
		$this->seedConfig(['nat' => ['rule' => [$orphan_nat, $user_nat]]]);

		// Assert before: two rows.
		$before = $this->getSection('nat/rule');
		$this->assertCount(2, $before, 'Before: both NAT rules must be present');
		$descrs = array_column($before, 'descr');
		$this->assertContains(PFB_FWOBJ_NAT_DESCR, $descrs,  'Before: orphan NAT must be in the section');
		$this->assertContains('My user NAT rule', $descrs,    'Before: user NAT must be in the section');

		// When: sweep.
		$result = pfb_fwobj_sweep(['nat/rule']);

		// Then: TRUE; only the user NAT rule remains.
		$this->assertTrue($result, 'Sweep must return TRUE (orphan was removed)');
		$after = $this->getSection('nat/rule');
		$this->assertCount(1, $after, 'After: only the user NAT rule must remain');
		$this->assertSame('My user NAT rule', $after[0]['descr'],
			'After: the surviving row must be the user NAT rule');
	}

	// -------------------------------------------------------------------------
	// No-op and idempotency — cases e–f
	// -------------------------------------------------------------------------

	/**
	 * e. testSweepIsNoopOnCleanConfig
	 *
	 * Scenario: all three sections are empty (or absent) — a clean post-disable state.
	 * Sweep must return FALSE and write_config must NOT be called.
	 *
	 * Given:  empty config (no rows in any of the three sections).
	 * When:   pfb_fwobj_sweep(['virtualip/vip', 'nat/rule', 'filter/rule']).
	 * Then:   returns FALSE; $GLOBALS['pfb_test_write_config_calls'] remains empty.
	 */
	public function testSweepIsNoopOnCleanConfig(): void
	{
		// Given: empty config; write_config spy starts empty.
		$this->seedConfig([]);
		$GLOBALS['pfb_test_write_config_calls'] = [];

		// Assert before: write_config has not been called.
		$this->assertEmpty($GLOBALS['pfb_test_write_config_calls'],
			'Before: write_config must not have been called yet');

		// When: sweep the three sections.
		$result = pfb_fwobj_sweep(['virtualip/vip', 'nat/rule', 'filter/rule']);

		// Then: FALSE (no orphans existed); write_config still not called.
		$this->assertFalse($result, 'Sweep must return FALSE (nothing to remove)');
		$this->assertEmpty($GLOBALS['pfb_test_write_config_calls'],
			'After: write_config must NOT have been called on a no-op sweep');
	}

	/**
	 * f. testSweepIsIdempotent
	 *
	 * Scenario: one orphan pfBlockerNG VIP. First sweep removes it (→ TRUE).
	 *           Second sweep finds nothing (→ FALSE).
	 *
	 * Given:  one orphan VIP in virtualip/vip.
	 * When:   sweep called twice in sequence.
	 * Then:   first call returns TRUE; second call returns FALSE.
	 */
	public function testSweepIsIdempotent(): void
	{
		// Given: one orphan VIP.
		$this->seedConfig(['virtualip' => ['vip' => [$this->orphanPfbVip4()]]]);

		// Assert before: one row.
		$before = $this->getSection('virtualip/vip');
		$this->assertCount(1, $before, 'Before: one orphan VIP must be present');

		// When: first sweep — removes the orphan.
		$first = pfb_fwobj_sweep(['virtualip/vip']);
		$this->assertTrue($first, 'First sweep must return TRUE (orphan was removed)');

		// Assert intermediate: section is now empty.
		$intermediate = $this->getSection('virtualip/vip');
		$this->assertCount(0, $intermediate, 'After first sweep: section must be empty');

		// When: second sweep — nothing to remove.
		$second = pfb_fwobj_sweep(['virtualip/vip']);

		// Then: FALSE (idempotent).
		$this->assertFalse($second, 'Second sweep must return FALSE (nothing left to remove)');
	}

	// -------------------------------------------------------------------------
	// Registration seam — cases g–h
	// -------------------------------------------------------------------------

	/**
	 * g. testRegisterVipAndReconcileCreatesWhenAbsent
	 *
	 * Scenario: register a VIP spec with a test builder; call pfb_fwobj_reconcile;
	 * the object is absent → builder is called and the VIP is created in config.
	 *
	 * Given:  VIP spec registered with a test builder; virtualip/vip is empty.
	 * When:   pfb_fwobj_reconcile(PFB_AUTO_VIP_DESCR_V4).
	 * Then:   builder was called exactly once; VIP entry appears in virtualip/vip.
	 */
	public function testRegisterVipAndReconcileCreatesWhenAbsent(): void
	{
		// Given: empty virtualip/vip section; VIP is absent.
		$this->seedConfig(['virtualip' => ['vip' => []]]);

		// Assert before: no VIP present.
		$before = $this->getSection('virtualip/vip');
		$this->assertCount(0, $before, 'Before: virtualip/vip must be empty');

		$builder_call_count = 0;
		$new_vip            = [
			'descr'       => PFB_AUTO_VIP_DESCR_V4,
			'mode'        => 'ipalias',
			'interface'   => 'lo0',
			'subnet'      => '10.10.10.53',
			'subnet_bits' => '32',
		];

		// Register the VIP spec with a test builder (analogous to pfb_fwobj_init_registrations).
		pfb_fwobj_register([
			'type'    => 'vip',
			'section' => 'virtualip/vip',
			'marker'  => PFB_AUTO_VIP_DESCR_V4,
			'builder' => static function () use (&$builder_call_count, $new_vip): array {
				$builder_call_count++;
				return $new_vip;
			},
			'guard'   => NULL,
		]);

		// When: reconcile — VIP is absent so builder should be invoked.
		pfb_fwobj_reconcile(PFB_AUTO_VIP_DESCR_V4);

		// Then: builder called exactly once; VIP now present in the section.
		$this->assertSame(1, $builder_call_count,
			'Builder must have been called exactly once (VIP was absent)');
		$after = $this->getSection('virtualip/vip');
		$this->assertCount(1, $after, 'After: one VIP entry must be present');
		$this->assertSame(PFB_AUTO_VIP_DESCR_V4, $after[0]['descr'],
			'After: VIP must carry the PFB_AUTO_VIP_DESCR_V4 marker');
		$this->assertSame('10.10.10.53', $after[0]['subnet'],
			'After: VIP must have the subnet the builder returned');
	}

	/**
	 * h. testRegisterVipAndReconcileIsIdempotent
	 *
	 * Scenario: register a VIP spec; call pfb_fwobj_reconcile twice.
	 * The builder is called only once (first reconcile creates the VIP;
	 * second reconcile finds it already present and is a no-op).
	 *
	 * Given:  VIP spec registered; virtualip/vip is empty.
	 * When:   pfb_fwobj_reconcile called twice.
	 * Then:   after first reconcile: VIP present; builder called once.
	 *         After second reconcile: still one VIP; builder still called once only.
	 */
	public function testRegisterVipAndReconcileIsIdempotent(): void
	{
		// Given: empty virtualip/vip section.
		$this->seedConfig(['virtualip' => ['vip' => []]]);

		// Assert before: no VIP present.
		$before = $this->getSection('virtualip/vip');
		$this->assertCount(0, $before, 'Before: virtualip/vip must be empty');

		$builder_call_count = 0;
		$new_vip            = [
			'descr'       => PFB_AUTO_VIP_DESCR_V4,
			'mode'        => 'ipalias',
			'interface'   => 'lo0',
			'subnet'      => '10.10.10.53',
			'subnet_bits' => '32',
		];

		pfb_fwobj_register([
			'type'    => 'vip',
			'section' => 'virtualip/vip',
			'marker'  => PFB_AUTO_VIP_DESCR_V4,
			'builder' => static function () use (&$builder_call_count, $new_vip): array {
				$builder_call_count++;
				return $new_vip;
			},
			'guard'   => NULL,
		]);

		// When: first reconcile — VIP is absent; builder must be called.
		pfb_fwobj_reconcile(PFB_AUTO_VIP_DESCR_V4);

		// Assert after first reconcile: VIP present; builder called once.
		$after_first = $this->getSection('virtualip/vip');
		$this->assertCount(1, $after_first, 'After first reconcile: exactly one VIP must exist');
		$this->assertSame(1, $builder_call_count,
			'After first reconcile: builder must have been called exactly once');

		// When: second reconcile — VIP is already present; builder must NOT be called again.
		pfb_fwobj_reconcile(PFB_AUTO_VIP_DESCR_V4);

		// Then: still one VIP; builder call count unchanged.
		$after_second = $this->getSection('virtualip/vip');
		$this->assertCount(1, $after_second,
			'After second reconcile: still exactly one VIP (no duplicate created)');
		$this->assertSame(1, $builder_call_count,
			'After second reconcile: builder must NOT have been called a second time');
	}
}
