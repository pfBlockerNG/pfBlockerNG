<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-35 Phase 2 — unit tests for the new pfblockerng_fwobj.inc ownership/marker layer.
 *
 * Functions under test:
 *   - pfb_fwobj_is_owned()     — ownership predicate (truth table)
 *   - pfb_fwobj_find()         — locate first owned row matching a marker
 *   - pfb_fwobj_remove()       — strip owned rows matching a marker
 *   - pfb_fwobj_sweep()        — remove all owned rows from a set of sections
 *   - pfb_fwobj_register()     — register a firewall-object spec
 *   - pfb_fwobj_reconcile()    — ensure a registered object exists (idempotent)
 *
 * Coverage mandate (CLAUDE.md):
 *   - Every branch exercised (both sides of every conditional).
 *   - Transition tests assert BEFORE state before mutating (no false passes).
 *   - Complex flows use BDD-style Given/When/Then comments.
 */
#[CoversFunction('pfb_fwobj_is_owned')]
#[CoversFunction('pfb_fwobj_find')]
#[CoversFunction('pfb_fwobj_remove')]
#[CoversFunction('pfb_fwobj_sweep')]
#[CoversFunction('pfb_fwobj_register')]
#[CoversFunction('pfb_fwobj_reconcile')]
final class FwobjLayerTest extends TestCase
{
	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Seed $GLOBALS['config'] so config_get_path() and config_set_path() work
	 * in each test. Accepts multiple sections by key.
	 *
	 * @param array<string,array<int,array<string,mixed>>> $sections  e.g. ['virtualip' => ['vip' => [...]]]
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

	/** A pfBlockerNG auto-managed v4 VIP (uses PFB_AUTO_VIP_DESCR_V4). */
	private function pfbVip4(string $subnet = '10.10.10.53'): array
	{
		return [
			'descr'       => PFB_AUTO_VIP_DESCR_V4,	// 'pfB_AUTO_VIP_v4'
			'mode'        => 'ipalias',
			'interface'   => 'lo0',
			'subnet'      => $subnet,
			'subnet_bits' => '32',
		];
	}

	/** A pfBlockerNG-owned NAT rule with the canonical full marker. */
	private function pfbNatRule(string $descr = PFB_FWOBJ_NAT_DESCR): array
	{
		return [
			'descr'      => $descr,
			'protocol'   => 'tcp',
			'interface'  => 'opt1',
			'target'     => '127.0.0.1',
			'local-port' => '8081',
		];
	}

	/** A user-owned NAT rule with no pfBlockerNG marker. */
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

	/** A pfBlockerNG-owned filter rule using the pfB_ prefix. */
	private function pfbFilterRule(string $descr = 'pfB_Deny_v4'): array
	{
		return [
			'descr'     => $descr,
			'type'      => 'block',
			'interface' => 'wan',
		];
	}

	/** A user-owned filter rule with no pfBlockerNG prefix. */
	private function userFilterRule(): array
	{
		return [
			'descr'     => 'Allow LAN to WAN',
			'type'      => 'pass',
			'interface' => 'lan',
		];
	}

	// -------------------------------------------------------------------------
	// Teardown: reset registry between tests
	// -------------------------------------------------------------------------

	protected function setUp(): void
	{
		// Clear the static registry via an empty register cycle is not possible
		// without a reset helper, so we seed it clean by populating then wiping:
		// pfb_fwobj_registry() returns a reference — clear it directly.
		$registry = &pfb_fwobj_registry();
		$registry = [];
	}

	// -------------------------------------------------------------------------
	// is_owned truth table (cases a–i)
	// -------------------------------------------------------------------------

	/**
	 * a. A description starting with 'pfB_' is owned (new prefix rule).
	 */
	public function testIsOwnedNewPfbPrefix(): void
	{
		$this->assertTrue(pfb_fwobj_is_owned('pfB_MyRule'));
	}

	/**
	 * b. PFB_AUTO_VIP_DESCR_V4 ('pfB_AUTO_VIP_v4') is owned — starts with 'pfB_'.
	 */
	public function testIsOwnedVipV4Marker(): void
	{
		$this->assertTrue(pfb_fwobj_is_owned(PFB_AUTO_VIP_DESCR_V4));
	}

	/**
	 * c. PFB_AUTO_VIP_DESCR_V6 ('pfB_AUTO_VIP_v6') is owned — starts with 'pfB_'.
	 */
	public function testIsOwnedVipV6Marker(): void
	{
		$this->assertTrue(pfb_fwobj_is_owned(PFB_AUTO_VIP_DESCR_V6));
	}

	/**
	 * d. The canonical NAT marker 'pfB DNSBL - DO NOT EDIT' is owned (contains 'pfB DNSBL').
	 */
	public function testIsOwnedNatFullDescr(): void
	{
		$this->assertTrue(pfb_fwobj_is_owned(PFB_FWOBJ_NAT_DESCR));
	}

	/**
	 * e. The bare legacy prefix 'pfB DNSBL' is owned.
	 */
	public function testIsOwnedNatLegacyPrefix(): void
	{
		$this->assertTrue(pfb_fwobj_is_owned(PFB_FWOBJ_NAT_LEGACY_PFX));
	}

	/**
	 * f. A legacy NAT variant 'pfB DNSBL Redirect' is owned (contains 'pfB DNSBL').
	 */
	public function testIsOwnedNatLegacyVariant(): void
	{
		$this->assertTrue(pfb_fwobj_is_owned('pfB DNSBL Redirect'));
	}

	/**
	 * g. A plain user description returns FALSE.
	 */
	public function testIsOwnedReturnsFalseForUserDescr(): void
	{
		$this->assertFalse(pfb_fwobj_is_owned('My custom rule'));
	}

	/**
	 * h. An empty description returns FALSE.
	 */
	public function testIsOwnedReturnsFalseForEmpty(): void
	{
		$this->assertFalse(pfb_fwobj_is_owned(''));
	}

	/**
	 * i. A partial match 'pfB' (no trailing _ and no space DNSBL) returns FALSE.
	 *    Guards that neither 'pfB_' nor 'pfB DNSBL' matches bare 'pfB'.
	 */
	public function testIsOwnedReturnsFalseForPartialMatch(): void
	{
		$this->assertFalse(pfb_fwobj_is_owned('pfB'));
	}

	// -------------------------------------------------------------------------
	// find/remove with and without guard (cases j–p)
	// -------------------------------------------------------------------------

	/**
	 * j. pfb_fwobj_find returns the marked row when it is present.
	 *
	 * Scenario: two-row VIP section — one pfBlockerNG row, one user row.
	 * Given: two rows are present.
	 * When:  pfb_fwobj_find is called with the pfB_ marker.
	 * Then:  the pfBlockerNG row is returned; the user row is NOT returned.
	 */
	public function testFindReturnsMatchedRow(): void
	{
		// Given: two rows present.
		$vip4 = $this->pfbVip4();
		$user = $this->userVip();
		$this->seedConfig(['virtualip' => ['vip' => [$vip4, $user]]]);

		// Sanity: both rows are present before the find.
		$rows = $this->getSection('virtualip/vip');
		$this->assertCount(2, $rows, 'Before: both rows must be present');

		// When: find by the pfB_AUTO_VIP_v4 marker.
		$result = pfb_fwobj_find('virtualip/vip', PFB_AUTO_VIP_DESCR_V4);

		// Then: the pfBlockerNG row is returned.
		$this->assertIsArray($result);
		$this->assertSame(PFB_AUTO_VIP_DESCR_V4, $result['descr']);
		$this->assertSame('10.10.10.53', $result['subnet']);
	}

	/**
	 * k. pfb_fwobj_find returns FALSE when no owned row matches the marker.
	 *
	 * Scenario: section contains only a user row — no pfBlockerNG rows.
	 * Given:  one user row.
	 * When:   pfb_fwobj_find with a pfB_ marker.
	 * Then:   returns FALSE.
	 */
	public function testFindReturnsFalseWhenAbsent(): void
	{
		// Given: only a user row.
		$this->seedConfig(['virtualip' => ['vip' => [$this->userVip()]]]);

		// When/Then: no owned row → FALSE.
		$result = pfb_fwobj_find('virtualip/vip', PFB_AUTO_VIP_DESCR_V4);
		$this->assertFalse($result);
	}

	/**
	 * l. pfb_fwobj_find with a guard skips rows the guard rejects.
	 *
	 * Scenario: two rows with the same pfB_ marker but different subnets;
	 *           guard accepts only the row with subnet '10.10.10.53'.
	 * Given:  two pfBlockerNG rows (10.10.10.53 and 10.10.10.54).
	 * When:   pfb_fwobj_find with a guard accepting only '10.10.10.53'.
	 * Then:   only the '10.10.10.53' row is returned.
	 */
	public function testFindWithGuardSkipsNonMatchingGuard(): void
	{
		// Given: two pfBlockerNG rows.
		$vip_a = $this->pfbVip4('10.10.10.53');
		$vip_b = $this->pfbVip4('10.10.10.54');
		$this->seedConfig(['virtualip' => ['vip' => [$vip_a, $vip_b]]]);

		// Sanity: two rows present.
		$this->assertCount(2, $this->getSection('virtualip/vip'));

		// When: find with guard that accepts only '10.10.10.53'.
		$result = pfb_fwobj_find(
			'virtualip/vip',
			PFB_AUTO_VIP_DESCR_V4,
			static fn(array $row): bool => ($row['subnet'] ?? '') === '10.10.10.53'
		);

		// Then: returns the '10.10.10.53' row, not '10.10.10.54'.
		$this->assertIsArray($result);
		$this->assertSame('10.10.10.53', $result['subnet']);
	}

	/**
	 * m. pfb_fwobj_remove deletes the owned row and leaves the user row intact.
	 *
	 * Scenario: one owned NAT rule + one user NAT rule.
	 * Given:  both rows present.
	 * When:   remove with the canonical NAT marker.
	 * Then:   owned row gone; user row survives; returns TRUE.
	 */
	public function testRemoveDeletesOwnedRow(): void
	{
		// Given: both rows present.
		$pfb  = $this->pfbNatRule();
		$user = $this->userNatRule();
		$this->seedConfig(['nat' => ['rule' => [$pfb, $user]]]);

		// Assert before: two rows.
		$before = $this->getSection('nat/rule');
		$this->assertCount(2, $before, 'Before: two NAT rules must be present');

		// When: remove the pfBlockerNG NAT rule.
		$result = pfb_fwobj_remove('nat/rule', PFB_FWOBJ_NAT_DESCR);

		// Then: returns TRUE, only the user row remains.
		$this->assertTrue($result);
		$after = $this->getSection('nat/rule');
		$this->assertCount(1, $after, 'After: only the user rule must remain');
		$this->assertSame('My user NAT rule', $after[0]['descr']);
	}

	/**
	 * n. pfb_fwobj_remove returns FALSE and does not write when no row matches.
	 *
	 * Scenario: section has only a user row.
	 * Given:  one user row.
	 * When:   remove with a pfBlockerNG marker.
	 * Then:   returns FALSE; section unchanged.
	 */
	public function testRemoveReturnsFalseWhenNothingMatches(): void
	{
		// Given: only a user row.
		$this->seedConfig(['nat' => ['rule' => [$this->userNatRule()]]]);

		// Assert before: one user row.
		$before = $this->getSection('nat/rule');
		$this->assertCount(1, $before, 'Before: one user rule must be present');

		// When: remove with a pfBlockerNG marker that is not present.
		$result = pfb_fwobj_remove('nat/rule', PFB_FWOBJ_NAT_DESCR);

		// Then: FALSE; the user row is untouched.
		$this->assertFalse($result);
		$after = $this->getSection('nat/rule');
		$this->assertCount(1, $after, 'After: user rule must still be present');
		$this->assertSame('My user NAT rule', $after[0]['descr']);
	}

	/**
	 * o. pfb_fwobj_remove NEVER removes a user-owned row.
	 *
	 * Scenario: only a user row in the section — no pfBlockerNG marker present.
	 * Passing the pfB_ marker must not touch the user row.
	 */
	public function testRemoveNeverTouchesUserRow(): void
	{
		// Given: only user row.
		$this->seedConfig(['virtualip' => ['vip' => [$this->userVip()]]]);

		$before = $this->getSection('virtualip/vip');
		$this->assertCount(1, $before, 'Before: one user VIP must be present');

		// When/Then: remove with a pfB_ marker → FALSE; user row untouched.
		$result = pfb_fwobj_remove('virtualip/vip', PFB_AUTO_VIP_DESCR_V4);
		$this->assertFalse($result);

		$after = $this->getSection('virtualip/vip');
		$this->assertCount(1, $after, 'After: user VIP must still be present');
		$this->assertSame('My custom user VIP', $after[0]['descr']);
	}

	/**
	 * p. pfb_fwobj_remove with a guard removes only the row matching the guard.
	 *
	 * Scenario: two owned rows with the same pfB_ marker but different subnets.
	 *           Guard accepts only subnet '10.10.10.53' → only that row is removed.
	 * Given:  both pfBlockerNG rows present.
	 * When:   remove with guard accepting only '10.10.10.53'.
	 * Then:   '10.10.10.53' row gone; '10.10.10.54' row survives.
	 */
	public function testRemoveWithGuard(): void
	{
		// Given: two pfBlockerNG rows.
		$vip_a = $this->pfbVip4('10.10.10.53');
		$vip_b = $this->pfbVip4('10.10.10.54');
		$this->seedConfig(['virtualip' => ['vip' => [$vip_a, $vip_b]]]);

		// Assert before: two rows.
		$before = $this->getSection('virtualip/vip');
		$this->assertCount(2, $before, 'Before: two pfBlockerNG VIPs must be present');

		// When: remove with guard accepting only '10.10.10.53'.
		$result = pfb_fwobj_remove(
			'virtualip/vip',
			PFB_AUTO_VIP_DESCR_V4,
			static fn(array $row): bool => ($row['subnet'] ?? '') === '10.10.10.53'
		);

		// Then: TRUE; only '10.10.10.54' survives.
		$this->assertTrue($result);
		$after = $this->getSection('virtualip/vip');
		$this->assertCount(1, $after, 'After: one VIP must remain');
		$this->assertSame('10.10.10.54', $after[0]['subnet']);
	}

	// -------------------------------------------------------------------------
	// sweep (cases q–s)
	// -------------------------------------------------------------------------

	/**
	 * q. pfb_fwobj_sweep removes all owned rows across multiple sections, leaving
	 *    user rows intact.
	 *
	 * Scenario: virtualip/vip (one pfB row + one user row) and
	 *           nat/rule (one pfB row + one user row).
	 * Given:  both sections contain mixed owned and user rows.
	 * When:   sweep(['virtualip/vip', 'nat/rule']).
	 * Then:   all owned rows removed; all user rows survive; returns TRUE.
	 */
	public function testSweepRemovesAllOwnedRows(): void
	{
		// Given: mixed rows in two sections.
		$this->seedConfig([
			'virtualip' => ['vip'  => [$this->pfbVip4(), $this->userVip()]],
			'nat'       => ['rule' => [$this->pfbNatRule(), $this->userNatRule()]],
		]);

		// Assert before: two rows in each section.
		$this->assertCount(2, $this->getSection('virtualip/vip'), 'Before VIP: two rows');
		$this->assertCount(2, $this->getSection('nat/rule'),      'Before NAT: two rows');

		// When: sweep both sections.
		$result = pfb_fwobj_sweep(['virtualip/vip', 'nat/rule']);

		// Then: TRUE; owned rows gone; user rows survive.
		$this->assertTrue($result);
		$vips = $this->getSection('virtualip/vip');
		$nats = $this->getSection('nat/rule');
		$this->assertCount(1, $vips, 'After VIP: only user row remains');
		$this->assertSame('My custom user VIP', $vips[0]['descr']);
		$this->assertCount(1, $nats, 'After NAT: only user row remains');
		$this->assertSame('My user NAT rule', $nats[0]['descr']);
	}

	/**
	 * r. pfb_fwobj_sweep returns FALSE and writes nothing when all sections are clean.
	 *
	 * Scenario: empty config — no rows in any section.
	 * Given:  empty config.
	 * When:   sweep with two section paths.
	 * Then:   returns FALSE; config remains empty.
	 */
	public function testSweepIsNoopOnCleanConfig(): void
	{
		// Given: empty config.
		$this->seedConfig([]);

		// When: sweep on non-existent / empty sections.
		$result = pfb_fwobj_sweep(['virtualip/vip', 'nat/rule']);

		// Then: FALSE.
		$this->assertFalse($result);
	}

	/**
	 * s. pfb_fwobj_sweep is idempotent — the second call returns FALSE.
	 *
	 * Scenario: one pfBlockerNG VIP. First sweep removes it and returns TRUE.
	 *           Second sweep finds nothing and returns FALSE.
	 * Given:  one pfBlockerNG VIP.
	 * When:   sweep twice.
	 * Then:   first call → TRUE; second call → FALSE.
	 */
	public function testSweepIsIdempotent(): void
	{
		// Given: one pfBlockerNG VIP.
		$this->seedConfig(['virtualip' => ['vip' => [$this->pfbVip4()]]]);

		// Assert before: one row.
		$before = $this->getSection('virtualip/vip');
		$this->assertCount(1, $before, 'Before: one owned VIP must be present');

		// When: first sweep — removes it.
		$first = pfb_fwobj_sweep(['virtualip/vip']);
		$this->assertTrue($first, 'First sweep must return TRUE (removed something)');

		// When: second sweep — nothing to remove.
		$second = pfb_fwobj_sweep(['virtualip/vip']);
		$this->assertFalse($second, 'Second sweep must return FALSE (nothing left)');
	}

	// -------------------------------------------------------------------------
	// register / reconcile (cases t–u)
	// -------------------------------------------------------------------------

	/**
	 * t. pfb_fwobj_reconcile creates the object via the builder when absent.
	 *
	 * Scenario: register a spec for a pfB_ filter rule; rule is absent from config.
	 * Given:  spec registered; filter/rule section is empty.
	 * When:   pfb_fwobj_reconcile called.
	 * Then:   builder was called; rule now present in config.
	 */
	public function testRegisterAndReconcileCreatesWhenAbsent(): void
	{
		// Given: empty filter/rule section.
		$this->seedConfig(['filter' => ['rule' => []]]);

		// Assert before: no rules.
		$before = $this->getSection('filter/rule');
		$this->assertCount(0, $before, 'Before: no filter rules must exist');

		$builder_called = FALSE;
		$new_rule       = $this->pfbFilterRule('pfB_Deny_v4');

		pfb_fwobj_register([
			'type'    => 'filter',
			'section' => 'filter/rule',
			'marker'  => 'pfB_Deny_v4',
			'builder' => static function () use (&$builder_called, $new_rule): array {
				$builder_called = TRUE;
				return $new_rule;
			},
			'guard' => NULL,
		]);

		// When: reconcile.
		pfb_fwobj_reconcile('pfB_Deny_v4');

		// Then: builder was called; rule is now in the section.
		$this->assertTrue($builder_called, 'Builder must have been called (object was absent)');
		$after = $this->getSection('filter/rule');
		$this->assertCount(1, $after, 'After: one filter rule must be present');
		$this->assertSame('pfB_Deny_v4', $after[0]['descr']);
	}

	/**
	 * u. pfb_fwobj_reconcile is idempotent — the builder is NOT called when the
	 *    object already exists.
	 *
	 * Scenario: register a spec for a pfB_ filter rule; rule is already present.
	 * Given:  spec registered; filter/rule already contains the rule.
	 * When:   pfb_fwobj_reconcile called.
	 * Then:   builder was NOT called; config unchanged (still one rule).
	 */
	public function testReconcileIsIdempotentWhenPresent(): void
	{
		// Given: rule already present.
		$existing_rule = $this->pfbFilterRule('pfB_Deny_v4');
		$this->seedConfig(['filter' => ['rule' => [$existing_rule]]]);

		// Assert before: one rule present.
		$before = $this->getSection('filter/rule');
		$this->assertCount(1, $before, 'Before: one filter rule must already exist');

		$builder_called = FALSE;

		pfb_fwobj_register([
			'type'    => 'filter',
			'section' => 'filter/rule',
			'marker'  => 'pfB_Deny_v4',
			'builder' => static function () use (&$builder_called): array {
				$builder_called = TRUE;
				return ['descr' => 'pfB_Deny_v4_NEW', 'type' => 'block'];
			},
			'guard' => NULL,
		]);

		// When: reconcile.
		pfb_fwobj_reconcile('pfB_Deny_v4');

		// Then: builder was NOT called; still exactly one rule.
		$this->assertFalse($builder_called, 'Builder must NOT be called (object already present)');
		$after = $this->getSection('filter/rule');
		$this->assertCount(1, $after, 'After: still exactly one filter rule');
		$this->assertSame('pfB_Deny_v4', $after[0]['descr'],
			'After: existing rule descr must be unchanged');
	}
}
