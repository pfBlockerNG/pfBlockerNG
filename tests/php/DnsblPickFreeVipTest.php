<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_pick_free_dnsbl_vip() (ADR-13 / issue #487) — the conflict-aware picker that
 * walks pfb_dnsbl_vip_candidates() and returns the first address free of VIP/subnet
 * conflicts.
 *
 * Scenario A (control): no existing VIPs, no configured subnets
 *   Given  the VIP list is empty and no subnets are seeded
 *   When   pfb_pick_free_dnsbl_vip(AF_INET, 'lan') is called
 *   Then   it returns '10.10.10.53' (the back-compat preferred address)
 *
 * Scenario B (regression — issue #487): a common 10.0.0.0/8 LAN occupies the
 *   entire primary 10.10.X.53 sweep
 *   Given  all candidates in 10.0.0.0/8 conflict (seeded subnet)
 *     AND  the existing-VIP list is empty
 *   When   pfb_pick_free_dnsbl_vip(AF_INET, 'lan') is called
 *   Then   it returns a NON-null address that lies outside 10.0.0.0/8
 *     AND  does NOT return null (proving the disjoint fallbacks are reachable)
 *
 * Scenario C (unknown family): non-IP family → null
 */
#[CoversFunction('pfb_pick_free_dnsbl_vip')]
final class DnsblPickFreeVipTest extends TestCase
{
	protected function setUp(): void
	{
		// Start each test with an empty VIP list and no subnet seed.
		unset($GLOBALS['pfb_test_vip_list']);
		unset($GLOBALS['pfb_test_configured_subnets']);
	}

	protected function tearDown(): void
	{
		// Ensure no state leaks to sibling tests.
		unset($GLOBALS['pfb_test_vip_list']);
		unset($GLOBALS['pfb_test_configured_subnets']);
	}

	// ---------- Scenario A — control ----------

	public function testV4_NoConflicts_ReturnsPreferredAddress(): void
	{
		// Given: empty VIP list, no subnet seed.
		// (globals are already unset in setUp)

		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan');

		// Then: back-compat preferred address is chosen.
		$this->assertSame('10.10.10.53', $result,
			'With no conflicts the picker must return the back-compat preferred address');
	}

	// ---------- Scenario B — regression pin for issue #487 ----------

	public function testV4_Common10Slash8LanConflict_ReturnsDisjointFallback(): void
	{
		// Given: the entire 10.0.0.0/8 aggregate is occupied — every 10.10.X.53 candidate
		// from the primary sweep will be reported as conflicting by where_is_ipaddr_configured.
		// Before the fix, the pool had NO candidates outside 10/8 so the picker returned null.

		// Assert the before-state: without seeding the subnet, the preferred address is returned
		// (proves the seeded run actually changes the outcome).
		$before = pfb_pick_free_dnsbl_vip(AF_INET, 'lan');
		$this->assertSame('10.10.10.53', $before,
			'Pre-condition: without subnet seed the picker must return the preferred address');

		// Now seed the 10/8 aggregate as occupied.
		$GLOBALS['pfb_test_configured_subnets'] = ['10.0.0.0/8'];

		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan');

		// Then: result must be non-null — the disjoint fallbacks provide an escape hatch.
		$this->assertNotNull($result,
			'With the entire 10/8 occupied the picker must NOT return null; '
			. 'disjoint fallbacks (e.g. 172.31.255.53, 192.0.2.53) must be reachable. '
			. 'This is the exact regression pinned by issue #487.');

		// And the chosen address must actually lie outside 10.0.0.0/8.
		$long       = ip2long($result);
		$net_start  = ip2long('10.0.0.0');
		$net_end    = ip2long('10.255.255.255');
		$this->assertIsInt($long, "picker result '{$result}' must be a parseable IPv4 address");
		$this->assertTrue($long < $net_start || $long > $net_end,
			"picker result '{$result}' must lie outside 10.0.0.0/8 — it is still inside the conflicting aggregate");

		// Confirm the result is one of the documented disjoint fallbacks.
		$expected_fallbacks = ['172.31.255.53', '172.31.254.53', '192.0.2.53', '198.51.100.53', '203.0.113.53', '100.64.0.53'];
		$this->assertContains($result, $expected_fallbacks,
			"picker result '{$result}' should be one of the disjoint fallbacks: " . implode(', ', $expected_fallbacks));
	}

	// ---------- Scenario C — unknown family ----------

	public function testUnknownFamily_ReturnsNull(): void
	{
		$this->assertNull(pfb_pick_free_dnsbl_vip(0, 'lan'));
		$this->assertNull(pfb_pick_free_dnsbl_vip(AF_UNIX, 'lan'));
	}
}
