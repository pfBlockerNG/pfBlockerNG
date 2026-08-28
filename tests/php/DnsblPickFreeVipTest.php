<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_pick_free_dnsbl_vip() (ADR-13 / issue #473 / issue #487) — the conflict-aware
 * picker that walks pfb_dnsbl_vip_candidates() and returns the first address free of
 * VIP/subnet conflicts.
 *
 * Scenario A (control): no existing VIPs, no configured subnets
 *   Given  the VIP list is empty and no subnets are seeded
 *   When   pfb_pick_free_dnsbl_vip(AF_INET, 'lan') is called
 *   Then   it returns '172.16.53.53' (the first Class-B candidate)
 *
 * Scenario B: first candidate conflicts — skip to next
 *   Given  172.16.53.53 is a configured subnet
 *   When   pfb_pick_free_dnsbl_vip(AF_INET, 'lan') is called
 *   Then   it returns '192.168.53.53' (second candidate)
 *
 * Scenario B2: first two candidates conflict — fall to the tertiary
 *   Given  172.16/12 and 192.168/16 are occupied
 *   Then   it returns '10.53.53.53' (third/last candidate)
 *
 * Scenario C: all three candidates conflict — pool exhausted → null
 *   Given  172.16/12, 192.168/16, and 10/8 are all occupied
 *   When   pfb_pick_free_dnsbl_vip(AF_INET, 'lan') is called
 *   Then   it returns null (user must resolve manually)
 *
 * Scenario E (IPv6): the single ULA candidate is returned when free, and null
 *   when it is already a configured VIP (the user resolves the conflict manually)
 *
 * Scenario D (unknown family): non-IP family → null
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

	public function testV4_NoConflicts_ReturnsFirstCandidate(): void
	{
		// Given: empty VIP list, no subnet seed (globals unset in setUp).

		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan');

		// Then: Class-B first candidate is chosen (least-used RFC1918 on end-user LANs).
		$this->assertSame('172.16.53.53', $result,
			'With no conflicts the picker must return the first (Class-B) candidate');
	}

	// ---------- Scenario B — first candidate conflicts ----------

	public function testV4_FirstCandidateConflicts_ReturnsSecond(): void
	{
		// Given: before seeding the conflict the first candidate is returned.
		$before = pfb_pick_free_dnsbl_vip(AF_INET, 'lan');
		$this->assertSame('172.16.53.53', $before,
			'Pre-condition: without subnet seed the picker must return the first candidate');

		// Seed 172.16/12 as occupied.
		$GLOBALS['pfb_test_configured_subnets'] = ['172.16.0.0/12'];

		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan');

		// Then: second candidate (Class-C) is chosen.
		$this->assertSame('192.168.53.53', $result,
			"With 172.16/12 occupied the picker must skip to '192.168.53.53'. "
			. "Got: '{$result}'");
	}

	// ---------- Scenario C — all candidates conflict → null ----------

	public function testV4_FirstTwoCandidatesConflict_ReturnsThird(): void
	{
		// Given: 172.16/12 (Class B) and 192.168/16 (Class C) are both occupied.
		$GLOBALS['pfb_test_configured_subnets'] = ['172.16.0.0/12', '192.168.0.0/16'];

		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan');

		// Then: the Class-A tertiary candidate is chosen (last in the fixed list).
		$this->assertSame('10.53.53.53', $result,
			"With 172.16/12 and 192.168/16 occupied the picker must fall to the Class-A '10.53.53.53'. "
			. "Got: '{$result}'");
	}

	public function testV4_AllCandidatesConflict_ReturnsNull(): void
	{
		// Given: all three RFC1918 ranges are occupied simultaneously.
		$GLOBALS['pfb_test_configured_subnets'] = [
			'172.16.0.0/12',   // covers 172.16.53.53
			'192.168.0.0/16',  // covers 192.168.53.53
			'10.0.0.0/8',      // covers 10.53.53.53
		];

		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan');

		// Then: pool exhausted → null; user must set the VIP manually.
		$this->assertNull($result,
			'With all three RFC1918 ranges occupied the fixed pool is exhausted and the picker must return null');
	}

	// ---------- Scenario E — IPv6 single ULA candidate ----------

	public function testV6_NoConflicts_ReturnsUlaCandidate(): void
	{
		// Given: empty VIP list, no seed.
		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET6, 'lan');

		// Then: the single ULA candidate is returned.
		$this->assertSame('fd00:53:53:53:53:53:53:53', $result,
			'With no conflicts the v6 picker must return the single ULA candidate');
	}

	public function testV6_CandidateIsExistingVip_ReturnsNull(): void
	{
		// Given: before seeding, the ULA candidate is returned (transition pre-state).
		$before = pfb_pick_free_dnsbl_vip(AF_INET6, 'lan');
		$this->assertSame('fd00:53:53:53:53:53:53:53', $before,
			'Pre-condition: without a conflicting VIP the v6 picker returns the ULA candidate');

		// The single ULA candidate already exists as a configured VIP.
		$GLOBALS['pfb_test_vip_list'] = ['_vip6test' => 'fd00:53:53:53:53:53:53:53'];

		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET6, 'lan');

		// Then: no free candidate -> null -> the user resolves the ULA conflict manually.
		$this->assertNull($result,
			'With the sole ULA candidate already taken by a VIP the picker must return null');
	}

	// ---------- Scenario D — unknown family ----------

	public function testUnknownFamily_ReturnsNull(): void
	{
		$this->assertNull(pfb_pick_free_dnsbl_vip(0, 'lan'));
		$this->assertNull(pfb_pick_free_dnsbl_vip(AF_UNIX, 'lan'));
	}
}
