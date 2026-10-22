<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
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
 *
 * Scenario F (issue #3540): a given address is honoured only when it is one of the fixed candidates
 *   and passes the same free checks; any other string returns null, so a synced value from a peer
 *   can never become a VIP address
 *
 * Scenario G (issue #3565): VIPs are listed as pfSense lists them — get_configured_vip_list() gives
 *   bare addresses, get_specialnet() labels them "<address> (<descr>)" — and a VIP at a candidate
 *   address takes it, whatever case or zero padding its stored IPv6 text uses
 */
#[CoversFunction('pfb_pick_free_dnsbl_vip')]
final class DnsblPickFreeVipTest extends TestCase
{
	protected function setUp(): void
	{
		// Start each test with an empty VIP list and no subnet seed.
		unset($GLOBALS['pfb_test_vip_list']);
		unset($GLOBALS['pfb_test_specialnet']);
		unset($GLOBALS['pfb_test_configured_subnets']);
	}

	protected function tearDown(): void
	{
		// Ensure no state leaks to sibling tests.
		unset($GLOBALS['pfb_test_vip_list']);
		unset($GLOBALS['pfb_test_specialnet']);
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

	// ---------- Scenario F — issue #3540: a caller-given address ----------

	public function testV4_GivenCandidateIsFree_ReturnsThatCandidateNotTheFirst(): void
	{
		// Given: every candidate is free, so a plain pick would return the first one.
		$this->assertSame('172.16.53.53', pfb_pick_free_dnsbl_vip(AF_INET, 'lan'),
			'Pre-condition: without a given address the picker returns the first candidate');

		// When: a free candidate other than the first is given.
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan', '192.168.53.53');

		// Then: that candidate, not the first one.
		$this->assertSame('192.168.53.53', $result,
			'A free given candidate must be returned as is. Got: ' . var_export($result, TRUE));
	}

	public function testV4_GivenCandidateIsAnExistingVip_ReturnsNull(): void
	{
		// Given: the given candidate is free, so it is returned.
		$this->assertSame('192.168.53.53', pfb_pick_free_dnsbl_vip(AF_INET, 'lan', '192.168.53.53'),
			'Pre-condition: a free given candidate is returned');

		// When: an existing VIP takes that address.
		$GLOBALS['pfb_test_vip_list'] = ['_vipuser1' => '192.168.53.53'];
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan', '192.168.53.53');

		// Then: no fallback to another candidate; the caller must treat it as a conflict.
		$this->assertNull($result,
			'A given candidate taken by a VIP must return NULL, not another candidate. Got: ' . var_export($result, TRUE));
	}

	public function testV4_GivenCandidateOverlapsAConfiguredSubnet_ReturnsNull(): void
	{
		// Given: the given candidate is free, so it is returned.
		$this->assertSame('192.168.53.53', pfb_pick_free_dnsbl_vip(AF_INET, 'lan', '192.168.53.53'),
			'Pre-condition: a free given candidate is returned');

		// When: a configured subnet covers that address.
		$GLOBALS['pfb_test_configured_subnets'] = ['192.168.0.0/16'];
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan', '192.168.53.53');

		// Then: no fallback to another candidate.
		$this->assertNull($result,
			'A given candidate inside a configured subnet must return NULL. Got: ' . var_export($result, TRUE));
	}

	public function testV6_GivenCandidateIsFree_ReturnsIt(): void
	{
		$result = pfb_pick_free_dnsbl_vip(AF_INET6, 'lan', 'fd00:53:53:53:53:53:53:53');

		$this->assertSame('fd00:53:53:53:53:53:53:53', $result,
			'The free v6 candidate given must be returned. Got: ' . var_export($result, TRUE));
	}

	public function testV6_GivenCandidateIsAnExistingVip_ReturnsNull(): void
	{
		// Given: the v6 candidate is taken by an existing VIP.
		$GLOBALS['pfb_test_vip_list'] = ['_vip6user' => 'fd00:53:53:53:53:53:53:53'];

		$result = pfb_pick_free_dnsbl_vip(AF_INET6, 'lan', 'fd00:53:53:53:53:53:53:53');

		$this->assertNull($result,
			'A given v6 candidate taken by a VIP must return NULL. Got: ' . var_export($result, TRUE));
	}

	/** @return array<string,array{0:int,1:string}> */
	public static function nonCandidateAddresses(): array
	{
		return [
			'v4: routable address'              => [AF_INET, '203.0.113.5'],
			'v4: candidate with a prefix'       => [AF_INET, '172.16.53.53/12'],
			'v4: leading space'                 => [AF_INET, ' 172.16.53.53'],
			'v4: trailing newline'              => [AF_INET, "172.16.53.53\n"],
			'v4: zero-padded octets'            => [AF_INET, '172.016.053.053'],
			'v4: the v6 candidate'              => [AF_INET, 'fd00:53:53:53:53:53:53:53'],
			'v4: empty string'                  => [AF_INET, ''],
			'v6: upper-case candidate'          => [AF_INET6, 'FD00:53:53:53:53:53:53:53'],
			'v6: a v4 candidate'                => [AF_INET6, '172.16.53.53'],
			'v6: compressed form of the ULA'    => [AF_INET6, 'fd00:53::53'],
		];
	}

	#[DataProvider('nonCandidateAddresses')]
	public function testGivenNonCandidateAddress_ReturnsNull(int $family, string $address): void
	{
		// Given: every candidate is free (setUp seeds no VIP or subnet), so only the address itself can decide.
		$result = pfb_pick_free_dnsbl_vip($family, 'lan', $address);

		$this->assertNull($result,
			'A given address that is not a fixed candidate of its family must return NULL. Given: '
			. var_export($address, TRUE) . ', got: ' . var_export($result, TRUE));
	}

	// ---------- Scenario G — issue #3565: VIPs in pfSense's own shapes ----------

	public function testV4_FirstCandidateHeldByADescribedVip_ReturnsSecond(): void
	{
		// Given: before the VIP exists the first candidate is returned.
		$this->assertSame('172.16.53.53', pfb_pick_free_dnsbl_vip(AF_INET, 'lan'),
			'Pre-condition: without a VIP the picker returns the first candidate');

		// A described VIP holds 172.16.53.53, listed exactly as pfSense lists it.
		$GLOBALS['pfb_test_vip_list']   = ['_vipweb' => '172.16.53.53'];
		$GLOBALS['pfb_test_specialnet'] = ['172.16.53.53' => '172.16.53.53 (web server)'];

		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET, 'lan');

		// Then: the VIP's address is taken, so the second candidate is chosen.
		$this->assertSame('192.168.53.53', $result,
			'A VIP at 172.16.53.53 must make the picker skip to 192.168.53.53. Got: ' . var_export($result, TRUE));
	}

	/** @return array<string,array{0:string}> */
	public static function v6CandidateSpellings(): array
	{
		return [
			'as the candidate is written' => ['fd00:53:53:53:53:53:53:53'],
			'upper case'                  => ['FD00:53:53:53:53:53:53:53'],
			'zero-padded groups'          => ['fd00:0053:0053:0053:0053:0053:0053:0053'],
		];
	}

	#[DataProvider('v6CandidateSpellings')]
	public function testV6_CandidateHeldByAVipInAnySpelling_ReturnsNull(string $stored): void
	{
		// Given: before the VIP exists the ULA candidate is returned.
		$this->assertSame('fd00:53:53:53:53:53:53:53', pfb_pick_free_dnsbl_vip(AF_INET6, 'lan'),
			'Pre-condition: without a VIP the v6 picker returns the ULA candidate');

		// pfSense stores a VIP address as typed; this one is the ULA candidate.
		$GLOBALS['pfb_test_vip_list'] = ['_vip6user' => $stored];

		// When
		$result = pfb_pick_free_dnsbl_vip(AF_INET6, 'lan');

		// Then
		$this->assertNull($result,
			'A VIP stored as ' . var_export($stored, TRUE) . ' holds the ULA candidate. Got: ' . var_export($result, TRUE));
	}

	public function testVipsAtNeighbouringAddresses_DoNotTakeTheCandidates(): void
	{
		// Given: VIPs one digit away from each family's first candidate.
		$GLOBALS['pfb_test_vip_list'] = [
			'_vipa' => '172.16.53.5',
			'_vipb' => '172.16.53.54',
			'_vipc' => 'fd00:53:53:53:53:53:53:5',
		];

		// When / Then: the candidates themselves are still free.
		$this->assertSame('172.16.53.53', pfb_pick_free_dnsbl_vip(AF_INET, 'lan'));
		$this->assertSame('fd00:53:53:53:53:53:53:53', pfb_pick_free_dnsbl_vip(AF_INET6, 'lan'));
	}
}
