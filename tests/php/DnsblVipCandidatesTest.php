<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_vip_candidates() (ADR-13 / issue #487) — the pure, side-effect-free
 * generator of DNS-themed candidate sinkhole VIP addresses.
 *
 * The pool has two tiers:
 *   1. Primary sweep: 10.10.10.53 (preferred, back-compat) + 10.10.{0..15}.53 (v4),
 *      fd00::53 + fd00:{1..15}::53 (v6) — 16 entries each.
 *   2. Disjoint-range fallbacks appended after the sweep so a single common aggregate
 *      (10/8 for v4, fd00::/8 for v6) can never exhaust the entire pool:
 *        v4: 172.31.255.53, 172.31.254.53, 192.0.2.53, 198.51.100.53,
 *            203.0.113.53, 100.64.0.53   (6 fallbacks)
 *        v6: 2001:db8::53, 2001:db8:1::53                               (2 fallbacks)
 *
 * The conflict-aware picker (pfb_pick_free_dnsbl_vip) selects the first free one;
 * the fallbacks are exercised by DnsblPickFreeVipTest when the sweep is exhausted.
 */
#[CoversFunction('pfb_dnsbl_vip_candidates')]
final class DnsblVipCandidatesTest extends TestCase
{
	// ---------- v4 ----------

	public function testV4PrefersTheDnsHomageAddressFirst(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);
		$this->assertSame('10.10.10.53', $candidates[0]);
	}

	public function testV4SweepPrecedes_Fallbacks_And_Contains_Full_16_Entries(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);

		// Preferred address is index 0 (back-compat).
		$this->assertSame('10.10.10.53', $candidates[0]);

		// Positions 0..15 are the full 10.10.X.53 sweep (preferred first, then X=0..9,11..15).
		$sweep = array_slice($candidates, 0, 16);
		$this->assertCount(16, $sweep);
		$this->assertSame($sweep, array_values(array_unique($sweep)));
		foreach ($sweep as $address) {
			$this->assertMatchesRegularExpression('/^10\.10\.(?:[0-9]|1[0-5])\.53$/', $address,
				"sweep entry '{$address}' should be 10.10.X.53 with X in 0..15");
		}

		// The full 10.10.X.53 set (X=0..15) is present exactly once in the sweep.
		$expected_sweep = [];
		for ($x = 0; $x <= 15; $x++) {
			$expected_sweep[] = "10.10.{$x}.53";
		}
		sort($expected_sweep);
		$got_sweep = $sweep;
		sort($got_sweep);
		$this->assertSame($expected_sweep, $got_sweep);
	}

	public function testV4FallbacksAppearAfterSweepInOrder(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);

		// Expected fallbacks in the required order.
		$expected_fallbacks = [
			'172.31.255.53',
			'172.31.254.53',
			'192.0.2.53',
			'198.51.100.53',
			'203.0.113.53',
			'100.64.0.53',
		];

		// Total size = 16 sweep + 6 fallbacks = 22.
		$this->assertCount(22, $candidates);
		$this->assertSame($candidates, array_values(array_unique($candidates)),
			'all candidates must be unique');

		// Fallbacks are in positions 16..21 in the documented order.
		$actual_fallbacks = array_slice($candidates, 16);
		$this->assertSame($expected_fallbacks, $actual_fallbacks,
			'fallbacks must appear after the sweep in the specified order');
	}

	public function testV4FallbacksAllAppearInPool(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);

		foreach (['172.31.255.53', '172.31.254.53', '192.0.2.53', '198.51.100.53', '203.0.113.53', '100.64.0.53'] as $fb) {
			$pos = array_search($fb, $candidates, TRUE);
			$this->assertIsInt($pos, "fallback '{$fb}' must be present in the candidate pool");
			$this->assertGreaterThanOrEqual(16, $pos,
				"fallback '{$fb}' must appear AFTER the primary 16-entry sweep (pos {$pos})");
		}
	}

	/**
	 * The main regression pin for issue #487: seeding the entire 10/8 aggregate as
	 * "occupied" must leave at least one v4 candidate that falls outside 10.0.0.0/8,
	 * so the picker has a non-null result. (The actual picker test is in
	 * DnsblPickFreeVipTest — this asserts the pool property directly.)
	 */
	public function testV4PoolSurvivesACommon10Slash8Aggregate(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);

		$ten_slash8_start = ip2long('10.0.0.0');
		$ten_slash8_end   = ip2long('10.255.255.255');

		$outside = array_filter($candidates, static function (string $addr) use ($ten_slash8_start, $ten_slash8_end): bool {
			$long = ip2long($addr);
			return $long !== FALSE && ($long < $ten_slash8_start || $long > $ten_slash8_end);
		});

		$this->assertNotEmpty($outside,
			'At least one v4 candidate must lie outside 10.0.0.0/8 so a common 10/8 LAN cannot exhaust the pool. '
			. 'Got pool: ' . implode(', ', $candidates));
	}

	// ---------- v6 ----------

	public function testV6PrefersTheDnsHomageAddressFirst(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET6);
		$this->assertSame('fd00::53', $candidates[0]);
	}

	public function testV6SweepPrecedes_Fallbacks_And_Contains_Full_16_Entries(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET6);

		// Positions 0..15 are fd00::53 + fd00:1::53..fd00:15::53 in order.
		$sweep = array_slice($candidates, 0, 16);
		$expected_sweep = ['fd00::53'];
		for ($x = 1; $x <= 15; $x++) {
			$expected_sweep[] = "fd00:{$x}::53";
		}
		$this->assertSame($expected_sweep, $sweep);
	}

	public function testV6FallbacksAppearAfterSweepInOrder(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET6);

		// Total size = 16 sweep + 2 fallbacks = 18.
		$this->assertCount(18, $candidates);
		$this->assertSame($candidates, array_values(array_unique($candidates)),
			'all candidates must be unique');

		$actual_fallbacks = array_slice($candidates, 16);
		$this->assertSame(['2001:db8::53', '2001:db8:1::53'], $actual_fallbacks,
			'v6 fallbacks must appear after the sweep in the specified order');
	}

	/**
	 * Analogue of testV4PoolSurvivesACommon10Slash8Aggregate for v6:
	 * a fd00::/8 ULA aggregate must leave at least one candidate outside.
	 */
	public function testV6PoolSurvivesACommonFd00Slash8Aggregate(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET6);

		$outside = array_filter($candidates, static function (string $addr): bool {
			// fd00::/8 = first octet of the expanded address is 'fd' (0xfd = 253 decimal).
			// Use a simple prefix check on the normalised hex representation.
			$bin = inet_pton($addr);
			if ($bin === FALSE) {
				return FALSE;
			}
			// First byte: 0xfd means it falls within fd00::/8 (fc00::/7 is fd + fc).
			$first_byte = ord($bin[0]);
			// fc00::/7 covers 0xfc and 0xfd; fd00::/8 is just 0xfd.
			return $first_byte !== 0xfd;
		});

		$this->assertNotEmpty($outside,
			'At least one v6 candidate must lie outside fd00::/8 so a common ULA aggregate '
			. 'cannot exhaust the pool. Got pool: ' . implode(', ', $candidates));
	}

	// ---------- unknown family ----------

	public function testUnknownFamilyReturnsEmpty(): void
	{
		// Any family other than AF_INET / AF_INET6 yields no candidates.
		$this->assertSame([], pfb_dnsbl_vip_candidates(0));
		$this->assertSame([], pfb_dnsbl_vip_candidates(AF_UNIX));
	}
}
