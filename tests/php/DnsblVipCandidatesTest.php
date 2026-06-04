<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_vip_candidates() (ADR-13) — the pure, side-effect-free generator of
 * DNS-themed candidate sinkhole VIP addresses. The only Phase-1 helper with no
 * pfSense-runtime coupling, so it is unit-tested here; the conflict-aware picker
 * and the v6-listen predicate depend on pfSense state and are covered by lint +
 * manual smoke (see .ADRs/ADR_13_Auto_DNSBL_VIP).
 */
#[CoversFunction('pfb_dnsbl_vip_candidates')]
final class DnsblVipCandidatesTest extends TestCase
{
	public function testV4PrefersTheDnsHomageAddressFirst(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);
		$this->assertSame('10.10.10.53', $candidates[0]);
	}

	public function testV6PrefersTheDnsHomageAddressFirst(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET6);
		$this->assertSame('fd00::53', $candidates[0]);
	}

	public function testV4SweepIsBoundedToSixteenUniqueDotFiftyThreeAddresses(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);

		// 16 candidates (octet sweep 0..15), all unique, all keep the .53 homage.
		$this->assertCount(16, $candidates);
		$this->assertSame($candidates, array_values(array_unique($candidates)));
		foreach ($candidates as $address) {
			$this->assertMatchesRegularExpression('/^10\.10\.(?:[0-9]|1[0-5])\.53$/', $address);
		}

		// The full 10.10.X.53 set (X=0..15) is present exactly once.
		$expected = [];
		for ($x = 0; $x <= 15; $x++) {
			$expected[] = "10.10.{$x}.53";
		}
		sort($expected);
		$got = $candidates;
		sort($got);
		$this->assertSame($expected, $got);
	}

	public function testV6SweepIsBoundedToSixteenUniqueDoubleColonFiftyThreeAddresses(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET6);

		// 16 candidates (fd00::53 + fd00:1::53..fd00:15::53), all unique, all ::53.
		$this->assertCount(16, $candidates);
		$this->assertSame($candidates, array_values(array_unique($candidates)));

		$expected = ['fd00::53'];
		for ($x = 1; $x <= 15; $x++) {
			$expected[] = "fd00:{$x}::53";
		}
		$this->assertSame($expected, $candidates);
	}

	public function testUnknownFamilyReturnsEmpty(): void
	{
		// Any family other than AF_INET / AF_INET6 yields no candidates.
		$this->assertSame([], pfb_dnsbl_vip_candidates(0));
		$this->assertSame([], pfb_dnsbl_vip_candidates(AF_UNIX));
	}
}
