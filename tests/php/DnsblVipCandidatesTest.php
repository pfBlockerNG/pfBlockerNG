<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_vip_candidates() (ADR-13 / issue #473 / issue #487) — the pure,
 * side-effect-free fixed ordered list of DNS-themed candidate sinkhole VIP addresses.
 *
 * IPv4: three candidates in Class-B-first order (least-used RFC1918 on end-user LANs first):
 *   172.16.53.53  (172.16/12)
 *   192.168.53.53 (192.168/16)
 *   10.53.53.53   (10/8, most common, so last)
 *
 * IPv6: single ULA candidate fd00:53:53:53:53:53:53:53.
 * On conflict the picker returns null and the user resolves it manually.
 *
 * Supersedes the prior sweep+disjoint-fallback pool from issue #487.
 */
#[CoversFunction('pfb_dnsbl_vip_candidates')]
final class DnsblVipCandidatesTest extends TestCase
{
	// ---------- v4 ----------

	public function testV4ReturnsExactFixedList(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);
		$this->assertSame(
			['172.16.53.53', '192.168.53.53', '10.53.53.53'],
			$candidates,
			'IPv4 candidate list must be the exact Class-B/C/A fixed list in that order'
		);
	}

	public function testV4FirstCandidateIsClassB(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);
		$this->assertSame('172.16.53.53', $candidates[0],
			'First IPv4 candidate must be the Class-B address (least-used RFC1918 on end-user LANs)');
	}

	public function testV4SecondCandidateIsClassC(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);
		$this->assertSame('192.168.53.53', $candidates[1],
			'Second IPv4 candidate must be the Class-C address');
	}

	public function testV4ThirdCandidateIsClassA(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);
		$this->assertSame('10.53.53.53', $candidates[2],
			'Third (last) IPv4 candidate must be the Class-A address (most-used, so last)');
	}

	public function testV4ExactlyThreeCandidates(): void
	{
		$this->assertCount(3, pfb_dnsbl_vip_candidates(AF_INET));
	}

	// ---------- v6 ----------

	public function testV6ReturnsExactFixedList(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET6);
		$this->assertSame(
			['fd00:53:53:53:53:53:53:53'],
			$candidates,
			'IPv6 candidate list must be the single ULA fixed address'
		);
	}

	public function testV6ExactlyOneCandidate(): void
	{
		$this->assertCount(1, pfb_dnsbl_vip_candidates(AF_INET6));
	}

	public function testV6CandidateIsUla(): void
	{
		$candidates = pfb_dnsbl_vip_candidates(AF_INET6);
		$addr       = $candidates[0];
		$bin        = inet_pton($addr);
		$this->assertNotFalse($bin, "'{$addr}' must be a parseable IPv6 address");
		// ULA = fc00::/7, first byte 0xfc or 0xfd.
		$first_byte = ord($bin[0]);
		$this->assertTrue($first_byte === 0xfc || $first_byte === 0xfd,
			"'{$addr}' must be a ULA address (fc00::/7)");
	}

	// ---------- unknown family ----------

	public function testUnknownFamilyReturnsEmpty(): void
	{
		// Any family other than AF_INET / AF_INET6 yields no candidates.
		$this->assertSame([], pfb_dnsbl_vip_candidates(0));
		$this->assertSame([], pfb_dnsbl_vip_candidates(AF_UNIX));
	}
}
