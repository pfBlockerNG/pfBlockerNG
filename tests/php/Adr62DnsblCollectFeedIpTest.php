<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_collect_feed_ip() -- ADR-62 P2 extraction of the 6 DNSBL IP-collection
 * call sites (3 v4 + 3 v6 pairs) into one helper. Pins the asymmetry the 6 original
 * blocks shared: v4 sanitizes the candidate THEN validates the sanitized result; v6
 * validates the candidate RAW and appends it unsanitized. $guard_value drives family
 * detection and can differ from $candidate_value (the csv:pon site's shape, where the
 * family check runs on one CSV column but the collected value is another).
 */
#[CoversFunction('pfb_dnsbl_collect_feed_ip')]
final class Adr62DnsblCollectFeedIpTest extends TestCase
{
	protected function setUp(): void
	{
		// Default: suppression OFF (no reserved/private filtering) -- matches
		// SanitizeIpaddrTest's setUp so sanitize_ipaddr() has a defined $pfb['supp'].
		$GLOBALS['pfb']['supp'] = 'off';
	}

	public function testV4CandidateIsSanitizedBeforeAppend(): void
	{
		// Guard and candidate agree on family (10.0.5.9), but the candidate carries a
		// leading-zero octet (10.0.05.9) that sanitize_ipaddr() normalises away --
		// pinning that the SANITIZED value, not the raw candidate, is what lands.
		$ip4 = [];
		$ip6 = [];
		$collected = pfb_dnsbl_collect_feed_ip('10.0.5.9', '10.0.05.9', false, $ip4, $ip6);
		$this->assertTrue($collected);
		$this->assertSame(['10.0.5.9'], $ip4);
		$this->assertSame([], $ip6);
	}

	public function testV6CandidateAppendedRawNeverSanitized(): void
	{
		// '0::1' starts with a '0' character sanitize_ipaddr()'s octet ltrim() would
		// strip to '::1' if the v6 branch ever routed through it -- asserting the
		// EXACT candidate string survives is the fail-on-mutation oracle for "v6 is
		// never sanitized" (breaking that asymmetry turns this red).
		$ip4 = [];
		$ip6 = [];
		$collected = pfb_dnsbl_collect_feed_ip('0::1', '0::1', false, $ip4, $ip6);
		$this->assertTrue($collected);
		$this->assertSame(['0::1'], $ip6);
		$this->assertSame([], $ip4);
	}

	public function testV4GuardWithFailingCandidateAppendsNothing(): void
	{
		// Guard passes is_ipaddrv4() so the v4 branch runs, but the candidate is not
		// an IP at all -- sanitize_ipaddr() passes it through unchanged and
		// validate_ipv4() rejects it, so nothing is appended.
		$ip4 = [];
		$ip6 = [];
		$collected = pfb_dnsbl_collect_feed_ip('198.51.100.5', 'not-an-ip', false, $ip4, $ip6);
		$this->assertFalse($collected);
		$this->assertSame([], $ip4);
		$this->assertSame([], $ip6);
	}

	public function testV6GuardWithFailingCandidateAppendsNothing(): void
	{
		$ip4 = [];
		$ip6 = [];
		$collected = pfb_dnsbl_collect_feed_ip('2001:db8::1', 'not-an-ip6', false, $ip4, $ip6);
		$this->assertFalse($collected);
		$this->assertSame([], $ip4);
		$this->assertSame([], $ip6);
	}

	public function testGuardDiffersFromCandidateMirrorsCsvPonSite(): void
	{
		// csv:pon's shape: the family check runs on csvline[0] (here the guard,
		// 192.0.2.9) but the value collected is csvline[2] (here the candidate,
		// 192.0.2.200) -- the appended value must be the CANDIDATE's, not the guard's.
		$ip4 = [];
		$ip6 = [];
		$collected = pfb_dnsbl_collect_feed_ip('192.0.2.9', '192.0.2.200', false, $ip4, $ip6);
		$this->assertTrue($collected);
		$this->assertSame(['192.0.2.200'], $ip4);
	}

	public function testNeitherFamilyGuardReturnsFalse(): void
	{
		$ip4 = [];
		$ip6 = [];
		$collected = pfb_dnsbl_collect_feed_ip('example.com', 'example.com', false, $ip4, $ip6);
		$this->assertFalse($collected);
		$this->assertSame([], $ip4);
		$this->assertSame([], $ip6);
	}

	public function testCustomFlagPassedThroughToSanitize(): void
	{
		// $custom drives sanitize_ipaddr()'s /0-clamp exemption (issue #744): a
		// downloaded feed's /0 clamps to a bare host, a custom list's /0 is kept.
		// Proves $custom rides through the helper unchanged either way.
		$ip4 = [];
		$ip6 = [];
		$this->assertTrue(pfb_dnsbl_collect_feed_ip('0.0.0.0', '0.0.0.0/0', false, $ip4, $ip6));
		$this->assertSame(['0.0.0.0'], $ip4);

		$ip4 = [];
		$this->assertTrue(pfb_dnsbl_collect_feed_ip('0.0.0.0', '0.0.0.0/0', true, $ip4, $ip6));
		$this->assertSame(['0.0.0.0/0'], $ip4);
	}

	public function testMultipleCallsAppendAcrossSharedArrays(): void
	{
		// The 6 original sites accumulate into the SAME per-feed arrays across many
		// lines -- pins that the helper appends (never resets) the by-ref arrays.
		$ip4 = [];
		$ip6 = [];
		$this->assertTrue(pfb_dnsbl_collect_feed_ip('192.0.2.9', '192.0.2.9', false, $ip4, $ip6));
		$this->assertTrue(pfb_dnsbl_collect_feed_ip('2001:db8::1', '2001:db8::1', false, $ip4, $ip6));
		$this->assertSame(['192.0.2.9'], $ip4);
		$this->assertSame(['2001:db8::1'], $ip6);
	}
}
