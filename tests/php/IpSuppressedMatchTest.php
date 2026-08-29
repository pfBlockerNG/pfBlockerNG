<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_ip_suppressed_match() -- issue #422 (ADR-53 follow-up): the longest-prefix
 * sibling of pfb_ip_suppressed() that returns the actual covering customlist
 * entry instead of a bool, so the Alerts un-suppress ('delete_ip') handler and
 * the suppressed-row icon detection can act on it directly.
 */
#[CoversFunction('pfb_ip_suppressed_match')]
final class IpSuppressedMatchTest extends TestCase
{
	// --- no coverage ---

	public function testNoEntriesReturnsNull(): void
	{
		$this->assertNull(pfb_ip_suppressed_match('10.0.0.1', []));
	}

	public function testNonCoveringEntryReturnsNull(): void
	{
		$this->assertNull(pfb_ip_suppressed_match('10.1.0.1', ['10.0.0.0/16']));
	}

	// --- single covering entry ---

	public function testSingleCoveringV4Slash16IsReturnedVerbatim(): void
	{
		$this->assertSame(
			'10.0.0.0/16',
			pfb_ip_suppressed_match('10.0.5.9', ['10.0.0.0/16'])
		);
	}

	/**
	 * Scenario: two containing CIDRs of different specificity cover the same
	 * host -- the longest prefix must win regardless of which one was authored
	 * first in the customlist (pins longest-prefix selection, not first-match).
	 */
	public function testLongestPrefixWinsRegardlessOfArrayOrder(): void
	{
		// Given a /16 and a /24 both covering the host 10.0.5.9
		$broad_first = ['10.0.0.0/16', '10.0.5.0/24'];
		$narrow_first = ['10.0.5.0/24', '10.0.0.0/16'];

		// When matching against either ordering
		// Then the more specific /24 is returned both times
		$this->assertSame('10.0.5.0/24', pfb_ip_suppressed_match('10.0.5.9', $broad_first));
		$this->assertSame('10.0.5.0/24', pfb_ip_suppressed_match('10.0.5.9', $narrow_first));
	}

	public function testExactHostSlash32BeatsACoveringSlash24(): void
	{
		$this->assertSame(
			'10.0.5.9/32',
			pfb_ip_suppressed_match('10.0.5.9', ['10.0.5.0/24', '10.0.5.9/32'])
		);
	}

	/**
	 * Scenario: two covering entries share the SAME prefix length -- the tie
	 * keeps the first-seen entry (stable), separating the tie contract from
	 * the longest-prefix contract pinned above. Same-CIDR lines that differ
	 * only in their inline comment are the realistic tie shape (a customlist
	 * duplicate); the RAW line identifies which one won.
	 */
	public function testEqualPrefixTieKeepsFirstSeenEntry(): void
	{
		// Given two lines with the same covering /24, distinguishable by comment
		$a = '10.0.5.0/24 # first';
		$b = '10.0.5.0/24 # second';

		// When matching against either ordering
		// Then the FIRST-SEEN line wins each time
		$this->assertSame($a, pfb_ip_suppressed_match('10.0.5.9', [$a, $b]));
		$this->assertSame($b, pfb_ip_suppressed_match('10.0.5.9', [$b, $a]));
	}

	// --- v6 ---

	public function testV6Slash128BeatsACoveringSlash64(): void
	{
		$this->assertSame(
			'2001:db8::1/128',
			pfb_ip_suppressed_match('2001:db8::1', ['2001:db8::/64', '2001:db8::1/128'])
		);
	}

	public function testV6HostInsideOnlyTheSlash64ReturnsTheSlash64(): void
	{
		$this->assertSame(
			'2001:db8::/64',
			pfb_ip_suppressed_match('2001:db8::9', ['2001:db8::/64', '2001:db8::1/128'])
		);
	}

	// --- bare-host tolerance (parity with the carve engines) ---

	/**
	 * Scenario: a customlist line with NO mask (hand-edited config; the UI
	 * validator normally enforces one). Both carve engines treat a bare hole
	 * as a single host (iprange: /32; pfb_v6_cidr_to_range(): /128), so the
	 * predicates must agree -- an entry the engine suppresses with must also
	 * read as "suppressed" here (killstates) and resolve for un-suppress.
	 * Before issue #422 a bare entry never matched (ip_in_subnet() requires
	 * a mask), silently diverging from the engines.
	 */
	public function testBareHostEntryMatchesItsExactIpBothFamilies(): void
	{
		$this->assertSame(
			'198.51.100.7',
			pfb_ip_suppressed_match('198.51.100.7', ['198.51.100.7'])
		);
		$this->assertTrue(pfb_ip_suppressed('198.51.100.7', ['198.51.100.7']));

		$this->assertSame(
			'2001:db8::7',
			pfb_ip_suppressed_match('2001:db8::7', ['2001:db8::7'])
		);
		$this->assertTrue(pfb_ip_suppressed('2001:db8::7', ['2001:db8::7']));

		// A DIFFERENT host is still not covered by a bare-host entry.
		$this->assertNull(pfb_ip_suppressed_match('198.51.100.8', ['198.51.100.7']));
	}

	// --- comment tolerance ---

	public function testCommentOnlyLineIsSkipped(): void
	{
		$this->assertNull(
			pfb_ip_suppressed_match('10.0.0.1', ['# comment', ''])
		);
	}

	public function testInlineCommentedEntryStillMatchesAndReturnsTheRawLine(): void
	{
		$this->assertSame(
			'10.0.0.0/24 # office',
			pfb_ip_suppressed_match('10.0.0.1', ['10.0.0.0/24 # office'])
		);
	}

	// --- refactor pin: pfb_ip_suppressed() agrees with this function ---

	public function testPfbIpSuppressedAgreesWithMatchOnAMixedSet(): void
	{
		$entries = ['10.0.0.0/16', '2001:db8::/64', 'not-a-cidr'];

		// Given a host covered by one of the entries
		$this->assertTrue(pfb_ip_suppressed('10.0.5.9', $entries));
		$this->assertNotNull(pfb_ip_suppressed_match('10.0.5.9', $entries));

		// Given a host covered by none of the entries
		$this->assertFalse(pfb_ip_suppressed('10.1.0.1', $entries));
		$this->assertNull(pfb_ip_suppressed_match('10.1.0.1', $entries));
	}
}
