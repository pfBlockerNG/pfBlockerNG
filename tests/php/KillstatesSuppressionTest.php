<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_ip_suppressed() -- ADR-53 Phase 7: the prefix-aware suppression-exclusion
 * predicate that replaces pfb_remove_states()'s old exact-IP hashmap +
 * subnetv4_expand() '/24' materialisation.
 *
 * BEHAVIOUR CHANGE (ADR-53 §2.2 killstates contract -- a correctness
 * strengthening, red->green): the old mechanism could only express a bare
 * host ('/32') or an exact '/24' suppression entry -- any other containing
 * mask (a v4 '/16', or ANY v6 mask, since v6suppression was never read by
 * killstates at all) silently left the state killed despite the user's
 * exemption. testV4Slash16ContainedIpIsSuppressed() and
 * testV6Slash64ContainedIpIsSuppressed() are the red->green proof: this
 * function did not exist before this phase, so every test here FAILS with a
 * fatal "undefined function" against the pre-Phase-7 code and PASSES once
 * pfb_ip_suppressed() lands. The wiring itself (pfb_remove_states() actually
 * calling this helper) is separately proven end-to-end in
 * PfbRemoveStatesTest.php.
 */
#[CoversFunction('pfb_ip_suppressed')]
final class KillstatesSuppressionTest extends TestCase
{
	// --- v4: containing masks the old exact-map + subnetv4_expand() couldn't express ---

	public function testV4Slash16ContainedIpIsSuppressed(): void
	{
		$this->assertTrue(
			pfb_ip_suppressed('10.0.5.9', ['10.0.0.0/16']),
			'10.0.5.9 lies inside the suppressed 10.0.0.0/16 -- the old mechanism only understood /32 and /24'
		);
	}

	public function testV4IpOutsideSuppressedRangeIsNotSuppressed(): void
	{
		$this->assertFalse(
			pfb_ip_suppressed('10.1.0.1', ['10.0.0.0/16'])
		);
	}

	// --- v4: legacy shapes still work (upgrade contract -- no config migration) ---

	public function testV4ExactSlash32HitIsSuppressed(): void
	{
		$this->assertTrue(
			pfb_ip_suppressed('198.51.100.7', ['198.51.100.7/32'])
		);
	}

	public function testV4Slash24MemberIsSuppressed(): void
	{
		$this->assertTrue(
			pfb_ip_suppressed('198.51.100.42', ['198.51.100.0/24'])
		);
	}

	// --- v6: containing masks (v6suppression was never wired to killstates before this phase) ---

	public function testV6Slash64ContainedIpIsSuppressed(): void
	{
		$this->assertTrue(
			pfb_ip_suppressed('2001:db8::9', ['2001:db8::/64'])
		);
	}

	public function testV6IpOutsideSuppressedRangeIsNotSuppressed(): void
	{
		$this->assertFalse(
			pfb_ip_suppressed('2001:db9::1', ['2001:db8::/64'])
		);
	}

	public function testV6ExactSlash128HitIsSuppressed(): void
	{
		$this->assertTrue(
			pfb_ip_suppressed('2001:db8::1', ['2001:db8::1/128'])
		);
	}

	// --- malformed / empty inputs never fatal ---

	public function testMalformedEntrySkippedNotFatal(): void
	{
		$this->assertFalse(
			pfb_ip_suppressed('10.0.0.1', ['not-a-cidr', '# a comment', ''])
		);
	}

	public function testMalformedEntryDoesNotBlockASubsequentRealMatch(): void
	{
		$this->assertTrue(
			pfb_ip_suppressed('10.0.0.1', ['garbage-token', '10.0.0.0/24'])
		);
	}

	public function testEmptyListIsNeverSuppressed(): void
	{
		$this->assertFalse(
			pfb_ip_suppressed('10.0.0.1', [])
		);
	}

	// --- cross-family entries never falsely match (ip_in_subnet's own family guard) ---

	public function testV4EntryNeverMatchesAV6Ip(): void
	{
		$this->assertFalse(
			pfb_ip_suppressed('2001:db8::1', ['10.0.0.0/8'])
		);
	}

	// --- malformed MASK never falsely matches (ADR-53 review finding H3: the
	// pfsense_doubles.php ip_in_subnet() double's own fidelity on this path --
	// pfb_ip_suppressed() forwards raw entries straight to ip_in_subnet() with
	// no mask-range validation of its own, so a lying double here would hide a
	// real suppression over-match) ---

	public function testV4OutOfRangeMaskEntryIsNeverSuppressed(): void
	{
		// '/33' is out of range for IPv4 (real pfSense's is_subnetv4() rejects
		// it, so ip_in_subnet() always returns FALSE) -- must never silently
		// degrade to an exact-host match.
		$this->assertFalse(
			pfb_ip_suppressed('10.0.0.1', ['10.0.0.1/33']),
			"/33 is an out-of-range IPv4 mask -- must never match, not silently normalise to /32"
		);
	}

	public function testV6OutOfRangeMaskEntryIsNeverSuppressed(): void
	{
		// '/129' is out of range for IPv6 -- same contract as the v4 case above.
		$this->assertFalse(
			pfb_ip_suppressed('2001:db8::1', ['2001:db8::1/129']),
			"/129 is an out-of-range IPv6 mask -- must never match"
		);
	}

	public function testV4NonNumericMaskEntryIsNeverSuppressed(): void
	{
		// A non-numeric mask ('/abc') must never fall through to matching
		// EVERY address -- real pfSense's is_subnet() requires the mask to be
		// all-digits; a bare (int) cast on the double's side would coerce
		// 'abc' to 0, i.e. '/0' (matches everything).
		$this->assertFalse(
			pfb_ip_suppressed('8.8.8.8', ['1.2.3.4/abc']),
			"a non-numeric mask must never coerce to /0 (match-everyone)"
		);
	}
}
