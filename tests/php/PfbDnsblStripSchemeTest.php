<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_strip_scheme() — ADR-22 Phase 1 oracle tests.
 *
 * Phase 1 is a behaviour-preserving extraction of the former inline non-lite scheme
 * strip: if '<scheme>://' is present, strip up to and including the FIRST '://' and
 * return the remainder; otherwise return the line unchanged. These tests PIN the
 * CURRENT (permissive) behaviour for every input class so the Phase-2 tightening (a
 * $strict toggle that validates the RFC 3986 scheme + rejects paths, returning
 * string|false) has explicit before-state anchors.
 *
 * Path/query/fragment/port stripping happens downstream (lines 9679-9706); this helper
 * intentionally returns the remainder WITH any path intact.
 */
#[CoversFunction('pfb_dnsbl_strip_scheme')]
final class PfbDnsblStripSchemeTest extends TestCase
{
	public function testHttpSchemeStripped(): void
	{
		// Path stripping is downstream; helper returns the remainder WITH '/path' intact.
		$this->assertSame('evil.com/path', pfb_dnsbl_strip_scheme('http://evil.com/path'));
	}

	public function testHttpsSchemeStripped(): void
	{
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('https://evil.com'));
	}

	public function testFtpSchemeStripped(): void
	{
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('ftp://evil.com'));
	}

	public function testTelnetSchemeStripped(): void
	{
		// telnet is a valid RFC 3986 scheme; this behaviour is UNCHANGED in Phase 2.
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('telnet://evil.com'));
	}

	public function testCustomValidSchemeStripped(): void
	{
		// Any valid RFC 3986 scheme is accepted; UNCHANGED in Phase 2.
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('evil://evil.com'));
	}

	public function testCompoundSchemeStripped(): void
	{
		// '+' is valid inside an RFC 3986 scheme; UNCHANGED in Phase 2.
		$this->assertSame('fakepkg.com', pfb_dnsbl_strip_scheme('pkg+https://fakepkg.com'));
	}

	public function testNoSchemeUnchanged(): void
	{
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('evil.com'));
	}

	public function testDigitStartSchemeCurrentBehavior(): void
	{
		// BEFORE-STATE ORACLE for Phase 2: a digit-start scheme is NOT a valid RFC 3986
		// scheme, yet the permissive strpos()-based strip extracts 'evil.com'. Phase 2's
		// strict mode changes this to false (skip + log). This pins today's behaviour.
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('123://evil.com'));
	}

	public function testEmptySchemeCurrentBehavior(): void
	{
		// BEFORE-STATE ORACLE for Phase 2: an empty scheme prefix -- strpos() finds '://'
		// at position 0, so the strip yields 'evil.com'. Phase 2's strict mode changes
		// this to false (skip + log). This pins today's behaviour.
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('://evil.com'));
	}

	public function testMidTokenValidSchemeCurrentBehavior(): void
	{
		// 'evil.com' is an RFC 3986-valid scheme ('.' is allowed), so the first '://'
		// match extracts 'junk'. This behaviour does NOT change in Phase 2 (the scheme is
		// valid); pfb_filter() downstream rejects 'junk' (no '.'). Documents the edge case.
		$this->assertSame('junk', pfb_dnsbl_strip_scheme('evil.com://junk'));
	}

	// ------------------------------------------------------------------
	// ADR-22 Phase 2 -- the $strict toggle (ADR §2.4 / §2.5 decision table).
	//
	// Scenario: scheme validation behind a single global lenient/strict toggle.
	//   Background: pfb_dnsbl_strip_scheme($line, $strict) -- $strict resolved at the
	//   call site from `lenient !== 'on'`. Lenient (false) is today's permissive strip;
	//   strict (true) validates the RFC 3986 scheme + rejects URL paths, returning FALSE.
	// ------------------------------------------------------------------

	// --- Lenient (strict=false): current behaviour preserved (the malformed cases that
	//     strict flips to FALSE; each pinned at strict=false BEFORE the strict assertion
	//     in the paired strict test, so green proves the toggle CAUSED the change). ---

	public function testInvalidSchemePassthroughWhenLenient(): void
	{
		// Given a digit-start (invalid RFC 3986) scheme, When lenient, Then the
		// permissive strip still yields the host (today's behaviour).
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('123://evil.com', false));
	}

	public function testEmptySchemePassthroughWhenLenient(): void
	{
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('://evil.com', false));
	}

	public function testPathPassthroughWhenLenient(): void
	{
		// Lenient keeps the path on the remainder (stripped downstream); not rejected.
		$this->assertSame('evil.com/path', pfb_dnsbl_strip_scheme('http://evil.com/path', false));
	}

	// --- Strict (strict=true): new behaviour. Each transition test first asserts the
	//     lenient (before) result, then the strict (after) result, so the change is
	//     attributable to the toggle, not an always-FALSE path. ---

	public function testInvalidSchemeRejectedWhenStrict(): void
	{
		// BEFORE (lenient): '123://evil.com' -> 'evil.com'.
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('123://evil.com', false));
		// AFTER (strict): digit-start scheme is not RFC 3986 valid -> FALSE (skip + log).
		$this->assertFalse(pfb_dnsbl_strip_scheme('123://evil.com', true));
	}

	public function testEmptySchemeRejectedWhenStrict(): void
	{
		// BEFORE (lenient): '://evil.com' -> 'evil.com'.
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('://evil.com', false));
		// AFTER (strict): empty scheme prefix -> FALSE.
		$this->assertFalse(pfb_dnsbl_strip_scheme('://evil.com', true));
	}

	public function testSpecialCharsSchemeRejectedWhenStrict(): void
	{
		// BEFORE (lenient): a non-alpha-start scheme still strips to the host.
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('!!bad://evil.com', false));
		// AFTER (strict): '!!bad' is not a valid scheme (non-alpha start) -> FALSE.
		$this->assertFalse(pfb_dnsbl_strip_scheme('!!bad://evil.com', true));
	}

	public function testPathRejectedWhenStrict(): void
	{
		// BEFORE (lenient): the path rides through on the remainder.
		$this->assertSame('evil.com/path', pfb_dnsbl_strip_scheme('http://evil.com/path', false));
		// AFTER (strict): a real URL path is present -> FALSE (skip + log).
		$this->assertFalse(pfb_dnsbl_strip_scheme('http://evil.com/path', true));
	}

	public function testTrailingSlashNormalisedWhenStrict(): void
	{
		// A single trailing '/' is the root path -- normalised away, NOT a rejection.
		$this->assertSame('ftp.evil.com', pfb_dnsbl_strip_scheme('ftp://ftp.evil.com/', true));
	}

	public function testPathAfterRootSlashRejectedWhenStrict(): void
	{
		// BEFORE (lenient): remainder keeps 'evil.com/path/'.
		$this->assertSame('evil.com/path/', pfb_dnsbl_strip_scheme('http://evil.com/path/', false));
		// AFTER (strict): one trailing '/' is normalised, but a '/' remains (the real
		// path) -> FALSE. Guards against a naive "strip the last slash" bypass.
		$this->assertFalse(pfb_dnsbl_strip_scheme('http://evil.com/path/', true));
	}

	// --- Regression guards: a valid RFC 3986 scheme (no path) is accepted in BOTH
	//     toggle states (ADR §2.6.1). ---

	public function testValidSchemeAcceptedWhenLenient(): void
	{
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('evil://evil.com', false));
	}

	public function testValidSchemeAcceptedWhenStrict(): void
	{
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('evil://evil.com', true));
	}

	public function testCompoundSchemeWhenStrict(): void
	{
		// '+' is valid inside a scheme; accepted under strict too.
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('pkg+https://evil.com', true));
	}

	public function testNoSchemeWhenStrict(): void
	{
		// No '://' -> returned unchanged regardless of toggle state.
		$this->assertSame('evil.com', pfb_dnsbl_strip_scheme('evil.com', true));
	}

	// --- Empty scheme + bracketed IPv6: a known DandelionSprouts-style "block
	//     regardless of scheme" convention. Confirmed live: 4 identical-shaped lines
	//     in a real feed, each pairing with an adjacent hosts-format block entry for
	//     the same campaign. ---

	public function testEmptySchemeBracketedIpv6PassesThroughWhenStrict(): void
	{
		// The brackets are NOT unwrapped here -- that is pfb_dnsbl_unbracket_ip6()'s
		// job, called later in the caller. This function only decides "is this a
		// scheme-rejection", so it returns the remainder as-is.
		$this->assertSame(
			'[2604:2dc0:100:4ed8::]',
			pfb_dnsbl_strip_scheme('://[2604:2dc0:100:4ed8::]', true)
		);
	}

	public function testEmptySchemeNonBracketedStillRejectedWhenStrict(): void
	{
		// The special-case is narrow: an empty scheme with anything OTHER than an
		// exact '[valid-ipv6]' remainder is still rejected, same as before.
		$this->assertFalse(pfb_dnsbl_strip_scheme('://evil.com', true));
	}

	public function testEmptySchemeInvalidBracketContentRejectedWhenStrict(): void
	{
		// A bracket-wrapped string that is NOT a valid IPv6 literal does not qualify.
		$this->assertFalse(pfb_dnsbl_strip_scheme('://[not-an-ipv6]', true));
	}

	public function testEmptySchemeBracketedIpv6WithTrailingJunkRejectedWhenStrict(): void
	{
		// Anything beyond the exact '[...]' shape (a path, trailing text) is still
		// an invalid URI and rejected -- only the clean whole-line form is special-cased.
		$this->assertFalse(pfb_dnsbl_strip_scheme('://[2604:2dc0:100:4ed8::]/path', true));
	}
}
