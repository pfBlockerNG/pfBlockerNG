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
}
