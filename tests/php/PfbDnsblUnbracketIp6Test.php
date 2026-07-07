<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_unbracket_ip6() -- issue #938.
 *
 * After scheme/port stripping, a bracketed IPv6 literal ('[2604:2dc0:100:4ed8::]') is never
 * recognised: is_ipaddrv6() rejects the brackets, pfb_filter() rejects it as a domain, and
 * every such line hits the DNSBL parse-error log on every feed update. This helper unwraps a
 * '[' ... ']' pair around a VALID IPv6 literal to the bare literal so the existing
 * is_ipaddrv6($line) collection branch picks it up; anything else stays unchanged and keeps
 * flowing to domain validation exactly as before.
 */
#[CoversFunction('pfb_dnsbl_unbracket_ip6')]
final class PfbDnsblUnbracketIp6Test extends TestCase
{
	public function testBracketedIp6Unwrapped(): void
	{
		$this->assertSame('2604:2dc0:100:4ed8::', pfb_dnsbl_unbracket_ip6('[2604:2dc0:100:4ed8::]'));
	}

	public function testBracketedFullIp6Unwrapped(): void
	{
		$this->assertSame(
			'2600:3c06::f03c:95ff:fed9:ce5e',
			pfb_dnsbl_unbracket_ip6('[2600:3c06::f03c:95ff:fed9:ce5e]')
		);
	}

	public function testBracketedLoopbackUnwrapped(): void
	{
		$this->assertSame('::1', pfb_dnsbl_unbracket_ip6('[::1]'));
	}

	public function testBracketedUnspecifiedUnwrapped(): void
	{
		$this->assertSame('::', pfb_dnsbl_unbracket_ip6('[::]'));
	}

	public function testBracketedNonIpUnchanged(): void
	{
		$this->assertSame('[not:an:ip]', pfb_dnsbl_unbracket_ip6('[not:an:ip]'));
	}

	public function testEmptyBracketsUnchanged(): void
	{
		$this->assertSame('[]', pfb_dnsbl_unbracket_ip6('[]'));
	}

	public function testBracketedIp4Unchanged(): void
	{
		// IPv4 is never bracket-legal in this feed grammar -- leave it for domain
		// validation (and the parse-error log) to reject exactly as before.
		$this->assertSame('[1.2.3.4]', pfb_dnsbl_unbracket_ip6('[1.2.3.4]'));
	}

	public function testUnclosedBracketUnchanged(): void
	{
		$this->assertSame('[2604::', pfb_dnsbl_unbracket_ip6('[2604::'));
	}

	public function testBareLiteralWithoutBracketsUnchanged(): void
	{
		// Already-bare literals aren't this helper's job -- the is_ipaddrv6($line)
		// collection branch downstream handles them directly.
		$this->assertSame('2604::', pfb_dnsbl_unbracket_ip6('2604::'));
	}

	public function testDoubleBracketedUnchanged(): void
	{
		// Outer brackets peel to the inner '[::]', which is NOT a valid IPv6 literal
		// (brackets aren't part of the address grammar) -- unchanged.
		$this->assertSame('[[::]]', pfb_dnsbl_unbracket_ip6('[[::]]'));
	}

	public function testPortSuffixedLineUnchangedByThisHelperAlone(): void
	{
		// The trailing ':443' means the line does not END with ']', so this helper
		// alone leaves it untouched -- port stripping happens upstream at the call site.
		$this->assertSame('[2604:2dc0::]:443', pfb_dnsbl_unbracket_ip6('[2604:2dc0::]:443'));
	}

	public function testComposedWithPortStripPinsCallSiteOrdering(): void
	{
		// Pins the production call-site order (pfb_strip_trailing_port() THEN
		// pfb_dnsbl_unbracket_ip6()): the port is stripped first, exposing the closing
		// ']' so the bracket unwrap can then fire.
		$this->assertSame(
			'2604:2dc0::',
			pfb_dnsbl_unbracket_ip6(pfb_strip_trailing_port('[2604:2dc0::]:443'))
		);
	}

	public function testZoneIdLiteralFollowsIsIpaddrv6Verbatim(): void
	{
		// Observed truth (run, not guessed): the pfSense is_ipaddrv6() double treats
		// 'fe80::1%em0' as a valid link-local literal (zone-id retained in the address
		// grammar for link-local addresses), so the bracket wrapper unwraps it verbatim
		// -- the helper never itself strips the zone id, it only defers to is_ipaddrv6().
		$this->assertTrue(is_ipaddrv6('fe80::1%em0'));
		$this->assertSame('fe80::1%em0', pfb_dnsbl_unbracket_ip6('[fe80::1%em0]'));
	}
}
