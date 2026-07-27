<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_is_skippable_control_line() -- ADR-62 P2 capture guard for the
 * (not-yet-wired) universal blank/comment/ABP-marker skip. The helper strips the
 * line itself (pfb_strip, Unicode class -- issue #1787; blank = exact '' match,
 * mirroring pfb_is_blank_or_comment_line); a
 * bracketed IPv6 literal is never treated as an ABP section marker (ADR-62 Semantics
 * #3) -- it is an address, collected by pfb_dnsbl_collect_feed_ip() instead.
 */
#[CoversFunction('pfb_dnsbl_is_skippable_control_line')]
final class Adr62DnsblIsSkippableControlLineTest extends TestCase
{
	public static function skippableProvider(): array
	{
		return [
			'empty string'                    => ['', true],
			'bang comment'                     => ['!comment', true],
			'abp title header'                 => ['! Title: X', true],
			'c-style comment'                  => ['//comment', true],
			'abp section marker'               => ['[Adblock Plus 2.0]', true],
			'non-ip bracket marker'            => ['[not-an-ip]', true],
			// is_ipaddrv6('') is FALSE, so an empty bracket pair is NOT the IPv6
			// carve-out -- it is an (unusual) ABP-style marker, skipped.
			'empty brackets'                   => ['[]', true],
			'bare domain'                      => ['domain.com', false],
			// '#' is pfb_dnsbl_hash_line_classify()'s job (side effects) -- this
			// predicate deliberately never claims it.
			'hash comment excluded on purpose' => ['#comment', false],
			'abp network anchor'               => ['||x^', false],
			'bare regex shape'                 => ['/re/', false],
		];
	}

	#[DataProvider('skippableProvider')]
	public function testSkippable(string $line, bool $expected): void
	{
		$this->assertSame($expected, pfb_dnsbl_is_skippable_control_line($line));
	}

	public function testBracketedIpv6LiteralIsNeverSkipped(): void
	{
		// ADR-62 Semantics #3: a bracketed IPv6 literal is an ADDRESS, not an ABP
		// section marker -- Decision 4's carve-out.
		$this->assertFalse(pfb_dnsbl_is_skippable_control_line('[2604:2dc0::]'));
		$this->assertFalse(pfb_dnsbl_is_skippable_control_line('[2001:db8::1]'));
	}

	public function testWhitespaceOnlyLineIsBlankPerThisHelpersContract(): void
	{
		// Issue #1787 flipped the old caller-trims-first contract: the helper now
		// strips the line itself (pfb_strip, Unicode class, mirroring
		// pfb_is_blank_or_comment_line), so a whitespace-only line is blank and
		// skippable even when a call site passes it untrimmed.
		$this->assertTrue(pfb_dnsbl_is_skippable_control_line('   '));
	}

	public function testTabLedAbpAnchorIsNotSkipped(): void
	{
		// A tab-led ABP anchor line self-strips to '||x^' -- an ABP rule, not a
		// '!'/'//'/'[' control line, so it stays on the capture path.
		$this->assertFalse(pfb_dnsbl_is_skippable_control_line("\t||x^"));
	}

	public function testBreakingTheIpv6CarveOutTurnsBracketedLiteralSkippable(): void
	{
		// Fail-on-mutation oracle: if the IPv6 carve-out broke (e.g. the bracket
		// check stopped consulting pfb_dnsbl_unbracket_ip6()/is_ipaddrv6()), a
		// bracketed IPv6 literal would wrongly become "skippable" again. This proves
		// TODAY's helper does NOT do that -- the assertion the mutation would flip.
		$this->assertFalse(pfb_dnsbl_is_skippable_control_line('[2604:2dc0::]'));
		// Sanity: pfb_dnsbl_unbracket_ip6() really does unwrap this literal, which is
		// the exact mechanism the carve-out depends on.
		$this->assertSame('2604:2dc0::', pfb_dnsbl_unbracket_ip6('[2604:2dc0::]'));
	}
}
