<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_is_skippable_control_line() -- ADR-62 P2 capture guard for the
 * (not-yet-wired) universal blank/comment/ABP-marker skip. Blank detection is an
 * exact '' match (caller trims first, mirroring pfb_is_blank_or_comment_line); a
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

	public function testWhitespaceOnlyLineIsNotBlankPerThisHelpersContract(): void
	{
		// Probe (brief hostile row): the download loop trims $line (inc:~16389)
		// BEFORE any capture-guard call, so a whitespace-only line never reaches a
		// call site untrimmed in production. This helper follows the SAME contract
		// as pfb_is_blank_or_comment_line -- the caller trims first; passed
		// unTrimmed, three spaces is not the exact '' match, so it is NOT skippable.
		$this->assertFalse(pfb_dnsbl_is_skippable_control_line('   '));
	}

	public function testTabLedAbpAnchorIsNotSkippedUntrimmed(): void
	{
		// Probe (brief hostile row): a raw tab-led line, called directly (bypassing
		// the loop's own trim at inc:~16389), does not start with '!'/'//'/'[' --
		// consistent with the caller-trims-first contract, not a bug.
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
