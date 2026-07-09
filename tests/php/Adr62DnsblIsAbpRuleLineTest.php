<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_is_abp_rule_line() -- ADR-62 P2 capture guard for the (not-yet-broadened)
 * per-line ABP shape set: answers "should Python's parse_abp() decide this line?",
 * never parses. Mirrors parse_abp()/_dnsbl_parse_abp_regex()'s recognised shapes
 * (pfb_unbound.py:3874/3905) -- every row here is cross-checked against that
 * reference in the handoff's predicate<->parse_abp agreement table.
 */
#[CoversFunction('pfb_dnsbl_is_abp_rule_line')]
final class Adr62DnsblIsAbpRuleLineTest extends TestCase
{
	public static function ruleShapeProvider(): array
	{
		return [
			'network anchor domain'        => ['||domain^', true],
			'network anchor ip'            => ['||1.2.3.4^', true],
			'allow anchor'                 => ['@@||d^', true],
			'allow regex'                  => ['@@/re/', true],
			'allow plain (broad @@ prefix)' => ['@@plain', true],
			'bare allow anchor'            => ['@@', true],
			'bare network anchor'          => ['||', true],
			'bare regex'                   => ['/re/', true],
			'regex with important option'  => ['/re/$important', true],
			'regex with badfilter option'  => ['/re/$badfilter', true],
			'regex missing closing slash'  => ['/no-closing-slash', false],
			'element hiding mid-line'      => ['example.com##.ad', true],
			'element hiding leading'       => ['##.ad', true],
			'exception element hiding'     => ['a#@#b', true],
			'extended css element hiding'  => ['a#?#b', true],
			'snippet marker'               => ['a#%#b', true],
			'abp2 snippet marker'          => ['a#$#b', true],
			'hash comment, not element hiding' => ['example.com#plain-comment', false],
			'bare domain'                  => ['domain.com', false],
			'punycode domain'              => ['xn--nxasmq6b.com', false],
			'control line, not a rule'     => ['[Adblock', false],
			'single pipe, not an anchor'   => ['|single', false],
		];
	}

	#[DataProvider('ruleShapeProvider')]
	public function testShape(string $line, bool $expected): void
	{
		$this->assertSame($expected, pfb_dnsbl_is_abp_rule_line($line));
	}

	public function testCStyleCommentIsNotTreatedAsARegexRule(): void
	{
		// Probe (brief hostile row): '//comment' starts with '/' but has no closing
		// '/' and no '/$options' marker -- _dnsbl_parse_abp_regex() (pfb_unbound.py)
		// also returns None for it (its own bare-domain fallback rejects the '/'
		// it still carries) -- NO PHP<->Python disagreement found; both reject the
		// regex-shape reading of this line.
		$this->assertFalse(pfb_dnsbl_is_abp_rule_line('//comment'));
	}

	public function testTabLedAnchorIsNotCapturedUntrimmed(): void
	{
		// Probe (brief hostile row): a raw tab-led line, called directly (bypassing
		// the loop's own trim at inc:~16389), does not start with '||' -- consistent
		// with the caller-trims-first contract shared by the sibling predicates.
		$this->assertFalse(pfb_dnsbl_is_abp_rule_line("\t||x^"));
	}

	public function testBareRegexSlashAloneIsNotCapturable(): void
	{
		// A single '/' trivially "starts and ends" with '/', but
		// _dnsbl_parse_abp_regex() rejects it (empty inner pattern) -- pinning the
		// strlen guard that keeps this predicate agreeing with Python on the
		// degenerate case.
		$this->assertFalse(pfb_dnsbl_is_abp_rule_line('/'));
	}

	public function testBreakingTheClosingSlashRuleTurnsAMalformedRegexCapturable(): void
	{
		// Fail-on-mutation oracle: if the closing-slash rule were loosened to a bare
		// str_starts_with($line, '/'), '/no-closing-slash' would wrongly become
		// capturable -- this pins that it does NOT (mirrors
		// _dnsbl_parse_abp_regex()'s explicit rejection of a missing closing slash).
		$this->assertFalse(pfb_dnsbl_is_abp_rule_line('/no-closing-slash'));
		// And the genuine regex shape one character longer (closing slash present)
		// DOES flip true, proving the check is discriminating on the slash, not on
		// some other property of the string.
		$this->assertTrue(pfb_dnsbl_is_abp_rule_line('/no-closing-slash/'));
	}

	public function testBareDomainLineStaysOnThePlainPath(): void
	{
		// ADR-62 Decision-2 note: a bare domain line MUST be FALSE here -- that
		// classification split (delta D1) is Phase 5's concern, never this
		// capture-only predicate's.
		$this->assertFalse(pfb_dnsbl_is_abp_rule_line('domain.com'));
		$this->assertFalse(pfb_dnsbl_is_abp_rule_line('sub.domain.example'));
	}
}
