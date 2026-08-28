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
	public static function positionZeroUnicodeWhitespaceProvider(): array
	{
		$whitespace = [
			'0009' => "\x09",
			'000A' => "\x0A",
			'000B' => "\x0B",
			'000C' => "\x0C",
			'000D' => "\x0D",
			'001C' => "\x1C",
			'001D' => "\x1D",
			'001E' => "\x1E",
			'001F' => "\x1F",
			'0020' => ' ',
			'0085' => "\xC2\x85",
			'00A0' => "\xC2\xA0",
			'1680' => "\xE1\x9A\x80",
			'2000' => "\xE2\x80\x80",
			'2001' => "\xE2\x80\x81",
			'2002' => "\xE2\x80\x82",
			'2003' => "\xE2\x80\x83",
			'2004' => "\xE2\x80\x84",
			'2005' => "\xE2\x80\x85",
			'2006' => "\xE2\x80\x86",
			'2007' => "\xE2\x80\x87",
			'2008' => "\xE2\x80\x88",
			'2009' => "\xE2\x80\x89",
			'200A' => "\xE2\x80\x8A",
			'2028' => "\xE2\x80\xA8",
			'2029' => "\xE2\x80\xA9",
			'202F' => "\xE2\x80\xAF",
			'205F' => "\xE2\x81\x9F",
			'3000' => "\xE3\x80\x80",
		];
		$cases = [];
		foreach (['##', '#@#', '#?#', '#%#', '#$#'] as $marker) {
			foreach ($whitespace as $codePoint => $separator) {
				$cases["{$marker} U+{$codePoint}"] = ["{$marker}{$separator}Section", false];
			}
		}

		return $cases + [
			'U+200B is content' => ["##\xE2\x80\x8BSection", true],
			'U+FEFF is content' => ["##\xEF\xBB\xBFSection", true],
			'malformed UTF-8 is content' => ["##\xFFSection", true],
			'## U+2003 then malformed UTF-8 remains whitespace' => ["##\xE2\x80\x83\xFFSection", false],
			'#@# U+2003 then malformed UTF-8 remains whitespace' => ["#@#\xE2\x80\x83\xFFSection", false],
			'#?# U+2003 then malformed UTF-8 remains whitespace' => ["#?#\xE2\x80\x83\xFFSection", false],
			'#%# U+2003 then malformed UTF-8 remains whitespace' => ["#%#\xE2\x80\x83\xFFSection", false],
			'#$# U+2003 then malformed UTF-8 remains whitespace' => ["#$#\xE2\x80\x83\xFFSection", false],
			'metacharacter payload is content' => ['##[data-test="a+b?c$"]', true],
			'punycode cosmetic prefix remains valid' => ['xn--nxasmq6b.com##.ad', true],
			'raw-Unicode cosmetic prefix remains invalid' => ["\xC3\xA9.example##.ad", false],
			'domain-prefixed marker with EM SPACE remains valid' => ["example.com##\xE2\x80\x83Section", true],
		];
	}

	#[DataProvider('positionZeroUnicodeWhitespaceProvider')]
	public function testPositionZeroUnicodeWhitespaceIsNotCaptured(string $line, bool $expected): void
	{
		$this->assertSame($expected, pfb_dnsbl_is_abp_rule_line($line));
	}

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
			// Cosmetic-prefix guard: a mid-line ' ## ' inline comment (hosts dialect),
			// a '#'-led comment mentioning a marker, or a URL/CSV '#'-fragment must
			// stay on the plain path -- capture would silently drop a working block.
			'hosts line with inline ## comment'   => ['0.0.0.0 example.com ## comment', false],
			'bare domain with inline ## comment'  => ['example.com ## seen 2024', false],
			'csv row with url #-fragment'         => ['12345,http://evil.example/path##frag,phish,online', false],
			'url with ##-fragment'                => ['http://example.com/##banner', false],
			'hash comment mentioning ##'          => ['# note ## x', false],
			'classifier-style comment with ##'    => ['# The Spamhaus Project Ltd ## marketing ## banner', false],
			'hash comment with exception marker'  => ['# c#@#d', false],
			'tab-led cosmetic rule (caller trims)' => ["\thost.example##.ad", false],
			'all-hash banner (marker at pos 0)'   => ['####################', true],
			'cosmetic rule, domain list'          => ['a.com,b.com##.ad', true],
			'cosmetic rule, longer domain list'   => ['example.com,example.org##.ad', true],
			'cosmetic rule, negated domain'       => ['~ex.com##.ad', true],
			'cosmetic rule, mixed-case domain'    => ['EXAMPLE.com##.ad', true],
			// '//'-led lines are comments by feed convention, never regex rules --
			// even with a closing '/' that would otherwise satisfy the /re/ shape.
			'comment with trailing slash'         => ['//cdn.example.com/ads/', false],
			'bare double slash'                   => ['//', false],
			'yhost @-prefix line'                 => ['@stray.example', false],
			// issue #1067: a leading comma is never valid ABP syntax (an empty first
			// cosmetic domain-list entry) -- left uncaught, a comma-first verbatim
			// capture collides with the plain-CSV dialect on the read side.
			'comma-prefixed cosmetic, 4 commas'      => [',a,b,c,d##x', false],
			'comma-prefixed cosmetic domain list'    => [',example.com,example.org##.ad', false],
			'comma-prefixed, mimics CSV field shape' => [',a,,1,RealFeed,x##y', false],
			'comma-prefixed network anchor'          => [',||x^', false],
			'bare comma'                             => [',', false],
			'comma-prefixed, marker at position 1'   => [',,##x', false],
			// issue #1276: a hosts-dialect whole-line comment ('## Section', a
			// marker at position 0 followed by whitespace) shares its shape with
			// a real generic cosmetic rule ('##selector') -- must stay on the
			// plain '#'-comment path, not be captured as an ABP element-hiding row.
			'hosts-dialect header, marker+space'         => ['## Section header', false],
			'hosts-dialect header, marker+tab'           => ["##\tSection", false],
			'sibling marker hosts-dialect, marker+space' => ['#@# note', false],
			'sibling marker exception rule, no space'    => ['#@#selector', true],
			'bare marker, nothing after'                 => ['##', false],
			// issue #1276: other whitespace a malformed feed can embed mid-line
			// (CR/VT/FF survive the caller's edge-only trim) is a comment too.
			'hosts-dialect header, marker+CR'            => ["##\rSection", false],
			'hosts-dialect header, marker+vertical tab'  => ["##\x0Bsection", false],
			'hosts-dialect header, marker+form feed'     => ["##\x0Csection", false],
			// issue #1276: a copy-pasted NBSP (U+00A0, UTF-8 "\xC2\xA0") right
			// after the marker must count as whitespace too, matching the call
			// site's own trim() charlist and Python's .isspace() on the same input.
			'hosts-dialect header, marker+NBSP'          => ["##\xC2\xA0Section", false],
			// issue #1276: every element-hiding marker sibling gets a position-0
			// row, not just '##'/'#@#' -- the guard branch is shared by all five.
			'sibling marker #?#, hosts-dialect'          => ['#?# note', false],
			'sibling marker #?#, no space'                => ['#?#selector', true],
			'sibling marker #%#, hosts-dialect'          => ['#%# note', false],
			'sibling marker #%#, no space'                => ['#%#selector', true],
			'sibling marker #$#, hosts-dialect'          => ['#$# note', false],
			'sibling marker #$#, no space'                => ['#$#selector', true],
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
