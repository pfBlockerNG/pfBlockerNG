<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_is_abp_header() — ADR-21 §2.4 broadened whole-feed ABP header sniff.
 *
 * The download-loop header sniff previously matched four magic strings via a mid-line
 * strpos() ('[Adblock Plus ' / '[Adblock Plus]' / '[uBlock Origin' / '! Title: AdGuard').
 * ADR-21 replaces those with three generic, leading-whitespace-tolerant PREFIX checks
 * ('[Adblock', '[uBlock', '! Title:') so a conventionally-authored ABP list led by ANY
 * '! Title:' (e.g. HaGeZi's ABP-format DNS lists) is detected, while a '! Title:'-like
 * token appearing MID-LINE in a data line can no longer flip the feed.
 *
 * Branch coverage: every prefix class that MUST flip the feed (TRUE) is paired with the
 * non-header / mid-line classes that must NOT (FALSE), so each side of the predicate is
 * pinned. The four legacy magic strings are pinned as a regression (superset guarantee,
 * ADR §2.3.9).
 */
#[CoversFunction('pfb_dnsbl_is_abp_header')]
final class DnsblIsAbpHeaderTest extends TestCase
{
	public static function provider(): array
	{
		return [
			// --- The four legacy magic strings still detect (ADR §2.3.9 regression). ---
			'legacy [Adblock Plus <ver>'       => ['[Adblock Plus 2.0]', true],
			'legacy [Adblock Plus]'            => ['[Adblock Plus]', true],
			'legacy [uBlock Origin'            => ['[uBlock Origin]', true],
			'legacy ! Title: AdGuard'          => ['! Title: AdGuard DNS filter', true],

			// --- Broadened: ANY '! Title:' / '[Adblock' / '[uBlock' prefix flips. ---
			'! Title: HaGeZi (non-AdGuard)'    => ['! Title: HaGeZi Pro DNS Blocklist', true],
			'! Title: bare'                    => ['! Title:', true],
			'[Adblock generic'                 => ['[Adblock]', true],
			'[uBlock generic'                  => ['[uBlock]', true],
			'leading whitespace tolerated'     => ['   ! Title: Something', true],
			'leading tab tolerated'            => ["\t[Adblock Plus]", true],

			// --- Non-headers / data lines must NOT flip. ---
			'plain bare domain'                => ['x.com', false],
			'hosts-format line'                => ['0.0.0.0 x.com', false],
			'abp anchor (per-line, not header)' => ['||x^', false],
			'plain ! comment'                  => ['! this is just a comment', false],
			'! Title mid-line in data'         => ['x.com ! Title: nope', false],
			'! Title: not at line start'       => ['data ! Title: AdGuard', false],
			'empty line'                       => ['', false],
			'hash comment'                     => ['# comment', false],
		];
	}

	#[DataProvider('provider')]
	public function testIsAbpHeader(string $line, bool $expected): void
	{
		$this->assertSame($expected, pfb_dnsbl_is_abp_header($line));
	}
}
