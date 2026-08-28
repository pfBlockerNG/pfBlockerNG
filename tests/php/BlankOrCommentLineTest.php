<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_is_blank_or_comment_line() — the blank/comment-prefix predicate for the generic
 * IP-list parser (its one production call site). The DNSBL hosts-format branch does
 * NOT call this function: it hand-inlines the equivalent '!'/'//' skip instead, kept
 * deliberately separate because its '#' handling carries side effects (hpHosts end
 * marker, Spamhaus format detection, h3x CSV header sniff) that must run BEFORE the
 * generic skip decision -- routing '#' through this predicate would skip those lines
 * before the side effects fire. The two are conceptually the same rule, not shared code.
 *
 * Regression pin for the DandelionSprouts bug (the DNSBL branch's own inlined check,
 * exercised indirectly here since it mirrors this predicate's '!'/'//' logic exactly):
 * a hosts-format feed embeds ABP-style '!#if'/'!#endif' directives mid-body; before
 * that inlined check existed, only '#'/'//' were recognised as comment prefixes there,
 * so a bang-comment line fell through into "typical host feed" column-stripping and
 * got logged as a parse error.
 *
 * Also pins that a scheme-less bracketed-IPv6 line ('://[...]', no leading '#'/'!'/'//')
 * is NOT swallowed here -- it must keep flowing to the strict-scheme validator, which is
 * the correct place to reject it (empty scheme before '://' is invalid URI syntax; this
 * is a separate, upstream-feed-defect concern from comment-line skipping).
 */
#[CoversFunction('pfb_is_blank_or_comment_line')]
final class BlankOrCommentLineTest extends TestCase
{
	public function testEmptyStringIsBlank(): void
	{
		$this->assertTrue(pfb_is_blank_or_comment_line(''));
	}

	public function testUntrimmedWhitespaceOnlyStringIsBlank(): void
	{
		// Issue #1787 flipped the old caller-trims-first contract: the helper now
		// strips the line itself (pfb_strip, Unicode class), so a whitespace-only
		// line is blank whether or not the caller trimmed. Pins the contract
		// explicitly instead of leaving it an unstated assumption.
		$this->assertTrue(pfb_is_blank_or_comment_line('   '));
	}

	public function testHashCommentIsSkipped(): void
	{
		$this->assertTrue(pfb_is_blank_or_comment_line('# a hosts-style comment'));
		$this->assertTrue(pfb_is_blank_or_comment_line('#'));
	}

	public function testBangCommentIsSkipped(): void
	{
		$this->assertTrue(pfb_is_blank_or_comment_line('!#if !env_mv3'));
		$this->assertTrue(pfb_is_blank_or_comment_line('!#endif'));
	}

	public function testSlashSlashCommentIsSkipped(): void
	{
		$this->assertTrue(pfb_is_blank_or_comment_line('// a C-style comment'));
	}

	public function testSingleSlashIsNotACommentPrefix(): void
	{
		// A lone leading '/' (e.g. a path-shaped line) must NOT match '//' by accident.
		$this->assertFalse(pfb_is_blank_or_comment_line('/etc/foo'));
	}

	public function testOrdinaryDomainLineIsNotSkipped(): void
	{
		$this->assertFalse(pfb_is_blank_or_comment_line('example.com'));
	}

	public function testOrdinaryIpLineIsNotSkipped(): void
	{
		$this->assertFalse(pfb_is_blank_or_comment_line('192.0.2.1'));
	}

	public function testSchemeLessBracketedIpv6IsNotSwallowedAsAComment(): void
	{
		// ':' is not '#'/'!'/'//' -- must fall through to the strict-scheme validator,
		// which is the correct layer to reject this (empty scheme before '://').
		$this->assertFalse(pfb_is_blank_or_comment_line('://[2604:2dc0:100:4ed8::]'));
	}
}
