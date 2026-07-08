<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_is_blank_or_comment_line() — the shared blank/comment-prefix predicate used by
 * the generic IP-list parser wholesale, and by the DNSBL hosts-format branch for its
 * side-effect-free '!'/'//' prefixes (its '#' handling carries side effects -- hpHosts
 * end marker, Spamhaus format detection, h3x CSV header sniff -- and is checked by the
 * caller itself, never routed through here).
 *
 * Regression pin for the DandelionSprouts bug: a hosts-format feed embeds ABP-style
 * '!#if'/'!#endif' directives mid-body; before this predicate existed, only '#'/'//'
 * were recognised as comment prefixes in that branch, so a bang-comment line fell
 * through into "typical host feed" column-stripping and got logged as a parse error.
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

	public function testUntrimmedWhitespaceOnlyStringIsNotBlank(): void
	{
		// empty('   ') is FALSE in PHP -- this predicate relies on the caller having
		// already trim()'d $line (both call sites do), matching every other
		// empty($line) check in this file rather than reimplementing trim-and-check.
		// Pins the contract explicitly instead of leaving it an unstated assumption.
		$this->assertFalse(pfb_is_blank_or_comment_line('   '));
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
