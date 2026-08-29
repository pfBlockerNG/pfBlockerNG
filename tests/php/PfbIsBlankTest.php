<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_is_blank() — the "nothing there" predicate for text values.
 *
 * empty() is the usual idiom but it calls the valid list row "0" empty (the
 * issue #1707 trap) and calls a whitespace-only string non-empty. This
 * predicate is TRUE for exactly one thing: no content at all — absent, empty,
 * or nothing but whitespace, ASCII or Unicode.
 */
#[CoversFunction('pfb_is_blank')]
final class PfbIsBlankTest extends TestCase
{
	public function testAbsentValueIsBlank(): void
	{
		$this->assertTrue(pfb_is_blank(NULL));
	}

	public function testEmptyStringIsBlank(): void
	{
		$this->assertTrue(pfb_is_blank(''));
	}

	public function testAsciiWhitespaceOnlyIsBlank(): void
	{
		$this->assertTrue(pfb_is_blank(' '));
		$this->assertTrue(pfb_is_blank("\t\n\r  "));
	}

	public function testUnicodeWhitespaceOnlyIsBlank(): void
	{
		// NBSP, ideographic space, and the BOM are what a copy-paste from a
		// browser or a spreadsheet actually leaves behind.
		$this->assertTrue(pfb_is_blank("\xC2\xA0"));
		$this->assertTrue(pfb_is_blank("\xE3\x80\x80"));
		$this->assertTrue(pfb_is_blank("\xEF\xBB\xBF"));
		$this->assertTrue(pfb_is_blank("\xC2\xA0 \xE3\x80\x80"));
	}

	public function testZeroIsNotBlank(): void
	{
		// The whole reason this predicate exists instead of empty(): "0" is a
		// valid row (issue #1707), and empty("0") is TRUE.
		$this->assertFalse(pfb_is_blank('0'));
		$this->assertFalse(pfb_is_blank(' 0 '));
	}

	public function testContentIsNotBlank(): void
	{
		$this->assertFalse(pfb_is_blank('example.com'));
		$this->assertFalse(pfb_is_blank('  example.com  '));
		$this->assertFalse(pfb_is_blank('.'));
	}

	public function testInvalidUtf8ReadsAsNonBlank(): void
	{
		// The Unicode pass degrades fail-open: a value the regex engine cannot
		// walk is treated as content, never silently as nothing.
		$this->assertFalse(pfb_is_blank("\xC3\x28"));
	}
}
