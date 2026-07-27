<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_is_empty() / pfb_rstrip() (issue #1787) — the honest "is this an empty
 * string?" answer and the Unicode-aware right-strip.
 *
 * pfb_is_empty() exists because empty() lies: empty('0') is TRUE, but "0" is a
 * real value (issue #1707). Absent (NULL) and '' are empty; everything else —
 * including whitespace — is content (blankness is pfb_is_blank()'s question).
 *
 * pfb_rstrip() strips trailing ASCII whitespace like rtrim(), and additionally
 * the Unicode whitespace/separator class pfb_is_blank() calls blank (NBSP,
 * ideographic space, line/paragraph separators, the BOM). Leading whitespace
 * is preserved — it is a right-strip, not a trim.
 */
#[CoversFunction('pfb_is_empty')]
#[CoversFunction('pfb_rstrip')]
final class PfbIsEmptyRstripTest extends TestCase
{
	// --- pfb_is_empty -----------------------------------------------------

	public function testAbsentAndEmptyStringAreEmpty(): void
	{
		$this->assertTrue(pfb_is_empty(NULL));
		$this->assertTrue(pfb_is_empty(''));
	}

	public function testZeroStringIsNotEmpty(): void
	{
		// The whole reason this helper exists instead of empty(): "0" is a
		// real value, and empty('0') is TRUE.
		$this->assertFalse(pfb_is_empty('0'));
	}

	public function testWhitespaceIsContentNotEmptiness(): void
	{
		// Emptiness is exact; a whitespace-only string is BLANK (pfb_is_blank),
		// not empty.
		$this->assertFalse(pfb_is_empty(' '));
		$this->assertFalse(pfb_is_empty("\u{00A0}"));
		$this->assertFalse(pfb_is_empty('a'));
	}

	// --- pfb_rstrip -------------------------------------------------------

	public function testStripsTrailingAsciiWhitespace(): void
	{
		$this->assertSame('value', pfb_rstrip("value \t\r\n"));
	}

	public function testStripsTrailingUnicodeWhitespaceAndBom(): void
	{
		// NBSP, ideographic space, line separator, BOM — all trailing
		// whitespace-class characters rtrim() misses.
		$this->assertSame('value', pfb_rstrip("value\u{00A0}\u{3000}\u{2028}\u{FEFF}"));
		// Mixed ASCII/Unicode runs strip in one pass too.
		$this->assertSame('value', pfb_rstrip("value \u{00A0}\t\u{3000} "));
	}

	public function testPreservesLeadingWhitespaceAndInnerContent(): void
	{
		// A right-strip, not a trim: the left side and inner whitespace stay.
		$this->assertSame("\u{00A0} a b", pfb_rstrip("\u{00A0} a b \u{00A0}"));
	}

	public function testWhitespaceOnlyStringStripsToEmpty(): void
	{
		$this->assertSame('', pfb_rstrip(" \t\u{00A0}\u{3000}"));
		$this->assertSame('', pfb_rstrip(''));
	}

	public function testZeroSurvives(): void
	{
		// The issue-#1707 row: "0" is data, never stripped to nothing.
		$this->assertSame('0', pfb_rstrip('0 '));
	}
}
