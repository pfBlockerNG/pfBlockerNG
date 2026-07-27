<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_is_empty() / pfb_rstrip() / pfb_lstrip() / pfb_strip() (issue #1787) —
 * the honest "is this an empty string?" answer and the Unicode-aware strips.
 *
 * pfb_is_empty() exists because empty() lies: empty('0') is TRUE, but "0" is a
 * real value (issue #1707). Absent (NULL) and '' are empty; everything else —
 * including whitespace — is content (blankness is pfb_is_blank()'s question).
 *
 * pfb_rstrip() strips trailing ASCII whitespace like rtrim(), and additionally
 * the Unicode whitespace/separator class pfb_is_blank() calls blank (NBSP,
 * ideographic space, line/paragraph separators, the BOM). Leading whitespace
 * is preserved — it is a right-strip, not a trim. pfb_lstrip() is its leading
 * mirror (so "what is the first NONBLANK character?" is answerable), and
 * pfb_strip() is the double-sided combination — trim() over the same class.
 */
#[CoversFunction('pfb_is_empty')]
#[CoversFunction('pfb_rstrip')]
#[CoversFunction('pfb_lstrip')]
#[CoversFunction('pfb_strip')]
#[CoversFunction('pfb_csv_list')]
#[CoversFunction('pfb_b64_text')]
final class PfbStringHelpersTest extends TestCase
{
	// --- pfb_csv_list (issue #1792) ---------------------------------------

	public function testCsvListSplitsEntriesAndKeepsZero(): void
	{
		$this->assertSame(['a', 'b'], pfb_csv_list('a,b'));
		// "0" is one real entry, never the default (the empty('0') lie again).
		$this->assertSame(['0'], pfb_csv_list('0'));
	}

	public function testCsvListAbsentOrEmptyYieldsDefault(): void
	{
		// The `explode(...) ?: $default` idiom this replaces NEVER produced
		// the default -- explode() on a string is always truthy, so '' gave
		// [''] and NULL gave [''] too. The default must now genuinely apply.
		$this->assertSame([], pfb_csv_list(NULL));
		$this->assertSame([], pfb_csv_list(''));
		$this->assertSame(['x', 'y'], pfb_csv_list('', ['x', 'y']));
		$this->assertSame(['x', 'y'], pfb_csv_list(NULL, ['x', 'y']));
	}

	// --- pfb_b64_text (issue #1792) ---------------------------------------

	public function testB64TextDecodesAndKeepsZero(): void
	{
		$this->assertSame('abc', pfb_b64_text(base64_encode('abc')));
		// 'MA==' decodes to '0' -- falsy, eaten by the `?: ''` idiom this
		// replaces; a stored "0" must survive to the re-rendered form.
		$this->assertSame('0', pfb_b64_text('MA=='));
	}

	public function testB64TextAbsentEmptyOrMalformedYieldsEmptyString(): void
	{
		$this->assertSame('', pfb_b64_text(NULL));
		$this->assertSame('', pfb_b64_text(''));
		// base64_decode() returns FALSE only in strict mode; the non-strict
		// default never does -- pinned so the FALSE guard is provably the
		// only degradation path and '' stays the worst case.
		$this->assertSame('', pfb_b64_text(base64_encode('')));
	}

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

	// --- pfb_lstrip -------------------------------------------------------

	public function testLstripStripsLeadingAsciiAndUnicodeWhitespace(): void
	{
		$this->assertSame('value', pfb_lstrip(" \t\u{00A0}\u{3000}\u{FEFF}value"));
	}

	public function testLstripPreservesTrailingWhitespaceAndInnerContent(): void
	{
		// A left-strip, not a trim: the right side and inner whitespace stay.
		$this->assertSame("a b \u{00A0}", pfb_lstrip("\u{00A0} a b \u{00A0}"));
	}

	public function testLstripExposesFirstNonblankCharacter(): void
	{
		// The comment-detection use: '#' hiding behind indentation is still
		// the first nonblank character.
		$this->assertTrue(str_starts_with(pfb_lstrip("\u{00A0} # comment"), '#'));
		$this->assertSame('', pfb_lstrip(" \u{00A0}"));
	}

	// --- pfb_strip --------------------------------------------------------

	public function testStripTrimsBothSidesAcrossAsciiAndUnicode(): void
	{
		$this->assertSame('a b', pfb_strip("\u{FEFF}\u{00A0} a b \t\u{3000}\r\n"));
		$this->assertSame('', pfb_strip(" \u{00A0}\u{2029} "));
	}

	public function testStripZeroSurvives(): void
	{
		$this->assertSame('0', pfb_strip(" 0\u{00A0}"));
	}

	public function testInvalidUtf8DegradesFailOpen(): void
	{
		// A truncated multibyte sequence makes the /u preg pass return NULL;
		// the strips must degrade to the ASCII-trimmed bytes, never to NULL
		// or wiped data (same fail-open contract as pfb_preg_replace_safe).
		$this->assertSame("abc\xC2", pfb_rstrip("abc\xC2"));
		$this->assertSame("abc\xC2", pfb_lstrip("abc\xC2"));
		$this->assertSame("abc\xC2", pfb_strip("abc\xC2"));
	}
}
