<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_sanitize_text() / pfb_sanitize_text_area() — shared text-field
 * normalizers (issues #1710/#1707): scrub invalid encodings to UTF-8, strip
 * Unicode control characters (and the BOM), and normalize whitespace. The
 * single-line helper strips CR/LF/TAB too; the textarea helper normalizes
 * line endings to LF and right-strips per-line trailing whitespace instead.
 */
#[CoversFunction('pfb_sanitize_text')]
#[CoversFunction('pfb_sanitize_text_area')]
final class PfbSanitizeTextTest extends TestCase
{
	// --- pfb_sanitize_text() ---

	public function testSanitizeTextRemovesC0ControlChars(): void
	{
		$this->assertSame('hello', pfb_sanitize_text("h\x00e\x1Bl\x07lo"));
	}

	public function testSanitizeTextRemovesEscButKeepsPrintableRemainder(): void
	{
		// ESC alone is the Cc control byte; the printable ANSI-code remainder
		// that follows it is ordinary text and survives.
		$this->assertSame('red[31mtext', pfb_sanitize_text("red\x1b[31mtext"));
	}

	public function testSanitizeTextRemovesDel(): void
	{
		$this->assertSame('ab', pfb_sanitize_text("a\x7Fb"));
	}

	public function testSanitizeTextRemovesEmbeddedLineEndingsAndTabs(): void
	{
		$this->assertSame('abcd', pfb_sanitize_text("a\rb\nc\td"));
	}

	public function testSanitizeTextRemovesBom(): void
	{
		$this->assertSame('hello', pfb_sanitize_text("\xEF\xBB\xBFhello"));
	}

	public function testSanitizeTextTrimsLeadingAndTrailingWhitespace(): void
	{
		$this->assertSame('hello', pfb_sanitize_text('  hello  '));
	}

	public function testSanitizeTextPreservesLiteralZero(): void
	{
		$this->assertSame('0', pfb_sanitize_text('0'));
	}

	public function testSanitizeTextEmptyInputReturnsEmptyString(): void
	{
		$this->assertSame('', pfb_sanitize_text(''));
	}

	public function testSanitizeTextPreservesUnicodeText(): void
	{
		$this->assertSame('café', pfb_sanitize_text('café'));
		$this->assertSame('日本語', pfb_sanitize_text('日本語'));
		$this->assertSame('🎉', pfb_sanitize_text('🎉'));
	}

	public function testSanitizeTextPreservesNbspMidString(): void
	{
		$this->assertSame("a\xC2\xA0b", pfb_sanitize_text("a\xC2\xA0b"));
	}

	public function testSanitizeTextPreservesZeroWidthJoiner(): void
	{
		$this->assertSame("a\xE2\x80\x8Db", pfb_sanitize_text("a\xE2\x80\x8Db"));
	}

	public function testSanitizeTextConvertsInvalidUtf8FromIso88591(): void
	{
		$this->assertSame('bücher', pfb_sanitize_text("b\xFCcher"));
	}

	// --- pfb_sanitize_text_area() ---

	public function testSanitizeTextAreaNormalizesCrlfToLf(): void
	{
		$this->assertSame("a\nb", pfb_sanitize_text_area("a\r\nb"));
	}

	public function testSanitizeTextAreaNormalizesCrToLf(): void
	{
		$this->assertSame("a\nb", pfb_sanitize_text_area("a\rb"));
	}

	public function testSanitizeTextAreaLeavesLfUnchanged(): void
	{
		$this->assertSame("a\nb", pfb_sanitize_text_area("a\nb"));
	}

	public function testSanitizeTextAreaNormalizesMixedLineEndings(): void
	{
		$this->assertSame("a\nb\nc\nd", pfb_sanitize_text_area("a\r\nb\nc\rd"));
	}

	public function testSanitizeTextAreaStripsTrailingSpacesAndTabsPerLine(): void
	{
		$this->assertSame("a\nb", pfb_sanitize_text_area("a  \t \nb\t\t"));
	}

	public function testSanitizeTextAreaPreservesLeadingIndentation(): void
	{
		$this->assertSame("  a\n\tb", pfb_sanitize_text_area("  a\n\tb"));
	}

	public function testSanitizeTextAreaPreservesInteriorTab(): void
	{
		$this->assertSame("a\tb", pfb_sanitize_text_area("a\tb"));
	}

	public function testSanitizeTextAreaRemovesVtFfNelEsc(): void
	{
		$in = "a\x0Bb\ncd\x0C\ne\x1Bf\ng\xC2\x85h";
		$this->assertSame("ab\ncd\nef\ngh", pfb_sanitize_text_area($in));
	}

	public function testSanitizeTextAreaRemovesBom(): void
	{
		$this->assertSame('hello', pfb_sanitize_text_area("\xEF\xBB\xBFhello"));
	}

	public function testSanitizeTextAreaPreservesUnicodeLineContent(): void
	{
		$this->assertSame("café\n日本語\n🎉", pfb_sanitize_text_area("café\n日本語\n🎉"));
	}

	public function testSanitizeTextAreaConvertsInvalidUtf8FromIso88591(): void
	{
		$this->assertSame('bücher', pfb_sanitize_text_area("b\xFCcher"));
	}

	public function testSanitizeTextAreaEmptyInputReturnsEmptyString(): void
	{
		$this->assertSame('', pfb_sanitize_text_area(''));
	}

	public function testSanitizeTextAreaPreservesBlankLinesAsRows(): void
	{
		// The helper does not drop rows — that is the caller's job.
		$this->assertSame("a\n\nb", pfb_sanitize_text_area("a\n\nb"));
	}
}
