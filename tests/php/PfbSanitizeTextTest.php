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

	public function testSanitizeTextRemovesC1ControlChars(): void
	{
		// NEL (U+0085, UTF-8 \xC2\x85) is a C1 control char, covered by \p{Cc}.
		$this->assertSame('ab', pfb_sanitize_text("a\xC2\x85b"));
	}

	public function testSanitizeTextPreservesBidiMarks(): void
	{
		// RLO (U+202E) is a Unicode format char, not \p{Cc} -- must survive.
		$this->assertSame("a\xE2\x80\xAEb", pfb_sanitize_text("a\xE2\x80\xAEb"));
	}

	public function testSanitizeTextTrimsUnicodeWhitespace(): void
	{
		// Leading U+3000 (ideographic space) and trailing NBSP must be trimmed,
		// not just ASCII space/tab.
		$this->assertSame('x', pfb_sanitize_text("\xE3\x80\x80x\xC2\xA0"));
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

	public function testSanitizeTextAreaSurvivesHugeControlRun(): void
	{
		// A pathological run of control chars must not blow up the alternation
		// pattern (JIT stack exhaustion -> NULL -> whole blob wiped to '').
		$in = "keep\n" . str_repeat("\x00", 20000) . "\nalso";
		$this->assertSame("keep\n\nalso", pfb_sanitize_text_area($in));
	}

	public function testSanitizeTextAreaSurvivesHugeSpaceRunMidLine(): void
	{
		// A >1,000,000-char space run mid-line (not at end-of-line) must not
		// exhaust pcre.backtrack_limit and fatal via the : string return type.
		$line = 'a' . str_repeat(' ', 1000001) . 'b';
		$this->assertSame($line . "\n", pfb_sanitize_text_area($line . "\n"));
	}

	public function testSanitizeTextAreaStripsTrailingUnicodeWhitespace(): void
	{
		// Trailing NBSP / U+3000 must right-strip like ASCII space/tab.
		$this->assertSame("a\nb\n", pfb_sanitize_text_area("a\xC2\xA0\nb\xE3\x80\x80\n"));
	}
}
