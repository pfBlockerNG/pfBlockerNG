<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_sanitize_text() / pfb_sanitize_text_area() — shared text-field
 * normalizers (issues #1710/#1707/#1795): scrub invalid encodings to UTF-8,
 * strip every \p{C} character (Cc/Cf/Co/Cs/Cn, which subsumes the BOM), and
 * normalize whitespace. The single-line helper strips CR/LF/TAB too; the
 * textarea helper normalizes line endings to LF, keeps \n/\t, and
 * right-strips per-line trailing whitespace instead.
 */
#[CoversFunction('pfb_sanitize_text')]
#[CoversFunction('pfb_sanitize_text_area')]
#[CoversFunction('pfb_text_area_encode')]
#[CoversFunction('pfb_text_area_decode')]
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

	public function testSanitizeTextStripsZeroWidthJoiner(): void
	{
		// issue #1795: widened from \p{Cc}+BOM to the full \p{C} set -- ZWJ
		// (U+200D) is Cf, so it is now stripped like every other format char.
		$this->assertSame('ab', pfb_sanitize_text("a\xE2\x80\x8Db"));
	}

	public function testSanitizeTextStripsPrivateUseChar(): void
	{
		// U+E000 (private-use area, category Co) -- issue #1795 widening.
		$this->assertSame('ab', pfb_sanitize_text("a\xEE\x80\x80b"));
	}

	public function testSanitizeTextStripsUnassignedCodepoint(): void
	{
		// U+0378 is unassigned (category Cn) -- issue #1795 widening.
		$this->assertSame('ab', pfb_sanitize_text("a\xCD\xB8b"));
	}

	public function testSanitizeTextNeverLeaksASurrogateCodepoint(): void
	{
		// Category Cs (surrogate) has no valid UTF-8 encoding (RFC 3629
		// excludes it) -- PCRE's /u modifier refuses to even run \p{C} over a
		// subject containing raw surrogate-shaped bytes (probed: preg_replace()
		// returns NULL, not a Cs match), so the \p{C} strip itself never sees
		// one. The issue #1797 (A6) deterministic scrub upstream substitutes
		// each of the raw bytes \xED\xA0\x80 with '?' first -- so no Cs
		// codepoint ever reaches the output, and the bytes that came along
		// with it do not survive either. Probed exact result (issues
		// #1795/#1797), not predicted.
		$this->assertSame('a???b', pfb_sanitize_text("a\xED\xA0\x80b"));
	}

	public function testSanitizeTextScrubsInvalidUtf8Deterministically(): void
	{
		// issue #1797 (A6): no ISO-8859-1 guessing -- mb_detect_encoding() can
		// never fail (every byte sequence is valid ISO-8859-1), so the old
		// branch silently produced mojibake. Invalid sequences are substituted
		// deterministically instead; the output-is-valid-UTF-8 invariant is
		// what pfb_preg_replace_safe()'s /u patterns depend on.
		$out = pfb_sanitize_text("b\xFCcher");
		$this->assertSame('b?cher', $out);
		$this->assertTrue(mb_check_encoding($out, 'UTF-8'));
	}

	public function testSanitizeTextRemovesC1ControlChars(): void
	{
		// NEL (U+0085, UTF-8 \xC2\x85) is a C1 control char, covered by \p{Cc}.
		$this->assertSame('ab', pfb_sanitize_text("a\xC2\x85b"));
	}

	public function testSanitizeTextStripsBidiMarks(): void
	{
		// issue #1795: RLO (U+202E) is Cf, now covered by the widened \p{C} strip.
		$this->assertSame('ab', pfb_sanitize_text("a\xE2\x80\xAEb"));
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

	public function testSanitizeTextAreaStripsCfCoCnButPreservesNewlineAndTab(): void
	{
		// issue #1795: widened from \p{Cc}(-\n\t)+BOM to the full \p{C} set
		// minus \n/\t. ZWJ (Cf, U+200D), private-use (Co, U+E000), and
		// unassigned (Cn, U+0378) are now stripped on every line; \n and \t
		// must still survive untouched.
		$in = "a\xE2\x80\x8D\tb\ncd\xEE\x80\x80\ne\xCD\xB8f";
		$this->assertSame("a\tb\ncd\nef", pfb_sanitize_text_area($in));
	}

	public function testSanitizeTextAreaPreservesUnicodeLineContent(): void
	{
		$this->assertSame("café\n日本語\n🎉", pfb_sanitize_text_area("café\n日本語\n🎉"));
	}

	public function testSanitizeTextAreaConvertsInvalidUtf8FromIso88591(): void
	{
		// issue #1797 (A6): the textarea helper KEEPS its legacy-encoding
		// conversion -- pfb_text_area_decode() feeds it config.xml blobs
		// written by older versions / restores / XMLRPC sync, and its docblock
		// promises legacy conversion. Only browser-fed pfb_sanitize_text()
		// dropped the guessing branch.
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

	public function testSanitizeTextSurvivesHugeWhitespaceRun(): void
	{
		// A >1,000,000-char space run defeats the trim regex's backtrack limit
		// the same way testSanitizeTextAreaSurvivesHugeSpaceRunMidLine() pins for
		// the textarea helper. Probed (issue #1723): pfb_preg_replace_safe()
		// degrades to the UNSTRIPPED input byte-for-byte (leading/trailing NBSP
		// included) rather than fatal-ing or wiping data -- a fail-open pin, not
		// a design goal: under this load the Unicode-whitespace trim may not
		// apply for the call.
		$in = "\xC2\xA0x" . str_repeat(' ', 1100000) . "y\xC2\xA0";
		$out = pfb_sanitize_text($in);
		$this->assertIsString($out);
		$this->assertStringContainsString('x', $out);
		$this->assertStringContainsString('y', $out);
		$this->assertSame($in, $out);
	}

	// --- pfb_text_area_encode() ---

	public function testTextAreaEncodeEmptyInputReturnsEmptyString(): void
	{
		$this->assertSame('', pfb_text_area_encode(''));
	}

	public function testTextAreaEncodeDecodeRoundTrip(): void
	{
		// Persist-boundary (encode) feeding the read-boundary (decode): the
		// decoder lowercases, strips \x07 (Cc, stripped by
		// pfb_sanitize_text_area()), and right-strips the trailing NBSP+space
		// off the 'B' row. Probed exact result (issue #1723): three rows,
		// 'a'/'b'/'c' -- not two, the \x07 does not merge 'B' and 'C' into one
		// row since it sits immediately after the '\n' it does not remove.
		$raw = "A\r\nB\xC2\xA0 \n\x07C";
		$encoded = pfb_text_area_encode($raw);
		$this->assertSame(['a', 'b', 'c'], pfb_text_area_decode($encoded, TRUE, FALSE));
	}

	// --- pfb_text_area_decode() ---

	public function testTextAreaDecodeAcceptsNullWithNoDiagnostics(): void
	{
		// issue #1768: untyped $text flows into base64_decode(); an absent
		// caller-side value (NULL) previously deprecated (PHP 8.1+: passing
		// NULL to a non-nullable string parameter). Coerced to '' at entry now.
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		}, E_WARNING | E_DEPRECATED);
		try {
			$result = pfb_text_area_decode(NULL);
		} finally {
			restore_error_handler();
		}
		$this->assertSame(
			[],
			$diagnostics,
			"pfb_text_area_decode(NULL) must emit zero diagnostics, got:\n" . implode("\n", $diagnostics)
		);
		$this->assertSame('', $result);
	}
}
