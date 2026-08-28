<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_text_area_decode() — the Custom_List/whitelist textarea decoder: base64
 * in, CRLF-split, '#'-comment handling, lower-casing, optional IDN->punycode.
 *
 * $mode: FALSE => newline-joined string; TRUE => array.
 * $type (mode only): TRUE => per-line [value(, '#comment')]; FALSE => bare value.
 * $idn:  TRUE  => convert non-ASCII hostnames to punycode (idn_to_ascii).
 */
#[CoversFunction('pfb_text_area_decode')]
final class TextAreaDecodeTest extends TestCase
{
	/** Encode like a browser textarea: lines joined by CRLF, then base64. */
	private static function enc(string ...$lines): string
	{
		return base64_encode(implode("\r\n", $lines));
	}

	/** Encode a raw payload verbatim (no CRLF-join) — for line-ending/control-char tests. */
	private static function rawEnc(string $raw): string
	{
		return base64_encode($raw);
	}

	public function testStringModeLowercasesJoinsAndStripsComments(): void
	{
		$in = self::enc('EXAMPLE.COM', 'foo.com', '# whole-line comment', 'bar.com # inline');
		// Whole-line comment dropped; inline comment trimmed off; all lower-cased.
		$this->assertSame("example.com\nfoo.com\nbar.com\n", pfb_text_area_decode($in));
	}

	public function testStringModeSkipsEmptyLines(): void
	{
		$in = self::enc('a.com', '', 'b.com');
		$this->assertSame("a.com\nb.com\n", pfb_text_area_decode($in));
	}

	public function testArrayModeBareValues(): void
	{
		$in = self::enc('Foo.com', '# c', 'bar.com # x');
		// mode=TRUE, type=FALSE => array of bare, comment-stripped, lower values.
		$this->assertSame(['foo.com', 'bar.com'], pfb_text_area_decode($in, true, false));
	}

	public function testArrayModeTypedNonCommentWrapsInArray(): void
	{
		$in = self::enc('Foo.com');
		// mode=TRUE, type=TRUE => each non-comment line becomes [value].
		$this->assertSame([['foo.com']], pfb_text_area_decode($in, true, true));
	}

	public function testArrayModeTypedCommentSplit(): void
	{
		$in = self::enc('bar.com # note');
		// Comment line splits into [value, '#comment'] via pfb_strtolower: the
		// value is trimmed+lowered, the '#'-bearing token kept (trimmed) verbatim.
		$this->assertSame([['bar.com', '# note']], pfb_text_area_decode($in, true, true));
	}

	/**
	 * Run $fn under the C locale.
	 *
	 * The IDN branch is gated on !ctype_print(), which is locale-sensitive.
	 * pfSense's PHP CLI runs under the C locale (high bytes non-printable),
	 * so pin that to make the conversion deterministic on any host.
	 */
	private static function underCLocale(callable $fn): void
	{
		$prev = setlocale(LC_CTYPE, '0');
		setlocale(LC_CTYPE, 'C');
		try {
			$fn();
		} finally {
			setlocale(LC_CTYPE, $prev);
		}
	}

	public function testIdnConversionToPunycode(): void
	{
		self::underCLocale(function (): void {
			$in = self::enc('bücher.de');
			$this->assertSame("xn--bcher-kva.de\n", pfb_text_area_decode($in, false, true, true));
		});
	}

	public function testEmptyInputReturnsEmptyString(): void
	{
		// base64('') => '' => explode gives [''] => nothing appended. String mode
		// initialises $custom to '' up front, so empty input yields '' (not null).
		$this->assertSame('', pfb_text_area_decode(''));
	}

	// --- issue #1710: split on any line ending, not just CRLF ---

	public function testLfOnlySplitsIntoRows(): void
	{
		$in = self::rawEnc("alpha\nbeta");
		$this->assertSame("alpha\nbeta\n", pfb_text_area_decode($in));
		$this->assertSame(['alpha', 'beta'], pfb_text_area_decode($in, true, false));
		$this->assertSame([['alpha'], ['beta']], pfb_text_area_decode($in, true, true));
	}

	public function testCrOnlySplitsIntoRows(): void
	{
		$in = self::rawEnc("alpha\rbeta");
		$this->assertSame("alpha\nbeta\n", pfb_text_area_decode($in));
		$this->assertSame(['alpha', 'beta'], pfb_text_area_decode($in, true, false));
		$this->assertSame([['alpha'], ['beta']], pfb_text_area_decode($in, true, true));
	}

	public function testMixedLineEndingsSplitInSourceOrder(): void
	{
		$in = self::rawEnc("alpha\r\nbeta\ngamma\rdelta");
		$this->assertSame("alpha\nbeta\ngamma\ndelta\n", pfb_text_area_decode($in));
		$this->assertSame(
			[['alpha'], ['beta'], ['gamma'], ['delta']],
			pfb_text_area_decode($in, true, true)
		);
	}

	public function testTrailingSeparatorYieldsNoTrailingEmptyRow(): void
	{
		$in = self::rawEnc("a.com\n");
		$this->assertSame("a.com\n", pfb_text_area_decode($in));
		$this->assertSame(['a.com'], pfb_text_area_decode($in, true, false));
		$this->assertSame([['a.com']], pfb_text_area_decode($in, true, true));
	}

	public function testControlCharsRemovedNotTreatedAsSeparators(): void
	{
		// VT (\x0B), FF (\x0C), NEL (U+0085, UTF-8 \xC2\x85) must be stripped from
		// the row and must NOT act as row separators.
		$in = self::rawEnc("al\x0Bpha\nbe\x0Cta\ngam\xC2\x85ma");
		$this->assertSame("alpha\nbeta\ngamma\n", pfb_text_area_decode($in));
	}

	// --- issue #1707 (PHP half): drop whitespace-only rows, keep literal "0" ---

	public function testWhitespaceOnlyRowsDropped(): void
	{
		$in = self::rawEnc("a.com\n   \nb.com\n\t\t\nc.com");
		$this->assertSame("a.com\nb.com\nc.com\n", pfb_text_area_decode($in));
		$this->assertSame(['a.com', 'b.com', 'c.com'], pfb_text_area_decode($in, true, false));
		$this->assertSame(
			[['a.com'], ['b.com'], ['c.com']],
			pfb_text_area_decode($in, true, true)
		);
	}

	public function testZeroRowPreserved(): void
	{
		// '0' is falsy in PHP; the old !empty($line) guard wrongly dropped it.
		$in = self::rawEnc('0');
		$this->assertSame("0\n", pfb_text_area_decode($in));
		$this->assertSame(['0'], pfb_text_area_decode($in, true, false));
		$this->assertSame([['0']], pfb_text_area_decode($in, true, true));
	}

	public function testUnicodeWhitespaceOnlyRowsDropped(): void
	{
		// A row that is only NBSP or only U+3000 (ideographic space) must
		// right-strip to '' and be dropped, same as an ASCII-whitespace row.
		$in = self::rawEnc("a.com\n\xC2\xA0\nb.com\n\xE3\x80\x80\nc.com");
		$this->assertSame("a.com\nb.com\nc.com\n", pfb_text_area_decode($in));
		$this->assertSame(['a.com', 'b.com', 'c.com'], pfb_text_area_decode($in, true, false));
		$this->assertSame(
			[['a.com'], ['b.com'], ['c.com']],
			pfb_text_area_decode($in, true, true)
		);
	}

	public function testDecoderSurvivesHugeControlRunRow(): void
	{
		// A pathological all-NUL row must not wipe the flanking good rows.
		$in = self::rawEnc("a.com\n" . str_repeat("\x00", 20000) . "\nb.com");
		$this->assertSame(['a.com', 'b.com'], pfb_text_area_decode($in, true, false));
	}

	// --- issue #1730: the IDN branch strips exactly ONE leading dot ---

	public function testSingleLeadingDotIdnRowKeepsWildcardForm(): void
	{
		// The legal wildcard form survives the round trip unchanged: one
		// leading dot in, one leading dot out, punycode body.
		self::underCLocale(function (): void {
			$in = self::enc('.bücher.de');
			$this->assertSame(".xn--bcher-kva.de\n", pfb_text_area_decode($in, false, true, true));
			$this->assertSame(['.xn--bcher-kva.de'], pfb_text_area_decode($in, true, false, true));
		});
	}

	public function testSingleLeadingDotIdnRowWithCommentKeepsWildcardForm(): void
	{
		// Same, through the '#'-comment branch, which converts the value token
		// separately from the comment token.
		self::underCLocale(function (): void {
			$in = self::enc('.bücher.de # note');
			$this->assertSame(".xn--bcher-kva.de\n", pfb_text_area_decode($in, false, true, true));
			$this->assertSame(
				[['.xn--bcher-kva.de', '# note']],
				pfb_text_area_decode($in, true, true, true)
			);
		});
	}

	public function testDoubleLeadingDotIdnRowIsNotPromotedToWildcard(): void
	{
		// '..bücher.de' is not a wildcard row: an ASCII '..example.com' row is
		// left as the invalid double-dot string it is, so the IDN row must not
		// be silently rewritten into the legal single-dot wildcard form. With
		// exactly one dot stripped, idn_to_ascii() rejects the remainder and
		// the row is logged and dropped instead.
		self::underCLocale(function (): void {
			$in = self::enc('..bücher.de');
			$this->assertSame('', pfb_text_area_decode($in, false, true, true));
			$this->assertSame([], pfb_text_area_decode($in, true, false, true));
		});
	}

	public function testDoubleLeadingDotIdnRowWithCommentIsNotPromotedToWildcard(): void
	{
		// Same guarantee through the '#'-comment branch.
		self::underCLocale(function (): void {
			$in = self::enc('..bücher.de # note');
			$this->assertSame('', pfb_text_area_decode($in, false, true, true));
			$this->assertSame([], pfb_text_area_decode($in, true, true, true));
		});
	}

	public function testDoubleLeadingDotIdnCommentRowDroppedWithoutTakingNeighboursDown(): void
	{
		// Same per-row guarantee for the '#'-comment branch: a singleton row
		// alone cannot tell a dropped row from an aborted batch.
		self::underCLocale(function (): void {
			$in = self::enc('a.com', '..bücher.de # note', 'b.com');
			$this->assertSame("a.com\nb.com\n", pfb_text_area_decode($in, false, true, true));
			$this->assertSame(
				[['a.com'], ['b.com']],
				pfb_text_area_decode($in, true, true, true)
			);
		});
	}

	public function testDoubleLeadingDotIdnRowDroppedWithoutTakingNeighboursDown(): void
	{
		// A dropped '..' IDN row is a per-row skip, not a batch abort: the rows
		// flanking it still decode.
		self::underCLocale(function (): void {
			$in = self::enc('a.com', '..bücher.de', 'b.com');
			$this->assertSame("a.com\nb.com\n", pfb_text_area_decode($in, false, true, true));
			$this->assertSame(['a.com', 'b.com'], pfb_text_area_decode($in, true, false, true));
		});
	}
}
